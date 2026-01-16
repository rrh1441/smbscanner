/**
 * =============================================================================
 * MODULE: githubSecretSearch.ts
 * =============================================================================
 * Searches GitHub for exposed secrets using the Code Search API.
 *
 * Key features:
 *   - Rate-limited to 10 requests/minute (GitHub Code Search limit)
 *   - Exponential backoff with jitter on rate limit errors
 *   - Pagination support for exhaustive searches
 *   - Respects GitHub API best practices (User-Agent, Accept headers)
 *   - Stores results in github_secret_leads table
 * =============================================================================
 */

import { request } from 'undici';
import * as crypto from 'crypto';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('githubSecretSearch');
import {
  BULK_SEARCHABLE_PATTERNS,
  SecretPattern,
  buildGitHubSearchQuery,
  getSecretPreview,
  matchSecretPatterns,
} from '../config/secretPatterns.js';

/* -------------------------------------------------------------------------- */
/*  Configuration                                                             */
/* -------------------------------------------------------------------------- */

// GitHub API token - required for Code Search API
const getApiToken = () => process.env.GITHUB_TOKEN ?? '';

// Rate limits
// Code Search API: 10 requests per minute for authenticated users
const CODE_SEARCH_RPM = Math.min(
  parseInt(process.env.GITHUB_CODE_SEARCH_RPM ?? '10', 10),
  10 // Hard cap at GitHub's limit
);

// REST API: 5000 requests per hour for authenticated users
const REST_API_RPH = parseInt(process.env.GITHUB_REST_API_RPH ?? '5000', 10);

// Results per page (max 100 for Code Search)
const PER_PAGE = parseInt(process.env.GITHUB_SEARCH_PER_PAGE ?? '100', 10);

// Maximum pages to fetch per pattern
const MAX_PAGES = parseInt(process.env.GITHUB_SEARCH_MAX_PAGES ?? '10', 10);

// Request timeout in ms
const TIMEOUT_MS = parseInt(process.env.GITHUB_SEARCH_TIMEOUT_MS ?? '30000', 10);

// API endpoints
const CODE_SEARCH_API = 'https://api.github.com/search/code';
const REPOS_API = 'https://api.github.com/repos';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

export interface GitHubCodeSearchResult {
  name: string;
  path: string;
  sha: string;
  url: string;
  git_url: string;
  html_url: string;
  repository: {
    id: number;
    name: string;
    full_name: string;
    owner: {
      login: string;
      type: string; // 'User' or 'Organization'
    };
    html_url: string;
    description: string | null;
    fork: boolean;
    stargazers_count: number;
    forks_count: number;
    language: string | null;
  };
  score: number;
  text_matches?: Array<{
    object_type: string;
    object_url: string;
    property: string;
    fragment: string;
    matches: Array<{
      text: string;
      indices: number[];
    }>;
  }>;
}

export interface GitHubSearchResponse {
  total_count: number;
  incomplete_results: boolean;
  items: GitHubCodeSearchResult[];
}

export interface SecretLead {
  repo_url: string;
  repo_owner: string;
  repo_name: string;
  repo_stars: number;
  repo_forks: number;
  repo_language: string | null;
  secret_type: string;
  secret_pattern: string;
  secret_hash: string;
  secret_preview: string;
  file_path: string;
  confidence_score: number;
  raw_metadata: object;
}

export interface SearchProgress {
  pattern: string;
  pages_fetched: number;
  total_results: number;
  secrets_found: number;
  last_cursor?: string;
}

/* -------------------------------------------------------------------------- */
/*  Rate Limiting                                                             */
/* -------------------------------------------------------------------------- */

// Timestamp queue for rate limiting (sliding window)
const codeSearchQueue: number[] = [];
const restApiQueue: number[] = [];

// Track remaining API calls from headers
let codeSearchRemaining = CODE_SEARCH_RPM;
let codeSearchResetAt = 0;
let restApiRemaining = REST_API_RPH;
let restApiResetAt = 0;

/**
 * Wait for rate limit budget before making a Code Search API call.
 */
async function waitForCodeSearchBudget(): Promise<void> {
  const now = Date.now();

  // Clean old timestamps (older than 60 seconds for Code Search)
  while (codeSearchQueue.length && now - codeSearchQueue[0] > 60_000) {
    codeSearchQueue.shift();
  }

  // If we've exhausted the budget, wait
  if (codeSearchQueue.length >= CODE_SEARCH_RPM) {
    const oldestRequest = codeSearchQueue[0];
    const waitTime = 60_000 - (now - oldestRequest) + 100; // Add 100ms buffer
    log.info(`Rate limit reached, waiting ${waitTime}ms`);
    await new Promise((r) => setTimeout(r, waitTime));
  }

  codeSearchQueue.push(Date.now());
}

/**
 * Wait for rate limit budget before making a REST API call.
 */
async function waitForRestApiBudget(): Promise<void> {
  const now = Date.now();

  // Clean old timestamps (older than 1 hour for REST API)
  while (restApiQueue.length && now - restApiQueue[0] > 3600_000) {
    restApiQueue.shift();
  }

  // If we've exhausted the budget, wait until reset
  if (restApiRemaining <= 0 && restApiResetAt > now) {
    const waitTime = restApiResetAt - now + 1000;
    log.info(`REST API rate limit reached, waiting ${Math.ceil(waitTime / 1000)}s`);
    await new Promise((r) => setTimeout(r, waitTime));
  }

  restApiQueue.push(Date.now());
}

/**
 * Update rate limit info from response headers.
 */
function updateRateLimits(headers: Record<string, string>, isCodeSearch: boolean): void {
  const remaining = parseInt(headers['x-ratelimit-remaining'] ?? '-1', 10);
  const reset = parseInt(headers['x-ratelimit-reset'] ?? '0', 10) * 1000;

  if (isCodeSearch) {
    if (remaining >= 0) codeSearchRemaining = remaining;
    if (reset) codeSearchResetAt = reset;
  } else {
    if (remaining >= 0) restApiRemaining = remaining;
    if (reset) restApiResetAt = reset;
  }
}

/* -------------------------------------------------------------------------- */
/*  HTTP Client with Rate Limiting & Retry                                    */
/* -------------------------------------------------------------------------- */

async function githubFetch<T>(
  url: string,
  isCodeSearch: boolean,
  attempt = 0
): Promise<T> {
  const token = getApiToken();
  if (!token) {
    throw new Error('GITHUB_TOKEN not configured');
  }

  // Wait for rate limit budget
  if (isCodeSearch) {
    await waitForCodeSearchBudget();
  } else {
    await waitForRestApiBudget();
  }

  try {
    const { body, statusCode, headers } = await request(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3.text-match+json', // Enable text_matches
        'User-Agent': 'SimplCyber-Scanner/1.0 (+https://simplcyber.com)',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      headersTimeout: TIMEOUT_MS,
      bodyTimeout: TIMEOUT_MS,
    });

    // Update rate limit tracking
    const headerMap: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      if (typeof value === 'string') {
        headerMap[key.toLowerCase()] = value;
      }
    }
    updateRateLimits(headerMap, isCodeSearch);

    // Handle rate limiting
    if (statusCode === 403 || statusCode === 429) {
      const retryAfter = parseInt(headerMap['retry-after'] ?? '60', 10);
      const waitTime = retryAfter * 1000 + Math.random() * 1000; // Add jitter

      if (attempt < 3) {
        log.info(`Rate limited (${statusCode}), retry in ${Math.ceil(waitTime / 1000)}s`);
        await new Promise((r) => setTimeout(r, waitTime));
        return githubFetch<T>(url, isCodeSearch, attempt + 1);
      }
      throw new Error(`GitHub rate limit exceeded after ${attempt + 1} attempts`);
    }

    // Handle server errors with retry
    if (statusCode >= 500) {
      if (attempt < 3) {
        const backoff = 1000 * 2 ** attempt + Math.random() * 500;
        log.info(`Server error ${statusCode}, retry in ${Math.ceil(backoff)}ms`);
        await new Promise((r) => setTimeout(r, backoff));
        return githubFetch<T>(url, isCodeSearch, attempt + 1);
      }
      throw new Error(`GitHub server error ${statusCode} after ${attempt + 1} attempts`);
    }

    // Handle client errors
    if (statusCode >= 400) {
      const text = await body.text();
      throw new Error(`GitHub API error ${statusCode}: ${text.slice(0, 200)}`);
    }

    return (await body.json()) as T;
  } catch (err) {
    // Retry on network errors
    const isNetworkError =
      (err as any).code === 'ECONNRESET' ||
      (err as any).code === 'ETIMEDOUT' ||
      (err as any).code === 'ECONNREFUSED';

    if (isNetworkError && attempt < 3) {
      const backoff = 1000 * 2 ** attempt + Math.random() * 500;
      log.info(`Network error, retry in ${Math.ceil(backoff)}ms`);
      await new Promise((r) => setTimeout(r, backoff));
      return githubFetch<T>(url, isCodeSearch, attempt + 1);
    }

    throw err;
  }
}

/* -------------------------------------------------------------------------- */
/*  Core Search Functions                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Search GitHub Code for a specific query.
 */
export async function searchCode(
  query: string,
  page = 1,
  perPage = PER_PAGE
): Promise<GitHubSearchResponse> {
  const encodedQuery = encodeURIComponent(query);
  const url = `${CODE_SEARCH_API}?q=${encodedQuery}&per_page=${Math.min(perPage, 100)}&page=${page}`;

  log.info(`Searching: ${query.slice(0, 100)}...`);

  return githubFetch<GitHubSearchResponse>(url, true);
}

/**
 * Search for all pages of a pattern, respecting rate limits.
 */
export async function searchPattern(
  pattern: SecretPattern,
  onProgress?: (progress: SearchProgress) => void
): Promise<SecretLead[]> {
  const leads: SecretLead[] = [];
  const query = buildGitHubSearchQuery(pattern);

  let page = 1;
  let totalResults = 0;

  while (page <= MAX_PAGES) {
    try {
      const response = await searchCode(query, page);

      if (page === 1) {
        totalResults = response.total_count;
        log.info(`Pattern "${pattern.name}": ${totalResults} total results`);
      }

      // Process results
      for (const item of response.items) {
        const lead = await processSearchResult(item, pattern);
        if (lead) {
          leads.push(lead);
        }
      }

      // Report progress
      onProgress?.({
        pattern: pattern.name,
        pages_fetched: page,
        total_results: totalResults,
        secrets_found: leads.length,
      });

      // Check if we've exhausted results
      if (response.items.length < PER_PAGE) {
        break;
      }

      // GitHub only returns first 1000 results
      if (page * PER_PAGE >= 1000) {
        log.info(`Reached 1000 result limit for "${pattern.name}"`);
        break;
      }

      page++;
    } catch (err) {
      log.info(`Error on page ${page}: ${(err as Error).message}`);
      break;
    }
  }

  return leads;
}

/**
 * Process a search result into a potential lead.
 */
async function processSearchResult(
  item: GitHubCodeSearchResult,
  pattern: SecretPattern
): Promise<SecretLead | null> {
  // Skip forks
  if (item.repository.fork) {
    return null;
  }

  // Extract text matches to find the actual secret
  const textMatches = item.text_matches ?? [];
  let matchedText = '';
  let confidenceScore = 50; // Base score

  for (const tm of textMatches) {
    for (const match of tm.matches) {
      // Validate against our regex pattern
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      if (regex.test(match.text)) {
        matchedText = match.text;
        confidenceScore = 80; // Higher confidence when regex matches
        break;
      }
    }
    if (matchedText) break;
  }

  // If no text_matches, use fragment
  if (!matchedText && textMatches.length > 0) {
    const fragment = textMatches[0].fragment;
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    const matches = fragment.match(regex);
    if (matches) {
      matchedText = matches[0];
      confidenceScore = 60;
    }
  }

  // If we still have no match, skip
  if (!matchedText) {
    return null;
  }

  // Check for common false positive indicators
  const filePath = item.path.toLowerCase();
  if (
    filePath.includes('test') ||
    filePath.includes('spec') ||
    filePath.includes('example') ||
    filePath.includes('sample') ||
    filePath.includes('mock') ||
    filePath.includes('fixture')
  ) {
    confidenceScore -= 30;
  }

  // Boost for .env files
  if (filePath.endsWith('.env') || filePath.endsWith('.env.local')) {
    confidenceScore += 15;
  }

  // Skip very low confidence
  if (confidenceScore < 30) {
    return null;
  }

  // Generate secret hash (never store actual secret)
  const secretHash = crypto.createHash('sha256').update(matchedText).digest('hex');

  return {
    repo_url: item.repository.html_url,
    repo_owner: item.repository.owner.login,
    repo_name: item.repository.name,
    repo_stars: item.repository.stargazers_count,
    repo_forks: item.repository.forks_count,
    repo_language: item.repository.language,
    secret_type: pattern.name,
    secret_pattern: pattern.regex.source.slice(0, 100),
    secret_hash: secretHash,
    secret_preview: getSecretPreview(matchedText),
    file_path: item.path,
    confidence_score: Math.min(confidenceScore, 100),
    raw_metadata: {
      github_score: item.score,
      html_url: item.html_url,
      git_url: item.git_url,
      owner_type: item.repository.owner.type,
      description: item.repository.description,
    },
  };
}

/* -------------------------------------------------------------------------- */
/*  Repository Info Fetching                                                  */
/* -------------------------------------------------------------------------- */

export interface RepoInfo {
  html_url: string;
  homepage: string | null;
  description: string | null;
  owner: {
    login: string;
    type: string;
    html_url: string;
  };
  organization?: {
    login: string;
    blog: string | null;
    email: string | null;
    description: string | null;
  };
}

/**
 * Fetch additional repository information.
 */
export async function getRepoInfo(owner: string, repo: string): Promise<RepoInfo | null> {
  try {
    const url = `${REPOS_API}/${owner}/${repo}`;
    return await githubFetch<RepoInfo>(url, false);
  } catch (err) {
    log.info(`Failed to fetch repo info for ${owner}/${repo}: ${(err as Error).message}`);
    return null;
  }
}

export interface OrgInfo {
  login: string;
  html_url: string;
  blog: string | null;
  email: string | null;
  description: string | null;
  name: string | null;
  company: string | null;
  location: string | null;
  public_repos: number;
  followers: number;
}

/**
 * Fetch organization information.
 */
export async function getOrgInfo(org: string): Promise<OrgInfo | null> {
  try {
    const url = `https://api.github.com/orgs/${org}`;
    return await githubFetch<OrgInfo>(url, false);
  } catch (err) {
    // 404 is expected for user accounts
    if ((err as Error).message.includes('404')) {
      return null;
    }
    log.info(`Failed to fetch org info for ${org}: ${(err as Error).message}`);
    return null;
  }
}

/* -------------------------------------------------------------------------- */
/*  Bulk Search Functions                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Run a full search across all bulk-searchable patterns.
 */
export async function searchAllPatterns(
  onProgress?: (pattern: string, progress: SearchProgress) => void
): Promise<Map<string, SecretLead[]>> {
  const results = new Map<string, SecretLead[]>();

  for (const pattern of BULK_SEARCHABLE_PATTERNS) {
    log.info(`Starting pattern: ${pattern.name}`);

    const leads = await searchPattern(pattern, (progress) => {
      onProgress?.(pattern.name, progress);
    });

    results.set(pattern.name, leads);

    log.info(`Pattern "${pattern.name}": ${leads.length} leads found`);

    // Small delay between patterns to be nice to GitHub
    await new Promise((r) => setTimeout(r, 2000));
  }

  return results;
}

/**
 * Search only high-value patterns (database, payment, AWS).
 */
export async function searchHighValuePatterns(
  onProgress?: (pattern: string, progress: SearchProgress) => void
): Promise<Map<string, SecretLead[]>> {
  const highValuePatterns = BULK_SEARCHABLE_PATTERNS.filter(
    (p) =>
      p.category === 'database' ||
      p.category === 'payment' ||
      p.name.includes('AWS')
  );

  const results = new Map<string, SecretLead[]>();

  for (const pattern of highValuePatterns) {
    log.info(`Starting high-value pattern: ${pattern.name}`);

    const leads = await searchPattern(pattern, (progress) => {
      onProgress?.(pattern.name, progress);
    });

    results.set(pattern.name, leads);

    await new Promise((r) => setTimeout(r, 2000));
  }

  return results;
}

/* -------------------------------------------------------------------------- */
/*  Status & Diagnostics                                                      */
/* -------------------------------------------------------------------------- */

export function getRateLimitStatus(): {
  codeSearch: { remaining: number; resetAt: Date };
  restApi: { remaining: number; resetAt: Date };
} {
  return {
    codeSearch: {
      remaining: codeSearchRemaining,
      resetAt: new Date(codeSearchResetAt),
    },
    restApi: {
      remaining: restApiRemaining,
      resetAt: new Date(restApiResetAt),
    },
  };
}

export function isConfigured(): boolean {
  return !!getApiToken();
}

/* -------------------------------------------------------------------------- */
/*  Default Export                                                            */
/* -------------------------------------------------------------------------- */

export default {
  searchCode,
  searchPattern,
  searchAllPatterns,
  searchHighValuePatterns,
  getRepoInfo,
  getOrgInfo,
  getRateLimitStatus,
  isConfigured,
};
