/**
 * Infostealer Probe Module
 * 
 * Queries LeakCheck API for comprehensive domain breach intelligence
 * to identify compromised accounts and infostealer malware exposure.
 */

import axios from 'axios';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { executeModule, apiCall } from '../util/errorHandler.js';

function sanitizeHostname(host: string): string {
  let d = (host || '').trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.replace(/\/.*/, '');
  d = d.replace(/:.*/, '');
  if (d.startsWith('www.')) d = d.slice(4);
  return d;
}

// Return eTLD+1 for common suffixes; fallback to last two labels
function toRegistrableDomain(host: string): string {
  const d = sanitizeHostname(host);
  const parts = d.split('.').filter(Boolean);
  if (parts.length <= 2) return d;
  const twoLabelTlds = new Set([
    // UK
    'co.uk','ac.uk','gov.uk','ltd.uk','plc.uk','me.uk','net.uk','org.uk',
    // AU
    'com.au','net.au','org.au','edu.au','gov.au',
    // JP
    'co.jp','ne.jp','or.jp','ac.jp','ad.jp','ed.jp','go.jp',
    // IN
    'co.in','firm.in','net.in','org.in','gen.in','ind.in',
    // Others common
    'com.br','com.mx','com.ar','com.sg','com.my','com.hk','com.tr','com.co'
  ]);
  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');
  if (twoLabelTlds.has(last2)) return last3;
  return last2;
}

// Configuration constants
const BREACH_DIRECTORY_API_BASE = 'https://BreachDirectory.com/api_usage';
const LEAKCHECK_API_BASE = 'https://leakcheck.io/api/v2';
const API_TIMEOUT_MS = 30_000;
const MAX_SAMPLE_USERNAMES = 100;
// Respect documented 3 RPS default limit; allow override via env
const LEAKCHECK_RPS = Math.max(1, parseInt(process.env.LEAKCHECK_RPS || '3', 10));
const LEAKCHECK_RATE_LIMIT_MS = Math.ceil(1000 / LEAKCHECK_RPS) + 25; // small buffer
const LEAKCHECK_MAX_RETRIES = Math.max(0, parseInt(process.env.LEAKCHECK_MAX_RETRIES || '3', 10));
let leakcheckNextAt = 0;
async function leakcheckRateLimit() {
  const now = Date.now();
  const waitMs = Math.max(0, leakcheckNextAt - now);
  if (waitMs > 0) await new Promise(r => setTimeout(r, waitMs));
  leakcheckNextAt = Date.now() + LEAKCHECK_RATE_LIMIT_MS;
}

// Enhanced logging
const log = createModuleLogger('infostealerProbe');

interface BreachDirectoryResponse {
  breached_total?: number;
  sample_usernames?: string[];
  error?: string;
  message?: string;
}

interface LeakCheckResponse {
  success: boolean;
  found: number;
  quota: number;
  result: Array<{
    email: string;
    source: {
      name: string;
      breach_date: string;
      unverified: number;
      passwordless: number;
      compilation: number;
    };
    first_name?: string;
    last_name?: string;
    username?: string;
    fields: string[];
  }>;
  error?: string;
}

interface BreachProbeSummary {
  domain: string;
  breached_total: number;
  sample_usernames: string[];
  high_risk_assessment: boolean;
  breach_directory_success: boolean;
  leakcheck_total: number;
  leakcheck_sources: string[];
  leakcheck_success: boolean;
  combined_total: number;
  leakcheck_results: Array<{
    email: string | null;
    username: string | null;
    source: {
      name: string;
      breach_date: string | null;
      unverified: number;
      passwordless: number;
      compilation: number;
    };
    has_password: boolean;
    has_cookies: boolean;
    has_autofill: boolean;
    has_browser_data: boolean;
    field_count: number;
    first_name: string | null;
    last_name: string | null;
  }>;
}

interface UserBreachRecord {
  userId: string;
  breaches: Array<{
    email: string | null;
    username: string | null;
    source: {
      name: string;
      breach_date: string | null;
      unverified: number;
      passwordless: number;
      compilation: number;
    };
    has_password: boolean;
    has_cookies: boolean;
    has_autofill: boolean;
    has_browser_data: boolean;
    field_count: number;
    first_name: string | null;
    last_name: string | null;
  }>;
  highestSeverity: 'CRITICAL' | 'MEDIUM' | 'INFO';
  exposureTypes: string[];
  allSources: string[];
  earliestBreach: string | null;
  latestBreach: string | null;
}

/**
 * Query Breach Directory API for domain breach data
 */
async function queryBreachDirectory(domain: string, apiKey: string): Promise<BreachDirectoryResponse> {
  const operation = async () => {
    log.info(`Querying Breach Directory for domain: ${domain}`);
    
    const response = await axios.get(BREACH_DIRECTORY_API_BASE, {
      params: {
        method: 'domain',
        key: apiKey,
        query: domain
      },
      timeout: API_TIMEOUT_MS,
      validateStatus: (status) => status < 500 // Accept 4xx as valid responses
    });
    
    if (response.status === 200) {
      const data = response.data as BreachDirectoryResponse;
      log.info(`Breach Directory response for ${domain}: ${data.breached_total || 0} breached accounts`);
      return data;
    } else if (response.status === 404) {
      log.info(`No breach data found for domain: ${domain}`);
      return { breached_total: 0, sample_usernames: [] };
    } else if (response.status === 403) {
      // Enhanced logging for 403 Forbidden responses
      const responseData = response.data || {};
      const errorMessage = responseData.error || responseData.message || 'Access forbidden';
      log.info(`Breach Directory API returned 403 Forbidden for ${domain}: ${errorMessage}`);
      throw new Error(`API access forbidden (403): ${errorMessage}`);
    } else {
      // Enhanced generic error handling with response data
      const responseData = response.data || {};
      const errorMessage = responseData.error || responseData.message || `HTTP ${response.status}`;
      log.info(`Breach Directory API returned status ${response.status} for ${domain}: ${errorMessage}`);
      throw new Error(`API returned status ${response.status}: ${errorMessage}`);
    }
  };

  const result = await apiCall(operation, {
    moduleName: 'breachDirectoryProbe',
    operation: 'queryBreachDirectory',
    target: domain
  });

  if (!result.success) {
    throw new Error((result as any).error);
  }

  return result.data;
}

/**
 * Query LeakCheck API for domain breach data
 */
async function queryLeakCheck(domain: string, apiKey: string): Promise<LeakCheckResponse> {
  const apex = toRegistrableDomain(domain);
  log.info(`Querying LeakCheck for domain: ${apex} (from ${domain})`);

  let attempt = 0;
  for (;;) {
    attempt++;
    await leakcheckRateLimit();

    const response = await axios.get(`${LEAKCHECK_API_BASE}/query/${apex}`, {
      headers: {
        'Accept': 'application/json',
        'X-API-Key': apiKey
      },
      params: {
        type: 'domain',
        limit: 1000
      },
      timeout: API_TIMEOUT_MS,
      validateStatus: (status) => status < 500
    });

    if (response.status === 200) {
      const data = response.data as LeakCheckResponse;
      log.info(`LeakCheck response for ${domain}: ${data.found || 0} accounts found`);
      return data;
    }
    if (response.status === 404) {
      log.info(`No leak data found for domain: ${domain}`);
      return { success: false, found: 0, quota: 0, result: [] };
    }
    if (response.status === 429 || response.status === 403) {
      const retryAfter = Number(response.headers?.['retry-after']);
      const baseDelay = retryAfter && !Number.isNaN(retryAfter)
        ? Math.min(5000, Math.max(500, Math.round(Number(retryAfter) * 1000)))
        : 500 + (attempt - 1) * 400;
      const jitter = Math.floor(Math.random() * 150);
      const delay = baseDelay + jitter;
      log.info(`LeakCheck rate/plan limit (${response.status}) for ${domain}; attempt ${attempt}/${LEAKCHECK_MAX_RETRIES + 1}, backing off ${delay}ms`);
      if (attempt <= LEAKCHECK_MAX_RETRIES) {
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
    }

    const responseData = response.data || {};
    const errorMessage = responseData.error || `HTTP ${response.status}`;
    throw new Error(`LeakCheck API error: ${errorMessage}`);
  }
}

/**
 * Analyze combined breach data from both sources
 */
function analyzeCombinedBreach(
  breachDirectoryData: BreachDirectoryResponse,
  leakCheckData: LeakCheckResponse
): BreachProbeSummary {
  const breached_total = breachDirectoryData.breached_total || 0;
  const sample_usernames = (breachDirectoryData.sample_usernames || []).slice(0, MAX_SAMPLE_USERNAMES);
  
  // LeakCheck data processing
  const leakcheck_total = leakCheckData.found || 0;
  const leakcheck_sources = leakCheckData.result
    .map(entry => entry.source.name)
    .filter((name, index, array) => array.indexOf(name) === index) // Remove duplicates
    .slice(0, 20); // Limit to first 20 unique sources
  
  // Process LeakCheck results for enhanced analysis (NO sensitive data stored)
  const leakCheckResults = leakCheckData.result
    .map(entry => ({
      email: entry.email || null,
      username: entry.username || (entry.email ? entry.email.split('@')[0] : null),
      source: {
        name: entry.source?.name || 'Unknown',
        breach_date: entry.source?.breach_date || null,
        unverified: entry.source?.unverified || 0,
        passwordless: entry.source?.passwordless || 0,
        compilation: entry.source?.compilation || 0
      },
      // Only store field existence flags, NOT actual values
      has_password: entry.fields?.includes('password') || false,
      has_cookies: entry.fields?.includes('cookies') || entry.fields?.includes('cookie') || false,
      has_autofill: entry.fields?.includes('autofill') || entry.fields?.includes('autofill_data') || false,
      has_browser_data: entry.fields?.includes('browser_data') || entry.fields?.includes('browser') || false,
      field_count: entry.fields?.length || 0,
      first_name: entry.first_name || null,
      last_name: entry.last_name || null
    }))
    .slice(0, 100); // Limit to 100 for performance

  // Add usernames from LeakCheck to sample usernames for backward compatibility
  const leakCheckUsernames = leakCheckResults
    .map(entry => entry.username)
    .filter(username => username !== null)
    .slice(0, 50);
  
  const combinedUsernames = [...sample_usernames, ...leakCheckUsernames]
    .filter((name, index, array) => array.indexOf(name) === index) // Remove duplicates
    .slice(0, MAX_SAMPLE_USERNAMES);
  
  const combined_total = breached_total + leakcheck_total;
  
  // High risk assessment based on breach count and username patterns
  let high_risk_assessment = false;
  
  // Risk factors
  if (combined_total >= 100) {
    high_risk_assessment = true;
  }
  
  // Check for administrative/privileged account patterns
  const privilegedPatterns = [
    'admin', 'administrator', 'root', 'sa', 'sysadmin',
    'ceo', 'cto', 'cfo', 'founder', 'owner',
    'security', 'infosec', 'it', 'tech'
  ];
  
  const hasPrivilegedAccounts = combinedUsernames.some(username => 
    privilegedPatterns.some(pattern => 
      username.toLowerCase().includes(pattern)
    )
  );
  
  if (hasPrivilegedAccounts && combined_total >= 10) {
    high_risk_assessment = true;
  }
  
  // Check for recent breaches in LeakCheck data
  const recentBreaches = leakCheckData.result.filter(entry => {
    if (!entry.source?.breach_date) return false;
    const breachYear = parseInt(entry.source.breach_date.split('-')[0]);
    return !isNaN(breachYear) && breachYear >= 2020; // Breaches from 2020 onwards
  });
  
  if (recentBreaches.length >= 10) {
    high_risk_assessment = true;
  }
  
  return {
    domain: '', // Will be set by caller
    breached_total,
    sample_usernames: combinedUsernames,
    high_risk_assessment,
    breach_directory_success: !breachDirectoryData.error,
    leakcheck_total,
    leakcheck_sources,
    leakcheck_success: leakCheckData.success,
    combined_total,
    leakcheck_results: leakCheckResults // Add full results with security flags
  };
}

/**
 * Check if breach source is infostealer malware
 * LeakCheck's "Stealer Logs" category = actual infostealer malware
 * These are credentials stolen by malware, NOT regular database breaches
 */
function isInfostealerSource(credential: any): boolean {
  if (!credential.source?.name) return false;
  const sourceName = credential.source.name.toLowerCase();

  // LeakCheck's "Stealer Logs" is the primary category for infostealer malware
  if (sourceName === 'stealer logs' || sourceName.includes('stealer')) {
    return true;
  }

  // Also match specific malware family names
  return sourceName.includes('redline') ||
         sourceName.includes('raccoon') ||
         sourceName.includes('vidar') ||
         sourceName.includes('azorult') ||
         sourceName.includes('formbook') ||
         sourceName.includes('lokibot') ||
         sourceName.includes('mars') ||
         sourceName.includes('lumma') ||
         sourceName.includes('titan');
}

/**
 * Check if user has username + password + session data (CRITICAL)
 */
function hasUsernamePasswordCookies(credential: any): boolean {
  return credential.has_password && 
         (credential.has_cookies || credential.has_autofill || credential.has_browser_data) &&
         (credential.username || credential.email);
}

/**
 * Check if user has username + password only (MEDIUM)
 */
function hasUsernamePassword(credential: any): boolean {
  return credential.has_password && 
         !credential.has_cookies && 
         !credential.has_autofill && 
         !credential.has_browser_data &&
         (credential.username || credential.email);
}

/**
 * Check if user has username/email only, no password (INFO)
 */
function hasUsernameOnly(credential: any): boolean {
  return !credential.has_password && 
         !credential.has_cookies && 
         !credential.has_autofill && 
         !credential.has_browser_data &&
         (credential.username || credential.email);
}

/**
 * Calculate the highest severity for a user across all their breaches
 *
 * CRITICAL = ONLY infostealer malware sources (Stealer Logs, Redline, Raccoon, etc.)
 * MEDIUM = Password breaches from regular sources (database leaks, not infostealer)
 * INFO = Email-only breaches
 *
 * If a user has BOTH infostealer AND regular breaches, they should be split into
 * separate findings (one CRITICAL for infostealer, one MEDIUM/INFO for others).
 * This is handled in the consolidation logic.
 */
function calculateUserSeverity(userBreaches: any[]): 'CRITICAL' | 'MEDIUM' | 'INFO' {
  // CRITICAL = ONLY actual infostealer malware sources
  // Check if ALL breaches with passwords are from infostealer sources
  const infostealerBreaches = userBreaches.filter(isInfostealerSource);
  const nonInfostealerBreaches = userBreaches.filter(b => !isInfostealerSource(b));

  // If user has ANY infostealer breaches, mark as CRITICAL
  // (The splitting logic below will separate mixed cases)
  if (infostealerBreaches.length > 0) {
    return 'CRITICAL';
  }

  // Check for password+session data from non-infostealer sources
  const hasPasswordAndSession = nonInfostealerBreaches.some(hasUsernamePasswordCookies);
  if (hasPasswordAndSession) {
    return 'CRITICAL';
  }

  // Check for MEDIUM condition (password-only from regular breaches)
  const hasPasswordOnly = nonInfostealerBreaches.some(hasUsernamePassword);
  if (hasPasswordOnly) {
    return 'MEDIUM';
  }

  // Default to INFO (username/email only)
  return 'INFO';
}

/**
 * Deduplicate and consolidate breach data by user
 */
function consolidateBreachesByUser(leakCheckResults: any[]): UserBreachRecord[] {
  const userBreachMap = new Map<string, UserBreachRecord>();
  
  leakCheckResults.forEach(credential => {
    // Use email as primary identifier, fallback to username
    const userId = credential.email || credential.username;
    if (!userId) return;
    
    // Normalize userId (lowercase for consistent grouping)
    const normalizedUserId = userId.toLowerCase();
    
    if (!userBreachMap.has(normalizedUserId)) {
      userBreachMap.set(normalizedUserId, {
        userId: userId, // Keep original case for display
        breaches: [],
        highestSeverity: 'INFO',
        exposureTypes: [],
        allSources: [],
        earliestBreach: null,
        latestBreach: null
      });
    }
    
    const userRecord = userBreachMap.get(normalizedUserId)!;
    userRecord.breaches.push(credential);
    
    // Track unique sources
    if (credential.source?.name && !userRecord.allSources.includes(credential.source.name)) {
      userRecord.allSources.push(credential.source.name);
    }
    
    // Track breach dates for timeline
    if (credential.source?.breach_date) {
      const breachDate = credential.source.breach_date;
      if (!userRecord.earliestBreach || breachDate < userRecord.earliestBreach) {
        userRecord.earliestBreach = breachDate;
      }
      if (!userRecord.latestBreach || breachDate > userRecord.latestBreach) {
        userRecord.latestBreach = breachDate;
      }
    }
  });
  
  // Calculate severity and exposure types for each user
  for (const userRecord of userBreachMap.values()) {
    userRecord.highestSeverity = calculateUserSeverity(userRecord.breaches);
    
    // Determine exposure types
    const exposureTypes = new Set<string>();
    userRecord.breaches.forEach(breach => {
      if (isInfostealerSource(breach)) {
        exposureTypes.add('Infostealer malware');
      }
      if (breach.has_password && (breach.has_cookies || breach.has_autofill || breach.has_browser_data)) {
        exposureTypes.add('Password + session data');
      } else if (breach.has_password) {
        exposureTypes.add('Password');
      }
      if (breach.has_cookies) exposureTypes.add('Cookies');
      if (breach.has_autofill) exposureTypes.add('Autofill data');
      if (breach.has_browser_data) exposureTypes.add('Browser data');
    });
    
    userRecord.exposureTypes = Array.from(exposureTypes);
  }
  
  return Array.from(userBreachMap.values());
}

/**
 * Split users with BOTH infostealer AND non-infostealer breaches into separate records
 *
 * Example: If user has 1 Stealer Logs breach + 5 Indiamart.com breaches:
 * - Create one CRITICAL record with ONLY the Stealer Logs breach
 * - Create one MEDIUM/INFO record with ONLY the 5 Indiamart.com breaches
 *
 * This ensures CRITICAL_BREACH_EXPOSURE findings only show actual infostealer data
 */
function splitMixedBreachUsers(consolidatedUsers: UserBreachRecord[]): UserBreachRecord[] {
  const splitUsers: UserBreachRecord[] = [];

  for (const user of consolidatedUsers) {
    const infostealerBreaches = user.breaches.filter(isInfostealerSource);
    const nonInfostealerBreaches = user.breaches.filter(b => !isInfostealerSource(b));

    // Case 1: User has ONLY infostealer breaches - keep as-is (CRITICAL)
    if (infostealerBreaches.length > 0 && nonInfostealerBreaches.length === 0) {
      splitUsers.push(user);
      continue;
    }

    // Case 2: User has ONLY non-infostealer breaches - keep as-is (MEDIUM/INFO)
    if (infostealerBreaches.length === 0 && nonInfostealerBreaches.length > 0) {
      splitUsers.push(user);
      continue;
    }

    // Case 3: User has BOTH - split into two separate records
    if (infostealerBreaches.length > 0 && nonInfostealerBreaches.length > 0) {
      // Create CRITICAL record for infostealer breaches
      const infostealerRecord: UserBreachRecord = {
        userId: user.userId,
        breaches: infostealerBreaches,
        highestSeverity: 'CRITICAL',
        exposureTypes: ['Infostealer malware'],
        allSources: infostealerBreaches.map(b => b.source?.name).filter(Boolean),
        earliestBreach: null, // Infostealers usually don't have dates
        latestBreach: null
      };
      splitUsers.push(infostealerRecord);

      // Create MEDIUM/INFO record for non-infostealer breaches
      const regularRecord: UserBreachRecord = {
        userId: user.userId,
        breaches: nonInfostealerBreaches,
        highestSeverity: calculateUserSeverity(nonInfostealerBreaches),
        exposureTypes: [],
        allSources: nonInfostealerBreaches.map(b => b.source?.name).filter(Boolean),
        earliestBreach: null,
        latestBreach: null
      };

      // Calculate exposure types for regular breaches
      const regularExposureTypes = new Set<string>();
      nonInfostealerBreaches.forEach(breach => {
        if (breach.has_password && (breach.has_cookies || breach.has_autofill || breach.has_browser_data)) {
          regularExposureTypes.add('Password + session data');
        } else if (breach.has_password) {
          regularExposureTypes.add('Password');
        }
        if (breach.has_cookies) regularExposureTypes.add('Cookies');
        if (breach.has_autofill) regularExposureTypes.add('Autofill data');
        if (breach.has_browser_data) regularExposureTypes.add('Browser data');
      });
      regularRecord.exposureTypes = Array.from(regularExposureTypes);

      // Calculate timeline for regular breaches
      nonInfostealerBreaches.forEach(breach => {
        if (breach.source?.breach_date) {
          const breachDate = breach.source.breach_date;
          if (!regularRecord.earliestBreach || breachDate < regularRecord.earliestBreach) {
            regularRecord.earliestBreach = breachDate;
          }
          if (!regularRecord.latestBreach || breachDate > regularRecord.latestBreach) {
            regularRecord.latestBreach = breachDate;
          }
        }
      });

      splitUsers.push(regularRecord);
    }
  }

  return splitUsers;
}

/**
 * Calculate breach recency in months from breach_date string (YYYY-MM format)
 */
function calculateBreachRecencyMonths(breachDate: string | null): number {
  if (!breachDate) return 999; // Default to old breach if no date

  try {
    const parts = breachDate.split('-');
    const breachYear = parseInt(parts[0]);
    const breachMonth = parseInt(parts[1] || '1');
    const now = new Date();
    const currentYear = now.getFullYear();
    const currentMonth = now.getMonth() + 1;
    return (currentYear - breachYear) * 12 + (currentMonth - breachMonth);
  } catch {
    return 999; // Default to old breach if parsing fails
  }
}

// Keep old function for EAL calculation compatibility
function calculateBreachRecencyYears(breachDate: string | null): number {
  const months = calculateBreachRecencyMonths(breachDate);
  return months / 12;
}

/**
 * Detect privilege level from username
 */
function detectPrivilegeLevel(userId: string): 'admin' | 'ceo' | 'normal' {
  const lowerUserId = userId.toLowerCase();

  const privilegedPatterns = {
    admin: ['admin', 'administrator', 'root', 'sa', 'sysadmin', 'security', 'infosec', 'it'],
    ceo: ['ceo', 'cto', 'cfo', 'founder', 'owner', 'president', 'executive']
  };

  for (const pattern of privilegedPatterns.ceo) {
    if (lowerUserId.includes(pattern)) return 'ceo';
  }

  for (const pattern of privilegedPatterns.admin) {
    if (lowerUserId.includes(pattern)) return 'admin';
  }

  return 'normal';
}

/**
 * Determine credential completeness from breach record
 */
function determineCredentialCompleteness(user: UserBreachRecord): 'cookies' | 'password' | 'email' {
  // Check if any breach has cookies/autofill/browser data
  const hasCookies = user.breaches.some(b => b.has_cookies || b.has_autofill || b.has_browser_data);
  if (hasCookies) return 'cookies';

  // Check if any breach has password
  const hasPassword = user.breaches.some(b => b.has_password);
  if (hasPassword) return 'password';

  // Only email
  return 'email';
}

/**
 * Check if any breach is from infostealer malware
 */
function hasInfostealerSource(user: UserBreachRecord): boolean {
  return user.breaches.some(b => isInfostealerSource(b));
}

/**
 * Calculate average breach recency across all user breaches
 *
 * NOTE: LeakCheck stealer records do NOT have breach dates. We previously assumed
 * 0.5 years (very fresh) but this may overstate risk. Using 1.5 years as a moderate
 * default that acknowledges uncertainty while still treating stealer data as more
 * concerning than undated regular breaches.
 *
 * See: https://github.com/simplcyber/scanner/issues/TBD for discussion
 */
function calculateAverageRecency(user: UserBreachRecord): number {
  // Default recency for undated stealer logs - moderate assumption (was 0.5, now 1.5)
  // This acknowledges that LeakCheck doesn't timestamp individual stealer records
  const UNDATED_STEALER_RECENCY_YEARS = 1.5;

  const recencies = user.breaches.map(b => {
    // If breach has a date, calculate actual recency
    if (b.source?.breach_date) {
      return calculateBreachRecencyYears(b.source.breach_date);
    }

    // No date: check if it's a stealer log
    // Use moderate default since LeakCheck doesn't timestamp stealer records
    if (isInfostealerSource(b)) {
      return UNDATED_STEALER_RECENCY_YEARS;
    }

    // No date and not a stealer: default to old
    return 10;
  });

  if (recencies.length === 0) return 10; // Default to old

  return recencies.reduce((sum, r) => sum + r, 0) / recencies.length;
}

/**
 * Get recommendation text based on severity
 * Aligned with remediation library - device isolation before password reset for infostealers
 */
function getRecommendationText(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'Isolate compromised devices, then reset passwords and revoke sessions';
    case 'MEDIUM':
      return 'Reset passwords, enable MFA, and review sign-in logs';
    case 'INFO':
      return 'Monitor for phishing attempts and consider security awareness training';
    default:
      return 'Review and monitor affected accounts';
  }
}

/**
 * Map severity to finding type
 */
function mapSeverityToFindingType(severity: string): string {
  switch (severity) {
    case 'CRITICAL':
      return 'CRITICAL_BREACH_EXPOSURE';
    case 'MEDIUM':
      return 'PASSWORD_BREACH_EXPOSURE';
    case 'INFO':
      return 'EMAIL_BREACH_EXPOSURE';
    default:
      return 'BREACH_EXPOSURE';
  }
}

/**
 * Generate breach intelligence summary
 */
function generateBreachSummary(results: BreachProbeSummary[]): {
  total_breached_accounts: number;
  leakcheck_total_accounts: number;
  combined_total_accounts: number;
  domains_with_breaches: number;
  high_risk_domains: number;
  privileged_accounts_found: boolean;
  unique_breach_sources: string[];
} {
  const summary = {
    total_breached_accounts: 0,
    leakcheck_total_accounts: 0,
    combined_total_accounts: 0,
    domains_with_breaches: 0,
    high_risk_domains: 0,
    privileged_accounts_found: false,
    unique_breach_sources: [] as string[]
  };
  
  const allSources = new Set<string>();
  
  results.forEach(result => {
    if ((result.breach_directory_success && result.breached_total > 0) || 
        (result.leakcheck_success && result.leakcheck_total > 0)) {
      
      summary.total_breached_accounts += result.breached_total;
      summary.leakcheck_total_accounts += result.leakcheck_total;
      summary.combined_total_accounts += result.combined_total;
      summary.domains_with_breaches += 1;
      
      if (result.high_risk_assessment) {
        summary.high_risk_domains += 1;
      }
      
      // Add unique breach sources from LeakCheck
      result.leakcheck_sources.forEach(source => allSources.add(source));
      
      // Check for privileged account indicators
      const privilegedPatterns = ['admin', 'ceo', 'root', 'sysadmin'];
      if (result.sample_usernames.some(username => 
        privilegedPatterns.some(pattern => username.toLowerCase().includes(pattern))
      )) {
        summary.privileged_accounts_found = true;
      }
    }
  });
  
  summary.unique_breach_sources = Array.from(allSources);
  
  return summary;
}

/**
 * Main breach directory probe function
 */
export async function runInfostealerProbe(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('infostealerProbe', async () => {
    const startTime = Date.now();
    
    log.info(`🔍 Starting infostealer probe for domain="${domain}" (LeakCheck), scan_id=${scanId}`);
    
    // Check for API key
    const leakCheckApiKey = process.env.LEAKCHECK_API_KEY;
    log.info(`🔑 LEAKCHECK_API_KEY: ${leakCheckApiKey ? 'SET' : 'MISSING'}`);
    
    if (!leakCheckApiKey) {
      log.info('LeakCheck API key not found - need LEAKCHECK_API_KEY environment variable');
      return 0;
    }
    
    // Initialize with empty breach data (we're not using BreachDirectory anymore)
    let breachData: BreachDirectoryResponse = { breached_total: 0, sample_usernames: [] };
    let leakCheckData: LeakCheckResponse = { success: false, found: 0, quota: 0, result: [] };
    
    // Query LeakCheck
    try {
      leakCheckData = await queryLeakCheck(domain, leakCheckApiKey);
      log.info(`✅ LeakCheck query successful: found ${leakCheckData.found} breaches`);
      log.info(`🎯 LeakCheck API returned data: ${JSON.stringify(leakCheckData.result?.slice(0, 2) || [])}`);
    } catch (error) {
      log.info(`❌ LeakCheck query failed: ${(error as Error).message}`);
      leakCheckData = { success: false, found: 0, quota: 0, result: [], error: (error as Error).message };
    }
    
    // Analyze combined results
    const analysis = analyzeCombinedBreach(breachData, leakCheckData);
    analysis.domain = domain;
    
    // Generate summary for reporting
    const summary = generateBreachSummary([analysis]);
    
    log.info(`Combined breach analysis complete: BD=${analysis.breached_total}, LC=${analysis.leakcheck_total}, Total=${analysis.combined_total}`);
    
    let findingsCount = 0;
    
    // Process breach findings with proper deduplication and severity logic
    if (analysis.leakcheck_results && analysis.leakcheck_results.length > 0) {
      // Step 1: Consolidate breaches by unique user
      const consolidatedUsers = consolidateBreachesByUser(analysis.leakcheck_results);

      log.info(`📊 Processing ${analysis.leakcheck_results.length} breach results for findings insertion`);
      log.info(`👥 Consolidated ${analysis.leakcheck_results.length} breach records into ${consolidatedUsers.length} unique users`);

      // Step 2: Split users who have BOTH infostealer AND regular breaches
      const splitUsers = splitMixedBreachUsers(consolidatedUsers);
      log.info(`🔀 Split mixed-breach users: ${consolidatedUsers.length} → ${splitUsers.length} records (separated infostealer from regular breaches)`);

      // Step 3: Filter out stale non-infostealer password breaches (older than 6 months)
      // Infostealers (CRITICAL) are always relevant; old password leaks (MEDIUM) are not actionable
      const BREACH_RECENCY_CUTOFF_MONTHS = 6;
      const filteredUsers = splitUsers.filter(user => {
        // Always keep CRITICAL (infostealer) and INFO (email-only) findings
        if (user.highestSeverity !== 'MEDIUM') return true;

        // For MEDIUM (password breaches), check if ANY breach is recent (within 12 months)
        const hasRecentBreach = user.breaches.some(b => {
          if (!b.source?.breach_date) return false; // No date = can't verify recency, exclude
          const recencyMonths = calculateBreachRecencyMonths(b.source.breach_date);
          return recencyMonths <= BREACH_RECENCY_CUTOFF_MONTHS;
        });

        if (!hasRecentBreach) {
          log.info(`⏭️ Skipping stale password breach for ${user.userId} (latest: ${user.latestBreach || 'unknown'})`);
        }
        return hasRecentBreach;
      });

      log.info(`📅 Recency filter: ${splitUsers.length} → ${filteredUsers.length} users (excluded ${splitUsers.length - filteredUsers.length} stale password breaches >12mo old)`);

      // Step 4: Group users by severity level
      const usersBySeverity = new Map<string, UserBreachRecord[]>();
      filteredUsers.forEach(user => {
        const severity = user.highestSeverity;
        if (!usersBySeverity.has(severity)) {
          usersBySeverity.set(severity, []);
        }
        usersBySeverity.get(severity)!.push(user);
      });

      // Step 5: Create separate artifact for each severity level (fixes severity inheritance bug)
      for (const [severityLevel, users] of usersBySeverity) {
        if (users.length === 0) continue;
        
        // Create artifact with correct severity for this specific level
        const artifactId = await insertArtifact({
          type: 'breach_directory_summary',
          val_text: `Breach probe: ${users.length} ${severityLevel.toLowerCase()} breach exposures for ${domain}`,
          severity: severityLevel as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
          meta: {
            scan_id: scanId,
            scan_module: 'breachDirectoryProbe',
            domain,
            breach_analysis: analysis,
            summary,
            breach_sources: analysis.leakcheck_sources,
            scan_duration_ms: Date.now() - startTime,
            severity_level: severityLevel,
            user_count: users.length
          }
        });
        
        // Create consolidated finding with all users of this severity
        const userList = users.map(u => u.userId).join(', ');

        // For CRITICAL findings driven by infostealers, ONLY show infostealer-related data
        // Don't pollute with unrelated breaches that have dates
        const isInfostealerDriven = severityLevel === 'CRITICAL' && users.some(u => hasInfostealerSource(u));

        let relevantSources: string[];
        let relevantTimelines: string[];

        if (isInfostealerDriven) {
          // Only include sources and timelines from actual infostealer breaches
          relevantSources = [...new Set(users.flatMap(u =>
            u.breaches
              .filter(b => isInfostealerSource(b))
              .map(b => b.source?.name)
              .filter(Boolean)
          ))];

          log.info(`🔍 INFOSTEALER FILTER: Original sources: ${[...new Set(users.flatMap(u => u.allSources))].join(', ')}`);
          log.info(`🔍 INFOSTEALER FILTER: Filtered to: ${relevantSources.join(', ')}`);

          // Infostealers typically have null dates, so timeline will be empty
          relevantTimelines = [];
        } else {
          // For non-infostealer findings, include all sources/timelines
          relevantSources = [...new Set(users.flatMap(u => u.allSources))];
          relevantTimelines = users
            .filter(u => u.earliestBreach || u.latestBreach)
            .map(u => {
              if (u.earliestBreach === u.latestBreach) {
                return u.earliestBreach;
              } else {
                return `${u.earliestBreach || 'unknown'} to ${u.latestBreach || 'unknown'}`;
              }
            })
            .filter((timeline, index, array) => array.indexOf(timeline) === index);
        }

        const allSources = relevantSources.join(', ');
        const allExposureTypes = [...new Set(users.flatMap(u => u.exposureTypes))].join(', ');
        const timelineInfo = relevantTimelines.join(', ');

        // Create detailed description with user information
        const userDetails = users.length <= 5
          ? users.map(u => u.userId).join(', ')
          : `${users.map(u => u.userId).slice(0, 5).join(', ')} and ${users.length - 5} more`;

        const exposurePlural = users.length === 1 ? 'exposure' : 'exposures';
        const detailedDescription = `${users.length} ${severityLevel.toLowerCase()} breach ${exposurePlural} found: ${userDetails}` +
          (allExposureTypes ? ` | Exposure types: ${allExposureTypes}` : '') +
          (allSources ? ` | Sources: ${allSources.slice(0, 100)}${allSources.length > 100 ? '...' : ''}` : '') +
          (timelineInfo ? ` | Timeline: ${timelineInfo}` : '');
        
        log.info(`💾 About to insert finding for ${severityLevel}: ${users.length} users, artifactId=${artifactId}`);

        // Calculate aggregate breach context from all users in this severity group
        const avgRecency = users.reduce((sum, u) => sum + calculateAverageRecency(u), 0) / users.length;
        const hasPrivileged = users.some(u => detectPrivilegeLevel(u.userId) !== 'normal');
        const mostPrivilegedUser = users.find(u => detectPrivilegeLevel(u.userId) !== 'normal');
        const privilegeLevel = mostPrivilegedUser ? detectPrivilegeLevel(mostPrivilegedUser.userId) : 'normal';

        // Determine most severe completeness across all users
        const completenessLevels = users.map(u => determineCredentialCompleteness(u));
        const credentialCompleteness = completenessLevels.includes('cookies') ? 'cookies' :
                                       completenessLevels.includes('password') ? 'password' : 'email';

        // Check if any user has infostealer source
        const infostealerSource = users.some(u => hasInfostealerSource(u));

        // Average breach count across users
        const avgBreachCount = users.reduce((sum, u) => sum + u.breaches.length, 0) / users.length;

        await insertFinding({
          artifact_id: artifactId,
          finding_type: mapSeverityToFindingType(severityLevel),
          recommendation: getRecommendationText(severityLevel),
          description: detailedDescription,
          scan_id: scanId,
          severity: severityLevel,
          type: mapSeverityToFindingType(severityLevel),
          data: {
            // Breach context metadata for EAL calculation
            breach_recency_years: avgRecency,
            user_privilege: privilegeLevel,
            credential_completeness: credentialCompleteness,
            infostealer_source: infostealerSource,
            breach_count_for_user: Math.round(avgBreachCount),
            // Additional context for reporting
            user_count: users.length,
            has_privileged_accounts: hasPrivileged,
            exposure_types: allExposureTypes,
            breach_sources: allSources,
            timeline: timelineInfo
          }
        });

        log.info(`✅ Successfully inserted ${severityLevel} finding for ${users.length} users`);
        
        findingsCount++;
        
        log.info(`Created ${severityLevel} finding for ${users.length} users: ${users.map(u => u.userId).slice(0, 5).join(', ')}${users.length > 5 ? '...' : ''}`);
      }
    }
    
    // Create summary artifact with overall stats
    const overallSeverity = analysis.combined_total >= 100 ? 'HIGH' : analysis.combined_total > 0 ? 'MEDIUM' : 'INFO';
    await insertArtifact({
      type: 'breach_directory_summary',
      val_text: `Breach probe complete: ${analysis.combined_total} total breached accounts (BD: ${analysis.breached_total}, LC: ${analysis.leakcheck_total}) for ${domain}`,
      severity: overallSeverity,
      meta: {
        scan_id: scanId,
        scan_module: 'breachDirectoryProbe',
        domain,
        breach_analysis: analysis,
        summary,
        breach_sources: analysis.leakcheck_sources,
        scan_duration_ms: Date.now() - startTime,
        is_summary: true
      }
    });
    
    const duration = Date.now() - startTime;
    log.info(`Breach probe completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  }, { scanId, target: domain });
}
