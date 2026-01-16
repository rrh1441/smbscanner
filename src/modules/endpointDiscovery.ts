/* =============================================================================
 * MODULE: endpointDiscovery.ts (Consolidated v5 – 2025‑06‑15)
 * =============================================================================
 * - Discovers endpoints via robots.txt, sitemaps, crawling, JS analysis, and brute-force
 * - Integrates endpoint visibility checking to label whether each discovered route is:
 *     • public GET‑only (no auth)  → likely static content
 *     • requires auth             → sensitive / attack surface
 *     • allows state‑changing verbs (POST / PUT / …)
 * - Consolidated implementation with no external module dependencies
 * =============================================================================
 */

import { httpRequest, httpGetText } from '../net/httpClient.js';
import { parse as parseHTML } from 'node-html-parser';
import { insertArtifact } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { URL } from 'node:url';

const log = createModuleLogger('endpointDiscovery');
import * as https from 'node:https';
import { parse as parseJS } from 'acorn';
import { simple } from 'acorn-walk';

// ---------- Configuration ----------------------------------------------------

const MAX_CRAWL_DEPTH = 1; // Reduced from 2 to prevent excessive crawling
const MAX_CONCURRENT_REQUESTS = 3; // Conservative concurrency to avoid overwhelming targets
const REQUEST_TIMEOUT = 8_000; // Conservative timeout for reliability
const DELAY_BETWEEN_CHUNKS_MS = 300; // Reasonable delay to avoid rate limiting
const MAX_JS_FILE_SIZE_BYTES = 1 * 1024 * 1024; // 1 MB
const VIS_PROBE_CONCURRENCY = 3; // Conservative concurrency
const VIS_PROBE_TIMEOUT = 8_000; // Conservative timeout

const readIntEnv = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const MAX_SITEMAP_URLS = readIntEnv('ENDPOINT_DISCOVERY_MAX_SITEMAP_URLS', 500);
const MAX_DISCOVERED_ENDPOINTS = readIntEnv('ENDPOINT_DISCOVERY_MAX_ENDPOINTS', 2000);

const PATH_INTERESTING_PATTERNS = [
  /^\/$/,
  /^\/api(?:\/|$)/i,
  /^\/graphql(?:\/|$)/i,
  /^\/-\/(?:|$)/,
  /^\/(oauth|auth|login|signin|session)(?:\/|$)/i,
  /^\/admin(?:\/|$)/i,
  /^\/uploads?(?:\/|$)/i,
  /^\/static(?:\/|$)/i,
  /^\/assets?(?:\/|$)/i,
];

const PATH_NOISE_PATTERNS = [
  /^\/(users?|members)(?:\/|$)/i,
  /^\/groups?(?:\/|$)/i,
  /^\/projects?(?:\/|$)/i,
  /^\/snippets?(?:\/|$)/i,
  /^\/explore(?:\/|$)/i,
  /^\/marketing(?:\/|$)/i,
  /^\/(customers?|company)(?:\/|$)/i,
  /^\/(blog|about|events|resources|solutions|partners|community)(?:\/|$)/i,
  /^\/(careers?|jobs?)(?:\/|$)/i,
  /^\/handbook(?:\/|$)/i,
];

// Anti-infinite operation protection - Balanced limits
const MAX_TOTAL_OPERATIONS = 100; // Smaller scope for faster completion
const MAX_OPERATION_TIME_MS = 20 * 1000; // 20 seconds - balanced

// ---------- Discovery Context (Thread-Safe State) ----------------------------

interface DiscoveryContext {
  discovered: Map<string, DiscoveredEndpoint>;
  webAssets: Map<string, WebAsset>;
  backendIdSet: Map<string, BackendIdentifier>;
  operationCount: number;
  scanStartTime: number;
  totalAssetSize: number;
  noiseSkipCount: number;
  endpointLimitLogged: boolean;
}

function createDiscoveryContext(): DiscoveryContext {
  return {
    discovered: new Map(),
    webAssets: new Map(),
    backendIdSet: new Map(),
    operationCount: 0,
    scanStartTime: Date.now(),
    totalAssetSize: 0,
    noiseSkipCount: 0,
    endpointLimitLogged: false,
  };
}

const ENDPOINT_WORDLIST = [
  // Critical security endpoints - reduced list for faster scanning
  'api',
  'admin',
  'auth',
  'login',
  'dashboard',
  'config',
  'user',
  'account',
  'upload',
  'debug',
  'test',
  'v1',
  'graphql',
  'oauth',
  'token',
  'session',
  'webhook'
]; // Reduced from 47 to 17 endpoints for faster scans

const AUTH_PROBE_HEADERS = [
  { Authorization: 'Bearer test' },
  { 'X-API-Key': 'test' },
  { 'x-access-token': 'test' },
  { 'X-Auth-Token': 'test' },
  { Cookie: 'session=test' },
  { 'X-Forwarded-User': 'test' }
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'curl/8.8.0',
  'python-requests/2.32.0',
  'Go-http-client/2.0'
];

const VERBS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
const HTTPS_AGENT = new https.Agent({ rejectUnauthorized: true });

// Backend identifier detection patterns
const RX = {
  firebaseHost  : /([a-z0-9-]{6,})\.(?:firebaseio\.com|(?:[a-z0-9-]+\.)?firebasedatabase\.app)/i,
  firebasePID   : /projectId["']\s*:\s*["']([a-z0-9-]{6,})["']/i,

  s3Host        : /([a-z0-9.\-]{3,63})\.s3[\.\-][a-z0-9\-\.]*\.amazonaws\.com/i,
  s3Path        : /s3[\.\-]amazonaws\.com\/([a-z0-9.\-]{3,63})/i,
  s3CompatHost  : /([a-z0-9.\-]{3,63})\.(?:r2\.cloudflarestorage\.com|digitaloceanspaces\.com|s3\.wasabisys\.com|s3\.[a-z0-9\-\.]*\.backblazeb2\.com)/i,
  bucketAssign  : /bucket["']\s*[:=]\s*["']([a-z0-9.\-]{3,63})["']/i,

  azureHost     : /([a-z0-9]{3,24})\.(?:blob|table|file)\.core\.windows\.net/i,
  azureAcct     : /storageAccount["']\s*[:=]\s*["']([a-z0-9]{3,24})["']/i,
  azureSAS      : /sv=\d{4}-\d{2}-\d{2}&ss=[bqtf]+&srt=[a-z]+&sp=[a-z]+&sig=[A-Za-z0-9%]+/i,

  gcsHost       : /storage\.googleapis\.com\/([a-z0-9.\-_]+)/i,
  gcsGs         : /gs:\/\/([a-z0-9.\-_]+)/i,
  gcsPath       : /\/b\/([a-z0-9.\-_]+)\/o/i,

  supabaseHost  : /https:\/\/([a-z0-9-]+)\.supabase\.(?:co|com)/i,

  realmHost     : /https:\/\/([a-z0-9-]+)\.realm\.mongodb\.com/i,

  // Modern serverless databases (2024+)
  planetscaleHost : /([a-z0-9-]+)\.(?:[a-z0-9-]+\.)?aws\.connect\.psdb\.cloud/i,
  planetscalePw   : /pscale_pw_[A-Za-z0-9_-]+/i,

  neonHost      : /([a-z0-9-]+)\.(?:[a-z0-9-]+\.)?aws\.neon\.tech/i,

  tursoHost     : /([a-z0-9-]+)\.turso\.io/i,
  tursoLibsql   : /libsql:\/\/([a-z0-9-]+)\.turso\.io/i,

  xataHost      : /([a-z0-9-]+)\.(?:[a-z0-9-]+\.)?xata\.sh/i,
  xataApi       : /https:\/\/([a-z0-9-]+)\.xata\.sh\/db/i,

  convexHost    : /([a-z0-9-]+)\.convex\.cloud/i,
  convexDeploy  : /https:\/\/([a-z0-9-]+)\.convex\.cloud/i,

  railwayHost   : /([a-z0-9-]+)\.railway\.app/i,

  // Vercel Storage (Postgres powered by Neon, KV powered by Upstash)
  vercelPostgres : /([a-z0-9-]+)-pooler\.(?:[a-z0-9-]+\.)?postgres\.vercel-storage\.com/i,
  vercelKV       : /VERCEL_KV_REST_API_URL|KV_REST_API_URL/i,

  // Upstash Redis (serverless Redis with REST API)
  upstashRedis   : /([a-z0-9-]+)\.upstash\.io/i,
  upstashToken   : /UPSTASH_REDIS_REST_TOKEN|UPSTASH_REDIS_REST_URL/i,

  connString    : /((?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^ \n\r'"`]+@[^\s'":\/\[\]]+(?::\d+)?\/[^\s'"]+)/i
} as const;

// ---------- Types ------------------------------------------------------------

interface DiscoveredEndpoint {
  url: string;
  path: string;
  confidence: 'high' | 'medium' | 'low';
  source:
    | 'robots.txt'
    | 'sitemap.xml'
    | 'crawl_link'
    | 'js_analysis'
    | 'wordlist_enum'
    | 'auth_probe';
  statusCode?: number;
  visibility?: 'public_get' | 'auth_required' | 'state_changing';
}

interface WebAsset {
  url: string;
  type: 'javascript' | 'css' | 'html' | 'json' | 'sourcemap' | 'other';
  size?: number;
  confidence: 'high' | 'medium' | 'low';
  source: 'crawl' | 'js_analysis' | 'sourcemap_hunt' | 'targeted_probe';
  content?: string;
  mimeType?: string;
}

interface SafeResult {
  ok: boolean;
  status?: number;
  data?: unknown;
  error?: string;
}

interface EndpointReport {
  url: string;
  publicGET: boolean;
  allowedVerbs: string[];
  authNeeded: boolean;
  notes: string[];
}

export interface BackendIdentifier {
  provider:
    | 'firebase' | 's3' | 'gcs' | 'azure' | 'supabase'
    | 'r2' | 'spaces' | 'b2' | 'realm'
    | 'planetscale' | 'neon' | 'turso' | 'xata' | 'convex' | 'railway'
    | 'vercel-postgres' | 'vercel-kv' | 'upstash';
  id : string;                        // bucket / project / account
  raw: string;                        // original match
  src: { file: string; line: number } // traceability
}

// ---------- Endpoint Visibility Checking ------------------------------------

async function safeVisibilityRequest(method: string, target: string, scanId?: string): Promise<any | null> {
  try {
    const response = await httpRequest({
      url: target,
      method: method as any,
      totalTimeoutMs: VIS_PROBE_TIMEOUT,
      connectTimeoutMs: 3000,
      firstByteTimeoutMs: 5000,
      idleSocketTimeoutMs: 5000,
      forceIPv4: true,
      maxRedirects: 5,
      scanId,
    });
    return {
      status: response.status,
      data: new TextDecoder('utf-8').decode(response.body),
      headers: response.headers
    };
  } catch {
    return null;
  }
}

async function checkEndpoint(urlStr: string, scanId?: string): Promise<EndpointReport> {
  const notes: string[] = [];
  const result: EndpointReport = {
    url: urlStr,
    publicGET: false,
    allowedVerbs: [],
    authNeeded: false,
    notes
  };

  /* Validate URL */
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    notes.push('Invalid URL');
    return result;
  }

  /* OPTIONS preflight to discover allowed verbs */
  const optRes = await safeVisibilityRequest('OPTIONS', urlStr, scanId);
  if (optRes) {
    const allow = (optRes.headers['allow'] as string | undefined)?.split(',');
    if (allow) {
      result.allowedVerbs = allow.map((v) => v.trim().toUpperCase()).filter(Boolean);
    }
  }

  /* Anonymous GET */
  const getRes = await safeVisibilityRequest('GET', urlStr, scanId);
  if (!getRes) {
    notes.push('GET request failed');
    return result;
  }
  result.publicGET = getRes.status === 200;

  /* Check auth headers and common tokens */
  if (getRes.status === 401 || getRes.status === 403) {
    result.authNeeded = true;
    return result;
  }
  const wwwAuth = getRes.headers['www-authenticate'];
  if (wwwAuth) {
    result.authNeeded = true;
    notes.push(`WWW-Authenticate: ${wwwAuth}`);
  }

  /* Test side‑effect verbs only if OPTIONS permitted them */
  for (const verb of VERBS.filter((v) => v !== 'GET')) {
    if (!result.allowedVerbs.includes(verb)) continue;
    const res = await safeVisibilityRequest(verb, urlStr, scanId);
    if (!res) continue;
    if (res.status < 400) {
      notes.push(`${verb} responded with status ${res.status}`);
    }
  }

  return result;
}

// ---------- Discovery Helpers -----------------------------------------------

const MAX_NOISE_LOGS = 20;

const passiveSources = new Set<DiscoveredEndpoint['source']>(['sitemap.xml', 'crawl_link', 'robots.txt']);

const hasReachedEndpointLimit = (ctx: DiscoveryContext): boolean => ctx.discovered.size >= MAX_DISCOVERED_ENDPOINTS;

const logEndpointLimitOnce = (ctx: DiscoveryContext): void => {
  if (ctx.endpointLimitLogged) return;
  ctx.endpointLimitLogged = true;
  log.warn({ maxEndpoints: MAX_DISCOVERED_ENDPOINTS }, 'Endpoint ceiling reached, suppressing additional paths');
};

const normalizePath = (path: string): string => {
  if (!path) return '/';
  return path.startsWith('/') ? path : `/${path}`;
};

const isInterestingPath = (path: string): boolean =>
  PATH_INTERESTING_PATTERNS.some((rx) => rx.test(path));

const looksNoisyPath = (path: string): boolean =>
  PATH_NOISE_PATTERNS.some((rx) => rx.test(path));

const shouldRecordPath = (ctx: DiscoveryContext, path: string, source: DiscoveredEndpoint['source']): boolean => {
  if (hasReachedEndpointLimit(ctx)) {
    logEndpointLimitOnce(ctx);
    return false;
  }

  if (passiveSources.has(source) && looksNoisyPath(path) && !isInterestingPath(path)) {
    if (ctx.noiseSkipCount < MAX_NOISE_LOGS) {
      log.debug({ source, path }, 'Skipping noisy path');
    }
    ctx.noiseSkipCount += 1;
    return false;
  }

  return true;
};

const getRandomUA = (): string =>
  USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];

const safeRequest = async (
  url: string,
  cfg: any = {},
  scanId?: string
): Promise<SafeResult> => {
  try {
    const res = await httpRequest({
      url,
      method: cfg.method || 'GET',
      headers: cfg.headers || { 'User-Agent': getRandomUA() },
      totalTimeoutMs: cfg.timeout || REQUEST_TIMEOUT,
      connectTimeoutMs: 3000,
      firstByteTimeoutMs: 5000,
      idleSocketTimeoutMs: 5000,
      forceIPv4: true,
      maxRedirects: cfg.maxRedirects || 5,
      maxBodyBytes: cfg.responseType === 'arraybuffer' ? 10_000_000 : 5_000_000,
      scanId,
    });
    const data = cfg.responseType === 'arraybuffer' ?
      res.body : new TextDecoder('utf-8').decode(res.body);
    return { ok: true, status: res.status, data };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown network error';
    return { ok: false, error: message };
  }
};

const addEndpoint = (
  ctx: DiscoveryContext,
  baseUrl: string,
  ep: Omit<DiscoveredEndpoint, 'url'>
): void => {
  const normalizedPath = normalizePath(ep.path);
  if (!shouldRecordPath(ctx, normalizedPath, ep.source)) return;
  if (ctx.discovered.has(normalizedPath)) return;

  const fullUrl = `${baseUrl}${normalizedPath}`;
  ctx.discovered.set(normalizedPath, { ...ep, path: normalizedPath, url: fullUrl });
  log.debug({ source: ep.source, path: normalizedPath, statusCode: ep.statusCode }, 'Endpoint discovered');
};

// Memory limits to prevent exhaustion
const MAX_WEB_ASSETS = 1000; // Maximum number of web assets to collect
const MAX_ASSET_SIZE = 2 * 1024 * 1024; // 2MB per asset
const MAX_TOTAL_ASSET_SIZE = 100 * 1024 * 1024; // 100MB total asset content

function recordBackend(ctx: DiscoveryContext, id: BackendIdentifier): void {
  const key = `${id.provider}:${id.id}`;
  if (!ctx.backendIdSet.has(key)) {
    ctx.backendIdSet.set(key, id);
    log.debug({ provider: id.provider, backendId: id.id, srcFile: id.src.file, srcLine: id.src.line }, 'Backend identifier discovered');
  }
}

const addWebAsset = (ctx: DiscoveryContext, asset: WebAsset): void => {
  if (ctx.webAssets.has(asset.url)) return;

  // Check memory limits
  if (ctx.webAssets.size >= MAX_WEB_ASSETS) {
    log.debug({ maxAssets: MAX_WEB_ASSETS, url: asset.url }, 'Asset limit reached, skipping');
    return;
  }

  const assetSize = asset.content?.length || asset.size || 0;
  if (assetSize > MAX_ASSET_SIZE) {
    log.debug({ assetSize, maxSize: MAX_ASSET_SIZE, url: asset.url }, 'Asset too large, skipping');
    return;
  }

  if (ctx.totalAssetSize + assetSize > MAX_TOTAL_ASSET_SIZE) {
    log.debug({ totalSize: ctx.totalAssetSize, maxTotalSize: MAX_TOTAL_ASSET_SIZE, url: asset.url }, 'Total asset size limit reached, skipping');
    return;
  }

  ctx.totalAssetSize += assetSize;
  ctx.webAssets.set(asset.url, asset);
  log.debug({ type: asset.type, url: asset.url, sizeBytes: assetSize, totalMB: Math.round(ctx.totalAssetSize/1024/1024) }, 'Web asset added');
};

const getAssetType = (url: string, mimeType?: string): WebAsset['type'] => {
  if (url.endsWith('.js.map')) return 'sourcemap';
  if (url.endsWith('.js') || mimeType?.includes('javascript')) return 'javascript';
  if (url.endsWith('.css') || mimeType?.includes('css')) return 'css';
  if (url.endsWith('.json') || mimeType?.includes('json')) return 'json';
  if (url.endsWith('.html') || url.endsWith('.htm') || mimeType?.includes('html')) return 'html';
  return 'other';
};

// ---------- Backend Identifier Extraction -----------------------------------

function extractViaRegex(ctx: DiscoveryContext, source: string, file: string): void {
  function m(rx: RegExp, prov: BackendIdentifier['provider']) {
    let match: RegExpExecArray | null;
    rx.lastIndex = 0;                                  // safety
    while ((match = rx.exec(source))) {
      const idx  = match.index;
      const lnum = source.slice(0, idx).split('\n').length;
      recordBackend(ctx, { provider: prov, id: match[1], raw: match[0],
                      src: { file, line: lnum } });
    }
  }

  m(RX.firebaseHost , 'firebase');  m(RX.firebasePID , 'firebase');
  m(RX.s3Host       , 's3');        m(RX.s3Path      , 's3');
  m(RX.s3CompatHost , 's3');        m(RX.bucketAssign, 's3');
  m(RX.azureHost    , 'azure');     m(RX.azureAcct   , 'azure');
  m(RX.gcsHost      , 'gcs');       m(RX.gcsGs       , 'gcs'); m(RX.gcsPath, 'gcs');
  m(RX.supabaseHost , 'supabase');
  m(RX.realmHost    , 'realm');
  // Modern serverless databases (2024+)
  m(RX.planetscaleHost, 'planetscale'); m(RX.planetscalePw, 'planetscale');
  m(RX.neonHost     , 'neon');
  m(RX.tursoHost    , 'turso');     m(RX.tursoLibsql  , 'turso');
  m(RX.xataHost     , 'xata');      m(RX.xataApi      , 'xata');
  m(RX.convexHost   , 'convex');    m(RX.convexDeploy , 'convex');
  m(RX.railwayHost  , 'railway');
  m(RX.vercelPostgres, 'vercel-postgres');
  m(RX.vercelKV     , 'vercel-kv');
  m(RX.upstashRedis , 'upstash');   m(RX.upstashToken , 'upstash');
  m(RX.connString   , 's3');   // generic DB strings → handled later
}

function extractViaAST(ctx: DiscoveryContext, source: string, file: string): void {
  let ast;
  try { ast = parseJS(source, { ecmaVersion: 'latest' }); }
  catch { return; }

  simple(ast as any, {
    Literal(node: any) {
      if (typeof node.value !== 'string') return;
      const v = node.value as string;
      extractViaRegex(ctx, v, file);                // reuse regex on literals
    }
  });
}

// ---------- Passive Discovery ------------------------------------------------

const parseRobotsTxt = async (ctx: DiscoveryContext, baseUrl: string, scanId?: string): Promise<void> => {
  const res = await safeRequest(`${baseUrl}/robots.txt`, {
    timeout: REQUEST_TIMEOUT,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  }, scanId);
  if (!res.ok || typeof res.data !== 'string') return;

  for (const raw of res.data.split('\n')) {
    const [directiveRaw, pathRaw] = raw.split(':').map((p) => p.trim());
    if (!directiveRaw || !pathRaw) continue;

    const directive = directiveRaw.toLowerCase();
    if ((directive === 'disallow' || directive === 'allow') && pathRaw.startsWith('/')) {
      addEndpoint(ctx, baseUrl, {
        path: pathRaw,
        confidence: 'medium',
        source: 'robots.txt'
      });
    } else if (directive === 'sitemap') {
      await parseSitemap(ctx, new URL(pathRaw, baseUrl).toString(), baseUrl, scanId);
    }
  }
};

const parseSitemap = async (ctx: DiscoveryContext, sitemapUrl: string, baseUrl: string, scanId?: string): Promise<void> => {
  const res = await safeRequest(sitemapUrl, {
    timeout: REQUEST_TIMEOUT,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  }, scanId);
  if (!res.ok || typeof res.data !== 'string') return;

  const root = parseHTML(res.data);
  const locElems = root.querySelectorAll('loc');
  let processed = 0;
  for (const el of locElems) {
    if (processed >= MAX_SITEMAP_URLS) {
      log.debug({ maxUrls: MAX_SITEMAP_URLS, sitemapUrl }, 'Sitemap limit reached');
      break;
    }

    processed += 1;
    try {
      const locText = el.text.trim();
      if (!locText) continue;
      const url = new URL(locText);
      addEndpoint(ctx, baseUrl, {
        path: url.pathname,
        confidence: 'high',
        source: 'sitemap.xml'
      });
      if (hasReachedEndpointLimit(ctx)) break;
    } catch {
      /* ignore bad URL */
    }
  }
};

// ---------- Active Discovery -------------------------------------------------

const analyzeJsFile = async (ctx: DiscoveryContext, jsUrl: string, baseUrl: string, scanId?: string): Promise<void> => {
  const res = await safeRequest(jsUrl, {
    timeout: REQUEST_TIMEOUT,
    maxContentLength: MAX_JS_FILE_SIZE_BYTES,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  }, scanId);
  if (!res.ok || typeof res.data !== 'string') return;

  // Save the JavaScript file as a web asset for secret scanning
  addWebAsset(ctx, {
    url: jsUrl,
    type: 'javascript',
    size: res.data.length,
    confidence: 'high',
    source: 'js_analysis',
    content: res.data.length > 50000 ? res.data.substring(0, 50000) + '...[truncated]' : res.data,
    mimeType: 'application/javascript'
  });

  // Extract backend identifiers from JavaScript
  extractViaRegex(ctx, res.data, jsUrl);
  extractViaAST(ctx, res.data, jsUrl);

  // Hunt for corresponding source map
  await huntSourceMap(ctx, jsUrl, baseUrl, scanId);

  // Extract endpoint patterns (existing functionality)
  const re = /['"`](\/[a-zA-Z0-9\-._/]*(?:api|auth|v\d|graphql|jwt|token)[a-zA-Z0-9\-._/]*)['"`]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(res.data)) !== null) {
    addEndpoint(ctx, baseUrl, {
      path: m[1],
      confidence: 'medium',
      source: 'js_analysis'
    });
  }

  // Look for potential data endpoints that might contain secrets
  const dataEndpointRe = /fetch\s*\(['"`]([^'"`]+)['"`]\)|axios\.[get|post|put|delete]+\(['"`]([^'"`]+)['"`]\)|\$\.get\(['"`]([^'"`]+)['"`]\)/g;
  let dataMatch: RegExpExecArray | null;
  while ((dataMatch = dataEndpointRe.exec(res.data)) !== null) {
    const endpoint = dataMatch[1] || dataMatch[2] || dataMatch[3];
    if (endpoint && endpoint.startsWith('/')) {
      addEndpoint(ctx, baseUrl, {
        path: endpoint,
        confidence: 'high',
        source: 'js_analysis'
      });
    }
  }
};

// Hunt for source maps that might expose backend secrets
const huntSourceMap = async (ctx: DiscoveryContext, jsUrl: string, baseUrl: string, scanId?: string): Promise<void> => {
  try {
    const sourceMapUrl = jsUrl + '.map';
    const res = await safeRequest(sourceMapUrl, {
      timeout: REQUEST_TIMEOUT,
      maxContentLength: 10 * 1024 * 1024, // 10MB max for source maps
      headers: { 'User-Agent': getRandomUA() },
      validateStatus: () => true
    }, scanId);

    if (res.ok && typeof res.data === 'string') {
      log.debug({ sourceMapUrl }, 'Source map found');
      addWebAsset(ctx, {
        url: sourceMapUrl,
        type: 'sourcemap',
        size: res.data.length,
        confidence: 'high',
        source: 'sourcemap_hunt',
        content: res.data.length > 100000 ? res.data.substring(0, 100000) + '...[truncated]' : res.data,
        mimeType: 'application/json'
      });
    }
  } catch (error) {
    // Source map hunting is opportunistic - don't log errors
  }
};

const crawlPage = async (
  ctx: DiscoveryContext,
  url: string,
  depth: number,
  baseUrl: string,
  seen: Set<string>,
  scanId?: string
): Promise<void> => {
  // Circuit breaker: prevent infinite operations
  ctx.operationCount++;
  if (ctx.operationCount > MAX_TOTAL_OPERATIONS) {
    log.debug({ maxOps: MAX_TOTAL_OPERATIONS, operationCount: ctx.operationCount }, 'Operation limit reached, stopping crawl');
    return;
  }

  if (ctx.scanStartTime > 0 && Date.now() - ctx.scanStartTime > MAX_OPERATION_TIME_MS) {
    log.debug({ maxTimeMs: MAX_OPERATION_TIME_MS, elapsedMs: Date.now() - ctx.scanStartTime }, 'Time limit reached, stopping crawl');
    return;
  }

  if (depth > MAX_CRAWL_DEPTH || seen.has(url)) return;
  seen.add(url);

  log.debug({ url, depth }, 'Starting crawl request');

  const requestStart = Date.now();
  const res = await safeRequest(url, {
    timeout: REQUEST_TIMEOUT,
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  }, scanId);

  const requestTime = Date.now() - requestStart;
  log.debug({ url, requestTimeMs: requestTime }, 'Crawl request completed');

  if (!res.ok || typeof res.data !== 'string') {
    log.debug({ url, ok: res.ok }, 'Crawl request failed or invalid response');
    return;
  }

  // Save HTML content as web asset for secret scanning
  const contentType = typeof res.data === 'object' && res.data && 'headers' in res.data ?
    (res.data as any).headers?.['content-type'] || '' : '';
  addWebAsset(ctx, {
    url,
    type: getAssetType(url, contentType),
    size: res.data.length,
    confidence: 'high',
    source: 'crawl',
    content: res.data.length > 100000 ? res.data.substring(0, 100000) + '...[truncated]' : res.data,
    mimeType: contentType
  });

  // Extract backend identifiers from HTML content
  extractViaRegex(ctx, res.data, url);

  const root = parseHTML(res.data);
  const pageLinks = new Set<string>();

  root.querySelectorAll('a[href]').forEach((a) => {
    try {
      const abs = new URL(a.getAttribute('href')!, baseUrl).toString();
      if (abs.startsWith(baseUrl)) {
        addEndpoint(ctx, baseUrl, {
          path: new URL(abs).pathname,
          confidence: 'low',
          source: 'crawl_link'
        });
        pageLinks.add(abs);
      }
    } catch {
      /* ignore */
    }
  });

  root.querySelectorAll('script[src]').forEach((s) => {
    try {
      const abs = new URL(s.getAttribute('src')!, baseUrl).toString();
      if (abs.startsWith(baseUrl)) void analyzeJsFile(ctx, abs, baseUrl, scanId);
    } catch {
      /* ignore */
    }
  });

  // Extract CSS files
  root.querySelectorAll('link[rel="stylesheet"][href]').forEach((link) => {
    try {
      const abs = new URL(link.getAttribute('href')!, baseUrl).toString();
      if (abs.startsWith(baseUrl)) {
        void analyzeCssFile(ctx, abs, baseUrl, scanId);
      }
    } catch {
      /* ignore */
    }
  });

  // Look for inline scripts with potential secrets
  root.querySelectorAll('script:not([src])').forEach((script, index) => {
    const content = script.innerHTML;
    if (content.length > 100) { // Only save substantial inline scripts
      const inlineUrl = `${url}#inline-script-${index}`;
      addWebAsset(ctx, {
        url: inlineUrl,
        type: 'javascript',
        size: content.length,
        confidence: 'high',
        source: 'crawl',
        content: content.length > 10000 ? content.substring(0, 10000) + '...[truncated]' : content,
        mimeType: 'application/javascript'
      });
      // Extract backend identifiers from inline scripts
      extractViaRegex(ctx, content, inlineUrl);
      extractViaAST(ctx, content, inlineUrl);
    }
  });

  // Process links in parallel batches to avoid sequential blocking
  const linkArray = Array.from(pageLinks);
  const BATCH_SIZE = 5;
  const MAX_PAGES_PER_CRAWL = 10; // Reduced from 50 to 10 to prevent excessive crawling

  // Stop if we've already crawled too many pages
  if (seen.size >= MAX_PAGES_PER_CRAWL) {
    log.debug({ maxPages: MAX_PAGES_PER_CRAWL, seenSize: seen.size }, 'Reached max pages limit, stopping crawl');
    return;
  }

  // Process links in batches with better error handling and aggressive timeouts
  log.debug({ linkCount: linkArray.length, seenSize: seen.size, maxPages: MAX_PAGES_PER_CRAWL }, 'Processing links in batches');

  for (let i = 0; i < linkArray.length && seen.size < MAX_PAGES_PER_CRAWL; i += BATCH_SIZE) {
    const batch = linkArray.slice(i, Math.min(i + BATCH_SIZE, linkArray.length));
    const batchNum = Math.floor(i/BATCH_SIZE) + 1;
    const totalBatches = Math.ceil(linkArray.length/BATCH_SIZE);
    log.debug({ batchNum, totalBatches, batchSize: batch.length }, 'Processing batch');

    const batchStart = Date.now();
    try {
      // Add aggressive timeout to each batch
      await Promise.race([
        Promise.allSettled(
          batch.map(link =>
            crawlPage(ctx, link, depth + 1, baseUrl, seen, scanId).catch(err => {
              log.warn({ err, link }, 'Error crawling link');
            })
          )
        ),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Batch timeout after 5s`)), 5000)
        )
      ]);

      const batchTime = Date.now() - batchStart;
      log.debug({ batchNum, batchTimeMs: batchTime, seenSize: seen.size }, 'Batch completed');

      // Check operation limits more frequently
      if (ctx.operationCount > MAX_TOTAL_OPERATIONS) {
        log.debug({ operationCount: ctx.operationCount, maxOps: MAX_TOTAL_OPERATIONS }, 'Operation limit reached during batch processing');
        break;
      }

    } catch (error) {
      log.warn({ err: error, batchNum }, 'Batch timeout or failure');
      break; // Stop processing if a batch times out
    }
  }
};

// Analyze CSS files for potential secrets (background URLs with tokens, etc.)
const analyzeCssFile = async (ctx: DiscoveryContext, cssUrl: string, baseUrl: string, scanId?: string): Promise<void> => {
  const res = await safeRequest(cssUrl, {
    timeout: REQUEST_TIMEOUT,
    maxContentLength: 2 * 1024 * 1024, // 2MB max for CSS
    headers: { 'User-Agent': getRandomUA() },
    validateStatus: () => true
  }, scanId);
  if (!res.ok || typeof res.data !== 'string') return;

  addWebAsset(ctx, {
    url: cssUrl,
    type: 'css',
    size: res.data.length,
    confidence: 'medium',
    source: 'crawl',
    content: res.data.length > 50000 ? res.data.substring(0, 50000) + '...[truncated]' : res.data,
    mimeType: 'text/css'
  });
};

// ---------- Brute-Force / Auth Probe -----------------------------------------

const bruteForce = async (ctx: DiscoveryContext, baseUrl: string, scanId?: string): Promise<void> => {
  // Circuit breaker: check operation limits
  if (ctx.operationCount > MAX_TOTAL_OPERATIONS * 0.8) { // Reserve 20% for other operations
    log.debug({ operationCount: ctx.operationCount, threshold: MAX_TOTAL_OPERATIONS * 0.8 }, 'Skipping brute force - operation limit approaching');
    return;
  }

  const tasks = ENDPOINT_WORDLIST.flatMap((word) => {
    const path = `/${word}`;
    const uaHeader = { 'User-Agent': getRandomUA() };

    const basic = {
      promise: safeRequest(`${baseUrl}${path}`, {
        method: 'HEAD',
        timeout: REQUEST_TIMEOUT,
        headers: uaHeader,
        validateStatus: () => true
      }, scanId),
      path,
      source: 'wordlist_enum' as const
    };

    const auths = AUTH_PROBE_HEADERS.map((h) => ({
      promise: safeRequest(`${baseUrl}${path}`, {
        method: 'GET',
        timeout: REQUEST_TIMEOUT,
        headers: { ...uaHeader, ...h },
        validateStatus: () => true
      }, scanId),
      path,
      source: 'auth_probe' as const
    }));

    return [basic, ...auths];
  });

  for (let i = 0; i < tasks.length; i += MAX_CONCURRENT_REQUESTS) {
    const slice = tasks.slice(i, i + MAX_CONCURRENT_REQUESTS);
    const settled = await Promise.all(slice.map((t) => t.promise));

    settled.forEach((res, idx) => {
      if (!res.ok) return;
      const { path, source } = slice[idx];
      if (res.status !== undefined && (res.status < 400 || res.status === 401 || res.status === 403)) {
        addEndpoint(ctx, baseUrl, {
          path,
          confidence: 'low',
          source,
          statusCode: res.status
        });
      }
    });

    await new Promise((r) => setTimeout(r, DELAY_BETWEEN_CHUNKS_MS));
  }
};

// ---------- Visibility Probe -------------------------------------------------

async function enrichVisibility(endpoints: DiscoveredEndpoint[], scanId?: string): Promise<void> {
  const worker = async (ep: DiscoveredEndpoint): Promise<void> => {
    try {
      const rep: EndpointReport = await checkEndpoint(ep.url, scanId);
      if (rep.authNeeded) {
        ep.visibility = 'auth_required';
      } else if (rep.allowedVerbs.some((v: string) => v !== 'GET')) {
        ep.visibility = 'state_changing';
      } else {
        ep.visibility = 'public_get';
      }
    } catch (err) {
      /* swallow errors – leave visibility undefined */
    }
  };

  // Process endpoints in chunks with controlled concurrency
  for (let i = 0; i < endpoints.length; i += VIS_PROBE_CONCURRENCY) {
    const chunk = endpoints.slice(i, i + VIS_PROBE_CONCURRENCY);
    const chunkTasks = chunk.map(worker);
    await Promise.allSettled(chunkTasks);
  }
}

// Target high-value paths that might contain secrets
const probeHighValuePaths = async (ctx: DiscoveryContext, baseUrl: string, scanId?: string): Promise<void> => {
  const highValuePaths = [
    '/',  // Index page
    '/index.html',  // Explicit index
    '/.env',
    '/config.json',
    '/app.config.json',
    '/settings.json',
    '/manifest.json',
    '/.env.local',
    '/.env.production',
    '/api/config',
    '/api/settings',
    '/_next/static/chunks/webpack.js',
    '/static/js/main.js',
    '/assets/config.js',
    '/config.js',
    '/build/config.json'
  ];

  const tasks = highValuePaths.map(async (path) => {
    try {
      const fullUrl = `${baseUrl}${path}`;
      const res = await safeRequest(fullUrl, {
        timeout: 5000,
        maxContentLength: 5 * 1024 * 1024, // 5MB max
        headers: { 'User-Agent': getRandomUA() },
        validateStatus: () => true
      }, scanId);

      if (res.ok && res.data) {
        const contentType = '';
        addWebAsset(ctx, {
          url: fullUrl,
          type: getAssetType(fullUrl, contentType),
          size: typeof res.data === 'string' ? res.data.length : 0,
          confidence: 'high',
          source: 'targeted_probe',
          content: typeof res.data === 'string' ?
            (res.data.length > 50000 ? res.data.substring(0, 50000) + '...[truncated]' : res.data) :
            '[binary content]',
          mimeType: contentType
        });

        log.debug({ url: fullUrl }, 'High-value asset found');
      }
    } catch {
      // Expected for most paths - don't log
    }
  });

  await Promise.all(tasks);
};

// ---------- Main Export ------------------------------------------------------

export async function runEndpointDiscovery(job: { domain: string; scanId?: string }): Promise<number> {
  const start = Date.now();
  const baseUrl = `https://${job.domain}`;
  log.info({ domain: job.domain, scanId: job.scanId, baseUrl }, 'Starting endpoint discovery');

  // Create isolated context for this scan (thread-safe)
  const ctx = createDiscoveryContext();
  log.debug('Initialized discovery context');

  // Existing discovery methods with timeout protection
  if (!hasReachedEndpointLimit(ctx)) {
    log.debug('Starting parseRobotsTxt');
    try {
      await Promise.race([
        parseRobotsTxt(ctx, baseUrl, job.scanId),
        new Promise((_, reject) => setTimeout(() => reject(new Error('parseRobotsTxt timeout')), 30000))
      ]);
      log.debug('parseRobotsTxt completed');
    } catch (e) {
      log.warn({ err: e }, 'parseRobotsTxt failed or timed out');
    }
  } else {
    log.debug('Skipping parseRobotsTxt - endpoint ceiling reached');
  }

  if (!hasReachedEndpointLimit(ctx)) {
    log.debug('Starting parseSitemap');
    try {
      await Promise.race([
        parseSitemap(ctx, `${baseUrl}/sitemap.xml`, baseUrl, job.scanId),
        new Promise((_, reject) => setTimeout(() => reject(new Error('parseSitemap timeout')), 30000))
      ]);
      log.debug('parseSitemap completed');
    } catch (e) {
      log.warn({ err: e }, 'parseSitemap failed or timed out');
    }
  } else {
    log.debug('Skipping parseSitemap - endpoint ceiling reached');
  }

  if (!hasReachedEndpointLimit(ctx)) {
    log.debug('Starting crawlPage');
    try {
      await Promise.race([
        crawlPage(ctx, baseUrl, 1, baseUrl, new Set<string>(), job.scanId),
        new Promise((_, reject) => setTimeout(() => reject(new Error('crawlPage timeout')), 15000))
      ]);
      log.debug({ endpointCount: ctx.discovered.size }, 'crawlPage completed');
    } catch (e) {
      log.warn({ err: e }, 'crawlPage failed or timed out');
    }
  } else {
    log.debug('Skipping crawlPage - endpoint ceiling reached');
  }

  if (!hasReachedEndpointLimit(ctx)) {
    log.debug('Starting bruteForce enumeration');
    try {
      await Promise.race([
        bruteForce(ctx, baseUrl, job.scanId),
        new Promise((_, reject) => setTimeout(() => reject(new Error('bruteForce timeout')), 5000))
      ]);
      log.debug({ totalEndpoints: ctx.discovered.size }, 'bruteForce completed');
    } catch (e) {
      log.warn({ err: e }, 'bruteForce failed or timed out');
    }
  } else {
    log.debug('Skipping bruteForce - endpoint ceiling reached');
  }

  // Probe high-value paths for secrets
  if (!hasReachedEndpointLimit(ctx)) {
    log.debug('Starting probeHighValuePaths');
    try {
      await probeHighValuePaths(ctx, baseUrl, job.scanId);
      log.debug('probeHighValuePaths completed');
    } catch (e) {
      log.warn({ err: e }, 'probeHighValuePaths failed');
    }
  } else {
    log.debug('Skipping probeHighValuePaths - endpoint ceiling reached');
  }

  const endpoints = [...ctx.discovered.values()];
  const assets = [...ctx.webAssets.values()];
  const backendArr = [...ctx.backendIdSet.values()];
  log.debug({ endpointCount: endpoints.length, assetCount: assets.length, backendCount: backendArr.length }, 'Collection complete');
  if (ctx.noiseSkipCount > MAX_NOISE_LOGS) {
    log.debug({ noiseSkipCount: ctx.noiseSkipCount, maxLogged: MAX_NOISE_LOGS }, 'Noisy paths skipped');
  }

  /* ------- Visibility enrichment (public/static vs. auth) ---------------- */
  log.debug({ endpointCount: ctx.discovered.size }, 'Starting visibility enrichment');
  try {
    await enrichVisibility(endpoints, job.scanId);
    log.debug('enrichVisibility completed');
  } catch (e) {
    log.warn({ err: e }, 'enrichVisibility failed');
  }

  // Save discovered endpoints
  if (endpoints.length) {
    await insertArtifact({
      type: 'discovered_endpoints',
      val_text: `Discovered ${endpoints.length} unique endpoints for ${job.domain}`,
      severity: 'INFO',
      meta: {
        scan_id: job.scanId,
        scan_module: 'endpointDiscovery',
        endpoints
      }
    });
  }

  // Save discovered web assets for secret scanning
  if (assets.length) {
    await insertArtifact({
      type: 'discovered_web_assets',
      val_text: `Discovered ${assets.length} web assets for secret scanning on ${job.domain}`,
      severity: 'INFO',
      meta: {
        scan_id: job.scanId,
        scan_module: 'endpointDiscovery',
        assets,
        asset_breakdown: {
          javascript: assets.filter(a => a.type === 'javascript').length,
          css: assets.filter(a => a.type === 'css').length,
          html: assets.filter(a => a.type === 'html').length,
          json: assets.filter(a => a.type === 'json').length,
          sourcemap: assets.filter(a => a.type === 'sourcemap').length,
          other: assets.filter(a => a.type === 'other').length
        }
      }
    });
  }

  // Save discovered backend identifiers
  if (backendArr.length) {
    await insertArtifact({
      type: 'backend_identifiers',
      severity: 'INFO',
      val_text: `Identified ${backendArr.length} backend IDs on ${job.domain}`,
      meta: {
        scan_id: job.scanId,
        scan_module: 'endpointDiscovery',
        backend_ids: backendArr
      }
    });
  }

  const durationMs = Date.now() - start;
  log.info({ domain: job.domain, endpointCount: endpoints.length, assetCount: assets.length, backendCount: backendArr.length, durationMs }, 'Endpoint discovery complete');
  // Return 0 as this module doesn't create findings, only artifacts
  return 0;
}
