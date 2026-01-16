/**
 * Centralized environment configuration for the security scanning pipeline
 *
 * All environment variables should be accessed through this module to ensure:
 * - Type safety with proper parsing
 * - Sensible defaults
 * - Documentation of available configuration
 * - Single source of truth
 */

// =============================================================================
// Helper Functions
// =============================================================================

function parseIntEnv(key: string, defaultValue: number): number {
  const value = process.env[key];
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

function parseFloatEnv(key: string, defaultValue: number): number {
  const value = process.env[key];
  if (!value) return defaultValue;
  const parsed = parseFloat(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

function parseBoolEnv(key: string, defaultValue: boolean): boolean {
  const value = process.env[key];
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

function parseStringEnv(key: string, defaultValue: string): string {
  return process.env[key] ?? defaultValue;
}

/**
 * Parse a comma-separated environment variable into an array of strings
 * @param key - Environment variable name
 * @param fallback - Default values if not set
 * @returns Array of trimmed, non-empty strings
 */
export function parseCsvEnv(key: string, fallback: string[]): string[] {
  const raw = process.env[key];
  if (!raw) return fallback;
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

// =============================================================================
// Runtime Environment
// =============================================================================

export const env = {
  /** Current environment: 'production' | 'development' | 'test' */
  NODE_ENV: parseStringEnv('NODE_ENV', 'development'),
  /** Is production environment */
  isProduction: process.env.NODE_ENV === 'production',
  /** Is development environment */
  isDevelopment: process.env.NODE_ENV !== 'production',
  /** Is test environment */
  isTest: process.env.NODE_ENV === 'test',
  /** Log level: 'debug' | 'info' | 'warn' | 'error' */
  LOG_LEVEL: parseStringEnv('LOG_LEVEL', 'info').toLowerCase(),
} as const;

// =============================================================================
// Database Configuration
// =============================================================================

export const database = {
  /** Primary database connection URL */
  DATABASE_URL: parseStringEnv('DATABASE_URL', 'postgresql://localhost/scanner_local'),
  /** PgBouncer connection URL (if using connection pooler) */
  PGBOUNCER_URL: process.env.PGBOUNCER_URL,
  /** Direct Postgres connection details */
  POSTGRES_USER: parseStringEnv('POSTGRES_USER', process.env.USER ?? 'postgres'),
  POSTGRES_HOST: parseStringEnv('POSTGRES_HOST', '127.0.0.1'),
  POSTGRES_DB: parseStringEnv('POSTGRES_DB', 'scanner_local'),
  POSTGRES_PASSWORD: parseStringEnv('POSTGRES_PASSWORD', ''),
  POSTGRES_PORT: parseIntEnv('POSTGRES_PORT', 5432),
  /** Pool configuration */
  PG_POOL_MAX: parseIntEnv('PG_POOL_MAX', 10),
  PG_IDLE_TIMEOUT_MS: parseIntEnv('PG_IDLE_TIMEOUT_MS', 0),
  PG_CONNECTION_TIMEOUT_MS: parseIntEnv('PG_CONNECTION_TIMEOUT_MS', 5000),
  PG_STATEMENT_TIMEOUT_MS: parseIntEnv('PG_STATEMENT_TIMEOUT_MS', 30000),
  PG_KEEPALIVE_DELAY_MS: parseIntEnv('PG_KEEPALIVE_DELAY_MS', 10000),
  /** Database lease configuration for resource management */
  DB_LEASE_TTL_MS: parseIntEnv('DB_LEASE_TTL_MS', 30000),
  DB_LEASE_WAIT_TIMEOUT_MS: parseIntEnv('DB_LEASE_WAIT_TIMEOUT_MS', 60000),
  DB_LEASE_LIMIT: parseIntEnv('DB_LEASE_LIMIT', parseIntEnv('DB_CONNECTION_LIMIT', 16)),
} as const;

// =============================================================================
// Redis Configuration
// =============================================================================

export const redis = {
  /** Redis connection URL (overrides host/port if set) */
  REDIS_URL: process.env.REDIS_URL,
  /** Redis host */
  REDIS_HOST: parseStringEnv('REDIS_HOST', '127.0.0.1'),
  /** Redis port */
  REDIS_PORT: parseIntEnv('REDIS_PORT', 6379),
  /** Redis database number */
  REDIS_DB: parseIntEnv('REDIS_DB', 0),
  /** Redis authentication */
  REDIS_USERNAME: process.env.REDIS_USERNAME,
  REDIS_PASSWORD: process.env.REDIS_PASSWORD,
} as const;

// =============================================================================
// Cloud Configuration (Optional - for GCP deployments)
// =============================================================================

export const gcp = {
  /** Google Cloud project ID (set via GOOGLE_CLOUD_PROJECT env var) */
  PROJECT_ID: parseStringEnv('GOOGLE_CLOUD_PROJECT', ''),
  /** Cloud Tasks location */
  CLOUD_TASKS_LOCATION: parseStringEnv('CLOUD_TASKS_LOCATION', 'us-central1'),
  /** Cloud Tasks queue name */
  CLOUD_TASKS_QUEUE: parseStringEnv('CLOUD_TASKS_QUEUE', 'scan-queue'),
  /** Worker service URL for Cloud Tasks */
  WORKER_URL: process.env.WORKER_URL,
  /** Cloud storage bucket for scan artifacts (set via GCS_BUCKET_NAME env var) */
  GCS_BUCKET_NAME: parseStringEnv('GCS_BUCKET_NAME', ''),
  /** Knative service name (set by Cloud Run) */
  K_SERVICE: process.env.K_SERVICE,
  /** Has GCP credentials configured */
  hasCredentials: !!(process.env.GOOGLE_APPLICATION_CREDENTIALS || process.env.GOOGLE_CLOUD_PROJECT),
} as const;

// =============================================================================
// Scan Configuration
// =============================================================================

export const scan = {
  /** Maximum concurrent scans */
  MAX_CONCURRENT_SCANS: parseIntEnv('MAX_CONCURRENT_SCANS', 2),
  /** Global scan timeout in milliseconds */
  SCAN_MAX_MS: parseIntEnv('SCAN_MAX_MS', 120000),
  /** Default module timeout if not specified */
  MODULE_TIMEOUT_MS_DEFAULT: parseIntEnv('MODULE_TIMEOUT_MS_DEFAULT', 15000),
  /** Scan queue name */
  SCAN_QUEUE_NAME: parseStringEnv('SCAN_QUEUE_NAME', 'scan-queue'),
  /** Resource sweep interval */
  RESOURCE_SWEEP_INTERVAL_MS: parseIntEnv('RESOURCE_SWEEP_INTERVAL_MS', 30000),
} as const;

// =============================================================================
// Module Timeouts
// =============================================================================

export const moduleTimeouts = {
  shodan_scan: parseIntEnv('MODULE_TIMEOUT_SHODAN', 5000),
  whois_wrapper: parseIntEnv('MODULE_TIMEOUT_WHOIS', 5000),
  spf_dmarc: parseIntEnv('MODULE_TIMEOUT_SPF', 10000),
  tech_stack_scan: parseIntEnv('MODULE_TIMEOUT_TECH', 10000),
  abuse_intel_scan: parseIntEnv('MODULE_TIMEOUT_ABUSE', 5000),
  client_secret_scanner: parseIntEnv('MODULE_TIMEOUT_CLIENT_SECRETS', 5000),
  backend_exposure_scanner: parseIntEnv('MODULE_TIMEOUT_BACKEND', 5000),
  denial_wallet_scan: parseIntEnv('MODULE_TIMEOUT_DENIAL_WALLET', 7000),
  database_api_exposure: parseIntEnv('MODULE_TIMEOUT_DATABASE_API', 10000),
  lightweight_backend_scan: parseIntEnv('MODULE_TIMEOUT_LIGHTWEIGHT_BACKEND', 6000),
  accessibility_lightweight: parseIntEnv('MODULE_TIMEOUT_ACCESSIBILITY', 10000),
  infostealer_probe: parseIntEnv('MODULE_TIMEOUT_INFOSTEALER', 10000),
  config_exposure: parseIntEnv('MODULE_TIMEOUT_CONFIG', 10000),
  tls_scan: parseIntEnv('MODULE_TIMEOUT_TLS', 20000),
  endpoint_discovery: parseIntEnv('MODULE_TIMEOUT_ENDPOINTS', 20000),
  lightweight_cve_check: parseIntEnv('MODULE_TIMEOUT_CVE', 10000),
  asset_correlator: parseIntEnv('MODULE_TIMEOUT_ASSET', 5000),
  wp_plugin_scan: parseIntEnv('MODULE_TIMEOUT_WP_PLUGIN', 15000),
  wp_vuln_resolver: parseIntEnv('MODULE_TIMEOUT_WP_VULN', 20000),
} as const;

// =============================================================================
// Feature Flags
// =============================================================================

export const features = {
  /** Enable endpoint discovery module */
  ENABLE_ENDPOINT_DISCOVERY: process.env.ENABLE_ENDPOINT_DISCOVERY !== 'false',
  /** Enable Puppeteer for dynamic scanning */
  ENABLE_PUPPETEER: process.env.ENABLE_PUPPETEER !== '0',
  /** Enable LLM-powered remediation guidance */
  ENABLE_LLM_REMEDIATION: process.env.ENABLE_LLM_REMEDIATION !== 'false',
  /** Include app-level tech stack detection */
  TECH_STACK_INCLUDE_APP: process.env.TECH_STACK_INCLUDE_APP !== 'false',
  /** Proxy enabled */
  PROXY_ENABLED: parseBoolEnv('PROXY_ENABLED', false),
} as const;

// =============================================================================
// API Keys
// =============================================================================

export const apiKeys = {
  /** Shodan API key */
  SHODAN_API_KEY: process.env.SHODAN_API_KEY ?? '',
  /** LeakCheck API key */
  LEAKCHECK_API_KEY: process.env.LEAKCHECK_API_KEY ?? '',
  /** OpenAI API key */
  OPENAI_API_KEY: process.env.OPENAI_API_KEY ?? '',
  /** GitHub token */
  GITHUB_TOKEN: process.env.GITHUB_TOKEN ?? '',
  /** NVD API key */
  NVD_API_KEY: process.env.NVD_API_KEY?.trim() ?? '',
  /** Captcha solver API key */
  CAPTCHA_API_KEY: process.env.CAPTCHA_API_KEY ?? '',
  /** HaveIBeenPwned API key */
  HIBP_API_KEY: process.env.HIBP_API_KEY ?? '',
  /** Chaos API key */
  CHAOS_API_KEY: process.env.CHAOS_API_KEY ?? '',
} as const;

// =============================================================================
// Rate Limiting
// =============================================================================

export const rateLimits = {
  /** Global network concurrency limit */
  GLOBAL_NET_CONCURRENCY: parseIntEnv('GLOBAL_NET_CONCURRENCY', 60),
  /** Per-host concurrency limit */
  PER_HOST_CONCURRENCY: parseIntEnv('PER_HOST_CONCURRENCY', 3),
  /** Shodan requests per second */
  SHODAN_RPS: parseIntEnv('SHODAN_RPS', 1),
  /** Shodan page limit */
  SHODAN_PAGE_LIMIT: parseIntEnv('SHODAN_PAGE_LIMIT', 10),
  /** Shodan target limit */
  SHODAN_TARGET_LIMIT: parseIntEnv('SHODAN_TARGET_LIMIT', 100),
  /** LeakCheck requests per second */
  LEAKCHECK_RPS: Math.max(1, parseIntEnv('LEAKCHECK_RPS', 3)),
  /** LeakCheck max retries */
  LEAKCHECK_MAX_RETRIES: Math.max(0, parseIntEnv('LEAKCHECK_MAX_RETRIES', 3)),
  /** WordPress vulnerability resolver concurrency */
  WP_VULN_RESOLVER_CONCURRENCY: parseIntEnv('WP_VULN_RESOLVER_CONCURRENCY', 4),
} as const;

// =============================================================================
// Resource Limits (Governor)
// =============================================================================

export const resourceLimits = {
  /** Database connection limit */
  RESOURCE_LIMIT_DB: process.env.RESOURCE_LIMIT_DB ? parseIntEnv('RESOURCE_LIMIT_DB', 0) : undefined,
  /** TLS scan limit */
  RESOURCE_LIMIT_TLS: process.env.RESOURCE_LIMIT_TLS ? parseIntEnv('RESOURCE_LIMIT_TLS', 0) : undefined,
  /** CPU tickets */
  RESOURCE_LIMIT_CPU: process.env.RESOURCE_LIMIT_CPU ? parseIntEnv('RESOURCE_LIMIT_CPU', 0) : undefined,
  /** Scan worker limit */
  RESOURCE_LIMIT_SCAN_WORKER: process.env.RESOURCE_LIMIT_SCAN_WORKER ? parseIntEnv('RESOURCE_LIMIT_SCAN_WORKER', 0) : undefined,
} as const;

// =============================================================================
// Worker Configuration
// =============================================================================

export const worker = {
  /** Worker ID */
  WORKER_ID: process.env.WORKER_ID,
  /** GG (git scanning) max workers */
  GG_MAX_WORKERS: parseIntEnv('GG_MAX_WORKERS', 4),
  /** Trufflehog git depth */
  TRUFFLEHOG_GIT_DEPTH: parseIntEnv('TRUFFLEHOG_GIT_DEPTH', 3),
  /** Scan worker lease TTL */
  SCAN_WORKER_LEASE_TTL_MS: parseIntEnv('SCAN_WORKER_LEASE_TTL_MS', 600000),
  /** Scan worker lease wait timeout */
  SCAN_WORKER_LEASE_WAIT_TIMEOUT_MS: parseIntEnv('SCAN_WORKER_LEASE_WAIT_TIMEOUT_MS', 600000),
  /** Module lease TTL */
  MODULE_LEASE_TTL_MS: parseIntEnv('MODULE_LEASE_TTL_MS', 60000),
  /** Puppeteer max pages */
  PUPPETEER_MAX_PAGES: process.env.PUPPETEER_MAX_PAGES ? parseIntEnv('PUPPETEER_MAX_PAGES', 0) : undefined,
  /** Debug Puppeteer */
  DEBUG_PUPPETEER: parseBoolEnv('DEBUG_PUPPETEER', false),
} as const;

// =============================================================================
// Proxy Configuration
// =============================================================================

export const proxy = {
  /** Proxy provider */
  PROXY_PROVIDER: parseStringEnv('PROXY_PROVIDER', 'none') as 'none' | 'brightdata' | 'oxylabs',
  /** Proxy rotation strategy */
  PROXY_ROTATION: parseStringEnv('PROXY_ROTATION', 'per_scan') as 'per_scan' | 'per_request' | 'sticky',
  /** Proxy country */
  PROXY_COUNTRY: process.env.PROXY_COUNTRY,
  /** Proxy session duration */
  PROXY_SESSION_DURATION_MS: parseIntEnv('PROXY_SESSION_DURATION_MS', 300000),
} as const;

// =============================================================================
// Cache Configuration
// =============================================================================

export const cache = {
  /** WordPress vulnerability cache TTL */
  WP_VULN_CACHE_TTL_MS: parseIntEnv('WP_VULN_CACHE_TTL_MS', 7 * 24 * 60 * 60 * 1000),
  /** WordPress vulnerability cache file path */
  WP_VULN_CACHE_FILE: parseStringEnv('WP_VULN_CACHE_FILE', 'scan-artifacts/wpvuln-cache.json'),
} as const;

// =============================================================================
// OpenVAS Configuration
// =============================================================================

export const openvas = {
  OPENVAS_HOST: parseStringEnv('OPENVAS_HOST', 'localhost'),
  OPENVAS_PORT: parseStringEnv('OPENVAS_PORT', '9390'),
  OPENVAS_USER: process.env.OPENVAS_USER,
  OPENVAS_PASSWORD: process.env.OPENVAS_PASSWORD,
} as const;

// =============================================================================
// OpenAI Configuration
// =============================================================================

export const openai = {
  /** OpenAI model to use */
  OPENAI_MODEL: parseStringEnv('OPENAI_MODEL', 'gpt-4o-mini-2024-07-18'),
} as const;

// =============================================================================
// Legacy Exports (for backward compatibility)
// =============================================================================

/** @deprecated Use worker.GG_MAX_WORKERS instead */
export const GG_MAX_WORKERS = worker.GG_MAX_WORKERS;

/** @deprecated Use worker.TRUFFLEHOG_GIT_DEPTH instead */
export const TRUFFLEHOG_GIT_DEPTH = worker.TRUFFLEHOG_GIT_DEPTH;

/** @deprecated Use scan.MAX_CONCURRENT_SCANS instead */
export const MAX_CONCURRENT_SCANS = scan.MAX_CONCURRENT_SCANS;
