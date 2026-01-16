import { config } from 'dotenv';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync } from 'node:fs';
// Load .env from project root robustly relative to this file
const __filename_env = fileURLToPath(import.meta.url);
const __dirname_env = dirname(__filename_env);
const envCandidates = [
  // dist build: apps/workers/dist -> root is ../../../
  resolve(__dirname_env, '../../../.env'),
  // ts run: apps/workers/src -> root is ../../
  resolve(__dirname_env, '../../.env'),
  // fallback to CWD
  resolve(process.cwd(), '.env')
];
let loaded = false;
for (const p of envCandidates) {
  if (existsSync(p)) {
    config({ path: p });
    loaded = true;
    break;
  }
}
if (!loaded) {
  config();
}

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { executeScan, ScanJob } from './scan/executeScan.js';
import { database } from './core/database.js';
import { QueueService } from './core/queueService.js';
import handlebars from 'handlebars';
import { execFileSync } from 'node:child_process';
import { timingSafeEqual } from 'node:crypto';
import { writeFileSync, unlinkSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { nanoid } from 'nanoid';
import { marked } from 'marked';
import DOMPurify from 'isomorphic-dompurify';
import { generateRemediationGuidance, generateExecutiveSummary, type ExecutiveSummaryInput } from './services/remediationOrchestrator.js';
import { getBaselineRemediation } from './services/remediationBaseline.js';
import { recordGuidanceEvent, consumeStats } from './services/remediationTelemetry.js';
import { RemediationGuidance, normalizePriority, severityToPriority, REMEDIATION_GUIDANCE_VERSION } from './core/remediation.js';
import { getRemediationContext, interpolateTemplate } from './services/findingEnrichers.js';
import { createModuleLogger } from './core/logger.js';
import { isValidDomain, normalizeDomain, isValidEmail } from './core/validation.js';
import { Errors, ErrorCode, createError } from './core/errors.js';
import { SEVERITY_LEVELS, SeverityKey } from './core/types.js';

const log = createModuleLogger('localServer');

/**
 * Sanitize error messages for client responses.
 * Logs full error internally but returns safe message to client.
 */
function safeErrorMessage(error: unknown, context: string): string {
  const fullMessage = error instanceof Error ? error.message : String(error);
  // Log full error for debugging
  log.debug({ err: error, context }, 'Error details (not exposed to client)');

  // Check for known safe error patterns that can be exposed
  const safePatterns = [
    /^Invalid (domain|email|priority|profile)/i,
    /^Domain is required/i,
    /^(Scan|Report|Job) not found/i,
    /^Service not ready/i,
    /^Unauthorized/i,
  ];

  if (safePatterns.some(pattern => pattern.test(fullMessage))) {
    return fullMessage;
  }

  // Return generic message for unknown errors
  return `${context} - please try again or contact support`;
}

const app = express();

// Initialize database and queue with configurable concurrency
const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || '8');
const queueService = new QueueService(MAX_CONCURRENT_SCANS);

// Domain validation moved to shared lib/validation.ts

const ENABLE_LLM_REMEDIATION = (process.env.ENABLE_LLM_REMEDIATION ?? 'true') !== 'false';

// Load remediation library for business_impact text
interface RemediationLibraryEntry {
  name: string;
  severity: string;
  business_impact?: string;
  risk_summary?: string;
  remediation_steps?: string[];
  action_line?: string;
}
let REMEDIATION_LIBRARY: Record<string, RemediationLibraryEntry> = {};
try {
  const libPath = resolve(__dirname_env, '../../../remediation_library.json');
  if (existsSync(libPath)) {
    const libContent = await readFile(libPath, 'utf-8');
    REMEDIATION_LIBRARY = JSON.parse(libContent);
    log.info({ count: Object.keys(REMEDIATION_LIBRARY).length }, 'Loaded remediation library entries');
  }
} catch (err) {
  log.warn({ err }, 'Could not load remediation_library.json');
}

// Get business_impact text for a finding type from the remediation library
function getBusinessImpact(findingType: string): string | null {
  const entry = REMEDIATION_LIBRARY[findingType];
  if (entry?.business_impact) {
    return entry.business_impact;
  }
  // Fall back to risk_summary if no business_impact, but only if it's not too technical
  // (In practice, we should add business_impact to all entries)
  return null;
}

// Initialize database connection
await database.initialize();

// Queue event listeners are handled internally by QueueService

// Middleware - Content Security Policy
// Note: 'unsafe-inline' is required for report HTML templates that use inline styles/scripts
// For API-only deployments, set CSP_STRICT=1 to disable unsafe-inline
const CSP_STRICT = process.env.CSP_STRICT === '1';
const defaultCsp = helmet.contentSecurityPolicy.getDefaultDirectives();
defaultCsp['script-src'] = CSP_STRICT
  ? ["'self'"]
  : ["'self'", "'unsafe-inline'"];  // Required for report interactivity
defaultCsp['style-src'] = CSP_STRICT
  ? ["'self'", 'https:']
  : ["'self'", 'https:', "'unsafe-inline'"];  // Required for report styling
defaultCsp['img-src'] = ["'self'", 'data:'];
defaultCsp['font-src'] = ["'self'", 'https:', 'data:'];
defaultCsp['connect-src'] = ["'self'"];
defaultCsp['object-src'] = ["'none'"];  // Prevent plugins
defaultCsp['base-uri'] = ["'self'"];    // Prevent base tag injection
defaultCsp['form-action'] = ["'self'"]; // Restrict form submissions
defaultCsp['frame-ancestors'] = ["'none'"]; // Prevent clickjacking
delete defaultCsp['upgrade-insecure-requests'];

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: defaultCsp
  },
  crossOriginEmbedderPolicy: false,
  hsts: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  noSniff: true,
  xssFilter: true
}));
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// CSRF Protection for browser-accessible endpoints
// Validates Origin header on state-changing requests to prevent cross-site attacks
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
const CSRF_ENABLED = process.env.CSRF_PROTECTION !== '0';

const csrfProtection: express.RequestHandler = (req, res, next) => {
  // Skip CSRF check if disabled
  if (!CSRF_ENABLED) return next();

  // Only check state-changing methods
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return next();
  }

  // API key auth provides CSRF protection for programmatic access
  // (browsers can't set custom headers on cross-origin requests without CORS preflight)
  const hasApiKey = req.headers['x-api-key'] || req.headers['authorization'];
  if (hasApiKey) return next();

  // For browser requests without API key, validate Origin
  const origin = req.headers['origin'];
  const referer = req.headers['referer'];

  // If no Origin/Referer, likely not a browser request
  if (!origin && !referer) return next();

  // Validate Origin against allowed list
  if (origin && ALLOWED_ORIGINS.length > 0) {
    if (!ALLOWED_ORIGINS.includes(origin)) {
      log.warn({ origin, path: req.path }, 'CSRF: Blocked request from unauthorized origin');
      return res.status(403).json({
        error: 'Forbidden',
        code: 'CSRF_ORIGIN_MISMATCH',
        message: 'Request origin not allowed'
      });
    }
  }

  next();
};

app.use(csrfProtection);

// Rate limiting configuration
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '3600000'); // 1 hour
const RATE_LIMIT_MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '5'); // 5 requests per window

const scanRateLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_REQUESTS,
  message: { error: 'Too many scan requests from this IP, please try again later.' },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// API Key authentication middleware
const API_KEY = process.env.SCANNER_API_KEY;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Fail fast in production if API key is not configured
if (IS_PRODUCTION && !API_KEY) {
  log.error('SCANNER_API_KEY must be set in production environment');
  process.exit(1);
}

/**
 * Timing-safe comparison for API keys to prevent timing attacks
 */
function safeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

const requireApiKey = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  // Skip API key check for health endpoint only
  if (req.path === '/health') {
    return next();
  }

  const providedKey = req.headers['x-api-key'] as string;

  // If no API key is configured (dev only), allow all requests
  if (!API_KEY) {
    log.warn('SCANNER_API_KEY not set - API is unprotected (dev mode only)');
    return next();
  }

  if (!providedKey || !safeCompare(providedKey, API_KEY)) {
    return res.status(401).json(Errors.unauthorized());
  }

  next();
};

// Apply API key authentication to all routes
app.use(requireApiKey);

// Feature gating (defaults enabled for backward compatibility)
const ENABLE_SCAN_API = (process.env.ENABLE_SCAN ?? '1') !== '0';
const ENABLE_BULK_API = (process.env.ENABLE_BULK ?? '1') !== '0';
const ENABLE_REPORTS_API = (process.env.ENABLE_REPORTS ?? '1') !== '0';

// Static file serving for reports and artifacts
if (ENABLE_REPORTS_API) {
  app.use('/reports', express.static('./scan-reports'));
}
app.use('/artifacts', express.static('./scan-artifacts'));
app.use('/static', express.static('./public'));

// Handlebars helpers
handlebars.registerHelper('toLowerCase', (str: string) => str.toLowerCase());
handlebars.registerHelper('eq', (a: any, b: any) => a === b);
handlebars.registerHelper('gt', (a: number, b: number) => a > b);
handlebars.registerHelper('or', (...args: any[]) => {
  // Last arg is the Handlebars options object, ignore it
  const values = args.slice(0, -1);
  return values.some(v => !!v);
});
handlebars.registerHelper('format_currency', (amount: number) => {
  if (!amount || isNaN(amount)) return '0';
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  }).format(amount);
});
handlebars.registerHelper('format_currency_thousands', (amount: number) => {
  if (!amount || isNaN(amount)) return '0';
  const rounded = Math.round(amount / 1000) * 1000;
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: 0,
    maximumFractionDigits: 0
  }).format(rounded);
});
handlebars.registerHelper('format_abbrev', (value: any) => {
  const n = Number(value) || 0;
  const abs = Math.abs(n);
  const fmt = (v: number, suffix: string) => `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)}${suffix}`;
  if (abs >= 1e12) return fmt(n / 1e12, 'T');
  if (abs >= 1e9)  return fmt(n / 1e9,  'B');
  if (abs >= 1e6)  return fmt(n / 1e6,  'M');
  if (abs >= 1e3)  return fmt(n / 1e3,  'k');
  return n.toLocaleString();
});
// Generic number formatter with grouping and optional decimals
handlebars.registerHelper('format_number', (value: any, options: any) => {
  const n = Number(value);
  if (isNaN(n)) return '0';
  const decimals = typeof options?.hash?.decimals === 'number' ? options.hash.decimals : 0;
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  }).format(n);
});
handlebars.registerHelper('lt', (a: number, b: number) => a < b);
handlebars.registerHelper('gt', (a: number, b: number) => a > b);
handlebars.registerHelper('take', (array: any, count: number) => {
  if (!Array.isArray(array)) return [];
  return array.slice(0, count);
});
handlebars.registerHelper('is_even', (n: any) => (Number(n) % 2) === 0);
handlebars.registerHelper('is_odd', (n: any) => (Number(n) % 2) === 1);

// Convert internal enum names to readable labels (e.g., CRITICAL_BREACH_EXPOSURE → Critical Breach Exposure)
handlebars.registerHelper('readable_type', (type: string) => {
  if (!type) return '';
  return type
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
});

// Pluralize helper: {{pluralize count "exposure" "exposures"}}
handlebars.registerHelper('pluralize', (count: number, singular: string, plural: string) => {
  return count === 1 ? singular : plural;
});

// Markdown to HTML helper - returns SafeString so Handlebars doesn't escape it
// Sanitizes output to prevent XSS attacks
handlebars.registerHelper('markdown', function(text: string) {
  if (!text) return '';
  // Convert markdown to HTML
  let html = marked.parse(text, { async: false }) as string;

  // Convert GFM-style task list checkboxes: - [ ] item and - [x] item
  // marked doesn't handle these by default, so we convert them manually
  html = html.replace(/<li>\s*\[\s*\]\s*/g, '<li><input type="checkbox" disabled> ');
  html = html.replace(/<li>\s*\[x\]\s*/gi, '<li><input type="checkbox" checked disabled> ');

  // Sanitize HTML to prevent XSS - allow safe formatting tags
  html = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'b', 'i', 'u', 'ul', 'ol', 'li', 'a', 'code', 'pre', 'blockquote', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'input', 'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td'],
    ALLOWED_ATTR: ['href', 'target', 'rel', 'type', 'checked', 'disabled', 'class'],
    ALLOW_DATA_ATTR: false
  });

  return new handlebars.SafeString(html);
});

const REPORT_TYPES = ['report', 'snapshot-report', 'snapshot-modern', 'technical-report'] as const;
type ReportType = typeof REPORT_TYPES[number];

const parseAllowedReportTypes = (): Set<ReportType> => {
  const raw = process.env.ALLOWED_REPORT_TYPES;
  const defaultSet = new Set<ReportType>(REPORT_TYPES);

  if (!raw) {
    return defaultSet;
  }

  const tokens = raw
    .split(',')
    .map(token => token.trim().toLowerCase())
    .filter(Boolean);

  const filtered = tokens.filter((token): token is ReportType =>
    (REPORT_TYPES as readonly string[]).includes(token)
  );

  if (!filtered.length) {
    return defaultSet;
  }

  return new Set<ReportType>(filtered);
};

const ALLOWED_REPORT_TYPES = parseAllowedReportTypes();

const resolveDefaultReportType = (): ReportType => {
  if (ALLOWED_REPORT_TYPES.has('report')) {
    return 'report';
  }
  const first = ALLOWED_REPORT_TYPES.values().next().value;
  return (first ?? 'snapshot-report') as ReportType;
};

const REPORT_TEMPLATES: Record<ReportType, string> = {
  report: 'report.hbs',
  'snapshot-report': 'snapshot-report.hbs',
  'snapshot-modern': 'snapshot-modern.hbs',
  'technical-report': 'technical-report.hbs'
};

const templateCache = new Map<ReportType, handlebars.TemplateDelegate>();
// Optional admin token to guard cache management endpoints
const REPORTS_ADMIN_TOKEN = (process.env.REPORTS_ADMIN_TOKEN || '').trim();

const objectHasKey = <T extends object>(obj: T, key: PropertyKey): key is keyof T =>
  Object.prototype.hasOwnProperty.call(obj, key);

const CATEGORY_FRIENDLY_NAMES: Record<string, string> = {
  ADA_COMPLIANCE: 'ADA Compliance',
  ADA_RISK_BAND: 'ADA Compliance',
  ACCESSIBILITY_OBSERVATION: 'ADA Compliance',
  PHISHING_BEC: 'Email Security',
  EMAIL_SECURITY_GAP: 'Email Security',
  EMAIL_SECURITY_WEAKNESS: 'Email Security',
  EMAIL_BREACH_EXPOSURE: 'Email Security',
  PASSWORD_BREACH_EXPOSURE: 'Password Exposure',
  SITE_HACK: 'Web Application Security',
  TLS_CONFIGURATION_ISSUE: 'TLS Configuration',
  MISSING_TLS_CERTIFICATE: 'TLS Configuration',
  CLIENT_SIDE_SECRET_EXPOSURE: 'Exposed Secrets',
  EXPOSED_SERVICE: 'Public Services',
  EXPOSED_DATABASE: 'Data Exposure',
  SENSITIVE_FILE_EXPOSURE: 'Sensitive Files',
  DENIAL_OF_WALLET: 'Cloud Cost Risk',
  GDPR_VIOLATION: 'Privacy Compliance',
  PCI_COMPLIANCE_FAILURE: 'PCI Compliance',
  CLOUD_COST_AMPLIFICATION: 'Cloud Cost Risk',
  MALICIOUS_TYPOSQUAT: 'Brand Impersonation',
  PHISHING_INFRASTRUCTURE: 'Phishing Infrastructure'
};

const isReportType = (value: string): value is ReportType =>
  (REPORT_TYPES as readonly string[]).includes(value as ReportType);

const isAllowedReportType = (value: string): value is ReportType =>
  ALLOWED_REPORT_TYPES.has(value as ReportType);

const normaliseReportType = (value?: string): ReportType => {
  if (!value) {
    return resolveDefaultReportType();
  }
  const candidate = value.toLowerCase();
  if (isReportType(candidate)) {
    if (!isAllowedReportType(candidate)) {
      throw new Error(`Report type ${candidate} not enabled`);
    }
    return candidate;
  }
  throw new Error(`Unsupported report type: ${value}`);
};

// Report generation functions
async function loadTemplate(reportType: ReportType): Promise<handlebars.TemplateDelegate> {
  const cachedTemplate = templateCache.get(reportType);
  if (cachedTemplate) {
    return cachedTemplate;
  }

  // Support user-provided overrides for snapshot variants
  const fileCandidates: string[] = (() => {
    if (reportType === 'snapshot-report' || reportType === 'snapshot-modern') {
      // Prefer a template matching the reportType, then generic snapshot.html, then default mapping
      return [`${reportType}.html`, 'snapshot.html', REPORT_TEMPLATES[reportType]];
    }
    return [REPORT_TEMPLATES[reportType]];
  })();

  const dirCandidates = [
    join(process.cwd(), 'templates'),
    join(process.cwd(), 'apps', 'workers', 'templates')
  ];

  const templateCandidates: string[] = [];
  for (const dir of dirCandidates) {
    for (const file of fileCandidates) {
      templateCandidates.push(join(dir, file));
    }
  }

  for (const templatePath of templateCandidates) {
    try {
      const templateContent = await readFile(templatePath, 'utf-8');
      const compiled = handlebars.compile(templateContent);
      templateCache.set(reportType, compiled);
      return compiled;
    } catch (error) {
      // Try next candidate
    }
  }

  throw new Error(`Report template not found for type: ${reportType}`);
}

async function generatePDF(html: string): Promise<Uint8Array> {
  // Use WeasyPrint for reliable CSS Paged Media support
  // WeasyPrint properly handles break-inside: avoid and page breaks
  const tempId = `report-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const htmlPath = `/tmp/${tempId}.html`;
  const pdfPath = `/tmp/${tempId}.pdf`;

  try {
    // Write HTML to temp file
    writeFileSync(htmlPath, html, 'utf-8');

    // Generate PDF using WeasyPrint
    // -q = quiet mode (suppress warnings about missing fonts etc)
    // --pdf-variant=pdf/ua = produce accessible PDF (optional, remove if issues)
    execFileSync('weasyprint', ['-q', htmlPath, pdfPath], {
      timeout: 60000, // 60 second timeout
      stdio: 'pipe'
    });

    // Read the generated PDF
    const { readFileSync } = await import('node:fs');
    const pdf = readFileSync(pdfPath);

    return new Uint8Array(pdf);
  } finally {
    // Clean up temp files
    try { unlinkSync(htmlPath); } catch {}
    try { unlinkSync(pdfPath); } catch {}
  }
}

// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const [dbHealth, queueHealth, queueMetrics] = await Promise.all([
      database.healthCheck(),
      queueService.healthCheck(),
      queueService.getMetrics()
    ]);
    
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '2.0.0-redis-postgres',
      database: dbHealth,
      redis: {
        status: queueHealth.status,
        ping: (queueHealth as any)?.details?.redis_ping ?? null
      },
      queue: {
        status: queueHealth.status,
        max_concurrent_scans: MAX_CONCURRENT_SCANS,
        waiting: queueMetrics.waiting,
        active: queueMetrics.active,
        completed: queueMetrics.completed,
        failed: queueMetrics.failed,
        delayed: queueMetrics.delayed,
        paused: queueMetrics.paused
      },
      postgres: database.poolStats
    });
  } catch (error: any) {
    res.status(500).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Lightweight scan viewer
app.get('/viewer', (_req, res) => {
  const viewerPath = join(process.cwd(), 'public', 'scan-viewer.html');
  res.sendFile(viewerPath);
});

// Valid scan profiles for lightweight pipelines
const VALID_PROFILES = ['full', 'aggressive', 'wordpress', 'infostealer', 'email', 'quick'] as const;
type ScanProfileType = typeof VALID_PROFILES[number];

// Profile documentation for API discovery
const PROFILE_DOCS: Record<ScanProfileType, { description: string; modules: string[]; tier: string; estimatedDuration: string; requiresOptIn?: boolean }> = {
  full: {
    description: 'Complete passive security scan with all 20 modules',
    modules: ['shodan', 'whois_wrapper', 'spf_dmarc', 'tech_stack_scan', 'endpoint_discovery', 'infostealer_probe', 'wp_plugin_quickscan', 'config_exposure', 'admin_panel_detector', 'dns_zone_transfer', 'subdomain_takeover', 'lightweight_backend_scan', 'backend_exposure_scanner', 'client_secret_scanner', 'denial_wallet_scan', 'accessibility_lightweight', 'tls_scan', 'lightweight_cve_check', 'asset_correlator'],
    tier: 'tier1 + tier2 + tier3',
    estimatedDuration: '5-10 minutes'
  },
  aggressive: {
    description: 'Full scan + active vulnerability scanning (nuclei, ZAP, port scanning, git analysis)',
    modules: ['nuclei', 'zap_scan', 'db_port_scan', 'trufflehog', 'github_secret_search', 'dns_twist', 'web_archive_scanner', 'openvas_scan'],
    tier: 'aggressive',
    estimatedDuration: '15-30 minutes',
    requiresOptIn: true
  },
  wordpress: {
    description: 'WordPress-focused scan for plugin vulnerabilities',
    modules: ['wp_plugin_quickscan', 'tech_stack_scan', 'tls_scan', 'config_exposure', 'admin_panel_detector'],
    tier: 'tier1',
    estimatedDuration: '3-5 minutes'
  },
  infostealer: {
    description: 'Credential exposure and breach detection scan',
    modules: ['infostealer_probe', 'client_secret_scanner', 'config_exposure'],
    tier: 'tier1',
    estimatedDuration: '2-3 minutes'
  },
  email: {
    description: 'Email security configuration scan (SPF, DMARC, MX)',
    modules: ['spf_dmarc', 'dns_zone_transfer'],
    tier: 'tier1',
    estimatedDuration: '1-2 minutes'
  },
  quick: {
    description: 'Fast reconnaissance scan for immediate insights',
    modules: ['tech_stack_scan', 'tls_scan', 'shodan', 'spf_dmarc'],
    tier: 'tier1',
    estimatedDuration: '2-3 minutes'
  }
};

// GET /scan/profiles - Document available scan profiles (Agent-Native API)
if (ENABLE_SCAN_API) app.get('/scan/profiles', (_req, res) => {
  res.json({
    profiles: VALID_PROFILES,
    details: PROFILE_DOCS,
    default: 'full',
    tiers: VALID_TIERS,
    config_options: {
      timeout_ms: { type: 'number', min: 60000, max: 3600000, default: 600000, description: 'Maximum scan duration in milliseconds' },
      modules: { type: 'string[]', description: 'Specific modules to run (overrides profile default)' },
      skip_modules: { type: 'string[]', description: 'Modules to skip from profile' },
      tier: { type: 'string', enum: ['tier1', 'tier2'], description: 'Scan depth tier' },
      aggressive: { type: 'boolean', default: false, description: 'Enable aggressive scanning (nuclei, ZAP, port scanning). Requires explicit opt-in.' },
      callback_url: { type: 'string', format: 'url', description: 'Webhook URL for completion notification' }
    },
    aggressive_modules: {
      description: 'Active scanning modules that require opt-in',
      modules: ['nuclei', 'zap_scan', 'db_port_scan', 'trufflehog', 'github_secret_search', 'dns_twist', 'web_archive_scanner', 'openvas_scan'],
      warning: 'These modules perform active probing and may trigger security alerts'
    }
  });
});

// Runtime configuration schema for scan requests
interface ScanConfig {
  timeout_ms?: number;        // Max scan duration in milliseconds (default: 600000 = 10 min)
  modules?: string[];         // Specific modules to run (empty = all for profile)
  skip_modules?: string[];    // Modules to skip
  tier?: 'tier1' | 'tier2';   // Scan depth: tier1 (quick), tier2 (deep)
  aggressive?: boolean;       // Enable aggressive scanning (nuclei, ZAP, port scanning)
  callback_url?: string;      // Webhook URL for completion notification
}

const VALID_TIERS = ['tier1', 'tier2'] as const;
const MAX_TIMEOUT_MS = 3600000; // 1 hour max
const MIN_TIMEOUT_MS = 60000;   // 1 minute min

// Queue-based scan endpoint
if (ENABLE_SCAN_API) app.post('/scan', scanRateLimiter as unknown as express.RequestHandler, async (req, res) => {
  const { domain, companyName, email, priority, profile, config } = req.body;

  if (!domain) {
    return res.status(400).json(Errors.missingField('domain'));
  }

  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain) {
    return res.status(400).json(Errors.invalidDomain(domain));
  }

  // Email validation (optional but recommended for public submissions)
  let normalizedEmail: string | undefined;
  if (email) {
    normalizedEmail = String(email).trim().toLowerCase();
    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json(Errors.invalidEmail(email));
    }
  }

  // Validate priority if provided
  const normalizedPriority = priority || 'normal';
  if (normalizedPriority && !['low', 'normal', 'high'].includes(normalizedPriority)) {
    return res.status(400).json(Errors.invalidOption('priority', ['low', 'normal', 'high']));
  }

  // Validate profile if provided (for lightweight scan pipelines)
  const normalizedProfile: ScanProfileType = profile || 'full';
  if (!VALID_PROFILES.includes(normalizedProfile)) {
    return res.status(400).json(Errors.invalidOption('profile', [...VALID_PROFILES]));
  }

  // Validate and normalize runtime config
  const scanConfig: ScanConfig = {};
  if (config && typeof config === 'object') {
    // Validate timeout
    if (config.timeout_ms !== undefined) {
      const timeout = parseInt(config.timeout_ms, 10);
      if (isNaN(timeout) || timeout < MIN_TIMEOUT_MS || timeout > MAX_TIMEOUT_MS) {
        return res.status(400).json(Errors.invalidFormat('timeout_ms', `Must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`));
      }
      scanConfig.timeout_ms = timeout;
    }

    // Validate tier
    if (config.tier !== undefined) {
      if (!VALID_TIERS.includes(config.tier)) {
        return res.status(400).json(Errors.invalidOption('tier', [...VALID_TIERS]));
      }
      scanConfig.tier = config.tier;
    }

    // Validate modules (array of strings)
    if (config.modules !== undefined) {
      if (!Array.isArray(config.modules) || !config.modules.every((m: unknown) => typeof m === 'string')) {
        return res.status(400).json(Errors.invalidFormat('modules', 'Must be an array of strings'));
      }
      scanConfig.modules = config.modules;
    }

    // Validate skip_modules (array of strings)
    if (config.skip_modules !== undefined) {
      if (!Array.isArray(config.skip_modules) || !config.skip_modules.every((m: unknown) => typeof m === 'string')) {
        return res.status(400).json(Errors.invalidFormat('skip_modules', 'Must be an array of strings'));
      }
      scanConfig.skip_modules = config.skip_modules;
    }

    // Validate callback_url
    if (config.callback_url !== undefined) {
      try {
        const url = new URL(config.callback_url);
        if (!['http:', 'https:'].includes(url.protocol)) {
          throw new Error('Invalid protocol');
        }
        scanConfig.callback_url = config.callback_url;
      } catch {
        return res.status(400).json(Errors.invalidUrl('callback_url'));
      }
    }
  }

  try {
    // Ensure the queue/governor is ready before accepting work
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json(Errors.serviceNotReady(e?.message || 'Resource governor not initialized'));
    }
    // Enqueue the scan job with runtime config
    const scan_id = await queueService.enqueue({
      domain: normalizedDomain,
      companyName,
      email: normalizedEmail,
      priority: normalizedPriority,
      profile: normalizedProfile,
      config: Object.keys(scanConfig).length > 0 ? scanConfig : undefined
    });

    // Get initial queue status
    const jobStatus = await queueService.getJobStatus(scan_id);

    log.info({ scan_id, domain: normalizedDomain, profile: normalizedProfile, config: scanConfig }, 'Enqueued scan');

    res.json({
      scan_id,
      status: jobStatus?.status || 'queued',
      domain: normalizedDomain,
      profile: normalizedProfile,
      config: Object.keys(scanConfig).length > 0 ? scanConfig : undefined,
      position_in_queue: jobStatus?.position_in_queue || 0,
      message: 'Scan queued successfully. Use GET /scan/{scan_id}/status to monitor progress.',
      status_url: `/scan/${scan_id}/status`,
      findings_url: `/scans/${scan_id}/findings`,
      artifacts_url: `/scans/${scan_id}/artifacts`,
      report_url: `/reports/${scan_id}/report.pdf`
    });
  } catch (error: any) {
    log.error({ err: error }, 'Failed to enqueue scan');

    res.status(500).json(createError(ErrorCode.QUEUE_ERROR, 'Failed to queue scan', {
      message: safeErrorMessage(error, 'Failed to queue scan')
    }));
  }
});

// Bulk enqueue endpoint
if (ENABLE_BULK_API) app.post('/scan/bulk', async (req, res) => {
  const { companies, priority, profile, batchId } = req.body ?? {};

  if (!Array.isArray(companies) || companies.length === 0) {
    return res.status(400).json(Errors.missingField('companies'));
  }

  // Validate batch-level profile if provided
  const batchProfile: ScanProfileType = profile || 'full';
  if (!VALID_PROFILES.includes(batchProfile)) {
    return res.status(400).json(Errors.invalidOption('profile', [...VALID_PROFILES]));
  }

  const results: Array<Record<string, any>> = [];
  const errors: Array<{ company: any; error: string }> = [];

  for (const company of companies) {
    const rawDomain = typeof company?.domain === 'string' ? company.domain : '';
    const normalizedDomain = normalizeDomain(rawDomain);
    const companyPriority = company?.priority || priority || 'normal';
    // Per-company profile overrides batch-level profile
    const companyProfile: ScanProfileType = company?.profile || batchProfile;

    if (!normalizedDomain) {
      errors.push({ company, error: `Invalid or missing domain: ${rawDomain}` });
      continue;
    }

    const companyName = typeof company?.companyName === 'string' ? company.companyName : normalizedDomain;

    if (companyPriority && !['low', 'normal', 'high'].includes(companyPriority)) {
      errors.push({ company, error: `Invalid priority: ${companyPriority}` });
      continue;
    }

    if (!VALID_PROFILES.includes(companyProfile)) {
      errors.push({ company, error: `Invalid profile: ${companyProfile}` });
      continue;
    }

    try {
      // Ensure readiness once before first enqueue (first loop iteration)
      if (results.length === 0) {
        try {
          await queueService.waitReady();
        } catch (e: any) {
          return res.status(503).json({ error: 'Service not ready', message: e?.message || 'Resource governor not initialized' });
        }
      }
      const scanId = await queueService.enqueue({
        domain: normalizedDomain,
        companyName,
        priority: companyPriority,
        profile: companyProfile,
        tags: Array.isArray(company?.tags) ? company.tags : undefined,
        batchId: company?.batchId || batchId,
        batchPosition: typeof company?.batchPosition === 'number' ? company.batchPosition : undefined,
        manifestScanId: company?.manifestScanId || company?.scanId
      });

      results.push({
        scanId,
        scan_id: scanId,
        status: 'queued',
        companyName,
        domain: normalizedDomain,
        profile: companyProfile,
        manifestScanId: company?.manifestScanId || company?.scanId || null
      });
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to enqueue scan';
      log.error({ err: error, company }, 'Bulk enqueue failed');
      errors.push({ company, error: errorMessage });
    }
  }

  log.info({ queued: results.length, total: companies.length, profile: batchProfile, errorCount: errors.length }, 'Bulk enqueue completed');

  res.json({
    total: companies.length,
    queued: results.length,
    failed: errors.length,
    results,
    errors
  });
});

// Get scan status endpoint
if (ENABLE_SCAN_API) app.get('/scan/:scanId/status', async (req, res) => {
  try {
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json(Errors.serviceNotReady(e?.message || 'Resource governor not initialized'));
    }
    const { scanId } = req.params;
    const jobStatus = await queueService.getJobStatus(scanId);

    if (!jobStatus) {
      return res.status(404).json(Errors.scanNotFound(scanId));
    }
    
    // If it's a completed scan, also include database details
    if (jobStatus.status === 'completed' || jobStatus.status === 'failed') {
      const scan = await database.getScan(scanId);
      if (scan) {
        return res.json({
          ...jobStatus,
          domain: scan.domain,
          created_at: scan.created_at,
          completed_at: scan.completed_at,
          findings_count: scan.findings_count,
          artifacts_count: scan.artifacts_count,
          duration_ms: scan.duration_ms
        });
      }
    }
    
    res.json(jobStatus);
  } catch (error: any) {
    res.status(500).json(createError(ErrorCode.INTERNAL_ERROR, 'Failed to get scan status', {
      message: safeErrorMessage(error, 'Failed to get scan status')
    }));
  }
});

// Cancel scan endpoint
if (ENABLE_SCAN_API) app.delete('/scan/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const cancelled = await queueService.cancelJob(scanId);

    if (cancelled) {
      res.json({
        scan_id: scanId,
        status: 'cancelled',
        message: 'Scan cancelled successfully'
      });
    } else {
      res.status(404).json(createError(ErrorCode.SCAN_NOT_FOUND, 'Scan not found or cannot be cancelled', {
        details: { scan_id: scanId }
      }));
    }
  } catch (error: any) {
    res.status(500).json(createError(ErrorCode.INTERNAL_ERROR, 'Failed to cancel scan', {
      message: safeErrorMessage(error, 'Failed to cancel scan')
    }));
  }
});

// Queue metrics endpoint
if (ENABLE_BULK_API) app.get('/queue/metrics', async (req, res) => {
  try {
    const metrics = await queueService.getMetrics();
    res.json({
      ...metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to get queue metrics', message: safeErrorMessage(error, 'Failed to get queue metrics') });
  }
});

// Queue status endpoint
if (ENABLE_BULK_API) app.get('/queue/status', async (req, res) => {
  try {
    // Ensure readiness before reading queue state
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json({ error: 'Service not ready', message: e?.message || 'Resource governor not initialized' });
    }
    const [allJobs, metrics] = await Promise.all([
      queueService.getAllJobs(),
      queueService.getMetrics()
    ]);
    
    res.json({
      jobs: allJobs,
      metrics,
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to get queue status', message: safeErrorMessage(error, 'Failed to get queue status') });
  }
});

// List scans endpoint (enhanced)
if (ENABLE_BULK_API) app.get('/scans', async (req, res) => {
  try {
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json({ error: 'Service not ready', message: e?.message || 'Resource governor not initialized' });
    }
    const limit = parseInt(req.query.limit as string) || 50;
    const [scans, queueMetrics] = await Promise.all([
      database.getRecentScans(limit),
      queueService.getMetrics()
    ]);
    
    res.json({
      scans,
      queue_info: {
        waiting: queueMetrics.waiting,
        active: queueMetrics.active,
        completed: queueMetrics.completed,
        failed: queueMetrics.failed
      },
      timestamp: new Date().toISOString()
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch scans', message: safeErrorMessage(error, 'Failed to fetch scans') });
  }
});

// Get specific scan details
if (ENABLE_BULK_API) app.get('/scans/:scanId', async (req, res) => {
  try {
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json({ error: 'Service not ready', message: e?.message || 'Resource governor not initialized' });
    }
    const { scanId } = req.params;
    const [scan, findings] = await Promise.all([
      database.getScan(scanId),
      database.getFindingsByScanId(scanId)
    ]);
    
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    res.json({
      ...scan,
      findings
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch scan details', message: safeErrorMessage(error, 'Failed to fetch scan details') });
  }
});

// Get findings for a specific scan (Agent-Native API)
if (ENABLE_BULK_API) app.get('/scans/:scanId/findings', async (req, res) => {
  try {
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json({ error: 'Service not ready', message: e?.message || 'Resource governor not initialized' });
    }
    const { scanId } = req.params;
    const { type, severity, limit, offset } = req.query;

    const scan = await database.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const findings = await database.getFindingsByScanId(scanId);

    // Apply optional filters
    let filtered = findings;
    if (type) {
      filtered = filtered.filter(f => f.type === type);
    }
    if (severity) {
      filtered = filtered.filter(f => f.severity === severity);
    }

    // Apply pagination
    const limitNum = limit ? parseInt(limit as string, 10) : undefined;
    const offsetNum = offset ? parseInt(offset as string, 10) : 0;
    if (limitNum) {
      filtered = filtered.slice(offsetNum, offsetNum + limitNum);
    } else if (offsetNum > 0) {
      filtered = filtered.slice(offsetNum);
    }

    res.json({
      scan_id: scanId,
      total: findings.length,
      returned: filtered.length,
      findings: filtered
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch findings', message: safeErrorMessage(error, 'Failed to fetch findings') });
  }
});

// Get artifacts for a specific scan (Agent-Native API)
if (ENABLE_BULK_API) app.get('/scans/:scanId/artifacts', async (req, res) => {
  try {
    try {
      await queueService.waitReady();
    } catch (e: any) {
      return res.status(503).json({ error: 'Service not ready', message: e?.message || 'Resource governor not initialized' });
    }
    const { scanId } = req.params;
    const { type, severity, limit, offset } = req.query;

    const scan = await database.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const artifacts = await database.getArtifactsByScanId(scanId, {
      type: type as string | undefined,
      severity: severity as string | undefined,
      limit: limit ? parseInt(limit as string, 10) : undefined,
      offset: offset ? parseInt(offset as string, 10) : undefined
    });

    const totalCount = await database.getArtifactCount(scanId);

    res.json({
      scan_id: scanId,
      total: totalCount,
      returned: artifacts.length,
      artifacts
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch artifacts', message: safeErrorMessage(error, 'Failed to fetch artifacts') });
  }
});

// Reports cache management endpoints (opt-in, safe local default)
if (ENABLE_REPORTS_API) {
  const isLocalIp = (ip: string | undefined) =>
    !!ip && (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1');

  const isAuthorized = (req: express.Request) => {
    if (REPORTS_ADMIN_TOKEN) {
      const token = (req.header('x-admin-token') || req.query.token || '').toString();
      return token === REPORTS_ADMIN_TOKEN;
    }
    return isLocalIp(req.ip);
  };

  app.get('/reports/cache/status', (req, res) => {
    if (!isAuthorized(req)) return res.status(403).json({ error: 'Forbidden' });
    const cached = Array.from(templateCache.keys());
    res.json({ status: 'ok', cached, count: cached.length, timestamp: new Date().toISOString() });
  });

  app.get('/reports/cache/clear', (req, res) => {
    if (!isAuthorized(req)) return res.status(403).json({ error: 'Forbidden' });
    const before = templateCache.size;
    templateCache.clear();
    res.json({ status: 'ok', cleared: before, remaining: templateCache.size, timestamp: new Date().toISOString() });
  });
}

// Generate public URL for hosting at simplcyber.com/reports
if (ENABLE_REPORTS_API) app.post('/reports/publish', async (req, res) => {
  const { scan_id, company_name } = req.body;

  if (!scan_id) {
    return res.status(400).json({ error: 'scan_id is required' });
  }

  try {
    const scan = await database.getScan(scan_id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Check if already has a public slug
    let publicSlug = await database.getPublicSlug(scan_id);

    if (!publicSlug) {
      // Generate new public slug
      const name = company_name || scan.metadata?.company_name || scan.domain;
      publicSlug = await database.generatePublicSlug(scan_id, name);
    }

    const publicUrl = `https://simplcyber.com/reports/${publicSlug}`;

    res.json({
      scan_id,
      public_slug: publicSlug,
      public_url: publicUrl,
      domain: scan.domain,
      company_name: company_name || scan.metadata?.company_name,
      status: 'published'
    });
  } catch (error: any) {
    log.error({ err: error, scan_id }, 'Failed to publish report');
    res.status(500).json({
      error: 'Failed to publish report',
      message: safeErrorMessage(error, 'Failed to publish report'),
      scan_id
    });
  }
});

// Get public URL for a scan
if (ENABLE_REPORTS_API) app.get('/reports/:scanId/public-url', async (req, res) => {
  const { scanId } = req.params;

  try {
    const scan = await database.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const publicSlug = await database.getPublicSlug(scanId);
    if (!publicSlug) {
      return res.status(404).json({
        error: 'No public URL exists for this scan',
        hint: 'POST /reports/publish to generate one'
      });
    }

    res.json({
      scan_id: scanId,
      public_slug: publicSlug,
      public_url: `https://simplcyber.com/reports/${publicSlug}`,
      domain: scan.domain
    });
  } catch (error: any) {
    log.error({ err: error, scanId }, 'Failed to get public URL');
    res.status(500).json({ error: error.message });
  }
});

// Generate report endpoint
// Supports format: 'html' (default) or 'json' for structured data
if (ENABLE_REPORTS_API) app.post('/reports/generate', async (req, res) => {
  const { scan_id, report_type, format = 'html' } = req.body;

  if (!scan_id) {
    return res.status(400).json({ error: 'scan_id is required' });
  }

  const normalizedFormat = (format || 'html').toLowerCase();
  if (normalizedFormat !== 'html' && normalizedFormat !== 'json') {
    return res.status(400).json({ error: 'Invalid format. Use "html" or "json"' });
  }

  let reportType: ReportType;
  try {
    reportType = normaliseReportType(report_type);
  } catch (error: any) {
    return res.status(400).json({ error: error.message || 'Invalid report_type' });
  }

  const startTime = Date.now();

  try {
    // For JSON format, return structured data directly without rendering HTML
    if (normalizedFormat === 'json') {
      const baseData = await assembleReportData(scan_id, reportType);
      const duration = Date.now() - startTime;
      return res.json({
        scan_id,
        report_type: reportType,
        format: 'json',
        generated_at: new Date().toISOString(),
        generation_time_ms: duration,
        scan: {
          id: baseData.scanData?.id,
          domain: baseData.scanData?.domain,
          status: baseData.scanData?.status,
          created_at: baseData.scanData?.created_at,
          completed_at: baseData.scanData?.completed_at,
          tier: baseData.scanData?.tier,
        },
        summary: {
          total_findings: baseData.findings.length,
          severity_counts: baseData.severityCounts,
          eal_summary: baseData.ealSummary,
          eal_by_family: baseData.ealByFamily,
        },
        findings: baseData.findings.map((f: any) => ({
          id: f.id,
          type: f.type,
          severity: f.severity,
          title: f.title,
          description: f.description,
          remediation: f.remediation,
          attack_type_code: f.attack_type_code,
          cvss_score: f.cvss_score,
          cve_id: f.cve_id,
          evidence: f.evidence,
          affected_asset: f.affected_asset,
          first_seen: f.first_seen,
          last_seen: f.last_seen,
          metadata: f.metadata,
        })),
      });
    }

    // HTML format - render and save report
    const assets = await renderAndSaveReport(scan_id, reportType);
    const duration = Date.now() - startTime;
    const fileBase = reportType === 'report' ? 'report' : reportType;

    res.json({
      report_url: `/reports/${scan_id}/${fileBase}.html`,
      html_url: `/reports/${scan_id}/${fileBase}.html`,
      json_url: `/reports/${scan_id}/${fileBase}.json`,
      report_type: reportType,
      format: 'html',
      scan_id,
      domain: assets.templateData.domain,
      total_findings: assets.templateData.total_findings,
      severity_counts: assets.templateData.severity_counts,
      generated_at: new Date().toISOString(),
      generation_time_ms: duration,
      status: `${reportType} generated successfully`
    });
  } catch (error: any) {
    const duration = Date.now() - startTime;
    log.error({ err: error, scan_id, report_type: reportType, duration_ms: duration }, 'Report generation failed');

    res.status(500).json({
      error: 'Report generation failed',
      message: safeErrorMessage(error, 'Report generation failed'),
      scan_id,
      report_type: reportType,
      duration_ms: duration
    });
  }
});

// Direct report access with auto-generation fallback (supports HTML and PDF via WeasyPrint)
if (ENABLE_REPORTS_API) app.get('/reports/:scanId/:fileName', async (req, res) => {
  try {
    const { scanId, fileName } = req.params;
    const parts = fileName.split('.');

    if (parts.length !== 2) {
      return res.status(400).json(Errors.invalidFormat('fileName', 'Use format: {report_type}.{format}'));
    }

    const [rawType, rawFormat] = parts;
    const format = rawFormat.toLowerCase();

    if (format !== 'html' && format !== 'pdf' && format !== 'json') {
      return res.status(400).json(Errors.reportInvalidFormat(['.html', '.pdf', '.json']));
    }

    let reportType: ReportType;
    try {
      reportType = normaliseReportType(rawType);
    } catch (error: any) {
      return res.status(404).json(Errors.reportInvalidType(['report', 'technical-report', 'executive-summary']));
    }

    // JSON format - return raw structured report data for programmatic consumption
    if (format === 'json') {
      const baseData = await assembleReportData(scanId, reportType);
      return res.json({
        scan_id: scanId,
        report_type: reportType,
        generated_at: new Date().toISOString(),
        scan: {
          id: baseData.scanData?.id,
          domain: baseData.scanData?.domain,
          status: baseData.scanData?.status,
          created_at: baseData.scanData?.created_at,
          completed_at: baseData.scanData?.completed_at,
          tier: baseData.scanData?.tier,
        },
        summary: {
          total_findings: baseData.findings.length,
          severity_counts: baseData.severityCounts,
          eal_summary: baseData.ealSummary,
          eal_by_family: baseData.ealByFamily,
        },
        findings: baseData.findings.map((f: any) => ({
          id: f.id,
          type: f.type,
          severity: f.severity,
          title: f.title,
          description: f.description,
          remediation: f.remediation,
          attack_type_code: f.attack_type_code,
          cvss_score: f.cvss_score,
          cve_id: f.cve_id,
          evidence: f.evidence,
          affected_asset: f.affected_asset,
          first_seen: f.first_seen,
          last_seen: f.last_seen,
          metadata: f.metadata,
        })),
      });
    }

    // For PDF requests, we need to generate the HTML first, then convert to PDF
    if (format === 'pdf') {
      // Check if HTML exists, generate if not
      let existingHtmlPath = await database.getReportPath(scanId, 'html', reportType);
      if (!existingHtmlPath) {
        const generateResult = await generateReportForScan(scanId, reportType);
        if (!generateResult.success) {
          return res.status(500).json({ error: 'Failed to generate report', message: generateResult.error });
        }
        existingHtmlPath = await database.getReportPath(scanId, 'html', reportType);
      }

      if (!existingHtmlPath) {
        return res.status(500).json({ error: 'Report generated but HTML file missing' });
      }

      // Read HTML and generate PDF using WeasyPrint
      const { readFileSync: readSync } = await import('node:fs');
      const html = readSync(join(process.cwd(), existingHtmlPath), 'utf-8');
      const pdf = await generatePDF(html);

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${reportType}-${scanId}.pdf"`);
      return res.send(Buffer.from(pdf));
    }

    // HTML format
    const existingPath = await database.getReportPath(scanId, 'html', reportType);
    if (existingPath) {
      return res.sendFile(existingPath, { root: process.cwd() });
    }

    const generateResult = await generateReportForScan(scanId, reportType);
    if (!generateResult.success) {
      return res.status(500).json({ error: 'Failed to generate report', message: generateResult.error });
    }

    const regeneratedPath = await database.getReportPath(scanId, 'html', reportType);
    if (!regeneratedPath) {
      return res.status(500).json({ error: 'Report generated but file missing' });
    }

    return res.sendFile(regeneratedPath, { root: process.cwd() });
  } catch (error: any) {
    log.error({ err: error, scanId: req.params.scanId }, 'Error serving report');
    res.status(500).json({ error: 'Failed to serve report', message: safeErrorMessage(error, 'Failed to serve report') });
  }
});

const EAL_EXCLUDE_FAMILIES: string[] = (process.env.EAL_EXCLUDE_FAMILIES || 'TLS')
  .split(',')
  .map(s => s.trim().toUpperCase())
  .filter(Boolean);

interface NormalizedEalSummary {
  total_eal_low: number;
  total_eal_ml: number;
  total_eal_high: number;
  total_eal_daily: number;
  daily_cloud_risk: number;
  compliance_risk: number;
  compliance_low: number;
  compliance_high: number;
  cyber_findings_count: number;
  compliance_findings_count: number;
  cloud_findings_count: number;
  total_findings: number;
  findings_with_eal: number;
}

const coerceNumber = (value: unknown): number => {
  if (value === null || value === undefined) return 0;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
};

const normalizeEalSummary = (row: any): NormalizedEalSummary | null => {
  if (!row) return null;

  const totalEalMl = coerceNumber(row.total_eal_ml);
  const complianceMl = coerceNumber(row.compliance_ml);
  // Cyber risk = total - compliance (compliance should NOT be included in cyber EAL)
  const cyberOnlyMl = Math.max(0, totalEalMl - complianceMl);

  return {
    total_eal_low: coerceNumber(row.total_eal_low),
    total_eal_ml: cyberOnlyMl,  // Now represents cyber-only risk
    total_eal_high: coerceNumber(row.total_eal_high),
    total_eal_daily: coerceNumber(row.total_eal_daily),
    daily_cloud_risk: coerceNumber(row.dow_daily),
    compliance_risk: complianceMl,
    compliance_low: coerceNumber(row.compliance_low),
    compliance_high: coerceNumber(row.compliance_high),
    cyber_findings_count: coerceNumber(row.cyber_findings_count),
    compliance_findings_count: coerceNumber(row.compliance_findings_count),
    cloud_findings_count: coerceNumber(row.cloud_findings_count),
    total_findings: coerceNumber(row.total_findings),
    findings_with_eal: coerceNumber(row.findings_with_eal)
  };
};

interface BaseReportData {
  scanData: Awaited<ReturnType<typeof database.getScan>>;
  findings: any[];
  severityCounts: Record<SeverityKey, number>;
  findingsBySeverity: Record<SeverityKey, any[]>;
  ealSummary: NormalizedEalSummary | null;
  ealByFamily?: Record<string, { sum_ml: number; cap_ml?: number }>;
}

interface CategorySummaryEntry {
  label: string;
  total: number;
  severityText: string;
}

/**
 * Smart deduplication: merge findings of same type+severity
 * Instead of dropping duplicates, combines their data (e.g., merges user lists)
 */
function deduplicateFindings(findings: any[]): any[] {
  const grouped = new Map<string, any[]>();

  for (const finding of findings) {
    const type = finding.type || 'UNKNOWN';
    const severity = (finding.severity || 'INFO').toUpperCase();
    const key = `${type}::${severity}`;

    if (!grouped.has(key)) {
      grouped.set(key, []);
    }
    grouped.get(key)!.push(finding);
  }

  const merged: any[] = [];

  for (const [key, group] of grouped) {
    if (group.length === 1) {
      // Fix pluralization for single findings too (legacy data fix)
      const finding = { ...group[0] };
      if (key.includes('BREACH_EXPOSURE') && finding.description) {
        // Fix "1 critical breach exposures" → "1 critical breach exposure"
        finding.description = finding.description.replace(
          /(\d+)\s+(\w+)\s+breach\s+exposures?\s+found/gi,
          (match: string, count: string, severity: string) => {
            const plural = parseInt(count) === 1 ? 'exposure' : 'exposures';
            return `${count} ${severity} breach ${plural} found`;
          }
        );
      }
      merged.push(finding);
      continue;
    }

    // For breach exposure types, merge the user lists and descriptions
    if (key.includes('BREACH_EXPOSURE')) {
      const first = { ...group[0] };

      // Extract all unique emails from descriptions
      const allEmails = new Set<string>();
      const allSources = new Set<string>();
      let allTimelines: string[] = [];

      for (const f of group) {
        const desc = f.description || '';
        // Extract emails before the pipe
        const emailMatch = desc.match(/found:\s*([^|]+)/);
        if (emailMatch) {
          const emails = emailMatch[1].split(',').map((e: string) => e.trim().replace(/\s+and\s+\d+\s+more$/, ''));
          emails.forEach((e: string) => { if (e && e.includes('@')) allEmails.add(e); });
        }
        // Extract sources
        const sourceMatch = desc.match(/Sources:\s*([^|]+)/);
        if (sourceMatch) {
          sourceMatch[1].split(',').map((s: string) => s.trim()).filter(Boolean).forEach((s: string) => allSources.add(s));
        }
        // Extract timeline
        const timelineMatch = desc.match(/Timeline:\s*(.+)$/);
        if (timelineMatch) {
          allTimelines.push(timelineMatch[1]);
        }
      }

      // Rebuild merged description
      const uniqueEmails = [...allEmails];
      const emailCount = uniqueEmails.length;
      const severity = (first.severity || 'medium').toLowerCase();
      const exposurePlural = emailCount === 1 ? 'exposure' : 'exposures';
      const emailSummary = uniqueEmails.length <= 5
        ? uniqueEmails.join(', ')
        : `${uniqueEmails.slice(0, 5).join(', ')} and ${uniqueEmails.length - 5} more`;

      let mergedDesc = `${emailCount} ${severity} breach ${exposurePlural} found: ${emailSummary}`;
      if (allSources.size > 0) {
        const sourceList = [...allSources];
        const sourceSummary = sourceList.length <= 5
          ? sourceList.join(', ')
          : `${sourceList.slice(0, 5).join(', ')} and ${sourceList.length - 5} more`;
        mergedDesc += ` | Sources: ${sourceSummary}`;
      }
      if (allTimelines.length > 0) {
        // Compress timeline to just year range
        const years = allTimelines.join(', ').match(/\d{4}/g);
        if (years && years.length > 0) {
          const minYear = Math.min(...years.map(Number));
          const maxYear = Math.max(...years.map(Number));
          mergedDesc += minYear === maxYear
            ? ` | Timeline: ${minYear}`
            : ` | Timeline: ${minYear}–${maxYear}`;
        }
      }

      first.description = mergedDesc;
      first._mergedCount = group.length;
      merged.push(first);
    } else {
      // For non-breach types, just take the first one (or could implement other merge logic)
      merged.push(group[0]);
    }
  }

  return merged;
}

async function assembleReportData(scan_id: string, reportType: ReportType): Promise<BaseReportData> {
  const scanData = await database.getScan(scan_id);
  if (!scanData) {
    throw new Error('Scan not found');
  }

  const findingsRaw = await database.getFindingsByScanId(scan_id);

  // Filter out INFO severity findings - they're noise and shouldn't appear in reports
  const actionableFindings = findingsRaw.filter((f: any) => {
    const severity = (f.severity || 'INFO').toUpperCase();
    return severity !== 'INFO';
  });

  const findings = await enrichFindings(actionableFindings, {
    scanId: scan_id,
    domain: scanData.domain,
    reportType
  });

  // Smart deduplication: merge findings of same type+severity, keeping all unique details
  // This prevents duplicate PASSWORD_BREACH_EXPOSURE entries while preserving all data
  const dedupedFindings = deduplicateFindings(findings);

  // Sort findings: Infostealers first, then other cyber, then compliance
  // Within each category, sort by severity
  const severityOrder: Record<string, number> = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'INFO': 4
  };

  // Category: 0 = infostealer/breach, 1 = other cyber, 2 = compliance
  const getCategoryOrder = (type: string): number => {
    const t = (type || '').toUpperCase();
    // Infostealers and breach exposure first
    if (t.includes('INFOSTEALER') || t.includes('BREACH') || t.includes('CREDENTIAL') || t.includes('PASSWORD')) {
      return 0;
    }
    // Compliance/accessibility last
    if (t.includes('ACCESSIBILITY') || t.includes('ADA') || t.includes('COMPLIANCE') || t.includes('GDPR') || t.includes('PCI')) {
      return 2;
    }
    // Everything else is cyber
    return 1;
  };

  dedupedFindings.sort((a: any, b: any) => {
    const aCat = getCategoryOrder(a.type);
    const bCat = getCategoryOrder(b.type);
    if (aCat !== bCat) return aCat - bCat;

    const aSev = (a.severity || 'INFO').toUpperCase();
    const bSev = (b.severity || 'INFO').toUpperCase();
    const aOrder = severityOrder[aSev] ?? 4;
    const bOrder = severityOrder[bSev] ?? 4;
    return aOrder - bOrder;
  });

  const severityCounts: Record<SeverityKey, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };

  const findingsBySeverity: Record<SeverityKey, any[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: []
  };

  dedupedFindings.forEach((finding: any) => {
    const severity = (finding.severity || 'INFO').toUpperCase();
    const severityKey = SEVERITY_LEVELS.includes(severity as SeverityKey)
      ? (severity as SeverityKey)
      : 'INFO';
    severityCounts[severityKey]++;
    findingsBySeverity[severityKey].push(finding);
  });

  const ealSummaryResult = await database.query(
    'SELECT * FROM scan_eal_summary WHERE scan_id = $1',
    [scan_id]
  );
  let ealSummary = normalizeEalSummary(ealSummaryResult.rows[0]);

  // Optionally exclude specific EAL families (e.g., TLS) from the reported totals
  if (ealSummary && EAL_EXCLUDE_FAMILIES.length > 0) {
    try {
      const familyRows = await database.query(
        'SELECT family, sum_ml, cap_ml FROM scan_eal_family_audit WHERE scan_id = $1',
        [scan_id]
      );
      let subtractMl = 0;
      for (const row of familyRows.rows || []) {
        const fam = String(row.family || '').toUpperCase();
        if (EAL_EXCLUDE_FAMILIES.includes(fam)) {
          const ml = Number(row.sum_ml) || 0;
          subtractMl += ml;
        }
      }
      if (subtractMl > 0) {
        ealSummary.total_eal_ml = Math.max(0, ealSummary.total_eal_ml - subtractMl);
      }
    } catch (err) {
      log.error({ err, scan_id, families: EAL_EXCLUDE_FAMILIES }, 'Failed to apply EAL_EXCLUDE_FAMILIES');
    }
  }

  // Pull per-family EAL contributions for business action planning
  const ealByFamily: Record<string, { sum_ml: number; cap_ml?: number }> = {};
  try {
    const famRows = await database.query(
      'SELECT family, sum_ml, cap_ml FROM scan_eal_family_audit WHERE scan_id = $1',
      [scan_id]
    );
    for (const row of famRows.rows || []) {
      const family = String(row.family || '').toUpperCase();
      const sum_ml = Number(row.sum_ml) || 0;
      const cap_ml = row.cap_ml !== undefined ? Number(row.cap_ml) || undefined : undefined;
      if (!family) continue;
      ealByFamily[family] = { sum_ml, cap_ml };
    }
  } catch (err) {
    log.error({ err, scan_id }, 'Failed to read scan_eal_family_audit');
  }

  const telemetryStats = consumeStats(scan_id);
  if (telemetryStats) {
    const existingMetadata = (scanData.metadata && typeof scanData.metadata === 'object') ? scanData.metadata : {};
    const updatedMetadata = {
      ...existingMetadata,
      remediation_stats: telemetryStats
    };
    scanData.metadata = updatedMetadata;

    try {
      await database.insertScan({
        id: scanData.id,
        domain: scanData.domain,
        status: scanData.status,
        created_at: scanData.created_at,
        completed_at: scanData.completed_at,
        findings_count: scanData.findings_count,
        artifacts_count: scanData.artifacts_count,
        duration_ms: scanData.duration_ms,
        metadata: updatedMetadata
      });
    } catch (error) {
      log.error({ err: error, scan_id }, 'Failed to persist telemetry stats');
    }
  }

  return {
    scanData,
    findings: dedupedFindings,
    severityCounts,
    findingsBySeverity,
    ealSummary,
    ealByFamily
  };
}

interface FindingEnrichmentContext {
  scanId: string;
  domain: string;
  reportType: ReportType;
}

async function enrichFindings(findings: any[], context: FindingEnrichmentContext): Promise<any[]> {
  const enriched: any[] = [];

  for (const finding of findings) {
    const data = normalizeFindingData(finding.data);
    const findingForGuidance = { ...finding, data };
    const moduleName = extractModuleName(findingForGuidance);
    const storedGuidance = (data?.remediation ?? data?.remediation_guidance) as RemediationGuidance | undefined;
    const hasFreshStored = storedGuidance?.version === REMEDIATION_GUIDANCE_VERSION;
    const storedIsLLM = storedGuidance?.source === 'llm';
    const hasRawResponse = Boolean(storedGuidance?.rawResponse);

    if (storedGuidance && hasFreshStored && hasRawResponse && (!ENABLE_LLM_REMEDIATION || storedIsLLM)) {
      recordGuidanceEvent({ scanId: context.scanId, guidance: storedGuidance });
      enriched.push({
        ...finding,
        data,
        remediation_guidance: storedGuidance,
        remediation: storedGuidance.description ?? storedGuidance.steps?.[0]?.summary,
        ai_remediation: mapGuidanceToTemplate(storedGuidance, finding, context.domain)
      });
      continue;
    }

    const baseGuidance = storedGuidance ?? extractBaseGuidance(findingForGuidance, moduleName);

    try {
      const guidance = await generateRemediationGuidance({
        context: {
          scanId: context.scanId,
          domain: context.domain,
          moduleName,
          severity: finding.severity,
          findingId: finding.id
        },
        baseGuidance,
        finding: findingForGuidance
      }, {
        reportType: context.reportType,
        useLLM: ENABLE_LLM_REMEDIATION
      });

      persistGuidanceToData(data, guidance);
      await persistFinding(context.scanId, finding, data);

      recordGuidanceEvent({ scanId: context.scanId, guidance });
      const aiRemediation = mapGuidanceToTemplate(guidance, finding, context.domain);

      enriched.push({
        ...finding,
        data,
        remediation_guidance: guidance,
        remediation: guidance.description ?? guidance.steps?.[0]?.summary,
        ai_remediation: aiRemediation
      });
    } catch (error) {
      log.error({ err: error, scanId: context.scanId, findingId: finding.id, moduleName }, 'Failed to generate guidance for finding');
      if (baseGuidance) {
        persistGuidanceToData(data, baseGuidance);
        await persistFinding(context.scanId, finding, data);
        recordGuidanceEvent({ scanId: context.scanId, guidance: baseGuidance });
      } else {
        recordGuidanceEvent({ scanId: context.scanId, guidance: undefined });
      }
      enriched.push({
        ...finding,
        data,
        remediation_guidance: baseGuidance,
        remediation: baseGuidance?.description,
        ai_remediation: baseGuidance ? mapGuidanceToTemplate(baseGuidance, finding, context.domain) : undefined
      });
    }
  }

  return enriched;
}

function extractModuleName(finding: any): string | undefined {
  const data = normalizeFindingData(finding.data);
  return data?.scan_module
    || data?.module
    || data?.meta?.scan_module
    || data?.meta?.module
    || finding.metadata?.module
    || finding.metadata?.scan_module
    || undefined;
}

function extractBaseGuidance(finding: any, moduleName?: string): RemediationGuidance | undefined {
  const data = normalizeFindingData(finding.data);
  const rawGuidance = data?.remediation || data?.remediation_guidance || finding.remediation;

  if (!rawGuidance) {
    const baseline = getBaselineRemediation(moduleName, severityToPriority(finding.severity), finding);
    if (baseline) {
      return baseline;
    }
    return undefined;
  }

  if (typeof rawGuidance === 'string') {
    return {
      priority: severityToPriority(finding.severity),
      description: rawGuidance,
      timeline: undefined,
      businessImpact: undefined,
      ownerHint: undefined,
      effort: undefined,
      verification: [],
      steps: [{ summary: rawGuidance }],
      additionalHardening: undefined,
      references: undefined,
      source: 'module',
      generatedAt: new Date().toISOString(),
      metadata: {
        legacy: true,
        module: moduleName
      },
      version: REMEDIATION_GUIDANCE_VERSION
    };
  }

  if (typeof rawGuidance === 'object') {
    return {
      priority: rawGuidance.priority ? normalizePriority(rawGuidance.priority) : severityToPriority(finding.severity),
      timeline: rawGuidance.timeline,
      description: rawGuidance.description,
      businessImpact: rawGuidance.businessImpact || rawGuidance.impact,
      ownerHint: rawGuidance.ownerHint || rawGuidance.owner,
      effort: rawGuidance.effort,
      verification: rawGuidance.verification || rawGuidance.validation || [],
      steps: mapLegacySteps(rawGuidance.steps),
      additionalHardening: rawGuidance.additionalHardening,
      references: rawGuidance.references,
      source: rawGuidance.source ?? 'module',
      rawResponse: rawGuidance.rawResponse,
      generatedAt: rawGuidance.generatedAt || new Date().toISOString(),
      metadata: {
        ...rawGuidance.metadata,
        module: moduleName
      },
      version: rawGuidance.version ?? REMEDIATION_GUIDANCE_VERSION
    };
  }

  const baseline = getBaselineRemediation(moduleName, severityToPriority(finding.severity), finding);
  if (baseline) {
    return baseline;
  }

  return undefined;
}

function mapLegacySteps(steps: any): { summary: string; details?: string }[] | undefined {
  if (!Array.isArray(steps) || steps.length === 0) return undefined;
  return steps.map((step) => {
    if (typeof step === 'string') {
      return { summary: step };
    }
    if (step && typeof step === 'object') {
      return {
        summary: step.summary || step.title || step.action || 'Perform remediation step',
        details: step.details || step.description
      };
    }
    return { summary: String(step) };
  });
}

function normalizeFindingData(data: any): Record<string, any> {
  if (!data) return {};
  if (typeof data === 'string') {
    try {
      const parsed = JSON.parse(data);
      return typeof parsed === 'object' && parsed ? parsed : {};
    } catch {
      return {};
    }
  }
  if (typeof data === 'object') {
    return data;
  }
  return {};
}

function mapGuidanceToTemplate(guidance: RemediationGuidance, finding?: any, scanDomain?: string) {
  const norm = (s?: string) => normalizeToUSEnglish(s || '');

  // Get enrichment context from finding data for template variable interpolation
  const findingType = finding?.type || guidance.metadata?.finding_type || '';
  const rawContext = finding ? getRemediationContext(findingType, finding) : {};

  // Override domain with scan context domain if not found in finding
  const enrichmentContext = {
    ...rawContext,
    domain: rawContext.domain || scanDomain || 'the domain'
  };

  // Helper to interpolate template variables and normalize
  const enrich = (s?: string) => {
    if (!s) return '';
    const normalized = norm(s);
    return finding ? interpolateTemplate(normalized, enrichmentContext) : normalized;
  };

  // Use the raw LLM response directly for markdown rendering - it has proper formatting
  let stepsMarkdown = guidance.rawResponse ? enrich(guidance.rawResponse) : '';

  // If no raw response (e.g., from remediation library), generate markdown from steps
  if (!stepsMarkdown && guidance.steps && guidance.steps.length > 0) {
    const parts: string[] = [];

    // DO NOT add business impact here - it's rendered separately in "Why This Matters"
    // Adding it here causes duplication

    // Add steps as ordered list
    parts.push('**Remediation Steps:**\n');
    guidance.steps.forEach((step, index) => {
      parts.push(`${index + 1}. ${enrich(step.summary)}`);
      if (step.details) {
        parts.push(`   ${enrich(step.details)}`);
      }
      if (step.verification && step.verification.length > 0) {
        step.verification.forEach(v => {
          parts.push(`   - ${enrich(v)}`);
        });
      }
    });

    // Add verification checklist if present - use checkbox markdown syntax
    if (guidance.verification && guidance.verification.length > 0) {
      // Validation checklist as a separate section with checkboxes
      parts.push('');
      parts.push('---');  // horizontal rule to break out of ordered list
      parts.push('');
      parts.push('**Validation Checklist:**');
      guidance.verification.forEach(v => {
        parts.push(`- [ ] ${enrich(v)}`);  // Checkbox syntax
      });
    }

    stepsMarkdown = parts.join('\n');
  }

  // Strip redundant title/header lines that duplicate the finding title
  // The LLM often includes "Remediation Runbook for X Objective: Y" all on one line
  // Split these compound lines first, then filter
  stepsMarkdown = stepsMarkdown
    // Split "Objective:" from the rest of the line
    .replace(/\s+(Objective|####\s*Objective):\s*/gi, '\n')
    .split('\n')
    .filter(line => {
      const lower = line.toLowerCase().trim();
      if (!lower) return false; // Skip empty lines
      // Skip lines that are redundant titles/headers
      if (lower.includes('remediation runbook')) return false;
      if (lower.includes('remediation plan')) return false;
      if (lower.startsWith('remediation steps:') && lower.length < 30) return false; // Skip standalone header
      if (lower.startsWith('for ') && /(breach|exposure|security|vulnerability|weakness)/i.test(lower)) return false;
      // Skip lines that are just markdown headers for these
      if (/^#+\s*(remediation|objective)/i.test(lower)) return false;
      return true;
    })
    .join('\n')
    .trim();

  // Generate action line: prefer library's explicit action_line, then first step, then description
  // Interpolate template variables in action_line for specific finding details
  const actionLine = guidance.metadata?.action_line
    ? enrich(guidance.metadata.action_line as string)
    : (guidance.steps && guidance.steps.length > 0
        ? enrich(guidance.steps[0].summary)
        : enrich(guidance.description));

  return {
    priority: guidance.priority,
    timeline: norm(guidance.timeline),
    description: enrich(guidance.description),
    impact: enrich(guidance.businessImpact),
    effort: guidance.effort,
    verification: guidance.verification ? guidance.verification.map(v => enrich(v)) : undefined,
    steps_markdown: stepsMarkdown,
    raw_response: guidance.rawResponse,
    owner: guidance.ownerHint,
    additional_hardening: guidance.additionalHardening,
    source: guidance.source,
    action_line: actionLine  // NEW: library-driven action line for title with interpolated variables
  };
}

function normalizeToUSEnglish(input: string): string {
  if (!input) return input;
  const replacements: Array<[RegExp, string|((m: string)=>string)]> = [
    [/\bprioritise\b/gi, 'prioritize'],
    [/\bprioritised\b/gi, 'prioritized'],
    [/\bprioritising\b/gi, 'prioritizing'],
    [/\bunauthoris(e|ed|ing|ation)\b/gi, (m) => m.toLowerCase().replace('unauthoris', 'unauthoriz')],
    [/\bauthoris(e|ed|ing|ation)\b/gi, (m) => m.toLowerCase().replace('authoris', 'authoriz')],
    [/\bauthorised\b/gi, 'authorized'],
    [/\bauthorisation\b/gi, 'authorization'],
    [/\bbehaviour\b/gi, 'behavior'],
    [/\bcolour\b/gi, 'color'],
    [/\bfavourite\b/gi, 'favorite'],
    [/\boptimis(e|ed|ing|ation)\b/gi, (m) => m.toLowerCase().replace('optimis', 'optimiz')],
    [/\borganis(e|ed|ing|ation)\b/gi, (m) => m.toLowerCase().replace('organis', 'organiz')],
    [/\brecognis(e|ed|ing|ation)\b/gi, (m) => m.toLowerCase().replace('recognis', 'recogniz')],
    [/\bdefence\b/gi, 'defense'],
    [/\blicen[cs]e\b/gi, 'license'],
    [/\btravell?ing\b/gi, 'traveling'],
    [/\bcentre\b/gi, 'center'],
    [/\benrol\b/gi, 'enroll']
  ];
  let out = input;
  for (const [re, repl] of replacements) {
    out = out.replace(re, typeof repl === 'function' ? (repl as any) : repl);
  }
  return out;
}

function persistGuidanceToData(targetData: Record<string, any>, guidance: RemediationGuidance) {
  const version = guidance.version ?? REMEDIATION_GUIDANCE_VERSION;
  const generatedAt = guidance.generatedAt ?? new Date().toISOString();

  guidance.version = version;
  guidance.generatedAt = generatedAt;

  targetData.remediation = {
    ...guidance,
    version,
    generatedAt
  };
  targetData.remediation_version = version;
  targetData.remediation_source = guidance.source;
  targetData.remediation_updated_at = generatedAt;
}

async function persistFinding(scanId: string, finding: any, data: Record<string, any>) {
  try {
    await database.insertFinding({
      id: finding.id,
      scan_id: scanId,
      type: finding.type,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      data,
      created_at: finding.created_at instanceof Date ? finding.created_at : new Date(finding.created_at)
    });
  } catch (error) {
    log.error({ err: error, scanId, findingId: finding.id }, 'Failed to persist guidance for finding');
  }
}

function buildTemplateData(baseData: BaseReportData, reportType: ReportType, executiveSummary?: string | null) {
  const { scanData, findings, severityCounts, findingsBySeverity, ealSummary } = baseData;

  const createdAt = scanData?.created_at instanceof Date
    ? scanData.created_at
    : new Date(scanData?.created_at || Date.now());

  const durationSeconds = Math.round((scanData?.duration_ms || 0) / 1000);
  const topFindings = (() => {
    const ordered: any[] = [
      ...findingsBySeverity.CRITICAL,
      ...findingsBySeverity.HIGH,
      ...findingsBySeverity.MEDIUM,
      ...findingsBySeverity.LOW,
      ...findingsBySeverity.INFO
    ];
    return ordered.slice(0, 8);
  })();

  const totalFindings = findings.length;
  const categoryBreakdown = (() => {
    if (!ealSummary) {
      return totalFindings
        ? [{ label: 'All Findings', count: totalFindings }]
        : [];
    }

    const baseCounts = [
      { label: 'Cyber Exposure', count: ealSummary.cyber_findings_count || 0 },
      { label: 'Compliance Gaps', count: ealSummary.compliance_findings_count || 0 },
      { label: 'Cloud Risks', count: ealSummary.cloud_findings_count || 0 }
    ];

    const assignedTotal = baseCounts.reduce((sum, item) => sum + item.count, 0);
    const otherCount = Math.max(totalFindings - assignedTotal, 0);

    if (otherCount > 0) {
      baseCounts.push({ label: 'Other Findings', count: otherCount });
    }

    return baseCounts.filter(item => item.count > 0);
  })();

  const categorySummary: CategorySummaryEntry[] = (() => {
    if (!findings.length) return [];

    const labelForAttack = (code?: string | null) => {
      if (typeof code !== 'string') return 'Unmapped category';
      const normalized = code.trim();
      if (!normalized) return 'Unmapped category';
      const upper = normalized.toUpperCase();
      if (upper in CATEGORY_FRIENDLY_NAMES) {
        return CATEGORY_FRIENDLY_NAMES[upper as keyof typeof CATEGORY_FRIENDLY_NAMES];
      }
      return upper
        .toLowerCase()
        .replace(/_/g, ' ');
    };

    const severityLabels: Record<SeverityKey, string> = {
      CRITICAL: 'critical',
      HIGH: 'high',
      MEDIUM: 'medium',
      LOW: 'low',
      INFO: 'informational'
    };

    const buckets = new Map<string, { counts: Record<SeverityKey, number>; total: number }>();

    findings.forEach(finding => {
      const label = labelForAttack(finding.attack_type_code);
      if (!buckets.has(label)) {
        buckets.set(label, {
          counts: {
            CRITICAL: 0,
            HIGH: 0,
            MEDIUM: 0,
            LOW: 0,
            INFO: 0
          },
          total: 0
        });
      }

      const entry = buckets.get(label)!;
      const severity = (finding.severity || 'INFO').toUpperCase() as SeverityKey;
      if (objectHasKey(severityLabels, severity)) {
        entry.counts[severity] += 1;
      } else {
        entry.counts.INFO += 1;
      }
      entry.total += 1;
    });

    return Array.from(buckets.entries())
      .map(([label, entry]) => {
        const breakdown = (Object.keys(entry.counts) as SeverityKey[])
          .filter(key => entry.counts[key] > 0)
          .map(key => `${entry.counts[key]} ${severityLabels[key]}`);

        const severityText = breakdown.join(', ');

        return {
          label,
          total: entry.total,
          severityText
        };
      })
      .sort((a, b) => b.total - a.total || a.label.localeCompare(b.label));
  })();

  const meaningStatements = (() => {
    const statements: Array<{ icon: string; heading: string; description: string; severity: SeverityKey }> = [];

    const pluralize = (count: number, singular: string) =>
      `${count} ${singular}${count === 1 ? '' : 's'}`;

    const templates: Array<{ severity: SeverityKey; icon: string; heading: string; build: (count: number) => string }> = [
      {
        severity: 'CRITICAL',
        icon: '🚨',
        heading: 'Critical exposure needs immediate action',
        build: (count) => `${pluralize(count, 'critical issue')} open the door to instant compromise—patch these before anything else.`
      },
      {
        severity: 'HIGH',
        icon: '⚠️',
        heading: 'High-risk gaps enable fast escalation',
        build: (count) => `${pluralize(count, 'high severity gap')} let attackers move quickly once inside. Prioritize fixes this week.`
      },
      {
        severity: 'MEDIUM',
        icon: '🔧',
        heading: 'Medium issues signal missing hardening',
        build: (count) => `${pluralize(count, 'medium severity finding')} erode your defensive depth. Tackle them after critical and high work.`
      },
      {
        severity: 'LOW',
        icon: '🧹',
        heading: 'Low findings show hygiene debt',
        build: (count) => `${pluralize(count, 'low severity gap')} highlight operational clean-up to schedule once higher risks are contained.`
      }
    ];

    templates.forEach(({ severity, icon, heading, build }) => {
      const count = severityCounts[severity];
      if (count > 0) {
        statements.push({ icon, heading, description: build(count), severity });
      }
    });

    return statements;
  })();

  // Derive compliance scoreboard (simple presence-based)
  const complianceScoreboard = (() => {
    const has = (pred: (f: any) => boolean) => findings.some(pred);
    const byType = (prefix: string) => (f: any) => String(f.type || '').toUpperCase().startsWith(prefix);
    const flags = {
      email_auth: has(f => /EMAIL_SECURITY_(GAP|WEAKNESS|EXPOSURE)/.test(String(f.type || '').toUpperCase())),
      ada: has(f => String(f.type || '').toUpperCase().startsWith('ADA_')),
      pci: has(byType('PCI_')),
      privacy: has(byType('GDPR_'))
    };
    return {
      email_auth: flags.email_auth ? 'Needs Attention' : 'OK',
      ada: flags.ada ? 'Needs Attention' : 'OK',
      pci: flags.pci ? 'Needs Attention' : 'OK',
      privacy: flags.privacy ? 'Needs Attention' : 'OK'
    };
  })();

  // Build Top 3 Business Actions from per-family EAL
  const businessActions = (() => {
    const ENABLE_TYPO_ACTIONS = (process.env.ENABLE_TYPO_ACTIONS ?? '0') === '1';
    const mapFamilyToTitle = (family: string): string => {
      const f = family.toUpperCase();
      // Credential/breach issues (infostealer, password breaches) - check first
      if (f.includes('CREDENTIAL') || f.includes('INFOSTEALER') || f.includes('PASSWORD') || f.includes('BREACH')) {
        return 'Address compromised credentials (password resets, 2FA)';
      }
      if (f.includes('EMAIL') || f.includes('PHISHING') || f.includes('BEC')) return 'Stop email spoofing (SPF/DKIM/DMARC)';
      if (f.includes('TLS')) return 'Fix website security (HTTPS/TLS)';
      if (f.includes('SITE_HACK') || f.includes('WEB') || f.includes('APP')) return 'Patch website weaknesses';
      if (f.includes('CLIENT_SIDE_SECRET')) return 'Remove exposed credentials from webpages';
      if (f.includes('EXPOSED_SERVICE') || f.includes('EXPOSED_DATABASE')) return 'Close publicly exposed services/databases';
      if (f.includes('SENSITIVE_FILE')) return 'Remove sensitive files from the internet';
      // Do not mention look‑alike/typosquats by default
      if (f.includes('ADA')) return 'Fix ADA accessibility issues';
      if (f.includes('PCI')) return 'Fix PCI compliance gaps';
      if (f.includes('GDPR')) return 'Address privacy compliance gaps';
      if (f.includes('CLOUD') || f.includes('DENIAL')) return 'Reduce cloud misconfiguration risk';
      return 'Reduce security risk in key area';
    };

    const timelineForSeverity = timelineForSeverityGlobal;

    // Group findings by family/type
    const findFamilySeverity = (family: string): SeverityKey => {
      const upper = family.toUpperCase();
      const related = findings.filter(f => String(f.type || '').toUpperCase().includes(upper));
      const counts: Record<SeverityKey, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      related.forEach(f => {
        const sev = String(f.severity || 'INFO').toUpperCase() as SeverityKey;
        if (counts[sev] !== undefined) counts[sev] += 1;
      });
      const order: SeverityKey[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      return order.reduce((best, s) => (counts[s] > counts[best] ? s : best), 'INFO');
    };

    const totalMlBA = ealSummary?.total_eal_ml || 0;
    const patternsByFamily: Record<string, RegExp[]> = {
      // Credential/breach families
      CREDENTIAL_COMPROMISE: [/BREACH_EXPOSURE/, /PASSWORD_BREACH/, /CREDENTIAL/, /INFOSTEALER/],
      // Email/phishing families
      PHISHING_BEC: [/EMAIL_SECURITY/, /PHISHING/, /BEC/, /EMAIL_BREACH/],
      EMAIL_SECURITY_GAP: [/EMAIL_SECURITY_(GAP|WEAKNESS|EXPOSURE)/, /PHISHING_BEC/],
      EMAIL_SECURITY_WEAKNESS: [/EMAIL_SECURITY_(GAP|WEAKNESS|EXPOSURE)/, /PHISHING_BEC/],
      EMAIL_BREACH_EXPOSURE: [/EMAIL_BREACH_EXPOSURE/, /PASSWORD_BREACH_EXPOSURE/],
      // TLS families
      MISSING_TLS_CERTIFICATE: [/MISSING_TLS_CERTIFICATE/, /TLS_CONFIGURATION_ISSUE/, /TLS_/],
      TLS_CONFIGURATION_ISSUE: [/TLS_CONFIGURATION_ISSUE/, /MISSING_TLS_CERTIFICATE/, /TLS_/],
      // Website families
      SITE_HACK: [/SITE_HACK/, /WEB/, /CVE/, /VULNERABILITY/],
      CLIENT_SIDE_SECRET_EXPOSURE: [/CLIENT_SIDE_SECRET_EXPOSURE/],
      SENSITIVE_FILE_EXPOSURE: [/SENSITIVE_FILE_EXPOSURE/],
      EXPOSED_SERVICE: [/EXPOSED_SERVICE/],
      EXPOSED_DATABASE: [/EXPOSED_DATABASE/],
      // Other families
      MALICIOUS_TYPOSQUAT: [/MALICIOUS_TYPOSQUAT/, /PHISHING_INFRASTRUCTURE/],
      PHISHING_INFRASTRUCTURE: [/PHISHING_INFRASTRUCTURE/, /MALICIOUS_TYPOSQUAT/],
      ADA_COMPLIANCE: [/ADA_/], PCI_COMPLIANCE_FAILURE: [/PCI_/], GDPR_VIOLATION: [/GDPR_/]
    };

    const hasRelated = (family: string): boolean => {
      const fam = family.toUpperCase();
      if ((fam.includes('MALICIOUS_TYPOSQUAT') || fam.includes('PHISHING_INFRASTRUCTURE')) && !ENABLE_TYPO_ACTIONS) {
        return false; // suppress lookalike/phishing infra unless explicitly enabled
      }
      const pats = patternsByFamily[fam] || [new RegExp(fam)];
      return findings.some(f => {
        const t = String(f.type || '').toUpperCase();
        return pats.some(rx => rx.test(t));
      });
    };

    // Compute raw effective values per family
    const rawEntries = Object.entries(baseData.ealByFamily || {})
      .map(([family, v]) => ({
        family,
        sum_ml: v.sum_ml || 0,
        // Use capped value (what actually contributes to total EAL), not raw sum
        effective_ml: v.cap_ml !== undefined ? Math.min(v.sum_ml || 0, v.cap_ml) : (v.sum_ml || 0)
      }))
      .filter(e => e.effective_ml > 0 && hasRelated(e.family))
      .sort((a, b) => b.effective_ml - a.effective_ml)
      .slice(0, 3);

    // Normalize effective_ml values to sum to total_eal_ml (audit view caps may differ from summary)
    const rawSum = rawEntries.reduce((s, e) => s + e.effective_ml, 0);
    const scaleFactorBA = (rawSum > 0 && totalMlBA > 0) ? totalMlBA / rawSum : 1;

    const entries = rawEntries.map(e => {
        const normalizedMl = Math.round(e.effective_ml * scaleFactorBA);
        const severity: SeverityKey = findFamilySeverity(e.family);
        const title = mapFamilyToTitle(e.family);
        const timeline = timelineForSeverity(severity);
        const reductionMl = normalizedMl;
        const reductionPct = totalMlBA > 0 ? Math.round((reductionMl / totalMlBA) * 100) : 0;
        const verify = (() => {
          const fam = e.family.toUpperCase();
          if (fam.includes('CREDENTIAL') || fam.includes('BREACH') || fam.includes('PASSWORD') || fam.includes('INFOSTEALER')) {
            return 'Affected users have reset passwords and enabled 2FA; no new breach exposures detected.';
          }
          if (fam.includes('EMAIL') || fam.includes('PHISHING') || fam.includes('BEC')) return 'Re-scan shows SPF/DKIM published and DMARC at p=quarantine or stronger.';
          if (fam.includes('TLS')) return 'Re-scan shows a valid certificate and modern TLS only.';
          if (fam.includes('EXPOSED_SERVICE') || fam.includes('EXPOSED_DATABASE')) return 'Service/database is no longer reachable from the internet.';
          if (fam.includes('SENSITIVE_FILE')) return 'Sensitive files are no longer publicly accessible.';
          return 'Re-scan confirms the issue is resolved.';
        })();
        return {
          title,
          family: e.family,
          severity,
          timeline,
          estimated_reduction_ml: reductionMl,
          estimated_reduction_pct: reductionPct,
          verification: verify
        };
      });
    if (entries.length > 0) return entries;

    // Fallback: estimate by category weights derived from findings and severity
    const sevWeight: Record<SeverityKey, number> = {
      CRITICAL: 1.0, HIGH: 0.6, MEDIUM: 0.35, LOW: 0.15, INFO: 0
    };
    type CatKey = 'EMAIL'|'CREDENTIAL'|'TLS'|'WEBSITE'|'CLOUD'|'COMPLIANCE'|'OTHER';
    const bucketFor = (typeStr: string): CatKey => {
      const t = typeStr.toUpperCase();
      if (t.includes('BREACH') || t.includes('CREDENTIAL') || t.includes('INFOSTEALER') || t.includes('PASSWORD')) return 'CREDENTIAL';
      if (t.includes('EMAIL') && !t.includes('BREACH')) return 'EMAIL';
      if (t.includes('TLS') || t.includes('CERT')) return 'TLS';
      if (t.includes('CLOUD') || t.includes('EXPOSED_SERVICE') || t.includes('EXPOSED_DATABASE')) return 'CLOUD';
      if (t.includes('ADA') || t.includes('PCI') || t.includes('GDPR') || t.includes('COMPLIANCE')) return 'COMPLIANCE';
      if (t.includes('SITE_HACK') || t.includes('WEB') || t.includes('APP') || t.includes('CLIENT_SIDE') || t.includes('SENSITIVE_FILE')) return 'WEBSITE';
      return 'OTHER';
    };
    const bucketTitle = (key: CatKey): string =>
      key === 'CREDENTIAL' ? 'Address compromised credentials (password resets, 2FA)'
      : key === 'EMAIL' ? 'Stop email spoofing (SPF/DKIM/DMARC)'
      : key === 'TLS' ? 'Fix website security (HTTPS/TLS)'
      : key === 'WEBSITE' ? 'Patch website weaknesses'
      : key === 'CLOUD' ? 'Reduce cloud misconfiguration risk'
      : key === 'COMPLIANCE' ? 'Fix compliance gaps'
      : 'Reduce security risk in key area';

    const buckets = new Map<CatKey, { w: number; maxSev: SeverityKey }>();
    findings.forEach(f => {
      const key = bucketFor(String(f.type || ''));
      const sev = (String(f.severity || 'INFO').toUpperCase() as SeverityKey);
      const prev = buckets.get(key) || { w: 0, maxSev: 'INFO' as SeverityKey };
      prev.w += sevWeight[sev] || 0;
      const order: SeverityKey[] = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
      prev.maxSev = order.indexOf(sev) < order.indexOf(prev.maxSev) ? sev : prev.maxSev;
      buckets.set(key, prev);
    });

    const totalW = Array.from(buckets.values()).reduce((a,b)=> a + b.w, 0) || 0;
    const totalMlBA2 = ealSummary?.total_eal_ml || 0;
    const fallback = Array.from(buckets.entries())
      .filter(([k,v]) => v.w > 0)
      .map(([k,v]) => ({
        title: bucketTitle(k),
        family: k,
        severity: v.maxSev,
        timeline: timelineForSeverity(v.maxSev),
        estimated_reduction_ml: totalW > 0 ? Math.round((v.w / totalW) * totalMlBA2) : 0,
        estimated_reduction_pct: totalW > 0 && totalMlBA2 > 0 ? Math.round(((v.w / totalW) * 100)) : 0,
        verification: ((): string => {
          if (k === 'CREDENTIAL') return 'Affected users have reset passwords and enabled 2FA; no new breach exposures detected.';
          if (k === 'EMAIL') return 'Re-scan shows SPF/DKIM are published and DMARC is enforced.';
          if (k === 'TLS') return 'Re-scan shows a valid certificate and modern TLS only.';
          if (k === 'WEBSITE') return 'Re-scan shows patched vulnerabilities and no exposed secrets/files.';
          if (k === 'CLOUD') return 'Re-scan shows public services closed or access controlled.';
          if (k === 'COMPLIANCE') return 'Re-scan shows reduced compliance findings (ADA/PCI/Privacy).';
          return 'Re-scan confirms the issue is resolved.';
        })()
      }))
      .sort((a,b)=> b.estimated_reduction_ml - a.estimated_reduction_ml)
      .slice(0,3);

    return fallback;
  })();

  // Category performance (business view) - EXCLUDES compliance (shown separately)
  const categoryPerformance = (() => {
    const labelFor = (key: string) => {
      if (key === 'email') return 'Email Security';
      if (key === 'website') return 'Website Security';
      if (key === 'cloud') return 'Cloud & Infrastructure';
      if (key === 'credential') return 'Credential Exposure';
      return 'Website Security'; // fallback to a defined bucket (never "Other")
    };

    // Compliance excluded - it's a separate category (contingent legal liability, not cyber EAL)
    type CatKey = 'email'|'website'|'cloud'|'credential';
    const catOrder: CatKey[] = ['email','website','cloud','credential'];

    const mapFamilyToCat = (family: string): CatKey | null => {
      const f = family.toUpperCase();
      // Skip compliance families - they're shown separately
      if (f.includes('ADA') || f.includes('PCI') || f.includes('GDPR') || f.includes('COMPLIANCE')) return null;
      if (f.includes('EMAIL') || f.includes('PHISHING') || f.includes('BEC')) return 'email';
      if (f.includes('BREACH') || f.includes('CREDENTIAL') || f.includes('INFOSTEALER') || f.includes('PASSWORD')) return 'credential';
      if (f.includes('TLS') || f.includes('SITE_HACK') || f.includes('WEB') || f.includes('APP') || f.includes('CLIENT_SIDE') || f.includes('SENSITIVE_FILE')) return 'website';
      if (f.includes('CLOUD') || f.includes('DENIAL') || f.includes('EXPOSED_SERVICE') || f.includes('EXPOSED_DATABASE')) return 'cloud';
      return 'website';
    };

    const buckets: Record<CatKey, { ml: number; topFamily?: string }> = {
      email: { ml: 0 }, website: { ml: 0 }, cloud: { ml: 0 }, credential: { ml: 0 }
    };
    for (const [family, v] of Object.entries(baseData.ealByFamily || {})) {
      const cat = mapFamilyToCat(family);
      if (!cat) continue; // Skip compliance families
      // Use capped value (what actually contributes to total EAL), not raw sum
      const effectiveMl = v.cap_ml !== undefined ? Math.min(v.sum_ml || 0, v.cap_ml) : (v.sum_ml || 0);
      buckets[cat].ml += effectiveMl;
      if (!buckets[cat].topFamily || (baseData.ealByFamily![buckets[cat].topFamily!]?.sum_ml || 0) < (v.sum_ml || 0)) {
        buckets[cat].topFamily = family;
      }
    }

    // Use raw bucket sum as the cyber-only total (compliance excluded)
    const cyberOnlyTotal = Object.values(buckets).reduce((s, b) => s + b.ml, 0);

    let result = catOrder.map((key) => {
      const data = buckets[key];
      const fam = data.topFamily || key;
      const sev = (() => {
        const related = findings.filter(f => String(f.type || '').toUpperCase().includes((fam || '').toUpperCase()));
        const order: SeverityKey[] = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
        const counts: Record<SeverityKey, number> = { CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0 };
        related.forEach(f => { const s = String(f.severity||'INFO').toUpperCase() as SeverityKey; counts[s] = (counts[s]||0)+1; });
        return order.reduce((best, s)=> counts[s]>counts[best]?s:best, 'INFO');
      })();
      const timeline = ((): string => {
        if (sev === 'CRITICAL') return 'Within 24 hours';
        if (sev === 'HIGH') return 'Within 7 days';
        if (sev === 'MEDIUM') return 'Within 30 days';
        return 'Next maintenance cycle';
      })();
      const status = data.ml > 0 ? 'Needs Attention' : 'OK';
      // Percentage is within cyber categories only (not total EAL which includes compliance)
      const pct = cyberOnlyTotal > 0 ? Math.round((data.ml / cyberOnlyTotal) * 100) : 0;
      return {
        key,
        label: labelFor(key),
        status,
        estimated_ml: data.ml,
        estimated_pct: pct,
        timeline
      };
    });

    // Sort: Needs Attention first, then by estimated_ml descending
    result.sort((a, b) => {
      if (a.status !== b.status) {
        return a.status === 'Needs Attention' ? -1 : 1;
      }
      return b.estimated_ml - a.estimated_ml;
    });

    // Only return if we have categories with actual risk
    const hasRisk = result.some(r => r.estimated_ml > 0);
    if (hasRisk) return result;

    // Fallback: weight categories from findings when per-family audit is unavailable
    // Compliance excluded - it's shown separately
    const sevWeight: Record<SeverityKey, number> = { CRITICAL:1, HIGH:0.6, MEDIUM:0.35, LOW:0.15, INFO:0 };
    const bucketForType = (typeStr: string): CatKey | null => {
      const t = typeStr.toUpperCase();
      // Skip compliance - shown separately
      if (t.includes('ADA') || t.includes('PCI') || t.includes('GDPR') || t.includes('COMPLIANCE')) return null;
      if (t.includes('EMAIL') && !t.includes('BREACH')) return 'email';
      if (t.includes('BREACH') || t.includes('CREDENTIAL') || t.includes('INFOSTEALER') || t.includes('PASSWORD')) return 'credential';
      if (t.includes('TLS') || t.includes('SITE_HACK') || t.includes('WEB') || t.includes('APP') || t.includes('CLIENT_SIDE') || t.includes('SENSITIVE_FILE')) return 'website';
      if (t.includes('CLOUD') || t.includes('EXPOSED_SERVICE') || t.includes('EXPOSED_DATABASE')) return 'cloud';
      return 'website';
    };
    const agg: Record<CatKey, { w: number; maxSev: SeverityKey }> = {
      email: { w: 0, maxSev: 'INFO' }, website: { w: 0, maxSev: 'INFO' }, cloud: { w: 0, maxSev: 'INFO' }, credential: { w: 0, maxSev: 'INFO' }
    };
    const order: SeverityKey[] = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
    findings.forEach(f => {
      const key = bucketForType(String(f.type || ''));
      if (!key) return; // Skip compliance
      const sev = (String(f.severity || 'INFO').toUpperCase() as SeverityKey);
      agg[key].w += sevWeight[sev];
      agg[key].maxSev = order.indexOf(sev) < order.indexOf(agg[key].maxSev) ? sev : agg[key].maxSev;
    });
    const totalW = (Object.values(agg).reduce((s,a)=> s + a.w, 0)) || 0;
    // Use cyber-only EAL (total minus compliance)
    const complianceMl = ealSummary?.compliance_risk || 0;
    const cyberMl = Math.max(0, (ealSummary?.total_eal_ml || 0) - complianceMl);
    result = catOrder.map((k) => {
      const ml = totalW > 0 ? Math.round((agg[k].w / totalW) * cyberMl) : 0;
      const status = ml > 0 ? 'Needs Attention' : 'OK';
      const pct = cyberMl > 0 ? Math.round((ml / cyberMl) * 100) : 0;
      return { key: k, label: labelFor(k), status, estimated_ml: ml, estimated_pct: pct, timeline: timelineForSeverityGlobal(agg[k].maxSev) };
    });

    return result;
  })();

  // Overall business summary from Top 3 actions
  const businessSummary = (() => {
    const totalMlSum = ealSummary?.total_eal_ml || 0;
    const sumMl = (businessActions || []).reduce((acc, a) => acc + (a.estimated_reduction_ml || 0), 0);
    const pct = totalMlSum > 0 ? Math.round((sumMl / totalMlSum) * 100) : 0;
    const window = ((): string => {
      // Take the slowest timeline among actions
      const times = (businessActions || []).map(a => a.timeline);
      if (times.some(t => /24 hours/i.test(t))) return 'Start within 24 hours; finish in 30 days';
      if (times.some(t => /7 days/i.test(t))) return 'Start this week; finish in 30 days';
      return 'Complete within 30 days';
    })();
    return { total_estimated_reduction_ml: sumMl, total_estimated_reduction_pct: pct, recommended_window: window };
  })();

  // Risk drivers for snapshot: pull business_impact text from remediation library
  // Groups findings by category and extracts business-facing explanations
  const riskDrivers = (() => {
    if (!findings.length) return [];

    // Group findings by category and collect unique business impacts
    const categoryImpacts = new Map<string, {
      category: string;
      impacts: Set<string>;
      severity: SeverityKey;
      estimated_ml: number;
    }>();

    // Map category labels to their EAL from categoryPerformance
    const categoryEal = new Map<string, number>();
    (categoryPerformance || []).forEach((cp: any) => {
      categoryEal.set(cp.label, cp.estimated_ml || 0);
    });

    findings.forEach((f: any) => {
      const type = String(f.type || '').toUpperCase();
      const severity = (f.severity || 'INFO').toUpperCase() as SeverityKey;

      // Get business_impact from remediation library
      const impact = getBusinessImpact(type);
      if (!impact) return; // Skip if no business_impact defined

      // Determine category label
      const attackCode = (f.attack_type_code || '').toUpperCase();
      let categoryLabel = 'Other Risk';
      if (attackCode.includes('CREDENTIAL') || attackCode.includes('BREACH') || type.includes('BREACH')) {
        categoryLabel = 'Credential Exposure';
      } else if (attackCode.includes('EMAIL') || attackCode.includes('PHISHING') || type.includes('EMAIL')) {
        categoryLabel = 'Email Security';
      } else if (attackCode.includes('TLS') || attackCode.includes('SITE_HACK') || type.includes('TLS')) {
        categoryLabel = 'Website Security';
      } else if (attackCode.includes('ADA') || attackCode.includes('COMPLIANCE')) {
        categoryLabel = 'Compliance';
      } else if (attackCode.includes('CLOUD') || attackCode.includes('EXPOSED')) {
        categoryLabel = 'Cloud & Infrastructure';
      }

      if (!categoryImpacts.has(categoryLabel)) {
        categoryImpacts.set(categoryLabel, {
          category: categoryLabel,
          impacts: new Set(),
          severity: 'INFO',
          estimated_ml: categoryEal.get(categoryLabel) || 0
        });
      }

      const entry = categoryImpacts.get(categoryLabel)!;
      entry.impacts.add(impact);

      // Track highest severity
      const severityOrder: SeverityKey[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      if (severityOrder.indexOf(severity) < severityOrder.indexOf(entry.severity)) {
        entry.severity = severity;
      }
    });

    // Convert to array, sorted by EAL descending, take top 3
    return Array.from(categoryImpacts.values())
      .filter(c => c.impacts.size > 0)
      .sort((a, b) => b.estimated_ml - a.estimated_ml)
      .slice(0, 3)
      .map(c => ({
        category: c.category,
        severity: c.severity,
        estimated_ml: c.estimated_ml,
        // Combine unique business impacts into a single paragraph
        description: Array.from(c.impacts).slice(0, 2).join(' ')
      }));
  })();

  return {
    report_type: reportType,
    scan_id: scanData?.id || 'unknown-scan',
    domain: scanData?.domain || 'unknown',
    scan_date: createdAt.toLocaleDateString(),
    report_date: new Date().toLocaleDateString(),
    duration_seconds: durationSeconds,
    modules_completed: scanData?.metadata?.modules_completed || 0,
    total_findings: findings.length,
    findings: findings.slice(0, 50),
    findings_by_severity: findingsBySeverity,
    severity_counts: severityCounts,
    has_critical_findings: severityCounts.CRITICAL > 0,
    top_findings: topFindings,
    eal_summary: ealSummary,
    category_breakdown: categoryBreakdown,
    category_summary: categorySummary,
    meaning_statements: meaningStatements,
    metadata: scanData?.metadata || {},
    business_actions: businessActions,
    compliance_scoreboard: complianceScoreboard,
    category_performance: categoryPerformance,
    business_summary: businessSummary,
    risk_drivers: riskDrivers,
    executive_summary: executiveSummary || undefined
  };
}

async function renderAndSaveReport(scan_id: string, reportType: ReportType) {
  const start = Date.now();
  const baseData = await assembleReportData(scan_id, reportType);

  // Generate executive summary for technical-report (cached on scan metadata)
  let executiveSummary: string | null = null;
  const llmEnabled = process.env.ENABLE_LLM_REMEDIATION === '1' || process.env.ENABLE_LLM_REMEDIATION === 'true';
  if (reportType === 'technical-report' && llmEnabled) {
    // Check for cached executive summary
    const cachedSummary = baseData.scanData?.metadata?.executive_summary as string | undefined;
    if (cachedSummary) {
      executiveSummary = cachedSummary;
      log.debug({ scan_id }, 'Using cached executive summary');
    } else {
      // Generate new summary
      const topFindings = [
        ...baseData.findingsBySeverity.CRITICAL,
        ...baseData.findingsBySeverity.HIGH,
        ...baseData.findingsBySeverity.MEDIUM
      ].slice(0, 5);

      const categorySummary = Array.from(
        baseData.findings.reduce((acc, f) => {
          const cat = String(f.attack_type_code || 'Other');
          acc.set(cat, (acc.get(cat) || 0) + 1);
          return acc;
        }, new Map<string, number>())
      ).map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      const summaryInput: ExecutiveSummaryInput = {
        domain: baseData.scanData?.domain || 'unknown',
        totalFindings: baseData.findings.length,
        severityCounts: {
          critical: baseData.severityCounts.CRITICAL,
          high: baseData.severityCounts.HIGH,
          medium: baseData.severityCounts.MEDIUM,
          low: baseData.severityCounts.LOW
        },
        categorySummary,
        topFindings: topFindings.map(f => ({
          type: f.type || 'unknown',
          severity: f.severity || 'unknown',
          title: f.title || 'Untitled finding'
        })),
        ealSummary: baseData.ealSummary ? {
          ml: baseData.ealSummary.total_eal_ml,
          low: baseData.ealSummary.total_eal_low,
          high: baseData.ealSummary.total_eal_high
        } : undefined
      };

      executiveSummary = await generateExecutiveSummary(summaryInput, {
        logger: (msg, meta) => log.debug(meta, msg)
      });

      // Cache the summary on scan metadata
      if (executiveSummary) {
        try {
          const currentMetadata = baseData.scanData?.metadata || {};
          const updatedMetadata = {
            ...currentMetadata,
            executive_summary: executiveSummary
          };
          await database.query(
            'UPDATE scans SET metadata = $1 WHERE id = $2',
            [JSON.stringify(updatedMetadata), scan_id]
          );
          log.debug({ scan_id }, 'Cached executive summary');
        } catch (error) {
          log.error({ err: error, scan_id }, 'Failed to cache executive summary');
        }
      }
    }
  }

  const templateData = buildTemplateData(baseData, reportType, executiveSummary);
  const template = await loadTemplate(reportType);
  const html = template(templateData);

  // PDF generation disabled - HTML only for now
  // const pdfBuffer = await generatePDF(html);
  // const pdfPath = await database.saveReport(scan_id, Buffer.from(pdfBuffer), 'pdf', reportType);
  const pdfPath = null;

  const htmlPath = await database.saveReport(scan_id, Buffer.from(html, 'utf-8'), 'html', reportType);
  const duration = Date.now() - start;

  log.info({ scan_id, reportType, duration_ms: duration }, 'Report HTML generated');

  return {
    pdfPath,
    htmlPath,
    duration,
    templateData
  };
}

async function generateReportForScan(scan_id: string, reportType: ReportType = 'report') {
  try {
    await renderAndSaveReport(scan_id, reportType);
    return { success: true };
  } catch (error: any) {
    log.error({ err: error, scan_id, reportType }, 'Failed to generate report');
    return { success: false, error: error.message };
  }
}

// Debug endpoint for testing (same as GCP version but simpler)
app.post('/debug/test-endpoints', async (req, res) => {
  const domain = req.body?.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  
  try {
    const result = await executeScan({ scan_id: `debug-${nanoid()}`, domain });
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
const port = Number(process.env.PORT ?? 8080);
app.listen(port, '127.0.0.1', () => {
  log.info({ port, maxConcurrentScans: MAX_CONCURRENT_SCANS }, 'Local Scanner Server with Queue running');
  log.info({ endpoint: `/health` }, 'Health check endpoint');
  log.info({ endpoint: `POST /scan` }, 'Start scan endpoint');
  log.info({ endpoint: `/queue/status` }, 'Queue status endpoint');
  log.info({ endpoint: `/scans` }, 'List scans endpoint');
  log.info({ endpoint: `/reports/{scan_id}/report.pdf` }, 'Reports endpoint');
});

// Add error handlers for debugging
process.on('uncaughtException', async (error) => {
  log.fatal({ err: error }, 'Uncaught exception');
  await gracefulShutdown();
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log.error({ reason, promise: String(promise) }, 'Unhandled rejection');
});

// Graceful shutdown function
async function gracefulShutdown() {
  log.info('Shutting down gracefully');

  try {
    // Shutdown queue first (waits for running scans to complete)
    await queueService.shutdown();
    log.info('Queue shutdown complete');
  } catch (error) {
    log.error({ err: error }, 'Queue shutdown error');
  }

  // Close database connections
  await database.close();
  log.info('Database connections closed');
}

// Graceful shutdown handlers
process.on('SIGINT', async () => {
  await gracefulShutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  log.info('Received SIGTERM, shutting down');
  await gracefulShutdown();
  process.exit(0);
});
  const timelineForSeverityGlobal = (sev: SeverityKey): string => {
    if (sev === 'CRITICAL') return 'Within 24 hours';
    if (sev === 'HIGH') return 'Within 7 days';
    if (sev === 'MEDIUM') return 'Within 30 days';
    return 'Next maintenance cycle';
  };
