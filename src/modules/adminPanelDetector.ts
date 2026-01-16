/* =============================================================================
 * MODULE: adminPanelDetector.ts
 * =============================================================================
 * Detects exposed admin panels, development environments, and sensitive files.
 *
 * Unlike endpointDiscovery (which saves artifacts), this module creates
 * findings for actually exposed resources that represent security risks.
 *
 * CRITICAL: This module must have LOW false positive rates.
 * We verify actual file/resource formats, not just keyword mentions.
 *
 * Detection approach:
 *   1. Probe paths for sensitive resources
 *   2. Verify response matches ACTUAL file format (not just contains keywords)
 *   3. Filter out captcha pages, 404s, and other false positives
 *   4. Create findings only for genuinely exposed resources
 *
 * Time budget: ~30 seconds
 * =============================================================================
 */

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('adminPanelDetector');

// Configuration
const CONFIG = {
  REQUEST_TIMEOUT_MS: 8_000,
  CONCURRENT_REQUESTS: 3,
  DELAY_BETWEEN_BATCHES_MS: 300,
  MAX_BODY_SIZE: 256 * 1024, // 256 KB
} as const;

// Patterns that indicate FALSE POSITIVES - actual blocking/error pages
// These must be specific to avoid filtering legitimate pages that mention these terms
const FALSE_POSITIVE_PATTERNS = [
  // SiteGround captcha - specific patterns
  /class="?sg-captcha/i,
  /sgcaptcha.*verify/i,
  /\.well-known\/sgcaptcha/i,            // SiteGround captcha redirect URL
  /meta.*refresh.*sgcaptcha/i,           // Meta refresh to captcha

  // Cloudflare challenge pages - specific structure, not just keyword
  /cf-challenge-running/i,
  /data-ray.*data-sitekey/i,
  /<title>.*Attention Required.*Cloudflare/i,
  /<title>.*Just a moment.*Cloudflare/i,

  // CAPTCHA challenges - require actual captcha form elements
  /g-recaptcha.*data-sitekey/i,
  /h-captcha.*data-sitekey/i,

  // 404/Not Found - only in title tags (not body text)
  /<title>\s*404\s*</i,
  /<title>\s*Not Found\s*</i,
  /<title>\s*Page Not Found\s*</i,

  // Access denied pages - look for page structure, not just keywords
  /<title>\s*403\s*</i,
  /<title>\s*Access Denied\s*</i,
  /<title>\s*Forbidden\s*</i,
  /<title>\s*Unauthorized\s*</i,
];

// Path definitions with STRICT detection patterns
interface ProbePath {
  path: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  findingType: string;
  // ALL patterns must match (AND logic) for stricter detection
  requiredPatterns: RegExp[];
  // Content-type hint for additional validation
  expectedContentType?: 'text' | 'html' | 'json' | 'binary';
  description: string;
}

const PROBE_PATHS: ProbePath[] = [
  // ============================================================
  // TIER 1: CRITICAL - Files with STRICT format requirements
  // ============================================================
  {
    path: '/.git/config',
    name: 'Exposed Git Config',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_GIT_CONFIG',
    // Git config has very specific format - require multiple markers
    requiredPatterns: [
      /\[core\]/,                    // Must have [core] section
      /repositoryformatversion\s*=/i, // Must have version line
    ],
    expectedContentType: 'text',
    description: 'Git configuration file is publicly accessible. Attackers can clone the repository.',
  },
  {
    path: '/.git/HEAD',
    name: 'Exposed Git HEAD',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_GIT_CONFIG',
    // Git HEAD is a tiny file with specific format
    requiredPatterns: [
      /^ref: refs\/heads\/[a-zA-Z0-9_\-./]+\s*$/m, // Exact ref format
    ],
    expectedContentType: 'text',
    description: 'Git HEAD file exposed, repository can be cloned.',
  },
  {
    path: '/.env',
    name: 'Exposed Environment File',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_ENV_FILE',
    // Env files have KEY=value format, require multiple env-like lines
    requiredPatterns: [
      /^[A-Z][A-Z0-9_]*=.+$/m,       // At least one KEY=value line
      /^[A-Z][A-Z0-9_]*=.+$/gm,      // Multiple lines matching (will check count)
    ],
    expectedContentType: 'text',
    description: 'Environment file with credentials exposed.',
  },
  {
    path: '/actuator/env',
    name: 'Spring Boot Environment',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_ACTUATOR',
    // Actuator env returns specific JSON structure
    requiredPatterns: [
      /"activeProfiles"\s*:/,        // Must have activeProfiles
      /"propertySources"\s*:/,       // Must have propertySources
    ],
    expectedContentType: 'json',
    description: 'Spring Boot actuator exposes environment variables.',
  },
  {
    path: '/actuator/heapdump',
    name: 'Spring Boot Heap Dump',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_ACTUATOR',
    // Heap dumps start with JAVA PROFILE binary signature
    requiredPatterns: [
      /^JAVA PROFILE/,
    ],
    expectedContentType: 'binary',
    description: 'Spring Boot heap dump exposes application memory.',
  },

  // ============================================================
  // phpMyAdmin - Require ACTUAL login form elements
  // ============================================================
  {
    path: '/phpmyadmin/',
    name: 'phpMyAdmin Login',
    severity: 'HIGH',  // Downgraded - login page is expected behavior
    findingType: 'EXPOSED_DATABASE_ADMIN',
    // Must have actual phpMyAdmin form elements
    requiredPatterns: [
      /pma_username|pma_password|name="pma_/i, // PMA form fields
      /phpmyadmin/i,                            // Brand mention
    ],
    expectedContentType: 'html',
    description: 'phpMyAdmin login page accessible (verify credentials are strong).',
  },
  {
    path: '/phpMyAdmin/',
    name: 'phpMyAdmin Login (alt)',
    severity: 'HIGH',
    findingType: 'EXPOSED_DATABASE_ADMIN',
    requiredPatterns: [
      /pma_username|pma_password|name="pma_/i,
      /phpmyadmin/i,
    ],
    expectedContentType: 'html',
    description: 'phpMyAdmin login page accessible.',
  },

  // ============================================================
  // Adminer - Require actual login form
  // ============================================================
  {
    path: '/adminer.php',
    name: 'Adminer Login',
    severity: 'HIGH',
    findingType: 'EXPOSED_DATABASE_ADMIN',
    // Adminer has specific form structure
    requiredPatterns: [
      /name="auth\[driver\]"|name="auth\[server\]"|name="auth\[username\]"/i,
      /adminer/i,
    ],
    expectedContentType: 'html',
    description: 'Adminer database login page accessible.',
  },

  // ============================================================
  // phpinfo() - Require actual PHP info output
  // ============================================================
  {
    path: '/phpinfo.php',
    name: 'PHP Info Page',
    severity: 'HIGH',
    findingType: 'EXPOSED_DEBUG_ENDPOINT',
    // phpinfo has very specific structure
    requiredPatterns: [
      /PHP Version\s*<\/h1>|<h1[^>]*>PHP Version/i,  // Version header
      /Configuration|php\.ini/i,                       // Config section
    ],
    expectedContentType: 'html',
    description: 'phpinfo() exposes server configuration.',
  },

  // ============================================================
  // Spring Boot Actuator index
  // ============================================================
  {
    path: '/actuator',
    name: 'Spring Boot Actuator',
    severity: 'HIGH',
    findingType: 'EXPOSED_ACTUATOR',
    // Actuator index has HAL format
    requiredPatterns: [
      /"_links"\s*:\s*\{/,           // HAL links
      /"href"\s*:\s*"/,              // href attribute
    ],
    expectedContentType: 'json',
    description: 'Spring Boot actuator endpoints exposed.',
  },

  // ============================================================
  // Server status pages - Require actual Apache format
  // ============================================================
  {
    path: '/server-status',
    name: 'Apache Server Status',
    severity: 'HIGH',
    findingType: 'EXPOSED_SERVER_STATUS',
    requiredPatterns: [
      /Apache Server Status/i,
      /Server Version:|Current Time:|Restart Time:/i,
    ],
    expectedContentType: 'html',
    description: 'Apache server status page exposes server info.',
  },

  // ============================================================
  // Debug endpoints - Require actual debug output format
  // ============================================================
  {
    path: '/_profiler/',
    name: 'Symfony Profiler',
    severity: 'HIGH',
    findingType: 'EXPOSED_DEBUG_ENDPOINT',
    // Symfony profiler has very specific elements
    requiredPatterns: [
      /class="sf-toolbar|class="sf-profiler|Symfony\s+Profiler/i,  // SF classes or title
      /Token|Collector|Request\/Response/i,                        // Profiler data sections
    ],
    expectedContentType: 'html',
    description: 'Symfony profiler exposes application internals.',
  },
  {
    path: '/rails/info/routes',
    name: 'Rails Routes',
    severity: 'HIGH',
    findingType: 'EXPOSED_DEBUG_ENDPOINT',
    // Rails routes page has specific table format
    requiredPatterns: [
      /Prefix\s+Verb\s+URI Pattern|Helper\s+HTTP Verb\s+Path/i,
      /Controller#Action|:controller|:action/i,
    ],
    expectedContentType: 'html',
    description: 'Rails routes page exposes all API endpoints.',
  },

  // ============================================================
  // GraphQL introspection - Require actual schema response
  // ============================================================
  {
    path: '/graphql',
    name: 'GraphQL Introspection',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_API_DOCS',
    // Only flag if introspection is enabled (returns schema)
    requiredPatterns: [
      /__schema|__type|queryType/i,
      /"data"\s*:\s*\{/,
    ],
    expectedContentType: 'json',
    description: 'GraphQL introspection exposes API schema.',
  },

  // ============================================================
  // Swagger/OpenAPI - Require actual spec structure
  // ============================================================
  {
    path: '/swagger.json',
    name: 'Swagger Spec',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_API_DOCS',
    requiredPatterns: [
      /"swagger"\s*:\s*"2|"openapi"\s*:\s*"3/,  // Version
      /"paths"\s*:\s*\{/,                        // Paths object
    ],
    expectedContentType: 'json',
    description: 'Swagger API specification exposed.',
  },
  {
    path: '/api-docs',
    name: 'API Docs',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_API_DOCS',
    requiredPatterns: [
      /"swagger"\s*:|"openapi"\s*:/,
      /"paths"\s*:\s*\{/,
    ],
    expectedContentType: 'json',
    description: 'API documentation exposed.',
  },

  // ============================================================
  // Backup files - Require actual file content format
  // ============================================================
  {
    path: '/backup.sql',
    name: 'SQL Backup',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_DATABASE_BACKUP',
    // SQL dumps have specific structure
    requiredPatterns: [
      /CREATE TABLE|INSERT INTO|DROP TABLE/i,
      /ENGINE=|AUTO_INCREMENT|PRIMARY KEY/i,
    ],
    expectedContentType: 'text',
    description: 'SQL database backup publicly accessible.',
  },
  {
    path: '/dump.sql',
    name: 'SQL Dump',
    severity: 'CRITICAL',
    findingType: 'EXPOSED_DATABASE_BACKUP',
    requiredPatterns: [
      /CREATE TABLE|INSERT INTO/i,
      /ENGINE=|AUTO_INCREMENT|PRIMARY KEY|\-\- MySQL|\-\- PostgreSQL/i,
    ],
    expectedContentType: 'text',
    description: 'SQL dump file publicly accessible.',
  },

  // ============================================================
  // TIER 2: LOGIN PANELS - Credential stuffing targets
  // Coalition data: 65%+ of businesses have exposed login panels
  // 3x attack likelihood increase
  // ============================================================
  {
    path: '/owa/',
    name: 'Outlook Web Access',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    // OWA has specific form structure
    requiredPatterns: [
      /name="password"|name="passwd"|type="password"/i,
      /Microsoft|Outlook|Exchange|OWA/i,
    ],
    expectedContentType: 'html',
    description: 'Outlook Web Access login exposed. Target for credential stuffing and password spraying attacks.',
  },
  {
    path: '/owa/auth/logon.aspx',
    name: 'Outlook Web Access Login',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /name="password"|name="passwd"|type="password"/i,
      /Microsoft|Outlook|Exchange/i,
    ],
    expectedContentType: 'html',
    description: 'Outlook Web Access login page exposed.',
  },
  {
    path: '/webmail/',
    name: 'Webmail Login',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /<form/i,
    ],
    expectedContentType: 'html',
    description: 'Webmail login portal exposed. Common credential stuffing target.',
  },
  {
    path: '/roundcube/',
    name: 'Roundcube Webmail',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /roundcube/i,
      /type="password"/i,
    ],
    expectedContentType: 'html',
    description: 'Roundcube webmail login exposed.',
  },
  {
    path: '/zimbra/',
    name: 'Zimbra Webmail',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /zimbra/i,
      /type="password"/i,
    ],
    expectedContentType: 'html',
    description: 'Zimbra webmail login exposed.',
  },

  // ============================================================
  // Hosting Panels - Direct server access
  // ============================================================
  {
    path: '/cpanel',
    name: 'cPanel Login',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /cpanel|cPanel/i,
      /type="password"/i,
    ],
    expectedContentType: 'html',
    description: 'cPanel login exposed. Grants full hosting control if compromised.',
  },
  {
    path: '/plesk/',
    name: 'Plesk Login',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /plesk/i,
      /type="password"/i,
    ],
    expectedContentType: 'html',
    description: 'Plesk control panel login exposed.',
  },
  {
    path: '/whm/',
    name: 'WHM Login',
    severity: 'HIGH',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /whm|WebHost Manager/i,
      /type="password"/i,
    ],
    expectedContentType: 'html',
    description: 'WebHost Manager login exposed. Grants root-level hosting access.',
  },

  // ============================================================
  // VPN/Remote Access Portals
  // ============================================================
  {
    path: '/remote/',
    name: 'Remote Access Portal',
    severity: 'HIGH',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /vpn|remote|access|login/i,
    ],
    expectedContentType: 'html',
    description: 'Remote access portal exposed. VPN login interfaces are common ransomware entry points.',
  },
  {
    path: '/vpn/',
    name: 'VPN Portal',
    severity: 'HIGH',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /vpn|ssl|remote/i,
    ],
    expectedContentType: 'html',
    description: 'VPN login portal exposed.',
  },
  {
    path: '/sslvpn/',
    name: 'SSL VPN Portal',
    severity: 'HIGH',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /vpn|ssl|fortinet|sonicwall|cisco/i,
    ],
    expectedContentType: 'html',
    description: 'SSL VPN login portal exposed.',
  },
  {
    path: '/global-protect/',
    name: 'GlobalProtect Portal',
    severity: 'HIGH',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /globalprotect|palo alto/i,
    ],
    expectedContentType: 'html',
    description: 'Palo Alto GlobalProtect VPN login exposed.',
  },

  // ============================================================
  // CRM / Business App Logins
  // ============================================================
  {
    path: '/crm/',
    name: 'CRM Login',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /<form/i,
    ],
    expectedContentType: 'html',
    description: 'CRM login portal exposed. May contain customer data.',
  },
  {
    path: '/portal/',
    name: 'Customer Portal',
    severity: 'MEDIUM',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /type="password"/i,
      /<form/i,
    ],
    expectedContentType: 'html',
    description: 'Customer portal login exposed.',
  },

  // ============================================================
  // WordPress Admin (separate from plugin vulnerabilities)
  // ============================================================
  {
    path: '/wp-login.php',
    name: 'WordPress Login',
    severity: 'LOW',
    findingType: 'EXPOSED_LOGIN_PANEL',
    requiredPatterns: [
      /wp-login|WordPress/i,
      /type="password"/i,
    ],
    expectedContentType: 'html',
    description: 'WordPress login exposed. Consider restricting access or adding MFA.',
  },
];

interface ProbeResult {
  path: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  findingType: string;
  status: 'exposed' | 'not_found' | 'error';
  statusCode?: number;
  description: string;
  evidence?: string;
}

/**
 * Make an HTTP request with timeout
 */
async function probeUrl(url: string): Promise<{ ok: boolean; status: number; body: string; contentType: string }> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
    });

    clearTimeout(timeoutId);

    const contentType = response.headers.get('content-type') || '';

    // Read body up to limit
    const reader = response.body?.getReader();
    if (!reader) {
      return { ok: response.ok, status: response.status, body: '', contentType };
    }

    let body = '';
    let bytesRead = 0;

    while (bytesRead < CONFIG.MAX_BODY_SIZE) {
      const { done, value } = await reader.read();
      if (done) break;

      const chunk = new TextDecoder().decode(value);
      body += chunk;
      bytesRead += value.length;
    }

    reader.cancel();

    return { ok: response.ok, status: response.status, body, contentType };
  } catch {
    return { ok: false, status: 0, body: '', contentType: '' };
  }
}

/**
 * Check if response is a false positive (captcha, 404, etc.)
 */
function isFalsePositive(body: string): boolean {
  for (const pattern of FALSE_POSITIVE_PATTERNS) {
    if (pattern.test(body)) {
      return true;
    }
  }
  return false;
}

/**
 * Analyze response with STRICT pattern matching
 * ALL requiredPatterns must match (AND logic)
 */
function analyzeResponse(
  probePath: ProbePath,
  result: { ok: boolean; status: number; body: string; contentType: string }
): ProbeResult {
  const baseResult: ProbeResult = {
    path: probePath.path,
    name: probePath.name,
    severity: probePath.severity,
    findingType: probePath.findingType,
    status: 'not_found',
    statusCode: result.status,
    description: probePath.description,
  };

  // Error/timeout
  if (result.status === 0) {
    baseResult.status = 'error';
    return baseResult;
  }

  // Non-success status codes
  if (result.status >= 400) {
    return baseResult;
  }

  // Check for false positives FIRST
  if (isFalsePositive(result.body)) {
    log.debug({ path: probePath.path }, 'Filtered false positive');
    return baseResult;
  }

  // Check body size - tiny responses are likely errors
  if (result.body.length < 50) {
    return baseResult;
  }

  // STRICT: ALL required patterns must match
  const allPatternsMatch = probePath.requiredPatterns.every(pattern => pattern.test(result.body));

  if (!allPatternsMatch) {
    return baseResult;
  }

  // Special check for .env files - require at least 3 KEY=value lines
  if (probePath.findingType === 'EXPOSED_ENV_FILE') {
    const envLinePattern = /^[A-Z][A-Z0-9_]*=.+$/gm;
    const matches = result.body.match(envLinePattern);
    if (!matches || matches.length < 3) {
      return baseResult;
    }
  }

  // All checks passed - this is a real finding
  baseResult.status = 'exposed';

  // Extract evidence from first matching pattern
  const match = result.body.match(probePath.requiredPatterns[0]);
  if (match) {
    baseResult.evidence = match[0].slice(0, 100);
  }

  return baseResult;
}

/**
 * Main module function
 */
export async function runAdminPanelDetector(job: {
  domain: string;
  scanId: string;
}): Promise<number> {
  const { domain, scanId } = job;
  const baseUrl = `https://${domain}`;

  log.info({ domain, scanId, pathCount: PROBE_PATHS.length }, 'Starting admin panel detection');

  let findingsCount = 0;
  const results: ProbeResult[] = [];

  // Process paths in batches
  for (let i = 0; i < PROBE_PATHS.length; i += CONFIG.CONCURRENT_REQUESTS) {
    const batch = PROBE_PATHS.slice(i, i + CONFIG.CONCURRENT_REQUESTS);

    const batchResults = await Promise.all(
      batch.map(async (probePath) => {
        const url = `${baseUrl}${probePath.path}`;
        const httpResult = await probeUrl(url);
        return analyzeResponse(probePath, httpResult);
      })
    );

    results.push(...batchResults);

    // Small delay between batches
    if (i + CONFIG.CONCURRENT_REQUESTS < PROBE_PATHS.length) {
      await new Promise(r => setTimeout(r, CONFIG.DELAY_BETWEEN_BATCHES_MS));
    }
  }

  // Create findings for exposed resources
  const exposedResults = results.filter(r => r.status === 'exposed');

  for (const result of exposedResults) {
    await insertFinding({
      scan_id: scanId,
      type: result.findingType,
      severity: result.severity,
      title: `${result.name} at ${result.path}`,
      description: result.description,
      data: {
        path: result.path,
        statusCode: result.statusCode,
        evidence: result.evidence,
      },
    });
    findingsCount++;

    log.warn({
      path: result.path,
      name: result.name,
      severity: result.severity,
      evidence: result.evidence,
    }, 'Verified exposed resource');
  }

  // Store summary artifact
  const summary = {
    total_paths_checked: PROBE_PATHS.length,
    exposed: exposedResults.length,
    not_found: results.filter(r => r.status === 'not_found').length,
    errors: results.filter(r => r.status === 'error').length,
  };

  await insertArtifact({
    type: 'admin_panel_scan_raw',
    val_text: `Admin panel detection complete for ${domain}`,
    severity: exposedResults.length > 0 ? 'HIGH' : 'INFO',
    meta: {
      scan_id: scanId,
      domain,
      summary,
      exposed_paths: exposedResults.map(r => ({
        path: r.path,
        name: r.name,
        severity: r.severity,
        evidence: r.evidence,
      })),
    },
  });

  log.info({
    domain,
    scanId,
    ...summary,
    findings: findingsCount,
  }, 'Admin panel detection complete');

  return findingsCount;
}
