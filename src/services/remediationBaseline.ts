import { RemediationGuidance, RemediationPriority, RemediationStep, REMEDIATION_GUIDANCE_VERSION } from '../core/remediation.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('remediationBaseline');

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

interface BaselineContext {
  moduleName?: string;
  priority: RemediationPriority;
  finding: any;
}

type BaselineGenerator = (context: BaselineContext) => RemediationGuidance;

interface RemediationLibraryEntry {
  name: string;
  severity: string;
  risk_summary: string;
  remediation_steps: string[];
  validation_checklist: string[];
  action_line?: string;  // Optional short action line for title
}

type RemediationLibrary = Record<string, RemediationLibraryEntry>;

// Load remediation library from JSON file
let REMEDIATION_LIBRARY: RemediationLibrary = {};
try {
  // Try relative path first (from apps/workers/dist/services/ to project root)
  let libraryPath = join(__dirname, '..', '..', '..', '..', 'remediation_library.json');
  log.debug({ libraryPath }, 'Attempting to load remediation library');

  let libraryContent: string;
  try {
    libraryContent = readFileSync(libraryPath, 'utf-8');
  } catch {
    // Fallback to absolute path if relative fails
    libraryPath = '/Users/ryanheger/scanner-local/remediation_library.json';
    log.debug({ libraryPath }, 'Fallback to absolute path');
    libraryContent = readFileSync(libraryPath, 'utf-8');
  }

  REMEDIATION_LIBRARY = JSON.parse(libraryContent);
  log.info({ templateCount: Object.keys(REMEDIATION_LIBRARY).length }, 'Loaded remediation templates from library');
} catch (error) {
  log.error({ err: error }, 'Failed to load remediation_library.json');
}

const BASELINE_GUIDANCE: Record<string, BaselineGenerator> = {
  tlsScan: ({ priority }) => ({
    priority,
    timeline: priority === 'Immediate' ? 'Begin remediation within 24 hours' : 'Schedule TLS hardening this week',
    description: 'Harden transport security by disabling legacy protocols/ciphers and installing a trusted certificate.',
    businessImpact: 'Insecure TLS allows credential theft, session hijacking, and non-compliance exposure.',
    ownerHint: 'Security engineering / infrastructure',
    effort: priority === 'Immediate' ? 'High' : 'Medium',
    verification: [
      'Re-run SimplCyber TLS scan and confirm no HIGH/MEDIUM findings',
      'Validate with SSL Labs or testssl.sh from multiple regions'
    ],
    steps: normaliseSteps([
      'Disable SSLv2, SSLv3, and TLS 1.0/1.1 across load balancers and origin servers.',
      'Limit cipher suites to modern AEAD options (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or stronger).',
      'Install or renew a publicly trusted certificate with full chain; enable OCSP stapling.',
      'Configure HTTP→HTTPS redirects and enable HSTS (minimum 6 months, includeSubDomains if ready).'
    ]),
    additionalHardening: [
      'Enable TLS 1.3 with perfect forward secrecy.',
      'Automate certificate renewal (ACME/managed certificates).'
    ],
    references: [
      { label: 'Mozilla TLS Configuration Guidelines', url: 'https://infosec.mozilla.org/guidelines/web_security#tls-configuration' },
      { label: 'OWASP Transport Layer Protection Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html' }
    ],
    source: 'module',
    generatedAt: new Date().toISOString(),
    metadata: { baseline: true },
    version: REMEDIATION_GUIDANCE_VERSION
  }),

  spf_dmarc: ({ priority, finding }) => ({
    priority,
    timeline: priority === 'Immediate' ? 'Update DNS within 48 hours' : 'Plan DNS updates within 1 week',
    description: 'Strengthen email authentication to prevent spoofing and phishing.',
    businessImpact: 'Missing SPF/DMARC leaves staff and customers vulnerable to impersonation attacks.',
    ownerHint: 'Messaging / DNS platform owner',
    effort: 'Medium',
    verification: [
      'Publish updated SPF + DKIM keys and wait for propagation.',
      'Confirm DMARC aggregate reports show alignment ≥ 95% and no unauthenticated traffic.'
    ],
    steps: normaliseSteps([
      'Log in to your DNS/domain provider (e.g., GoDaddy, Namecheap, Cloudflare).',
      'Review current DNS TXT records; remove "+all" or overly permissive SPF mechanisms.',
      'List authorized senders explicitly (SPF include mechanisms per ESP).',
      'Deploy DKIM signing for all outbound services; rotate keys if unknown.',
      'Publish DMARC with rua/ruf addresses and a policy of quarantine→reject after monitoring.',
      'Monitor DMARC reports daily until unauthorized sources are eliminated.'
    ]),
    additionalHardening: [
      'Implement BIMI or VMC after DMARC enforcement to boost mail legitimacy.',
      'Automate DMARC report analysis (Postmark, dmarcian, etc.).'
    ],
    references: [
      { label: 'Google DMARC Deployment Best Practices', url: 'https://support.google.com/a/answer/2466580' },
      { label: 'CISA: Phishing-Resistant Authentication', url: 'https://www.cisa.gov/resources-tools/resources/spoofing-and-phishing' }
    ],
    source: 'module',
    generatedAt: new Date().toISOString(),
    metadata: {
      baseline: true,
      finding_summary: finding?.title
    },
    version: REMEDIATION_GUIDANCE_VERSION
  }),

  configExposureScanner: ({ priority }) => ({
    priority,
    timeline: priority === 'Immediate' ? 'Lock down exposed configuration files within 24 hours' : 'Remediate this sprint',
    description: 'Remove public access to configuration files that leak secrets or environment details.',
    businessImpact: 'Exposed configs disclose credentials, API keys, and internal architecture to attackers.',
    ownerHint: 'Web platform / DevOps',
    effort: 'Medium',
    verification: [
      'Attempt to fetch known config paths (/.env, /.git/config) and confirm HTTP 403/404.',
      'Re-run SimplCyber config exposure module to ensure zero leaks.'
    ],
    steps: normaliseSteps([
      'Block sensitive file patterns at the web server or CDN (e.g., /.env, /.git, /config/*.yml).',
      'Ensure application servers never ship build artifacts containing secrets.',
      'Rotate any credentials or tokens that were exposed in the discovered files.',
      'Add automated tests or CI checks to block deployments with sensitive files present.'
    ]),
    additionalHardening: [
      'Use environment variables or secret managers instead of committed config files.',
      'Add detection rules in WAF/SIEM for requests matching sensitive patterns.'
    ],
    references: [
      { label: 'OWASP Configuration Guide', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Application_Configuration_Cheat_Sheet.html' }
    ],
    source: 'module',
    generatedAt: new Date().toISOString(),
    metadata: { baseline: true },
    version: REMEDIATION_GUIDANCE_VERSION
  }),

  denialWalletScan: ({ priority }) => ({
    priority,
    timeline: priority === 'Immediate' ? 'Implement rate limits within 48 hours' : 'Deploy mitigations this sprint',
    description: 'Guard consumption-based APIs against abusive traffic that can inflate cloud spend.',
    businessImpact: 'Attackers can cause runaway costs or resource exhaustion leading to outages.',
    ownerHint: 'API platform / product engineering',
    effort: 'High',
    verification: [
      'Simulate burst traffic and confirm limits throttle requests appropriately.',
      'Review billing dashboards for anomalies post-mitigation.'
    ],
    steps: normaliseSteps([
      'Apply authenticated rate limiting and quotas at API gateway or edge (per user/IP/key).',
      'Add circuit breakers and cost guardrails (budget alerts, per-request spend caps).',
      'Require stronger authentication/authorization for high-cost actions.',
      'Instrument detailed usage telemetry and alerts for rapid anomaly detection.'
    ]),
    additionalHardening: [
      'Integrate anomaly detection to flag sudden spend spikes.',
      'Implement quiet hours or request smoothing for non-critical operations.'
    ],
    references: [
      { label: 'AWS Architecture Blog: Cost-Aware Design', url: 'https://aws.amazon.com/blogs/architecture/' }
    ],
    source: 'module',
    generatedAt: new Date().toISOString(),
    metadata: { baseline: true },
    version: REMEDIATION_GUIDANCE_VERSION
  })
};

function normaliseSteps(items: string[]): RemediationStep[] {
  return items.map(summary => ({ summary }));
}

/**
 * Convert remediation library entry to RemediationGuidance format
 */
function libraryEntryToGuidance(
  entry: RemediationLibraryEntry,
  priority: RemediationPriority,
  finding: any
): RemediationGuidance {
  const timelineMap: Record<RemediationPriority, string> = {
    Immediate: 'Begin remediation within 24-48 hours',
    High: 'Address within 7 days',
    Medium: 'Schedule within 30 days',
    Low: 'Plan for next maintenance cycle'
  };

  const effortMap: Record<string, RemediationGuidance['effort']> = {
    CRITICAL: 'High',
    HIGH: 'High',
    MEDIUM: 'Medium',
    LOW: 'Low',
    INFO: 'Low'
  };

  return {
    priority,
    timeline: timelineMap[priority],
    description: entry.name,
    businessImpact: entry.risk_summary,
    ownerHint: 'Security / IT Operations',
    effort: effortMap[entry.severity] || 'Medium',
    verification: entry.validation_checklist,
    steps: entry.remediation_steps.map(step => ({ summary: step })),
    source: 'module',
    generatedAt: new Date().toISOString(),
    metadata: {
      baseline: true,
      finding_type: finding?.type,
      library_severity: entry.severity,
      from_library: true,
      action_line: entry.action_line  // Pass through library's explicit action line
    },
    version: REMEDIATION_GUIDANCE_VERSION
  };
}

export function getBaselineRemediation(
  moduleName: string | undefined,
  priority: RemediationPriority,
  finding: any
): RemediationGuidance | undefined {
  // Priority 0: Detect subtypes based on finding metadata
  let effectiveType = finding?.type as string | undefined;

  // SPF-specific error detection
  if (effectiveType === 'EMAIL_SECURITY_MISCONFIGURATION') {
    // Check data fields first
    const spfError = finding?.data?.spf_error || finding?.metadata?.spf_error;
    // Also check description field (e.g., "SPF record validation failed with error: TOO_MANY_LOOKUPS")
    const description = finding?.description || '';
    const hasTooManyLookups = spfError === 'TOO_MANY_LOOKUPS' || description.includes('TOO_MANY_LOOKUPS');

    if (hasTooManyLookups && REMEDIATION_LIBRARY['SPF_TOO_MANY_LOOKUPS']) {
      log.debug('Detected SPF subtype: TOO_MANY_LOOKUPS');
      effectiveType = 'SPF_TOO_MANY_LOOKUPS';
    }
  }

  // Priority 1: Try to match by finding type (or detected subtype) from remediation library
  log.debug({ findingType: effectiveType, templateCount: Object.keys(REMEDIATION_LIBRARY).length }, 'Looking for finding type');

  if (effectiveType && REMEDIATION_LIBRARY[effectiveType]) {
    log.debug({ findingType: effectiveType }, 'Using library entry for finding type');
    return libraryEntryToGuidance(REMEDIATION_LIBRARY[effectiveType], priority, finding);
  }

  if (effectiveType && Object.keys(REMEDIATION_LIBRARY).length > 0) {
    log.debug({ findingType: effectiveType, availableKeys: Object.keys(REMEDIATION_LIBRARY).slice(0, 5) }, 'No library match');
  }

  // Priority 2: Fall back to module-specific guidance
  if (!moduleName) return undefined;
  const generator = BASELINE_GUIDANCE[moduleName];
  if (!generator) {
    log.debug({ moduleName }, 'No module generator found');
    return undefined;
  }
  log.debug({ moduleName }, 'Using module generator');
  return generator({ moduleName, priority, finding });
}
