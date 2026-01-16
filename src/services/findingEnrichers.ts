/**
 * Finding Enrichers - Extract and normalize finding-specific data for templating
 *
 * This module maps raw finding data (which varies by scanner/module) into
 * a consistent context object that can be interpolated into remediation templates.
 */

export interface RemediationContext {
  [key: string]: string | number | undefined;
}

// Default fallbacks so templates never show raw {{variable}} placeholders
const DEFAULT_CONTEXT: RemediationContext = {
  site_url: 'your website',
  domain: 'the domain',
  email: 'the affected account',
  port: 'the exposed port',
  service: 'the service',
  ip: 'the IP address',
  plugin_name: 'the vulnerable plugin',
  current_version: 'the current version',
  fixed_version: 'the latest secure version',
  cve_id: 'the identified CVE',
  breach_source: 'a data breach',
  record_type: 'the DNS record',
  cipher: 'the weak cipher',
  protocol: 'the protocol',
  file_path: 'the exposed file',
  username: 'the username',
  severity: 'the severity level'
};

type EnricherFunction = (finding: any) => RemediationContext;

/**
 * Type-specific enrichers that normalize scanner output into template variables
 */
const FINDING_ENRICHERS: Record<string, EnricherFunction> = {

  // ============================================
  // BREACH / CREDENTIAL EXPOSURE
  // ============================================

  'CRITICAL_BREACH_EXPOSURE': (f) => {
    const email = f.metadata?.email || f.data?.email || f.data?.username;
    const accountType = inferAccountType(email);
    const accountTypeImpact = accountType === 'shared/team mailbox'
      ? 'multiple devices may access it and any of them could be infected'
      : 'the associated device may be infected';
    return {
      email,
      breach_source: f.metadata?.source || f.data?.source || 'infostealer malware logs',
      machine_name: f.metadata?.machine_name || f.data?.machine_name,
      last_seen: f.metadata?.last_seen || f.data?.last_seen,
      account_type: accountType,
      account_type_impact: accountTypeImpact,
      breach_date: f.metadata?.breach_date || f.data?.date
    };
  },

  'PASSWORD_BREACH_EXPOSURE_RECENT': (f) => ({
    email: f.metadata?.email || f.data?.email,
    breach_source: f.metadata?.source || f.data?.source || 'recent data breach',
    breach_name: f.metadata?.breach_name || f.data?.breach_name,
    breach_date: f.metadata?.breach_date || f.data?.date,
    exposed_data: f.metadata?.exposed_fields?.join(', ') || 'password'
  }),

  'PASSWORD_BREACH_EXPOSURE_RECENT_PRIV': (f) => ({
    email: f.metadata?.email || f.data?.email,
    breach_source: f.metadata?.source || f.data?.source,
    role: f.metadata?.role || 'privileged account',
    breach_date: f.metadata?.breach_date || f.data?.date
  }),

  'PASSWORD_BREACH_EXPOSURE_OLD': (f) => ({
    email: f.metadata?.email || f.data?.email,
    breach_source: f.metadata?.source || f.data?.source,
    breach_date: f.metadata?.breach_date || f.data?.date,
    years_ago: calculateYearsAgo(f.metadata?.breach_date || f.data?.date)
  }),

  'EMAIL_BREACH_EXPOSURE': (f) => ({
    email: f.metadata?.email || f.data?.email,
    breach_count: f.metadata?.breach_count || f.data?.count || '1',
    breach_sources: f.metadata?.sources?.join(', ') || f.data?.source
  }),

  // ============================================
  // EMAIL SECURITY
  // ============================================

  'EMAIL_SECURITY_GAP': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    missing_records: getMissingEmailRecords(f),
    spf_status: f.metadata?.spf_status || f.data?.spf?.status || 'missing',
    dkim_status: f.metadata?.dkim_status || f.data?.dkim?.status || 'missing',
    dmarc_status: f.metadata?.dmarc_status || f.data?.dmarc?.status || 'missing'
  }),

  'EMAIL_SECURITY_WEAKNESS': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    spf_mechanism: f.metadata?.spf_mechanism || f.data?.spf?.mechanism,
    dmarc_policy: f.metadata?.dmarc_policy || f.data?.dmarc?.policy || 'none',
    current_spf: f.metadata?.spf_record || f.data?.spf?.record,
    current_dmarc: f.metadata?.dmarc_record || f.data?.dmarc?.record
  }),

  'EMAIL_SECURITY_MISCONFIGURATION': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    error_type: f.metadata?.error_type || f.data?.error,
    record_type: f.metadata?.record_type || 'SPF/DKIM/DMARC',
    error_detail: f.metadata?.error_detail || f.data?.error_message
  }),

  'SPF_TOO_MANY_LOOKUPS': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    lookup_count: f.metadata?.lookup_count || f.data?.lookups || '11+',
    max_lookups: '10',
    includes: f.metadata?.includes?.join(', ') || f.data?.includes?.join(', ')
  }),

  // ============================================
  // TLS / CERTIFICATES
  // ============================================

  'MISSING_TLS_CERTIFICATE': (f) => ({
    domain: f.metadata?.domain || f.data?.host || f.data?.domain,
    host: f.metadata?.host || f.data?.host,
    port: f.metadata?.port || f.data?.port || '443',
    error: f.metadata?.error || f.data?.error
  }),

  'TLS_CONFIGURATION_ISSUE': (f) => ({
    domain: f.metadata?.domain || f.data?.host,
    host: f.metadata?.host || f.data?.host,
    issue: f.metadata?.issue || f.data?.issue,
    protocols: f.metadata?.weak_protocols?.join(', ') || f.data?.protocols?.join(', '),
    ciphers: f.metadata?.weak_ciphers?.join(', ') || f.data?.ciphers?.join(', ')
  }),

  'WEAK_TLS_CIPHER': (f) => ({
    domain: f.metadata?.domain || f.data?.host,
    cipher: f.metadata?.cipher || f.data?.cipher_suite,
    protocol: f.metadata?.protocol || f.data?.protocol,
    grade: f.metadata?.grade || f.data?.ssl_grade
  }),

  'CERTIFICATE_EXPIRY': (f) => ({
    domain: f.metadata?.domain || f.data?.host,
    expiry_date: f.metadata?.expiry_date || f.data?.not_after,
    days_remaining: f.metadata?.days_remaining || f.data?.days_until_expiry,
    issuer: f.metadata?.issuer || f.data?.issuer
  }),

  'TLS_VALIDATION_INCONSISTENCY': (f) => ({
    domain: f.metadata?.domain || f.data?.host,
    hosts_affected: f.metadata?.hosts?.join(', ') || f.data?.hosts?.join(', '),
    issue: f.metadata?.issue || f.data?.validation_error
  }),

  // ============================================
  // DNS CONFIGURATION
  // ============================================

  'DNS_ZONE_TRANSFER_ENABLED': (f) => ({
    domain: f.data?.domain || f.metadata?.domain,
    vulnerable_nameservers: f.data?.vulnerable_nameservers || f.metadata?.vulnerable_nameservers || [],
    total_records_exposed: f.data?.total_records_exposed || f.metadata?.total_records || 0,
    record_types: f.data?.record_type_breakdown || f.metadata?.record_types || {}
  }),

  // ============================================
  // EXPOSED SERVICES / INFRASTRUCTURE
  // ============================================

  'EXPOSED_SERVICE': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port,
    service: f.data?.service || f.metadata?.product || f.data?.product || inferServiceFromPort(f.data?.port),
    protocol: f.metadata?.transport || f.data?.transport || 'TCP',
    banner: f.data?.banner || f.metadata?.banner,
    version: f.data?.version || f.metadata?.version
  }),

  'EXPOSED_DATABASE': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port,
    database_type: f.metadata?.db_type || f.data?.product || inferDatabaseFromPort(f.data?.port),
    version: f.data?.version || f.metadata?.version
  }),

  'EXPOSED_RDP': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '3389',
    os_version: f.metadata?.os || f.data?.os,
    hostname: f.metadata?.hostname || f.data?.hostname,
    hostnames: f.data?.hostnames || []
  }),

  'EXPOSED_VNC': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '5900',
    product: f.data?.product || f.metadata?.product,
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || []
  }),

  'EXPOSED_VPN': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port,
    vpn_product: f.metadata?.product || f.data?.product,
    version: f.metadata?.version || f.data?.version
  }),

  // Specific database exposure types (for higher EAL multipliers)
  'EXPOSED_DATABASE_MYSQL': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '3306',
    database_type: 'MySQL',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || []
  }),

  'EXPOSED_DATABASE_POSTGRES': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '5432',
    database_type: 'PostgreSQL',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || []
  }),

  'EXPOSED_DATABASE_MSSQL': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '1433',
    database_type: 'MS SQL Server',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || []
  }),

  'EXPOSED_DATABASE_MONGODB': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '27017',
    database_type: 'MongoDB',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || [],
    auth_note: 'MongoDB often runs without authentication by default'
  }),

  'EXPOSED_DATABASE_REDIS': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '6379',
    database_type: 'Redis',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || [],
    auth_note: 'Redis often runs without authentication by default'
  }),

  'EXPOSED_DATABASE_ELASTICSEARCH': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '9200',
    database_type: 'Elasticsearch',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || [],
    auth_note: 'Elasticsearch often runs without authentication by default'
  }),

  'EXPOSED_DATABASE_COUCHDB': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '5984',
    database_type: 'CouchDB',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || []
  }),

  'EXPOSED_DATABASE_MEMCACHED': (f) => ({
    ip: f.data?.ip || f.metadata?.ip,
    port: f.data?.port || f.metadata?.port || '11211',
    database_type: 'Memcached',
    version: f.data?.version || f.metadata?.version,
    hostnames: f.data?.hostnames || [],
    auth_note: 'Memcached has no authentication - all cached data is accessible'
  }),

  'DATABASE_EXPOSURE': (f) => ({
    service: f.metadata?.service || f.data?.service || 'Firebase/Supabase',
    database_url: f.metadata?.url || f.data?.url,
    rules_issue: f.metadata?.rules_issue || f.data?.issue
  }),

  // ============================================
  // VULNERABILITIES / CVEs
  // ============================================

  'VERIFIED_CVE': (f) => ({
    cve_id: f.metadata?.cve || f.data?.cve || f.metadata?.cve_id,
    cvss_score: f.metadata?.cvss || f.data?.cvss_score,
    component: f.metadata?.component || f.data?.affected_component,
    version: f.metadata?.version || f.data?.version,
    fix_version: f.metadata?.fixed_in || f.data?.patched_version
  }),

  'UNPATCHED_VPN_CVE': (f) => ({
    cve_id: f.metadata?.cve || f.data?.cve,
    vpn_product: f.metadata?.product || f.data?.product,
    version: f.metadata?.version || f.data?.version,
    fix_version: f.metadata?.fixed_in || f.data?.patched_version
  }),

  // ============================================
  // WORDPRESS
  // ============================================

  'WP_PLUGIN_VULNERABILITY': (f) => {
    const cveId = f.metadata?.cve || f.data?.cve;
    return {
      plugin_name: f.metadata?.plugin_name || f.metadata?.plugin_slug || f.data?.plugin || f.data?.name,
      current_version: f.metadata?.version || f.data?.installed_version || f.data?.version,
      fixed_version: f.metadata?.fixed_in || f.metadata?.patched_version || f.data?.fixed_version || 'the latest version',
      cve_id: cveId,
      cve_info: cveId ? ` (${cveId})` : '',
      vuln_type: f.metadata?.vuln_type || f.data?.vulnerability_type || 'unauthorized access or data exposure',
      site_url: f.metadata?.site_url || f.data?.url
    };
  },

  'WP_CORE_VULNERABILITY': (f) => ({
    current_version: f.metadata?.version || f.data?.wordpress_version,
    fixed_version: f.metadata?.fixed_in || f.data?.patched_version,
    cve_id: f.metadata?.cve || f.data?.cve,
    site_url: f.metadata?.site_url || f.data?.url
  }),

  'WP_THEME_VULNERABILITY': (f) => ({
    theme_name: f.metadata?.theme_name || f.metadata?.theme_slug || f.data?.theme,
    current_version: f.metadata?.version || f.data?.installed_version,
    fixed_version: f.metadata?.fixed_in || f.data?.patched_version,
    cve_id: f.metadata?.cve || f.data?.cve,
    site_url: f.metadata?.site_url || f.data?.url
  }),

  // ============================================
  // SECRETS / CONFIG EXPOSURE
  // ============================================

  'CLIENT_SIDE_SECRET_EXPOSURE': (f) => ({
    secret_type: f.metadata?.secret_type || f.data?.type || 'API key',
    service: f.metadata?.service || f.data?.service,
    file_path: f.metadata?.file || f.data?.url,
    key_prefix: f.metadata?.key_prefix || maskSecret(f.data?.key)
  }),

  'SENSITIVE_FILE_EXPOSURE': (f) => ({
    file_path: f.metadata?.path || f.data?.url || f.data?.file,
    file_type: f.metadata?.file_type || inferFileType(f.data?.url),
    content_preview: f.metadata?.preview
  }),

  'EXPOSED_SECRETS': (f) => ({
    secret_type: f.metadata?.type || f.data?.type,
    location: f.metadata?.location || f.data?.file,
    service: f.metadata?.service || f.data?.provider
  }),

  // ============================================
  // ACCESSIBILITY / ADA
  // ============================================

  'ADA_RISK_BAND': (f) => {
    const blocking = f.data?.blocking || 0;
    const high = f.data?.high || 0;
    const medium = f.data?.medium || 0;
    const low = f.data?.low || 0;
    const total = blocking + high + medium + low;

    // Build a simple breakdown: "X blocking, Y high, Z medium, W low"
    const parts: string[] = [];
    if (blocking > 0) parts.push(`${blocking} blocking`);
    if (high > 0) parts.push(`${high} high`);
    if (medium > 0) parts.push(`${medium} medium`);
    if (low > 0) parts.push(`${low} low`);
    const issuesBreakdown = parts.join(', ') + '.';

    return {
      total_violations: total,
      issues_breakdown: issuesBreakdown
    };
  },

  'ADA_LEGAL_CONTINGENT_LIABILITY': (f) => ({
    estimated_liability: f.metadata?.liability_estimate || f.data?.estimated_cost,
    violation_count: f.metadata?.violation_count || f.data?.total_issues,
    blocking_issues: f.metadata?.blocking_issues || f.data?.critical
  }),

  'ACCESSIBILITY_VIOLATION': (f) => ({
    wcag_criterion: f.metadata?.wcag || f.data?.wcag_id,
    element: f.metadata?.element || f.data?.selector,
    page_url: f.metadata?.url || f.data?.page,
    issue_description: f.metadata?.description || f.data?.message
  }),

  'ACCESSIBILITY_OBSERVATION': (f) => {
    const issueType = f.data?.issue_type || f.metadata?.type || 'accessibility issue';

    // Try to extract count from description (e.g., "204 images missing alt text")
    // The description often has the real count while instance_count is 1
    let instanceCount = f.data?.instance_count || f.metadata?.count || 1;
    const description = f.description || '';
    const countMatch = description.match(/^(\d+)\s+/);
    if (countMatch && parseInt(countMatch[1], 10) > instanceCount) {
      instanceCount = parseInt(countMatch[1], 10);
    }

    // Map issue types to human-readable display names and explanations
    // Fix instructions use {{count}} placeholder to be interpolated at the end
    const issueTypeMap: Record<string, {
      display: string;
      explanation: string;
      fixInstructionTemplate: string;
      fixDetails: string;
      validationTemplate: string;
    }> = {
      'MISSING_ALT_TEXT': {
        display: 'images missing alt text',
        explanation: 'Screen reader users cannot understand what these images show.',
        fixInstructionTemplate: 'Add alt="" attributes to all {{count}} images.',
        fixDetails: 'For meaningful images, describe the content (e.g., alt="Team photo at company retreat"). For decorative images, use alt="" (empty).',
        validationTemplate: 'All {{count}} images have descriptive alt attributes.'
      },
      'MISSING_LANGUAGE': {
        display: 'missing language declaration',
        explanation: 'Screen readers cannot determine the correct language for pronunciation.',
        fixInstructionTemplate: 'Add the lang attribute to your <html> element.',
        fixDetails: 'Change <html> to <html lang="en"> (or appropriate language code like "es", "fr", "de").',
        validationTemplate: '<html> tag includes lang="en" (or appropriate language).'
      },
      'MISSING_FORM_LABELS': {
        display: 'form inputs missing labels',
        explanation: 'Screen reader users cannot identify what information to enter.',
        fixInstructionTemplate: 'Add <label> elements to all {{count}} form inputs.',
        fixDetails: 'Use <label for="fieldId">Field Name</label> paired with <input id="fieldId">.',
        validationTemplate: 'All {{count}} form inputs have associated labels.'
      },
      'COLOR_CONTRAST': {
        display: 'insufficient color contrast',
        explanation: 'Users with low vision cannot read this text.',
        fixInstructionTemplate: 'Fix color contrast on {{count}} elements.',
        fixDetails: 'Text must have 4.5:1 contrast ratio (3:1 for large text). Use WebAIM Contrast Checker to verify.',
        validationTemplate: 'All text meets WCAG 2.1 AA contrast requirements.'
      },
      'KEYBOARD_TRAP': {
        display: 'keyboard navigation traps',
        explanation: 'Keyboard-only users get stuck and cannot navigate away.',
        fixInstructionTemplate: 'Fix keyboard navigation so users can Tab through all elements.',
        fixDetails: 'Ensure focus moves logically with Tab/Shift+Tab. Modals should trap focus but allow Escape to close.',
        validationTemplate: 'Users can navigate the entire site with keyboard only.'
      },
      'MISSING_SKIP_LINK': {
        display: 'missing skip navigation link',
        explanation: 'Keyboard users must tab through all navigation on every page.',
        fixInstructionTemplate: 'Add a "Skip to main content" link at the top of each page.',
        fixDetails: 'Add <a href="#main-content" class="skip-link">Skip to main content</a> as the first focusable element.',
        validationTemplate: 'Skip link is first focusable element and jumps to main content.'
      }
    };

    const mapped = issueTypeMap[issueType] || {
      display: issueType.toLowerCase().replace(/_/g, ' '),
      explanation: 'This creates barriers for users with disabilities.',
      fixInstructionTemplate: f.title || 'Address this accessibility issue.',
      fixDetails: f.description || 'Review and fix the identified accessibility barrier.',
      validationTemplate: 'Issue is resolved and verified with accessibility tools.'
    };

    // Interpolate {{count}} in templates
    const fixInstruction = mapped.fixInstructionTemplate.replace(/\{\{count\}\}/g, String(instanceCount));
    const validation = mapped.validationTemplate.replace(/\{\{count\}\}/g, String(instanceCount));

    return {
      issue_type: issueType,
      issue_type_display: mapped.display,
      instance_count: instanceCount,
      issue_explanation: mapped.explanation,
      fix_instruction: fixInstruction,
      fix_details: mapped.fixDetails,
      validation_step: validation,
      page_url: f.metadata?.url || f.data?.page,
      element: f.metadata?.element || f.data?.selector,
      recommendation: f.title || f.metadata?.recommendation || f.data?.suggestion
    };
  },

  'ACCESSIBILITY_MISSING_ALT_TEXT': (f) => ({
    instance_count: f.data?.instance_count || f.metadata?.count || '(multiple)',
    page_url: f.metadata?.url || f.data?.page,
    sample_images: f.metadata?.samples?.join(', ')
  }),

  'ACCESSIBILITY_MISSING_LANGUAGE': (f) => ({
    instance_count: 1,
    page_url: f.metadata?.url || f.data?.page
  }),

  'ACCESSIBILITY_MISSING_FORM_LABELS': (f) => ({
    instance_count: f.data?.instance_count || f.metadata?.count || '(multiple)',
    page_url: f.metadata?.url || f.data?.page,
    input_types: f.metadata?.input_types?.join(', ')
  }),

  'ACCESSIBILITY_COLOR_CONTRAST': (f) => ({
    instance_count: f.data?.instance_count || f.metadata?.count || '(multiple)',
    page_url: f.metadata?.url || f.data?.page
  }),

  'ACCESSIBILITY_KEYBOARD_TRAP': (f) => ({
    page_url: f.metadata?.url || f.data?.page,
    element: f.metadata?.element || f.data?.selector
  }),

  // ============================================
  // COMPLIANCE
  // ============================================

  'GDPR_VIOLATION': (f) => ({
    violation_type: f.metadata?.type || f.data?.violation_type,
    data_category: f.metadata?.data_category || f.data?.personal_data_type,
    article: f.metadata?.gdpr_article || f.data?.article
  }),

  'PCI_COMPLIANCE_FAILURE': (f) => ({
    requirement: f.metadata?.pci_requirement || f.data?.requirement,
    control: f.metadata?.control || f.data?.control_id,
    gap: f.metadata?.gap || f.data?.finding
  }),

  // ============================================
  // CLOUD / COST
  // ============================================

  'DENIAL_OF_WALLET': (f) => ({
    endpoint: f.metadata?.endpoint || f.data?.url,
    service: f.metadata?.service || f.data?.cloud_service,
    cost_multiplier: f.metadata?.cost_factor || f.data?.amplification_factor
  }),

  'CLOUD_COST_AMPLIFICATION': (f) => ({
    service: f.metadata?.service || f.data?.service,
    resource: f.metadata?.resource || f.data?.resource_type,
    risk_factor: f.metadata?.risk_factor || f.data?.amplification
  }),

  // ============================================
  // BRAND / TYPOSQUATTING
  // ============================================

  'MALICIOUS_TYPOSQUAT': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    similarity: f.metadata?.similarity || f.data?.similarity_score,
    threat_type: f.metadata?.threat_type || f.data?.classification,
    registrar: f.metadata?.registrar || f.data?.registrar
  }),

  'SUSPICIOUS_TYPOSQUAT': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    similarity: f.metadata?.similarity || f.data?.similarity_score,
    registration_date: f.metadata?.created || f.data?.registration_date
  }),

  'PARKED_TYPOSQUAT': (f) => ({
    domain: f.metadata?.domain || f.data?.domain,
    similarity: f.metadata?.similarity || f.data?.similarity_score
  }),

  // ============================================
  // IP / REPUTATION
  // ============================================

  'IP_REPUTATION_ISSUE': (f) => ({
    ip: f.metadata?.ip || f.data?.ip,
    blacklists: f.metadata?.blacklists?.join(', ') || f.data?.listed_on?.join(', '),
    abuse_score: f.metadata?.abuse_score || f.data?.confidence_score,
    categories: f.metadata?.categories?.join(', ') || f.data?.categories?.join(', ')
  })
};

// ============================================
// HELPER FUNCTIONS
// ============================================

function inferAccountType(email?: string): string {
  if (!email) return 'unknown endpoint';
  const localPart = email.split('@')[0]?.toLowerCase();
  const sharedPrefixes = ['support', 'info', 'hello', 'hi', 'contact', 'sales', 'help', 'admin', 'team', 'billing'];
  if (sharedPrefixes.some(p => localPart?.startsWith(p))) {
    return 'shared/team mailbox';
  }
  return 'individual account';
}

function calculateYearsAgo(dateStr?: string): string {
  if (!dateStr) return 'several';
  try {
    const date = new Date(dateStr);
    const years = Math.floor((Date.now() - date.getTime()) / (365.25 * 24 * 60 * 60 * 1000));
    return years > 0 ? String(years) : '< 1';
  } catch {
    return 'several';
  }
}

function getMissingEmailRecords(f: any): string {
  const missing: string[] = [];
  const data = f.data || f.metadata || {};
  if (!data.spf || data.spf?.status === 'missing') missing.push('SPF');
  if (!data.dkim || data.dkim?.status === 'missing') missing.push('DKIM');
  if (!data.dmarc || data.dmarc?.status === 'missing') missing.push('DMARC');
  return missing.length > 0 ? missing.join(', ') : 'email authentication records';
}

function inferServiceFromPort(port?: number | string): string {
  const portMap: Record<number, string> = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    2082: 'cPanel',
    2083: 'cPanel SSL',
    2086: 'WHM',
    2087: 'WHM SSL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP Proxy',
    8443: 'HTTPS Alt',
    8880: 'HTTP Alt',
    27017: 'MongoDB'
  };
  const p = typeof port === 'string' ? parseInt(port, 10) : port;
  return p ? (portMap[p] || `service on port ${p}`) : 'unknown service';
}

function inferDatabaseFromPort(port?: number | string): string {
  const dbMap: Record<number, string> = {
    1433: 'Microsoft SQL Server',
    1521: 'Oracle Database',
    3306: 'MySQL/MariaDB',
    5432: 'PostgreSQL',
    6379: 'Redis',
    9200: 'Elasticsearch',
    27017: 'MongoDB',
    28015: 'RethinkDB'
  };
  const p = typeof port === 'string' ? parseInt(port, 10) : port;
  return p ? (dbMap[p] || 'database') : 'database';
}

function inferFileType(path?: string): string {
  if (!path) return 'sensitive file';
  const lower = path.toLowerCase();
  if (lower.includes('.env')) return '.env configuration file';
  if (lower.includes('.git')) return 'Git repository data';
  if (lower.includes('config')) return 'configuration file';
  if (lower.includes('backup') || lower.includes('.sql') || lower.includes('.bak')) return 'backup file';
  if (lower.includes('.log')) return 'log file';
  if (lower.includes('.key') || lower.includes('.pem')) return 'private key file';
  return 'sensitive file';
}

function maskSecret(key?: string): string {
  if (!key || key.length < 8) return '***';
  return key.substring(0, 4) + '...' + key.substring(key.length - 4);
}

// ============================================
// MAIN EXPORT
// ============================================

/**
 * Get enriched context variables for a finding, ready for template interpolation
 */
export function getRemediationContext(findingType: string, finding: any): RemediationContext {
  const enricher = FINDING_ENRICHERS[findingType];
  const specificContext = enricher ? enricher(finding) : {};

  // Also pull common fields that might exist on any finding
  const commonContext: RemediationContext = {
    domain: finding.metadata?.domain || finding.data?.domain || finding.domain,
    severity: finding.severity,
    title: finding.title,
    description: finding.description
  };

  // Merge: defaults < common < specific (specific wins)
  return { ...DEFAULT_CONTEXT, ...commonContext, ...specificContext };
}

/**
 * Interpolate template variables in a string
 * {{variable}} -> value from context
 */
export function interpolateTemplate(text: string, context: RemediationContext): string {
  return text.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    const value = context[key];
    if (value === undefined || value === null || value === '') {
      // Return a readable fallback instead of raw placeholder
      return DEFAULT_CONTEXT[key]?.toString() || `[${key}]`;
    }
    return String(value);
  });
}

/**
 * Check if a finding type has a registered enricher
 */
export function hasEnricher(findingType: string): boolean {
  return findingType in FINDING_ENRICHERS;
}

/**
 * Get list of all supported finding types
 */
export function getSupportedFindingTypes(): string[] {
  return Object.keys(FINDING_ENRICHERS);
}
