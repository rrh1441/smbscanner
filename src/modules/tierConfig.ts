/*
 * =============================================================================
 * MODULE: tierConfig.ts
 * =============================================================================
 * Configuration for tiered scanning system:
 *
 * PASSIVE TIERS (default, safe to run):
 * - Tier 1: Foundation (independent modules, just needs domain)
 * - Tier 2: Enrichment (depends on Tier 1 artifacts)
 * - Tier 3: Correlation (aggregates all findings)
 *
 * AGGRESSIVE TIER (opt-in only):
 * - Active vulnerability scanning (nuclei, ZAP)
 * - Port scanning (dbPortScan)
 * - Git repo scanning (trufflehog, githubSecretSearch)
 * - Typosquatting detection (dnsTwist)
 * =============================================================================
 */

export interface ScanTier {
    name: 'tier1' | 'tier2' | 'tier3' | 'aggressive';
    description: string;
    targetTime: string;
    requiresOptIn: boolean;
}

export const SCAN_TIERS: Record<string, ScanTier> = {
    tier1: {
        name: 'tier1',
        description: 'Foundation - passive discovery modules',
        targetTime: '2-5 minutes',
        requiresOptIn: false
    },
    tier2: {
        name: 'tier2',
        description: 'Enrichment - CVE lookups from Tier 1 data',
        targetTime: '30 seconds',
        requiresOptIn: false
    },
    tier3: {
        name: 'tier3',
        description: 'Correlation - aggregate and correlate findings',
        targetTime: '10 seconds',
        requiresOptIn: false
    },
    aggressive: {
        name: 'aggressive',
        description: 'Active scanning - vulnerability probing, port scanning, git analysis',
        targetTime: '10-30 minutes',
        requiresOptIn: true
    }
};

// Endpoint Discovery Configuration
export const ENDPOINT_DISCOVERY_CONFIG = {
    tier1: {
        maxCrawlDepth: 2,
        maxConcurrentRequests: 12,
        requestTimeout: 3000,
        maxJsFileSize: 2 * 1024 * 1024, // 2MB max
        maxFilesPerCrawl: 25,
        maxTotalCrawlSize: 20 * 1024 * 1024, // 20MB total
        maxPages: 50,
        highValuePathsOnly: true
    }
};

// Tech Stack Scan Configuration
export const TECH_STACK_CONFIG = {
    tier1: {
        maxConcurrentRequests: 10,
        requestTimeout: 5000,
        checkJsFrameworks: true,
        checkHeaders: true,
        checkMetaTags: true
    }
};

// Aggressive Module Configurations
export const NUCLEI_CONFIG = {
    aggressive: {
        maxConcurrentTemplates: 25,
        requestTimeout: 10000,
        rateLimit: 150, // requests per second
        templateTags: ['cve', 'exposure', 'misconfiguration'],
        severityFilter: ['medium', 'high', 'critical']
    }
};

export const ZAP_CONFIG = {
    aggressive: {
        spiderMaxDepth: 5,
        spiderMaxChildren: 10,
        ajaxSpider: true,
        activeScanPolicy: 'Default Policy',
        alertThreshold: 'Medium'
    }
};

export const DB_PORT_SCAN_CONFIG = {
    aggressive: {
        ports: [3306, 5432, 27017, 6379, 9200, 5984, 8529, 7474, 1433, 1521],
        timeout: 5000,
        maxConcurrent: 10
    }
};

export const TRUFFLEHOG_CONFIG = {
    aggressive: {
        maxRepoSize: 100 * 1024 * 1024, // 100MB
        maxCommits: 1000,
        onlyVerified: true
    }
};

// =============================================================================
// MODULE LISTS BY TIER
// =============================================================================

// Tier 1 - Passive foundation modules (no active probing)
export const TIER_1_MODULES = [
    'shodan',
    'whois_wrapper',
    'spf_dmarc',
    'tech_stack_scan',
    'endpoint_discovery',
    'infostealer_probe',
    'wp_plugin_quickscan',
    'config_exposure',
    'admin_panel_detector',
    'dns_zone_transfer',
    'subdomain_takeover',
    'lightweight_backend_scan',
    'backend_exposure_scanner',
    'client_secret_scanner',
    'denial_wallet_scan',
    'accessibility_lightweight',
    'tls_scan'
];

// Tier 2 - Passive enrichment (depends on Tier 1)
export const TIER_2_MODULES = [
    'lightweight_cve_check'  // Depends on tech_stack_scan
];

// Tier 3 - Correlation
export const TIER_3_MODULES = [
    'asset_correlator'  // Correlates all findings
];

// Aggressive modules - REQUIRE OPT-IN
export const AGGRESSIVE_MODULES = [
    'nuclei',              // Active vulnerability scanning with templates
    'zap_scan',            // OWASP ZAP active web scanning
    'db_port_scan',        // Port scanning for databases
    'trufflehog',          // Git repository secret scanning
    'github_secret_search', // GitHub code search for secrets
    'dns_twist',           // Typosquatting domain detection
    'web_archive_scanner', // Wayback Machine historical analysis
    'openvas_scan'         // OpenVAS vulnerability assessment
];

// All passive modules (default scan)
export const PASSIVE_MODULES = [...TIER_1_MODULES, ...TIER_2_MODULES, ...TIER_3_MODULES];

// All modules including aggressive (full scan with opt-in)
export const ALL_MODULES = [...PASSIVE_MODULES, ...AGGRESSIVE_MODULES];

/**
 * Get configuration for a specific module and tier
 */
export function getModuleConfig<T>(module: string, tier: string): T {
    const configs: Record<string, any> = {
        endpointDiscovery: ENDPOINT_DISCOVERY_CONFIG,
        techStackScan: TECH_STACK_CONFIG,
        nuclei: NUCLEI_CONFIG,
        zapScan: ZAP_CONFIG,
        dbPortScan: DB_PORT_SCAN_CONFIG,
        trufflehog: TRUFFLEHOG_CONFIG
    };

    return configs[module]?.[tier] as T;
}

/**
 * Check if a module requires opt-in (is aggressive)
 */
export function isAggressiveModule(module: string): boolean {
    return AGGRESSIVE_MODULES.includes(module);
}

/**
 * Get modules for a scan based on aggressive flag
 */
export function getModulesForScan(aggressive: boolean = false): string[] {
    if (aggressive) {
        return ALL_MODULES;
    }
    return PASSIVE_MODULES;
}

/**
 * Check if a module should be skipped for a tier
 */
export function shouldSkipModule(module: string, tier: string, aggressive: boolean = false): boolean {
    // Skip aggressive modules unless opted in
    if (isAggressiveModule(module) && !aggressive) {
        return true;
    }

    // Tier 2 modules depend on Tier 1 completing first
    if (tier === 'tier1' && TIER_2_MODULES.includes(module)) {
        return true;
    }
    if (tier === 'tier1' && TIER_3_MODULES.includes(module)) {
        return true;
    }
    if (tier === 'tier2' && TIER_3_MODULES.includes(module)) {
        return true;
    }

    return false;
}
