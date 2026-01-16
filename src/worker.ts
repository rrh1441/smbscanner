import { config } from 'dotenv';
import { insertArtifact } from './core/artifactStore.js';
import { runShodanScan } from './modules/shodan.js';
import { runClientSecretScanner } from './modules/clientSecretScanner.js';
import { runTlsScan } from './modules/tlsScan.js';
import { executeModule as runLightweightCveCheck } from './modules/lightweightCveCheck.js';
import { runSpfDmarc } from './modules/spfDmarc.js';
import { runEndpointDiscovery } from './modules/endpointDiscovery.js';
import { runTechStackScan } from './modules/techStackScan.js';
import { runAccessibilityLightweight } from './modules/accessibilityLightweight.js';
import { runInfostealerProbe } from './modules/infostealerProbe.js';
import { runAssetCorrelator } from './modules/assetCorrelator.js';
import { runConfigExposureScanner } from './modules/configExposureScanner.js';
import { runBackendExposureScanner } from './modules/backendExposureScanner.js';
import { runLightweightBackendScan } from './modules/lightweightBackendScan.js';
import { runDenialWalletScan } from './modules/denialWalletScan.js';
import { runWhoisWrapper } from './modules/whoisWrapper.js';
import { runWpPluginQuickScan } from './modules/wpPluginQuickScan.js';
import { runAdminPanelDetector } from './modules/adminPanelDetector.js';
import { runDnsZoneTransfer } from './modules/dnsZoneTransfer.js';
import { runSubdomainTakeover } from './modules/subdomainTakeover.js';
import { createModuleLogger } from './core/logger.js';

const log = createModuleLogger('worker');

// Module timeout wrapper
async function runModuleWithTimeout<T>(
  moduleName: string,
  moduleFunction: () => Promise<T>,
  timeoutMs: number,
  scanId: string,
  options: { onTimeoutReturn?: T } = {}
): Promise<T> {
  const startTime = Date.now();

  let timeoutHandle: NodeJS.Timeout | undefined;

  try {
    return await Promise.race([
      moduleFunction().then(result => {
        const duration = Date.now() - startTime;
        log.info({ moduleName, durationMs: duration, scanId }, 'Module completed');
        if (timeoutHandle) clearTimeout(timeoutHandle);
        return result;
      }).catch(error => {
        const duration = Date.now() - startTime;
        log.error({ moduleName, err: error, durationMs: duration, scanId }, 'Module failed');
        if (timeoutHandle) clearTimeout(timeoutHandle);
        throw error;
      }),
      new Promise<T>((_, reject) => {
        timeoutHandle = setTimeout(() => {
          log.warn({ moduleName, timeoutMs, scanId }, 'Module timeout');
          reject(new Error(`Module ${moduleName} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      })
    ]);
  } catch (error) {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    if (error instanceof Error && error.message.includes('timed out') && options.onTimeoutReturn !== undefined) {
      log.info({ moduleName, scanId }, 'Timeout handled - returning fallback result');
      return options.onTimeoutReturn;
    }
    throw error;
  }
}

config();

const ENABLE_ENDPOINT_DISCOVERY = process.env.ENABLE_ENDPOINT_DISCOVERY !== 'false';
const ENDPOINT_DISCOVERY_TIMEOUT_MS = parseInt(process.env.ENDPOINT_DISCOVERY_TIMEOUT_MS || '60000', 10);

// Update scan status - uses local database
async function updateScanStatus(scanId: string, updates: any) {
  try {
    // For OSS, scan status is managed by queueService/database
    // This is a no-op stub for compatibility
    log.debug({ scanId, updates }, 'Scan status update (local mode)');
  } catch (error) {
    log.error({ err: error, scanId }, 'Failed to update scan');
  }
}

interface ScanJob {
  scanId: string;
  companyName: string;
  domain: string;
  createdAt: string;
}

// Tier 1 modules - Foundation (no dependencies, just needs domain)
const BASE_TIER_1_MODULES = [
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

const TIER_1_MODULES = ENABLE_ENDPOINT_DISCOVERY
  ? BASE_TIER_1_MODULES
  : BASE_TIER_1_MODULES.filter(module => module !== 'endpoint_discovery');

export async function processScan(job: ScanJob) {
  const { scanId, companyName, domain } = job;

  log.info({ scanId, companyName, domain }, 'Processing scan');

  try {
    // Update scan status
    await updateScanStatus(scanId, {
      status: 'processing',
      started_at: new Date().toISOString()
    });

    const activeModules = TIER_1_MODULES;
    let totalFindings = 0;

    // Run modules in parallel where possible
    const parallelModules: { [key: string]: Promise<number> } = {};

    // Tier 1 - Foundation modules (independent, just need domain)
    if (activeModules.includes('shodan')) {
      log.info({ module: 'shodan', scanId }, 'Starting module');
      parallelModules.shodan = runModuleWithTimeout('shodan',
        () => runShodanScan({ domain, scanId, companyName }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('whois_wrapper')) {
      log.info({ module: 'whois_wrapper', scanId }, 'Starting module');
      parallelModules.whois_wrapper = runModuleWithTimeout('whois_wrapper',
        () => runWhoisWrapper({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('spf_dmarc')) {
      log.info({ module: 'spf_dmarc', scanId }, 'Starting module');
      parallelModules.spf_dmarc = runModuleWithTimeout('spf_dmarc',
        () => runSpfDmarc({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('tech_stack_scan')) {
      log.info({ module: 'tech_stack_scan', scanId }, 'Starting module');
      parallelModules.tech_stack_scan = runModuleWithTimeout('tech_stack_scan',
        () => runTechStackScan({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (ENABLE_ENDPOINT_DISCOVERY && activeModules.includes('endpoint_discovery')) {
      log.info({ module: 'endpoint_discovery', scanId }, 'Starting module');
      parallelModules.endpoint_discovery = runModuleWithTimeout('endpoint_discovery',
        () => runEndpointDiscovery({ domain, scanId }),
        ENDPOINT_DISCOVERY_TIMEOUT_MS, scanId, { onTimeoutReturn: 0 });
    }
    if (activeModules.includes('infostealer_probe')) {
      log.info({ module: 'infostealer_probe', scanId }, 'Starting module');
      parallelModules.infostealer_probe = runModuleWithTimeout('infostealer_probe',
        () => runInfostealerProbe({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('wp_plugin_quickscan')) {
      log.info({ module: 'wp_plugin_quickscan', scanId }, 'Starting module');
      parallelModules.wp_plugin_quickscan = runModuleWithTimeout('wp_plugin_quickscan',
        () => runWpPluginQuickScan({ domain, scanId }),
        30 * 1000, scanId, { onTimeoutReturn: 0 });
    }
    if (activeModules.includes('config_exposure')) {
      log.info({ module: 'config_exposure', scanId }, 'Starting module');
      parallelModules.config_exposure = runModuleWithTimeout('config_exposure',
        () => runConfigExposureScanner({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('admin_panel_detector')) {
      log.info({ module: 'admin_panel_detector', scanId }, 'Starting module');
      parallelModules.admin_panel_detector = runModuleWithTimeout('admin_panel_detector',
        () => runAdminPanelDetector({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('dns_zone_transfer')) {
      log.info({ module: 'dns_zone_transfer', scanId }, 'Starting module');
      parallelModules.dns_zone_transfer = runModuleWithTimeout('dns_zone_transfer',
        () => runDnsZoneTransfer({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('subdomain_takeover')) {
      log.info({ module: 'subdomain_takeover', scanId }, 'Starting module');
      parallelModules.subdomain_takeover = runModuleWithTimeout('subdomain_takeover',
        () => runSubdomainTakeover({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('lightweight_backend_scan')) {
      log.info({ module: 'lightweight_backend_scan', scanId }, 'Starting module');
      parallelModules.lightweight_backend_scan = runModuleWithTimeout('lightweight_backend_scan',
        () => runLightweightBackendScan({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('backend_exposure_scanner')) {
      log.info({ module: 'backend_exposure_scanner', scanId }, 'Starting module');
      parallelModules.backend_exposure_scanner = runModuleWithTimeout('backend_exposure_scanner',
        () => runBackendExposureScanner({ scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('client_secret_scanner')) {
      log.info({ module: 'client_secret_scanner', scanId }, 'Starting module');
      parallelModules.client_secret_scanner = runModuleWithTimeout('client_secret_scanner',
        () => runClientSecretScanner({ scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('denial_wallet_scan')) {
      log.info({ module: 'denial_wallet_scan', scanId }, 'Starting module');
      parallelModules.denial_wallet_scan = runModuleWithTimeout('denial_wallet_scan',
        () => runDenialWalletScan({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('accessibility_lightweight')) {
      log.info({ module: 'accessibility_lightweight', scanId }, 'Starting module');
      parallelModules.accessibility_lightweight = runModuleWithTimeout('accessibility_lightweight',
        () => runAccessibilityLightweight({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }
    if (activeModules.includes('tls_scan')) {
      log.info({ module: 'tls_scan', scanId }, 'Starting module');
      parallelModules.tls_scan = runModuleWithTimeout('tls_scan',
        () => runTlsScan({ domain, scanId }),
        3 * 60 * 1000, scanId);
    }

    // Wait for tech_stack_scan first (needed for Tier 2)
    let techStackResults = 0;
    if (parallelModules.tech_stack_scan) {
      techStackResults = await parallelModules.tech_stack_scan;
      log.info({ findingsCount: techStackResults }, 'Tech stack scan completed');
      delete parallelModules.tech_stack_scan;
      totalFindings += techStackResults;
    }

    // Tier 2 - Enrichment modules (depend on Tier 1 artifacts)
    log.info({ module: 'lightweight_cve_check', scanId }, 'Starting module');
    parallelModules.lightweight_cve_check = runModuleWithTimeout('lightweight_cve_check',
      async () => {
        const result = await runLightweightCveCheck({ scanId, domain, artifacts: [] });
        return result.findings ? result.findings.length : 0;
      },
      30 * 1000, scanId);

    // Wait for all modules with graceful degradation
    let completedModules = 0;
    const totalModulesCount = Object.keys(parallelModules).length;

    for (const [moduleName, promise] of Object.entries(parallelModules)) {
      try {
        const results = await promise;
        completedModules++;
        totalFindings += results;
        log.info({ completedModules, totalModules: totalModulesCount, moduleName, findingsCount: results, scanId }, 'Module progress');
      } catch (error) {
        completedModules++;
        log.warn({ moduleName, err: error, scanId }, 'Module failed but scan continues');
        log.info({ completedModules, totalModules: totalModulesCount, moduleName, status: 'FAILED', scanId }, 'Module progress');

        await insertArtifact({
          type: 'scan_error',
          val_text: `Module ${moduleName} failed: ${(error as Error).message}`,
          severity: 'MEDIUM',
          meta: { scan_id: scanId, module: moduleName }
        });
      }
    }

    // Tier 3 - Correlation
    try {
      await runAssetCorrelator({ scanId, domain, tier: 'tier1' });
      log.info({ scanId }, 'Asset correlation completed');
    } catch (error) {
      log.warn({ err: error, scanId }, 'Asset correlation failed');
    }

    // Update scan completion
    await updateScanStatus(scanId, {
      status: 'completed',
      completed_at: new Date().toISOString(),
      total_findings: totalFindings
    });

    log.info({ totalFindings, scanId }, 'Scan completed');

  } catch (error) {
    log.error({ err: error, scanId }, 'Scan failed');

    await updateScanStatus(scanId, {
      status: 'failed',
      error: (error as Error).message,
      failed_at: new Date().toISOString()
    });

    await insertArtifact({
      type: 'scan_error',
      val_text: `Scan failed: ${(error as Error).message}`,
      severity: 'CRITICAL',
      meta: { scan_id: scanId }
    });

    throw error;
  }
}

// Export for use by worker-pubsub.ts
// The main entry point is now handled by worker-pubsub.ts which listens to Pub/Sub messages
