/* =============================================================================
 * MODULE: subdomainTakeover.ts
 * =============================================================================
 * Detects dangling DNS records (CNAME/A) pointing to claimable third-party
 * services. Attackers can claim these abandoned resources to host phishing,
 * malware, or steal cookies.
 *
 * Detection approach:
 *   1. Enumerate subdomains via Certificate Transparency (crt.sh)
 *   2. Resolve DNS records for each subdomain
 *   3. Check CNAMEs against known claimable service patterns
 *   4. Verify takeover possibility via HTTP fingerprint matching
 *
 * Time budget: ~2-3 minutes (quality over speed)
 * =============================================================================
 */

import { Resolver } from 'node:dns/promises';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('subdomainTakeover');

// Create DNS resolver with custom servers
const dnsResolver = new Resolver();
dnsResolver.setServers(['8.8.8.8', '1.1.1.1', '9.9.9.9']);

// Configuration
const CONFIG = {
  CRT_SH_TIMEOUT_MS: 30_000,
  DNS_TIMEOUT_MS: 5_000,
  HTTP_TIMEOUT_MS: 8_000,
  MAX_SUBDOMAINS: 200,
  CONCURRENT_DNS: 50,
  CONCURRENT_HTTP: 10,
} as const;

// Known claimable services with their fingerprints
// Based on https://github.com/EdOverflow/can-i-take-over-xyz
interface ClaimableService {
  name: string;
  cnamePatterns: RegExp[];
  fingerprints: string[];
  nxdomain?: boolean; // Some services return NXDOMAIN when unclaimed
}

const CLAIMABLE_SERVICES: ClaimableService[] = [
  {
    name: 'GitHub Pages',
    cnamePatterns: [/\.github\.io$/i],
    fingerprints: [
      "There isn't a GitHub Pages site here",
      'For root URLs (like http://example.com/) you must provide an index.html file',
    ],
  },
  {
    name: 'Heroku',
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokudns\.com$/i],
    fingerprints: [
      'No such app',
      "There's nothing here, yet.",
      'herokucdn.com/error-pages/no-such-app.html',
    ],
  },
  {
    name: 'AWS S3',
    cnamePatterns: [/\.s3\.amazonaws\.com$/i, /\.s3-[\w-]+\.amazonaws\.com$/i, /\.s3\.[\w-]+\.amazonaws\.com$/i],
    fingerprints: [
      'The specified bucket does not exist',
      'NoSuchBucket',
    ],
  },
  {
    name: 'Azure',
    cnamePatterns: [
      /\.azurewebsites\.net$/i,
      /\.cloudapp\.azure\.com$/i,
      /\.cloudapp\.net$/i,
      /\.azureedge\.net$/i,
      /\.trafficmanager\.net$/i,
      /\.blob\.core\.windows\.net$/i,
    ],
    fingerprints: [],
    nxdomain: true, // Azure returns NXDOMAIN when resource doesn't exist
  },
  {
    name: 'Shopify',
    cnamePatterns: [/\.myshopify\.com$/i],
    fingerprints: [
      'Sorry, this shop is currently unavailable',
      "Only one step left!",
    ],
  },
  {
    name: 'Surge.sh',
    cnamePatterns: [/\.surge\.sh$/i],
    fingerprints: ['project not found'],
  },
  {
    name: 'Pantheon',
    cnamePatterns: [/\.pantheonsite\.io$/i, /\.pantheon\.io$/i],
    fingerprints: [
      'The gods are wise',
      '404 error unknown site!',
    ],
  },
  {
    name: 'Tumblr',
    cnamePatterns: [/\.tumblr\.com$/i],
    fingerprints: [
      "There's nothing here.",
      "Whatever you were looking for doesn't currently exist at this address",
    ],
  },
  {
    name: 'WordPress.com',
    cnamePatterns: [/\.wordpress\.com$/i],
    fingerprints: [
      "Do you want to register",
    ],
  },
  {
    name: 'Ghost',
    cnamePatterns: [/\.ghost\.io$/i],
    fingerprints: [
      'The thing you were looking for is no longer here',
    ],
  },
  {
    name: 'Fastly',
    cnamePatterns: [/\.fastly\.net$/i, /\.fastlylb\.net$/i],
    fingerprints: [
      'Fastly error: unknown domain',
    ],
  },
  {
    name: 'Fly.io',
    cnamePatterns: [/\.fly\.dev$/i],
    fingerprints: [],
    nxdomain: true,
  },
  {
    name: 'Netlify',
    cnamePatterns: [/\.netlify\.app$/i, /\.netlify\.com$/i],
    fingerprints: [],
    nxdomain: true, // Netlify returns NXDOMAIN for unclaimed subdomains
  },
  {
    name: 'Vercel',
    cnamePatterns: [/\.vercel\.app$/i, /\.now\.sh$/i],
    fingerprints: [],
    nxdomain: true,
  },
  {
    name: 'Zendesk',
    cnamePatterns: [/\.zendesk\.com$/i],
    fingerprints: [
      'Help Center Closed',
      'This help center no longer exists',
    ],
  },
  {
    name: 'Intercom',
    cnamePatterns: [/\.intercom\.help$/i, /\.intercom\.io$/i],
    fingerprints: [
      "This page is reserved for",
      "Uh oh. That page doesn't exist.",
    ],
  },
  {
    name: 'Cargo',
    cnamePatterns: [/\.cargo\.site$/i],
    fingerprints: [
      '404 Not Found',
    ],
  },
  {
    name: 'Statuspage',
    cnamePatterns: [/\.statuspage\.io$/i],
    fingerprints: [
      'Status page pushed a b]it too hard',
      "You are being <a href=",
    ],
  },
  {
    name: 'UserVoice',
    cnamePatterns: [/\.uservoice\.com$/i],
    fingerprints: [
      'This UserVoice subdomain is currently available!',
    ],
  },
  {
    name: 'HelpScout',
    cnamePatterns: [/\.helpscoutdocs\.com$/i],
    fingerprints: [
      'No settings were found for this company:',
    ],
  },
  {
    name: 'Freshdesk',
    cnamePatterns: [/\.freshdesk\.com$/i],
    fingerprints: [
      "There is no helpdesk here!",
      "May be this is still cooking",
    ],
  },
  {
    name: 'Tilda',
    cnamePatterns: [/\.tilda\.ws$/i],
    fingerprints: [
      'Please renew your subscription',
    ],
  },
  {
    name: 'Webflow',
    cnamePatterns: [/\.webflow\.io$/i],
    fingerprints: [
      "The page you are looking for doesn't exist or has been moved.",
    ],
  },
  {
    name: 'Readme.io',
    cnamePatterns: [/\.readme\.io$/i],
    fingerprints: [
      'Project doesnt exist... yet!',
    ],
  },
  {
    name: 'Bitbucket',
    cnamePatterns: [/\.bitbucket\.io$/i],
    fingerprints: [
      'Repository not found',
    ],
  },
  {
    name: 'SmartJobBoard',
    cnamePatterns: [/\.smartjobboard\.com$/i],
    fingerprints: [
      'This job board website is either expired or its domain name is invalid',
    ],
  },
  {
    name: 'Agile CRM',
    cnamePatterns: [/\.agilecrm\.com$/i],
    fingerprints: [
      "Sorry, this page is no longer available.",
    ],
  },
  {
    name: 'Airee.ru',
    cnamePatterns: [/\.airee\.ru$/i],
    fingerprints: [
      'Ошибка 402. Сервис',
    ],
  },
  {
    name: 'Anima',
    cnamePatterns: [/\.animaapp\.io$/i],
    fingerprints: [
      'If this is your website and you\'ve just created it, try refreshing in a minute',
    ],
  },
  {
    name: 'AWS Elastic Beanstalk',
    cnamePatterns: [/\.elasticbeanstalk\.com$/i],
    fingerprints: [],
    nxdomain: true,
  },
  {
    name: 'Canny',
    cnamePatterns: [/\.canny\.io$/i],
    fingerprints: [
      'There is no such company. Did you enter the right URL?',
    ],
  },
  {
    name: 'LaunchRock',
    cnamePatterns: [/launchrock\.com$/i],
    fingerprints: [
      "It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",
    ],
  },
  {
    name: 'Ngrok',
    cnamePatterns: [/\.ngrok\.io$/i],
    fingerprints: [
      'ngrok.io not found',
      'Tunnel .*.ngrok.io not found',
    ],
  },
];

// Indicators that a domain is parked (false positive prevention)
const PARKING_INDICATORS = [
  'domain is for sale',
  'this domain is for sale',
  'buy this domain',
  'sedoparking',
  'godaddy.com/forsale',
  'hugedomains.com',
  'domainsmarket',
  'domainmarket',
  'namecheap.com',
  'dan.com',
  'afternic.com',
  'sedo.com',
  'parked',
  'underconstruction',
  'coming soon',
  'site under construction',
];

interface SubdomainResult {
  subdomain: string;
  cname?: string;
  aRecords?: string[];
  service?: string;
  fingerprint?: string;
  vulnerable: boolean;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  reason?: string;
}

/**
 * Fetch subdomains from Certificate Transparency logs via crt.sh
 */
async function enumerateSubdomains(domain: string): Promise<string[]> {
  const subdomains = new Set<string>();

  try {
    // Query crt.sh for certificate transparency logs
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONFIG.CRT_SH_TIMEOUT_MS);

    try {
      const response = await fetch(
        `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`,
        {
          signal: controller.signal,
          headers: {
            'User-Agent': 'SimplCyber-Scanner/1.0 (security-research)',
          },
        }
      );

      clearTimeout(timeoutId);

      if (!response.ok) {
        log.warn({ status: response.status, domain }, 'crt.sh returned non-OK status');
        return [];
      }

      const data = await response.json() as Array<{ name_value: string }>;

      for (const entry of data) {
        // name_value can contain multiple names separated by newlines
        const names = entry.name_value.split('\n');
        for (const name of names) {
          const cleaned = name.toLowerCase().trim().replace(/^\*\./, '');
          // Only include subdomains of the target domain
          if (cleaned.endsWith(`.${domain}`) || cleaned === domain) {
            subdomains.add(cleaned);
          }
        }
      }
    } finally {
      clearTimeout(timeoutId);
    }

    log.info({ domain, count: subdomains.size }, 'Enumerated subdomains from crt.sh');
  } catch (error: any) {
    if (error.name === 'AbortError') {
      log.warn({ domain }, 'crt.sh request timed out');
    } else {
      log.error({ err: error, domain }, 'Failed to enumerate subdomains');
    }
  }

  // Limit to configured max
  const results = Array.from(subdomains).slice(0, CONFIG.MAX_SUBDOMAINS);
  return results;
}

/**
 * Resolve CNAME record for a subdomain
 */
async function resolveCNAME(subdomain: string): Promise<string | null> {
  try {
    const records = await dnsResolver.resolveCname(subdomain);
    return records[0] || null;
  } catch {
    return null;
  }
}

/**
 * Resolve A records for a subdomain
 */
async function resolveA(subdomain: string): Promise<string[]> {
  try {
    const records = await dnsResolver.resolve4(subdomain);
    return records;
  } catch {
    return [];
  }
}

/**
 * Check if a CNAME points to a known claimable service
 */
function matchClaimableService(cname: string): ClaimableService | null {
  for (const service of CLAIMABLE_SERVICES) {
    for (const pattern of service.cnamePatterns) {
      if (pattern.test(cname)) {
        return service;
      }
    }
  }
  return null;
}

/**
 * Fetch HTTP response and check for vulnerability fingerprints
 */
async function checkHttpFingerprint(
  subdomain: string,
  service: ClaimableService
): Promise<{ vulnerable: boolean; fingerprint?: string; parked?: boolean }> {
  if (service.fingerprints.length === 0 && !service.nxdomain) {
    // Service relies on NXDOMAIN check only, already handled
    return { vulnerable: false };
  }

  const protocols = ['https', 'http'];

  for (const protocol of protocols) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONFIG.HTTP_TIMEOUT_MS);

      try {
        const response = await fetch(`${protocol}://${subdomain}`, {
          signal: controller.signal,
          redirect: 'follow',
          headers: {
            'User-Agent': 'Mozilla/5.0 (compatible; SimplCyber-Scanner/1.0)',
          },
        });

        clearTimeout(timeoutId);

        const text = await response.text();
        const lowerText = text.toLowerCase();

        // Check for parking indicators (false positive)
        for (const indicator of PARKING_INDICATORS) {
          if (lowerText.includes(indicator.toLowerCase())) {
            return { vulnerable: false, parked: true };
          }
        }

        // Check for vulnerability fingerprints
        for (const fingerprint of service.fingerprints) {
          if (text.includes(fingerprint)) {
            return { vulnerable: true, fingerprint };
          }
        }

        // If we got a valid response without fingerprint, it's likely claimed
        if (response.ok) {
          return { vulnerable: false };
        }
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error: any) {
      // Connection errors might indicate NXDOMAIN or unresolvable
      if (service.nxdomain) {
        // For NXDOMAIN services, connection failure = vulnerable
        if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
          return { vulnerable: true, fingerprint: 'DNS resolution failed (NXDOMAIN)' };
        }
      }
    }
  }

  return { vulnerable: false };
}

/**
 * Process a batch of subdomains concurrently
 */
async function processSubdomainsBatch<T>(
  items: T[],
  concurrency: number,
  processor: (item: T) => Promise<SubdomainResult | null>
): Promise<SubdomainResult[]> {
  const results: SubdomainResult[] = [];

  for (let i = 0; i < items.length; i += concurrency) {
    const batch = items.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(processor));
    results.push(...batchResults.filter((r): r is SubdomainResult => r !== null));
  }

  return results;
}

/**
 * Main module function
 */
export async function runSubdomainTakeover(job: {
  domain: string;
  scanId: string;
}): Promise<number> {
  const { domain, scanId } = job;
  log.info({ domain, scanId }, 'Starting subdomain takeover detection');

  let findingsCount = 0;
  const vulnerableResults: SubdomainResult[] = [];

  try {
    // Step 1: Enumerate subdomains via Certificate Transparency
    const subdomains = await enumerateSubdomains(domain);

    if (subdomains.length === 0) {
      log.info({ domain }, 'No subdomains found in CT logs');
      await insertArtifact({
        type: 'subdomain_takeover_raw',
        val_text: `No subdomains found for ${domain}`,
        severity: 'INFO',
        meta: { scan_id: scanId, domain, subdomain_count: 0 },
      });
      return 0;
    }

    log.info({ domain, count: subdomains.length }, 'Processing subdomains');

    // Step 2: Resolve DNS and check for claimable services
    const results = await processSubdomainsBatch(
      subdomains,
      CONFIG.CONCURRENT_DNS,
      async (subdomain): Promise<SubdomainResult | null> => {
        try {
          // First try CNAME resolution
          const cname = await resolveCNAME(subdomain);

          if (cname) {
            const service = matchClaimableService(cname);

            if (service) {
              // Check HTTP fingerprint for confirmation
              const httpCheck = await checkHttpFingerprint(subdomain, service);

              if (httpCheck.parked) {
                return null; // Skip parked domains
              }

              if (httpCheck.vulnerable || service.nxdomain) {
                return {
                  subdomain,
                  cname,
                  service: service.name,
                  fingerprint: httpCheck.fingerprint,
                  vulnerable: true,
                  severity: 'CRITICAL',
                  reason: `Dangling CNAME to ${service.name} - resource can be claimed`,
                };
              }

              // CNAME matches but no fingerprint - could still be vulnerable
              return {
                subdomain,
                cname,
                service: service.name,
                vulnerable: false,
                severity: 'LOW',
                reason: `CNAME points to ${service.name} but appears claimed`,
              };
            }
          }

          // Check for A records pointing to unresponsive IPs
          const aRecords = await resolveA(subdomain);
          if (aRecords.length === 0 && !cname) {
            // Subdomain exists in CT but has no DNS records - potential orphan
            return {
              subdomain,
              vulnerable: false,
              severity: 'INFO',
              reason: 'Subdomain in CT logs but no DNS records',
            };
          }

          return null; // No issues found
        } catch (error) {
          log.debug({ subdomain, err: error }, 'Error checking subdomain');
          return null;
        }
      }
    );

    // Filter to only vulnerable results for detailed HTTP checks
    const potentiallyVulnerable = results.filter(r => r.vulnerable);

    // Step 3: Double-check vulnerable results with temporal validation
    for (const result of potentiallyVulnerable) {
      if (!result.service) continue;

      // Wait a moment and recheck to avoid transient issues
      await new Promise(resolve => setTimeout(resolve, 2000));

      const service = CLAIMABLE_SERVICES.find(s => s.name === result.service);
      if (!service) continue;

      const recheck = await checkHttpFingerprint(result.subdomain, service);

      if (recheck.vulnerable) {
        vulnerableResults.push(result);

        // Insert finding
        await insertFinding({
          scan_id: scanId,
          type: 'SUBDOMAIN_TAKEOVER_VULNERABILITY',
          severity: result.severity,
          title: `Subdomain takeover vulnerability: ${result.subdomain}`,
          description: `${result.subdomain} has a dangling CNAME record pointing to ${result.cname} (${result.service}). ` +
            `This resource is not claimed and can be registered by an attacker to host malicious content, ` +
            `steal cookies, or impersonate your organization.`,
          data: {
            subdomain: result.subdomain,
            cname: result.cname,
            service: result.service,
            fingerprint: result.fingerprint,
          },
        });
        findingsCount++;

        log.warn({
          subdomain: result.subdomain,
          service: result.service,
          cname: result.cname
        }, 'Confirmed subdomain takeover vulnerability');
      }
    }

    // Store raw results as artifact
    await insertArtifact({
      type: 'subdomain_takeover_raw',
      val_text: `Subdomain takeover scan complete for ${domain}`,
      severity: vulnerableResults.length > 0 ? 'CRITICAL' : 'INFO',
      meta: {
        scan_id: scanId,
        domain,
        subdomain_count: subdomains.length,
        vulnerable_count: vulnerableResults.length,
        vulnerable_subdomains: vulnerableResults.map(r => ({
          subdomain: r.subdomain,
          service: r.service,
          cname: r.cname,
        })),
      },
    });

    log.info({
      domain,
      scanId,
      subdomains_checked: subdomains.length,
      findings: findingsCount
    }, 'Subdomain takeover detection complete');

  } catch (error: any) {
    log.error({ err: error, domain, scanId }, 'Subdomain takeover detection failed');

    await insertArtifact({
      type: 'subdomain_takeover_error',
      val_text: `Subdomain takeover detection error: ${error.message}`,
      severity: 'LOW',
      meta: { scan_id: scanId, domain, error: error.message },
    });
  }

  return findingsCount;
}
