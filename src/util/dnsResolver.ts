/**
 * DNS Resolver Utility
 *
 * Resolves DNS records for domains to support Shodan and AbuseIPDB modules.
 * Returns deduplicated IP sets with metadata for threshold adjustments.
 */

import { promises as dns } from 'dns';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('dnsResolver');

interface ResolvedIP {
  ip: string;
  source: 'A' | 'AAAA' | 'MX';
  hostname?: string; // For MX records
}

interface DnsResolutionResult {
  ips: string[]; // Deduplicated list of all IPs
  ipDetails: ResolvedIP[]; // Full details including source
  webIPs: string[]; // A/AAAA records only (for web scanning)
  mailIPs: string[]; // MX-resolved IPs only (for mail reputation)
}

/**
 * Resolve A and AAAA records for apex and www variants
 */
async function resolveWebIPs(domain: string): Promise<ResolvedIP[]> {
  const results: ResolvedIP[] = [];
  const bare = domain.replace(/^https?:\/\//i, '').split(':')[0].trim();

  // Try apex + www (skip www for IPs and localhost)
  const isIpOrLocalhost = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|127\.0\.0\.1|::1)/i.test(bare);
  const hostsToResolve = isIpOrLocalhost ? [bare] : [bare, `www.${bare}`];

  for (const host of hostsToResolve) {
    // A records (IPv4)
    try {
      const addresses = await dns.resolve4(host);
      for (const ip of addresses) {
        results.push({ ip, source: 'A' });
      }
      log.info(`Resolved ${addresses.length} A record(s) for ${host}`);
    } catch (err: any) {
      // ENOTFOUND is expected for non-existent hosts
      if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
        log.info(`Error resolving A records for ${host}: ${err.message}`);
      }
    }

    // AAAA records (IPv6)
    try {
      const addresses = await dns.resolve6(host);
      for (const ip of addresses) {
        results.push({ ip, source: 'AAAA' });
      }
      log.info(`Resolved ${addresses.length} AAAA record(s) for ${host}`);
    } catch (err: any) {
      // ENOTFOUND/ENODATA is expected
      if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
        log.info(`Error resolving AAAA records for ${host}: ${err.message}`);
      }
    }
  }

  return results;
}

/**
 * Resolve MX records and then resolve each MX hostname to IPs
 */
async function resolveMailIPs(domain: string): Promise<ResolvedIP[]> {
  const results: ResolvedIP[] = [];
  const bare = domain.replace(/^https?:\/\//i, '').split(':')[0].trim();

  try {
    const mxRecords = await dns.resolveMx(bare);
    log.info(`Found ${mxRecords.length} MX record(s) for ${bare}`);

    for (const mx of mxRecords) {
      const mxHost = mx.exchange;

      // Resolve MX hostname to IPs
      try {
        const addresses = await dns.resolve4(mxHost);
        for (const ip of addresses) {
          results.push({ ip, source: 'MX', hostname: mxHost });
        }
        log.info(`Resolved ${addresses.length} IP(s) for MX ${mxHost}`);
      } catch (err: any) {
        if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
          log.info(`Error resolving MX host ${mxHost}: ${err.message}`);
        }
      }

      // Try IPv6 for MX as well
      try {
        const addresses = await dns.resolve6(mxHost);
        for (const ip of addresses) {
          results.push({ ip, source: 'MX', hostname: mxHost });
        }
      } catch (err: any) {
        // ENODATA is common for IPv6
        if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
          log.info(`Error resolving MX host ${mxHost} (IPv6): ${err.message}`);
        }
      }
    }
  } catch (err: any) {
    if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
      log.info(`Error resolving MX records for ${bare}: ${err.message}`);
    }
  }

  return results;
}

/**
 * Main resolver function - resolves all DNS records for a domain
 */
export async function resolveDomain(domain: string): Promise<DnsResolutionResult> {
  log.info(`Resolving DNS for ${domain}`);

  // Resolve web and mail IPs in parallel
  const [webResults, mailResults] = await Promise.all([
    resolveWebIPs(domain),
    resolveMailIPs(domain)
  ]);

  // Combine and deduplicate
  const allDetails = [...webResults, ...mailResults];
  const ipSet = new Set<string>();
  const webIPSet = new Set<string>();
  const mailIPSet = new Set<string>();

  for (const detail of allDetails) {
    ipSet.add(detail.ip);
    if (detail.source === 'A' || detail.source === 'AAAA') {
      webIPSet.add(detail.ip);
    } else if (detail.source === 'MX') {
      mailIPSet.add(detail.ip);
    }
  }

  const result = {
    ips: Array.from(ipSet),
    ipDetails: allDetails,
    webIPs: Array.from(webIPSet),
    mailIPs: Array.from(mailIPSet)
  };

  log.info(`DNS resolution complete: ${result.ips.length} total IPs (${result.webIPs.length} web, ${result.mailIPs.length} mail)`);

  return result;
}

/**
 * Get ASN/provider for an IP (optional, for threshold adjustments)
 * Returns null if unknown or on error
 */
export async function getIPProvider(ip: string): Promise<{ asn?: string; org?: string; provider?: string } | null> {
  // For now, detect common cloud providers by IP prefix
  // More sophisticated approach would use MaxMind GeoIP or Shodan API

  // AWS IP ranges (simplified - just a few examples)
  if (ip.startsWith('52.') || ip.startsWith('54.') || ip.startsWith('3.')) {
    return { provider: 'AWS', org: 'Amazon Web Services' };
  }

  // GCP IP ranges (simplified)
  if (ip.startsWith('35.') || ip.startsWith('34.')) {
    return { provider: 'GCP', org: 'Google Cloud Platform' };
  }

  // Azure IP ranges (simplified)
  if (ip.startsWith('13.') || ip.startsWith('40.') || ip.startsWith('52.')) {
    return { provider: 'Azure', org: 'Microsoft Azure' };
  }

  // Cloudflare
  if (ip.startsWith('104.') || ip.startsWith('172.')) {
    return { provider: 'Cloudflare', org: 'Cloudflare Inc' };
  }

  return null;
}

/**
 * Check if IP belongs to major shared hosting provider
 * Used for adjusting AbuseIPDB thresholds
 */
export async function isSharedHostingIP(ip: string): Promise<boolean> {
  const provider = await getIPProvider(ip);
  if (!provider) return false;

  const sharedProviders = ['AWS', 'GCP', 'Azure', 'Cloudflare'];
  return provider.provider ? sharedProviders.includes(provider.provider) : false;
}
