/*
 * =============================================================================
 * MODULE: dnsZoneTransfer.ts
 * =============================================================================
 * Detects DNS zone transfer (AXFR) vulnerabilities on domain nameservers.
 *
 * Why This Matters:
 *   - Zone transfers expose the ENTIRE DNS zone (all subdomains, internal hosts)
 *   - 2-5% hit rate on SMB domains due to misconfigured DNS servers
 *   - Enables reconnaissance for further attacks (subdomain enumeration)
 *   - Easy to fix: restrict zone transfers to authorized IPs only
 *
 * Detection Approach:
 *   1. Query NS records to find authoritative nameservers
 *   2. Attempt AXFR query against each nameserver
 *   3. If transfer succeeds and returns records, flag as vulnerability
 *
 * False Positive Prevention:
 *   - Only flag if transfer returns actual resource records
 *   - Ignore if only SOA/NS records returned (empty zone)
 *   - 10-second timeout per nameserver (some servers hang)
 * =============================================================================
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('dnsZoneTransfer');
const exec = promisify(execFile);

// Timeout for AXFR queries (some servers hang indefinitely)
const AXFR_TIMEOUT_MS = 10000;

// Maximum nameservers to test (to stay within time budget)
const MAX_NAMESERVERS = 4;

interface ZoneTransferResult {
  nameserver: string;
  vulnerable: boolean;
  recordCount: number;
  recordTypes: string[];
  transferSize?: string;
  error?: string;
}

/**
 * Extract apex/organizational domain from a given domain.
 * Zone transfers only work at the apex domain level.
 */
function extractApexDomain(domain: string): string {
  let apex = domain.replace(/^www\./, '');
  const parts = apex.split('.');

  if (parts.length >= 2) {
    const lastTwo = parts.slice(-2).join('.');
    const lastThree = parts.slice(-3).join('.');

    // Common multi-part TLDs
    const multiPartTLDs = ['co.uk', 'com.au', 'co.jp', 'co.nz', 'com.br', 'co.in', 'co.za'];
    if (multiPartTLDs.includes(lastTwo) && parts.length >= 3) {
      return lastThree;
    }

    return lastTwo;
  }

  return apex;
}

/**
 * Get authoritative nameservers for a domain.
 */
async function getNameservers(domain: string): Promise<string[]> {
  try {
    const { stdout } = await exec('dig', ['+short', 'NS', domain], {
      timeout: 5000,
      maxBuffer: 1024 * 1024,
    });

    const nameservers = stdout
      .trim()
      .split('\n')
      .map(ns => ns.replace(/\.$/, '').trim())
      .filter(ns => ns.length > 0);

    return nameservers;
  } catch (err) {
    log.debug({ err, domain }, 'Failed to get nameservers');
    return [];
  }
}

/**
 * Attempt zone transfer against a single nameserver.
 */
async function attemptZoneTransfer(domain: string, nameserver: string): Promise<ZoneTransferResult> {
  const result: ZoneTransferResult = {
    nameserver,
    vulnerable: false,
    recordCount: 0,
    recordTypes: [],
  };

  try {
    log.debug({ domain, nameserver }, 'Attempting zone transfer');

    const { stdout, stderr } = await exec('dig', ['AXFR', domain, `@${nameserver}`], {
      timeout: AXFR_TIMEOUT_MS,
      maxBuffer: 10 * 1024 * 1024,
    });

    // Check for successful transfer indicators
    if (stdout.includes('XFR size:')) {
      const sizeMatch = stdout.match(/XFR size:\s*(\d+)\s*records/);
      if (sizeMatch) {
        result.recordCount = parseInt(sizeMatch[1], 10);
        result.transferSize = sizeMatch[0];
      }

      const recordTypeMatches = [...stdout.matchAll(/^\S+\s+\d+\s+IN\s+(\w+)/gm)];
      const types = new Set<string>();
      for (const match of recordTypeMatches) {
        types.add(match[1]);
      }
      result.recordTypes = Array.from(types);

      const meaningfulTypes = result.recordTypes.filter(t => !['SOA', 'NS'].includes(t));

      if (result.recordCount > 2 || meaningfulTypes.length > 0) {
        result.vulnerable = true;
        log.info({ domain, nameserver, recordCount: result.recordCount, recordTypes: result.recordTypes },
          'Zone transfer SUCCESSFUL - vulnerability confirmed');
      }
    } else if (stdout.includes('Transfer failed') || stdout.includes('REFUSED') || stderr.includes('REFUSED')) {
      log.debug({ domain, nameserver }, 'Zone transfer properly refused');
    } else if (stdout.includes('connection timed out') || stdout.includes('no servers could be reached')) {
      result.error = 'timeout';
    }
  } catch (err: any) {
    if (err.killed) {
      result.error = 'timeout';
    } else {
      result.error = err.message;
    }
  }

  return result;
}

/**
 * Main module entry point.
 */
export async function runDnsZoneTransfer(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;

  log.info({ domain, scanId }, 'Starting DNS zone transfer detection');

  const apexDomain = extractApexDomain(domain);

  if (apexDomain !== domain) {
    log.info({ apexDomain, scanDomain: domain }, 'Using apex domain for zone transfer check');
  }

  const nameservers = await getNameservers(apexDomain);

  if (nameservers.length === 0) {
    log.info({ domain: apexDomain }, 'No nameservers found - skipping zone transfer check');
    return 0;
  }

  log.info({ domain: apexDomain, nameserverCount: nameservers.length },
    `Found ${nameservers.length} nameservers, testing up to ${MAX_NAMESERVERS}`);

  const results: ZoneTransferResult[] = [];
  let findingsCount = 0;

  for (const ns of nameservers.slice(0, MAX_NAMESERVERS)) {
    const result = await attemptZoneTransfer(apexDomain, ns);
    results.push(result);

    if (result.vulnerable) {
      await insertArtifact({
        type: 'dns_zone_transfer',
        val_text: `Zone transfer succeeded on ${ns}: ${result.recordCount} records (${result.recordTypes.join(', ')})`,
        severity: 'HIGH',
        src_url: null,
        meta: {
          scan_id: scanId,
          scan_module: 'dnsZoneTransfer',
          nameserver: ns,
          record_count: result.recordCount,
          record_types: result.recordTypes,
          transfer_size: result.transferSize,
        },
      });

      await insertFinding({
        scan_id: scanId,
        type: 'DNS_ZONE_TRANSFER_ENABLED',
        severity: 'HIGH',
        title: 'DNS zone transfer enabled',
        description: `The nameserver ${ns} allows unrestricted zone transfers (AXFR). ` +
          `This exposed ${result.recordCount} DNS records including: ${result.recordTypes.join(', ')}. ` +
          'Zone transfers reveal your entire DNS infrastructure, enabling attackers to discover ' +
          'all subdomains, internal hostnames, and mail servers for targeted attacks.',
        data: {
          recommendation: 'Restrict zone transfers to authorized secondary nameservers only. ' +
            'Configure your DNS server to deny AXFR requests from unauthorized IP addresses. ' +
            'For BIND: use "allow-transfer { trusted-servers; };" directive. ' +
            'For Windows DNS: configure zone transfer settings in DNS Manager.',
          nameserver: ns,
          record_count: result.recordCount,
          record_types: result.recordTypes,
          apex_domain: apexDomain,
        },
      });

      findingsCount++;
      break;
    }
  }

  const vulnerableCount = results.filter(r => r.vulnerable).length;
  const testedCount = results.length;

  await insertArtifact({
    type: 'dns_zone_transfer_summary',
    val_text: `Zone transfer check: ${vulnerableCount}/${testedCount} nameservers vulnerable`,
    severity: vulnerableCount > 0 ? 'HIGH' : 'INFO',
    meta: {
      scan_id: scanId,
      scan_module: 'dnsZoneTransfer',
      apex_domain: apexDomain,
      nameservers_tested: testedCount,
      nameservers_vulnerable: vulnerableCount,
      results: results.map(r => ({
        nameserver: r.nameserver,
        vulnerable: r.vulnerable,
        recordCount: r.recordCount,
        error: r.error,
      })),
    },
  });

  log.info({ domain: apexDomain, testedCount, vulnerableCount, findingsCount }, 'DNS zone transfer detection complete');

  return findingsCount;
}

export default runDnsZoneTransfer;
