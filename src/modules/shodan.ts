/*
 * =============================================================================
 * MODULE: shodan.ts  (Hardened v2.1 — compile-clean)
 * =============================================================================
 * Queries the Shodan REST API for exposed services and vulnerabilities
 * associated with a target domain and discovered sub-targets.  
 *
 * Key features
 *   • Built-in rate-limit guard (configurable RPS) and exponential back-off
 *   • Pagination (PAGE_LIMIT pages per query) and target-set cap (TARGET_LIMIT)
 *   • CVSS-aware severity escalation and contextual recommendations
 *   • All findings persisted through insertArtifact / insertFinding
 *   • Lint-clean & strict-mode TypeScript
 * =============================================================================
 */

import { request } from 'undici';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('shodan');
import { resolveDomain } from '../util/dnsResolver.js';

/* -------------------------------------------------------------------------- */
/*  Configuration                                                              */
/* -------------------------------------------------------------------------- */

// Lazy-load API key at runtime to ensure dotenv has initialized
const getApiKey = () => process.env.SHODAN_API_KEY ?? '';

const RPS          = Number.parseInt(process.env.SHODAN_RPS ?? '1', 10);       // reqs / second
const PAGE_LIMIT   = Number.parseInt(process.env.SHODAN_PAGE_LIMIT ?? '10', 10);
const TARGET_LIMIT = Number.parseInt(process.env.SHODAN_TARGET_LIMIT ?? '100', 10);

const SEARCH_BASE = 'https://api.shodan.io/shodan/host/search';

// Simple in-memory 30-day cache (clears per process)
const cache = new Map<string, { ts: number; data: any }>();

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

interface ShodanMatch {
  ip_str: string;
  port: number;
  location?: { country_name?: string; city?: string };
  org?: string;
  isp?: string;
  product?: string;
  version?: string;
  vulns?: Record<string, { cvss?: number }>;
  ssl?: { cert?: { expired?: boolean } };
  hostnames?: string[];
}

interface ShodanResponse {
  matches: ShodanMatch[];
  total: number;
}

/* -------------------------------------------------------------------------- */
/*  Severity helpers                                                           */
/* -------------------------------------------------------------------------- */

const PORT_RISK: Record<number, 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = {
  21:  'MEDIUM',
  22:  'MEDIUM',
  23:  'HIGH',
  25:  'LOW',
  53:  'LOW',
  80:  'LOW',
  110: 'LOW',
  135: 'HIGH',
  139: 'HIGH',
  445: 'HIGH',
  502: 'CRITICAL',  // Modbus TCP
  1433:'CRITICAL',  // MSSQL - direct database access
  1883:'CRITICAL',  // MQTT
  3306:'CRITICAL',  // MySQL - direct database access
  3389:'CRITICAL',  // RDP - ransomware entry point (90% of ransomware uses RDP)
  5432:'CRITICAL',  // PostgreSQL - direct database access
  5900:'HIGH',      // VNC - remote GUI access
  6379:'CRITICAL',  // Redis - often no auth by default
  9200:'CRITICAL',  // Elasticsearch - often no auth by default
  27017:'CRITICAL', // MongoDB - often no auth by default
  20000:'CRITICAL', // DNP3
  47808:'CRITICAL', // BACnet
};

/* -------------------------------------------------------------------------- */
/*  Specific finding type mapping for high-value exposures                     */
/* -------------------------------------------------------------------------- */

interface SpecificFindingType {
  type: string;
  title: string;
  recommendation: string;
}

/**
 * VPN/Firewall product patterns for detecting exposed admin interfaces.
 * Coalition data: Cisco ASA = 5x claims, Fortinet = 2x claims, exposed VPN = 58% ransomware entry
 */
const VPN_FIREWALL_PATTERNS: Array<{ pattern: RegExp; vendor: string; product: string }> = [
  // Fortinet FortiGate - 2x claims increase per Coalition
  { pattern: /fortigate|fortios|fortissl/i, vendor: 'Fortinet', product: 'FortiGate' },
  { pattern: /fortinet/i, vendor: 'Fortinet', product: 'FortiGate' },

  // Cisco ASA - 5x claims increase per Coalition
  { pattern: /cisco.*asa|adaptive security appliance/i, vendor: 'Cisco', product: 'ASA' },
  { pattern: /asdm/i, vendor: 'Cisco', product: 'ASA ASDM' },

  // SonicWall - common SMB firewall
  { pattern: /sonicwall|sonic.*wall/i, vendor: 'SonicWall', product: 'Firewall' },

  // Palo Alto GlobalProtect
  { pattern: /globalprotect|palo.*alto/i, vendor: 'Palo Alto', product: 'GlobalProtect' },

  // Pulse Secure / Ivanti
  { pattern: /pulse.*secure|ivanti.*connect/i, vendor: 'Pulse Secure', product: 'VPN' },

  // Citrix Gateway/NetScaler
  { pattern: /citrix.*gateway|netscaler/i, vendor: 'Citrix', product: 'Gateway' },

  // OpenVPN Access Server
  { pattern: /openvpn.*access|openvpn.*as/i, vendor: 'OpenVPN', product: 'Access Server' },

  // WatchGuard
  { pattern: /watchguard/i, vendor: 'WatchGuard', product: 'Firewall' },

  // Juniper SRX/SSL VPN
  { pattern: /juniper.*srx|junos|juniper.*ssl/i, vendor: 'Juniper', product: 'SRX' },

  // Zyxel
  { pattern: /zyxel|zywall/i, vendor: 'Zyxel', product: 'Firewall' },
];

/**
 * Check if product string matches a VPN/Firewall admin interface.
 */
function matchVPNFirewall(product?: string, banner?: string): { vendor: string; product: string } | null {
  const searchText = `${product || ''} ${banner || ''}`.toLowerCase();

  for (const vpn of VPN_FIREWALL_PATTERNS) {
    if (vpn.pattern.test(searchText)) {
      return { vendor: vpn.vendor, product: vpn.product };
    }
  }
  return null;
}

/**
 * Maps specific ports to detailed finding types for higher EAL multipliers.
 * Returns null for ports that should use generic EXPOSED_SERVICE.
 */
function getSpecificFindingType(port: number, product?: string): SpecificFindingType | null {
  // VPN/Firewall Admin Interfaces - CRITICAL (58% of ransomware starts here)
  // Check product field for VPN/Firewall signatures
  const vpnMatch = matchVPNFirewall(product);
  if (vpnMatch) {
    return {
      type: 'EXPOSED_VPN_ADMIN',
      title: `${vpnMatch.vendor} ${vpnMatch.product} admin interface exposed`,
      recommendation: `CRITICAL: ${vpnMatch.vendor} ${vpnMatch.product} admin interface is exposed to the internet. 58% of ransomware attacks start from compromised VPN/firewall devices. Restrict admin access to internal networks only, enable MFA, and ensure firmware is up to date.`
    };
  }

  // Remote Access - CRITICAL (ransomware entry points)
  if (port === 3389) {
    return {
      type: 'EXPOSED_RDP',
      title: 'RDP exposed to internet',
      recommendation: 'CRITICAL: Disable public RDP access immediately. RDP is abused in 90% of ransomware attacks. Use a VPN or zero-trust solution (e.g., Cloudflare Access, Tailscale) for remote access.'
    };
  }

  if (port === 5900 || port === 5901) {
    return {
      type: 'EXPOSED_VNC',
      title: 'VNC exposed to internet',
      recommendation: 'Disable public VNC access. Use SSH tunneling or VPN for remote desktop. VNC provides direct GUI access to systems.'
    };
  }

  // Databases - CRITICAL (direct data access)
  const DB_TYPE_MAP: Record<number, { name: string; type: string; auth_note: string }> = {
    3306:  { name: 'MySQL',         type: 'EXPOSED_DATABASE_MYSQL',         auth_note: '' },
    5432:  { name: 'PostgreSQL',    type: 'EXPOSED_DATABASE_POSTGRES',      auth_note: '' },
    1433:  { name: 'MS SQL Server', type: 'EXPOSED_DATABASE_MSSQL',         auth_note: '' },
    27017: { name: 'MongoDB',       type: 'EXPOSED_DATABASE_MONGODB',       auth_note: ' MongoDB often runs without authentication by default.' },
    6379:  { name: 'Redis',         type: 'EXPOSED_DATABASE_REDIS',         auth_note: ' Redis often runs without authentication by default.' },
    9200:  { name: 'Elasticsearch', type: 'EXPOSED_DATABASE_ELASTICSEARCH', auth_note: ' Elasticsearch often runs without authentication by default.' },
    9300:  { name: 'Elasticsearch', type: 'EXPOSED_DATABASE_ELASTICSEARCH', auth_note: ' Elasticsearch cluster port - internal communication exposed.' },
    5984:  { name: 'CouchDB',       type: 'EXPOSED_DATABASE_COUCHDB',       auth_note: '' },
    11211: { name: 'Memcached',     type: 'EXPOSED_DATABASE_MEMCACHED',     auth_note: ' Memcached has no authentication - all data is accessible.' },
  };

  const dbInfo = DB_TYPE_MAP[port];
  if (dbInfo) {
    return {
      type: dbInfo.type,
      title: `${dbInfo.name} database exposed to internet`,
      recommendation: `CRITICAL: Never expose database ports to the internet. Restrict ${dbInfo.name} (port ${port}) to internal networks only. Use firewall rules to block external access.${dbInfo.auth_note}`
    };
  }

  return null;
}

type Sev = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

const cvssToSeverity = (s?: number): Sev => {
  if (s === undefined) return 'INFO';
  if (s >= 9) return 'CRITICAL';
  if (s >= 7) return 'HIGH';
  if (s >= 4) return 'MEDIUM';
  return 'LOW';
};

/* -------------------------------------------------------------------------- */
/*  Rate-limited fetch with retry                                              */
/* -------------------------------------------------------------------------- */

const tsQueue: number[] = [];

let apiCallsCount = 0;

async function rlFetch<T>(url: string, attempt = 0): Promise<T> {
  const now = Date.now();
  while (tsQueue.length && now - tsQueue[0] > 1_000) tsQueue.shift();
  if (tsQueue.length >= RPS) {
    await new Promise((r) => setTimeout(r, 1_000 - (now - tsQueue[0])));
  }
  tsQueue.push(Date.now());

  try {
    const { body, statusCode } = await request(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'DealBrief-Scanner/1.0 (+https://dealbrief.com)'
      },
    });

    if (statusCode === 403) throw new Error('HTTP 403 rate limited');
    if (statusCode >= 500) throw new Error(`Upstream error ${statusCode}`);

    const data = (await body.json()) as T;
    apiCallsCount++;
    log.info(`[Shodan] API call ${apiCallsCount}`);
    return data;
  } catch (err) {
    const retriable =
      (err as any).code === 'ECONNABORTED' || /Upstream/.test((err as Error).message);
    if (retriable && attempt < 3) {
      const backoff = 500 * 2 ** attempt;
      await new Promise((r) => setTimeout(r, backoff));
      return rlFetch<T>(url, attempt + 1);
    }
    throw err;
  }
}

/* -------------------------------------------------------------------------- */
/*  Recommendation text                                                        */
/* -------------------------------------------------------------------------- */

function buildRecommendation(
  port: number,
  finding: string,
  product: string,
  version: string,
): string {
  if (finding.startsWith('CVE-')) {
    return `Patch ${product || 'service'} ${version || ''} immediately to remediate ${finding}.`;
  }
  if (finding === 'Expired SSL certificate') {
    return 'Renew the TLS certificate and configure automated renewal.';
  }
  switch (port) {
    case 3389:
      return 'Secure RDP with VPN or gateway and enforce MFA.';
    case 445:
    case 139:
      return 'Block SMB/NetBIOS from the Internet; use VPN.';
    case 23:
      return 'Disable Telnet; migrate to SSH.';
    case 5900:
      return 'Avoid exposing VNC publicly; tunnel through SSH or VPN.';
    case 502:
      return 'CRITICAL: Modbus TCP exposed to internet. Isolate OT networks behind firewall/VPN immediately.';
    case 1883:
      return 'CRITICAL: MQTT broker exposed to internet. Implement authentication and network isolation.';
    case 20000:
      return 'CRITICAL: DNP3 protocol exposed to internet. Air-gap industrial control systems immediately.';
    case 47808:
      return 'CRITICAL: BACnet exposed to internet. Isolate building automation systems behind firewall.';
    default:
      return 'Restrict public access and apply latest security hardening guides.';
  }
}

/* -------------------------------------------------------------------------- */
/*  Persist a single Shodan match                                              */
/* -------------------------------------------------------------------------- */

async function persistMatch(
  m: ShodanMatch,
  scanId: string,
  searchTarget: string,
): Promise<number> {
  let inserted = 0;

  /* --- baseline severity ------------------------------------------------- */
  let sev: Sev = (PORT_RISK[m.port] ?? 'INFO') as Sev;
  const findings: string[] = [];

  /* --- ICS/OT protocol detection ----------------------------------------- */
  const ICS_PORTS = [502, 1883, 20000, 47808];
  const ICS_PRODUCTS = ['modbus', 'mqtt', 'bacnet', 'dnp3', 'scada'];
  
  let isICSProtocol = false;
  if (ICS_PORTS.includes(m.port)) {
    isICSProtocol = true;
    sev = 'CRITICAL';
  }
  
  // Check product field for ICS indicators
  const productLower = (m.product ?? '').toLowerCase();
  if (ICS_PRODUCTS.some(ics => productLower.includes(ics))) {
    isICSProtocol = true;
    if (sev === 'INFO') sev = 'CRITICAL';
  }

  /* --- VPN/Firewall admin interface detection ----------------------------- */
  // Coalition data: 58% of ransomware starts from compromised VPN/firewall
  const vpnMatch = matchVPNFirewall(m.product);
  if (vpnMatch) {
    sev = 'CRITICAL'; // Always CRITICAL for exposed VPN/Firewall admin
  }

  if (m.ssl?.cert?.expired) {
    findings.push('Expired SSL certificate');
    if (sev === 'INFO') sev = 'LOW';
  }

  // CVE processing removed - handled by techStackScan module

  const artId = await insertArtifact({
    type: 'shodan_service',
    val_text: `${m.ip_str}:${m.port} ${m.product ?? ''} ${m.version ?? ''}`.trim(),
    severity: sev,
    src_url: `https://www.shodan.io/host/${m.ip_str}`,
    meta: {
      scan_id: scanId,
      search_term: searchTarget,
      ip: m.ip_str,
      port: m.port,
      product: m.product,
      version: m.version,
      hostnames: m.hostnames ?? [],
      location: m.location,
      org: m.org,
      isp: m.isp,
    },
  });
  inserted += 1;

  // Use actionability filter to determine if we should create a finding
  const shouldCreateFinding = isActionableService(m) ||
                             isICSProtocol ||
                             findings.length > 0; // Has specific security issues (expired cert, etc.)

  if (shouldCreateFinding) {
    // Check for specific finding type (RDP, VNC, databases) for higher EAL multipliers
    const specificFinding = getSpecificFindingType(m.port, m.product);

    if (specificFinding) {
      // Use specific finding type with tailored recommendation
      await insertFinding({
        scan_id: scanId,
        type: specificFinding.type,
        severity: sev,
        title: specificFinding.title,
        description: specificFinding.recommendation,
        data: {
          artifact_id: artId,
          port: m.port,
          product: m.product,
          version: m.version,
          ip: m.ip_str,
          hostnames: m.hostnames ?? []
        }
      });
      inserted += 1;
    } else if (isICSProtocol) {
      // ICS/OT protocols get their own finding type
      await insertFinding({
        scan_id: scanId,
        type: 'OT_PROTOCOL_EXPOSED',
        severity: sev,
        title: `Industrial control protocol exposed on port ${m.port}`,
        description: buildRecommendation(m.port, `ICS protocol on port ${m.port}`, m.product ?? '', m.version ?? ''),
        data: {
          artifact_id: artId,
          port: m.port,
          product: m.product,
          version: m.version,
          ip: m.ip_str
        }
      });
      inserted += 1;
    } else {
      // Generic exposed service for other actionable services
      const title = findings.length > 0 ? findings[0] : `Exposed service on port ${m.port}`;
      await insertFinding({
        scan_id: scanId,
        type: 'EXPOSED_SERVICE',
        severity: sev,
        title: title,
        description: buildRecommendation(m.port, title, m.product ?? '', m.version ?? ''),
        data: {
          artifact_id: artId,
          port: m.port,
          product: m.product,
          version: m.version,
          ip: m.ip_str
        }
      });
      inserted += 1;
    }
  }
  return inserted;
}

/* -------------------------------------------------------------------------- */
/*  Actionability filter (per shodanupdate.md)                                 */
/* -------------------------------------------------------------------------- */

/**
 * Determine if a Shodan match represents an actionable security finding.
 * Filters out generic web servers, CDN edges, and ambient infrastructure signals.
 */
function isActionableService(m: ShodanMatch): boolean {
  const port = m.port;
  const product = (m.product ?? '').toLowerCase();

  // VPN/Firewall admin interfaces - CRITICAL (58% ransomware entry point)
  if (matchVPNFirewall(m.product)) {
    return true;
  }

  // Always promote high-risk/admin services (RDP, VNC, SMB, ICS protocols)
  const HIGH_RISK_PORTS = [22, 23, 445, 139, 3389, 5900, 5901, 502, 1883, 20000, 47808];
  if (HIGH_RISK_PORTS.includes(port)) {
    return true;
  }

  // Promote exposed databases - all are CRITICAL
  const DB_PORTS = [3306, 5432, 6379, 9200, 9300, 27017, 1433, 5984, 11211];
  if (DB_PORTS.includes(port)) {
    return true;
  }

  // Promote if product has known vulnerabilities (has version evidence)
  if (m.version && m.version.length > 0) {
    return true;
  }

  // Promote if SSL certificate is expired
  if (m.ssl?.cert?.expired) {
    return true;
  }

  // Filter out generic web servers and CDN edges on common ports
  const COMMON_WEB_PORTS = [80, 443, 8080, 8443];
  if (COMMON_WEB_PORTS.includes(port)) {
    // Generic web servers (nginx/apache without version) are ambient noise
    const GENERIC_WEB_PRODUCTS = ['nginx', 'apache', 'http', 'https'];
    if (GENERIC_WEB_PRODUCTS.some(p => product.includes(p)) && !m.version) {
      return false; // Skip generic web server
    }

    // CDN/proxy services are usually ambient
    const CDN_INDICATORS = ['cloudflare', 'cloudfront', 'akamai', 'fastly'];
    if (CDN_INDICATORS.some(cdn => product.includes(cdn) || (m.org || '').toLowerCase().includes(cdn))) {
      return false; // Skip CDN edge
    }
  }

  // Filter out standard mail server ports (normal infrastructure, not vulnerabilities)
  const MAIL_PORTS = [25, 110, 143, 465, 587, 993, 995];
  if (MAIL_PORTS.includes(port)) {
    return false; // Skip normal mail infrastructure
  }

  // Filter out DNS servers
  if (port === 53) {
    return false; // Skip DNS (normal infrastructure)
  }

  // FTP on port 21 is worth flagging (legacy/insecure)
  if (port === 21) {
    return true;
  }

  // Non-standard ports (like 2222 for SSH) are worth investigating
  if (port > 1024 && port !== 8080 && port !== 8443) {
    return true;
  }

  // Default: skip everything else not explicitly flagged above
  return false;
}

/* -------------------------------------------------------------------------- */
/*  Main exported function                                                     */
/* -------------------------------------------------------------------------- */

export async function runShodanScan(job: {
  domain: string;
  scanId: string;
  companyName: string;
}): Promise<number> {
  const { domain, scanId, companyName } = job;

  // Check API key at runtime
  const API_KEY = getApiKey();
  if (!API_KEY) {
    log.info('[shodan] SHODAN_API_KEY not configured - skipping scan');
    return 0;
  }
  log.info(`[Shodan] Start scan for ${domain}`);

  /* Resolve DNS first (for IP-scoped and SSL queries) -------------------- */
  const dnsResult = await resolveDomain(domain);
  log.info(`[Shodan] Resolved ${dnsResult.ips.length} IPs for ${domain}`);

  if (dnsResult.ips.length === 0) {
    log.info(`[Shodan] No IPs resolved for ${domain} - skipping`);
    return 0;
  }

  /* Build queries using multi-pronged strategy ---------------------------- */
  const queries: Array<{ query: string; type: string; description: string }> = [];

  // High-risk ports to scan (from shodanupdate.md recommendation)
  const HIGH_RISK_PORTS = '22,3389,445,21,3306,5432,6379,9200,27017';

  // 1. IP-scoped queries (highest SNR)
  for (const ip of dnsResult.ips.slice(0, 5)) { // Limit to first 5 IPs to control API usage
    queries.push({
      query: `ip:${ip}`,
      type: 'ip',
      description: `IP scan for ${ip}`
    });

    // High-risk port scan for each IP
    queries.push({
      query: `ip:${ip} port:${HIGH_RISK_PORTS}`,
      type: 'ip_high_risk_ports',
      description: `High-risk ports on ${ip}`
    });
  }

  // 2. SSL certificate queries (good for finding related infrastructure)
  const bare = domain.replace(/^https?:\/\//i, '').split(':')[0].trim();
  queries.push({
    query: `ssl.cert.subject.CN:"${bare}"`,
    type: 'ssl_cert_cn',
    description: `SSL CN match for ${bare}`
  });
  queries.push({
    query: `ssl.cert.alt_names:"${bare}"`,
    type: 'ssl_cert_san',
    description: `SSL SAN match for ${bare}`
  });

  // 3. HTTP evidence (fallback, only if company name is distinctive)
  const isDistinctive = companyName && companyName.length > 5 && !companyName.match(/^(www|http|https)/i);
  if (isDistinctive) {
    queries.push({
      query: `http.title:"${companyName}"`,
      type: 'http_title',
      description: `HTTP title match for "${companyName}"`
    });
  }

  log.info(`[Shodan] Executing ${queries.length} query strategies`);

  let totalItems = 0;
  const seenServices = new Set<string>(); // Deduplication for similar services

  for (const queryDef of queries) {
    let fetched = 0;
    for (let page = 1; page <= Math.min(PAGE_LIMIT, 3); page += 1) { // Limit pages per query
      const q = encodeURIComponent(queryDef.query);
      const url = `${SEARCH_BASE}?key=${API_KEY}&query=${q}&page=${page}`;

      try {
        // eslint-disable-next-line no-await-in-loop
        const data = await rlFetch<ShodanResponse>(url);
        if (data.matches.length === 0) break;

        log.info(`[Shodan] ${queryDef.type}: found ${data.matches.length} matches (page ${page})`);

        for (const m of data.matches) {
          // Deduplicate similar services to prevent spam
          const serviceKey = `${m.ip_str}:${m.port}:${m.product || 'unknown'}`;
          if (seenServices.has(serviceKey)) {
            continue; // Skip duplicate service
          }
          seenServices.add(serviceKey);

          // Only promote actionable findings (not generic web servers on common ports)
          const isActionable = isActionableService(m);
          if (!isActionable) {
            log.info(`[Shodan] Skipping non-actionable: ${m.ip_str}:${m.port} ${m.product || 'unknown'}`);
            continue;
          }

          // eslint-disable-next-line no-await-in-loop
          totalItems += await persistMatch(m, scanId, `${queryDef.type}:${queryDef.description}`);
        }

        fetched += data.matches.length;
        if (fetched >= Math.min(data.total, 50)) break; // Cap results per query type
      } catch (err) {
        log.info(`[Shodan] ERROR for ${queryDef.type} (page ${page}): ${(err as Error).message}`);
        break; // next query
      }
    }
  }

  await insertArtifact({
    type: 'scan_summary',
    val_text: `Shodan scan: ${totalItems} services found, ${seenServices.size} unique after deduplication`,
    severity: 'INFO',
    meta: {
      scan_id: scanId,
      total_items: totalItems,
      unique_services: seenServices.size,
      api_calls_used: apiCallsCount,
      query_strategies: queries.length,
      resolved_ips: dnsResult.ips.length,
      timestamp: new Date().toISOString()
    },
  });

  log.info(`[Shodan] Done — ${totalItems} services found, ${seenServices.size} unique after deduplication, ${apiCallsCount} API calls across ${queries.length} query strategies`);
  return totalItems;
}

export default runShodanScan;
