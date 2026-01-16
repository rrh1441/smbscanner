/* =============================================================================
 * MODULE: wpPluginQuickScan.ts
 * =============================================================================
 * Ultra-fast, passive WordPress plugin enumerator for Tier-1 scans.
 * - Runs only if WordPress is detected (via artifacts) or quick page heuristics
 * - Parses homepage HTML for /wp-content/plugins/<slug>/ asset references
 * - Attempts lightweight version resolution via ?ver= query and readme.txt
 * - Writes a single inventory artifact; no nuclei invocation
 * =============================================================================
 */

import { insertArtifact } from '../core/artifactStore.js';
import { httpClient } from '../net/httpClient.js';
import { createModuleLogger } from '../core/logger.js';
import { Severity } from '../core/types.js';

const log = createModuleLogger('wpPluginQuickScan');

interface RunJob {
  domain: string;
  scanId: string;
}

interface DetectedPlugin {
  slug: string;
  versions: Set<string>; // collected from asset query params or readme
  evidence: Set<string>; // sample URLs or markers
  confirmedViaReadme?: boolean;
}

function buildTargets(domain: string): string[] {
  // Accept host or host:port
  const host = domain.trim();
  const bare = host.replace(/^https?:\/\//i, '');

  // For localhost/127.0.0.1, prefer HTTP first (HTTPS rarely works on localhost)
  const isLocalhost = /^(localhost|127\.0\.0\.1|::1)/i.test(bare);
  const schemes = isLocalhost ? ['http', 'https'] : ['https', 'http'];

  // Don't add www. to localhost or IP addresses
  const isIpOrLocalhost = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|127\.0\.0\.1|::1)/i.test(bare.split(':')[0]);
  const withWww = (!isIpOrLocalhost && !bare.includes(':')) ? `www.${bare}` : null;

  // Common subpaths (env override)
  const envPaths = (process.env.WPQS_SUBPATHS || '').split(',').map(s => s.trim()).filter(Boolean);
  const defaultPaths = ['/', '/blog', '/news', '/wp', '/site', '/en', '/press', '/fr', '/de', '/es', '/it'];
  const paths = envPaths.length ? ['/', ...envPaths] : defaultPaths;

  const candidates: string[] = [];
  for (const scheme of schemes) {
    const hosts = withWww ? [bare, withWww] : [bare];
    for (const h of hosts) {
      const origin = `${scheme}://${h}`;
      for (const p of paths) {
        const url = p === '/' ? origin : `${origin}${p}`;
        candidates.push(url);
      }
    }
  }
  return Array.from(new Set(candidates)).slice(0, 16);
}

function isLikelyWordPressFromHtml(html: string, headers?: any): boolean {
  const h = html.toLowerCase();
  if (h.includes('wp-content') || h.includes('wp-includes')) return true;
  if (h.includes('name="generator"') && h.includes('wordpress')) return true;
  if (headers) {
    try {
      const xp = (typeof headers.get === 'function')
        ? headers.get('x-pingback')
        : (headers['x-pingback'] || headers['X-Pingback']);
      if (xp && String(xp).length > 0) return true;
    } catch { /* ignore */ }
  }
  return false;
}

function extractPluginsFromHtml(html: string): Map<string, DetectedPlugin> {
  const results = new Map<string, DetectedPlugin>();
  const lower = html.toLowerCase();

  // Match /wp-content/plugins/<slug>/... optionally with query parameters
  const re = /\/wp-content\/plugins\/([a-z0-9._-]+)\/[^\s"'<>]+/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(lower)) !== null) {
    const slug = m[1];
    const url = m[0];
    const qp = url.split('?')[1] || '';
    const verMatch = /(?:^|&)(?:ver|version)=([a-z0-9._-]+)/i.exec(qp);
    const version = verMatch?.[1];

    if (!results.has(slug)) {
      results.set(slug, { slug, versions: new Set<string>(), evidence: new Set<string>() });
    }
    const entry = results.get(slug)!;
    if (version) entry.versions.add(version);
    // keep a small set of evidence URLs
    if (entry.evidence.size < 3) entry.evidence.add(url);
  }
  return results;
}

function pickBestVersion(versions: Set<string>): string | undefined {
  if (versions.size === 0) return undefined;
  // Naive best-effort: prefer the longest/most specific version string
  return Array.from(versions).sort((a, b) => b.length - a.length)[0];
}

async function tryReadmeVersion(baseUrl: string, slug: string): Promise<string | undefined> {
  const candidates = [
    `/wp-content/plugins/${slug}/readme.txt`,
  ];
  for (const path of candidates) {
    try {
      const url = `${baseUrl}${path}`;
      const res = await httpClient.get<string>(url, {
        timeout: 1200,
        responseType: 'text'
      } as any);
      if (res.status === 200 && typeof res.data === 'string') {
        const text = res.data;
        // Parse common markers
        const stable = /Stable\s*tag\s*:\s*([\w.-]+)/i.exec(text)?.[1];
        const version = stable || /Version\s*:\s*([\w.-]+)/i.exec(text)?.[1];
        if (version) return version.trim();
      }
    } catch { /* ignore for speed */ }
  }
  return undefined;
}

async function fetchText(url: string, timeoutMs = 3500): Promise<{ html?: string; headers?: any; status: number }> {
  try {
    const r = await httpClient.get<string>(url, { timeout: timeoutMs, responseType: 'text', maxRedirects: 3 } as any);
    return { html: typeof r.data === 'string' ? r.data : undefined, headers: r.headers as any, status: r.status };
  } catch (error) {
    return { status: 0 };
  }
}

export async function runWpPluginQuickScan(job: RunJob): Promise<number> {
  const { domain, scanId } = job;
  const start = Date.now();
  log.info(`START scan_id=${scanId} domain=${domain}`);

  // Build small set of targets
  const targets = buildTargets(domain);

  // Determine if WordPress is present quickly across candidates
  let wpBase: string | null = null;
  log.info(`Checking ${targets.length} target URLs for WordPress markers...`);
  for (const candidate of targets) {
    const res = await fetchText(candidate, 3000);
    if (res.html && isLikelyWordPressFromHtml(res.html, res.headers)) {
      wpBase = candidate;
      log.info(`✓ WordPress detected at: ${wpBase}`);
      break;
    }
  }

  if (!wpBase) {
    // Soft exit for speed – no WP markers
    log.info(`No WordPress markers found; skipping. scan_id=${scanId}`);
    log.info(`Tried ${targets.length} URLs: ${targets.slice(0, 5).join(', ')}${targets.length > 5 ? '...' : ''}`);
    return 0;
  }

  // Enumerate plugins from the first WP base (and optionally next one)
  const pluginMap = new Map<string, DetectedPlugin>();
  log.info(`Parsing HTML for plugin asset references...`);
  for (const base of [wpBase, ...targets.filter(t => t !== wpBase)].slice(0, 2)) {
    const res = await fetchText(base, 4000);
    if (!res.html) continue;
    const found = extractPluginsFromHtml(res.html);
    if (found.size > 0) {
      log.info(`Found ${found.size} plugin(s) in HTML from ${base}`);
    }
    for (const [slug, info] of found) {
      if (!pluginMap.has(slug)) {
        pluginMap.set(slug, { slug, versions: new Set<string>(), evidence: new Set<string>() });
      }
      const dst = pluginMap.get(slug)!;
      info.versions.forEach(v => dst.versions.add(v));
      info.evidence.forEach(e => dst.evidence.add(e));
    }
  }

  if (pluginMap.size === 0) {
    log.info(`⚠ No plugin assets found in HTML - will check common plugins via readme.txt`);
  } else {
    log.info(`Total unique plugins from HTML: ${pluginMap.size}`);
  }

  // Resolve versions via readme.txt (cap for speed)
  const MAX_README_CHECKS = 10;
  let checks = 0;
  for (const [slug, info] of pluginMap) {
    if (checks >= MAX_README_CHECKS) break;
    if (pickBestVersion(info.versions)) continue; // already have version hint
    const baseForReadme = new URL(wpBase).origin; // use origin for readme fetch
    const ver = await tryReadmeVersion(baseForReadme, slug);
    if (ver) {
      info.versions.add(ver);
      info.confirmedViaReadme = true;
    }
    checks++;
  }

  // Opportunistic readme checks for common plugins not seen in HTML
  const envPlugins = (process.env.WPQS_FORCE_CHECK_PLUGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const COMMON_PLUGINS = envPlugins.length > 0 ? envPlugins : ['elementor', 'jetpack', 'woocommerce', 'contact-form-7', 'yoast-seo', 'wpforms-lite'];
  const baseOrigin = new URL(wpBase).origin;

  log.info(`Checking for common plugins: ${COMMON_PLUGINS.join(', ')}`);

  for (const slug of COMMON_PLUGINS) {
    if (pluginMap.has(slug)) {
      log.info(`  ${slug}: already found in HTML`);
      continue;
    }
    if (checks >= MAX_README_CHECKS) {
      log.info(`  Reached max readme checks (${MAX_README_CHECKS}), stopping`);
      break;
    }
    try {
      const ver = await tryReadmeVersion(baseOrigin, slug);
      if (ver) {
        log.info(`  ${slug}: found via readme.txt (v${ver})`);
        const entry: DetectedPlugin = { slug, versions: new Set([ver]), evidence: new Set([`/wp-content/plugins/${slug}/readme.txt`]), confirmedViaReadme: true };
        pluginMap.set(slug, entry);
      } else {
        log.info(`  ${slug}: readme.txt not accessible or no version found`);
      }
    } catch (e: any) {
      log.info(`  ${slug}: error checking readme - ${e.message}`);
    }
    checks++;
  }

  const plugins = Array.from(pluginMap.values()).map(p => ({
    slug: p.slug,
    version: pickBestVersion(p.versions),
    evidence: Array.from(p.evidence),
    confirmed_via_readme: Boolean(p.confirmedViaReadme)
  }));

  // Write inventory artifact (INFO)
  await insertArtifact({
    type: 'wordpress_plugin_inventory',
    val_text: `Detected ${plugins.length} plugin(s)`,
    severity: 'INFO' as Severity,
    meta: {
      scan_id: scanId,
      scan_module: 'wpPluginQuickScan',
      domain,
      targets,
      wp_base: wpBase,
      plugins,
      duration_ms: Date.now() - start
    }
  });

  log.info(`COMPLETE plugins=${plugins.length} duration_ms=${Date.now() - start} scan_id=${scanId}`);
  return plugins.length;
}

export default { runWpPluginQuickScan };
