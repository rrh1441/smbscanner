/**
 * Lightweight Backend Scanner - Fast JS-only backend detection
 *
 * Skips full endpoint discovery and just fetches common JS bundles
 * to extract backend identifiers (Firebase, Supabase, Vercel, etc.)
 *
 * Target: <5 seconds per scan
 */

import { httpRequest } from '../net/httpClient.js';
import { insertArtifact } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('lightweightBackendScan');

interface BackendIdentifier {
  provider: string;
  id: string;
  raw: string;
  src: { file: string; line: number };
}

// Backend detection patterns (from endpointDiscovery.ts)
const BACKEND_PATTERNS: Record<string, RegExp> = {
  firebaseHost: /([a-z0-9-]+)\.firebaseio\.com/gi,
  firebasePID: /firebase[_-]?project[_-]?id["\s:=]+["']?([a-z0-9-]+)["']?/gi,
  supabaseHost: /([a-z0-9]+)\.supabase\.co/gi,
  s3Host: /([\w.-]+)\.s3\.amazonaws\.com/gi,
  s3Path: /s3\.amazonaws\.com\/([\w.-]+)/gi,
  planetscaleHost: /([a-z0-9-]+)\.aws\.connect\.psdb\.cloud/gi,
  planetscalePw: /pscale_pw_[a-zA-Z0-9_-]+/gi,
  neonHost: /([a-z0-9-]+)\.(?:[a-z0-9-]+\.)?aws\.neon\.tech/gi,
  tursoHost: /([a-z0-9-]+)\.turso\.io/gi,
  tursoLibsql: /libsql:\/\/([a-z0-9-]+)\.turso\.io/gi,
  xataHost: /([a-z0-9-]+)\.xata\.sh/gi,
  xataApi: /https:\/\/([a-z0-9-]+)\.xata\.sh\/db/gi,
  convexHost: /([a-z0-9-]+)\.convex\.cloud/gi,
  convexDeploy: /https:\/\/([a-z0-9-]+)\.convex\.cloud/gi,
  railwayHost: /([a-z0-9-]+)\.railway\.app/gi,
  vercelPostgres: /([a-z0-9-]+)-pooler\.(?:[a-z0-9-]+\.)?postgres\.vercel-storage\.com/gi,
  vercelKV: /VERCEL_KV_REST_API_URL|KV_REST_API_URL/gi,
  upstashRedis: /([a-z0-9-]+)\.upstash\.io/gi,
  upstashToken: /UPSTASH_REDIS_REST_TOKEN|UPSTASH_REDIS_REST_URL/gi,
};

const PROVIDER_MAP: Record<string, string> = {
  firebaseHost: 'firebase', firebasePID: 'firebase',
  supabaseHost: 'supabase',
  s3Host: 's3', s3Path: 's3',
  planetscaleHost: 'planetscale', planetscalePw: 'planetscale',
  neonHost: 'neon',
  tursoHost: 'turso', tursoLibsql: 'turso',
  xataHost: 'xata', xataApi: 'xata',
  convexHost: 'convex', convexDeploy: 'convex',
  railwayHost: 'railway',
  vercelPostgres: 'vercel-postgres',
  vercelKV: 'vercel-kv',
  upstashRedis: 'upstash', upstashToken: 'upstash',
};

// Common JS bundle paths to check (ordered by likelihood)
const COMMON_JS_PATHS = [
  '/',  // HTML page itself
  '/main.js',
  '/app.js',
  '/bundle.js',
  '/vendor.js',
  '/_next/static/chunks/pages/_app.js',
  '/_next/static/chunks/main.js',
  '/static/js/main.js',
  '/static/js/bundle.js',
  '/assets/index.js',
  '/assets/main.js',
  '/dist/main.js',
  '/dist/bundle.js',
  '/build/main.js',
  '/js/app.js',
  '/js/main.js',
];

async function fetchContent(url: string): Promise<string | null> {
  try {
    const response = await httpRequest({
      url,
      method: 'GET',
      totalTimeoutMs: 5000,
      maxRedirects: 2,
    });

    if (response.status === 200 && response.body) {
      // Convert Uint8Array to string and limit to 2MB
      const bodyStr = Buffer.from(response.body).toString('utf-8');
      return bodyStr.substring(0, 2 * 1024 * 1024);
    }
  } catch (err) {
    // Silent fail - many paths won't exist
  }
  return null;
}

function extractBackends(content: string, sourcePath: string): BackendIdentifier[] {
  const backends: BackendIdentifier[] = [];
  const seen = new Set<string>();

  for (const [patternName, regex] of Object.entries(BACKEND_PATTERNS)) {
    const provider = PROVIDER_MAP[patternName];
    if (!provider) continue;

    const matches = content.matchAll(regex);

    for (const match of matches) {
      const id = match[1] || match[0];
      const raw = match[0];
      const key = `${provider}:${id}`;

      if (!seen.has(key)) {
        seen.add(key);
        backends.push({
          provider,
          id,
          raw,
          src: { file: sourcePath, line: 0 }
        });
      }
    }
  }

  return backends;
}

export async function runLightweightBackendScan(opts: {
  domain: string;
  scanId: string;
}): Promise<number> {
  const { domain, scanId } = opts;
  const startTime = Date.now();

  log.info({ domain, scanId }, 'Starting backend scan');

  const baseUrl = domain.startsWith('http') ? domain : `https://${domain}`;
  const allBackends: BackendIdentifier[] = [];
  let fetchedCount = 0;

  // Quick check: fetch up to 5 common paths
  for (const path of COMMON_JS_PATHS.slice(0, 5)) {
    const url = path === '/' ? baseUrl : `${baseUrl}${path}`;
    const content = await fetchContent(url);

    if (content) {
      fetchedCount++;
      const backends = extractBackends(content, path);
      allBackends.push(...backends);

      // Early exit if we found backends
      if (backends.length > 0) {
        log.info({ backendsFound: backends.length, path }, 'Found backends, stopping early');
        break;
      }
    }

    // Small delay between requests
    await new Promise(resolve => setTimeout(resolve, 100));
  }

  // Dedupe
  const uniqueBackends = Array.from(
    new Map(allBackends.map(b => [`${b.provider}:${b.id}`, b])).values()
  );

  // Save artifact
  if (uniqueBackends.length > 0) {
    await insertArtifact({
      type: 'backend_identifiers',
      severity: 'INFO',
      val_text: `Identified ${uniqueBackends.length} backend IDs`,
      meta: {
        scan_id: scanId,
        scan_module: 'lightweightBackendScan',
        backend_ids: uniqueBackends
      }
    });
  }

  const duration = Date.now() - startTime;
  log.info({ durationMs: duration, backendsFound: uniqueBackends.length, pathsFetched: fetchedCount }, 'Scan completed');

  return uniqueBackends.length;
}
