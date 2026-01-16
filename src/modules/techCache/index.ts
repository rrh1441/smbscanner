/**
 * Technology Cache - Simple in-memory cache for tech detection results
 */

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const cache = new Map<string, CacheEntry<any>>();
const DEFAULT_TTL = 3600000; // 1 hour

export function get<T>(key: string): T | undefined {
  const entry = cache.get(key);
  if (!entry) return undefined;

  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return undefined;
  }

  return entry.value as T;
}

export function set<T>(key: string, value: T, ttl: number = DEFAULT_TTL): void {
  cache.set(key, {
    value,
    expiresAt: Date.now() + ttl
  });
}

export function has(key: string): boolean {
  const entry = cache.get(key);
  if (!entry) return false;

  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return false;
  }

  return true;
}

export function del(key: string): boolean {
  return cache.delete(key);
}

export function clear(): void {
  cache.clear();
}

export function size(): number {
  return cache.size;
}

// UnifiedCache class for compatibility
export class UnifiedCache<T = any> {
  private prefix: string;
  private ttl: number;

  constructor(prefix: string = '', ttl: number = DEFAULT_TTL) {
    this.prefix = prefix;
    this.ttl = ttl;
  }

  private makeKey(key: string): string {
    return this.prefix ? `${this.prefix}:${key}` : key;
  }

  get(key: string): T | undefined {
    return get<T>(this.makeKey(key));
  }

  set(key: string, value: T, ttl?: number): void {
    set(this.makeKey(key), value, ttl || this.ttl);
  }

  has(key: string): boolean {
    return has(this.makeKey(key));
  }

  delete(key: string): boolean {
    return del(this.makeKey(key));
  }

  clear(): void {
    // Only clear entries with this prefix
    for (const key of cache.keys()) {
      if (!this.prefix || key.startsWith(this.prefix)) {
        cache.delete(key);
      }
    }
  }
}

export default { get, set, has, del, clear, size, UnifiedCache };
