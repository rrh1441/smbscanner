import { createClient, RedisClientType } from 'redis';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('resourceGovernor');

export interface ResourceLimit {
  name: string;
  limit: number;
  defaultTtlMs?: number;
}

export interface ResourceRequest {
  name: string;
  count?: number;
  ttlMs?: number;
}

export interface AcquireOptions {
  workerId: string;
  purpose?: string;
  metadata?: Record<string, unknown>;
  leaseTtlMs?: number;
  wait?: boolean;
  waitTimeoutMs?: number;
  retryDelayMs?: number;
  autoRenew?: boolean;
}

export interface ResourceLeaseInfo {
  id: string;
  resources: ResourceRequest[];
  workerId: string;
  expiresAt: number;
  metadata?: Record<string, unknown>;
}

export interface ResourceGovernorOptions {
  redisUrl?: string;
  redisDb?: number;
  redisHost?: string;
  redisPort?: number;
  resourceLimits: ResourceLimit[];
  defaultLeaseTtlMs?: number;
  sweepIntervalMs?: number;
}

interface ScriptDefinitions {
  acquireMany: string;
  release: string;
  renew: string;
  verify: string;
  sweepLease: string;
}

interface LeaseHeartbeat {
  leaseId: string;
  interval: NodeJS.Timeout;
}

const DEFAULT_RETRY_DELAY_MS = 250;
const DEFAULT_WAIT_TIMEOUT_MS = 30_000;
const DEFAULT_LEASE_TTL_MS = 30_000;
const LEASE_INDEX_KEY = 'resource:lease-index';
const LIMITS_KEY = 'resource:limits';
const USAGE_KEY = 'resource:usage';
const EPOCH_KEY = 'resource:epoch';
const RELEASE_CHANNEL = 'channel:resource:released';

function toResourceRequest(input: ResourceRequest): ResourceRequest {
  return {
    name: input.name,
    count: input.count ?? 1,
    ttlMs: input.ttlMs
  };
}

export class ManagedLease {
  private readonly governor: ResourceGovernor;
  private heartbeat?: LeaseHeartbeat;
  readonly id: string;
  readonly resources: ResourceRequest[];
  readonly workerId: string;
  expiresAt: number;
  metadata?: Record<string, unknown>;

  constructor(governor: ResourceGovernor, info: ResourceLeaseInfo) {
    this.governor = governor;
    this.id = info.id;
    this.resources = info.resources.map(toResourceRequest);
    this.workerId = info.workerId;
    this.expiresAt = info.expiresAt;
    this.metadata = info.metadata;
  }

  async renew(ttlMs?: number): Promise<boolean> {
    const next = await this.governor.renewLease(this.id, ttlMs);
    if (next) {
      this.expiresAt = next.expiresAt;
      this.metadata = next.metadata;
      return true;
    }
    return false;
  }

  startHeartbeat(ttlMs?: number, jitterMs: number = 200): void {
    const refreshTtl = ttlMs ?? Math.max(10_000, Math.floor((this.expiresAt - Date.now()) / 2));
    const refreshInterval = Math.max(3_000, Math.min(refreshTtl - 1_000, 10_000));
    const initialDelay = Math.floor(Math.random() * (refreshInterval + jitterMs));

    const runRenew = async () => {
      try {
        await this.renew(ttlMs);
      } catch (error) {
        log.error({ err: error }, 'Lease heartbeat failed');
      }
    };

    const interval = setInterval(runRenew, refreshInterval + Math.floor(Math.random() * jitterMs));
    (interval as unknown as { unref?: () => void }).unref?.();

    this.heartbeat = { leaseId: this.id, interval };

    const initialTimer = setTimeout(runRenew, initialDelay);
    (initialTimer as unknown as { unref?: () => void }).unref?.();
  }

  stopHeartbeat(): void {
    if (this.heartbeat) {
      clearInterval(this.heartbeat.interval);
      this.heartbeat = undefined;
    }
  }

  async release(): Promise<boolean> {
    this.stopHeartbeat();
    return this.governor.releaseLease(this.id);
  }
}

export class ResourceGovernor extends EventEmitter {
  private client?: RedisClientType;
  private subscriber?: RedisClientType;
  private scripts?: ScriptDefinitions;
  private sweepTimer?: NodeJS.Timeout;
  private initialized = false;
  private limits: Map<string, ResourceLimit> = new Map();

  async initialize(options: ResourceGovernorOptions): Promise<void> {
    if (this.initialized) return;

    const redisUrl = options.redisUrl ?? process.env.REDIS_URL;
    const redisHost = options.redisHost ?? process.env.REDIS_HOST ?? '127.0.0.1';
    const redisPort = options.redisPort ?? (process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT, 10) : 6379);
    const redisDb = options.redisDb ?? (process.env.REDIS_DB ? parseInt(process.env.REDIS_DB, 10) : 0);

    const baseConfig = redisUrl
      ? { url: redisUrl }
      : { socket: { host: redisHost, port: redisPort } };

    this.client = createClient({
      ...baseConfig,
      socket: {
        ...(baseConfig.socket ?? {}),
        reconnectStrategy: (retries) => Math.min(1000 * 2 ** retries, 5000)
      },
      database: redisDb,
      username: process.env.REDIS_USERNAME,
      password: process.env.REDIS_PASSWORD,
      name: 'resource-governor-client'
    });

    this.subscriber = createClient({
      ...baseConfig,
      socket: {
        ...(baseConfig.socket ?? {}),
        reconnectStrategy: (retries) => Math.min(1000 * 2 ** retries, 5000)
      },
      database: redisDb,
      username: process.env.REDIS_USERNAME,
      password: process.env.REDIS_PASSWORD,
      name: 'resource-governor-subscriber'
    });

    this.subscriber.on('error', (error) => {
      log.error({ err: error }, 'Subscriber error');
    });
    this.client.on('error', (error) => {
      log.error({ err: error }, 'Client error');
    });

    await Promise.all([this.client.connect(), this.subscriber.connect()]);

    // Enable keyspace notifications for expirations if possible
    try {
      await this.client.configSet('notify-keyspace-events', 'Ex');
    } catch (error) {
      log.warn({ err: error }, 'Unable to set keyspace notifications (requires admin privileges)');
    }

    await this.defineScripts();

    // Set resource limits
    for (const limit of options.resourceLimits) {
      if (limit.limit <= 0) continue;
      this.limits.set(limit.name, limit);
    }

    if (!this.limits.size) {
      log.warn('No resource limits configured. Governor will be inactive.');
    }

    if (this.client) {
      const pipeline = this.client.multi();
      for (const limit of this.limits.values()) {
        pipeline.hSet(LIMITS_KEY, limit.name, String(limit.limit));
      }
      pipeline.hSetNX(USAGE_KEY, '__init__', '0');
      pipeline.hDel(USAGE_KEY, '__init__');
      pipeline.setNX(EPOCH_KEY, '0');
      await pipeline.exec();
    }

    await this.subscriber?.pSubscribe('__keyevent@*__:expired', async (key) => {
      if (!key.startsWith('resource:lease:')) return;
      const leaseId = key.replace('resource:lease:', '');
      try {
        await this.handleLeaseExpiration(leaseId, 'expired');
      } catch (error) {
        log.error({ err: error }, 'Error handling lease expiration');
      }
    });

    const sweepIntervalMs = options.sweepIntervalMs ?? 30_000;
    this.sweepTimer = setInterval(() => {
      this.runSweep().catch((error) => {
        log.error({ err: error }, 'Periodic sweep failed');
      });
    }, sweepIntervalMs);
    this.sweepTimer.unref?.();

    this.initialized = true;
  }

  private async defineScripts(): Promise<void> {
    if (!this.client) throw new Error('ResourceGovernor client not available');

    const acquireMany = `
      local limitsKey = KEYS[1]
      local usageKey = KEYS[2]
      local epochKey = KEYS[3]
      local indexKey = KEYS[4]
      local now = tonumber(ARGV[1])
      local ttl = tonumber(ARGV[2])
      local leaseId = ARGV[3]
      local workerId = ARGV[4]
      local resourcesJson = ARGV[5]
      local metadataJson = ARGV[6]
      local resources = cjson.decode(resourcesJson)
      local metadata = {}
      if metadataJson and metadataJson ~= '' then
        metadata = cjson.decode(metadataJson)
      end

      local function pruneResource(resourceName)
        local leaseHashKey = 'resource:' .. resourceName .. ':leases'
        local cursor = '0'
        repeat
          local scanResult = redis.call('HSCAN', leaseHashKey, cursor, 'COUNT', 50)
          cursor = scanResult[1]
          local entries = scanResult[2]
          for i = 1, #entries, 2 do
            local existingLeaseId = entries[i]
            local payload = entries[i + 1]
            if payload then
              local lease = cjson.decode(payload)
              if lease.expires_at and tonumber(lease.expires_at) <= now then
                redis.call('HDEL', leaseHashKey, existingLeaseId)
                local decrement = tonumber(lease.count or 1)
                local newUsage = redis.call('HINCRBY', usageKey, resourceName, -decrement)
                if tonumber(newUsage) < 0 then
                  redis.call('HSET', usageKey, resourceName, 0)
                end
                redis.call('HDEL', indexKey, existingLeaseId)
              end
            end
          end
        until cursor == '0'
      end

      for i = 1, #resources do
        local res = resources[i]
        local name = res.name
        local count = tonumber(res.count or 1)
        pruneResource(name)
        local limit = redis.call('HGET', limitsKey, name)
        if not limit then
          return cjson.encode({ ok = false, reason = 'limit_missing', resource = name })
        end
        local usage = tonumber(redis.call('HGET', usageKey, name) or '0')
        if usage + count > tonumber(limit) then
          return cjson.encode({ ok = false, reason = 'limit_exceeded', resource = name, available = tonumber(limit) - usage })
        end
      end

      local sentinelKey = 'resource:lease:' .. leaseId
      local setResult = redis.call('SET', sentinelKey, '1', 'PX', ttl, 'NX')
      -- Under RESP3 the status reply comes back as a table-like userdata.
      -- A nil response is the only signal that NX failed, so treat any
      -- truthy reply as success instead of strict string comparison.
      if not setResult then
        return cjson.encode({ ok = false, reason = 'sentinel_exists' })
      end

      local expiresAt = now + ttl
      local leaseSummary = { worker_id = workerId, resources = resources, expires_at = expiresAt, metadata = metadata }
      redis.call('HSET', indexKey, leaseId, cjson.encode(leaseSummary))

      for i = 1, #resources do
        local res = resources[i]
        local name = res.name
        local count = tonumber(res.count or 1)
        local leaseHashKey = 'resource:' .. name .. ':leases'
        redis.call('HSET', leaseHashKey, leaseId, cjson.encode({ worker_id = workerId, expires_at = expiresAt, count = count }))
        redis.call('HINCRBY', usageKey, name, count)
      end

      return cjson.encode({ ok = true, lease_id = leaseId, expires_at = expiresAt })
    `;

    const release = `
      local usageKey = KEYS[1]
      local epochKey = KEYS[2]
      local indexKey = KEYS[3]
      local leaseId = ARGV[1]
      local reason = ARGV[2]
      local now = tonumber(ARGV[3])
      local sentinelKey = 'resource:lease:' .. leaseId

      local infoJson = redis.call('HGET', indexKey, leaseId)
      if not infoJson then
        redis.call('DEL', sentinelKey)
        return cjson.encode({ ok = false, reason = 'not_found' })
      end

      local info = cjson.decode(infoJson)
      local resources = info.resources or {}

      for i = 1, #resources do
        local res = resources[i]
        local name = res.name
        local count = tonumber(res.count or 1)
        local leaseHashKey = 'resource:' .. name .. ':leases'
        redis.call('HDEL', leaseHashKey, leaseId)
        local newUsage = redis.call('HINCRBY', usageKey, name, -count)
        if tonumber(newUsage) < 0 then
          redis.call('HSET', usageKey, name, 0)
        end
      end

      redis.call('DEL', sentinelKey)
      redis.call('HDEL', indexKey, leaseId)
      local epoch = redis.call('INCR', epochKey)
      redis.call('PUBLISH', '${RELEASE_CHANNEL}', cjson.encode({ lease_id = leaseId, reason = reason, epoch = epoch, ts = now }))
      return cjson.encode({ ok = true, epoch = epoch })
    `;

    const renew = `
      local leaseId = ARGV[1]
      local ttl = tonumber(ARGV[2])
      local now = tonumber(ARGV[3])
      local usageKey = KEYS[1]
      local indexKey = KEYS[2]
      local sentinelKey = 'resource:lease:' .. leaseId

      local ttlResult = redis.call('PEXPIRE', sentinelKey, ttl)
      if ttlResult == 0 then
        return cjson.encode({ ok = false, reason = 'missing' })
      end

      local infoJson = redis.call('HGET', indexKey, leaseId)
      if not infoJson then
        redis.call('DEL', sentinelKey)
        return cjson.encode({ ok = false, reason = 'missing_info' })
      end

      local info = cjson.decode(infoJson)
      local expiresAt = now + ttl
      info.expires_at = expiresAt
      redis.call('HSET', indexKey, leaseId, cjson.encode(info))

      local resources = info.resources or {}
      for i = 1, #resources do
        local res = resources[i]
        local name = res.name
        local leaseHashKey = 'resource:' .. name .. ':leases'
        local leaseInfoJson = redis.call('HGET', leaseHashKey, leaseId)
        if leaseInfoJson then
          local leaseInfo = cjson.decode(leaseInfoJson)
          leaseInfo.expires_at = expiresAt
          redis.call('HSET', leaseHashKey, leaseId, cjson.encode(leaseInfo))
        else
          redis.call('HSET', leaseHashKey, leaseId, cjson.encode({ worker_id = info.worker_id, expires_at = expiresAt, count = res.count or 1 }))
          redis.call('HINCRBY', usageKey, name, tonumber(res.count or 1))
        end
      end

      return cjson.encode({ ok = true, lease_id = leaseId, expires_at = expiresAt })
    `;

    const verify = `
      local leaseId = ARGV[1]
      local indexKey = KEYS[1]
      local infoJson = redis.call('HGET', indexKey, leaseId)
      if not infoJson then
        return cjson.encode({ ok = false })
      end
      local info = cjson.decode(infoJson)
      return cjson.encode({ ok = true, lease_id = leaseId, expires_at = info.expires_at, worker_id = info.worker_id, resources = info.resources, metadata = info.metadata })
    `;

    const sweep = `
      local usageKey = KEYS[1]
      local epochKey = KEYS[2]
      local indexKey = KEYS[3]
      local now = tonumber(ARGV[1])
      local processed = 0
      local leaseIds = redis.call('HKEYS', indexKey)
      for _, leaseId in ipairs(leaseIds) do
        local infoJson = redis.call('HGET', indexKey, leaseId)
        if infoJson then
          local info = cjson.decode(infoJson)
          if info.expires_at and tonumber(info.expires_at) <= now then
            local resources = info.resources or {}
            for i = 1, #resources do
              local res = resources[i]
              local leaseHashKey = 'resource:' .. res.name .. ':leases'
              redis.call('HDEL', leaseHashKey, leaseId)
              local newUsage = redis.call('HINCRBY', usageKey, res.name, -tonumber(res.count or 1))
              if tonumber(newUsage) < 0 then
                redis.call('HSET', usageKey, res.name, 0)
              end
            end
            redis.call('HDEL', indexKey, leaseId)
            redis.call('DEL', 'resource:lease:' .. leaseId)
            redis.call('INCR', epochKey)
            processed = processed + 1
          end
        end
      end
      return processed
    `;

    this.scripts = {
      acquireMany,
      release,
      renew,
      verify,
      sweepLease: sweep
    };
  }

  private ensureClient(): RedisClientType {
    if (!this.client) throw new Error('ResourceGovernor not initialized');
    return this.client;
  }

  private async eval<T = unknown>(script: string, keys: string[], args: (string | number)[]): Promise<T> {
    const client = this.ensureClient();
    const result = await client.eval(script, {
      keys,
      arguments: args.map((arg) => String(arg))
    });
    return result as T;
  }

  private parseResult(result: unknown): any {
    if (typeof result === 'string') {
      try {
        return JSON.parse(result);
      } catch (error) {
        log.error({ err: error, result }, 'Failed to parse script result');
      }
    }
    return result;
  }

  private buildLeaseInfo(raw: any, workerId: string, resources: ResourceRequest[]): ResourceLeaseInfo {
    return {
      id: raw.lease_id,
      workerId,
      resources,
      expiresAt: Number(raw.expires_at ?? Date.now()),
      metadata: raw.metadata && typeof raw.metadata === 'object' ? raw.metadata : undefined
    };
  }

  async acquireMany(requests: ResourceRequest[], options: AcquireOptions): Promise<ManagedLease | null> {
    if (!this.initialized) throw new Error('ResourceGovernor not initialized');
    const resources = requests.map(toResourceRequest);
    const leaseTtl = options.leaseTtlMs ?? DEFAULT_LEASE_TTL_MS;
    const workerId = options.workerId;
    const metadata = options.metadata ?? {};
    const wait = options.wait ?? true;
    const waitTimeout = options.waitTimeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS;
    const retryDelay = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;

    const start = Date.now();

    while (true) {
      const leaseId = randomUUID();
      const payload = await this.eval<string>(this.scripts!.acquireMany, [LIMITS_KEY, USAGE_KEY, EPOCH_KEY, LEASE_INDEX_KEY], [
        Date.now(),
        leaseTtl,
        leaseId,
        workerId,
        JSON.stringify(resources),
        JSON.stringify({ ...metadata, purpose: options.purpose })
      ]);

      const parsed = this.parseResult(payload);

      if (parsed && parsed.ok === true) {
        const info = this.buildLeaseInfo(parsed, workerId, resources);
        const lease = new ManagedLease(this, info);
        if (options.autoRenew) {
          lease.startHeartbeat(leaseTtl);
        }
        return lease;
      }

      if (parsed && parsed.reason === 'limit_missing') {
        const missing = parsed.resource ?? 'unknown';
        throw new Error(`Resource limit not configured for ${missing}`);
      }

      if (!wait) {
        return null;
      }

      if (Date.now() - start >= waitTimeout) {
        return null;
      }

      await new Promise((resolve) => setTimeout(resolve, retryDelay + Math.floor(Math.random() * retryDelay))).catch(() => undefined);
    }
  }

  async releaseLease(leaseId: string): Promise<boolean> {
    if (!this.scripts) throw new Error('ResourceGovernor not initialized');
    const result = await this.eval<string>(this.scripts.release, [USAGE_KEY, EPOCH_KEY, LEASE_INDEX_KEY], [
      leaseId,
      'release',
      Date.now()
    ]);
    const parsed = this.parseResult(result);
    return Boolean(parsed && parsed.ok === true);
  }

  async renewLease(leaseId: string, ttlMs?: number): Promise<ResourceLeaseInfo | null> {
    if (!this.scripts) throw new Error('ResourceGovernor not initialized');
    const ttl = ttlMs ?? DEFAULT_LEASE_TTL_MS;
    const result = await this.eval<string>(this.scripts.renew, [USAGE_KEY, LEASE_INDEX_KEY], [
      leaseId,
      ttl,
      Date.now()
    ]);
    const parsed = this.parseResult(result);
    if (parsed && parsed.ok === true) {
      return {
        id: leaseId,
        resources: (parsed.resources ?? []).map(toResourceRequest),
        workerId: parsed.worker_id ?? 'unknown',
        expiresAt: Number(parsed.expires_at ?? Date.now()),
        metadata: parsed.metadata
      };
    }
    return null;
  }

  async verifyLease(leaseId: string): Promise<ResourceLeaseInfo | null> {
    if (!this.scripts) throw new Error('ResourceGovernor not initialized');
    const result = await this.eval<string>(this.scripts.verify, [LEASE_INDEX_KEY], [leaseId]);
    const parsed = this.parseResult(result);
    if (parsed && parsed.ok === true) {
      return {
        id: leaseId,
        resources: (parsed.resources ?? []).map(toResourceRequest),
        workerId: parsed.worker_id ?? 'unknown',
        expiresAt: Number(parsed.expires_at ?? Date.now()),
        metadata: parsed.metadata
      };
    }
    return null;
  }

  async getUsage(): Promise<Record<string, number>> {
    const client = this.ensureClient();
    const values = await client.hGetAll(USAGE_KEY);
    const usage: Record<string, number> = {};
    for (const [key, value] of Object.entries(values)) {
      if (key === 'init') continue;
      usage[key] = Number(value ?? '0');
    }
    return usage;
  }

  async handleLeaseExpiration(leaseId: string, reason: string): Promise<void> {
    if (!this.scripts) return;
    await this.eval<string>(this.scripts.release, [USAGE_KEY, EPOCH_KEY, LEASE_INDEX_KEY], [
      leaseId,
      reason,
      Date.now()
    ]);
  }

  async runSweep(): Promise<void> {
    if (!this.scripts) return;
    await this.eval<number>(this.scripts.sweepLease, [USAGE_KEY, EPOCH_KEY, LEASE_INDEX_KEY], [Date.now()]);
  }

  async shutdown(): Promise<void> {
    if (this.sweepTimer) {
      clearInterval(this.sweepTimer);
      this.sweepTimer = undefined;
    }
    if (this.subscriber) {
      try {
        await this.subscriber.disconnect();
      } catch (error) {
        log.error({ err: error }, 'Failed to disconnect subscriber');
      }
      this.subscriber = undefined;
    }
    if (this.client) {
      try {
        await this.client.disconnect();
      } catch (error) {
        log.error({ err: error }, 'Failed to disconnect client');
      }
      this.client = undefined;
    }
    this.initialized = false;
  }
}

export const resourceGovernor = new ResourceGovernor();

export function defaultResourceLimits(): ResourceLimit[] {
  const defaults: ResourceLimit[] = [];
  const dbLimit = process.env.RESOURCE_LIMIT_DB ? parseInt(process.env.RESOURCE_LIMIT_DB, 10) : undefined;
  if (dbLimit && !Number.isNaN(dbLimit)) {
    defaults.push({ name: 'db', limit: dbLimit, defaultTtlMs: DEFAULT_LEASE_TTL_MS });
  }
  const tlsLimit = process.env.RESOURCE_LIMIT_TLS ? parseInt(process.env.RESOURCE_LIMIT_TLS, 10) : undefined;
  if (tlsLimit && !Number.isNaN(tlsLimit)) {
    defaults.push({ name: 'tls_scan', limit: tlsLimit, defaultTtlMs: DEFAULT_LEASE_TTL_MS });
  }
  const cpuTickets = process.env.RESOURCE_LIMIT_CPU ? parseInt(process.env.RESOURCE_LIMIT_CPU, 10) : undefined;
  if (cpuTickets && !Number.isNaN(cpuTickets)) {
    defaults.push({ name: 'cpu_ticket', limit: cpuTickets, defaultTtlMs: DEFAULT_LEASE_TTL_MS });
  }
  const scanWorkers = process.env.RESOURCE_LIMIT_SCAN_WORKER ? parseInt(process.env.RESOURCE_LIMIT_SCAN_WORKER, 10) : undefined;
  if (scanWorkers && !Number.isNaN(scanWorkers)) {
    defaults.push({ name: 'scan_worker', limit: scanWorkers, defaultTtlMs: DEFAULT_LEASE_TTL_MS });
  }
  return defaults;
}
