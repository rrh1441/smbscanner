import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { ManagedLease, resourceGovernor } from './resourceGovernor.js';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('resourceManager');

export interface ModuleResourceRequirement {
  name: string;
  count?: number;
  ttlMs?: number;
}

export interface AcquireContext {
  workerId?: string;
  jobId?: string;
  purpose?: string;
}

const HOST_WORKER_ID = process.env.WORKER_ID ?? `${os.hostname()}-${process.pid}`;
const JOB_LEASE_TTL_MS = parseInt(process.env.SCAN_WORKER_LEASE_TTL_MS ?? '600000', 10);
const JOB_LEASE_WAIT_TIMEOUT_MS = parseInt(process.env.SCAN_WORKER_LEASE_WAIT_TIMEOUT_MS ?? `${JOB_LEASE_TTL_MS}`, 10);
const MODULE_LEASE_TTL_MS = parseInt(process.env.MODULE_LEASE_TTL_MS ?? '60000', 10);

export async function acquireJobLease(jobId: string, context: AcquireContext = {}): Promise<ManagedLease> {
  const workerId = context.workerId ?? HOST_WORKER_ID;
  const lease = await resourceGovernor.acquireMany([
    { name: 'scan_worker', count: 1, ttlMs: JOB_LEASE_TTL_MS }
  ], {
    workerId,
    purpose: `scan:${jobId}`,
    wait: true,
    waitTimeoutMs: JOB_LEASE_WAIT_TIMEOUT_MS,
    leaseTtlMs: JOB_LEASE_TTL_MS,
    autoRenew: true
  });

  if (!lease) {
    throw new Error(`Unable to acquire scan_worker lease for job ${jobId}`);
  }

  lease.startHeartbeat(JOB_LEASE_TTL_MS);
  return lease;
}

export async function withModuleLease<T>(moduleName: string, resources: ModuleResourceRequirement[], fn: () => Promise<T>, context: AcquireContext = {}): Promise<T> {
  if (!resources.length) {
    return fn();
  }

  const workerId = context.workerId ?? HOST_WORKER_ID;
  const leaseTtl = Math.max(MODULE_LEASE_TTL_MS, ...resources.map((r) => r.ttlMs ?? MODULE_LEASE_TTL_MS));

  const start = performance.now();
  const lease = await resourceGovernor.acquireMany(resources, {
    workerId,
    purpose: `module:${moduleName}`,
    wait: true,
    leaseTtlMs: leaseTtl,
    autoRenew: true
  });

  if (!lease) {
    throw new Error(`Unable to acquire resources for module ${moduleName}`);
  }

  lease.startHeartbeat(leaseTtl);

  try {
    return await fn();
  } finally {
    const duration = performance.now() - start;
    log.debug({ moduleName, leaseId: lease.id, durationMs: Math.round(duration) }, 'Module released lease');
    await lease.release();
  }
}

export async function recordUsageSnapshot(source: 'scheduler' | 'redis_sampler' | 'worker'): Promise<void> {
  const usage = await resourceGovernor.getUsage();
  log.debug({ source, usage }, 'Usage snapshot');
}
