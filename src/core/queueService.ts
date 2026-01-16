import Bull, { Queue, Job, JobOptions } from 'bull';
import { nanoid } from 'nanoid';
import { database, ScanData } from './database.js';
import { acquireJobLease, recordUsageSnapshot } from './resourceManager.js';
import { resourceGovernor, defaultResourceLimits } from './resourceGovernor.js';
import type { ScanProfile } from '../config/scanProfiles.js';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('queue');

export interface ScanJobData {
  scan_id: string;
  domain: string;
  companyName?: string;
  email?: string;
  priority?: 'low' | 'normal' | 'high';
  profile?: ScanProfile;  // Scan profile: 'full' | 'wordpress' | 'infostealer' | 'email' | 'quick'
  tags?: string[];
  batchId?: string;
  batchPosition?: number;
  manifestScanId?: string;
  created_at: Date;
  /** Runtime configuration options */
  config?: {
    timeout_ms?: number;
    tier?: 'tier1' | 'tier2';
    modules?: string[];
    skip_modules?: string[];
    callback_url?: string;
  };
}

export interface ScanJobStatus {
  scan_id: string;
  status: 'queued' | 'active' | 'completed' | 'failed' | 'delayed' | 'waiting';
  position_in_queue?: number;
  progress?: number;
  started_at?: Date;
  completed_at?: Date;
  error_message?: string;
  duration_ms?: number;
}

export interface QueueMetrics {
  waiting: number;
  active: number;
  completed: number;
  failed: number;
  delayed: number;
  paused: boolean;
  resource_usage?: Record<string, number>;
}

/**
 * Redis-based queue service using Bull
 * Provides persistent, scalable job queue management
 */
export class QueueService {
  private scanQueue: Queue<ScanJobData>;
  private redisConfig: any;
  private governorReady: Promise<void>;

  private async loadScan(scanId: string): Promise<ScanData | null> {
    try {
      return await database.getScan(scanId);
    } catch (error) {
      log.error({ err: error, scanId }, 'Failed to load scan record for merge');
      return null;
    }
  }

  private mergeMetadata(existing: Record<string, any> | null | undefined, updates: Record<string, any>): Record<string, any> {
    const base = existing ? { ...existing } : {};
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined || value === null) continue;
      base[key] = value;
    }
    return base;
  }

  constructor(concurrency: number = 8) {
    // Redis connection config
    this.redisConfig = {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      db: parseInt(process.env.REDIS_DB || '0'),
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
    };

    this.governorReady = this.ensureGovernor();

    // Initialize scan queue (configurable name for separate inbound/outbound queues)
    const queueName = process.env.SCAN_QUEUE_NAME || 'scan-queue';
    log.info({ queueName }, 'Using queue');
    this.scanQueue = new Bull<ScanJobData>(queueName, {
      redis: this.redisConfig,
      defaultJobOptions: {
        removeOnComplete: 50, // Keep last 50 completed jobs
        removeOnFail: 50,     // Keep last 50 failed jobs
        attempts: 1,          // No retries for scans to avoid duplicates
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }
    });

    this.setupProcessor(concurrency);
    this.setupEventHandlers();
  }

  /**
   * Wait until the resource governor is ready (or throw if init failed)
   */
  async waitReady(): Promise<void> {
    await this.governorReady;
  }

  /**
   * Ensure the ResourceGovernor is initialized. Retries with backoff until success.
   */
  private ensureGovernor(): Promise<void> {
    const resourceLimits = defaultResourceLimits();
    const sweepIntervalMs = parseInt(process.env.RESOURCE_SWEEP_INTERVAL_MS || '30000', 10);
    let delay = 1000;

    return new Promise((resolve) => {
      const attempt = async () => {
        try {
          await resourceGovernor.initialize({ resourceLimits, sweepIntervalMs });
          log.info('Resource governor initialized');
          resolve();
        } catch (error: unknown) {
          log.error({ err: error, retryDelayMs: delay }, 'Resource governor init failed, retrying');
          setTimeout(() => {
            delay = Math.min(delay * 2, 30000);
            void attempt();
          }, delay);
        }
      };
      void attempt();
    });
  }

  private setupProcessor(concurrency: number) {
    // Process scan jobs with specified concurrency
    this.scanQueue.process(concurrency, async (job: Job<ScanJobData>) => {
      await this.governorReady;
      const { scan_id, domain, companyName, profile } = job.data;
      const workerLabel = `worker-${job.id}`;

      const jobLease = await acquireJobLease(job.id?.toString() ?? scan_id, { workerId: workerLabel, jobId: scan_id });
      const profileLabel = profile || 'full';
      log.info({ scanId: scan_id, domain, profile: profileLabel }, 'Processing scan');
      
      const existingScan = await this.loadScan(scan_id);
      let mergedMetadata = existingScan?.metadata ? { ...existingScan.metadata } : {};
      const baseCreatedAt = existingScan?.created_at ?? job.data.created_at;
      const baseDomain = (existingScan?.domain ?? domain).toLowerCase();

      // Update scan status to running
      mergedMetadata = this.mergeMetadata(mergedMetadata, {
        started_at: new Date().toISOString(),
        worker_id: workerLabel,
        last_status: 'running'
      });

      await database.insertScan({
        id: scan_id,
        domain: baseDomain,
        status: 'running',
        created_at: baseCreatedAt,
        completed_at: existingScan?.completed_at,
        findings_count: existingScan?.findings_count ?? 0,
        artifacts_count: existingScan?.artifacts_count ?? 0,
        duration_ms: existingScan?.duration_ms,
        metadata: mergedMetadata
      });

      try {
        // Dynamic import to avoid circular dependency
        const { executeScan } = await import('../scan/executeScan.js');

        const startTime = Date.now();

        // Execute the scan with optional profile for lightweight pipelines
        const result = await executeScan({
          scan_id,
          domain,
          companyName,
          profile  // 'full' | 'wordpress' | 'infostealer' | 'email' | 'quick'
        });

        const duration = Date.now() - startTime;

        // Refresh counts now that modules have stored findings/artifacts
        let findingsCount = 0;
        let artifactsCount = 0;
        try {
          findingsCount = await database.getFindingCount(scan_id);
          artifactsCount = await database.getArtifactCount(scan_id);
        } catch (countError) {
          log.error({ err: countError, scanId: scan_id }, 'Failed to refresh finding/artifact counts');
        }

        const augmentedMetadata = {
          ...(result.metadata ?? {}),
          findings_count: findingsCount,
          artifacts_count: artifactsCount
        };

        mergedMetadata = this.mergeMetadata(mergedMetadata, {
          completed_at: new Date().toISOString(),
          worker_id: workerLabel,
          modules_completed: result.metadata?.modules_completed || 0,
          modules_failed: result.metadata?.modules_failed || 0,
          findings_count: findingsCount,
          artifacts_count: artifactsCount,
          scan_result: { ...result, metadata: augmentedMetadata },
          last_status: 'completed',
          duration_ms: duration
        });

        await database.insertScan({
          id: scan_id,
          domain: baseDomain,
          status: 'completed',
          created_at: baseCreatedAt,
          completed_at: new Date(),
          findings_count: findingsCount,
          artifacts_count: artifactsCount,
          duration_ms: duration,
          metadata: mergedMetadata
        });

        log.info({ scanId: scan_id, durationMs: duration, findingsCount, artifactsCount }, 'Completed scan');

        // Auto-generate snapshot report disabled by default
        // Only generate reports on-demand to save disk space
        // Uncomment to re-enable:
        // this.generateSnapshotReport(scan_id).catch(err => {
        //   console.error(`[Queue] Failed to auto-generate snapshot report for ${scan_id}:`, err);
        // });

        return result;

      } catch (error) {
        log.error({ err: error, scanId: scan_id, domain }, 'Scan failed');

        let findingsCount = 0;
        let artifactsCount = 0;
        try {
          findingsCount = await database.getFindingCount(scan_id);
          artifactsCount = await database.getArtifactCount(scan_id);
        } catch (countError) {
          log.error({ err: countError, scanId: scan_id }, 'Failed to refresh counts after failure');
        }

        mergedMetadata = this.mergeMetadata(mergedMetadata, {
          failed_at: new Date().toISOString(),
          worker_id: workerLabel,
          error_message: error instanceof Error ? error.message : 'Unknown error',
          findings_count: findingsCount,
          artifacts_count: artifactsCount,
          last_status: 'failed'
        });

        await database.insertScan({
          id: scan_id,
          domain: baseDomain,
          status: 'failed',
          created_at: baseCreatedAt,
          completed_at: new Date(),
          findings_count: findingsCount,
          artifacts_count: artifactsCount,
          duration_ms: Date.now() - (job.processedOn || Date.now()),
          metadata: mergedMetadata
        });

        throw error; // Re-throw to mark job as failed
      } finally {
        await jobLease.release();
      }
    });
  }

  private setupEventHandlers() {
    this.scanQueue.on('completed', async (job, result) => {
      log.info({ jobId: job.id }, 'Job completed successfully');
      await recordUsageSnapshot('scheduler');
    });

    this.scanQueue.on('failed', async (job, err) => {
      log.error({ jobId: job.id, err }, 'Job failed');
      await recordUsageSnapshot('scheduler');
    });

    this.scanQueue.on('stalled', (job) => {
      log.warn({ jobId: job.id }, 'Job stalled and will be retried');
    });

    this.scanQueue.on('error', (error) => {
      log.error({ err: error }, 'Queue error');
    });
  }

  /**
   * Auto-generate snapshot report for completed scan
   * Snapshot reports are free (no LLM costs)
   */
  private async generateSnapshotReport(scanId: string): Promise<void> {
    const REPORTS_PORT = process.env.REPORTS_PORT || '8082';
    const reportsUrl = `http://127.0.0.1:${REPORTS_PORT}/reports/generate`;

    try {
      log.info({ scanId }, 'Auto-generating snapshot report');

      const response = await fetch(reportsUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scan_id: scanId,
          report_type: 'snapshot-report'
        })
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Report generation failed: ${response.status} - ${error}`);
      }

      const result = await response.json();
      log.info({ scanId, result }, 'Snapshot report generated');
    } catch (error) {
      // Don't throw - just log the error so scan completion isn't blocked
      log.error({ err: error, scanId }, 'Failed to generate snapshot report');
    }
  }

  /**
   * Add a scan job to the queue
   */
  async enqueue(jobData: Omit<ScanJobData, 'scan_id' | 'created_at'>): Promise<string> {
    // Ensure resource governor is initialized before any DB/queue work
    await this.governorReady;
    const scan_id = `scan-${nanoid()}`;
    const created_at = new Date();
    
    const job: ScanJobData = {
      ...jobData,
      scan_id,
      created_at,
      domain: jobData.domain.toLowerCase()
    };

    // Store initial scan record in database
    const initialMetadata: Record<string, any> = {
      priority: jobData.priority || 'normal',
      profile: jobData.profile || 'full',  // Default to full scan
      queued_at: created_at.toISOString(),
      last_status: 'queued'
    };

    if (jobData.companyName) initialMetadata.company_name = jobData.companyName;
    if (jobData.email) initialMetadata.submitter_email = jobData.email;
    if (jobData.tags && jobData.tags.length > 0) initialMetadata.tags = jobData.tags;
    if (jobData.batchId) initialMetadata.batch_id = jobData.batchId;
    if (typeof jobData.batchPosition === 'number') initialMetadata.batch_position = jobData.batchPosition;
    if (jobData.manifestScanId) initialMetadata.manifest_scan_id = jobData.manifestScanId;

    await database.insertScan({
      id: scan_id,
      domain: job.domain,
      status: 'queued',
      created_at,
      findings_count: 0,
      artifacts_count: 0,
      metadata: initialMetadata
    });

    // Add to Redis queue with priority
    const priority = this.getPriorityValue(jobData.priority);
    const bullJob = await this.scanQueue.add(job, {
      priority,
      delay: 0
    });

    const profileLabel = jobData.profile || 'full';
    log.info({ scanId: scan_id, domain: job.domain, profile: profileLabel, jobId: bullJob.id }, 'Enqueued scan');

    return scan_id;
  }

  /**
   * Get job status from queue or database
   */
  async getJobStatus(scan_id: string): Promise<ScanJobStatus | null> {
    // First try to find in Redis queue (active/waiting jobs)
    const jobs = await this.scanQueue.getJobs(['waiting', 'active', 'completed', 'failed', 'delayed']);
    const queueJob = jobs.find(job => job.data.scan_id === scan_id);
    
    if (queueJob) {
      // Get position in queue for waiting jobs
      let position: number | undefined;
      if (await queueJob.getState() === 'waiting') {
        const waiting = await this.scanQueue.getWaiting();
        position = waiting.findIndex(j => j.id === queueJob.id) + 1;
        position = position > 0 ? position : undefined;
      }

      return {
        scan_id,
        status: await queueJob.getState() as any,
        position_in_queue: position,
        progress: queueJob.progress(),
        started_at: queueJob.processedOn ? new Date(queueJob.processedOn) : undefined,
        completed_at: queueJob.finishedOn ? new Date(queueJob.finishedOn) : undefined,
        error_message: queueJob.failedReason,
        duration_ms: queueJob.finishedOn && queueJob.processedOn ? 
          queueJob.finishedOn - queueJob.processedOn : undefined
      };
    }

    // If not in queue, check database for completed/failed scans
    const scan = await database.getScan(scan_id);
    if (!scan) return null;

    return {
      scan_id,
      status: scan.status as any,
      started_at: scan.metadata?.started_at ? new Date(scan.metadata.started_at) : undefined,
      completed_at: scan.completed_at,
      error_message: scan.metadata?.error_message,
      duration_ms: scan.duration_ms
    };
  }

  /**
   * Cancel a job (if it's still in queue)
   */
  async cancelJob(scan_id: string): Promise<boolean> {
    const jobs = await this.scanQueue.getJobs(['waiting', 'delayed']);
    const job = jobs.find(j => j.data.scan_id === scan_id);
    
    if (job) {
      await job.remove();
      
      // Update database
      await database.insertScan({
        id: scan_id,
        domain: 'cancelled',
        status: 'cancelled',
        created_at: new Date(),
        completed_at: new Date(),
        findings_count: 0,
        artifacts_count: 0
      });

      log.info({ scanId: scan_id }, 'Cancelled job');
      return true;
    }

    return false;
  }

  /**
   * Get queue metrics
   */
  async getMetrics(): Promise<QueueMetrics> {
    const [waiting, active, completed, failed, delayed, paused, usage] = await Promise.all([
      this.scanQueue.getWaiting(),
      this.scanQueue.getActive(),
      this.scanQueue.getCompleted(),
      this.scanQueue.getFailed(),
      this.scanQueue.getDelayed(),
      this.scanQueue.isPaused(),
      resourceGovernor.getUsage().catch(() => ({} as Record<string, number>))
    ]);

    return {
      waiting: waiting.length,
      active: active.length,
      completed: completed.length,
      failed: failed.length,
      delayed: delayed.length,
      paused,
      resource_usage: usage
    };
  }

  /**
   * Get all jobs in various states
   */
  async getAllJobs() {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.scanQueue.getWaiting(),
      this.scanQueue.getActive(),
      this.scanQueue.getCompleted().then(jobs => jobs.slice(0, 20)), // Limit recent
      this.scanQueue.getFailed().then(jobs => jobs.slice(0, 20)),
      this.scanQueue.getDelayed()
    ]);

    return { waiting, active, completed, failed, delayed };
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{ status: 'ok' | 'error'; details: any }> {
    try {
      const metrics = await this.getMetrics();
      const redisInfo = await this.scanQueue.client.ping();
      
      return {
        status: 'ok',
        details: {
          redis_ping: redisInfo,
          queue_metrics: metrics,
          queue_name: this.scanQueue.name
        }
      };
    } catch (error) {
      return {
        status: 'error',
        details: { error: error instanceof Error ? error.message : 'Unknown error' }
      };
    }
  }

  /**
   * Clean completed/failed jobs
   */
  async cleanJobs(grace: number = 24 * 60 * 60 * 1000): Promise<void> {
    await this.scanQueue.clean(grace, 'completed');
    await this.scanQueue.clean(grace, 'failed');
    log.info({ graceMs: grace }, 'Cleaned old completed/failed jobs');
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    log.info('Shutting down queue service');

    // Wait for active jobs to complete (with timeout)
    const activeJobs = await this.scanQueue.getActive();
    if (activeJobs.length > 0) {
      log.info({ activeJobCount: activeJobs.length }, 'Waiting for active jobs to complete');

      // Wait max 2 minutes for jobs to complete
      const timeout = setTimeout(async () => {
        log.warn('Shutdown timeout reached, closing queue');
        await this.scanQueue.close();
      }, 2 * 60 * 1000);

      await this.scanQueue.whenCurrentJobsFinished();
      clearTimeout(timeout);
    }

    await this.scanQueue.close();
    log.info('Queue service shutdown complete');
  }

  private getPriorityValue(priority?: string): number {
    switch (priority) {
      case 'high': return 10;
      case 'normal': return 5;
      case 'low': return 1;
      default: return 5;
    }
  }
}
