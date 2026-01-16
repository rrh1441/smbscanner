import { Pool, PoolClient } from 'pg';
import { promises as fs } from 'fs';
import { join } from 'path';
import os from 'node:os';
import {
  resourceGovernor,
  defaultResourceLimits,
  ManagedLease,
  ResourceLimit
} from './resourceGovernor.js';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('database');

export interface ScanData {
  id: string;
  domain: string;
  status: string;
  created_at: Date;
  completed_at?: Date;
  findings_count: number;
  artifacts_count: number;
  duration_ms?: number;
  metadata?: any;
  tier?: 'tier1' | 'tier2';
}

export interface FindingData {
  id: string;
  scan_id: string;
  type: string;
  severity: string;
  title: string;
  description?: string;
  data?: any;
  created_at: Date;
}

export interface ArtifactData {
  id: string;
  scan_id: string;
  type: string;
  file_path: string;
  size_bytes: number;
  created_at: Date;
  severity?: string;
  val_text?: string;
  src_url?: string;
  sha256?: string;
  mime_type?: string;
  metadata?: any;
}

const DEFAULT_DB_LEASE_TTL_MS = parseInt(process.env.DB_LEASE_TTL_MS ?? '30000', 10);
const DEFAULT_DB_WAIT_TIMEOUT_MS = parseInt(process.env.DB_LEASE_WAIT_TIMEOUT_MS ?? '60000', 10);
const DEFAULT_DB_LIMIT = parseInt(process.env.DB_LEASE_LIMIT ?? process.env.DB_CONNECTION_LIMIT ?? '16', 10);

function ensureJson(value: unknown): unknown {
  if (!value || typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

export class DatabaseService {
  private pool: Pool;
  private readonly reportsDir: string;
  private readonly artifactsDir: string;
  private initialized = false;
  private readonly workerId: string;
  private readonly dbLeaseTtlMs: number;
  private readonly dbLeaseWaitTimeoutMs: number;

  constructor() {
    this.pool = this.createPool();

    this.reportsDir = './scan-reports';
    this.artifactsDir = './scan-artifacts';
    this.workerId = process.env.WORKER_ID ?? `${os.hostname()}-${process.pid}`;
    this.dbLeaseTtlMs = DEFAULT_DB_LEASE_TTL_MS;
    this.dbLeaseWaitTimeoutMs = DEFAULT_DB_WAIT_TIMEOUT_MS;
  }

  private createPool(): Pool {
    const connectionString = this.resolveConnectionString();
    const maxConnections = parseInt(process.env.PG_POOL_MAX ?? '10', 10);

    const pool = new Pool({
      connectionString,
      max: maxConnections,
      min: 0,
      idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT_MS ?? '0', 10),
      allowExitOnIdle: true,
      connectionTimeoutMillis: parseInt(process.env.PG_CONNECTION_TIMEOUT_MS ?? '5000', 10),
      statement_timeout: parseInt(process.env.PG_STATEMENT_TIMEOUT_MS ?? '30000', 10),
      keepAlive: true,
      keepAliveInitialDelayMillis: parseInt(process.env.PG_KEEPALIVE_DELAY_MS ?? '10000', 10)
    });

    pool.on('error', (error) => {
      log.error({
        err: error,
        poolStats: {
          total: pool.totalCount,
          idle: pool.idleCount,
          waiting: pool.waitingCount
        }
      }, 'Pool error');
    });

    pool.on('acquire', () => {
      if (pool.waitingCount > 0 || pool.totalCount >= pool.options.max) {
        log.warn({
          poolStats: {
            total: pool.totalCount,
            idle: pool.idleCount,
            waiting: pool.waitingCount,
            max: pool.options.max
          }
        }, 'Connection pool pressure');
      }
    });

    pool.on('connect', () => {
      log.info({ poolSize: pool.totalCount }, 'Connection established');
    });

    return pool;
  }

  private resolveConnectionString(): string {
    const directUrl = process.env.PGBOUNCER_URL ?? process.env.DATABASE_URL;
    if (directUrl) return directUrl;

    const user = process.env.POSTGRES_USER ?? process.env.USER ?? 'postgres';
    const host = process.env.POSTGRES_HOST ?? '127.0.0.1';
    const db = process.env.POSTGRES_DB ?? 'scanner_local';
    const password = process.env.POSTGRES_PASSWORD ?? '';
    const port = process.env.POSTGRES_PORT ?? '5432';

    const auth = password ? `${user}:${password}` : user;
    return `postgresql://${auth}@${host}:${port}/${db}`;
  }

  private computeResourceLimits(): ResourceLimit[] {
    const limits = defaultResourceLimits();
    if (!limits.some((limit) => limit.name === 'db')) {
      limits.push({ name: 'db', limit: DEFAULT_DB_LIMIT, defaultTtlMs: DEFAULT_DB_LEASE_TTL_MS });
    }
    return limits;
  }

  private async acquireDbLease(purpose: string): Promise<ManagedLease> {
    const lease = await resourceGovernor.acquireMany([
      { name: 'db', count: 1, ttlMs: this.dbLeaseTtlMs }
    ], {
      workerId: this.workerId,
      purpose,
      wait: true,
      waitTimeoutMs: this.dbLeaseWaitTimeoutMs,
      leaseTtlMs: this.dbLeaseTtlMs
    });

    if (!lease) {
      throw new Error(`Timed out acquiring DB lease for ${purpose}`);
    }

    return lease;
  }

  private async withDbClient<T>(purpose: string, fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const lease = await this.acquireDbLease(purpose);
    let client: PoolClient | null = null;
    try {
      client = await this.pool.connect();
      return await fn(client);
    } finally {
      if (client) {
        try {
          client.release();
        } catch (error) {
          log.error({ err: error }, 'Failed to release client');
        }
      }
      try {
        await lease.release();
      } catch (error) {
        log.error({ err: error }, 'Failed to release DB lease');
      }
    }
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    await resourceGovernor.initialize({
      resourceLimits: this.computeResourceLimits(),
      sweepIntervalMs: parseInt(process.env.RESOURCE_SWEEP_INTERVAL_MS ?? '30000', 10)
    });

    await fs.mkdir(this.reportsDir, { recursive: true });
    await fs.mkdir(this.artifactsDir, { recursive: true });

    await this.withDbClient('initialize', async (client) => {
      await client.query('SELECT 1');
    });

    log.info('Database connection verified');
    this.initialized = true;
  }

  async query<T = any>(text: string, params?: any[], retries = 3): Promise<{ rows: T[]; rowCount: number }> {
    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        return await this.withDbClient('query', async (client) => {
          const result = await client.query(text, params);
          return {
            rows: result.rows as T[],
            rowCount: result.rowCount ?? 0
          };
        });
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (attempt < retries) {
          log.warn({ attempt, retries, err: lastError }, 'Query attempt failed, retrying');
          await new Promise((resolve) => setTimeout(resolve, 100 * 2 ** attempt));
        }
      }
    }
    throw lastError ?? new Error('Query failed after retries');
  }

  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    return this.withDbClient('transaction', async (client) => {
      await client.query('BEGIN');
      try {
        const result = await callback(client);
        await client.query('COMMIT');
        return result;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    });
  }

  // Scan operations
  async insertScan(scan: Partial<ScanData>): Promise<void> {
    await this.query(`
      INSERT INTO scans (id, domain, status, created_at, completed_at, findings_count, artifacts_count, duration_ms, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      ON CONFLICT (id) DO UPDATE SET
        status = EXCLUDED.status,
        completed_at = EXCLUDED.completed_at,
        findings_count = EXCLUDED.findings_count,
        artifacts_count = EXCLUDED.artifacts_count,
        duration_ms = EXCLUDED.duration_ms,
        metadata = EXCLUDED.metadata
    `, [
      scan.id,
      scan.domain,
      scan.status,
      scan.created_at,
      scan.completed_at,
      scan.findings_count ?? 0,
      scan.artifacts_count ?? 0,
      scan.duration_ms,
      scan.metadata ? JSON.stringify(scan.metadata) : null
    ]);
  }

  async getScan(scanId: string): Promise<ScanData | null> {
    const result = await this.query<ScanData>(`
      SELECT id, domain, status, created_at, completed_at,
             findings_count, artifacts_count, duration_ms, metadata
      FROM scans WHERE id = $1
    `, [scanId]);
    if (!result.rows.length) return null;
    const scan = result.rows[0];
    scan.metadata = ensureJson(scan.metadata);
    return scan;
  }

  async getRecentScans(limit: number = 50): Promise<ScanData[]> {
    const result = await this.query<ScanData>(`
      SELECT id, domain, status, created_at, completed_at,
             findings_count, artifacts_count, duration_ms, metadata
      FROM scans ORDER BY created_at DESC LIMIT $1
    `, [limit]);
    return result.rows.map((row) => ({
      ...row,
      metadata: ensureJson(row.metadata)
    }));
  }

  // Finding operations
  async insertFinding(finding: Partial<FindingData>): Promise<void> {
    await this.query(`
      INSERT INTO findings (id, scan_id, type, severity, title, description, data, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (id) DO UPDATE SET
        type = EXCLUDED.type,
        severity = EXCLUDED.severity,
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        data = EXCLUDED.data
    `, [
      finding.id,
      finding.scan_id,
      finding.type,
      finding.severity,
      finding.title,
      finding.description,
      finding.data ? JSON.stringify(finding.data) : null,
      finding.created_at ?? new Date()
    ]);
  }

  async getFindingsByScanId(scanId: string): Promise<FindingData[]> {
    const result = await this.query<FindingData>(`
      SELECT id, scan_id, type, severity, title, description, data, created_at
      FROM findings WHERE scan_id = $1 ORDER BY created_at DESC
    `, [scanId]);
    return result.rows.map((row) => ({
      ...row,
      data: ensureJson(row.data)
    }));
  }

  async getFindingCount(scanId: string): Promise<number> {
    const result = await this.query<{ count: number }>('SELECT COUNT(*) AS count FROM findings WHERE scan_id = $1', [scanId]);
    return Number(result.rows[0]?.count ?? 0);
  }

  // Artifact operations
  async insertArtifact(artifact: Partial<ArtifactData>): Promise<void> {
    await this.query(`
      INSERT INTO artifacts (id, scan_id, type, file_path, size_bytes, created_at, severity, val_text, src_url, sha256, mime_type, metadata)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (id) DO UPDATE SET
        type = EXCLUDED.type,
        file_path = EXCLUDED.file_path,
        size_bytes = EXCLUDED.size_bytes,
        severity = EXCLUDED.severity,
        val_text = EXCLUDED.val_text,
        src_url = EXCLUDED.src_url,
        sha256 = EXCLUDED.sha256,
        mime_type = EXCLUDED.mime_type,
        metadata = EXCLUDED.metadata
    `, [
      artifact.id,
      artifact.scan_id,
      artifact.type,
      artifact.file_path,
      artifact.size_bytes ?? 0,
      artifact.created_at ?? new Date(),
      artifact.severity,
      artifact.val_text,
      artifact.src_url,
      artifact.sha256,
      artifact.mime_type,
      artifact.metadata ? JSON.stringify(artifact.metadata) : null
    ]);
  }

  async getArtifactCount(scanId: string): Promise<number> {
    const result = await this.query<{ count: number }>('SELECT COUNT(*) AS count FROM artifacts WHERE scan_id = $1', [scanId]);
    return Number(result.rows[0].count);
  }

  async getArtifactsByScanId(scanId: string, options?: { type?: string; severity?: string; limit?: number; offset?: number }): Promise<ArtifactData[]> {
    const conditions = ['scan_id = $1'];
    const params: unknown[] = [scanId];
    let paramIndex = 2;

    if (options?.type) {
      conditions.push(`type = $${paramIndex++}`);
      params.push(options.type);
    }
    if (options?.severity) {
      conditions.push(`severity = $${paramIndex++}`);
      params.push(options.severity);
    }

    let query = `
      SELECT id, scan_id, type, file_path, size_bytes, created_at, severity, val_text, src_url, sha256, mime_type, metadata
      FROM artifacts WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC
    `;

    if (options?.limit) {
      query += ` LIMIT $${paramIndex++}`;
      params.push(options.limit);
    }
    if (options?.offset) {
      query += ` OFFSET $${paramIndex++}`;
      params.push(options.offset);
    }

    const result = await this.query<ArtifactData>(query, params);
    return result.rows.map((row) => ({
      ...row,
      metadata: ensureJson(row.metadata)
    }));
  }

  // File operations
  async saveReport(scanId: string, report: Buffer, format: 'pdf' | 'html' = 'pdf', reportType: string = 'report'): Promise<string> {
    const scanDir = join(this.reportsDir, scanId);
    await fs.mkdir(scanDir, { recursive: true });
    const normalizedType = (reportType || 'report').toLowerCase();
    const filename = normalizedType === 'report' ? `report.${format}` : `${normalizedType}.${format}`;
    const filePath = join(scanDir, filename);
    await fs.writeFile(filePath, report);
    return filePath;
  }

  async saveArtifact(scanId: string, filename: string, data: Buffer): Promise<string> {
    const scanDir = join(this.artifactsDir, scanId);
    await fs.mkdir(scanDir, { recursive: true });
    const filePath = join(scanDir, filename);
    await fs.writeFile(filePath, data);
    return filePath;
  }

  async getReportPath(scanId: string, format: 'pdf' | 'html' = 'pdf', reportType: string = 'report'): Promise<string | null> {
    const normalizedType = (reportType || 'report').toLowerCase();
    const fileName = normalizedType === 'report' ? `report.${format}` : `${normalizedType}.${format}`;
    const reportPath = join(this.reportsDir, scanId, fileName);
    try {
      await fs.access(reportPath);
      return reportPath;
    } catch {
      return null;
    }
  }

  async healthCheck(): Promise<{ status: 'ok' | 'error'; details: any }> {
    try {
      const result = await this.query('SELECT NOW() AS timestamp');
      return {
        status: 'ok',
        details: {
          timestamp: result.rows[0]?.timestamp,
          pool_total: this.pool.totalCount,
          pool_idle: this.pool.idleCount,
          pool_waiting: this.pool.waitingCount
        }
      };
    } catch (error) {
      return {
        status: 'error',
        details: { error: error instanceof Error ? error.message : 'Unknown error' }
      };
    }
  }

  async close(): Promise<void> {
    try {
      await this.pool.end();
    } catch (error) {
      log.error({ err: error }, 'Error closing pool');
    }
    try {
      await resourceGovernor.shutdown();
    } catch (error) {
      log.error({ err: error }, 'Error shutting down resource governor');
    }
    this.pool = this.createPool();
    this.initialized = false;
    log.info('Database connections closed');
  }

  get poolStats() {
    return {
      total: this.pool.totalCount,
      idle: this.pool.idleCount,
      waiting: this.pool.waitingCount
    };
  }

  // Public slug operations for simplcyber.com/reports hosting
  async generatePublicSlug(scanId: string, companyName: string): Promise<string> {
    // Generate slug using database function
    const result = await this.query<{ slug: string }>(
      'SELECT generate_public_slug($1) AS slug',
      [companyName || 'report']
    );
    const slug = result.rows[0]?.slug;
    if (!slug) {
      throw new Error('Failed to generate public slug');
    }

    // Update the scan with the public slug
    await this.query(
      'UPDATE scans SET public_slug = $1 WHERE id = $2',
      [slug, scanId]
    );

    return slug;
  }

  async getPublicSlug(scanId: string): Promise<string | null> {
    const result = await this.query<{ public_slug: string | null }>(
      'SELECT public_slug FROM scans WHERE id = $1',
      [scanId]
    );
    return result.rows[0]?.public_slug ?? null;
  }

  async getScanByPublicSlug(publicSlug: string): Promise<ScanData | null> {
    const result = await this.query<ScanData>(`
      SELECT id, domain, status, created_at, completed_at,
             findings_count, artifacts_count, duration_ms, metadata
      FROM scans WHERE public_slug = $1
    `, [publicSlug]);
    if (!result.rows.length) return null;
    const scan = result.rows[0];
    scan.metadata = ensureJson(scan.metadata);
    return scan;
  }

  async setPublicSlug(scanId: string, publicSlug: string): Promise<void> {
    await this.query(
      'UPDATE scans SET public_slug = $1 WHERE id = $2',
      [publicSlug, scanId]
    );
  }
}

export const database = new DatabaseService();
