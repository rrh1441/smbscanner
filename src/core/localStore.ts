import { promises as fs } from 'fs';
import { join } from 'path';
import { database, ScanData, FindingData, ArtifactData } from './database.js';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('localStore');

export class LocalStore {
  private readonly reportsDir = './scan-reports';
  private readonly artifactsDir = './scan-artifacts';
  private initialized = false;

  constructor() {
    void this.init();
  }

  private async init(): Promise<void> {
    if (this.initialized) return;
    await database.initialize();
    await fs.mkdir(this.reportsDir, { recursive: true });
    await fs.mkdir(this.artifactsDir, { recursive: true });
    log.debug('Ready (delegates to DatabaseService)');
    this.initialized = true;
  }

  async query<T = any>(text: string, params?: any[]): Promise<{ rows: T[]; rowCount: number }> {
    await this.init();
    return database.query<T>(text, params);
  }

  async insertScan(scan: Partial<ScanData>): Promise<void> {
    await this.init();
    await database.insertScan(scan);
  }

  async insertFinding(finding: Partial<FindingData>): Promise<void> {
    await this.init();
    await database.insertFinding(finding);
  }

  async insertArtifact(artifact: Partial<ArtifactData>): Promise<void> {
    await this.init();
    await database.insertArtifact(artifact);
  }

  async getScan(scanId: string): Promise<ScanData | null> {
    await this.init();
    return database.getScan(scanId);
  }

  async getRecentScans(limit: number = 50): Promise<ScanData[]> {
    await this.init();
    return database.getRecentScans(limit);
  }

  async getFindingsByScanId(scanId: string): Promise<FindingData[]> {
    await this.init();
    return database.getFindingsByScanId(scanId);
  }

  async getFindingCount(scanId: string): Promise<number> {
    await this.init();
    return database.getFindingCount(scanId);
  }

  async getArtifactCount(scanId: string): Promise<number> {
    await this.init();
    return database.getArtifactCount(scanId);
  }

  async saveReport(scanId: string, report: Buffer, format: 'pdf' | 'html' = 'pdf', reportType: string = 'report'): Promise<string> {
    await this.init();
    return database.saveReport(scanId, report, format, reportType);
  }

  async saveArtifact(scanId: string, filename: string, data: Buffer): Promise<string> {
    await this.init();
    return database.saveArtifact(scanId, filename, data);
  }
  async close(): Promise<void> {
    // Intentionally no-op: database is a shared singleton managed by the server lifecycle.
    // Closing it mid-scan can tear down the ResourceGovernor and disrupt other jobs.
    return;
  }

}
