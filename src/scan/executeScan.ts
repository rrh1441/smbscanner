/**
 * Execute Scan - Orchestrates scan execution
 */

import { processScan } from '../worker.js';

export interface ScanJob {
  scanId: string;
  domain: string;
  companyName?: string;
  profile?: string;
  tier?: 'tier1' | 'tier2';
  modules?: string[];
  skipModules?: string[];
  timeoutMs?: number;
  callbackUrl?: string;
  createdAt?: string;
}

export interface ScanRequest {
  scanId?: string;
  scan_id?: string; // Alias for compatibility
  domain: string;
  companyName?: string;
  profile?: string;
  tier?: 'tier1' | 'tier2';
  modules?: string[];
  skipModules?: string[];
  timeoutMs?: number;
  callbackUrl?: string;
}

export interface ScanResult {
  scanId: string;
  status: 'completed' | 'failed' | 'timeout';
  totalFindings: number;
  duration: number;
  error?: string;
  metadata?: Record<string, any>;
}

/**
 * Execute a scan with the given configuration
 */
export async function executeScan(request: ScanRequest): Promise<ScanResult> {
  const startTime = Date.now();

  try {
    await processScan({
      scanId: request.scanId || request.scan_id || '',
      domain: request.domain,
      companyName: request.companyName || request.domain,
      createdAt: new Date().toISOString()
    });

    return {
      scanId: request.scanId,
      status: 'completed',
      totalFindings: 0, // Would be populated from database
      duration: Date.now() - startTime,
      metadata: {}
    };
  } catch (error) {
    return {
      scanId: request.scanId,
      status: 'failed',
      totalFindings: 0,
      duration: Date.now() - startTime,
      error: (error as Error).message,
      metadata: {}
    };
  }
}

export default { executeScan };
