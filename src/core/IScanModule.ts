/**
 * IScanModule - Standard interface for scanner modules
 *
 * All scanner modules should implement this interface to ensure
 * consistent behavior and make modules easily discoverable and testable.
 */

export interface ScanJob {
  /** Target domain to scan */
  domain: string;
  /** Unique scan identifier */
  scanId: string;
  /** Optional company name for context */
  companyName?: string;
  /** Scan tier (tier1 = quick, tier2 = deep) */
  tier?: 'tier1' | 'tier2';
  /** Additional module-specific options */
  options?: Record<string, unknown>;
}

export interface ScanResult {
  /** Number of findings/artifacts created */
  findingsCount: number;
  /** Module execution status */
  status: 'success' | 'partial' | 'failed' | 'skipped';
  /** Error message if failed */
  error?: string;
  /** Execution duration in milliseconds */
  durationMs?: number;
  /** Additional result metadata */
  metadata?: Record<string, unknown>;
}

export interface ModuleMetadata {
  /** Unique module identifier (e.g., 'shodan', 'tls_scan') */
  id: string;
  /** Human-readable module name */
  name: string;
  /** Brief description of what the module does */
  description: string;
  /** Module category */
  category: 'reconnaissance' | 'vulnerability' | 'exposure' | 'infrastructure' | 'secrets' | 'compliance';
  /** Which tiers this module runs in */
  tiers: ('tier1' | 'tier2')[];
  /** Required environment variables */
  requiredEnvVars?: string[];
  /** Optional environment variables */
  optionalEnvVars?: string[];
  /** External tools required (e.g., 'nuclei', 'nmap') */
  requiredTools?: string[];
  /** Estimated duration range */
  estimatedDuration?: { min: number; max: number };
  /** Risk level of running this module */
  riskLevel?: 'low' | 'medium' | 'high';
}

/**
 * Standard scanner module interface
 *
 * Example implementation:
 * ```typescript
 * import { IScanModule, ScanJob, ScanResult, ModuleMetadata } from '../core/IScanModule.js';
 *
 * export const metadata: ModuleMetadata = {
 *   id: 'example_scan',
 *   name: 'Example Scanner',
 *   description: 'Scans for example vulnerabilities',
 *   category: 'vulnerability',
 *   tiers: ['tier1'],
 * };
 *
 * export async function run(job: ScanJob): Promise<ScanResult> {
 *   const startTime = Date.now();
 *   // ... scanning logic ...
 *   return {
 *     findingsCount: 0,
 *     status: 'success',
 *     durationMs: Date.now() - startTime,
 *   };
 * }
 * ```
 */
export interface IScanModule {
  /** Module metadata for discovery and documentation */
  metadata: ModuleMetadata;

  /**
   * Execute the scan
   * @param job - Scan job parameters
   * @returns Scan result with findings count and status
   */
  run(job: ScanJob): Promise<ScanResult>;

  /**
   * Optional: Check if module can run (dependencies, env vars, etc.)
   * @returns true if module is ready to run
   */
  canRun?(): Promise<boolean>;

  /**
   * Optional: Validate job parameters before running
   * @param job - Scan job to validate
   * @returns Validation errors or empty array if valid
   */
  validateJob?(job: ScanJob): string[];
}

/**
 * Helper to create a module that conforms to IScanModule
 */
export function defineModule(
  metadata: ModuleMetadata,
  run: (job: ScanJob) => Promise<ScanResult>,
  options?: {
    canRun?: () => Promise<boolean>;
    validateJob?: (job: ScanJob) => string[];
  }
): IScanModule {
  return {
    metadata,
    run,
    canRun: options?.canRun,
    validateJob: options?.validateJob,
  };
}

/**
 * Type guard to check if an object implements IScanModule
 */
export function isValidModule(obj: unknown): obj is IScanModule {
  if (!obj || typeof obj !== 'object') return false;
  const module = obj as IScanModule;
  return (
    typeof module.metadata === 'object' &&
    typeof module.metadata.id === 'string' &&
    typeof module.metadata.name === 'string' &&
    typeof module.run === 'function'
  );
}
