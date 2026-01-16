/**
 * LOCAL SQLITE ONLY - NO GCP FIRESTORE
 * Artifact store with exact GCP function signatures but LOCAL SQLite backend
 */

import { LocalStore } from './localStore.js';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('artifactStoreLocal');

// Global store instance
let store: LocalStore | null = null;

// In-memory mapping for numeric ID to string artifact ID compatibility
const artifactIdMap: Map<number, string> = new Map();

function getStore(): LocalStore {
  if (!store) {
    store = new LocalStore();
  }
  return store;
}

// Stub pool for backward compatibility
export const pool = {
  query: async () => ({ rows: [] }),
  connect: async () => ({ release: () => {} }),
  end: async () => {}
};

export interface ArtifactInput {
  type: string;
  val_text: string;
  severity: string;
  src_url?: string;
  sha256?: string;
  mime?: string;
  meta?: any;
  description?: string;
  repro_command?: string;
}

// EXACT SAME FUNCTION SIGNATURES AS GCP VERSION
// But uses SQLite instead of Firestore

// Function overloads for insertArtifact backward compatibility
export function insertArtifact(artifact: ArtifactInput): Promise<number>;
export function insertArtifact(
  type: string,
  val_text: string,
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  meta?: any
): Promise<number>;
export function insertArtifact(
  type: string,
  val_text: string,
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  meta: any,
  unused?: any
): Promise<number>;
export async function insertArtifact(
  artifactOrType: ArtifactInput | string,
  val_text?: string,
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO',
  meta?: any,
  unused?: any
): Promise<number> {
  // Handle legacy 4 or 5 parameter calls
  if (typeof artifactOrType === 'string') {
    const artifact: ArtifactInput = {
      type: artifactOrType,
      val_text: val_text || '',
      severity: severity || 'INFO',
      meta: meta || {}
    };
    return insertArtifactInternal(artifact);
  }
  
  // Handle new single-parameter calls
  return insertArtifactInternal(artifactOrType as ArtifactInput);
}

async function insertArtifactInternal(artifact: ArtifactInput): Promise<number> {
  try {
    const scan_id = artifact.meta?.scan_id;
    log.debug({ type: artifact.type, severity: artifact.severity, scan_id: scan_id || 'MISSING', val_text_length: artifact.val_text?.length || 0 }, 'Inserting artifact');

    // Ensure we have a valid scan_id
    if (!scan_id || scan_id === 'unknown') {
      log.error({ meta: artifact.meta }, 'Artifact missing scan_id');
      return -1;
    }
    
    const artifactData = {
      id: `artifact_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      scan_id: scan_id,
      type: artifact.type,
      file_path: `${artifact.type}_${Date.now()}.txt`,
      size_bytes: Buffer.byteLength(artifact.val_text || '', 'utf8'),
      severity: artifact.severity,
      val_text: artifact.val_text,
      src_url: artifact.src_url,
      sha256: artifact.sha256,
      mime_type: artifact.mime,
      metadata: artifact.meta,
      created_at: new Date()
    };
    
    await getStore().insertArtifact(artifactData);
    log.debug({ type: artifactData.type, scan_id: artifactData.scan_id }, 'Inserted artifact');
    
    // Store mapping for lookup compatibility and return numeric ID
    const numericId = Date.now() + Math.floor(Math.random() * 1000);
    artifactIdMap.set(numericId, artifactData.id);
    return numericId;
  } catch (error: any) {
    log.error({ err: error, artifact_type: artifact?.type }, 'Failed to insert artifact');
    // Don't throw - log and continue to prevent scan failure
    return -1;
  }
}

// Stub for compatibility
export async function initializeDatabase(): Promise<void> {
  log.debug('Using SQLite - initialization handled by LocalStore');
}

// Function overloads for insertFinding backward compatibility
export function insertFinding(finding: any): Promise<number>;
export function insertFinding(
  artifactId: number,
  findingType: string,
  recommendation: string,
  description?: string,
  reproCommand?: string
): Promise<number>;
export async function insertFinding(
  findingOrArtifactId: any | number,
  findingType?: string,
  recommendation?: string,
  description?: string,
  reproCommand?: string
): Promise<number> {
  // Handle legacy 4 or 5 parameter calls
  if (typeof findingOrArtifactId === 'number' && findingType) {
    // Look up scan_id and severity from the artifact using the mapping
    let scanId = 'unknown';
    let severity = 'MEDIUM'; // fallback
    try {
      const store = getStore();

      // First try the in-memory mapping for recent artifacts
      const actualArtifactId = artifactIdMap.get(findingOrArtifactId);
      if (actualArtifactId) {
        const result = await store.query('SELECT scan_id, severity FROM artifacts WHERE id = $1', [actualArtifactId]);
        if (result.rows.length > 0) {
          scanId = result.rows[0].scan_id;
          severity = result.rows[0].severity || 'MEDIUM';
        }
      } else {
        // Fallback: try direct lookup (shouldn't work but just in case)
        const result = await store.query('SELECT scan_id, severity FROM artifacts WHERE id = $1', [findingOrArtifactId]);
        if (result.rows.length > 0) {
          scanId = result.rows[0].scan_id;
          severity = result.rows[0].severity || 'MEDIUM';
        }
      }
    } catch (error) {
      log.error({ err: error }, 'Error looking up scan_id/severity for artifact');
    }

    const finding = {
      artifact_id: findingOrArtifactId,
      finding_type: findingType,
      recommendation: recommendation || '',
      description: description || '',
      repro_command: reproCommand || null,
      scan_id: scanId,
      severity: severity,
      type: findingType
    };
    return insertFindingInternal(finding);
  }
  
  // Handle new single-parameter calls
  return insertFindingInternal(findingOrArtifactId);
}

async function insertFindingInternal(finding: any): Promise<number> {
  try {
    log.debug({ type: finding.type || finding.finding_type, severity: finding.severity, scan_id: finding.scan_id, title: finding.title || finding.recommendation }, 'Inserting finding');

    // Ensure we have a valid scan_id
    if (!finding.scan_id || finding.scan_id === 'unknown') {
      log.error({ finding }, 'Finding missing scan_id');
      return -1;
    }
    
    const findingData = {
      id: `finding_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      scan_id: finding.scan_id,
      type: finding.type || finding.finding_type,
      severity: finding.severity || 'MEDIUM',
      title: finding.title || finding.recommendation || finding.description?.substring(0, 100) || 'Security Finding',
      description: finding.description || finding.recommendation || '',
      data: {
        ...finding.data,
        artifact_id: finding.artifact_id,
        repro_command: finding.repro_command,
        meta: finding.meta
      },
      created_at: new Date()
    };
    
    await getStore().insertFinding(findingData);
    log.debug({ type: findingData.type, severity: findingData.severity, scan_id: findingData.scan_id }, 'Inserted finding');

    // Return a fake numeric ID for compatibility
    return Date.now();
  } catch (error: any) {
    log.error({ err: error, finding_type: finding?.type }, 'Failed to insert finding');
    // Don't throw - log and continue to prevent scan failure
    return -1;
  }
}