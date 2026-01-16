/**
 * Shared type definitions used across the scanner
 */

// =============================================================================
// Severity Types
// =============================================================================

/**
 * Standard severity levels for findings (ordered from most to least severe)
 */
export const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

/**
 * Severity type derived from SEVERITY_LEVELS constant
 */
export type Severity = (typeof SEVERITY_LEVELS)[number];

/**
 * Alias for Severity (used in some modules)
 */
export type SeverityKey = Severity;

/**
 * Extended severity that includes 'OK' for TLS scan results
 */
export type TlsSeverity = Severity | 'OK';

/**
 * Severity weights for scoring calculations
 */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 1.0,
  HIGH: 0.6,
  MEDIUM: 0.35,
  LOW: 0.15,
  INFO: 0,
} as const;

/**
 * Severity order index (lower = more severe)
 */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
} as const;

/**
 * Check if a string is a valid severity level
 */
export function isValidSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && SEVERITY_LEVELS.includes(value as Severity);
}

/**
 * Normalize a severity string to a valid Severity type
 * Returns 'INFO' for invalid/unknown values
 */
export function normalizeSeverity(value: unknown): Severity {
  if (typeof value !== 'string') return 'INFO';
  const upper = value.toUpperCase();
  return isValidSeverity(upper) ? upper : 'INFO';
}

/**
 * Compare two severities, returns negative if a is more severe than b
 */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b];
}

/**
 * Get the more severe of two severity levels
 */
export function maxSeverity(a: Severity, b: Severity): Severity {
  return compareSeverity(a, b) <= 0 ? a : b;
}

// =============================================================================
// Finding Status
// =============================================================================

/**
 * Scan status values
 */
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

/**
 * Module execution status values
 */
export type ModuleStatus = 'success' | 'partial' | 'failed' | 'skipped';
