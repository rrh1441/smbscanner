/**
 * Shared validation utilities for input sanitization
 * Used across API endpoints and scanning modules for defense-in-depth
 */

/**
 * Strict domain validation regex
 * Allows: alphanumeric, hyphens, dots
 * Requires: at least one dot, valid TLD (2+ chars)
 * Blocks: consecutive dots/hyphens, starting/ending with dot/hyphen
 */
const DOMAIN_REGEX = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i;

/**
 * Maximum domain length per RFC 1035
 */
const MAX_DOMAIN_LENGTH = 253;

/**
 * Validate that a string is a legitimate domain name
 * This is a strict check designed to prevent command injection
 */
export function isValidDomain(domain: unknown): domain is string {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > MAX_DOMAIN_LENGTH || domain.length < 4) return false;

  // Must match strict domain pattern
  if (!DOMAIN_REGEX.test(domain)) return false;

  // Additional safety checks
  if (domain.includes('..') || domain.includes('--')) return false;

  // Block common shell metacharacters that might slip through
  if (/[;&|`$(){}[\]<>\\!#*?~]/.test(domain)) return false;

  return true;
}

/**
 * Normalize and validate a domain input
 * Strips protocol, path, and converts to lowercase
 * Returns null if invalid
 */
export function normalizeDomain(rawDomain: unknown): string | null {
  if (!rawDomain || typeof rawDomain !== 'string') return null;

  // Strip protocol and path
  const normalized = rawDomain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .replace(/^www\./, '');

  if (!isValidDomain(normalized)) return null;

  return normalized;
}

/**
 * Assert that a domain is valid, throwing if not
 * Use this in scanning modules for defense-in-depth
 */
export function assertValidDomain(domain: unknown, context?: string): asserts domain is string {
  if (!isValidDomain(domain)) {
    const msg = context
      ? `Invalid domain in ${context}: ${String(domain).slice(0, 50)}`
      : `Invalid domain: ${String(domain).slice(0, 50)}`;
    throw new Error(msg);
  }
}

/**
 * Validate email format
 */
export function isValidEmail(email: unknown): email is string {
  if (!email || typeof email !== 'string') return false;
  // Basic email validation - local@domain format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}

/**
 * Validate and bound a numeric parameter
 */
export function validateNumericParam(
  value: unknown,
  defaultValue: number,
  min: number,
  max: number
): number {
  const num = Number(value);
  if (isNaN(num)) return defaultValue;
  return Math.max(min, Math.min(max, Math.floor(num)));
}
