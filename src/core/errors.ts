/**
 * Structured error codes and helpers for consistent API error responses
 *
 * Error code format: CATEGORY_SPECIFIC_ERROR
 * Categories:
 * - AUTH: Authentication/authorization errors
 * - VALIDATION: Input validation errors
 * - SCAN: Scan-related errors
 * - QUEUE: Queue/job errors
 * - REPORT: Report generation errors
 * - RESOURCE: Resource/service availability errors
 * - INTERNAL: Internal server errors
 */

export const ErrorCode = {
  // Authentication (401)
  AUTH_MISSING_KEY: 'AUTH_MISSING_KEY',
  AUTH_INVALID_KEY: 'AUTH_INVALID_KEY',

  // Validation (400)
  VALIDATION_MISSING_FIELD: 'VALIDATION_MISSING_FIELD',
  VALIDATION_INVALID_DOMAIN: 'VALIDATION_INVALID_DOMAIN',
  VALIDATION_INVALID_EMAIL: 'VALIDATION_INVALID_EMAIL',
  VALIDATION_INVALID_FORMAT: 'VALIDATION_INVALID_FORMAT',
  VALIDATION_INVALID_OPTION: 'VALIDATION_INVALID_OPTION',
  VALIDATION_INVALID_URL: 'VALIDATION_INVALID_URL',

  // Scan (400/404/500)
  SCAN_NOT_FOUND: 'SCAN_NOT_FOUND',
  SCAN_ALREADY_EXISTS: 'SCAN_ALREADY_EXISTS',
  SCAN_FAILED: 'SCAN_FAILED',
  SCAN_CANCELLED: 'SCAN_CANCELLED',
  SCAN_TIMEOUT: 'SCAN_TIMEOUT',

  // Queue (500/503)
  QUEUE_FULL: 'QUEUE_FULL',
  QUEUE_ERROR: 'QUEUE_ERROR',
  QUEUE_JOB_NOT_FOUND: 'QUEUE_JOB_NOT_FOUND',

  // Report (400/404/500)
  REPORT_NOT_FOUND: 'REPORT_NOT_FOUND',
  REPORT_GENERATION_FAILED: 'REPORT_GENERATION_FAILED',
  REPORT_INVALID_TYPE: 'REPORT_INVALID_TYPE',
  REPORT_INVALID_FORMAT: 'REPORT_INVALID_FORMAT',

  // Resource (503)
  RESOURCE_SERVICE_NOT_READY: 'RESOURCE_SERVICE_NOT_READY',
  RESOURCE_DATABASE_ERROR: 'RESOURCE_DATABASE_ERROR',
  RESOURCE_REDIS_ERROR: 'RESOURCE_REDIS_ERROR',
  RESOURCE_RATE_LIMITED: 'RESOURCE_RATE_LIMITED',

  // Internal (500)
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  INTERNAL_UNEXPECTED: 'INTERNAL_UNEXPECTED',
} as const;

export type ErrorCodeType = typeof ErrorCode[keyof typeof ErrorCode];

/**
 * Structured API error response
 */
export interface ApiError {
  error: string;
  code: ErrorCodeType;
  message?: string;
  details?: Record<string, unknown>;
}

/**
 * Create a structured error response
 */
export function createError(
  code: ErrorCodeType,
  error: string,
  options?: {
    message?: string;
    details?: Record<string, unknown>;
  }
): ApiError {
  return {
    error,
    code,
    ...(options?.message && { message: options.message }),
    ...(options?.details && { details: options.details }),
  };
}

/**
 * Common error responses
 */
export const Errors = {
  unauthorized: (message?: string) =>
    createError(ErrorCode.AUTH_INVALID_KEY, 'Unauthorized - Invalid or missing API key', { message }),

  missingField: (field: string) =>
    createError(ErrorCode.VALIDATION_MISSING_FIELD, `${field} is required`, {
      details: { field },
    }),

  invalidDomain: (domain?: string) =>
    createError(ErrorCode.VALIDATION_INVALID_DOMAIN, 'Invalid domain format', {
      details: domain ? { domain } : undefined,
    }),

  invalidEmail: (email?: string) =>
    createError(ErrorCode.VALIDATION_INVALID_EMAIL, 'Invalid email format', {
      details: email ? { email } : undefined,
    }),

  invalidOption: (field: string, validOptions: string[]) =>
    createError(ErrorCode.VALIDATION_INVALID_OPTION, `Invalid ${field}. Must be one of: ${validOptions.join(', ')}`, {
      details: { field, valid_options: validOptions },
    }),

  invalidFormat: (field: string, expected: string) =>
    createError(ErrorCode.VALIDATION_INVALID_FORMAT, `Invalid ${field}. ${expected}`, {
      details: { field, expected },
    }),

  invalidUrl: (field: string) =>
    createError(ErrorCode.VALIDATION_INVALID_URL, `Invalid ${field}. Must be a valid HTTP/HTTPS URL`, {
      details: { field },
    }),

  scanNotFound: (scanId?: string) =>
    createError(ErrorCode.SCAN_NOT_FOUND, 'Scan not found', {
      details: scanId ? { scan_id: scanId } : undefined,
    }),

  scanFailed: (message?: string, scanId?: string) =>
    createError(ErrorCode.SCAN_FAILED, 'Scan failed', {
      message,
      details: scanId ? { scan_id: scanId } : undefined,
    }),

  reportNotFound: (scanId?: string, reportType?: string) =>
    createError(ErrorCode.REPORT_NOT_FOUND, 'Report not found', {
      details: { scan_id: scanId, report_type: reportType },
    }),

  reportGenerationFailed: (message?: string) =>
    createError(ErrorCode.REPORT_GENERATION_FAILED, 'Report generation failed', { message }),

  reportInvalidType: (validTypes: string[]) =>
    createError(ErrorCode.REPORT_INVALID_TYPE, 'Report type not found', {
      details: { valid_types: validTypes },
    }),

  reportInvalidFormat: (validFormats: string[]) =>
    createError(ErrorCode.REPORT_INVALID_FORMAT, `Unsupported report format. Use ${validFormats.join(', ')}`, {
      details: { valid_formats: validFormats },
    }),

  serviceNotReady: (message?: string) =>
    createError(ErrorCode.RESOURCE_SERVICE_NOT_READY, 'Service not ready', { message }),

  queueFull: () =>
    createError(ErrorCode.QUEUE_FULL, 'Queue is full. Please try again later.'),

  rateLimited: (retryAfter?: number) =>
    createError(ErrorCode.RESOURCE_RATE_LIMITED, 'Rate limit exceeded', {
      details: retryAfter ? { retry_after_seconds: retryAfter } : undefined,
    }),

  internal: (message?: string) =>
    createError(ErrorCode.INTERNAL_ERROR, 'Internal server error', { message }),
} as const;
