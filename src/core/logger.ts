import pino, { Logger } from 'pino';

// Determine environment
const isDev = process.env.NODE_ENV !== 'production';

// Configure pino transport
const transport = isDev
  ? {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'HH:MM:ss.l',
        ignore: 'pid,hostname',
        singleLine: false,
      },
    }
  : undefined;

// Create base logger
export const logger = pino({
  level: process.env.LOG_LEVEL?.toLowerCase() || 'info',
  transport,
  formatters: {
    level: (label) => ({ level: label }),
  },
  base: {
    service: 'scanner-workers',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: ['*.password', '*.apiKey', '*.token', '*.secret', '*.credential', '*.auth'],
    censor: '[REDACTED]',
  },
});

// Child logger factory for modules
export function createModuleLogger(module: string): Logger {
  return logger.child({ module });
}

// Re-export log level enum for backward compatibility
export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
}

// Structured logging interface (matches existing LogContext)
export interface LogContext {
  module?: string;
  scanId?: string;
  domain?: string;
  action?: string;
  duration?: number;
  error?: Error;
  [key: string]: unknown;
}

// Legacy support - keep old interface for gradual migration
export function logLegacy(...args: unknown[]) {
  logger.info({ legacy: true }, args.map(String).join(' '));
}

// Backward-compatible functions that match existing interface
export function log(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.info({ err, ...rest }, message);
  } else {
    logger.info(rest, message);
  }
}

export function debug(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.debug({ err, ...rest }, message);
  } else {
    logger.debug(rest, message);
  }
}

export function info(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.info({ err, ...rest }, message);
  } else {
    logger.info(rest, message);
  }
}

export function warn(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.warn({ err, ...rest }, message);
  } else {
    logger.warn(rest, message);
  }
}

export function error(message: string, context?: LogContext) {
  const { error: err, ...rest } = context || {};
  if (err) {
    logger.error({ err, ...rest }, message);
  } else {
    logger.error(rest, message);
  }
}
