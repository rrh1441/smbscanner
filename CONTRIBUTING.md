# Contributing to Scanner-OSS

Thank you for your interest in contributing to Scanner-OSS! This document provides guidelines for contributing new scanner modules and other improvements.

## Table of Contents

- [Creating a New Scanner Module](#creating-a-new-scanner-module)
- [Module Interface](#module-interface)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Code Style](#code-style)

## Creating a New Scanner Module

Scanner modules are located in `src/modules/`. Each module performs a specific type of security scan and produces findings/artifacts.

### Quick Start

1. Create a new file in `src/modules/` (e.g., `myScanner.ts`)
2. Implement the module using the template below
3. Add your module to the scan executor in `src/scan/executeScan.ts`
4. Test locally before submitting a PR

### Module Template

```typescript
/**
 * MODULE: myScanner.ts
 *
 * Brief description of what this module scans for.
 */

import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { Severity } from '../core/types.js';
import { httpClient } from '../net/httpClient.js';

const log = createModuleLogger('myScanner');

// Module configuration
const CONFIG = {
  TIMEOUT_MS: 10_000,
  MAX_RETRIES: 3,
} as const;

interface RunJob {
  domain: string;
  scanId: string;
  tier?: 'tier1' | 'tier2';
}

interface ScanResult {
  findingsCount: number;
  artifactsCount: number;
  status: 'success' | 'partial' | 'failed' | 'skipped';
  error?: string;
}

/**
 * Main entry point for the scanner module
 */
export async function run(job: RunJob): Promise<ScanResult> {
  const { domain, scanId, tier = 'tier1' } = job;
  const startTime = Date.now();

  log.info({ domain, scanId, tier }, 'Starting scan');

  try {
    // 1. Perform your scanning logic
    const findings = await performScan(domain);

    // 2. Store findings
    let findingsCount = 0;
    for (const finding of findings) {
      await insertFinding({
        scan_id: scanId,
        type: 'MY_FINDING_TYPE',
        severity: finding.severity,
        title: finding.title,
        description: finding.description,
        remediation: finding.remediation,
        evidence: finding.evidence,
        metadata: finding.metadata,
      });
      findingsCount++;
    }

    // 3. Store artifacts (raw data)
    await insertArtifact({
      scan_id: scanId,
      type: 'my_scanner_results',
      content: JSON.stringify({ findings, scanned_at: new Date().toISOString() }),
    });

    const duration = Date.now() - startTime;
    log.info({ domain, scanId, findingsCount, duration_ms: duration }, 'Scan completed');

    return {
      findingsCount,
      artifactsCount: 1,
      status: 'success',
    };
  } catch (error: any) {
    log.error({ err: error, domain, scanId }, 'Scan failed');
    return {
      findingsCount: 0,
      artifactsCount: 0,
      status: 'failed',
      error: error.message,
    };
  }
}

/**
 * Core scanning logic - implement your specific scan here
 */
async function performScan(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Example: HTTP request to target
  const url = `https://${domain}/`;
  const response = await httpClient.get(url, {
    timeout: CONFIG.TIMEOUT_MS,
    maxRedirects: 3,
  });

  // Analyze response and create findings
  // ...

  return findings;
}

interface Finding {
  severity: Severity;
  title: string;
  description: string;
  remediation?: string;
  evidence?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}
```

## Module Interface

For modules that need to expose a standard interface for discovery and testing, use the `IScanModule` interface:

```typescript
import { IScanModule, ScanJob, ScanResult, ModuleMetadata } from '../core/IScanModule.js';

export const metadata: ModuleMetadata = {
  id: 'my_scanner',
  name: 'My Scanner',
  description: 'Scans for specific vulnerabilities',
  category: 'vulnerability',  // reconnaissance | vulnerability | exposure | infrastructure | secrets | compliance
  tiers: ['tier1', 'tier2'],
  requiredEnvVars: ['MY_API_KEY'],  // Optional: list required env vars
  optionalEnvVars: ['MY_TIMEOUT'],   // Optional: list optional env vars
  requiredTools: [],                  // Optional: external tools needed
  riskLevel: 'low',                   // low | medium | high
};

export async function run(job: ScanJob): Promise<ScanResult> {
  // Implementation
}
```

## Best Practices

### Security

- **Never trust user input** - Always validate and sanitize domain names
- **Use safe execution** - Use `execFileAsync` instead of `exec` to avoid command injection
- **Validate binary paths** - Check that external tools are from trusted locations
- **Handle credentials safely** - Never log API keys or credentials

```typescript
import { isValidDomain, normalizeDomain } from '../core/validation.js';

// Always validate domains before use
const normalized = normalizeDomain(domain);
if (!normalized) {
  throw new Error('Invalid domain');
}
```

### Logging

Use structured logging with the module logger:

```typescript
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('myScanner');

// Good - structured logging with context
log.info({ domain, scanId, findingsCount: 5 }, 'Scan completed');

// Avoid - unstructured messages
console.log(`Scan completed for ${domain}`);
```

### Error Handling

- Always catch and handle errors gracefully
- Return meaningful status codes ('success', 'partial', 'failed', 'skipped')
- Log errors with full context for debugging

```typescript
try {
  // Scan logic
} catch (error: any) {
  log.error({ err: error, domain, scanId }, 'Scan failed');
  return { status: 'failed', error: error.message, findingsCount: 0 };
}
```

### Timeouts

- Always set reasonable timeouts for network requests
- Use module-specific timeout configuration
- Consider using the environment variable pattern for configurability

```typescript
import { moduleTimeouts } from '../core/env.js';

const TIMEOUT_MS = moduleTimeouts.my_scanner ?? 10000;
```

### Rate Limiting

Be mindful of rate limits when calling external APIs:

```typescript
import { rateLimits } from '../core/env.js';

// Use rate limit configuration
const requestsPerSecond = rateLimits.MY_API_RPS ?? 1;
```

## Severity Levels

Use consistent severity levels from `src/core/types.ts`:

| Severity | Use Case |
|----------|----------|
| CRITICAL | Actively exploitable, data at risk |
| HIGH | Significant security weakness |
| MEDIUM | Security concern requiring attention |
| LOW | Minor security improvement |
| INFO | Informational finding, no action needed |

```typescript
import { Severity } from '../core/types.js';

const severity: Severity = 'HIGH';
```

## Testing

### Local Testing

1. Set up required environment variables in `.env`
2. Start the local server: `npm run dev`
3. Test your module: `curl -X POST http://localhost:8080/scan -d '{"domain":"example.com"}'`

### Unit Tests

Place tests in `src/modules/__tests__/` following the naming convention `myScanner.test.ts`.

## Code Style

- Use TypeScript strict mode where possible
- Follow existing code patterns in the repository
- Use meaningful variable and function names
- Add JSDoc comments for public functions
- Keep modules focused - one responsibility per module

## Pull Request Checklist

- [ ] Module follows the template structure
- [ ] Logging uses `createModuleLogger`
- [ ] Domain validation is performed
- [ ] Timeouts are configured
- [ ] Error handling returns appropriate status
- [ ] No credentials or API keys in code
- [ ] Added entry to scan executor (if applicable)
- [ ] Tested locally with real domain

## Questions?

Open an issue on GitHub for questions or clarifications.
