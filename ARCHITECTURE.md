# Scanner-OSS Architecture

This document describes the high-level architecture of the Scanner-OSS security scanning platform.

## Overview

Scanner-OSS is a modular security scanning platform designed for automated vulnerability assessment. It supports multiple scan types, from quick reconnaissance to deep vulnerability analysis.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         API Layer (Express)                         │
│  POST /scan  │  GET /scan/:id/status  │  GET /reports/:id/:file    │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Queue Service (Bull/Redis)                  │
│            Job scheduling, prioritization, rate limiting            │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Scan Executor                               │
│         Module orchestration, timeout management, callbacks         │
└─────────────────────────────────────────────────────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│   Module A    │       │   Module B    │       │   Module N    │
│  (shodan)     │       │  (tlsScan)    │       │  (nuclei)     │
└───────────────┘       └───────────────┘       └───────────────┘
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Artifact Store (PostgreSQL)                    │
│              Findings, artifacts, scan metadata, reports            │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. API Layer (`src/localServer.ts`)

The Express-based REST API provides:

- **Scan Management**: Start, monitor, and cancel scans
- **Report Generation**: HTML, PDF, and JSON report formats
- **Queue Status**: Monitor scan queue and job status
- **Health Checks**: Service availability endpoints

Key endpoints:
- `POST /scan` - Start a new scan
- `GET /scan/:scanId/status` - Check scan progress
- `GET /scans/:scanId/findings` - Get scan findings (JSON)
- `GET /reports/:scanId/report.json` - Get structured report

### 2. Queue Service (`src/core/queueService.ts`)

Built on Bull (Redis-backed), handles:

- **Job Scheduling**: FIFO with priority support
- **Concurrency Control**: Configurable parallel scan limit
- **Rate Limiting**: Per-API and global limits
- **Job Lifecycle**: Queued → Active → Completed/Failed

### 3. Scan Executor (`src/scan/executeScan.ts`)

Orchestrates scan execution:

- **Module Selection**: Based on scan profile/tier
- **Parallel Execution**: Runs independent modules concurrently
- **Timeout Management**: Per-module and global timeouts
- **Error Isolation**: Module failures don't crash the scan

### 4. Scanner Modules (`src/modules/`)

Each module implements a specific scan type:

```typescript
interface IScanModule {
  metadata: ModuleMetadata;  // id, name, category, tiers
  run(job: ScanJob): Promise<ScanResult>;
  canRun?(): Promise<boolean>;
  validateJob?(job: ScanJob): string[];
}
```

Module categories:
- **Reconnaissance**: shodan, whois, dnsTwist
- **Vulnerability**: nuclei, tlsScan, wpVuln
- **Exposure**: configExposure, backendExposure
- **Infrastructure**: techStack, dbPortScan
- **Secrets**: trufflehog, githubSecrets
- **Compliance**: accessibility, spfDmarc

### 5. Data Layer (`src/core/database.ts`, `src/core/artifactStore.ts`)

PostgreSQL storage for:

- **Scans**: Metadata, status, timing
- **Findings**: Vulnerabilities with severity, remediation
- **Artifacts**: Raw scan output, evidence
- **Reports**: Generated HTML/PDF files

## Data Flow

### Scan Lifecycle

```
1. API Request (POST /scan)
   └─► Validate domain, create scan record

2. Queue Job
   └─► Add to Bull queue with priority

3. Job Processing
   └─► Acquire worker lease
   └─► Select modules based on profile
   └─► Execute modules in parallel

4. Module Execution
   └─► Each module:
       ├─► Perform scan operations
       ├─► Insert findings to database
       └─► Store artifacts

5. Completion
   └─► Update scan status
   └─► Trigger callback (if configured)
   └─► Release worker lease
```

### Finding Structure

```typescript
{
  scan_id: string;
  type: string;           // e.g., 'SSL_WEAK_CIPHER'
  severity: Severity;     // CRITICAL | HIGH | MEDIUM | LOW | INFO
  title: string;
  description: string;
  remediation?: string;
  evidence?: object;
  cvss_score?: number;
  cve_id?: string;
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | `postgresql://localhost/scanner_local` |
| `REDIS_HOST` | Redis host for queue | `127.0.0.1` |
| `MAX_CONCURRENT_SCANS` | Parallel scan limit | `2` |
| `SCAN_MAX_MS` | Global scan timeout | `120000` |
| `SCANNER_API_KEY` | API authentication key | (required in prod) |

### Scan Profiles

- **full**: All modules, comprehensive scan
- **quick**: Fast reconnaissance only
- **wordpress**: WordPress-specific checks
- **infostealer**: Credential leak detection
- **email**: Email security (SPF, DMARC)

## Security Architecture

### Input Validation
- Domain validation via `src/core/validation.ts`
- SQL injection prevention via parameterized queries
- Command injection prevention via `execFileAsync`

### Authentication
- API key required for all endpoints (production)
- Timing-safe key comparison
- Rate limiting per IP

### Output Security
- Content Security Policy headers
- CSRF protection for browser requests
- XSS prevention in reports

## Extending the System

### Adding a New Module

1. Create `src/modules/myModule.ts`
2. Implement the module interface (see `CONTRIBUTING.md`)
3. Register in scan executor
4. Add timeout configuration

### Adding a New Endpoint

1. Add route in `src/localServer.ts`
2. Use structured error codes from `src/core/errors.ts`
3. Add appropriate rate limiting
4. Document in API spec

## Performance Considerations

- **Module Parallelization**: Independent modules run concurrently
- **Connection Pooling**: PostgreSQL pool with configurable size
- **Caching**: In-memory caching for repeated lookups
- **Timeouts**: Aggressive timeouts prevent hung scans

## Deployment

### Local Development
```bash
npm install
npm run dev
```

### Production
- Set `NODE_ENV=production`
- Configure `SCANNER_API_KEY`
- Use external Redis for queue persistence
- Configure PostgreSQL connection pooling
