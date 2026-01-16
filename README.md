# SimplCyber Scanner

A security scanner with 28 modules for vulnerability detection, credential exposure analysis, and financial risk quantification. Supports passive (default) and aggressive (opt-in) scanning modes.

## Overview

SimplCyber Scanner orchestrates multiple security scanning modules to provide comprehensive attack surface analysis. It combines OSINT reconnaissance, vulnerability scanning, credential breach detection, and web security analysis into a unified platform with REST API access.

**Key Capabilities:**
- Vulnerability scanning (CVE checks, TLS analysis, WordPress plugins)
- Credential and breach detection (infostealers, client-side secrets)
- Network reconnaissance (Shodan, WHOIS, DNS analysis)
- Web security analysis (admin panels, config exposure, API endpoints)
- Email security validation (SPF, DKIM, DMARC)
- Financial risk quantification using FAIR methodology (Expected Annual Loss)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp config/env.example .env
# Edit .env with your API keys and database credentials

# 3. Start the server
npm run dev
```

The server starts on `http://localhost:3000`. Trigger a scan:

```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "profile": "quick"}'
```

## Prerequisites

- Node.js 20+
- PostgreSQL 12+
- Redis 5+

## API Keys

| Service | Environment Variable | Required | Purpose |
|---------|---------------------|----------|---------|
| PostgreSQL | `DATABASE_URL` | Yes | Core findings database |
| Redis | `REDIS_URL` | Optional | Job queue (falls back to in-memory) |
| Shodan | `SHODAN_API_KEY` | Recommended | Internet-wide service enumeration |
| LeakCheck | `LEAKCHECK_API_KEY` | Recommended | Credential breach detection |
| OpenAI | `OPENAI_API_KEY` | Optional | AI-powered remediation guidance |
| NVD | `NVD_API_KEY` | Recommended | CVE database lookups |
| WHOISXML | `WHOISXML_API_KEY` | Optional | Domain intelligence |
| Serper | `SERPER_API_KEY` | Optional | Search-based reconnaissance |
| Scanner API | `SCANNER_API_KEY` | Optional | API authentication (required in production) |
| **Aggressive Mode** | | | |
| GitHub | `GITHUB_TOKEN` | For aggressive | GitHub secret search |
| OpenVAS | `OPENVAS_HOST`, `OPENVAS_USER`, `OPENVAS_PASSWORD` | For aggressive | OpenVAS vulnerability scanning |

## Scan Profiles

### Passive Profiles (Default)

| Profile | Duration | Description |
|---------|----------|-------------|
| `full` | 5-10 min | All 20 passive modules - comprehensive analysis |
| `quick` | 2-3 min | Fast OSINT (Shodan, tech stack, TLS) |
| `wordpress` | 3-5 min | WordPress plugin vulnerabilities |
| `infostealer` | 2-3 min | Credential breach and infostealer detection |
| `email` | 1-2 min | Email security only (SPF/DKIM/DMARC) |

### Aggressive Profile (Opt-In)

| Profile | Duration | Description |
|---------|----------|-------------|
| `aggressive` | 15-30 min | Full scan + active vulnerability scanning |

Enable aggressive scanning with explicit opt-in:

```bash
# Using aggressive profile
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "profile": "aggressive"}'

# Or add aggressive flag to any profile
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "profile": "full", "config": {"aggressive": true}}'
```

## Modules

### Passive Modules (20 modules - run by default)

#### Tier 1 - Foundation (no dependencies)
- **shodan** - Internet-wide service enumeration
- **whoisWrapper** - WHOIS domain intelligence
- **spfDmarc** - SPF, DKIM, DMARC validation
- **techStackScan** - Technology stack detection
- **endpointDiscovery** - API endpoint enumeration
- **infostealerProbe** - Credential breach detection
- **wpPluginQuickScan** - WordPress plugin vulnerabilities
- **configExposureScanner** - Configuration file exposure
- **adminPanelDetector** - Admin panel discovery
- **dnsZoneTransfer** - DNS zone transfer testing
- **subdomainTakeover** - Subdomain takeover detection
- **lightweightBackendScan** - Quick backend exposure checks
- **backendExposureScanner** - Backend service exposure
- **clientSecretScanner** - Client-side secret exposure
- **denialWalletScan** - Denial of wallet attack vectors
- **accessibilityLightweight** - Quick WCAG accessibility checks
- **tlsScan** - TLS/SSL configuration analysis

#### Tier 2 - Enrichment (depends on Tier 1)
- **lightweightCveCheck** - CVE lookups (requires techStackScan)

#### Tier 3 - Correlation
- **assetCorrelator** - Cross-module asset correlation

### Aggressive Modules (8 modules - require opt-in)

These modules perform active scanning and may trigger security alerts. Enable with `"profile": "aggressive"` or `"config": {"aggressive": true}`.

- **nuclei** - Template-based active vulnerability scanning
- **zapScan** - OWASP ZAP active web security scanning
- **dbPortScan** - Database port scanning (MySQL, PostgreSQL, MongoDB, Redis, etc.)
- **trufflehog** - Git repository secret scanning
- **githubSecretSearch** - GitHub code search for exposed secrets
- **dnsTwist** - Typosquatting and phishing domain detection
- **webArchiveScanner** - Historical exposure via Wayback Machine
- **openvasScan** - OpenVAS vulnerability assessment

## REST API

### Start a Scan
```bash
POST /scan
Content-Type: application/json

{
  "domain": "example.com",
  "profile": "full",
  "priority": "high"
}
```

### Bulk Scan
```bash
POST /scan/bulk
Content-Type: application/json

{
  "domains": ["example.com", "test.com"],
  "profile": "quick"
}
```

### Check Scan Status
```bash
GET /scan/:scanId/status
```

### Get Scan Results
```bash
GET /scans/:scanId
```

### Generate Report
```bash
POST /reports/generate
Content-Type: application/json

{
  "scanId": "abc-123",
  "format": "html"
}
```

### Health Check
```bash
GET /health
```

## Build & Run

### Development
```bash
npm run dev          # Start with auto-reload
npm run test         # Run tests
npm run lint         # Run linter
```

### Production
```bash
npm run build        # Compile TypeScript to dist/
npm start            # Run compiled server
```

### Environment Configuration

Create a `.env` file from the example:

```bash
cp config/env.example .env
```

Key configuration options:

```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/scanner

# Redis
REDIS_URL=redis://localhost:6379

# API Keys
SHODAN_API_KEY=your_key_here
LEAKCHECK_API_KEY=your_key_here

# Server
PORT=3000
NODE_ENV=production
```

## Financial Risk Model

The scanner quantifies security risk as Expected Annual Loss (EAL) using FAIR methodology:

- **Base Anchor:** $300,000 (typical SMB breach cost)
- **Risk Families:** Findings are grouped by attack vector (credentials, WordPress, phishing, etc.)
- **Severity Multipliers:** CRITICAL=5.0x, HIGH=2.5x, MEDIUM=1.0x, LOW=0.3x

See [docs/EAL_METHODOLOGY.md](docs/EAL_METHODOLOGY.md) for complete methodology documentation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     REST API (Express)                       │
│                    localhost:3000                            │
├─────────────────────────────────────────────────────────────┤
│                     Job Queue (Bull/Redis)                   │
├─────────────────────────────────────────────────────────────┤
│  PASSIVE (default)                                           │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Shodan  │ │TechStack│ │LeakCheck│ │  TLS    │  20 mods  │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
├─────────────────────────────────────────────────────────────┤
│  AGGRESSIVE (opt-in)                                         │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │ Nuclei  │ │   ZAP   │ │Trufflehog│ │PortScan│  8 mods   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
├─────────────────────────────────────────────────────────────┤
│                   PostgreSQL (Findings DB)                   │
└─────────────────────────────────────────────────────────────┘
```

## License

BUSL-1.1 (Business Source License 1.1)
