# External Tool Requirements

Scanner-OSS integrates with several external security tools. This document lists the tools, their purposes, and installation instructions.

## Required Tools

### sslscan

**Purpose**: TLS/SSL configuration analysis

**Used by**: `src/modules/tlsScan.ts`

**Installation**:
```bash
# macOS
brew install sslscan

# Ubuntu/Debian
apt-get install sslscan

# From source
git clone https://github.com/rbsec/sslscan.git
cd sslscan && make && sudo make install
```

**Version**: 2.0+

---

### nuclei

**Purpose**: Template-based vulnerability scanning

**Used by**: `src/util/nucleiWrapper.ts`

**Installation**:
```bash
# macOS
brew install nuclei

# Go install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Binary download
# https://github.com/projectdiscovery/nuclei/releases
```

**Version**: 3.0+

**Notes**:
- Requires template updates: `nuclei -update-templates`
- Binary must be in PATH or set `NUCLEI_PATH` env var

---

## Optional Tools

### whatweb

**Purpose**: Web technology fingerprinting

**Used by**: `src/util/fastTechDetection.ts`

**Installation**:
```bash
# macOS
brew install whatweb

# Ubuntu/Debian
apt-get install whatweb

# Ruby gem
gem install whatweb
```

---

### webtech

**Purpose**: Web technology detection

**Used by**: `src/util/fastTechDetection.ts`

**Installation**:
```bash
pip install webtech
```

---

### gau (GetAllUrls)

**Purpose**: URL discovery from web archives

**Used by**: `src/modules/webArchiveScanner.ts`

**Installation**:
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

### trufflehog

**Purpose**: Secret detection in repositories

**Used by**: `src/modules/trufflehog.ts`

**Installation**:
```bash
# macOS
brew install trufflehog

# Go install
go install github.com/trufflesecurity/trufflehog/v3@latest

# Docker
docker pull trufflesecurity/trufflehog:latest
```

**Version**: 3.0+

---

### dnstwist

**Purpose**: Domain permutation detection (typosquatting)

**Used by**: `src/modules/dnsTwist.ts`

**Installation**:
```bash
# pip
pip install dnstwist

# macOS
brew install dnstwist

# Docker
docker pull elceef/dnstwist
```

---

### WeasyPrint

**Purpose**: HTML to PDF conversion for reports

**Used by**: `src/localServer.ts` (report generation)

**Installation**:
```bash
# macOS
brew install weasyprint

# Ubuntu/Debian
apt-get install weasyprint

# pip
pip install weasyprint
```

**Notes**: Requires Cairo and Pango libraries

---

## Security Tool Wrappers

### OpenVAS/GVM

**Purpose**: Comprehensive vulnerability scanning

**Used by**: `src/core/securityWrapper.ts`

**Installation**: See [OpenVAS Documentation](https://greenbone.github.io/docs/latest/)

**Notes**:
- Requires separate server setup
- Set `OPENVAS_HOST`, `OPENVAS_USER`, `OPENVAS_PASSWORD` env vars

---

### OWASP ZAP

**Purpose**: Web application security testing

**Used by**: `src/core/securityWrapper.ts`

**Installation**:
```bash
# Docker
docker pull zaproxy/zap-stable

# Direct download
# https://www.zaproxy.org/download/
```

---

### Trivy

**Purpose**: Container and dependency vulnerability scanning

**Used by**: `src/core/securityWrapper.ts`

**Installation**:
```bash
# macOS
brew install trivy

# Ubuntu/Debian
apt-get install trivy

# Docker
docker pull aquasec/trivy
```

---

## Verification

Run this script to check tool availability:

```bash
#!/bin/bash

tools=("sslscan" "nuclei" "whatweb" "gau" "trufflehog" "dnstwist" "weasyprint")

echo "Checking external tool availability..."
echo "======================================"

for tool in "${tools[@]}"; do
  if command -v "$tool" &> /dev/null; then
    version=$("$tool" --version 2>&1 | head -1)
    echo "✓ $tool: $version"
  else
    echo "✗ $tool: NOT FOUND"
  fi
done
```

## Environment Variables

| Variable | Tool | Description |
|----------|------|-------------|
| `NUCLEI_PATH` | nuclei | Custom path to nuclei binary |
| `NUCLEI_TEMPLATES` | nuclei | Path to custom templates |
| `OPENVAS_HOST` | OpenVAS | OpenVAS server host |
| `OPENVAS_USER` | OpenVAS | OpenVAS username |
| `OPENVAS_PASSWORD` | OpenVAS | OpenVAS password |
| `TRUFFLEHOG_GIT_DEPTH` | trufflehog | Git history depth to scan |

## Notes

- Most modules gracefully degrade if their external tool is unavailable
- Tools are validated at scan time, not startup
- Docker-based tools may require additional configuration for network access
