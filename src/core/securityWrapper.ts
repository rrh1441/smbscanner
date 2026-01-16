/**
 * Unified Security Scanner Wrapper System
 * 
 * Provides standardized execution interface for all security scanning tools:
 * - Nuclei v3.4.5
 * - OpenVAS/Greenbone CE  
 * - OWASP ZAP
 * - scan4all
 * - Trivy
 * - ScoutSuite/Prowler
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { writeFile, unlink, mkdir } from 'fs/promises';
import { existsSync, readFileSync } from 'fs';
import path from 'path';
import { randomBytes } from 'crypto';
import { createModuleLogger } from './logger.js';

const log = createModuleLogger('securityWrapper');

const execFileAsync = promisify(execFile);

// Configuration
const SCAN_TIMEOUT_MS = 600000; // 10 minutes default timeout
const MAX_BUFFER_SIZE = 100 * 1024 * 1024; // 100MB
const TEMP_DIR = '/tmp/security-scans';

interface ScannerConfig {
  name: string;
  executable: string;
  version: string;
  timeout: number;
  maxConcurrent: number;
  outputFormats: string[];
  requiresEnvVars?: string[];
}

interface ScanRequest {
  scanner: string;
  target: string;
  scanType: string;
  options?: Record<string, any>;
  timeout?: number;
  scanId?: string;
}

interface ScanResult {
  scanner: string;
  target: string;
  success: boolean;
  findings: any[];
  rawOutput: string;
  metadata: {
    startTime: Date;
    endTime: Date;
    duration: number;
    command: string;
    exitCode: number;
  };
  error?: string;
}

// Command structure for execFileAsync (prevents shell injection)
interface ScanCommand {
  executable: string;
  args: string[];
  env?: Record<string, string>; // Additional environment variables (for secrets)
}

// Scanner configurations
const SCANNER_CONFIGS: Record<string, ScannerConfig> = {
  nuclei: {
    name: 'Nuclei',
    executable: 'nuclei',
    version: 'v3.4.5',
    timeout: 600000,
    maxConcurrent: 4,
    outputFormats: ['json', 'yaml'],
    requiresEnvVars: []
  },
  openvas: {
    name: 'OpenVAS/Greenbone',
    executable: 'gvm-cli',
    version: 'latest',
    timeout: 1800000, // 30 minutes
    maxConcurrent: 2,
    outputFormats: ['xml', 'json'],
    requiresEnvVars: ['OPENVAS_HOST', 'OPENVAS_USER', 'OPENVAS_PASSWORD']
  },
  zap: {
    name: 'OWASP ZAP',
    executable: 'zap-baseline.py',
    version: 'latest',
    timeout: 900000, // 15 minutes
    maxConcurrent: 3,
    outputFormats: ['xml', 'json', 'html'],
    requiresEnvVars: []
  },
  scan4all: {
    name: 'scan4all',
    executable: 'scan4all',
    version: 'latest',
    timeout: 1200000, // 20 minutes
    maxConcurrent: 2,
    outputFormats: ['json'],
    requiresEnvVars: []
  },
  trivy: {
    name: 'Trivy',
    executable: 'trivy',
    version: 'latest',
    timeout: 300000, // 5 minutes
    maxConcurrent: 6,
    outputFormats: ['json', 'table'],
    requiresEnvVars: []
  },
  scoutsuite: {
    name: 'ScoutSuite',
    executable: 'scout',
    version: 'latest',
    timeout: 600000, // 10 minutes
    maxConcurrent: 1,
    outputFormats: ['json'],
    requiresEnvVars: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
  }
};

export class SecurityScannerWrapper {
  private activeScanCount = 0;
  private scanHistory: Map<string, ScanResult> = new Map();

  constructor() {
    this.ensureTempDirectory();
  }

  private async ensureTempDirectory(): Promise<void> {
    if (!existsSync(TEMP_DIR)) {
      await mkdir(TEMP_DIR, { recursive: true });
    }
  }

  /**
   * Execute a security scan using the unified interface
   */
  async executeScan(request: ScanRequest): Promise<ScanResult> {
    const config = SCANNER_CONFIGS[request.scanner];
    if (!config) {
      throw new Error(`Unknown scanner: ${request.scanner}`);
    }

    // Validate environment variables
    if (config.requiresEnvVars) {
      for (const envVar of config.requiresEnvVars) {
        if (!process.env[envVar]) {
          throw new Error(`Required environment variable ${envVar} not set for ${config.name}`);
        }
      }
    }

    // Check concurrent scan limits
    if (this.activeScanCount >= config.maxConcurrent) {
      throw new Error(`Maximum concurrent scans (${config.maxConcurrent}) reached for ${config.name}`);
    }

    const startTime = new Date();
    const sessionId = randomBytes(8).toString('hex');
    const outputFile = path.join(TEMP_DIR, `${request.scanner}_${sessionId}.json`);

    try {
      this.activeScanCount++;

      const cmd = await this.buildCommand(request, config, outputFile);
      const timeout = request.timeout || config.timeout;
      const commandStr = `${cmd.executable} ${cmd.args.join(' ')}`; // For logging/metadata only

      log.debug({ name: config.name, executable: cmd.executable, args: cmd.args }, 'Executing scanner');

      // Use execFileAsync to avoid shell injection vulnerabilities
      // Merge command-specific env vars (e.g., secrets) with process env
      const execEnv = { ...process.env, NO_COLOR: '1', ...(cmd.env || {}) };
      const { stdout, stderr } = await execFileAsync(cmd.executable, cmd.args, {
        timeout,
        maxBuffer: MAX_BUFFER_SIZE,
        env: execEnv
      });

      const endTime = new Date();
      const findings = await this.parseOutput(request.scanner, outputFile, stdout);

      const result: ScanResult = {
        scanner: request.scanner,
        target: request.target,
        success: true,
        findings,
        rawOutput: stdout,
        metadata: {
          startTime,
          endTime,
          duration: endTime.getTime() - startTime.getTime(),
          command: commandStr,
          exitCode: 0
        }
      };

      // Store in history for debugging
      this.scanHistory.set(sessionId, result);
      
      return result;

    } catch (error) {
      const endTime = new Date();
      const result: ScanResult = {
        scanner: request.scanner,
        target: request.target,
        success: false,
        findings: [],
        rawOutput: '',
        metadata: {
          startTime,
          endTime,
          duration: endTime.getTime() - startTime.getTime(),
          command: 'failed',
          exitCode: (error as any).code || -1
        },
        error: (error as Error).message
      };

      this.scanHistory.set(sessionId, result);
      return result;

    } finally {
      this.activeScanCount--;
      
      // Cleanup temporary files
      try {
        if (existsSync(outputFile)) {
          await unlink(outputFile);
        }
      } catch (cleanupError) {
        log.warn({ err: cleanupError, outputFile }, 'Failed to cleanup output file');
      }
    }
  }

  /**
   * Build scanner-specific command
   * Returns structured command to prevent shell injection via execFileAsync
   */
  private async buildCommand(request: ScanRequest, config: ScannerConfig, outputFile: string): Promise<ScanCommand> {
    const { scanner, target, scanType, options = {} } = request;

    switch (scanner) {
      case 'nuclei':
        return this.buildNucleiCommand(target, scanType, options, outputFile);

      case 'openvas':
        return this.buildOpenVASCommand(target, scanType, options, outputFile);

      case 'zap':
        return this.buildZAPCommand(target, scanType, options, outputFile);

      case 'scan4all':
        return this.buildScan4allCommand(target, scanType, options, outputFile);

      case 'trivy':
        return this.buildTrivyCommand(target, scanType, options, outputFile);

      case 'scoutsuite':
        return this.buildScoutSuiteCommand(target, scanType, options, outputFile);

      default:
        throw new Error(`Command builder not implemented for ${scanner}`);
    }
  }

  /**
   * Nuclei command builder (updated for v3.4.5)
   */
  private buildNucleiCommand(target: string, scanType: string, options: any, outputFile: string): ScanCommand {
    const args = [
      '-u', target,
      '-json',
      '-silent',
      '-timeout', (options.timeout || 20).toString(),
      '-retries', (options.retries || 2).toString(),
      '-td', '/opt/nuclei-templates'
    ];

    // Add scan type specific flags
    switch (scanType) {
      case 'vulnerability':
        args.push('-tags', options.tags || 'cve,misconfiguration,exposure');
        break;
      case 'technology':
        args.push('-tags', 'tech');
        break;
      case 'network':
        args.push('-tags', 'network,port-scan');
        break;
      case 'web':
        args.push('-tags', 'web,http');
        break;
      default:
        args.push('-tags', options.tags || 'misconfiguration,exposure');
    }

    // Add SSL bypass if needed
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') {
      args.push('-dca'); // disable certificate verification
    }

    // Add headless mode for web scans
    if (['web', 'technology'].includes(scanType)) {
      args.push('-headless');
    }

    return { executable: 'nuclei', args };
  }

  /**
   * OpenVAS command builder
   * Note: Credentials are passed via environment variables to avoid exposure in process listings
   */
  private buildOpenVASCommand(target: string, scanType: string, options: any, outputFile: string): ScanCommand {
    // OpenVAS via GVM-CLI - credentials passed via env vars for security
    const args = [
      '--host', process.env.OPENVAS_HOST || 'localhost',
      '--port', process.env.OPENVAS_PORT || '9390',
      '--xml', `<create_task><name>DealBrief-${Date.now()}</name><target id='${target}'/><config id='full_and_fast'/></create_task>`
    ];

    // Pass credentials via environment variables (not visible in ps aux)
    // GVM-CLI supports GVM_USERNAME and GVM_PASSWORD env vars
    const env: Record<string, string> = {};
    if (process.env.OPENVAS_USER) {
      env.GVM_USERNAME = process.env.OPENVAS_USER;
    }
    if (process.env.OPENVAS_PASSWORD) {
      env.GVM_PASSWORD = process.env.OPENVAS_PASSWORD;
    }

    return { executable: 'gvm-cli', args, env };
  }

  /**
   * OWASP ZAP command builder
   */
  private buildZAPCommand(target: string, scanType: string, options: any, outputFile: string): ScanCommand {
    const args = [
      '-t', target,
      '-J', outputFile,
      '-a' // Include the 'alpha' rules
    ];

    if (options.authenticatedScan) {
      args.push('-A', options.authenticatedUser || 'testuser');
    }

    return { executable: 'zap-baseline.py', args };
  }

  /**
   * scan4all command builder
   */
  private buildScan4allCommand(target: string, scanType: string, options: any, outputFile: string): ScanCommand {
    const args = [
      '-host', target,
      '-json'
    ];

    if (scanType === 'comprehensive') {
      args.push('-all');
    }

    return { executable: 'scan4all', args };
  }

  /**
   * Trivy command builder
   */
  private buildTrivyCommand(target: string, scanType: string, options: any, outputFile: string): ScanCommand {
    const args: string[] = [];

    switch (scanType) {
      case 'image':
        args.push('image', target);
        break;
      case 'filesystem':
        args.push('fs', target);
        break;
      case 'repository':
        args.push('repo', target);
        break;
      default:
        args.push('image', target);
    }

    args.push('-f', 'json', '-o', outputFile);

    return { executable: 'trivy', args };
  }

  /**
   * ScoutSuite command builder
   */
  private buildScoutSuiteCommand(target: string, scanType: string, options: any, outputFile: string): ScanCommand {
    const args = [
      'aws', // Default to AWS, can be extended for other cloud providers
      '--no-browser',
      '--report-dir', path.dirname(outputFile)
    ];

    if (options.region) {
      args.push('--regions', options.region);
    }

    return { executable: 'scout', args };
  }

  /**
   * Parse scanner output into standardized format
   */
  private async parseOutput(scanner: string, outputFile: string, stdout: string): Promise<any[]> {
    try {
      switch (scanner) {
        case 'nuclei':
          return this.parseNucleiOutput(stdout);
        
        case 'openvas':
          return this.parseOpenVASOutput(outputFile);
        
        case 'zap':
          return this.parseZAPOutput(outputFile);
        
        case 'scan4all':
          return this.parseScan4allOutput(stdout);
        
        case 'trivy':
          return this.parseTrivyOutput(outputFile);
        
        case 'scoutsuite':
          return this.parseScoutSuiteOutput(outputFile);
        
        default:
          return [];
      }
    } catch (error) {
      log.warn({ err: error, scanner }, 'Failed to parse scanner output');
      return [];
    }
  }

  /**
   * Parse Nuclei JSON output
   */
  private parseNucleiOutput(stdout: string): any[] {
    const findings: any[] = [];
    
    for (const line of stdout.split('\n')) {
      if (line.trim()) {
        try {
          const result = JSON.parse(line);
          findings.push({
            id: result['template-id'],
            name: result.info.name,
            severity: result.info.severity,
            description: result.info.description,
            host: result.host,
            type: 'nuclei_vulnerability',
            metadata: result
          });
        } catch (parseError) {
          // Skip malformed lines
        }
      }
    }
    
    return findings;
  }

  /**
   * Parse OpenVAS XML output into findings
   */
  private parseOpenVASOutput(outputFile: string): any[] {
    try {
      const content = readFileSync(outputFile, 'utf-8');
      const findings: any[] = [];
      // Basic XML parsing for OpenVAS results - looks for <result> elements
      const resultMatches = content.matchAll(/<result[^>]*>([\s\S]*?)<\/result>/gi);
      for (const match of resultMatches) {
        const resultXml = match[1];
        const nameMatch = resultXml.match(/<name>([^<]*)<\/name>/i);
        const severityMatch = resultXml.match(/<severity>([^<]*)<\/severity>/i);
        const descMatch = resultXml.match(/<description>([^<]*)<\/description>/i);
        const hostMatch = resultXml.match(/<host>([^<]*)<\/host>/i);
        if (nameMatch) {
          findings.push({
            title: nameMatch[1],
            severity: this.mapOpenVASSeverity(parseFloat(severityMatch?.[1] || '0')),
            description: descMatch?.[1] || '',
            host: hostMatch?.[1] || '',
          });
        }
      }
      return findings;
    } catch {
      return [];
    }
  }

  private mapOpenVASSeverity(score: number): string {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'INFO';
  }

  /**
   * Parse ZAP JSON output into findings
   */
  private parseZAPOutput(outputFile: string): any[] {
    try {
      const content = readFileSync(outputFile, 'utf-8');
      const data = JSON.parse(content);
      const findings: any[] = [];
      // ZAP JSON format has site -> alerts array
      for (const site of data.site || []) {
        for (const alert of site.alerts || []) {
          findings.push({
            title: alert.name || alert.alert,
            severity: this.mapZAPRisk(alert.riskcode),
            description: alert.desc || alert.description,
            solution: alert.solution,
            reference: alert.reference,
            url: alert.url || site.host,
            cweId: alert.cweid,
          });
        }
      }
      return findings;
    } catch {
      return [];
    }
  }

  private mapZAPRisk(riskcode: number | string): string {
    const code = typeof riskcode === 'string' ? parseInt(riskcode, 10) : riskcode;
    if (code >= 3) return 'HIGH';
    if (code === 2) return 'MEDIUM';
    if (code === 1) return 'LOW';
    return 'INFO';
  }

  /**
   * Parse scan4all JSON output into findings
   */
  private parseScan4allOutput(stdout: string): any[] {
    try {
      const findings: any[] = [];
      // scan4all outputs JSON lines
      for (const line of stdout.split('\n')) {
        if (!line.trim()) continue;
        try {
          const result = JSON.parse(line);
          if (result.vulnerability || result.finding) {
            findings.push({
              title: result.name || result.vulnerability || 'Unknown',
              severity: result.severity || 'MEDIUM',
              description: result.description || result.details || '',
              url: result.url || result.target,
            });
          }
        } catch {
          // Skip non-JSON lines
        }
      }
      return findings;
    } catch {
      return [];
    }
  }

  /**
   * Parse Trivy JSON output into findings
   */
  private parseTrivyOutput(outputFile: string): any[] {
    try {
      const content = readFileSync(outputFile, 'utf-8');
      const data = JSON.parse(content);
      const findings: any[] = [];
      // Trivy JSON format has Results array with Vulnerabilities
      for (const result of data.Results || []) {
        for (const vuln of result.Vulnerabilities || []) {
          findings.push({
            title: `${vuln.VulnerabilityID}: ${vuln.PkgName}`,
            severity: vuln.Severity || 'UNKNOWN',
            description: vuln.Description || vuln.Title,
            package: vuln.PkgName,
            installedVersion: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            cveId: vuln.VulnerabilityID,
            cvss: vuln.CVSS,
          });
        }
      }
      return findings;
    } catch {
      return [];
    }
  }

  /**
   * Parse ScoutSuite JSON output into findings
   */
  private parseScoutSuiteOutput(outputFile: string): any[] {
    try {
      const content = readFileSync(outputFile, 'utf-8');
      const data = JSON.parse(content);
      const findings: any[] = [];
      // ScoutSuite outputs findings per service
      for (const [service, serviceData] of Object.entries(data.services || {})) {
        const svc = serviceData as any;
        for (const [findingKey, finding] of Object.entries(svc.findings || {})) {
          const f = finding as any;
          if (f.flagged_items > 0) {
            findings.push({
              title: f.description || findingKey,
              severity: this.mapScoutSuiteLevel(f.level),
              description: f.rationale || '',
              service,
              flaggedItems: f.flagged_items,
              checkedItems: f.checked_items,
            });
          }
        }
      }
      return findings;
    } catch {
      return [];
    }
  }

  private mapScoutSuiteLevel(level: string): string {
    switch (level?.toLowerCase()) {
      case 'danger': return 'HIGH';
      case 'warning': return 'MEDIUM';
      default: return 'LOW';
    }
  }

  /**
   * Get scanner status and health
   */
  async getScannersStatus(): Promise<Record<string, any>> {
    const status: Record<string, any> = {};

    for (const [name, config] of Object.entries(SCANNER_CONFIGS)) {
      try {
        // Use execFileAsync to prevent shell injection
        const { stdout } = await execFileAsync('which', [config.executable]);
        status[name] = {
          available: true,
          executable: stdout.trim(),
          version: config.version,
          activeScanCount: this.activeScanCount
        };
      } catch (error) {
        status[name] = {
          available: false,
          error: (error as Error).message
        };
      }
    }

    return status;
  }

  /**
   * Get scan history for debugging
   */
  getScanHistory(): Map<string, ScanResult> {
    return this.scanHistory;
  }
}

// Singleton instance
export const securityWrapper = new SecurityScannerWrapper();

// Convenience functions for common scan types
export async function runNucleiScan(target: string, scanType: string = 'vulnerability', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'nuclei',
    target,
    scanType,
    options
  });
}

export async function runOpenVASScan(target: string, scanType: string = 'comprehensive', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'openvas',
    target,
    scanType,
    options
  });
}

export async function runZAPScan(target: string, scanType: string = 'baseline', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'zap',
    target,
    scanType,
    options
  });
}

export async function runScan4allScan(target: string, scanType: string = 'comprehensive', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'scan4all',
    target,
    scanType,
    options
  });
}

export async function runTrivyScan(target: string, scanType: string = 'image', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'trivy',
    target,
    scanType,
    options
  });
}

export async function runScoutSuiteScan(target: string, scanType: string = 'aws', options: any = {}): Promise<ScanResult> {
  return securityWrapper.executeScan({
    scanner: 'scoutsuite',
    target,
    scanType,
    options
  });
}