/*
 * =============================================================================
 * MODULE: spfDmarc.ts (Refactored)
 * =============================================================================
 * This module performs deep analysis of a domain's email security posture by
 * checking DMARC, SPF, and DKIM configurations.
 *
 * Key Improvements from previous version:
 * 1.  **Recursive SPF Validation:** The SPF check now recursively resolves `include`
 * and `redirect` mechanisms to accurately count DNS lookups.
 * 2.  **Comprehensive DKIM Probing:** Probes for a much wider array of common and
 * provider-specific DKIM selectors.
 * 3.  **BIMI Record Check:** Adds validation for Brand Indicators for Message
 * Identification (BIMI) for enhanced brand trust in email clients.
 * =============================================================================
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('spfDmarc');
const exec = promisify(execFile);

interface SpfResult {
  record: string;
  lookups: number;
  error?: 'TOO_MANY_LOOKUPS' | 'REDIRECT_LOOP' | 'MULTIPLE_RECORDS' | 'NONE_FOUND';
  allMechanism: '~all' | '-all' | '?all' | 'none';
}

/**
 * REFACTOR: A new recursive function to fully resolve an SPF record.
 * It follows includes and redirects to accurately count DNS lookups.
 */
async function resolveSpfRecord(domain: string, lookups: number = 0, redirectChain: string[] = []): Promise<SpfResult> {
  const MAX_LOOKUPS = 10;

  if (lookups > MAX_LOOKUPS) {
    return { record: '', lookups, error: 'TOO_MANY_LOOKUPS', allMechanism: 'none' };
  }
  if (redirectChain.includes(domain)) {
    return { record: '', lookups, error: 'REDIRECT_LOOP', allMechanism: 'none' };
  }

  try {
    const { stdout } = await exec('dig', ['-4', 'TXT', domain, '+short'], { 
      timeout: 10000,
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      killSignal: 'SIGKILL' // Force kill if hangs
    });
    const records = stdout.trim().split('\n').map(s => s.replace(/"/g, '')).filter(r => r.startsWith('v=spf1'));

    if (records.length === 0) return { record: '', lookups, error: 'NONE_FOUND', allMechanism: 'none' };
    if (records.length > 1) return { record: records.join(' | '), lookups, error: 'MULTIPLE_RECORDS', allMechanism: 'none' };

    const record = records[0];
    const mechanisms = record.split(' ').slice(1);
    let currentLookups = lookups;
    let finalResult: SpfResult = { record, lookups, allMechanism: 'none' };

    for (const mech of mechanisms) {
      if (mech.startsWith('include:')) {
        currentLookups++;
        const includeDomain = mech.split(':')[1];
        const result = await resolveSpfRecord(includeDomain, currentLookups, [...redirectChain, domain]);
        currentLookups = result.lookups;
        if (result.error) return { ...finalResult, error: result.error, lookups: currentLookups };
      } else if (mech.startsWith('redirect=')) {
        currentLookups++;
        const redirectDomain = mech.split('=')[1];
        return resolveSpfRecord(redirectDomain, currentLookups, [...redirectChain, domain]);
      } else if (mech.startsWith('a') || mech.startsWith('mx') || mech.startsWith('exists:')) {
        currentLookups++;
      }
    }

    finalResult.lookups = currentLookups;
    if (record.includes('-all')) finalResult.allMechanism = '-all';
    else if (record.includes('~all')) finalResult.allMechanism = '~all';
    else if (record.includes('?all')) finalResult.allMechanism = '?all';

    if (currentLookups > MAX_LOOKUPS) {
        finalResult.error = 'TOO_MANY_LOOKUPS';
    }

    return finalResult;
  } catch (error) {
    return { record: '', lookups, error: 'NONE_FOUND', allMechanism: 'none' };
  }
}

/**
 * Extract apex/organizational domain from a given domain
 * Email authentication records are always at the apex domain, never on subdomains
 */
function extractApexDomain(domain: string): string {
  // Remove common prefixes
  let apex = domain.replace(/^www\./, '');

  // Handle common TLDs and eTLD+1 extraction
  // For proper eTLD+1, we'd use a library, but this covers most cases
  const parts = apex.split('.');

  if (parts.length >= 2) {
    // Keep last 2 parts for most TLDs (domain.com, domain.co.uk, etc)
    // Special handling for common multi-part TLDs
    const lastTwo = parts.slice(-2).join('.');
    const lastThree = parts.slice(-3).join('.');

    // Common multi-part TLDs
    const multiPartTLDs = ['co.uk', 'com.au', 'co.jp', 'co.nz', 'com.br', 'co.in', 'co.za'];
    if (multiPartTLDs.includes(lastTwo) && parts.length >= 3) {
      return lastThree;
    }

    return lastTwo;
  }

  return apex;
}

// Track which scans have already been processed to prevent duplicate findings
const processedScans = new Set<string>();

export async function runSpfDmarc(job: { domain: string; scanId?: string }): Promise<number> {
  log.info({ domain: job.domain, scanId: job.scanId }, 'Starting email security scan');

  // DEDUPLICATION: Check if this scan has already been processed
  if (job.scanId && processedScans.has(job.scanId)) {
    log.info({ scanId: job.scanId }, 'Scan already processed, skipping to prevent duplicates');
    return 0;
  }

  // Extract apex domain for email auth checks
  // Email authentication is ALWAYS at apex, never on subdomains (www, app, etc)
  const apexDomain = extractApexDomain(job.domain);

  if (apexDomain !== job.domain) {
    log.info({ apexDomain, scanDomain: job.domain }, 'Checking email security for apex domain');
  } else {
    log.info({ domain: job.domain }, 'Starting email security scan');
  }

  // Mark this scan as processed to prevent duplicate runs
  if (job.scanId) {
    processedScans.add(job.scanId);
  }

  let findingsCount = 0;

  // Track email auth control presence for gap type determination
  let dmarcPresent = false;
  let dmarcStrong = false;
  let spfPresent = false;
  let spfStrong = false;
  let dkimPresent = false;

  // Collect findings to insert after determining gap types
  const pendingFindings: Array<{
    type: string;
    severity: string;
    title: string;
    description: string;
    recommendation: string;
    control_missing?: string;
  }> = [];

  // --- 1. DMARC Check ---
  log.debug('Checking DMARC record');
  try {
    const { stdout: dmarcOut } = await exec('dig', ['-4', 'txt', `_dmarc.${apexDomain}`, '+short'], {
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      killSignal: 'SIGKILL' // Force kill if hangs
    });
    if (!dmarcOut.trim()) {
        dmarcPresent = false;
        await insertArtifact({ type: 'dmarc_missing', val_text: `DMARC record missing`, severity: 'MEDIUM', meta: { scan_id: job.scanId, scan_module: 'spfDmarc' } });
        pendingFindings.push({
          type: 'EMAIL_SECURITY_GAP',
          severity: 'MEDIUM',
          title: 'DMARC policy missing',
          description: 'No DMARC record found.',
          recommendation: 'Implement a DMARC policy (start with p=none) to gain visibility into email channels and begin protecting against spoofing.',
          control_missing: 'dmarc'
        });
    } else if (/p=none/i.test(dmarcOut)) {
        dmarcPresent = true;
        dmarcStrong = false;
        await insertArtifact({ type: 'dmarc_weak', val_text: `DMARC policy is not enforcing`, severity: 'LOW', meta: { record: dmarcOut.trim(), scan_id: job.scanId, scan_module: 'spfDmarc' } });
        // Weak policy can be inserted immediately with gap type
        await insertFinding({
          scan_id: job.scanId,
          type: 'EMAIL_SECURITY_WEAKNESS',
          severity: 'LOW',
          title: 'DMARC policy too weak',
          description: 'DMARC policy is currently in monitoring mode (p=none), which limits enforcement against domain spoofing but does not present an immediate security risk.',
          data: {
            recommendation: 'Strengthen DMARC policy from p=none to p=quarantine or p=reject to actively prevent email spoofing.',
            email_gap_type: 'weak_policy'
          }
        });
        findingsCount++;
    } else {
        dmarcPresent = true;
        dmarcStrong = true;
    }
  } catch (e) {
      log.debug({ err: e }, 'DMARC check failed or no record found');
      dmarcPresent = false;
  }

  // --- 2. Recursive SPF Check ---
  log.debug('Performing recursive SPF check');
  const spfResult = await resolveSpfRecord(apexDomain);

  if (spfResult.error === 'NONE_FOUND') {
      spfPresent = false;
      await insertArtifact({ type: 'spf_missing', val_text: `SPF record missing`, severity: 'MEDIUM', meta: { scan_id: job.scanId, scan_module: 'spfDmarc' } });
      pendingFindings.push({
        type: 'EMAIL_SECURITY_GAP',
        severity: 'MEDIUM',
        title: 'SPF record missing',
        description: 'No SPF record found.',
        recommendation: 'Implement an SPF record to specify all authorized mail servers. This is a foundational step for DMARC.',
        control_missing: 'spf'
      });
  } else if (spfResult.error) {
      spfPresent = false; // Invalid SPF counts as missing
      await insertArtifact({ type: 'spf_invalid', val_text: `SPF record is invalid: ${spfResult.error}`, severity: 'HIGH', meta: { record: spfResult.record, lookups: spfResult.lookups, error: spfResult.error, scan_id: job.scanId, scan_module: 'spfDmarc' } });
      pendingFindings.push({
        type: 'EMAIL_SECURITY_MISCONFIGURATION',
        severity: 'HIGH',
        title: 'SPF record invalid',
        description: `SPF record validation failed with error: ${spfResult.error}.`,
        recommendation: `Correct the invalid SPF record. The error '${spfResult.error}' can cause email delivery failures for legitimate mail.`,
        control_missing: 'spf'
      });
  } else {
    if (spfResult.allMechanism === '~all' || spfResult.allMechanism === '?all') {
        spfPresent = true;
        spfStrong = false;
        await insertArtifact({ type: 'spf_weak', val_text: `SPF policy is too permissive (${spfResult.allMechanism})`, severity: 'LOW', meta: { record: spfResult.record, scan_id: job.scanId, scan_module: 'spfDmarc' } });
        // Weak policy can be inserted immediately with gap type
        await insertFinding({
          scan_id: job.scanId,
          type: 'EMAIL_SECURITY_WEAKNESS',
          severity: 'LOW',
          title: 'SPF policy too weak',
          description: 'The SPF record does not instruct receivers to reject unauthorized mail.',
          data: {
            recommendation: 'Strengthen SPF policy by using "-all" (hard fail) instead of "~all" (soft fail) or "?all" (neutral).',
            email_gap_type: 'weak_policy'
          }
        });
        findingsCount++;
    } else {
        spfPresent = true;
        spfStrong = true;
    }
  }
  
  // --- 3. Comprehensive DKIM Check ---
  log.debug('Probing for common DKIM selectors');
  // REFACTOR: Expanded list of provider-specific DKIM selectors.
  const currentYear = new Date().getFullYear();
  const commonSelectors = [
      'default', 'selector1', 'selector2', 'google', 'k1', 'k2', 'mandrill', 
      'sendgrid', 'mailgun', 'zoho', 'amazonses', 'dkim', 'm1', 'pm', 'o365',
      'mailchimp', 'constantcontact', 'hubspot', 'salesforce', // Added providers
      `s${currentYear}`, `s${currentYear - 1}`
  ];
  let dkimFound = false;
  
  for (const selector of commonSelectors) {
    try {
      const { stdout: dkimOut } = await exec('dig', ['-4', 'txt', `${selector}._domainkey.${apexDomain}`, '+short'], {
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        killSignal: 'SIGKILL' // Force kill if hangs
      });
      if (dkimOut.trim().includes('k=rsa')) {
        dkimFound = true;
        log.info({ selector }, 'Found DKIM record');
        break;
      }
    } catch (dkimError) { /* Selector does not exist */ }
  }
  
  if (!dkimFound) {
    dkimPresent = false;
    await insertArtifact({ type: 'dkim_missing', val_text: `DKIM record not detected for common selectors`, severity: 'LOW', meta: { selectors_checked: commonSelectors, scan_id: job.scanId, scan_module: 'spfDmarc' } });
    // DKIM can be inserted immediately with gap type (doesn't depend on other controls)
    await insertFinding({
      scan_id: job.scanId,
      type: 'EMAIL_SECURITY_GAP',
      severity: 'LOW',
      title: 'DKIM record missing',
      description: 'Could not find a valid DKIM record using a wide range of common selectors.',
      data: {
        recommendation: 'Implement DKIM signing for outbound email to cryptographically verify message integrity. This is a critical component for DMARC alignment.',
        email_gap_type: 'dkim_missing'
      }
    });
    findingsCount++;
  } else {
    dkimPresent = true;
  }

  // REFACTOR: --- 4. BIMI Check (Optional Enhancement) ---
  log.debug('Checking for BIMI record');
  try {
      const { stdout: bimiOut } = await exec('dig', ['-4', 'txt', `default._bimi.${apexDomain}`, '+short'], {
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
        killSignal: 'SIGKILL' // Force kill if hangs
      });
      if (bimiOut.trim().startsWith('v=BIMI1')) {
          log.info({ record: bimiOut.trim() }, 'Found BIMI record');
          await insertArtifact({
              type: 'bimi_found',
              val_text: 'BIMI record is properly configured',
              severity: 'INFO',
              meta: { record: bimiOut.trim(), scan_id: job.scanId, scan_module: 'spfDmarc' }
          });
      } else {
          // A missing BIMI record is not a security failure, but an opportunity.
          await insertArtifact({
              type: 'bimi_missing',
              val_text: 'BIMI record not found',
              severity: 'INFO',
              meta: { scan_id: job.scanId, scan_module: 'spfDmarc' }
          });
      }
  } catch (bimiError) {
      log.debug({ err: bimiError }, 'BIMI check failed or no record found');
  }

  // --- 5. Insert pending findings with correct gap types ---
  try {
    // Determine appropriate gap type based on which controls are missing
    let gapType: string | null = null;

    if (!dmarcPresent && !spfPresent) {
      gapType = 'none'; // No SPF + no DMARC (full auth gap)
    } else if (!dmarcPresent && spfPresent) {
      gapType = 'dmarc_only'; // Missing DMARC only
    } else if (dmarcPresent && !spfPresent) {
      gapType = 'spf_only'; // Missing SPF only
    }

    // Insert all pending findings with determined gap type
    for (const finding of pendingFindings) {
      await insertFinding({
        scan_id: job.scanId,
        type: finding.type,
        severity: finding.severity,
        title: finding.title,
        description: finding.description,
        data: {
          recommendation: finding.recommendation,
          control_missing: finding.control_missing,
          email_gap_type: gapType || 'unknown'
        }
      });
      findingsCount++;
    }

    if (gapType && pendingFindings.length > 0) {
      log.info({ findingsCount: pendingFindings.length, gapType, scanId: job.scanId }, 'Inserted findings with email gap type');
    }
  } catch (e) {
    log.error({ err: e }, 'Failed to insert pending findings with gap types');
  }

  log.info({ findingsCount, domain: job.domain }, 'Completed email security scan');
  return findingsCount;
}
