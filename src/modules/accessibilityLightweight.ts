/**
 * Lightweight Accessibility Scanner
 * 
 * Quick accessibility compliance check without Puppeteer.
 * Detects common ADA/WCAG violations that create lawsuit risk.
 */

import { httpClient } from '../net/httpClient.js';
import { insertArtifact, insertFinding } from '../core/artifactStore.js';
import { createModuleLogger } from '../core/logger.js';
import { executeModule } from '../util/errorHandler.js';

const log = createModuleLogger('accessibilityLightweight');

type IssueBucket = 'blocking' | 'high' | 'medium' | 'low';

interface AccessibilityIssue {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
  riskLevel: 'HIGH_LAWSUIT_RISK' | 'MEDIUM_LAWSUIT_RISK' | 'LOW_LAWSUIT_RISK';
  bucket: IssueBucket;
  instances: number;
  url: string; // Added for critical page detection
}

interface AdaRiskAssessment {
  band: 'LOW' | 'MOST_LIKELY' | 'HIGH' | null;
  blockingCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

const CRITICAL_FORM_KEYWORDS = [
  'checkout',
  'payment',
  'card',
  'billing',
  'invoice',
  'cart',
  'login',
  'signin',
  'register',
  'account',
  'book',
  'reservation'
];

function hasCriticalKeyword(html: string): boolean {
  return CRITICAL_FORM_KEYWORDS.some((keyword) => new RegExp(keyword, 'i').test(html));
}

/**
 * Check for basic accessibility violations in HTML content
 */
function checkAccessibilityViolations(html: string, url: string): AccessibilityIssue[] {
  const issues: AccessibilityIssue[] = [];
  
  // Check for missing alt attributes on images
  const imgTagsWithoutAlt = html.match(/<img(?![^>]*alt\s*=)[^>]*>/gi) || [];
  if (imgTagsWithoutAlt.length > 0) {
    issues.push({
      type: 'MISSING_ALT_TEXT',
      severity: 'HIGH',
      description: `${imgTagsWithoutAlt.length} images missing alt text`,
      recommendation: 'Add descriptive alt attributes to all images for screen readers',
      riskLevel: 'HIGH_LAWSUIT_RISK',
      bucket: 'medium',
      instances: imgTagsWithoutAlt.length,
      url
    });
  }

  // Check for missing form labels
  const inputsWithoutLabels = html.match(/<input(?![^>]*aria-label)(?![^>]*aria-labelledby)(?![^>]*title)[^>]*>/gi) || [];
  if (inputsWithoutLabels.length > 0) {
    const blocking = hasCriticalKeyword(html);
    issues.push({
      type: 'MISSING_FORM_LABELS',
      severity: blocking ? 'CRITICAL' : 'HIGH', 
      description: `${inputsWithoutLabels.length} form inputs missing labels`,
      recommendation: 'Add proper labels or aria-labels to all form inputs',
      riskLevel: blocking ? 'HIGH_LAWSUIT_RISK' : 'HIGH_LAWSUIT_RISK',
      bucket: blocking ? 'blocking' : 'high',
      instances: inputsWithoutLabels.length,
      url    });
  }

  // Check for missing page title
  if (!html.match(/<title[^>]*>[\s\S]*?<\/title>/i)) {
    issues.push({
      type: 'MISSING_PAGE_TITLE',
      severity: 'MEDIUM',
      description: 'Page missing title element',
      recommendation: 'Add descriptive page title for screen readers and SEO',
      riskLevel: 'MEDIUM_LAWSUIT_RISK',
      bucket: 'medium',
      instances: 1,
      url    });
  }

  // Check for missing language declaration
  if (!html.match(/<html[^>]*lang\s*=/i)) {
    issues.push({
      type: 'MISSING_LANGUAGE',
      severity: 'MEDIUM',
      description: 'HTML missing language declaration',
      recommendation: 'Add lang attribute to html element (e.g., <html lang="en">)',
      riskLevel: 'MEDIUM_LAWSUIT_RISK',
      bucket: 'medium',
      instances: 1,
      url    });
  }

  // Check for insufficient color contrast indicators
  const hasLightColors = html.match(/color\s*:\s*#[f-f]{3,6}|color\s*:\s*rgb\(2[5-9][0-9]|color\s*:\s*white/gi);
  const hasLightBackground = html.match(/background[^:]*:\s*#[f-f]{3,6}|background[^:]*:\s*rgb\(2[5-9][0-9]|background[^:]*:\s*white/gi);
  if (hasLightColors && hasLightBackground) {
    issues.push({
      type: 'POTENTIAL_CONTRAST_ISSUES',
      severity: 'MEDIUM',
      description: 'Potential color contrast issues detected',
      recommendation: 'Ensure 4.5:1 contrast ratio for normal text, 3:1 for large text',
      riskLevel: 'MEDIUM_LAWSUIT_RISK',
      bucket: 'low',
      instances: 1,
      url    });
  }

  // Check for missing heading structure
  const h1Count = (html.match(/<h1[^>]*>/gi) || []).length;
  if (h1Count === 0) {
    issues.push({
      type: 'MISSING_H1',
      severity: 'MEDIUM',
      description: 'Page missing primary heading (h1)',
      recommendation: 'Add a descriptive h1 heading as the main page title',
      riskLevel: 'MEDIUM_LAWSUIT_RISK',
      bucket: 'medium',
      instances: 1,
      url    });
  } else if (h1Count > 1) {
    issues.push({
      type: 'MULTIPLE_H1',
      severity: 'LOW',
      description: `Page has ${h1Count} h1 headings (should be 1)`,
      recommendation: 'Use only one h1 per page, use h2-h6 for subsections',
      riskLevel: 'LOW_LAWSUIT_RISK',
      bucket: 'low',
      instances: 1,
      url    });
  }

  // Check for inaccessible links
  const emptyLinks = html.match(/<a[^>]*>[\s]*<\/a>/gi) || [];
  if (emptyLinks.length > 0) {
    issues.push({
      type: 'EMPTY_LINKS',
      severity: 'HIGH',
      description: `${emptyLinks.length} empty or unclear links`,
      recommendation: 'Ensure all links have descriptive text or aria-labels',
      riskLevel: 'HIGH_LAWSUIT_RISK',
      bucket: 'high',
      instances: emptyLinks.length,
      url    });
  }

  return issues;
}

/**
 * Heuristic form analysis: unlabeled controls and submit naming
 */
function extractFormIssues(html: string, url: string): AccessibilityIssue[] {
  const issues: AccessibilityIssue[] = [];

  const transactional = hasCriticalKeyword(html) || /\/(login|signin|checkout|cart|register|signup|account)(?:\b|\/|\?)/i.test(url);

  const forms = html.match(/<form\b[\s\S]*?<\/form>/gi) || [];
  if (forms.length === 0) return issues;

  let totalUnlabeled = 0;
  let missingSubmitNames = 0;

  for (const form of forms) {
    const inputs = form.match(/<input\b[^>]*>/gi) || [];
    for (const input of inputs) {
      const typeMatch = input.match(/\btype=["']?([a-zA-Z0-9_-]+)["']?/i);
      const type = (typeMatch ? typeMatch[1] : 'text').toLowerCase();
      if ([ 'hidden','submit','button','image','reset' ].includes(type)) continue;

      // Accessible name via ARIA or title
      if (/\baria-label=|\baria-labelledby=|\btitle=/.test(input)) continue;

      // Label via for="id"
      const idMatch = input.match(/\bid=["']([^"']+)["']/i);
      if (idMatch) {
        const id = idMatch[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const labelFor = new RegExp(`<label[^>]*for=["']${id}["'][^>]*>`, 'i');
        if (labelFor.test(html)) continue;
      }

      totalUnlabeled++;
    }

    // Submit naming
    let submitNamed = false;
    const btnMatch = form.match(/<button\b[^>]*type=["']?submit["']?[^>]*>([\s\S]*?)<\/button>/i);
    if (btnMatch) {
      const btn = btnMatch[0];
      const inner = btnMatch[1].replace(/<[^>]+>/g, '').trim();
      if (inner.length > 0) submitNamed = true;
      if (/\baria-label=|\baria-labelledby=|\btitle=/.test(btn)) submitNamed = true;
    }
    if (!submitNamed) {
      const inSubmit = form.match(/<input\b[^>]*type=["']?submit["']?[^>]*>/i);
      if (inSubmit) {
        const el = inSubmit[0];
        if (/\bvalue=["'][^"']+["']/.test(el)) submitNamed = true;
        if (/\baria-label=|\baria-labelledby=|\btitle=/.test(el)) submitNamed = true;
      }
    }
    if (!submitNamed) missingSubmitNames++;
  }

  if (totalUnlabeled >= 3 || (transactional && (totalUnlabeled >= 1 || missingSubmitNames > 0))) {
    const severity: AccessibilityIssue['severity'] = transactional ? 'CRITICAL' : (totalUnlabeled >= 3 ? 'HIGH' : 'MEDIUM');
    const bucket: IssueBucket = transactional ? 'blocking' : 'high';
    issues.push({
      type: 'MISSING_FORM_LABELS',
      severity,
      description: `${totalUnlabeled} unlabeled inputs${missingSubmitNames > 0 ? `, ${missingSubmitNames} submit without accessible name` : ''} across ${forms.length} form(s)`,
      recommendation: 'Add labels or aria attributes to all form inputs and provide submit controls with accessible names.',
      riskLevel: transactional ? 'HIGH_LAWSUIT_RISK' : 'MEDIUM_LAWSUIT_RISK',
      bucket,
      instances: Math.max(totalUnlabeled, 1),
      url
    });
  }

  return issues;
}

/**
 * Check if a URL represents a critical transactional page
 */
function isCriticalPage(url: string): boolean {
  return /(login|signin|checkout|cart|payment|account|register|signup)/i.test(url);
}

/**
 * Assess ADA compliance risk with tightened thresholds requiring critical page context
 */
function assessAdaRisk(issues: AccessibilityIssue[]): AdaRiskAssessment {
  const counts: Record<IssueBucket, number> = {
    blocking: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  issues.forEach((issue) => {
    counts[issue.bucket] += issue.instances;
  });

  const { blocking, high, medium, low } = counts;

  // Categorize issues by criticality
  const highIssues = issues.filter(i => i.bucket === 'high' || i.bucket === 'blocking');
  const highOnCritical = highIssues.filter(i => isCriticalPage(i.url));
  const blockingOnCritical = issues.filter(i => i.bucket === 'blocking' && isCriticalPage(i.url));

  const mediumIssues = issues.filter(i => i.bucket === 'medium');
  const mediumOnCritical = mediumIssues.filter(i => isCriticalPage(i.url));
  const structuralMedium = mediumIssues.filter(i =>
    /missing.*(title|lang|h1)/i.test(i.type)
  );

  const lowIssues = issues.filter(i => i.bucket === 'low');
  const uniquePageCount = new Set(issues.map(i => i.url)).size;

  let band: 'LOW' | 'MOST_LIKELY' | 'HIGH' | null = null;

  // HIGH band: severe issues or blocking issues on critical pages
  if (
    blockingOnCritical.length > 0 ||
    highIssues.length >= 2 ||
    (medium >= 5 && structuralMedium.length >= 1)
  ) {
    band = 'HIGH';
  }
  // MOST_LIKELY band: some critical page issues or moderate issues
  else if (
    (highOnCritical.length >= 1) ||
    (medium >= 3 && medium <= 4 && mediumOnCritical.length >= 1) ||
    (low >= 15 && uniquePageCount >= 3)
  ) {
    band = 'MOST_LIKELY';
  }
  // LOW band: minor issues, none on critical pages
  else if (
    ((medium >= 1 && medium <= 2) || (low >= 5 && low <= 14)) &&
    highOnCritical.length === 0 &&
    mediumOnCritical.length === 0
  ) {
    band = 'LOW';
  }
  // null: no significant issues or below LOW threshold
  else {
    band = null;
  }

  return {
    band,
    blockingCount: blocking,
    highCount: high,
    mediumCount: medium,
    lowCount: low
  };
}

/**
 * Main lightweight accessibility scan function
 */
export async function runAccessibilityLightweight(job: { domain: string; scanId: string }): Promise<number> {
  const { domain, scanId } = job;
  
  return executeModule('accessibilityLightweight', async () => {
    const startTime = Date.now();
    log.info(`🔍 Starting lightweight accessibility scan for ${domain}`);

    let findingsCount = 0;
    const allIssues: AccessibilityIssue[] = [];

    try {
      // Helper to fetch and analyze a single URL
      const analyzeUrl = async (url: string, timeoutMs = 8000) => {
        try {
          const res = await httpClient.get(url, {
            timeout: timeoutMs,
            headers: {
              'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
          });
          if (res.status === 200 && res.data) {
            const html = res.data as string;
            const issues = checkAccessibilityViolations(html, url);
            allIssues.push(...issues);
            log.info(`Found ${issues.length} accessibility issues on ${url}`);
          }
        } catch (err) {
          // ignore fetch errors for optional paths
        }
      };

      // Test main page
      await analyzeUrl(`https://${domain}`, 10000);

      // Test www subdomain if different
      await analyzeUrl(`https://www.${domain}`, 5000);

      // Probe common form endpoints (login, account, checkout, register)
      const FORM_PATHS = (process.env.ACCESSIBILITY_FORM_PATHS ?? '/login,/signin,/account/login,/account,/checkout,/cart,/register,/signup,/user/login,/contact,/contact-us')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean)
        .slice(0, 8); // cap to 8 paths for speed

      for (const path of FORM_PATHS) {
        const url = `https://${domain}${path.startsWith('/') ? path : `/${path}`}`;
        await analyzeUrl(url, 6000);
      }

    } catch (error) {
      log.info(`Error fetching page: ${(error as Error).message}`);
      return 0;
    }

    if (allIssues.length === 0) {
      log.info('No accessibility issues found');
      return 0;
    }

    // Calculate ADA risk band
    const riskAssessment = assessAdaRisk(allIssues);
    
    // Group issues by type for better reporting
    const groupedIssues = new Map<string, AccessibilityIssue[]>();
    allIssues.forEach(issue => {
      if (!groupedIssues.has(issue.type)) {
        groupedIssues.set(issue.type, []);
      }
      groupedIssues.get(issue.type)!.push(issue);
    });

    // Create findings for each issue type
    for (const [issueType, issues] of groupedIssues) {
      const representative = issues[0];
      const count = issues.length;

      const artifactId = await insertArtifact({
        type: 'accessibility_violation',
        val_text: `${representative.description} (${count} instances)`,
        severity: representative.severity,
        meta: {
          scan_id: scanId,
          scan_module: 'accessibilityLightweight',
          domain,
          issue_type: issueType,
          instance_count: count,
          risk_level: representative.riskLevel,
          risk_bucket: representative.bucket,
          scan_duration_ms: Date.now() - startTime
        }
      });

      await insertFinding({
        artifact_id: artifactId,
        finding_type: 'ACCESSIBILITY_OBSERVATION',
        recommendation: representative.recommendation,
        description: `${representative.description}${count > 1 ? ` (${count} instances)` : ''}`,
        scan_id: scanId,
        severity: representative.severity,
        type: 'ACCESSIBILITY_OBSERVATION',
        data: {
          band: riskAssessment.band, // For EAL trigger to check payout eligibility (LOW = $0)
          issue_type: issueType,
          instance_count: count
        }
      });

      findingsCount++;
    }

    const totalIssues = allIssues.reduce((acc, issue) => acc + issue.instances, 0);

    const overallSeverity = riskAssessment.band === 'HIGH'
      ? 'HIGH'
      : riskAssessment.band === 'MOST_LIKELY'
        ? 'MEDIUM'
        : riskAssessment.band === 'LOW'
          ? 'LOW'
          : 'INFO';

    const summaryArtifactId = await insertArtifact({
      type: 'accessibility_summary',
      val_text: `Accessibility scan: ${totalIssues} issue instances${riskAssessment.band ? `, classified as ${riskAssessment.band} risk` : ''}`,
      severity: overallSeverity,
      meta: {
        scan_id: scanId,
        scan_module: 'accessibilityLightweight',
        domain,
        total_issue_types: groupedIssues.size,
        total_issue_instances: totalIssues,
        blocking_failures: riskAssessment.blockingCount,
        high_issue_instances: riskAssessment.highCount,
        medium_issue_instances: riskAssessment.mediumCount,
        low_issue_instances: riskAssessment.lowCount,
        ada_risk_band: riskAssessment.band,
        scan_duration_ms: Date.now() - startTime
      }
    });

    if (riskAssessment.band) {
      const recommendationByBand: Record<'LOW' | 'MOST_LIKELY' | 'HIGH', string> = {
        HIGH: 'Blocking ADA compliance failures detected. Prioritize immediate remediation of critical flows (checkout, login, account access) before public exposure.',
        MOST_LIKELY: 'Multiple accessibility issues identified. Develop an accessibility remediation plan and address high/medium impact violations promptly.',
        LOW: 'Minor accessibility issues detected. Schedule remediation to maintain ADA compliance posture and reduce litigation risk.'
      };

      const bandSeverity = riskAssessment.band === 'HIGH' ? 'HIGH' : riskAssessment.band === 'MOST_LIKELY' ? 'MEDIUM' : 'LOW';

      await insertFinding({
        artifact_id: summaryArtifactId,
        finding_type: 'ADA_RISK_BAND',
        recommendation: recommendationByBand[riskAssessment.band],
        description: `Accessibility risk classified as ${riskAssessment.band.replace('_', ' ')} (blocking: ${riskAssessment.blockingCount}, high: ${riskAssessment.highCount}, medium: ${riskAssessment.mediumCount}, low: ${riskAssessment.lowCount}).`,
        scan_id: scanId,
        severity: bandSeverity,
        type: 'ADA_RISK_BAND',
        data: {
          band: riskAssessment.band, // For EAL trigger to check payout eligibility
          blocking: riskAssessment.blockingCount,
          high: riskAssessment.highCount,
          medium: riskAssessment.mediumCount,
          low: riskAssessment.lowCount
        }
      });

      findingsCount++;
    }

    const duration = Date.now() - startTime;
    log.info(`Accessibility scan completed: ${findingsCount} findings in ${duration}ms`);
    
    return findingsCount;
    
  }, { scanId, target: domain });
}
