import OpenAI from 'openai';
import {
  ModuleRemediationPayload,
  RemediationGuidance,
  RemediationPriority,
  RemediationSource,
  RemediationStep,
  normalizePriority,
  severityToPriority,
  REMEDIATION_GUIDANCE_VERSION
} from '../core/remediation.js';
import { getBaselineRemediation } from './remediationBaseline.js';
import { createModuleLogger } from '../core/logger.js';

const log = createModuleLogger('remediationOrchestrator');

export type RemediationReportType = 'report' | 'snapshot-report' | 'snapshot-modern' | 'technical-report';

interface RemediationOptions {
  useLLM?: boolean;
  reportType?: RemediationReportType;
  temperature?: number;
  maxTokens?: number;
  logger?: (message: string, meta?: Record<string, unknown>) => void;
}

const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY, timeout: 30_000 })
  : null;

const DEFAULT_TIMELINE_BY_PRIORITY: Record<RemediationPriority, string> = {
  Immediate: 'Begin remediation within 24 hours',
  High: 'Address within 7 days',
  Medium: 'Schedule within 30 days',
  Low: 'Plan for the next maintenance cycle'
};

const DEFAULT_EFFORT_BY_PRIORITY: Record<RemediationPriority, RemediationGuidance['effort']> = {
  Immediate: 'High',
  High: 'High',
  Medium: 'Medium',
  Low: 'Low'
};

const GENERIC_STEPS: RemediationStep[] = [
  {
    summary: 'Assess the finding in your environment',
    verification: ['Document affected systems and scope of exposure']
  },
  {
    summary: 'Implement corrective changes',
    verification: ['Apply configuration or code updates', 'Peer review the change before deployment']
  },
  {
    summary: 'Validate and monitor the fix',
    verification: ['Re-run the SimplCyber scan', 'Enable monitoring or alerting for recurrence']
  }
];

const defaultLogger = (message: string, meta?: Record<string, unknown>) => {
  if (meta) {
    log.info(meta, message);
  } else {
    log.info(message);
  }
};

export async function generateRemediationGuidance(
  payload: ModuleRemediationPayload,
  options: RemediationOptions = {}
): Promise<RemediationGuidance> {
  const mergedOptions: RemediationOptions = {
    useLLM: true,
    reportType: 'technical-report',
    temperature: 0.3,
    maxTokens: 1_000,
    logger: defaultLogger,
    ...options
  };

  log.debug({
    findingType: payload.finding?.type,
    module: payload.context.moduleName,
    useLLM: mergedOptions.useLLM,
    openaiAvailable: !!openai
  }, 'Remediation generation start');

  const severityPriority = severityToPriority(payload.finding.severity);
  log.debug({ severityPriority }, 'Calculated severity priority');

  const baseline = payload.baseGuidance
    || getBaselineRemediation(payload.context.moduleName, severityPriority, payload.finding);

  log.debug({
    baselineSource: baseline?.source ?? 'NONE',
    hasSteps: !!baseline?.steps?.length,
    fromLibrary: !!baseline?.metadata?.from_library
  }, 'Baseline guidance resolved');

  const baseGuidance = normalizeGuidance(baseline, severityPriority, payload.context);
  log.debug({ stepsCount: baseGuidance?.steps?.length ?? 0 }, 'After normalize');

  if (!mergedOptions.useLLM || !openai) {
    log.debug({ firstStep: baseGuidance?.steps?.[0]?.summary?.substring(0, 50) }, 'Returning baseline (LLM disabled or unavailable)');
    return withSource(baseGuidance, baseGuidance.source ?? 'module');
  }

  try {
    const aiGuidance = await generateAiGuidance(payload, mergedOptions);
    if (!aiGuidance) {
      mergedOptions.logger?.('LLM returned empty guidance, using module defaults', {
        scanId: payload.context.scanId,
        module: payload.context.moduleName
      });
      return withSource(baseGuidance, baseGuidance.source ?? 'module');
    }

    const combined = mergeGuidance(baseGuidance, aiGuidance);
    combined.version = REMEDIATION_GUIDANCE_VERSION;
    return withSource(combined, combined.source ?? 'llm');
  } catch (error) {
    mergedOptions.logger?.('LLM remediation generation failed, falling back to module guidance', {
      error: error instanceof Error ? error.message : String(error),
      scanId: payload.context.scanId,
      module: payload.context.moduleName
    });
    const fallback = {
      ...baseGuidance,
      source: baseGuidance.source ?? 'module',
      metadata: {
        ...baseGuidance.metadata,
        llm_error: error instanceof Error ? error.message : String(error)
      },
      version: REMEDIATION_GUIDANCE_VERSION
    } as RemediationGuidance;
    return withSource(fallback, fallback.source ?? 'module');
  }
}

function normalizeGuidance(
  guidance: RemediationGuidance | undefined,
  severityPriority: RemediationPriority,
  context: ModuleRemediationPayload['context']
): RemediationGuidance {
  if (guidance) {
    const priority = guidance.priority ?? severityPriority;
    return {
      priority,
      timeline: guidance.timeline ?? DEFAULT_TIMELINE_BY_PRIORITY[priority],
      description: guidance.description ?? payloadAwareDescription(context),
      businessImpact: guidance.businessImpact,
      ownerHint: guidance.ownerHint,
      effort: guidance.effort ?? DEFAULT_EFFORT_BY_PRIORITY[priority],
      verification: guidance.verification ?? [],
      steps: guidance.steps && guidance.steps.length > 0 ? guidance.steps : GENERIC_STEPS,
      additionalHardening: guidance.additionalHardening,
      references: guidance.references,
      source: guidance.source ?? 'module',
      rawResponse: guidance.rawResponse,
      generatedAt: guidance.generatedAt ?? new Date().toISOString(),
      metadata: {
        ...guidance.metadata,
        severity: context.severity,
        module: context.moduleName
      },
      version: guidance.version ?? REMEDIATION_GUIDANCE_VERSION
    };
  }

  return {
    priority: severityPriority,
    timeline: DEFAULT_TIMELINE_BY_PRIORITY[severityPriority],
    description: payloadAwareDescription(context),
    businessImpact: undefined,
    ownerHint: undefined,
    effort: DEFAULT_EFFORT_BY_PRIORITY[severityPriority],
    verification: [],
    steps: GENERIC_STEPS,
    additionalHardening: undefined,
    references: undefined,
    source: 'module',
    generatedAt: new Date().toISOString(),
    metadata: {
      severity: context.severity,
      module: context.moduleName
    },
    version: REMEDIATION_GUIDANCE_VERSION
  };
}

function payloadAwareDescription(context: ModuleRemediationPayload['context']): string | undefined {
  if (!context.moduleName) return undefined;
  if (context.moduleName === 'tlsScan') {
    return 'Harden TLS configuration by disabling weak protocols and deploying a trusted certificate.';
  }
  if (context.moduleName === 'spf_dmarc') {
    return 'Update SPF, DKIM, and DMARC policies to enforce authentication and prevent spoofing.';
  }
  return undefined;
}

async function generateAiGuidance(
  payload: ModuleRemediationPayload,
  options: RemediationOptions
): Promise<RemediationGuidance | null> {
  if (!openai) return null;

  const messages = buildMessages(payload, options.reportType ?? 'technical-report');
  const completion = await openai.chat.completions.create({
    model: process.env.OPENAI_MODEL || 'gpt-4o-mini-2024-07-18',
    messages,
    temperature: options.temperature,
    max_tokens: options.maxTokens
  });

  const response = completion.choices?.[0]?.message?.content?.trim();
  if (!response) return null;

  const parsed = parseAiResponse(response);
  const priority = parsed.priority ?? severityToPriority(payload.finding.severity);

  return {
    priority,
    timeline: parsed.timeline ?? DEFAULT_TIMELINE_BY_PRIORITY[priority],
    description: parsed.description,
    businessImpact: parsed.businessImpact,
    ownerHint: parsed.ownerHint,
    effort: parsed.effort ?? DEFAULT_EFFORT_BY_PRIORITY[priority],
    verification: parsed.verification,
    steps: parsed.steps,
    additionalHardening: parsed.additionalHardening,
    references: parsed.references,
    rawResponse: response,
    generatedAt: new Date().toISOString(),
    source: 'llm',
    metadata: {
      model: completion.model,
      usage: completion.usage,
      reportType: options.reportType,
      module: payload.context.moduleName,
      scanId: payload.context.scanId
    }
  };
}

function buildMessages(
  payload: ModuleRemediationPayload,
  reportType: RemediationReportType
): OpenAI.Chat.Completions.ChatCompletionMessageParam[] {
  const systemPrompt = getSystemPrompt(reportType);
  const baseInfo = buildBasePrompt(payload);
  const moduleHints = buildModuleHints(payload);
  const userContent = `${baseInfo}\n\nUse US English (American spelling). Provide precise, technician-ready steps with commands and concrete examples. ${moduleHints}\n\nFormat your response as follows:
1. Start with 1-2 sentences explaining the business impact (based on the BUSINESS IMPACT guidance above)
2. Then provide numbered remediation steps
3. Put command-line examples in code blocks using triple backticks (\`\`\`bash ... \`\`\`)
4. End with a validation checklist as a bulleted list

Example code block format:
\`\`\`bash
curl -X POST https://api.example.com/reset \\
  -H "Authorization: Bearer TOKEN" \\
  -d '{"email": "user@example.com"}'
\`\`\`

Use Markdown for formatting: **bold** for emphasis, \`inline code\` for short commands/filenames, code blocks for multi-line commands, and bulleted/numbered lists.`;
  return [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: userContent }
  ];
}

function buildModuleHints(payload: ModuleRemediationPayload): string {
  const mod = String(payload.context.moduleName || '').toLowerCase();
  const findingType = String(payload.finding.type || '').toLowerCase();

  // Business impact guidance based on finding type
  let impactHint = '';
  if (findingType.includes('breach') || findingType.includes('credential') || findingType.includes('infostealer') || mod.includes('infostealer')) {
    impactHint = 'BUSINESS IMPACT: Employee/customer credentials found in breach databases mean attackers can directly access your company accounts, services, and data RIGHT NOW. This enables account takeover, data theft, financial fraud, and lateral movement into your systems. Immediate forced password resets required.';
  } else if (mod.includes('tls') || findingType.includes('tls') || findingType.includes('certificate')) {
    impactHint = 'BUSINESS IMPACT: Missing or weak TLS/SSL exposes customer data (passwords, payment info, personal data) in transit. Browsers show "Not Secure" warnings that drive customers away. Required for PCI-DSS, HIPAA, and GDPR compliance.';
  } else if (mod.includes('spf') || mod.includes('dmarc') || mod.includes('email')) {
    impactHint = 'BUSINESS IMPACT: Without proper email authentication, attackers can impersonate your domain to phish your customers, partners, and employees. This damages your brand reputation and enables business email compromise (BEC) fraud that costs companies millions.';
  } else if (mod.includes('exposed_service') || mod.includes('exposed_database') || findingType.includes('exposed')) {
    impactHint = 'BUSINESS IMPACT: Publicly exposed services/databases can be directly accessed and exploited by attackers. This can lead to data breaches, ransomware, system compromise, and regulatory fines. Should only be accessible from trusted networks.';
  } else if (findingType.includes('secret') || findingType.includes('sensitive_file')) {
    impactHint = 'BUSINESS IMPACT: Exposed API keys, credentials, or sensitive files let attackers access your services, run up cloud bills, steal data, or pivot to other systems. Leaked keys must be rotated immediately as they may already be compromised.';
  }

  // Technical remediation hints
  let techHint = '';
  if (mod.includes('tls')) {
    techHint = 'TECHNICAL: include steps to obtain a certificate (e.g., Let\'s Encrypt Certbot) and install for common servers (Nginx, Apache). Show sample Nginx/Apache config snippets to disable TLSv1.0/1.1 and weak ciphers. Include commands to test (openssl s_client, nmap --script ssl-enum-ciphers), and note how to reload the server.';
  } else if (mod.includes('spf') || mod.includes('dmarc') || mod.includes('email')) {
    techHint = 'TECHNICAL: include sample SPF (v=spf1 include:_spf.example.com -all), DKIM selector setup, and a DMARC record (v=DMARC1; p=quarantine; rua=mailto:security@example.com). Add verification commands (dig/nslookup) and note propagation and raising DMARC policy after monitoring.';
  } else if (mod.includes('exposed_service') || mod.includes('exposed_database') || mod.includes('cloud')) {
    techHint = 'TECHNICAL: include firewall/security-group rules to restrict ingress to trusted IPs or private networks, remove public exposure from console/CLI, rotate credentials, and test from outside the network to confirm closure.';
  } else if (mod.includes('client_side_secret') || mod.includes('sensitive_file')) {
    techHint = 'TECHNICAL: detail how to remove the asset from public paths, rotate leaked keys, add deny rules, and verify with HTTP requests that the resource is no longer accessible.';
  }

  return [impactHint, techHint].filter(Boolean).join(' ');
}

function buildBasePrompt(payload: ModuleRemediationPayload): string {
  const finding = payload.finding;
  const metadata = JSON.stringify(finding.metadata ?? {}, null, 2);
  return [
    'Security Finding Details:',
    `- Type: ${finding.type ?? 'unknown'}`,
    `- Severity: ${finding.severity ?? 'unknown'}`,
    `- Title: ${finding.title ?? 'missing title'}`,
    `- Description: ${finding.description ?? 'No description provided'}`,
    `- Domain: ${payload.context.domain}`,
    `- Module: ${payload.context.moduleName ?? 'unknown'}`,
    `- Metadata: ${metadata}`
  ].join('\n');
}

function getSystemPrompt(reportType: RemediationReportType): string {
  switch (reportType) {
    case 'snapshot-report':
      return 'You are a cybersecurity expert speaking to business decision makers. Provide concise, high-level remediation guidance under 120 words.';
    case 'technical-report':
      return 'You are a senior security engineer writing for business owners who will read this first. Start with 1-2 sentences explaining why this security issue matters to the business in plain English (customer trust, revenue impact, compliance risk, etc.). Then provide detailed remediation runbooks with commands, configuration guidance, and validation steps.';
    default:
      return 'You are a cybersecurity expert providing remediation advice that balances business and technical detail.';
  }
}

function parseAiResponse(response: string): Partial<RemediationGuidance> {
  const lines = response.split('\n').map(line => line.trim()).filter(Boolean);

  const priority = extractPriority(lines);
  const timeline = extractTimeline(lines);
  const description = extractDescription(lines);
  const steps = extractSteps(lines);
  const verification = extractVerification(lines);

  // Try to extract business impact from marked sections first
  let businessImpact = extractSection(lines, ['business impact', 'impact explanation', 'what this means', 'why this matters']);

  // If no marked section, grab the first 2-3 sentences before any steps/lists
  if (!businessImpact) {
    const firstFewLines: string[] = [];
    for (const line of lines) {
      // Stop if we hit a numbered list, bullet, or header
      if (/^\d+\.|^[-*•]|^#+\s/.test(line)) break;
      // Skip metadata-like lines (Priority:, Timeline:, etc.)
      if (/^(priority|timeline|effort|objective):/i.test(line)) continue;
      firstFewLines.push(line);
      // Stop after ~2-3 sentences
      if (firstFewLines.join(' ').split(/[.!?]/).length >= 3) break;
    }
    if (firstFewLines.length > 0) {
      businessImpact = firstFewLines.join(' ');
    }
  }

  const effortRaw = extractEffort(lines);

  return {
    priority: priority ?? 'Medium',
    timeline: timeline ?? DEFAULT_TIMELINE_BY_PRIORITY[priority ?? 'Medium'],
    description,
    businessImpact: businessImpact ?? undefined,
    verification,
    steps,
    effort: effortRaw ? (effortRaw as RemediationGuidance['effort']) : undefined,
    source: 'llm'
  };
}

function extractPriority(lines: string[]): RemediationPriority | undefined {
  const priorityRegex = /(immediate|critical|high|medium|low)\s+(priority|risk|urgency)/i;
  for (const line of lines) {
    const match = line.match(priorityRegex);
    if (match) {
      return normalizePriority(match[1]);
    }
  }
  return undefined;
}

function extractTimeline(lines: string[]): string | undefined {
  const timelineRegex = /(within\s+\d+\s+\w+|immediately|asap|urgent|next\s+[\w\s]+cycle)/i;
  for (const line of lines) {
    const match = line.match(timelineRegex);
    if (match) return match[0];
  }
  return undefined;
}

function extractDescription(lines: string[]): string | undefined {
  const markers = ['summary', 'business impact', 'what this means', 'description'];
  for (let i = 0; i < lines.length; i++) {
    if (markers.some(marker => lines[i].toLowerCase().includes(marker))) {
      return lines.slice(i + 1, i + 3).join(' ');
    }
  }
  return lines.slice(0, 2).join(' ');
}

function extractSteps(lines: string[]): RemediationStep[] | undefined {
  const numberedRegex = /^\d+\.\s*(.+)/;
  const bulletRegex = /^[-*•]\s*(.+)/;
  const steps: RemediationStep[] = [];

  for (const line of lines) {
    const numbered = line.match(numberedRegex);
    if (numbered) {
      steps.push({ summary: numbered[1] });
      continue;
    }
    const bullet = line.match(bulletRegex);
    if (bullet) {
      steps.push({ summary: bullet[1] });
    }
  }

  return steps.length ? steps : undefined;
}

function extractVerification(lines: string[]): string[] | undefined {
  const markers = ['verify', 'validation', 'test'];
  const matches: string[] = [];
  for (const line of lines) {
    if (markers.some(marker => line.toLowerCase().includes(marker))) {
      matches.push(line);
    }
  }
  return matches.length ? matches : undefined;
}

function extractSection(lines: string[], markers: string[]): string | undefined {
  for (let i = 0; i < lines.length; i++) {
    const lower = lines[i].toLowerCase();
    if (markers.some(marker => lower.includes(marker))) {
      // Found the marker line - now find actual content (skip markdown headers and empty lines)
      const contentLines: string[] = [];
      for (let j = i + 1; j < lines.length && contentLines.length < 2; j++) {
        const line = lines[j].trim();
        // Skip empty lines and markdown headers (###, ##, #)
        if (!line || line.startsWith('#')) {
          continue;
        }
        // Stop at the next section marker (like "Remediation Steps:", "Technical Details:")
        if (line.endsWith(':') && line.split(' ').length <= 4) {
          break;
        }
        contentLines.push(line);
      }
      return contentLines.length ? contentLines.join(' ') : undefined;
    }
  }
  return undefined;
}

function extractEffort(lines: string[]): string | undefined {
  const regex = /(low|medium|high)\s+effort/i;
  for (const line of lines) {
    const match = line.match(regex);
    if (match) {
      return match[1].charAt(0).toUpperCase() + match[1].slice(1).toLowerCase();
    }
  }
  return undefined;
}

function mergeGuidance(
  baseGuidance: RemediationGuidance,
  aiGuidance: RemediationGuidance
): RemediationGuidance {
  const priority = aiGuidance.priority ?? baseGuidance.priority;
  const timeline = aiGuidance.timeline ?? baseGuidance.timeline;
  const steps = mergeSteps(baseGuidance.steps, aiGuidance.steps);
  const verification = mergeArrays(baseGuidance.verification, aiGuidance.verification);

  return {
    priority,
    timeline,
    description: aiGuidance.description ?? baseGuidance.description,
    businessImpact: aiGuidance.businessImpact ?? baseGuidance.businessImpact,
    ownerHint: aiGuidance.ownerHint ?? baseGuidance.ownerHint,
    effort: aiGuidance.effort ?? baseGuidance.effort,
    verification,
    steps,
    additionalHardening: mergeArrays(baseGuidance.additionalHardening, aiGuidance.additionalHardening),
    references: mergeArrays(baseGuidance.references, aiGuidance.references),
    source: aiGuidance.source ?? 'llm',
    rawResponse: aiGuidance.rawResponse ?? baseGuidance.rawResponse,
    generatedAt: aiGuidance.generatedAt ?? baseGuidance.generatedAt,
    metadata: {
      ...baseGuidance.metadata,
      ...aiGuidance.metadata,
      sourceMerge: 'module+llm'
    }
  };
}

function mergeSteps(
  baseSteps?: RemediationStep[],
  aiSteps?: RemediationStep[]
): RemediationStep[] | undefined {
  if (aiSteps && aiSteps.length) return aiSteps;
  return baseSteps ?? GENERIC_STEPS;
}

function mergeArrays<T>(base?: T[], override?: T[]): T[] | undefined {
  if (override && override.length) return override;
  if (base && base.length) return base;
  return undefined;
}

function withSource(guidance: RemediationGuidance, source: RemediationSource): RemediationGuidance {
  return {
    ...guidance,
    source
  };
}

// Executive Summary Generation (scan-level)
export interface ExecutiveSummaryInput {
  domain: string;
  totalFindings: number;
  severityCounts: { critical: number; high: number; medium: number; low: number };
  categorySummary: Array<{ category: string; count: number }>;
  topFindings: Array<{ type: string; severity: string; title: string }>;
  ealSummary?: { ml?: number; low?: number; high?: number };
}

export async function generateExecutiveSummary(
  input: ExecutiveSummaryInput,
  options: { logger?: (message: string, meta?: Record<string, unknown>) => void } = {}
): Promise<string | null> {
  if (!openai) {
    options.logger?.('OpenAI not configured, skipping executive summary generation');
    return null;
  }

  try {
    const systemPrompt = `You are a cybersecurity expert briefing a business owner. Be professional but human - write like you're explaining something serious to someone who needs to understand it clearly, not like you're reading from a corporate handbook. Be direct and straightforward.`;

    const topCategories = input.categorySummary.slice(0, 3).map(c => c.category).join(', ');
    const topSeverities = Object.entries(input.severityCounts)
      .filter(([_, count]) => count > 0)
      .map(([sev, count]) => `${count} ${sev}`)
      .join(', ');

    const ealContext = input.ealSummary?.ml
      ? `The estimated annual security risk is approximately $${Math.round(input.ealSummary.ml).toLocaleString()}.`
      : '';

    const userContent = `Security Assessment for ${input.domain}:
- Total findings: ${input.totalFindings}
- Severity breakdown: ${topSeverities}
- Top categories: ${topCategories}
${ealContext}

Write a professional but straightforward paragraph (3-5 sentences) that:
1. States the main security issues in clear language (no jargon)
2. Identifies the 2-3 most important problems
3. Explains the real business consequences (financial loss, customer impact, legal risk, reputation damage)
4. Provides clear next steps with timeline

Be serious and professional, but write like you're talking to a person, not a committee. Avoid corporate buzzwords like "leverage," "synergies," "enhance frameworks," "strategic imperatives." Use US English.`;

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini-2024-07-18',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userContent }
      ],
      temperature: 0.4,
      max_tokens: 300
    });

    const summary = completion.choices?.[0]?.message?.content?.trim();
    return summary || null;
  } catch (error) {
    options.logger?.('Executive summary generation failed', {
      error: error instanceof Error ? error.message : String(error)
    });
    return null;
  }
}
