import { RemediationGuidance } from '../core/remediation.js';

type GuidanceSourceSummary = 'module' | 'llm' | 'fallback';

export interface RemediationStats {
  scanId: string;
  totalFindings: number;
  moduleGuidance: number;
  llmGuidance: number;
  fallbackGuidance: number;
  promptTokens: number;
  completionTokens: number;
  firstCapturedAt: string;
  lastCapturedAt: string;
}

interface UpdatePayload {
  scanId: string;
  moduleName?: string;
  guidance: RemediationGuidance | undefined;
}

const statsByScan = new Map<string, RemediationStats>();

function ensureStats(scanId: string): RemediationStats {
  const existing = statsByScan.get(scanId);
  if (existing) return existing;
  const nowIso = new Date().toISOString();
  const created: RemediationStats = {
    scanId,
    totalFindings: 0,
    moduleGuidance: 0,
    llmGuidance: 0,
    fallbackGuidance: 0,
    promptTokens: 0,
    completionTokens: 0,
    firstCapturedAt: nowIso,
    lastCapturedAt: nowIso
  };
  statsByScan.set(scanId, created);
  return created;
}

export function recordGuidanceEvent({ scanId, guidance }: UpdatePayload) {
  const stats = ensureStats(scanId);
  stats.totalFindings += 1;
  stats.lastCapturedAt = new Date().toISOString();

  const source: GuidanceSourceSummary = guidance?.source ?? 'fallback';
  if (source === 'llm') {
    stats.llmGuidance += 1;
  } else if (source === 'module') {
    stats.moduleGuidance += 1;
  } else {
    stats.fallbackGuidance += 1;
  }

  const usage = (guidance?.metadata as any)?.usage;
  if (usage) {
    const promptTokens = Number(usage.prompt_tokens ?? usage.promptTokens ?? 0);
    const completionTokens = Number(usage.completion_tokens ?? usage.completionTokens ?? 0);
    if (!Number.isNaN(promptTokens)) {
      stats.promptTokens += promptTokens;
    }
    if (!Number.isNaN(completionTokens)) {
      stats.completionTokens += completionTokens;
    }
  }
}

export function consumeStats(scanId: string): RemediationStats | null {
  const stats = statsByScan.get(scanId);
  if (!stats) return null;
  // Clone before clearing to avoid external mutation
  const clone: RemediationStats = { ...stats };
  statsByScan.delete(scanId);
  return clone;
}

export function peekStats(scanId: string): RemediationStats | null {
  const stats = statsByScan.get(scanId);
  return stats ? { ...stats } : null;
}
