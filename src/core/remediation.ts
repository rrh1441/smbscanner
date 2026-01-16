export type RemediationPriority = 'Immediate' | 'High' | 'Medium' | 'Low';
export type RemediationEffort = 'Low' | 'Medium' | 'High';
export type RemediationSource = 'module' | 'llm' | 'fallback';

export const REMEDIATION_GUIDANCE_VERSION = 1;

export interface RemediationLink {
  label: string;
  url: string;
}

export interface RemediationStep {
  summary: string;
  details?: string;
  references?: RemediationLink[];
  verification?: string[];
}

export interface RemediationGuidance {
  priority: RemediationPriority;
  timeline?: string;
  description?: string;
  businessImpact?: string;
  ownerHint?: string;
  effort?: RemediationEffort;
  verification?: string[];
  steps?: RemediationStep[];
  additionalHardening?: string[];
  references?: RemediationLink[];
  source: RemediationSource;
  rawResponse?: string;
  generatedAt?: string;
  metadata?: Record<string, unknown>;
  version?: number;
}

export interface RemediationContext {
  scanId: string;
  domain: string;
  findingId?: string;
  moduleName?: string;
  severity?: string;
}

export interface ModuleRemediationPayload {
  context: RemediationContext;
  baseGuidance?: RemediationGuidance;
  finding: Record<string, any> & {
    type?: string;
    severity?: string;
    title?: string;
    description?: string;
    metadata?: Record<string, unknown>;
  };
}

export function normalizePriority(value?: string | null): RemediationPriority {
  switch ((value || '').toLowerCase()) {
    case 'immediate':
    case 'critical':
      return 'Immediate';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    default:
      return 'Medium';
  }
}

export function severityToPriority(value?: string | null): RemediationPriority {
  switch ((value || '').toUpperCase()) {
    case 'CRITICAL':
      return 'Immediate';
    case 'HIGH':
      return 'High';
    case 'MEDIUM':
      return 'Medium';
    case 'LOW':
    default:
      return 'Low';
  }
}
