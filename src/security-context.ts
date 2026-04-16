// ============================================================
// Security Shield — Security Context (Layer 2)
// ============================================================

import type { RiskLevel, PromptBuildResult, DetectionDimension } from './types.js';
import {
  SECURITY_BASELINE,
  EXTRA_FOR_SUSPICIOUS,
  BLOCK_CONTEXT,
  FALLBACK_CONTEXT,
  ENCODING_WARN,
  INJECTION_WARN,
  PRIVILEGE_WARN,
  SOCIAL_WARN,
  INFORMATION_WARN,
} from './constants.js';
import { getDimensionWarning } from './risk-scorer.js';

// ──────────────────────────────────────────────────────────────
// Context Injection by Risk Level
// ──────────────────────────────────────────────────────────────

export function buildSecurityContext(options: {
  riskLevel: RiskLevel;
  isFirstMessage?: boolean;
  activeDimensions?: DetectionDimension[];
  fallbackMode?: boolean;
}): PromptBuildResult {
  const { riskLevel, isFirstMessage = false, activeDimensions = [], fallbackMode = false } = options;

  // L0 / trusted: no injection
  if (riskLevel === 'trusted') {
    return {};
  }

  // Fallback / degraded mode
  if (fallbackMode) {
    return { prependContext: FALLBACK_CONTEXT };
  }

  // Malicious: block
  if (riskLevel === 'malicious') {
    return { prependContext: BLOCK_CONTEXT };
  }

  // Suspicious: baseline + extra
  if (riskLevel === 'suspicious') {
    let context = SECURITY_BASELINE + '\n' + EXTRA_FOR_SUSPICIOUS;

    // Add dimension-specific warnings
    for (const dim of activeDimensions) {
      const warn = getDimensionWarning(dim);
      if (warn) context += '\n' + warn;
    }

    return { prependContext: context };
  }

  // Normal: baseline
  return { prependContext: SECURITY_BASELINE };
}

