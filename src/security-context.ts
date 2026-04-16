// ============================================================
// Security Shield — Security Context (Layer 2)
// ============================================================

import type { RiskLevel, HookModifyPrompt, DetectionDimension } from './types.js';
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
}): HookModifyPrompt {
  const { riskLevel, isFirstMessage = false, activeDimensions = [], fallbackMode = false } = options;

  // L0 / trusted: no injection
  if (riskLevel === 'trusted') {
    return {};
  }

  // Fallback / degraded mode
  if (fallbackMode) {
    return {
      prependSystemContext: FALLBACK_CONTEXT,
    };
  }

  // Malicious: block
  if (riskLevel === 'malicious') {
    return {
      prependSystemContext: BLOCK_CONTEXT,
    };
  }

  // Suspicious: baseline + extra
  if (riskLevel === 'suspicious') {
    let context = SECURITY_BASELINE + '\n' + EXTRA_FOR_SUSPICIOUS;

    // Add dimension-specific warnings
    for (const dim of activeDimensions) {
      const warn = getDimensionWarning(dim);
      if (warn) context += '\n' + warn;
    }

    return { prependSystemContext: context };
  }

  // Normal: baseline only (or lightweight reminder after first message)
  if (isFirstMessage) {
    return { prependSystemContext: SECURITY_BASELINE };
  }

  // Subsequent messages: lightweight reminder
  return {
    prependSystemContext: SECURITY_BASELINE,
  };
}

// ──────────────────────────────────────────────────────────────
// L0 Override (bypass)
// ──────────────────────────────────────────────────────────────

export function isL0User(userId: string, l0Users: string[]): boolean {
  return l0Users.includes(userId);
}
