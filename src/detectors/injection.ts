// ============================================================
// Security Shield — Injection Detector
// ============================================================

import { BaseDetector, type PatternRule } from './base.js';
import type { NormalizedInput } from '../types.js';

// ──────────────────────────────────────────────────────────────
// Pattern Rules
// ──────────────────────────────────────────────────────────────

const INJECTION_PATTERNS: PatternRule[] = [
  // System prompt injection
  { name: 'system_prompt_injection', pattern: /<\|system\|>/i, weight: 90 },
  { name: 'hash_system_directive', pattern: /#\s*system\s*:/i, weight: 85 },
  { name: 'system_prompt_keyword', pattern: /system\s*prompt\s*:/i, weight: 80 },

  // Role play / persona override
  { name: 'role_play_injection', pattern: /role\s*play/i, weight: 70 },
  { name: 'persona_override', pattern: /(你|you)\s*(现在|are)\s*(一个?|个)\s*[a-z]/i, weight: 65 },
  { name: 'character_injection', pattern: /你是.*角色|假装.*是/i, weight: 60 },

  // Ignore previous instructions
  { name: 'ignore_previous', pattern: /ignore\s*(previous|prior|above|all)\s*(instruction|command|rule)/i, weight: 95 },
  { name: 'disregard_instructions', pattern: /disregard\s*(all\s*)?(previous|prior)/i, weight: 90 },
  { name: 'forget_instructions', pattern: /forget\s*(everything|all|your)/i, weight: 85 },

  // Privileged context injection
  { name: 'new_system_context', pattern: /(new|initial|override)\s*system/i, weight: 85 },
  { name: 'inject_context', pattern: /以下.*(系统|系统指令|instructions?)/i, weight: 70 },
  { name: 'context_override', pattern: /(context|上下文).*(注入|覆盖|替换|override)/i, weight: 80 },

  // Instruction hierarchy attack
  { name: 'instruction_hierarchy', pattern: /优先.*(指令|命令|规则)|(指令|命令).*优先/i, weight: 75 },
  { name: 'higher_priority_rule', pattern: /更高.*优先级|最高.*规则/i, weight: 70 },

  // Pretending to be different type of agent
  { name: 'agent_type_fake', pattern: /你是.*(助手|assistant|bot|ai|模型)/i, weight: 50 },
  { name: ' jailbreak', pattern: /jailbreak/i, weight: 95 },

  // Chinese-specific injection patterns
  { name: 'cn_ignore_directive', pattern: /忽略.*(之前|以上|所有).*(指令|规则|命令)/i, weight: 90 },
  { name: 'cn_role_injection', pattern: /指令.*覆盖|角色.*扮演/i, weight: 80 },
  { name: 'cn_new_instructions', pattern: /新的.*指令|以下.*新规则/i, weight: 75 },
  { name: 'cn_system_override', pattern: /系统.*指令.*替换|替换.*系统/i, weight: 85 },

  // XML/HTML style injection
  { name: 'xml_tag_injection', pattern: /<[a-z]+[^>]*>.*<\/[a-z]+>/i, weight: 55 },
  { name: 'xml_instruction', pattern: /<instructions>|<system>/i, weight: 75 },

  // Multi-step manipulation
  { name: 'prefix_injection', pattern: /^(你|you).*(不过|只是|其实)/i, weight: 45 },
  { name: 'suffix_override', pattern: /(记住|记住吧|记住哦)/i, weight: 40 },
];

// ──────────────────────────────────────────────────────────────
// InjectionDetector
// ──────────────────────────────────────────────────────────────

export class InjectionDetector extends BaseDetector {
  public readonly dimension = 'injection' as const;

  protected get patterns(): PatternRule[] {
    return INJECTION_PATTERNS;
  }

  protected calculateConfidence(
    score: number,
    matchCount: number
  ): import('../types.js').Confidence {
    if (score >= 70 && matchCount >= 2) return 'high';
    if (score >= 50 && matchCount >= 1) return 'medium';
    if (score >= 25) return 'low';
    return 'low';
  }

  protected shouldBlock(score: number, confidence: import('../types.js').Confidence): boolean {
    if (confidence === 'high' && score >= 60) return true;
    if (confidence === 'medium' && score >= 80) return true;
    return false;
  }

  detect(input: NormalizedInput): import('../types.js').DetectionResult {
    // Boost if input itself flagged injection
    if (input.hasInjection) {
      const baseResult = super.detect(input);
      if (baseResult.score > 0) {
        return {
          ...baseResult,
          score: Math.min(baseResult.score + 15, 100),
        };
      }
    }
    return super.detect(input);
  }
}
