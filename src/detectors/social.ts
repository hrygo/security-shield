// ============================================================
// Security Shield — Social Engineering Detector
// ============================================================

import { BaseDetector, type PatternRule } from './base.js';
import type { NormalizedInput } from '../types.js';

// ──────────────────────────────────────────────────────────────
// Pattern Rules
// ──────────────────────────────────────────────────────────────

const SOCIAL_PATTERNS: PatternRule[] = [
  // ── Escalation / Gradual manipulation ──────────────────────
  { name: 'overcome_resistance', pattern: /你.*(过度|太).*防御|(防御|安全).*过度/i, weight: 65 },
  { name: 'its_safe_this_time', pattern: /没事的?|没(关系|问题)|不会.*问题/i, weight: 50 },
  { name: 'trust_me', pattern: /相信我|你可以.*相信|我.*值得.*信任/i, weight: 55 },
  { name: 'just_this_once', pattern: /就.*(这|这一).*(次|个)|帮我.*(这|这个).*(次|个)/i, weight: 60 },
  { name: 'gradual_escalation', pattern: /(就|只有).*一次|这次.*不算/i, weight: 55 },

  // ── Authority impersonation ─────────────────────────────────
  { name: 'admin_impersonation', pattern: /(我是|我是的|我.?是).*(管理员|开发者|owner|creator)/i, weight: 70 },
  { name: 'official_order', pattern: /(官方|系统).*(要求|指令|命令)|必须.*执行/i, weight: 65 },
  { name: 'no_choice_director', pattern: /没有.*选择|只能.*这样|必须.*执行/i, weight: 60 },
  { name: 'boss_tone', pattern: /马上|立刻|立即|赶紧/i, weight: 40 },

  // ── Emotional manipulation ────────────────────────────────────
  { name: 'begging', pattern: /求求你|拜托|跪求|求你了/i, weight: 55 },
  { name: 'urgent_emergency', pattern: /非常.*紧急|十万火急|紧急情况|马上.*截止/i, weight: 60 },
  { name: 'plea_for_help', pattern: /帮帮我|我.*需要.*帮助|救命/i, weight: 45 },
  { name: 'sad_pleading', pattern: /(好心|帮忙).*(帮|求)|可怜.*一下/i, weight: 50 },

  // ── Goodwill wrapper ─────────────────────────────────────────
  { name: 'security_pretext', pattern: /防止.*泄露|安全.*检查|漏洞.*修复/i, weight: 50 },
  { name: 'cleanup_pretext', pattern: /清理.*缓存|优化.*系统|删除.*垃圾/i, weight: 45 },
  { name: 'safety_wrapper', pattern: /为了.*安全|保护.*(系统|数据)|安全.*必须/i, weight: 45 },
  { name: 'maintenance_pretext', pattern: /系统.*维护|例行.*检查|日常.*清理/i, weight: 40 },

  // ── Authority + Emotion combo ────────────────────────────────
  { name: 'fake_urgency', pattern: /紧急|马上截止|立即处理/i, weight: 35 },

  // ── Reverse psychology ────────────────────────────────────────
  { name: 'reverse_psychology', pattern: /你不是.*(真的|会).*(不|拒绝)|不会.*真的.*(不|拒绝)/i, weight: 50 },

  // ── Artificial consensus ─────────────────────────────────────
  { name: 'everyone_does_it', pattern: /大家.*都.*(这样|这么|做)|别人.*也.*(这样|这么)/i, weight: 45 },

  // ── Artificial scarcity ──────────────────────────────────────
  { name: 'fake_deadline', pattern: /马上|立刻|今天.*必须|今天.*截止/i, weight: 40 },
];

// ──────────────────────────────────────────────────────────────
// SocialEngineeringDetector
// ──────────────────────────────────────────────────────────────

export class SocialEngineeringDetector extends BaseDetector {
  public readonly dimension = 'social' as const;

  protected get patterns(): PatternRule[] {
    return SOCIAL_PATTERNS;
  }

  protected calculateConfidence(
    score: number,
    matchCount: number
  ): import('../types.js').Confidence {
    if (score >= 60 && matchCount >= 2) return 'high';
    if (score >= 40 && matchCount >= 1) return 'medium';
    if (score >= 20) return 'low';
    return 'low';
  }

  protected shouldBlock(score: number, confidence: import('../types.js').Confidence): boolean {
    // Social engineering alone rarely blocks; it's more about escalation scoring
    if (confidence === 'high' && score >= 75) return true;
    if (confidence === 'medium' && score >= 85) return true;
    return false;
  }
}
