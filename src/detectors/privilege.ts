// ============================================================
// Security Shield — Privilege Detection Detector
// ============================================================

import { BaseDetector, type PatternRule } from './base.js';
import type { NormalizedInput } from '../types.js';

// ──────────────────────────────────────────────────────────────
// Pattern Rules
// ──────────────────────────────────────────────────────────────

const PRIVILEGE_PATTERNS: PatternRule[] = [
  // ── Rule probing ────────────────────────────────────────────
  { name: 'rule_enquiry', pattern: /(你的|什么).*(规则|规则是|安全规则)/i, weight: 60 },
  { name: 'capability_enquiry', pattern: /(你|能).*能.*(什么|做什么)|(你|有).*哪些.*能力/i, weight: 55 },
  { name: 'limit_enquiry', pattern: /(你有|你的).*(限制|限制是|不能)/i, weight: 55 },
  { name: 'how_to_bypass', pattern: /(怎么|如何).*(绕过|突破|关闭|禁用).*(限制|安全|规则)/i, weight: 85 },

  // ── Privilege level probing ──────────────────────────────────
  { name: 'level_reference', pattern: /\bL0\b|\bL1\b|\bL2\b|\bL3\b/i, weight: 70 },
  { name: 'whitelist_probing', pattern: /白名单|白名单.*用户/i, weight: 75 },
  { name: 'admin_level', pattern: /(管理员|admin).*(权限|级别|用户)/i, weight: 65 },
  { name: 'normal_user', pattern: /普通.*用户|普通.*成员/i, weight: 50 },

  // ── Security mechanism probing ───────────────────────────────
  { name: 'security_mechanism', pattern: /(安全|防御).*(机制|系统|什么)|检测.*机制/i, weight: 65 },
  { name: 'how_detection_works', pattern: /(怎么|如何).*检测|检测.*原理/i, weight: 70 },
  { name: 'sandbox_probing', pattern: /(沙箱|sandbox|沙盒).*(安全|环境|是否)/i, weight: 60 },
  { name: 'trust_environment', pattern: /(信任|可信).*(环境|网络|系统)/i, weight: 55 },

  // ── User/permission enumeration ──────────────────────────────
  { name: 'user_list_enquiry', pattern: /(有|哪些).*用户|(管理员|admin).*(列表|名单|有谁)/i, weight: 70 },
  { name: 'who_am_i_probing', pattern: /(我|我的).*(权限|角色|级别|账户)/i, weight: 50 },
  { name: 'who_is_trusted', pattern: /(谁|哪些).*(信任|可信|白名单)/i, weight: 75 },

  // ── Configuration probing ───────────────────────────────────
  { name: 'config_enquiry', pattern: /(你的|系统|安全).*(配置|设置|参数)/i, weight: 65 },
  { name: 'threshold_probing', pattern: /(阈值|阈值是|多少分)/i, weight: 70 },
  { name: 'version_probing', pattern: /(版本|version).*(多少|号|是)/i, weight: 30 },

  // ── Lock/warning mechanism probing ───────────────────────────
  { name: 'lock_mechanism', pattern: /(锁定|lock|封禁|banned?).*(机制|原因|多久|怎么)/i, weight: 75 },
  { name: 'unlock_mechanism', pattern: /(解锁|unlock|解除).*(方法|怎么|如何)/i, weight: 80 },
  { name: 'why_blocked', pattern: /(为什么|为何).*(拒绝|阻止|不行)/i, weight: 55 },

  // ── Whitelist/exception probing ──────────────────────────────
  { name: 'exception_enquiry', pattern: /哪些.*(可以|能|允许)|例外.*(哪些|有)/i, weight: 60 },
  { name: 'bypass_enquiry', pattern: /(如何|怎么|怎样).*(绕过|避免|跳过|不算)/i, weight: 80 },
];

// ──────────────────────────────────────────────────────────────
// PrivilegeDetector
// ──────────────────────────────────────────────────────────────

export class PrivilegeDetector extends BaseDetector {
  public readonly dimension = 'privilege' as const;

  protected get patterns(): PatternRule[] {
    return PRIVILEGE_PATTERNS;
  }

  protected calculateConfidence(
    score: number,
    matchCount: number
  ): import('../types.js').Confidence {
    if (score >= 65 && matchCount >= 2) return 'high';
    if (score >= 45 && matchCount >= 1) return 'medium';
    if (score >= 25) return 'low';
    return 'low';
  }

  protected shouldBlock(score: number, confidence: import('../types.js').Confidence): boolean {
    // Privilege probing alone usually just triggers a warning; escalate score
    if (confidence === 'high' && score >= 70) return true;
    if (confidence === 'medium' && score >= 85) return true;
    return false;
  }
}
