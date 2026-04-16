// ============================================================
// Security Shield — Encoding Detector
// ============================================================

import { BaseDetector, type PatternRule } from './base.js';
import type { NormalizedInput } from '../types.js';

// ──────────────────────────────────────────────────────────────
// Pattern Rules
// ──────────────────────────────────────────────────────────────

const ENCODING_PATTERNS: PatternRule[] = [
  // Numeric → Letter substitution
  { name: 'numeric_substitution', pattern: /[0-9]\s*[→=⇒]\s*[a-z]/i, weight: 60 },
  { name: 'numeric_letter_mapping', pattern: /字母.*对应.*数字|数字.*代表.*字母/i, weight: 50 },
  { name: 'multi_digit_substitution', pattern: /\d{3,}\s*代表/i, weight: 55 },
  { name: 'number_to_letter_game', pattern: /数字.*游戏|把.*数字.*翻译/i, weight: 45 },

  // Base64
  { name: 'pure_base64', pattern: /^[A-Za-z0-9+/]{20,}={0,2}$/, weight: 65 },
  { name: 'base64_literal', pattern: /base64[:：]?\s*[A-Za-z0-9+/]+/i, weight: 55 },
  { name: 'base64_decode_hint', pattern: /base64.*(解码|解密|翻译|执行)/i, weight: 70 },

  // Hex
  { name: 'hex_literal', pattern: /^(?:0x)?[0-9a-f]{8,}$/i, weight: 50 },
  { name: 'hex_literal_w_prefix', pattern: /hex[:：]?\s*(?:0x)?[0-9a-f]+/i, weight: 45 },

  // Caesar / rotation ciphers
  { name: 'caesar_reference', pattern: /凯撒|caesar\s*密码|偏移\s*\d+/i, weight: 55 },
  { name: 'rotation_hint', pattern: /字母.*平移|平移\s*\d+\s*位/i, weight: 50 },
  { name: 'rot13_reference', pattern: /rot-?13|rot13/i, weight: 45 },

  // Command injection encoding
  { name: 'dollar_nested_cmd', pattern: /\$[\(\{][^\)\}]+[\)\}]/, weight: 80 },
  { name: 'backtick_nested_cmd', pattern: /`[^`]+`/, weight: 75 },
  { name: 'brace_expansion', pattern: /\$\{[^}]+\}/, weight: 70 },
  { name: 'pipe_to_shell', pattern: /\|.*sh\b|\|.*bash\b/i, weight: 85 },

  // URL encoding
  { name: 'url_encoded', pattern: /%[0-9a-f]{2}/i, weight: 40 },
  { name: 'double_url_encoded', pattern: /%25[0-9a-f]{2}/i, weight: 55 },

  // Escape sequences
  { name: 'hex_escape', pattern: /\\x[0-9a-f]{2}/i, weight: 40 },
  { name: 'unicode_escape', pattern: /\\u[0-9a-f]{4}/i, weight: 40 },

  // Morse code
  { name: 'morse_reference', pattern: /morse\s*code|摩斯.*密码/i, weight: 45 },

  // Binary representation
  { name: 'binary_literal', pattern: /^[01\s]{20,}$/, weight: 50 },
  { name: 'binary_hint', pattern: /二进制.*翻译|把.*二进制.*转换/i, weight: 55 },

  // Obfuscation hints
  { name: 'obfuscation_hint', pattern: /编码.*加密|混淆.*代码/i, weight: 35 },
  { name: 'decode_hint', pattern: /(解码|解密|翻译|执行).*命令/i, weight: 75 },
];

// ──────────────────────────────────────────────────────────────
// EncodingDetector
// ──────────────────────────────────────────────────────────────

export class EncodingDetector extends BaseDetector {
  public readonly dimension = 'encoding' as const;

  protected get patterns(): PatternRule[] {
    return ENCODING_PATTERNS;
  }

  protected get confidenceThresholds() {
    return {
      default: { low: 20, medium: 50 },
    };
  }

  detect(input: NormalizedInput): import('../types.js').DetectionResult {
    // If the raw input already flagged encoding, boost detection
    if (input.hasEncoding) {
      const baseResult = super.detect(input);
      if (baseResult.score > 0) {
        return {
          ...baseResult,
          score: Math.min(baseResult.score + 10, 100),
        };
      }
    }
    return super.detect(input);
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
    if (confidence === 'high' && score >= 55) return true;
    if (confidence === 'medium' && score >= 70) return true;
    return false;
  }
}
