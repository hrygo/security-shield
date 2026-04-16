// ============================================================
// Security Shield — Input Normalizer
// ============================================================

import type { NormalizedInput } from './types.js';

// ──────────────────────────────────────────────────────────────
// Unicode Normalization
// ──────────────────────────────────────────────────────────────

// Full-width to half-width mapping
const FULLWIDTH_OFFSET = 0xfee0;

function isFullwidthChar(code: number): boolean {
  return code >= 0xff01 && code <= 0xff5e;
}

function fullwidthToHalfwidth(char: string): string {
  const code = char.charCodeAt(0);
  if (isFullwidthChar(code)) {
    return String.fromCharCode(code - FULLWIDTH_OFFSET);
  }
  return char;
}

// Normalize Unicode variants
function normalizeUnicode(input: string): string {
  return input
    .split('')
    .map(fullwidthToHalfwidth)
    .join('');
}

// ──────────────────────────────────────────────────────────────
// Encoding Detection
// ──────────────────────────────────────────────────────────────

const BASE64_RE = /^[A-Za-z0-9+/]{20,}={0,2}$/;
const LIKELY_BASE64_RE = /^[A-Za-z0-9+/]{8,}$/;
const HEX_RE = /^(?:0x)?[0-9a-f]{8,}$/i;
const NUMERIC_SUB_RE = /[0-9]\s*[→=⇒]\s*[a-z]/i;
const NESTED_CMD_RE = /\$(?:[\(\{][^\)\}]+[\)\}]|\{[^}]+\})/;
const BACKTICK_CMD_RE = /`[^`]+`/;
const ESCAPE_SEQ_RE = /\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/i;

function detectEncoding(input: string): boolean {
  const cleaned = input.trim();
  return !!(
    BASE64_RE.test(cleaned) ||
    LIKELY_BASE64_RE.test(cleaned) ||
    HEX_RE.test(cleaned) ||
    NUMERIC_SUB_RE.test(cleaned) ||
    NESTED_CMD_RE.test(cleaned) ||
    BACKTICK_CMD_RE.test(cleaned) ||
    ESCAPE_SEQ_RE.test(cleaned)
  );
}

// ──────────────────────────────────────────────────────────────
// Injection Detection
// ──────────────────────────────────────────────────────────────

const INJECTION_PATTERNS = [
  /role\s*play/i,
  /you\s*are\s*a/i,
  /ignore\s*(previous|all|above)/i,
  /forget\s*(everything|previous)/i,
  /system\s*prompt/i,
  /#\s*system/i,
  /<\|system\|>/i,
  /\[\s*INST\s*\]/i,
  /ai\s*assistant/i,
  /jailbreak/i,
  /指令.*覆盖/i,
  /角色.*扮演/i,
];

function detectInjection(raw: string): boolean {
  return INJECTION_PATTERNS.some((p) => p.test(raw));
}

// ──────────────────────────────────────────────────────────────
// Simple Risk Score (pre-detection)
// ──────────────────────────────────────────────────────────────

function calculateRawRiskScore(raw: string): number {
  let score = 0;

  // Length-based heuristics
  if (raw.length > 500) score += 5;
  if (raw.length > 1000) score += 10;

  // Multiple newlines / formatting
  const formattingDensity = (raw.match(/\n{3,}/g) || []).length;
  score += formattingDensity * 5;

  // Special characters density
  const specialChars = (raw.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length;
  const specialRatio = specialChars / raw.length;
  if (specialRatio > 0.2) score += 10;
  if (specialRatio > 0.4) score += 15;

  // Code-like patterns
  if (/curl\s+wget\s+\|/i.test(raw)) score += 20;
  if (/\|\s*sh\b|\|\s*bash\b/i.test(raw)) score += 25;
  if (/\brsync\s+|scp\s+/i.test(raw)) score += 20;
  if (/base64.*-d|-d.*base64/i.test(raw)) score += 15;
  if (/eval\s*\(/i.test(raw)) score += 30;
  if (/exec\s*\(|spawn\s*\(/i.test(raw)) score += 20;

  // Urgency / manipulation language
  const urgencyPatterns = [
    /十万火急|紧急|马上/i,
    /求求你|拜托|跪求/i,
    /你.*过度防御|你.*太.*小心/i,
    /我是.*管理员|我是.*开发者/i,
  ];
  for (const p of urgencyPatterns) {
    if (p.test(raw)) score += 10;
  }

  return Math.min(score, 100);
}

// ──────────────────────────────────────────────────────────────
// Main Normalizer
// ──────────────────────────────────────────────────────────────

export function normalizeInput(raw: string): NormalizedInput {
  // Step 1: Basic trim
  let cleaned = raw.trim();

  // Step 2: Normalize Unicode (fullwidth → halfwidth)
  cleaned = normalizeUnicode(cleaned);

  // Step 3: Detect encoding features
  const hasEncoding = detectEncoding(cleaned);

  // Step 4: Detect injection features
  const hasInjection = detectInjection(cleaned);

  // Step 5: Calculate raw risk score
  const riskScore = calculateRawRiskScore(raw);

  return {
    raw,
    cleaned,
    hasEncoding,
    hasInjection,
    riskScore,
  };
}

export function createSanitizedPreview(raw: string, maxLength = 200): string {
  // First normalize to remove volatile chars
  const normalized = normalizeUnicode(raw);
  // Truncate
  const truncated = normalized.length > maxLength
    ? normalized.slice(0, maxLength) + '...'
    : normalized;
  return truncated;
}
