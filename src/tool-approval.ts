// ============================================================
// Security Shield — Tool Approval (Layer 3)
// ============================================================

import type {
  ToolCallContext,
  ApprovalResult,
  ToolSeverity,
  ToolApprovalConfig,
} from './types.js';
import { createLogger, sanitizeForLog } from './audit-log.js';

const logger = createLogger();

// ──────────────────────────────────────────────────────────────
// Dangerous Patterns
// ──────────────────────────────────────────────────────────────

interface DangerousPattern {
  pattern: RegExp;
  severity: ToolSeverity;
  reason: string;
}

const DANGEROUS_PATTERNS: DangerousPattern[] = [
  // ── File deletion ────────────────────────────────────────────
  {
    pattern: /rm\s+-[rfv]+\s*/,
    severity: 'critical',
    reason: '不可逆删除',
  },
  {
    pattern: /\brmdir\s+/,
    severity: 'high',
    reason: '目录删除',
  },
  {
    pattern: /unlink\s+/,
    severity: 'high',
    reason: '文件解链',
  },

  // ── Permission changes ───────────────────────────────────────
  {
    pattern: /chmod\s+[47]\d{3}/,
    severity: 'critical',
    reason: '权限降级风险',
  },
  {
    pattern: /chown\s+/,
    severity: 'critical',
    reason: '所有权变更',
  },
  {
    pattern: /umask\s+/,
    severity: 'medium',
    reason: '权限掩码变更',
  },

  // ── Sensitive file access ────────────────────────────────────
  {
    pattern: /cat\s+.*\.(env|key|token|pass|secret|password)/i,
    severity: 'critical',
    reason: '敏感文件读取',
  },
  {
    pattern: /grep\s+.*(password|token|secret|key)/i,
    severity: 'high',
    reason: '敏感信息搜索',
  },
  {
    pattern: /(\/etc|\/home|\/root).*shadow|passwd|group$/,
    severity: 'critical',
    reason: '系统账户文件访问',
  },

  // ── Network operations ───────────────────────────────────────
  {
    pattern: /curl.*(-d|-X|--data|-F)/,
    severity: 'high',
    reason: '外部数据发送',
  },
  {
    pattern: /wget\s+http/,
    severity: 'high',
    reason: '网络下载',
  },
  {
    pattern: /ncat\s+|nc\s+(-e|--exec)/,
    severity: 'critical',
    reason: '反向Shell',
  },

  // ── Process / execution ──────────────────────────────────────
  {
    pattern: /eval\s*\(/,
    severity: 'critical',
    reason: '动态代码执行',
  },
  {
    pattern: /exec\s*\(\s*\$/,
    severity: 'critical',
    reason: '变量命令执行',
  },
  {
    pattern: /spawn\s*\(/,
    severity: 'high',
    reason: '进程生成',
  },

  // ── System info ───────────────────────────────────────────────
  {
    pattern: /env\s+.*(PASSWORD|TOKEN|KEY|SECRET)/i,
    severity: 'critical',
    reason: '凭据泄露',
  },
  {
    pattern: /printenv\s+.*(PASSWORD|TOKEN|KEY|SECRET)/i,
    severity: 'critical',
    reason: '凭据读取',
  },

  // ── Fire-and-forget background ───────────────────────────────
  {
    pattern: /&\s*$/,
    severity: 'medium',
    reason: '后台执行',
  },
];

// ──────────────────────────────────────────────────────────────
// Egress Patterns (Gap 4 fix)
// ──────────────────────────────────────────────────────────────

const EGRESS_PATTERNS: DangerousPattern[] = [
  {
    pattern: /curl.*--data|fetch.*body|wget.*-O-|scp\s+.*remote|rsync.*remote/i,
    severity: 'critical',
    reason: '数据发送至外部/文件外发',
  },
  {
    pattern: /curl\s+(https?:\/\/)/i,
    severity: 'high',
    reason: 'HTTP 请求第三方',
  },
  {
    pattern: /upload|send.*file|post.*file/i,
    severity: 'high',
    reason: '文件上传操作',
  },
  {
    pattern: /tee\s+.*\|/,
    severity: 'high',
    reason: '数据分流管道',
  },
];

// ──────────────────────────────────────────────────────────────
// Tool Severity Map
// ──────────────────────────────────────────────────────────────

function getToolSeverity(toolName: string): ToolSeverity {
  const critical = [
    'exec',
    'shell',
    'subprocess',
    'spawn',
    'eval',
    'write',
    'delete',
    'remove',
    'unlink',
    'rmdir',
    'chmod',
    'chown',
    'system',
    'bash',
    'sh',
  ];
  const high = [
    'edit',
    'move',
    'rename',
    'copy',
    'mkdir',
    'touch',
    'ln',
    'curl',
    'wget',
    'fetch',
    'scp',
    'rsync',
    'ncat',
    'nc',
  ];
  const medium = ['read'];

  const lower = toolName.toLowerCase();
  if (critical.some((t) => lower.includes(t))) return 'critical';
  if (high.some((t) => lower.includes(t))) return 'high';
  if (medium.some((t) => lower.includes(t))) return 'medium';
  return 'low';
}

// ──────────────────────────────────────────────────────────────
// Pattern Matching
// ──────────────────────────────────────────────────────────────

function checkPatterns(
  text: string,
  patterns: DangerousPattern[]
): DangerousPattern | null {
  for (const p of patterns) {
    if (p.pattern.test(text)) {
      return p;
    }
  }
  return null;
}

function argsToString(args: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(args)) {
    parts.push(`${k}=${String(v)}`);
  }
  return parts.join(' ');
}

// ──────────────────────────────────────────────────────────────
// Main Approval Check
// ──────────────────────────────────────────────────────────────

export function checkToolApproval(
  context: ToolCallContext,
  config: ToolApprovalConfig,
  l0Users: string[]
): ApprovalResult {
  const { toolName, args, userId } = context;

  // L0 user: bypass all
  if (l0Users.includes(userId)) {
    return { approved: true, requiresApproval: false };
  }

  const severity = getToolSeverity(toolName);
  const argsStr = argsToString(args);
  const fullText = `${toolName} ${argsStr}`;

  // Check dangerous patterns
  const dangerMatch = checkPatterns(fullText, DANGEROUS_PATTERNS);
  if (dangerMatch) {
    logger.warn('Dangerous pattern detected', {
      tool: toolName,
      pattern: dangerMatch.pattern.source,
      severity: dangerMatch.severity,
      reason: dangerMatch.reason,
    });

    // Auto-block critical patterns
    if (dangerMatch.severity === 'critical') {
      return {
        approved: false,
        requiresApproval: true,
        blocked: true,
        blockReason: dangerMatch.reason,
      };
    }
  }

  // Check egress patterns (Gap 4)
  const egressMatch = checkPatterns(fullText, EGRESS_PATTERNS);
  if (egressMatch) {
    logger.warn('Egress pattern detected', {
      tool: toolName,
      pattern: egressMatch.pattern.source,
      severity: egressMatch.severity,
      reason: egressMatch.reason,
    });

    if (egressMatch.severity === 'critical') {
      return {
        approved: false,
        requiresApproval: true,
        blocked: true,
        blockReason: egressMatch.reason,
      };
    }
  }

  // Determine if approval is required
  let requiresApproval = false;
  switch (severity) {
    case 'critical':
      requiresApproval = config.criticalRequiresApproval;
      break;
    case 'high':
      requiresApproval = config.highRequiresApproval;
      break;
    case 'medium':
      requiresApproval = config.mediumRequiresApproval;
      break;
    default:
      requiresApproval = false;
  }

  if (!requiresApproval) {
    return { approved: true, requiresApproval: false };
  }

  return {
    approved: false,
    requiresApproval: true,
    blocked: false,
    reason: `[Security Shield] ${severity.toUpperCase()} tool "${toolName}" requires approval: ${
      dangerMatch?.reason ?? egressMatch?.reason ?? 'No specific reason'
    }`,
  };
}

// ──────────────────────────────────────────────────────────────
// Severity Label
// ──────────────────────────────────────────────────────────────

export function severityLabel(severity: ToolSeverity): string {
  const map: Record<ToolSeverity, string> = {
    low: '🟢 LOW',
    medium: '🟡 MEDIUM',
    high: '🟠 HIGH',
    critical: '🔴 CRITICAL',
  };
  return map[severity];
}
