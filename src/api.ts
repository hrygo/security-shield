// ============================================================
// Security Shield — Internal API
// ============================================================

import type {
  SecurityShieldConfig,
  AttackState,
  RiskLevel,
  AuditLogRecord,
  AuditLogQuery,
  HealthCheckResult,
  PluginConfig,
} from './types.js';
import {
  getState,
  getUserHistory,
  unlockUser,
  lockUser,
  getLockInfo,
  getAllLocks,
  isLocked,
  getOrCreateState,
} from './state-manager.js';
import { queryAuditLogs } from './audit-log.js';
import { scoreToRiskLevel } from './risk-scorer.js';
import { createLogger } from './audit-log.js';

const logger = createLogger();

// ──────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────

let currentConfig: SecurityShieldConfig = {
  enabled: true,
  l0Users: ['ou_629389a1fb75c44b3509be6fd395d0b0'],
  targetAgents: [],  // Empty = protect all agents; non-empty = only these agents
  riskThresholds: { warn: 30, block: 60, lock: 80 },
  lockConfig: { durationMinutes: 30, maxRejectsBeforeLock: 2, persistOnRestart: true },
  toolApproval: { criticalRequiresApproval: true, highRequiresApproval: true, mediumRequiresApproval: false },
  auditLog: { enabled: true, path: '~/.openclaw/plugins/security-shield/audit', maxSizeMb: 10, maxFiles: 5, retentionDays: 30 },
  replies: { reject: '不陪你玩了 🏃', lock: '你的请求已被拒绝，请勿继续试探。' },
};

export function getConfig(): SecurityShieldConfig {
  return currentConfig;
}

export function updateConfig(partial: Partial<PluginConfig>): void {
  currentConfig = {
    ...currentConfig,
    ...(partial.enabled !== undefined ? { enabled: partial.enabled } : {}),
    ...(partial.l0Users ? { l0Users: partial.l0Users } : {}),
    ...(partial.targetAgents ? { targetAgents: partial.targetAgents } : {}),
    ...(partial.riskThresholds ? { riskThresholds: { ...currentConfig.riskThresholds, ...partial.riskThresholds } } : {}),
    ...(partial.lockConfig ? { lockConfig: { ...currentConfig.lockConfig, ...partial.lockConfig } } : {}),
    ...(partial.toolApproval ? { toolApproval: { ...currentConfig.toolApproval, ...partial.toolApproval } } : {}),
    ...(partial.auditLog ? { auditLog: { ...currentConfig.auditLog, ...partial.auditLog } } : {}),
    ...(partial.replies ? { replies: { ...currentConfig.replies, ...partial.replies } } : {}),
  };
  logger.info('Config updated', { partial });
}

export function isL0User(userId: string): boolean {
  return currentConfig.l0Users.includes(userId);
}

export function isEnabled(): boolean {
  return currentConfig.enabled;
}

export function isTargetAgent(agentId?: string): boolean {
  // targetAgents 为空 = 保护所有 agent
  if (!currentConfig.targetAgents.length) return true;
  // agentId 为空时保守返回 true（不过滤）
  if (!agentId) return true;
  return currentConfig.targetAgents.includes(agentId);
}

// ──────────────────────────────────────────────────────────────
// User State
// ──────────────────────────────────────────────────────────────

export function getUserRiskLevel(userId: string): RiskLevel {
  const state = getState(userId);
  if (!state) return 'normal';

  // Check lock status
  if (isLocked(userId)) return 'malicious';

  return state.riskLevel;
}

export function getUserState(userId: string): AttackState | null {
  return getState(userId);
}

export function getUserHistoryData(userId: string) {
  return getUserHistory(userId);
}

// ──────────────────────────────────────────────────────────────
// Lock / Unlock
// ──────────────────────────────────────────────────────────────

export async function manualUnlockUser(userId: string): Promise<boolean> {
  const result = await unlockUser(userId);
  logger.info('Manual unlock', { userId, success: result });
  return result;
}

export async function manualLockUser(
  userId: string,
  durationMinutes?: number
): Promise<boolean> {
  const duration = durationMinutes ?? currentConfig.lockConfig.durationMinutes;
  await lockUser(userId, duration, 'Manual lock by administrator');
  return true;
}

// ──────────────────────────────────────────────────────────────
// Audit Log
// ──────────────────────────────────────────────────────────────

export async function getAuditLog(options: AuditLogQuery): Promise<{
  records: AuditLogRecord[];
  total: number;
}> {
  return queryAuditLogs(options);
}

// ──────────────────────────────────────────────────────────────
// Health Check
// ──────────────────────────────────────────────────────────────

export function healthCheck(): HealthCheckResult {
  const errors: string[] = [];

  if (!currentConfig.l0Users.length) {
    errors.push('l0Users is empty — no L0 users configured');
  }

  const { warn, block, lock } = currentConfig.riskThresholds;
  if (warn >= block || block >= lock) {
    errors.push('riskThresholds ordering invalid: warn < block < lock');
  }

  if (currentConfig.lockConfig.durationMinutes < 1) {
    errors.push('lockConfig.durationMinutes must be >= 1');
  }

  if (currentConfig.lockConfig.durationMinutes > 1440) {
    errors.push('lockConfig.durationMinutes must be <= 1440');
  }

  return {
    status: errors.length > 0 ? 'degraded' : 'healthy',
    errors,
  };
}
