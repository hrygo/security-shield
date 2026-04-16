// ============================================================
// Security Shield — Plugin Entry Point
// ============================================================
//
// Registers 3 hooks:
//   - before_agent_reply  → InputGuard (L1)
//   - before_prompt_build → SecurityContext (L2)
//   - before_tool_call    → ToolApproval (L3)
//
// ============================================================

import type {
  SecurityShieldPlugin,
  HookResult,
  PluginConfig,
  RiskScoreResult,
} from './src/types.js';
import { normalizeInput } from './src/normalizer.js';
import { sanitizeForLog } from './src/audit-log.js';
import { calculateRiskScore } from './src/risk-scorer.js';
import {
  initStateManager,
  getUserHistory,
  updateRiskLevel,
  recordRejection,
  recordCorrectionAttempt,
  recordEncodingAttempt,
  incrementMessageCount,
  isLocked,
  lockUser,
  getOrCreateState,
} from './src/state-manager.js';
import { buildSecurityContext, isL0User } from './src/security-context.js';
import { checkToolApproval } from './src/tool-approval.js';
import { writeAuditLog } from './src/audit-log.js';
import {
  getConfig,
  updateConfig,
  isL0User as apiIsL0User,
  isEnabled,
  isTargetAgent,
} from './src/api.js';
import {
  DEFAULT_REPLIES,
  DEFAULT_RISK_THRESHOLDS,
  DEFAULT_LOCK_CONFIG,
} from './src/constants.js';

// ──────────────────────────────────────────────────────────────
// Hook Handlers
// ──────────────────────────────────────────────────────────────

/**
 * Layer 1: before_agent_reply — Input Guard
 * Runs before LLM is called. Catches attacks before any token is spent.
 */
async function handleBeforeAgentReply(
  rawMessage: string,
  context: {
    userId: string;
    sessionId: string;
    channel: string;
    agentId?: string;
  }
): Promise<HookResult | undefined> {
  if (!isEnabled()) return undefined;
  if (!isTargetAgent(context.agentId)) return undefined;  // Not a target agent — skip

  const config = getConfig();
  const { userId, sessionId, channel } = context;

  // L0 bypass
  if (apiIsL0User(userId)) {
    return undefined;
  }

  // Check lock
  if (isLocked(userId)) {
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'attack_detected',
      layer: 'before_agent_reply',
      userId,
      sessionId,
      channel,
      action: 'blocked',
      reply: config.replies.lock,
      rawMessagePreview: sanitizeForLog(rawMessage),
    });
    return { handled: true, reply: config.replies.lock };
  }

  // Normalize input
  const normalized = normalizeInput(rawMessage);

  // Get user history
  const history = getUserHistory(userId);

  // Score risk
  const result = calculateRiskScore(normalized, history, {
    userId,
    sessionId,
    channel,
    messageCount: history.messageCount,
  });

  // Handle degraded mode
  if (result.fallbackMode) {
    return {
      handled: false,
      modifyPrompt: {
        prependSystemContext: result.fallbackContext ?? '',
      },
    };
  }

  // Record encoding attempts
  if (normalized.hasEncoding) {
    await recordEncodingAttempt(userId);
  }

  const thresholds = config.riskThresholds;

  // ── Decision ─────────────────────────────────────────────────
  if (result.riskScore >= thresholds.lock) {
    // Lock user
    await lockUser(userId, config.lockConfig.durationMinutes, `Score: ${result.riskScore}`);
    await recordRejection(userId);

    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'user_locked',
      layer: 'before_agent_reply',
      userId,
      sessionId,
      channel,
      score: result.riskScore,
      confidence: 'high',
      action: 'blocked',
      reply: config.replies.lock,
      rawMessagePreview: sanitizeForLog(rawMessage),
      trifectaScore: result.trifectaScore,
    });

    return { handled: true, reply: config.replies.lock };
  }

  if (result.riskScore >= thresholds.block) {
    // Block
    await recordRejection(userId);
    await updateRiskLevel(userId, 'suspicious');

    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'attack_detected',
      layer: 'before_agent_reply',
      dimension: result.detections[0]?.dimension,
      score: result.riskScore,
      confidence: result.detections[0]?.confidence ?? 'medium',
      userId,
      sessionId,
      channel,
      action: 'blocked',
      reply: config.replies.reject,
      rawMessagePreview: sanitizeForLog(rawMessage),
      trifectaScore: result.trifectaScore,
    });

    return { handled: true, reply: config.replies.reject };
  }

  if (result.riskScore >= thresholds.warn) {
    // Warn — inject context but don't block
    await updateRiskLevel(userId, 'suspicious');

    const activeDimensions = result.detections.map((d) => d.dimension);
    const modifyPrompt = buildSecurityContext({
      riskLevel: 'suspicious',
      activeDimensions,
    });

    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'attack_detected',
      layer: 'before_agent_reply',
      dimension: result.detections[0]?.dimension,
      score: result.riskScore,
      confidence: result.detections[0]?.confidence ?? 'low',
      userId,
      sessionId,
      channel,
      action: 'warned',
      rawMessagePreview: sanitizeForLog(rawMessage),
      trifectaScore: result.trifectaScore,
    });

    return { handled: false, modifyPrompt };
  }

  // Normal — allow, increment message count
  await incrementMessageCount(userId);

  return undefined;
}

/**
 * Layer 2: before_prompt_build — Security Context Injection
 * Injects security rules into the prompt.
 */
async function handleBeforePromptBuild(
  context: {
    userId: string;
    sessionId: string;
    channel: string;
    agentId?: string;
    isFirstMessage?: boolean;
  }
): Promise<HookResult | undefined> {
  if (!isEnabled()) return undefined;
  if (!isTargetAgent(context.agentId)) return undefined;  // Not a target agent — skip

  const { userId } = context;

  // L0 bypass
  if (apiIsL0User(userId)) {
    return undefined;
  }

  // Check if locked
  if (isLocked(userId)) {
    return {
      handled: false,
      modifyPrompt: {
        prependSystemContext: buildSecurityContext({ riskLevel: 'malicious' }).prependSystemContext ?? '',
      },
    };
  }

  // Get current risk level from state
  const state = getOrCreateState(userId);
  const { riskLevel } = state;

  const modifyPrompt = buildSecurityContext({
    riskLevel,
    isFirstMessage: context.isFirstMessage,
  });

  if (modifyPrompt.prependSystemContext || modifyPrompt.appendSystemContext) {
    return { handled: false, modifyPrompt };
  }

  return undefined;
}

/**
 * Layer 3: before_tool_call — Tool Approval
 * Intercepts dangerous tool calls for approval/blocking.
 */
async function handleBeforeToolCall(
  toolName: string,
  args: Record<string, unknown>,
  context: {
    userId: string;
    sessionId: string;
    channel: string;
    agentId?: string;
  }
): Promise<HookResult | undefined> {
  if (!isEnabled()) return undefined;
  if (!isTargetAgent(context.agentId)) return undefined;  // Not a target agent — skip

  const config = getConfig();
  const { userId, sessionId, channel } = context;

  // L0 bypass
  if (apiIsL0User(userId)) {
    return undefined;
  }

  const approvalResult = checkToolApproval(
    { toolName, args, userId, sessionId, channel },
    config.toolApproval,
    config.l0Users
  );

  if (!approvalResult.requiresApproval) {
    return undefined;
  }

  if (approvalResult.blocked) {
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'tool_blocked',
      layer: 'before_tool_call',
      userId,
      sessionId,
      channel,
      toolName,
      action: 'blocked',
      reason: approvalResult.blockReason,
      rawMessagePreview: sanitizeForLog(`${toolName} ${JSON.stringify(args)}`),
    });

    return {
      handled: true,
      reply: `[Security Shield] 操作被阻止: ${approvalResult.blockReason ?? '危险操作'}`,
    };
  }

  // Requires approval but not blocked — return approval request
  await writeAuditLog({
    timestamp: new Date().toISOString(),
    event: 'approval_requested',
    layer: 'before_tool_call',
    userId,
    sessionId,
    channel,
    toolName,
    action: 'warned',
    reason: approvalResult.reason,
  });

  // Return null to defer to approval flow
  return undefined;
}

// ──────────────────────────────────────────────────────────────
// Plugin Definition
// ──────────────────────────────────────────────────────────────

const securityShieldPlugin: SecurityShieldPlugin = {
  id: 'security-shield',
  name: 'Security Shield',
  version: '1.1.0',

  async onLoad(pluginConfig: PluginConfig = {}): Promise<void> {
    // Merge config
    const defaults: PluginConfig = {
      enabled: true,
      l0Users: ['ou_629389a1fb75c44b3509be6fd395d0b0'],
      targetAgents: [],  // Empty = protect all agents
      riskThresholds: DEFAULT_RISK_THRESHOLDS,
      lockConfig: DEFAULT_LOCK_CONFIG,
      toolApproval: { criticalRequiresApproval: true, highRequiresApproval: true, mediumRequiresApproval: false },
      auditLog: { enabled: true, path: '~/.openclaw/plugins/security-shield/audit', maxSizeMb: 10, maxFiles: 5, retentionDays: 30 },
      replies: DEFAULT_REPLIES,
    };

    const merged: PluginConfig = {
      ...defaults,
      ...pluginConfig,
    };

    updateConfig(merged);

    // Initialize state manager
    await initStateManager();
  },

  hooks: {
    async before_agent_reply(rawMessage, context) {
      return handleBeforeAgentReply(rawMessage, context as { userId: string; sessionId: string; channel: string; agentId?: string });
    },

    async before_prompt_build(context) {
      return handleBeforePromptBuild(context as { userId: string; sessionId: string; channel: string; agentId?: string; isFirstMessage?: boolean });
    },

    async before_tool_call(toolName, args, context) {
      return handleBeforeToolCall(
        toolName,
        args as Record<string, unknown>,
        context as { userId: string; sessionId: string; channel: string; agentId?: string }
      );
    },
  },
};

// ──────────────────────────────────────────────────────────────
// Export
// ──────────────────────────────────────────────────────────────

export default securityShieldPlugin;

// Also export for direct use
export {
  getConfig,
  updateConfig,
  isL0User,
  isEnabled,
} from './src/api.js';

export type { SecurityShieldPlugin } from './src/types.js';
