// ============================================================
// Security Shield — Plugin Entry Point
// ============================================================
//
// Registers 3 hooks via api.registerHook:
//   - reply_dispatch      → InputGuard (L1) — intercepts user messages before LLM
//   - before_prompt_build → SecurityContext (L2) — injects safety rules into prompt
//   - before_tool_call    → ToolApproval (L3) — blocks/requires approval for dangerous tools
//
// Hook signatures match oh-my-openagent plugin SDK.
// ============================================================

// @ts-expect-error openclaw/plugin-sdk/plugin-entry has no TypeScript declarations
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { normalizeInput } from './src/normalizer.js';
import { sanitizeForLog, writeAuditLog } from './src/audit-log.js';
import { calculateRiskScore } from './src/risk-scorer.js';
import {
  initStateManager,
  getUserHistory,
  updateRiskLevel,
  recordRejection,
  recordEncodingAttempt,
  incrementMessageCount,
  isLocked,
  lockUser,
  getOrCreateState,
} from './src/state-manager.js';
import { buildSecurityContext } from './src/security-context.js';
import { checkToolApproval } from './src/tool-approval.js';
import { getConfig, updateConfig, isL0User, isEnabled, isTargetAgent } from './src/api.js';
import { DEFAULT_REPLIES, DEFAULT_RISK_THRESHOLDS, DEFAULT_LOCK_CONFIG } from './src/constants.js';

// ──────────────────────────────────────────────────────────────
// Layer 1: reply_dispatch — Input Guard
// ──────────────────────────────────────────────────────────────

async function handleReplyDispatch(event: any, ctx: any) {
  if (!isEnabled()) return;
  if (!isTargetAgent(ctx.agentId)) return;

  const config = getConfig();
  const userId = event.userId ?? ctx.userId;
  const sessionId = event.sessionId ?? ctx.sessionId;
  const channel = event.channel ?? ctx.channel;
  const rawMessage = event.message ?? event.text ?? event.content ?? '';

  // L0 bypass
  if (isL0User(userId)) return;

  // Check lock
  if (isLocked(userId)) {
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'attack_detected',
      layer: 'reply_dispatch',
      userId, sessionId, channel,
      action: 'blocked',
      reply: config.replies.lock,
      rawMessagePreview: sanitizeForLog(rawMessage),
    });
    return { block: true, reply: config.replies.lock };
  }

  // Normalize & score
  const normalized = normalizeInput(rawMessage);
  const history = getUserHistory(userId);
  const result = calculateRiskScore(normalized, history, {
    userId, sessionId, channel,
    messageCount: history.messageCount,
  });

  // Fallback mode
  if (result.fallbackMode) {
    return { prependContext: result.fallbackContext ?? '' };
  }

  if (normalized.hasEncoding) {
    await recordEncodingAttempt(userId);
  }

  const thresholds = config.riskThresholds;

  // ── Lock ──
  if (result.riskScore >= thresholds.lock) {
    await lockUser(userId, config.lockConfig.durationMinutes, `Score: ${result.riskScore}`);
    await recordRejection(userId);
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'user_locked',
      layer: 'reply_dispatch',
      userId, sessionId, channel,
      score: result.riskScore,
      confidence: 'high',
      action: 'blocked',
      reply: config.replies.lock,
      rawMessagePreview: sanitizeForLog(rawMessage),
      trifectaScore: result.trifectaScore,
    });
    return { block: true, reply: config.replies.lock };
  }

  // ── Block ──
  if (result.riskScore >= thresholds.block) {
    await recordRejection(userId);
    await updateRiskLevel(userId, 'suspicious');
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'attack_detected',
      layer: 'reply_dispatch',
      dimension: result.detections[0]?.dimension,
      score: result.riskScore,
      confidence: result.detections[0]?.confidence ?? 'medium',
      userId, sessionId, channel,
      action: 'blocked',
      reply: config.replies.reject,
      rawMessagePreview: sanitizeForLog(rawMessage),
      trifectaScore: result.trifectaScore,
    });
    return { block: true, reply: config.replies.reject };
  }

  // ── Warn: inject context but allow ──
  if (result.riskScore >= thresholds.warn) {
    await updateRiskLevel(userId, 'suspicious');
    const activeDimensions = result.detections.map((d) => d.dimension);
    const ctx_result = buildSecurityContext({
      riskLevel: 'suspicious',
      activeDimensions,
    });
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'attack_detected',
      layer: 'reply_dispatch',
      dimension: result.detections[0]?.dimension,
      score: result.riskScore,
      confidence: result.detections[0]?.confidence ?? 'low',
      userId, sessionId, channel,
      action: 'warned',
      rawMessagePreview: sanitizeForLog(rawMessage),
      trifectaScore: result.trifectaScore,
    });
    if (ctx_result.prependContext) {
      return { prependContext: ctx_result.prependContext };
    }
  }

  // Normal — allow
  await incrementMessageCount(userId);
}

// ──────────────────────────────────────────────────────────────
// Layer 2: before_prompt_build — Security Context Injection
// ──────────────────────────────────────────────────────────────

async function handleBeforePromptBuild(event: any, ctx: any) {
  if (!isEnabled()) return;
  if (!isTargetAgent(ctx.agentId)) return;

  const userId = event.userId ?? ctx.userId;

  // L0 bypass
  if (isL0User(userId)) return;

  // Check lock
  if (isLocked(userId)) {
    return {
      prependContext: buildSecurityContext({ riskLevel: 'malicious' }).prependContext ?? '',
    };
  }

  // Get current risk level from state
  const state = getOrCreateState(userId);
  const isFirstMessage = event.isFirstMessage ?? ctx.isFirstMessage ?? false;

  const ctx_result = buildSecurityContext({
    riskLevel: state.riskLevel,
    isFirstMessage,
  });

  if (ctx_result.prependContext) {
    return { prependContext: ctx_result.prependContext };
  }
}

// ──────────────────────────────────────────────────────────────
// Layer 3: before_tool_call — Tool Approval
// ──────────────────────────────────────────────────────────────

async function handleBeforeToolCall(event: any, ctx: any) {
  if (!isEnabled()) return;
  if (!isTargetAgent(ctx.agentId)) return;

  const config = getConfig();
  const userId = event.userId ?? ctx.userId;
  const sessionId = event.sessionId ?? ctx.sessionId;
  const channel = event.channel ?? ctx.channel;
  const toolName = event.toolName ?? event.tool;
  const args = event.params ?? event.args ?? {};

  // L0 bypass
  if (isL0User(userId)) return;

  const approvalResult = checkToolApproval(
    { toolName, args, userId, sessionId, channel },
    config.toolApproval,
    config.l0Users,
  );

  if (!approvalResult.requiresApproval) {
    return; // Allow
  }

  if (approvalResult.blocked) {
    await writeAuditLog({
      timestamp: new Date().toISOString(),
      event: 'tool_blocked',
      layer: 'before_tool_call',
      userId, sessionId, channel,
      toolName,
      action: 'blocked',
      reason: approvalResult.blockReason,
      rawMessagePreview: sanitizeForLog(`${toolName} ${JSON.stringify(args)}`),
    });
    return { block: true };
  }

  // Requires approval
  await writeAuditLog({
    timestamp: new Date().toISOString(),
    event: 'approval_requested',
    layer: 'before_tool_call',
    userId, sessionId, channel,
    toolName,
    action: 'warned',
    reason: approvalResult.reason,
  });

  return {
    requireApproval: {
      title: "Security Shield — 高风险操作",
      description: approvalResult.reason ?? '该操作被标记为高风险',
      severity: "critical",
      timeoutMs: 120_000,
      timeoutBehavior: "deny",
    },
  };
}

// ──────────────────────────────────────────────────────────────
// Plugin Definition
// ──────────────────────────────────────────────────────────────

export default definePluginEntry({
  id: "security-shield",
  name: "Security Shield",
  description: "Multi-layer security defense for OpenClaw agents in shared group chats",

  register(api) {
    api.registerHook("reply_dispatch", handleReplyDispatch, {
      name: "security-shield-reply_dispatch",
    });

    api.registerHook("before_prompt_build", handleBeforePromptBuild, {
      name: "security-shield-before_prompt_build",
    });

    api.registerHook("before_tool_call", handleBeforeToolCall, {
      name: "security-shield-before_tool_call",
    });
  },

  async onLoad(pluginConfig: any = {}) {
    const defaults: any = {
      enabled: true,
      l0Users: ["ou_629389a1fb75c44b3509be6fd395d0b0"],
      targetAgents: [],
      riskThresholds: DEFAULT_RISK_THRESHOLDS,
      lockConfig: DEFAULT_LOCK_CONFIG,
      toolApproval: {
        criticalRequiresApproval: true,
        highRequiresApproval: true,
        mediumRequiresApproval: false,
      },
      auditLog: {
        enabled: true,
        path: "~/.openclaw/plugins/security-shield/audit",
        maxSizeMb: 10,
        maxFiles: 5,
        retentionDays: 30,
      },
      replies: DEFAULT_REPLIES,
    };

    updateConfig({ ...defaults, ...pluginConfig });
    await initStateManager();
  },
});
