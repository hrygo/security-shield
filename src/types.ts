// ============================================================
// Security Shield — Types
// ============================================================

export type RiskLevel = 'trusted' | 'normal' | 'suspicious' | 'malicious' | 'degraded';

export type DetectionDimension = 'encoding' | 'injection' | 'social' | 'privilege' | 'information';

export type Confidence = 'low' | 'medium' | 'high';

export type AuditEventType =
  | 'attack_detected'
  | 'user_locked'
  | 'user_unlocked'
  | 'tool_blocked'
  | 'approval_requested'
  | 'l0_override'
  | 'error';

export type ToolSeverity = 'low' | 'medium' | 'high' | 'critical';

// ──────────────────────────────────────────────────────────────
// Normalized Input
// ──────────────────────────────────────────────────────────────
export interface NormalizedInput {
  raw: string;
  cleaned: string;
  hasEncoding: boolean;
  hasInjection: boolean;
  riskScore: number;
}

// ──────────────────────────────────────────────────────────────
// Detection
// ──────────────────────────────────────────────────────────────
export interface DetectionResult {
  dimension: DetectionDimension;
  score: number;
  confidence: Confidence;
  matchedPatterns: string[];
  shouldBlock: boolean;
}

export interface DetectionContext {
  input: NormalizedInput;
  userId: string;
  sessionId: string;
  channel: string;
  messageCount: number;
  toolSet?: string[];
}

// ──────────────────────────────────────────────────────────────
// Risk Scoring
// ──────────────────────────────────────────────────────────────
export interface RiskScoreResult {
  riskLevel: RiskLevel;
  riskScore: number;
  trifectaScore: number;
  dimensionScores: Partial<Record<DetectionDimension, number>>;
  detections: DetectionResult[];
  context: {
    hasExternalSourceInstructions: boolean;
    hasLongContext: boolean;
    agentCanAffectExternalWorld: boolean;
  };
  fallbackMode?: boolean;
  fallbackContext?: string;
}

// ──────────────────────────────────────────────────────────────
// State
// ──────────────────────────────────────────────────────────────
export interface AttackState {
  userId: string;
  riskLevel: RiskLevel;
  rejectedCount: number;
  correctionAttempts: number;
  encodingAttempts: number;
  escalationScore: number;
  locked: boolean;
  lockedUntil: number | null;
  lastInteraction: number;
  firstSeen: number;
  messageCount: number;
}

export interface UserHistory {
  userId: string;
  messageCount: number;
  rejectedCount: number;
  correctionAttempts: number;
  encodingAttempts: number;
  recentAttempts: number;
  lastAttempt: number;
  firstSeen: number;
}

// ──────────────────────────────────────────────────────────────
// Tool Approval
// ──────────────────────────────────────────────────────────────
export interface ToolCallContext {
  toolName: string;
  args: Record<string, unknown>;
  userId: string;
  sessionId: string;
  channel: string;
}

export interface ToolPatternMatch {
  pattern: RegExp;
  severity: ToolSeverity;
  reason: string;
  matched: boolean;
}

export interface ApprovalResult {
  approved: boolean;
  reason?: string;
  requiresApproval: boolean;
  blocked?: boolean;
  blockReason?: string;
}

// ──────────────────────────────────────────────────────────────
// Audit
// ──────────────────────────────────────────────────────────────
export interface AuditLogRecord {
  timestamp: string;
  event: AuditEventType;
  layer?: 'before_agent_reply' | 'before_prompt_build' | 'before_tool_call';
  dimension?: DetectionDimension;
  score?: number;
  confidence?: Confidence;
  userId: string;
  sessionId: string;
  channel: string;
  action?: 'blocked' | 'warned' | 'allowed' | 'approved' | 'rejected';
  reply?: string;
  rawMessagePreview?: string;
  riskLevel?: RiskLevel;
  toolName?: string;
  pattern?: string;
  reason?: string;
  duration?: number;
  errorType?: string;
  errorMessage?: string;
  trifectaScore?: number;
}

export interface AuditLogConfig {
  enabled: boolean;
  path: string;
  maxSizeMb: number;
  maxFiles: number;
  retentionDays: number;
}

// ──────────────────────────────────────────────────────────────
// Config
// ──────────────────────────────────────────────────────────────
export interface RiskThresholds {
  warn: number;
  block: number;
  lock: number;
}

export interface LockConfig {
  durationMinutes: number;
  maxRejectsBeforeLock: number;
  persistOnRestart: boolean;
}

export interface ToolApprovalConfig {
  criticalRequiresApproval: boolean;
  highRequiresApproval: boolean;
  mediumRequiresApproval: boolean;
}

export interface RepliesConfig {
  reject: string;
  lock: string;
}

export interface SecurityShieldConfig {
  enabled: boolean;
  l0Users: string[];
  targetAgents: string[];  // Agent IDs to protect (empty = all agents)
  riskThresholds: RiskThresholds;
  lockConfig: LockConfig;
  toolApproval: ToolApprovalConfig;
  auditLog: AuditLogConfig;
  replies: RepliesConfig;
}

export interface PluginConfig {
  enabled?: boolean;
  l0Users?: string[];
  targetAgents?: string[];  // Agent IDs to protect (empty = all agents)
  riskThresholds?: RiskThresholds;
  lockConfig?: LockConfig;
  toolApproval?: ToolApprovalConfig;
  auditLog?: AuditLogConfig;
  replies?: RepliesConfig;
}

// ──────────────────────────────────────────────────────────────
// Hook Return Types
// ──────────────────────────────────────────────────────────────
export interface HookModifyPrompt {
  prependSystemContext?: string;
  appendSystemContext?: string;
}

export interface HookResult {
  handled: boolean;
  reply?: string | null;
  modifyPrompt?: HookModifyPrompt;
  toolResult?: unknown;
  approve?: boolean;
}

// ──────────────────────────────────────────────────────────────
// Security Context
// ──────────────────────────────────────────────────────────────
export interface SecurityContextOptions {
  riskLevel: RiskLevel;
  userId: string;
  isFirstMessage?: boolean;
}

// ──────────────────────────────────────────────────────────────
// Lock State
// ──────────────────────────────────────────────────────────────
export interface LockState {
  userId: string;
  lockedAt: number;
  lockedUntil: number;
  reason: string;
}

// ──────────────────────────────────────────────────────────────
// API
// ──────────────────────────────────────────────────────────────
export interface AuditLogQuery {
  limit?: number;
  offset?: number;
  eventType?: AuditEventType;
  userId?: string;
  startTime?: Date;
  endTime?: Date;
}

export interface HealthCheckResult {
  status: 'healthy' | 'degraded';
  errors: string[];
}

// ──────────────────────────────────────────────────────────────
// Plugin Interface
// ──────────────────────────────────────────────────────────────

export interface HookContext {
  userId: string;
  sessionId: string;
  channel: string;
  agentId?: string;  // Which agent is being invoked
  isFirstMessage?: boolean;
}

export interface BeforeAgentReplyHook {
  (rawMessage: string, context: HookContext): Promise<HookResult | undefined>;
}

export interface BeforePromptBuildHook {
  (context: HookContext): Promise<HookResult | undefined>;
}

export interface BeforeToolCallHook {
  (toolName: string, args: Record<string, unknown>, context: HookContext): Promise<HookResult | undefined>;
}

export interface SecurityShieldPluginHooks {
  before_agent_reply?: BeforeAgentReplyHook;
  before_prompt_build?: BeforePromptBuildHook;
  before_tool_call?: BeforeToolCallHook;
}

export interface SecurityShieldPlugin {
  id: string;
  name: string;
  version: string;
  onLoad?(config?: PluginConfig): Promise<void>;
  hooks: SecurityShieldPluginHooks;
}
