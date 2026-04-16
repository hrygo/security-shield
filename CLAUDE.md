# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Security Shield** — an OpenClaw plugin providing multi-layer security defense for agent sessions in shared bot group chats. It protects against social engineering, prompt injection, and privilege escalation attacks.

Design principles: Defense in Depth, Zero Trust, Least Privilege, Secure by Default.

## Commands

```bash
npm install         # Install dependencies
npm run build       # Type check only (tsc --noEmit)
npm run typecheck   # Same as build
```

The project uses TypeScript with `"noEmit": true` — it is loaded directly by the OpenClaw plugin runtime, no compilation step needed.

## Architecture

### 4-Layer Defense Pipeline

```
User Input
  │
  ▼
L1: before_agent_reply  → Input normalization + 5-dimension attack detection + risk scoring
  │ (pass)
  ▼
L2: before_prompt_build → Security context injection into prompt (tiered by risk level)
  │
  ▼
L3: before_tool_call    → Tool call approval / blocking for dangerous operations
  │
  ▼
L4: session-init        → Security baseline (implemented via L2 prependSystemContext)
```

### Key Components

| Module | Path | Purpose |
|--------|------|---------|
| Plugin entry | `index.ts` | Registers 3 OpenClaw hooks, orchestrates L1/L2/L3 flow |
| Types | `src/types.ts` | All shared type definitions |
| Constants | `src/constants.ts` | Default config, thresholds, patterns |
| Normalizer | `src/normalizer.ts` | Input cleaning, encoding/injection feature detection |
| Detectors | `src/detectors/` | 5 independent detectors: encoding, injection, social, privilege, information |
| Risk scorer | `src/risk-scorer.ts` | Aggregates detector scores + Lethal Trifecta factor |
| State manager | `src/state-manager.ts` | Per-user attack state + persistence (JSON file) |
| Security context | `src/security-context.ts` | Builds risk-tiered system context for L2 injection |
| Tool approval | `src/tool-approval.ts` | Categorizes tools by severity, checks patterns + egress controls |
| Audit log | `src/audit-log.ts` | JSONL audit logging with sanitization + rotation |
| API | `src/api.ts` | Runtime config management, feature flags |

### Data Flow (L1)

1. `normalizeInput(rawMessage)` → `NormalizedInput`
2. `getUserHistory(userId)` → in-memory state
3. `calculateRiskScore(normalized, history)` → `RiskScoreResult`
4. Decision based on thresholds:
   - `score >= lock` (80) → block + lock user
   - `score >= block` (60) → block + mark suspicious
   - `score >= warn` (30) → allow + inject security context
   - `score < 30` → allow, no injection

### Risk Levels

`trusted (L0)` → no checks | `normal (L1)` → standard | `suspicious (L2)` → warn | `malicious (L3)` → block | `degraded` → fallback mode

L0 users (configured via `l0Users`) bypass all checks.

### State Persistence

- Attack state + lock state persisted to `~/.openclaw/plugins/security-shield/state/`
- Audit logs written to `~/.openclaw/plugins/security-shield/audit/` (JSONL, rotatable)

## Important Design Constraints

- **No token overhead for L1**: All detection is regex/string-based, zero LLM calls
- **Graceful degradation**: Detector errors fall back to minimal security baseline, never fully disabled
- **Audit log sanitization**: All log output passes through `sanitizeForLog()` to strip secrets
- **Secure by default**: `enabled: true` is the default; empty `targetAgents` means protect all agents
