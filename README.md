# Security Shield

Multi-layer security defense plugin for OpenClaw agents. Protects against social engineering, prompt injection, and privilege escalation attacks in shared bot group chats.

## Features

- **Layer 1 — Input Guard**: Real-time attack detection before LLM call. Zero token overhead, <2ms latency. Detects encoding attacks, prompt injection, social engineering, privilege probing, and information gathering.
- **Layer 2 — Security Context**: Risk-tiered security rules injected into the prompt. Adapts intensity based on user risk level.
- **Layer 3 — Tool Approval**: Intercepts dangerous tool calls (exec, file write, egress) for approval or blocking. Includes egress traffic controls.
- **Layer 4 — Security Baseline**: Session-level security baseline established via prompt injection.

## Design Principles

- **Defense in Depth** — Each layer operates independently; no single point of failure
- **Zero Trust** — No unverified input is trusted
- **Least Privilege** — Permissions granted on-demand, revocable at any time
- **Secure by Default** — Deny by default, allow exceptions explicitly

## Quick Start

### Installation

```bash
# Copy plugin to OpenClaw plugins directory
mkdir -p ~/.openclaw/plugins/security-shield/src/detectors
cp -r src/* ~/.openclaw/plugins/security-shield/src/
cp index.ts package.json openclaw.plugin.json ~/.openclaw/plugins/security-shield/

# Install dependencies
cd ~/.openclaw/plugins/security-shield
npm install

# Restart gateway
openclaw gateway restart
```

### Configuration

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "security-shield": {
        "enabled": true,
        "config": {
          "l0Users": ["ou_YOUR_L0_USER_ID"],
          "riskThresholds": {
            "warn": 30,
            "block": 60,
            "lock": 80
          },
          "lockConfig": {
            "durationMinutes": 30,
            "maxRejectsBeforeLock": 2,
            "persistOnRestart": true
          },
          "replies": {
            "reject": "不陪你玩了",
            "lock": "你的请求已被拒绝，请勿继续试探。"
          }
        }
      }
    }
  }
}
```

### Verify Installation

```bash
openclaw status
tail -f ~/.openclaw/plugins/security-shield/audit/audit-000.jsonl
```

## Risk Levels

| Level | Name | Behavior |
|-------|------|----------|
| L0 | Trusted | All checks bypassed |
| L1 | Normal | Standard detection |
| L2 | Suspicious | Warnings + security context injection |
| L3 | Malicious | Hard block + user lock |

## Detection Dimensions

- **Encoding**: Base64, hex, numeric substitution, Caesar cipher, command obfuscation
- **Injection**: Nested commands, roleplay instructions, system impersonation
- **Social Engineering**: Escalation, authority伪装, emotional manipulation, goodwill wrapper
- **Privilege Probing**: Rule inquiries, capability scanning, level discovery
- **Information Gathering**: Path enumeration, config reading, environment detection

## Architecture

```
User Input → L1 (Input Guard) → L2 (Security Context) → L3 (Tool Approval) → Agent
```

See [CLAUDE.md](CLAUDE.md) for detailed architecture and [PLUGIN-SPEC.md](PLUGIN-SPEC.md) for the full specification.

## Development

```bash
npm install       # Install dependencies
npm run build     # Type check
npm run typecheck # Alias for build
```

TypeScript with `noEmit` — loaded directly by OpenClaw runtime.

## License

MIT
