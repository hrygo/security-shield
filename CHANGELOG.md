# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Switch from noEmit source-loading to compiled dist/ output
- Add build.sh script for one-command build
- Manual install instructions: copy dist/ to OpenClaw plugin directory
- Update tsconfig.json: module=Node16, outDir=dist/, declarations enabled

## [1.1.0] — 2026-04-16

### Added
- Layer 1: Input guard with 5-dimension attack detection (encoding, injection, social engineering, privilege probing, information gathering)
- Layer 2: Security context injection with risk-tiered intensity
- Layer 3: Tool approval system with pattern-based blocking and egress controls
- Layer 4: Security baseline via session-init bootstrap
- Risk scoring with Lethal Trifecta factor
- User lockout mechanism with persistence across restarts
- Audit logging with JSONL format, sanitization, and automatic rotation
- Graceful degradation on detector failures
- L0 user bypass for trusted users (creator / admin)

[Unreleased]: https://github.com/hrygo/security-shield/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/hrygo/security-shield/releases/tag/v1.1.0
