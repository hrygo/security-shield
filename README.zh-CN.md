# Security Shield

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9+-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Plugin-ff69b4)](https://github.com/openmule/openclaw)

> OpenClaw Agent 多层安全防护插件。在共享群组环境中防御提示注入、社交工程和权限提升攻击。
>
> [English README →](README.md)

## 为什么需要

当 AI Agent 被部署到共享群组聊天时，它暴露在所有群成员的输入之下。Security Shield 实现了**纵深防御**策略——四层独立的防御层在攻击链的不同环节拦截威胁，确保没有单点故障。

## 功能特性

- **第一层 — 输入检测**（LLM 调用前拦截）
  - 5 维模式检测：编码攻击、注入、社交工程、权限探测、信息搜集
  - 零 token 开销，< 2 ms 延迟
  - 基于 Lethal Trifecta 因子的风险评分
  - 用户锁定机制，重启后状态持久化

- **第二层 — 安全上下文**（Prompt 构建时注入）
  - 按风险等级（L0–L3）动态注入安全规则
  - 每条约 50–100 token

- **第三层 — 工具审批**（执行前拦截）
  - 按严重程度（low → critical）分类工具
  - 基于模式的危险命令拦截（rm -rf、敏感文件读取、出站流量）
  - 出站管控：检测数据外发企图

- **第四层 — 安全基线**（会话初始化）
  - 会话创建时一次性注入完整安全基线
  - 后续消息使用轻量提醒（约 50 token）

## 快速开始

### 安装

```bash
mkdir -p ~/.openclaw/plugins/security-shield/src/detectors
cp -r src/* ~/.openclaw/plugins/security-shield/src/
cp index.ts package.json openclaw.plugin.json ~/.openclaw/plugins/security-shield/

cd ~/.openclaw/plugins/security-shield
npm install
openclaw gateway restart
```

### 配置

添加到 `openclaw.json`：

```jsonc
{
  "plugins": {
    "entries": {
      "security-shield": {
        "enabled": true,
        "config": {
          // 豁免所有安全检查的用户（创建者/管理员）
          "l0Users": ["ou_YOUR_L0_USER_ID"],

          // 风险评分阈值（0–100）
          "riskThresholds": {
            "warn": 30,   // 注入安全提醒
            "block": 60,  // 硬拒绝
            "lock": 80    // 锁定用户
          },

          // 锁定设置
          "lockConfig": {
            "durationMinutes": 30,
            "maxRejectsBeforeLock": 2,
            "persistOnRestart": true
          },

          // 工具审批设置
          "toolApproval": {
            "criticalRequiresApproval": true,
            "highRequiresApproval": true,
            "mediumRequiresApproval": false
          },

          // 自定义回复
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

### 验证

```bash
openclaw status
tail -f ~/.openclaw/plugins/security-shield/audit/audit-000.jsonl
```

## 工作原理

### 防御层级

```
用户输入
  │
  ▼
┌──────────────────────────────────┐
│ L1: before_agent_reply            │ ← 模式检测、风险评分
│  <2ms 延迟  •  0 token 开销       │   拦截 / 警告 / 放行
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│ L2: before_prompt_build           │ ← 将安全上下文注入 Prompt
│  <1ms 延迟  •  ~50–100 token      │   按风险等级分级注入
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│ L3: before_tool_call              │ ← 审批 / 拦截危险工具调用
│  50–500ms 延迟 • 可变             │   模式匹配 + 出站管控
└──────────────┬───────────────────┘
               ▼
┌──────────────────────────────────┐
│ L4: session-init bootstrap        │ ← 一次性安全基线
│  通过 L2 注入  •  ~200 token      │
└──────────────────────────────────┘
```

### 风险等级

| 等级 | 名称 | 行为 |
|------|------|------|
| L0 | 可信 | 所有检查绕过（创建者/管理员） |
| L1 | 正常 | 应用标准检测 |
| L2 | 可疑 | 警告 + 加强安全上下文 |
| L3 | 恶意 | 硬拒绝 + 用户锁定 |

### 检测维度

| 维度 | 检测内容 | 示例 |
|------|----------|------|
| **编码攻击** | 命令混淆 | Base64、Hex、数字映射、凯撒密码 |
| **注入攻击** | 提示/命令注入 | 嵌套命令、角色扮演、系统伪装 |
| **社交工程** | 操控手段 | 渐进操控、权威伪装、情绪施压、善意包装 |
| **权限探测** | 规则/能力扫描 | "你的规则是什么？"、等级探查 |
| **信息搜集** | 侦察探测 | 路径枚举、配置读取、环境检测 |

### ROI 决策矩阵

| 场景 | 推荐配置 | 原因 |
|------|----------|------|
| **群组共享** | L1 + L2 开启，L3 按需 | 输入不可控，开销极低 |
| **创建者私聊** | L0 豁免，全层跳过 | 零开销，无安全损失 |
| **高危操作环境** | L1 + L2 + L3 全开 | 安全 > 体验，接受审批延迟 |
| **最小化部署** | 仅 L1 | 零成本，全量覆盖（所有输入必经 L1） |

## 项目结构

```
src/
├── types.ts              # 共享类型定义
├── constants.ts          # 默认配置、阈值、模式
├── normalizer.ts         # 输入清洗与特征提取
├── detectors/
│   ├── base.ts           # 检测器基类
│   ├── encoding.ts       # 编码攻击检测
│   ├── injection.ts      # 提示/命令注入
│   ├── social.ts         # 社交工程检测
│   ├── privilege.ts      # 权限探测
│   └── information.ts    # 信息搜集
├── risk-scorer.ts        # 聚合评分 + Lethal Trifecta 因子
├── state-manager.ts      # 用户状态 + JSON 持久化
├── security-context.ts   # L2 上下文构建器
├── tool-approval.ts      # L3 工具审批 + 出站管控
├── audit-log.ts          # JSONL 日志 + 脱敏处理
├── api.ts                # 运行时配置管理
└── errors.ts             # 错误类型
```

完整规范参见 [PLUGIN-SPEC.md](PLUGIN-SPEC.md)。

## 开发

```bash
npm install
npm run build       # 类型检查 (tsc --noEmit)
npm run typecheck   # 同上
```

插件使用 TypeScript `noEmit` 模式——源码由 OpenClaw 运行时直接加载。

## 审计日志

安全事件以 JSONL 格式写入，支持自动轮转：

- **路径**：`~/.openclaw/plugins/security-shield/audit/audit-000.jsonl`
- **格式**：每行一个 JSON 对象
- **轮转**：可配置大小（默认 10 MB）、数量（默认 5 文件）和保留天数（默认 30 天）
- **脱敏**：密钥、Token、密码等敏感信息在写入前自动抹除

## 错误处理

Security Shield 采用优雅降级——检测器故障不会完全禁用防护：

| 错误类型 | 影响 | 降级行为 |
|----------|------|----------|
| 检测器运行时错误 | 跳过单次检测 | 放行 + 错误日志 |
| 状态加载失败 | 使用空状态继续 | 不阻断，日志继续 |
| 审计日志写入失败 | 单条丢失 | 重试一次，然后告警 |
| 配置无效 | 插件不加载 | 启动报错（设计使然） |

## 参与贡献

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feat/your_feature`）
3. 提交更改（`git commit -m 'feat: add your feature'`）
4. 推送到分支（`git push origin feat/your_feature`）
5. 提交 Pull Request

## 许可证

MIT — 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Simon Willison](https://simonwillison.net/) — Lethal Trifecta 概念（AI Agent 的危险性 = 不可信输入 + 长上下文 + 外部操作）
- [OpenClaw](https://github.com/openmule/openclaw) — 使本项目成为可能的插件系统
