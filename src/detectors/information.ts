// ============================================================
// Security Shield — Information Gathering Detector
// ============================================================

import { BaseDetector, type PatternRule } from './base.js';
import type { NormalizedInput } from '../types.js';

// ──────────────────────────────────────────────────────────────
// Pattern Rules
// ──────────────────────────────────────────────────────────────

const INFORMATION_PATTERNS: PatternRule[] = [
  // ── Path enumeration ─────────────────────────────────────────
  { name: 'path_enumeration', pattern: /(列出|查看|看看).*(目录|文件夹|文件列表)/i, weight: 45 },
  { name: 'workspace_path', pattern: /(工作|workspace).*(目录|路径|在哪|在哪)/i, weight: 50 },
  { name: 'list_home_dir', pattern: /ls\s+(~|\/home|\/root)|home.*目录/i, weight: 55 },
  { name: 'list_system_dir', pattern: /ls\s+(\/etc|\/var|\/usr|\/tmp)/, weight: 50 },
  { name: 'recursive_list', pattern: /ls\s+-R|find\s+.*-type\s+f/, weight: 45 },

  // ── Config / environment probing ──────────────────────────────
  { name: 'env_vars', pattern: /env\s+|--env|printenv|环境变量/i, weight: 55 },
  { name: 'config_files', pattern: /cat\s+.*\.(conf|config|ini|cfg|yaml|yml|json)/i, weight: 60 },
  { name: 'sensitive_config', pattern: /\.(env|ini|conf)\b.*(key|token|pass|secret)/i, weight: 70 },
  { name: 'docker_env', pattern: /docker\s+(ps|images|inspect)|容器.*环境/i, weight: 50 },
  { name: 'kubernetes_env', pattern: /kubectl|namespace.*list|k8s/i, weight: 50 },

  // ── System info gathering ─────────────────────────────────────
  { name: 'system_info', pattern: /uname|whoami|hostname|uptime/i, weight: 40 },
  { name: 'network_info', pattern: /ifconfig|ip\s+addr|netstat|ss\s+-tuln/i, weight: 50 },
  { name: 'process_info', pattern: /ps\s+-ef|ps\s+aux|进程.*列表/i, weight: 45 },
  { name: 'disk_info', pattern: /df\s+-h|du\s+-sh|磁盘.*使用/i, weight: 40 },

  // ── Credential harvesting ────────────────────────────────────
  { name: 'password_files', pattern: /(\/etc|\/home).*passwd|shadow|group$/, weight: 75 },
  { name: 'ssh_key_hunting', pattern: /\.ssh\/|id_rsa|id_ed25519|ssh.*key/i, weight: 70 },
  { name: 'env_secret_hunting', pattern: /(PASSWORD|TOKEN|SECRET|KEY).*=|\.env\b.*[=:]/i, weight: 75 },
  { name: 'kubeconfig_hunting', pattern: /\.kube\/config|kubeconfig/i, weight: 70 },

  // ── Service enumeration ───────────────────────────────────────
  { name: 'service_list', pattern: /systemctl\s+list|service\s+.*list|进程.*(列表|服务)/i, weight: 50 },
  { name: 'port_scanning_hint', pattern: /端口.*扫描|nmap|scan.*port/i, weight: 65 },
  { name: 'network_topology', pattern: /路由.*表|拓扑|arp\s+-a|网络.*结构/i, weight: 55 },

  // ── Log / history probing ─────────────────────────────────────
  { name: 'log_files', pattern: /\.(log|logs)\b|日志.*查看|cat\s+.*\.log/i, weight: 45 },
  { name: 'shell_history', pattern: /\.bash_history|\.zsh_history|历史.*命令/i, weight: 60 },
  { name: 'audit_log', pattern: /审计.*日志|auth\.log|secure\s+log/i, weight: 60 },

  // ── User/owner enumeration ────────────────────────────────────
  { name: 'user_enum', pattern: /(用户|成员).*(列表|有哪些|查)/i, weight: 55 },
  { name: 'owner_info', pattern: /(创建者|owner|负责人|管理员).*(是|是谁)/i, weight: 50 },
  { name: 'sudo_user_enum', pattern: /sudo\s+-l|sudoer|谁.*sudo/i, weight: 65 },
];

// ──────────────────────────────────────────────────────────────
// InformationDetector
// ──────────────────────────────────────────────────────────────

export class InformationDetector extends BaseDetector {
  public readonly dimension = 'information' as const;

  protected get patterns(): PatternRule[] {
    return INFORMATION_PATTERNS;
  }

  protected calculateConfidence(
    score: number,
    matchCount: number
  ): import('../types.js').Confidence {
    if (score >= 60 && matchCount >= 2) return 'high';
    if (score >= 40 && matchCount >= 1) return 'medium';
    if (score >= 20) return 'low';
    return 'low';
  }

  protected shouldBlock(score: number, confidence: import('../types.js').Confidence): boolean {
    // Sensitive file access or credential hunting = block
    if (confidence === 'high' && score >= 65) return true;
    if (confidence === 'medium' && score >= 80) return true;
    return false;
  }
}
