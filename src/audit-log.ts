// ============================================================
// Security Shield — Audit Log
// ============================================================

import { promises as fs } from 'fs';
import path from 'path';
import type {
  AuditLogRecord,
  AuditLogConfig,
  AuditEventType,
} from './types.js';
import { SecurityShieldError, SecurityShieldException } from './errors.js';

// ──────────────────────────────────────────────────────────────
// Paths
// ──────────────────────────────────────────────────────────────

const DEFAULT_AUDIT_PATH = '~/.openclaw/plugins/security-shield/audit';
const DEFAULT_LOG_FILE = 'audit-000.jsonl';

// ──────────────────────────────────────────────────────────────
// Logger (stderr-based for now; file writing async)
// ──────────────────────────────────────────────────────────────

export interface Logger {
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  debug?(msg: string, meta?: Record<string, unknown>): void;
}

let _logger: Logger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

export function createLogger(): Logger {
  return _logger;
}

export function setLogger(logger: Logger): void {
  _logger = logger;
}

// ──────────────────────────────────────────────────────────────
// Audit Log Config
// ──────────────────────────────────────────────────────────────

let auditConfig: AuditLogConfig = {
  enabled: true,
  path: DEFAULT_AUDIT_PATH,
  maxSizeMb: 10,
  maxFiles: 5,
  retentionDays: 30,
};

export function configureAuditLog(config: AuditLogConfig): void {
  auditConfig = { ...auditConfig, ...config };
}

// ──────────────────────────────────────────────────────────────
// Sanitize for Log (Gap 6 fix)
// ──────────────────────────────────────────────────────────────

export function sanitizeForLog(preview: string, maxLength = 200): string {
  return preview
    .replace(/sk-[a-zA-Z0-9]{20,}/g, 'sk-***')
    .replace(/(password|token|key|secret)["\s:=]+\S+/gi, '$1=***')
    .replace(/Bearer\s+[a-zA-Z0-9_-]+/g, 'Bearer ***')
    .replace(/\b[0-9a-f]{32,}\b/gi, '***')
    .slice(0, maxLength);
}

// ──────────────────────────────────────────────────────────────
// File Path Resolution
// ──────────────────────────────────────────────────────────────

function resolvePath(p: string): string {
  return p.replace('~', process.env.HOME ?? '');
}

function getLogFilePath(): string {
  return path.join(resolvePath(auditConfig.path), DEFAULT_LOG_FILE);
}

// ──────────────────────────────────────────────────────────────
// Directory Init
// ──────────────────────────────────────────────────────────────

let dirInitialized = false;

async function ensureAuditDir(): Promise<void> {
  if (dirInitialized) return;
  try {
    await fs.mkdir(resolvePath(auditConfig.path), { recursive: true });
    dirInitialized = true;
  } catch {
    // Already exists
    dirInitialized = true;
  }
}

// ──────────────────────────────────────────────────────────────
// Rotation
// ──────────────────────────────────────────────────────────────

async function checkRotation(): Promise<void> {
  const filePath = getLogFilePath();
  try {
    const stat = await fs.stat(filePath);
    const maxBytes = auditConfig.maxSizeMb * 1024 * 1024;
    if (stat.size >= maxBytes) {
      await rotateLogFile();
    }
  } catch {
    // File doesn't exist — skip rotation
  }
}

async function rotateLogFile(): Promise<void> {
  const basePath = getLogFilePath().replace(/\.jsonl$/, '');
  const auditDir = resolvePath(auditConfig.path);

  // Find highest numbered file
  let highestNum = 0;
  try {
    const files = await fs.readdir(auditDir);
    for (const f of files) {
      const m = f.match(/audit-(\d+)\.jsonl$/);
      if (m) {
        highestNum = Math.max(highestNum, parseInt(m[1], 10));
      }
    }
  } catch {
    // Dir doesn't exist
  }

  // Rotate existing files
  for (let i = highestNum; i >= 0; i--) {
    const oldName = i === 0 ? `${basePath}.jsonl` : `${basePath}-${String(i).padStart(3, '0')}.jsonl`;
    const newName = `${basePath}-${String(i + 1).padStart(3, '0')}.jsonl`;
    try {
      await fs.rename(oldName, newName);
    } catch {
      // File doesn't exist
    }
  }

  // Remove oldest if exceeds maxFiles
  const oldestName = `${basePath}-${String(auditConfig.maxFiles).padStart(3, '0')}.jsonl`;
  try {
    await fs.unlink(oldestName);
  } catch {
    // Doesn't exist
  }
}

// ──────────────────────────────────────────────────────────────
// Write Record
// ──────────────────────────────────────────────────────────────

export async function writeAuditLog(record: AuditLogRecord): Promise<void> {
  if (!auditConfig.enabled) return;

  try {
    await ensureAuditDir();
    await checkRotation();

    const filePath = getLogFilePath();
    const line = JSON.stringify(record) + '\n';
    await fs.appendFile(filePath, line, 'utf-8');
  } catch (err) {
    // Audit log failure: degrade to stderr
    _logger.error('Audit log write failed, falling back to stderr', {
      error: err instanceof Error ? err.message : String(err),
      record: JSON.stringify(record),
    });
  }
}

// ──────────────────────────────────────────────────────────────
// Query Logs
// ──────────────────────────────────────────────────────────────

export async function queryAuditLogs(options: {
  limit?: number;
  offset?: number;
  eventType?: AuditEventType;
  userId?: string;
  startTime?: Date;
  endTime?: Date;
}): Promise<{ records: AuditLogRecord[]; total: number }> {
  const { limit = 100, offset = 0, eventType, userId, startTime, endTime } = options;

  const auditDir = resolvePath(auditConfig.path);
  const records: AuditLogRecord[] = [];

  try {
    const files = await fs.readdir(auditDir);
    const logFiles = files
      .filter((f) => f.startsWith('audit-') && f.endsWith('.jsonl'))
      .sort();

    for (const file of logFiles) {
      const content = await fs.readFile(path.join(auditDir, file), 'utf-8');
      const lines = content.split('\n').filter(Boolean);

      for (const line of lines) {
        try {
          const record = JSON.parse(line) as AuditLogRecord;

          if (eventType && record.event !== eventType) continue;
          if (userId && record.userId !== userId) continue;
          if (startTime) {
            const recordTime = new Date(record.timestamp);
            if (recordTime < startTime) continue;
          }
          if (endTime) {
            const recordTime = new Date(record.timestamp);
            if (recordTime > endTime) continue;
          }

          records.push(record);
        } catch {
          // Skip malformed lines
        }
      }
    }
  } catch {
    // Directory doesn't exist
  }

  // Sort by timestamp descending
  records.sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  const total = records.length;
  const paginated = records.slice(offset, offset + limit);

  return { records: paginated, total };
}

// ──────────────────────────────────────────────────────────────
// Retention Cleanup
// ──────────────────────────────────────────────────────────────

export async function cleanupOldLogs(retentionDays: number): Promise<void> {
  const auditDir = resolvePath(auditConfig.path);
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

  try {
    const files = await fs.readdir(auditDir);
    for (const file of files) {
      if (!file.startsWith('audit-') || !file.endsWith('.jsonl')) continue;
      const filePath = path.join(auditDir, file);
      const stat = await fs.stat(filePath);
      if (stat.mtimeMs < cutoff) {
        await fs.unlink(filePath);
        _logger.info('Deleted old audit log', { file, mtime: stat.mtimeMs });
      }
    }
  } catch {
    // Ignore
  }
}
