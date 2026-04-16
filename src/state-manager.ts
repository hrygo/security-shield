// ============================================================
// Security Shield — State Manager
// ============================================================

import { promises as fs } from 'fs';
import path from 'path';
import type { AttackState, RiskLevel, LockState } from './types.js';
import { STATE_DIR, LOCKS_FILE, STATE_FILE } from './constants.js';
import { createLogger } from './audit-log.js';

const logger = createLogger();

// ──────────────────────────────────────────────────────────────
// State Map (in-memory)
// ──────────────────────────────────────────────────────────────

const stateMap = new Map<string, AttackState>();
const locksMap = new Map<string, LockState>();

// ──────────────────────────────────────────────────────────────
// Paths
// ──────────────────────────────────────────────────────────────

function getStatePath(): string {
  return path.join(STATE_DIR.replace('~', process.env.HOME ?? ''), STATE_FILE);
}

function getLocksPath(): string {
  return path.join(STATE_DIR.replace('~', process.env.HOME ?? ''), LOCKS_FILE);
}

// ──────────────────────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────────────────────

export async function initStateManager(): Promise<void> {
  try {
    await fs.mkdir(STATE_DIR.replace('~', process.env.HOME ?? ''), { recursive: true });
    await loadState();
    await loadLocks();
    logger.info('State manager initialized');
  } catch (err) {
    logger.error('State manager init failed', {
      error: err instanceof Error ? err.message : String(err),
    });
    // Continue with empty state
  }
}

// ──────────────────────────────────────────────────────────────
// State Persistence
// ──────────────────────────────────────────────────────────────

async function loadState(): Promise<void> {
  const filePath = getStatePath();
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(data) as Record<string, AttackState>;
    for (const [userId, state] of Object.entries(parsed)) {
      stateMap.set(userId, state);
    }
    logger.info(`Loaded ${stateMap.size} user states`);
  } catch {
    // File doesn't exist or is invalid — start with empty
    stateMap.clear();
  }
}

async function loadLocks(): Promise<void> {
  const filePath = getLocksPath();
  try {
    const data = await fs.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(data) as Record<string, LockState>;
    const now = Date.now();
    for (const [userId, lock] of Object.entries(parsed)) {
      // Skip expired locks
      if (lock.lockedUntil > now) {
        locksMap.set(userId, lock);
      }
    }
    logger.info(`Loaded ${locksMap.size} active locks`);
  } catch {
    locksMap.clear();
  }
}

async function saveState(): Promise<void> {
  const filePath = getStatePath();
  try {
    const obj = Object.fromEntries(stateMap);
    await fs.writeFile(filePath, JSON.stringify(obj, null, 2), 'utf-8');
  } catch (err) {
    logger.error('Failed to save state', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

async function saveLocks(): Promise<void> {
  const filePath = getLocksPath();
  try {
    const obj = Object.fromEntries(locksMap);
    await fs.writeFile(filePath, JSON.stringify(obj, null, 2), 'utf-8');
  } catch (err) {
    logger.error('Failed to save locks', {
      error: err instanceof Error ? err.message : String(err),
    });
  }
}

// ──────────────────────────────────────────────────────────────
// State Operations
// ──────────────────────────────────────────────────────────────

export function getOrCreateState(userId: string): AttackState {
  const existing = stateMap.get(userId);
  if (existing) return existing;

  const newState: AttackState = {
    userId,
    riskLevel: 'normal',
    rejectedCount: 0,
    correctionAttempts: 0,
    encodingAttempts: 0,
    escalationScore: 0,
    locked: false,
    lockedUntil: null,
    lastInteraction: Date.now(),
    firstSeen: Date.now(),
    messageCount: 0,
  };
  stateMap.set(userId, newState);
  return newState;
}

export function getState(userId: string): AttackState | null {
  return stateMap.get(userId) ?? null;
}

export async function updateState(
  userId: string,
  updates: Partial<AttackState>
): Promise<void> {
  const state = getOrCreateState(userId);
  const updated = { ...state, ...updates, lastInteraction: Date.now() };
  stateMap.set(userId, updated);
  await saveState();
}

export async function incrementMessageCount(userId: string): Promise<void> {
  const state = getOrCreateState(userId);
  state.messageCount += 1;
  state.lastInteraction = Date.now();
  await saveState();
}

export async function recordRejection(userId: string): Promise<void> {
  const state = getOrCreateState(userId);
  state.rejectedCount += 1;
  state.escalationScore += 10;
  state.lastInteraction = Date.now();
  await saveState();
}

export async function recordCorrectionAttempt(userId: string): Promise<void> {
  const state = getOrCreateState(userId);
  state.correctionAttempts += 1;
  state.escalationScore += 15;
  state.lastInteraction = Date.now();
  await saveState();
}

export async function recordEncodingAttempt(userId: string): Promise<void> {
  const state = getOrCreateState(userId);
  state.encodingAttempts += 1;
  state.escalationScore += 15;
  state.lastInteraction = Date.now();
  await saveState();
}

export function updateRiskLevel(userId: string, riskLevel: RiskLevel): void {
  const state = getOrCreateState(userId);
  state.riskLevel = riskLevel;
  stateMap.set(userId, state);
}

// ──────────────────────────────────────────────────────────────
// Lock Operations
// ──────────────────────────────────────────────────────────────

export async function lockUser(
  userId: string,
  durationMinutes: number,
  reason: string
): Promise<void> {
  const now = Date.now();
  const lock: LockState = {
    userId,
    lockedAt: now,
    lockedUntil: now + durationMinutes * 60 * 1000,
    reason,
  };
  locksMap.set(userId, lock);

  // Also update attack state
  const state = getOrCreateState(userId);
  state.locked = true;
  state.lockedUntil = lock.lockedUntil;
  state.riskLevel = 'malicious';
  stateMap.set(userId, state);

  await saveLocks();
  await saveState();
  logger.info('User locked', { userId, durationMinutes, reason });
}

export async function unlockUser(userId: string): Promise<boolean> {
  const deleted = locksMap.delete(userId);
  const state = stateMap.get(userId);
  if (state) {
    state.locked = false;
    state.lockedUntil = null;
    state.riskLevel = 'normal';
    stateMap.set(userId, state);
  }
  await saveLocks();
  await saveState();
  logger.info('User unlocked', { userId });
  return deleted;
}

export function isLocked(userId: string): boolean {
  const lock = locksMap.get(userId);
  if (!lock) return false;
  const now = Date.now();
  if (now > lock.lockedUntil) {
    // Lock expired — auto unlock
    locksMap.delete(userId);
    const state = stateMap.get(userId);
    if (state) {
      state.locked = false;
      state.lockedUntil = null;
      if (state.riskLevel === 'malicious') {
        state.riskLevel = 'normal';
      }
    }
    return false;
  }
  return true;
}

export function getLockInfo(userId: string): LockState | null {
  return locksMap.get(userId) ?? null;
}

export function getAllLocks(): LockState[] {
  return Array.from(locksMap.values());
}

// ──────────────────────────────────────────────────────────────
// User History (for risk scorer)
// ──────────────────────────────────────────────────────────────

export function getUserHistory(userId: string) {
  const state = getOrCreateState(userId);
  return {
    userId: state.userId,
    messageCount: state.messageCount,
    rejectedCount: state.rejectedCount,
    correctionAttempts: state.correctionAttempts,
    encodingAttempts: state.encodingAttempts,
    recentAttempts: Math.min(state.rejectedCount, 5),
    lastAttempt: state.lastInteraction,
    firstSeen: state.firstSeen,
  };
}
