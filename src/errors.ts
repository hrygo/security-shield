// ============================================================
// Security Shield — Error Types
// ============================================================

export enum SecurityShieldError {
  // Detection errors
  DETECTOR_INIT_FAILED = 'DETECTOR_INIT_FAILED',
  DETECTOR_RUNTIME_ERROR = 'DETECTOR_RUNTIME_ERROR',

  // State management errors
  STATE_LOAD_FAILED = 'STATE_LOAD_FAILED',
  STATE_SAVE_FAILED = 'STATE_SAVE_FAILED',

  // Audit log errors
  AUDIT_LOG_WRITE_FAILED = 'AUDIT_LOG_WRITE_FAILED',

  // Config errors
  CONFIG_INVALID = 'CONFIG_INVALID',

  // Tool approval errors
  TOOL_APPROVAL_FAILED = 'TOOL_APPROVAL_FAILED',
}

export interface SecurityShieldErrorDetail {
  code: SecurityShieldError;
  message: string;
  recoverable: boolean;
  details?: unknown;
}

export class SecurityShieldException extends Error {
  public readonly code: SecurityShieldError;
  public readonly recoverable: boolean;
  public readonly details?: unknown;

  constructor(detail: SecurityShieldErrorDetail) {
    super(detail.message);
    this.name = 'SecurityShieldException';
    this.code = detail.code;
    this.recoverable = detail.recoverable;
    this.details = detail.details;
  }
}

export function isSecurityShieldError(err: unknown): err is SecurityShieldException {
  return err instanceof SecurityShieldException;
}
