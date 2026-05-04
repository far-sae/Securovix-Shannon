export class ShannonError extends Error {
  constructor(
    message: string,
    public readonly retryable: boolean,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'ShannonError';
  }
}

export function classifyError(error: unknown): ShannonError {
  if (error instanceof ShannonError) return error;

  const message = error instanceof Error ? error.message : String(error);
  const truncated = message.slice(0, 2000);

  // Non-retryable errors
  if (isAuthError(message)) {
    return new ShannonError(truncated, false, 'AUTH_FAILURE');
  }
  if (isConfigError(message)) {
    return new ShannonError(truncated, false, 'INVALID_CONFIG');
  }
  if (isOOMError(message)) {
    return new ShannonError(truncated, false, 'OUT_OF_MEMORY');
  }

  // Retryable errors
  if (isRateLimitError(message)) {
    return new ShannonError(truncated, true, 'RATE_LIMIT');
  }
  if (isNetworkError(message)) {
    return new ShannonError(truncated, true, 'NETWORK_ERROR');
  }

  return new ShannonError(truncated, true, 'UNKNOWN');
}

function isAuthError(msg: string): boolean {
  return /401|403|authentication failed|invalid.*api.*key|unauthorized/i.test(msg);
}

function isConfigError(msg: string): boolean {
  return /invalid config|config.*not found|validation failed/i.test(msg);
}

function isOOMError(msg: string): boolean {
  return /out of memory|heap|ENOMEM|OOM/i.test(msg);
}

function isRateLimitError(msg: string): boolean {
  return /429|rate.?limit|too many requests|overloaded/i.test(msg);
}

function isNetworkError(msg: string): boolean {
  return /ECONNREFUSED|ECONNRESET|ETIMEDOUT|socket hang up|network/i.test(msg);
}
