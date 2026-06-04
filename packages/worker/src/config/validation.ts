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
  if (isScopeError(message)) {
    return new ShannonError(truncated, false, 'SCOPE_DENIED');
  }
  if (isBudgetError(message)) {
    return new ShannonError(truncated, false, 'BUDGET_EXHAUSTED');
  }

  // Retryable errors
  if (isBrokerUnavailable(message)) {
    return new ShannonError(truncated, true, 'BROKER_UNAVAILABLE');
  }
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

function isScopeError(msg: string): boolean {
  return /out.?of.?scope|scope.*(denied|block)|blocked.*scope|not in scope/i.test(msg);
}

function isBudgetError(msg: string): boolean {
  return /budget.*(exceed|exhaust)|max.*(tool.*invocation|http.*request|cost)|cost.*limit/i.test(msg);
}

function isBrokerUnavailable(msg: string): boolean {
  return /broker.*(unavailable|unreachable|down)|tool-broker.*(refused|unavailable)/i.test(msg);
}
