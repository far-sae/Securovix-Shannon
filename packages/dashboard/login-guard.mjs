// login-guard.mjs — lock an ACCOUNT after repeated failed sign-ins, whatever address they come from.
//
// The per-address rate limit stops one machine guessing; it does nothing against a guesser that
// rotates addresses, because every new address starts with a fresh allowance. This counts failures
// per account instead. After `limit` failures inside `windowMs`, sign-in for that account is refused
// for `lockMs` — including with the right password, which is the point: the guesser cannot tell a
// correct guess from a wrong one while the lock holds.
//
// Design notes:
//   * Keyed on a hash of whatever identifier was typed, existing account or not, so the response
//     never reveals whether an account exists and no email addresses sit in memory.
//   * The lock is temporary and short. A permanent lock would let anyone lock a victim out forever.
//   * A lock is not extended by attempts made while it holds, so it always ends on schedule.
//   * Memory is bounded: the oldest entries are dropped past `maxKeys`.
//   * In-process. With several server instances each keeps its own count, so the effective limit is
//     `limit` × instances — still a hard ceiling where there was none.
import { createHash } from 'node:crypto';

export function createLoginGuard({
  limit = 10,
  windowMs = 15 * 60_000,
  lockMs = 15 * 60_000,
  maxKeys = 50_000,
  now = () => Date.now(),
} = {}) {
  const entries = new Map(); // key -> { failures: number[], lockedUntil: number }
  const keyOf = (scope, id) =>
    createHash('sha256')
      .update(
        `${scope}:${String(id || '')
          .trim()
          .toLowerCase()}`,
      )
      .digest('base64url');

  const retryAfter = (until) => Math.max(1, Math.ceil((until - now()) / 1000));

  /** Is this account locked right now? Call before checking the password. */
  function check(scope, id) {
    const entry = entries.get(keyOf(scope, id));
    if (!entry || !(entry.lockedUntil > now())) return { locked: false };
    return { locked: true, retryAfter: retryAfter(entry.lockedUntil) };
  }

  /** Record one failed attempt. Returns { locked: true } when this failure trips the lock. */
  function fail(scope, id) {
    const key = keyOf(scope, id);
    const t = now();
    const entry = entries.get(key) || { failures: [], lockedUntil: 0 };
    if (entry.lockedUntil > t) return { locked: true, retryAfter: retryAfter(entry.lockedUntil), justLocked: false };
    entry.failures = entry.failures.filter((x) => t - x < windowMs);
    entry.failures.push(t);
    // Re-insert so Map order tracks recency and the oldest entry is the first key.
    entries.delete(key);
    entries.set(key, entry);
    if (entries.size > maxKeys) entries.delete(entries.keys().next().value);
    if (entry.failures.length < limit) return { locked: false, remaining: limit - entry.failures.length };
    entry.failures = [];
    entry.lockedUntil = t + lockMs;
    return { locked: true, retryAfter: retryAfter(entry.lockedUntil), justLocked: true };
  }

  /** A successful sign-in clears the count. */
  function succeed(scope, id) {
    entries.delete(keyOf(scope, id));
  }

  return { check, fail, succeed, size: () => entries.size };
}
