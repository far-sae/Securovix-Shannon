import type { RetryPolicy } from '@temporalio/common';

export const RETRY_PRESETS = {
  default: {
    maximumAttempts: 50,
    initialInterval: '5m',
    maximumInterval: '30m',
    backoffCoefficient: 2,
  } satisfies RetryPolicy,

  fast: {
    maximumAttempts: 5,
    initialInterval: '10s',
    maximumInterval: '2m',
    backoffCoefficient: 2,
  } satisfies RetryPolicy,

  subscription: {
    maximumAttempts: 100,
    initialInterval: '5m',
    maximumInterval: '6h',
    backoffCoefficient: 2,
  } satisfies RetryPolicy,
} as const;

export type RetryPresetName = keyof typeof RETRY_PRESETS;

export function getRetryPolicy(preset: RetryPresetName = 'default'): RetryPolicy {
  return RETRY_PRESETS[preset];
}
