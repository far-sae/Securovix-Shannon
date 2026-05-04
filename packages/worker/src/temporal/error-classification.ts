import { ApplicationFailure } from '@temporalio/common';
import { classifyError } from '../config/validation.js';

export function toTemporalError(error: unknown): ApplicationFailure {
  const classified = classifyError(error);

  return ApplicationFailure.create({
    message: classified.message,
    type: classified.code,
    nonRetryable: !classified.retryable,
  });
}

export const ACTIVITY_TIMEOUTS = {
  startToCloseTimeout: '2h',
  heartbeatTimeout: '60m',
} as const;

export const MAX_DELIVERABLE_SIZE = 2 * 1024 * 1024; // 2MB
export const MAX_ERROR_LENGTH = 2000;

export function truncateForSerialization(data: string): string {
  if (data.length <= MAX_DELIVERABLE_SIZE) return data;
  return data.slice(0, MAX_DELIVERABLE_SIZE) + '\n\n[TRUNCATED - exceeded 2MB limit]';
}
