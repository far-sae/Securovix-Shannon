import { execSync } from 'node:child_process';
import { type Result, ok, err, tryCatch } from '../result.js';

export class GitCheckpoint {
  private workspaceDir: string;
  private static semaphore = Promise.resolve();

  constructor(workspaceDir: string) {
    this.workspaceDir = workspaceDir;
  }

  async createCheckpoint(label: string): Promise<Result<string>> {
    return this.serialized(async () => {
      try {
        this.git('add', '-A');
        this.git('commit', '--allow-empty', '-m', `checkpoint: ${label}`);
        const hash = this.git('rev-parse', 'HEAD').trim();
        return ok(hash);
      } catch (e) {
        return err(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  async rollback(label: string): Promise<Result<void>> {
    return this.serialized(async () => {
      try {
        const hash = await this.getCheckpoint(label);
        if (hash) {
          this.git('reset', '--hard', hash);
        }
        return ok(undefined);
      } catch (e) {
        return err(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  async getCheckpoint(label: string): Promise<string | null> {
    try {
      const log = this.git('log', '--oneline', '--all', '--grep', `checkpoint: ${label}`);
      const match = log.match(/^([a-f0-9]+)/);
      return match ? match[1] : null;
    } catch {
      return null;
    }
  }

  async restoreTo(hash: string): Promise<Result<void>> {
    return this.serialized(async () => {
      try {
        this.git('reset', '--hard', hash);
        return ok(undefined);
      } catch (e) {
        return err(e instanceof Error ? e : new Error(String(e)));
      }
    });
  }

  // Serialize git operations through a semaphore to avoid index lock conflicts
  private async serialized<T>(fn: () => Promise<T>): Promise<T> {
    const prev = GitCheckpoint.semaphore;
    let resolve: () => void;
    GitCheckpoint.semaphore = new Promise<void>((r) => { resolve = r; });

    await prev;
    try {
      return await fn();
    } finally {
      resolve!();
    }
  }

  private git(...args: string[]): string {
    return execSync(`git ${args.join(' ')}`, {
      cwd: this.workspaceDir,
      encoding: 'utf-8',
      timeout: 30_000,
    });
  }
}
