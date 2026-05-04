import { homedir } from 'node:os';
import { join } from 'node:path';

export interface LocalMode {
  type: 'local';
  workspacesDir: string;
  mountPrompts: boolean;
  imageBuild: 'local';
}

export interface NpxMode {
  type: 'npx';
  workspacesDir: string;
  configDir: string;
  imageBuild: 'pull';
}

export type RuntimeMode = LocalMode | NpxMode;

export function detectMode(): RuntimeMode {
  if (process.env.SHANNON_LOCAL) {
    return {
      type: 'local',
      workspacesDir: join(process.cwd(), 'workspaces'),
      mountPrompts: true,
      imageBuild: 'local',
    };
  }

  const shannonHome = join(homedir(), '.shannon');
  return {
    type: 'npx',
    workspacesDir: join(shannonHome, 'workspaces'),
    configDir: shannonHome,
    imageBuild: 'pull',
  };
}
