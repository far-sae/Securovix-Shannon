import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { type Result, ok, err } from '../result.js';

const PROMPTS_DIR = process.env.SHANNON_PROMPTS_DIR ?? '/app/prompts';

export interface PromptContext {
  targetUrl: string;
  repoPath?: string;
  configContext?: string;
  loginInstructions?: string;
}

export function loadPrompt(name: string, context: PromptContext): Result<string> {
  const promptPath = resolvePromptPath(name);
  if (!existsSync(promptPath)) {
    return err(new Error(`Prompt template not found: ${promptPath}`));
  }

  try {
    let template = readFileSync(promptPath, 'utf-8');
    template = substituteVariables(template, context);
    template = resolvePartials(template);
    return ok(template);
  } catch (e) {
    return err(e instanceof Error ? e : new Error(String(e)));
  }
}

function resolvePromptPath(name: string): string {
  // Support nested paths like "vuln/sqli"
  return join(PROMPTS_DIR, `${name}.txt`);
}

function substituteVariables(template: string, context: PromptContext): string {
  return template
    .replace(/\{\{TARGET_URL\}\}/g, context.targetUrl)
    .replace(/\{\{REPO_PATH\}\}/g, context.repoPath ?? 'N/A')
    .replace(/\{\{CONFIG_CONTEXT\}\}/g, context.configContext ?? '')
    .replace(/\{\{LOGIN_INSTRUCTIONS\}\}/g, context.loginInstructions ?? 'No authentication required.');
}

function resolvePartials(template: string): string {
  const partialRegex = /\{\{>(\S+)\}\}/g;
  return template.replace(partialRegex, (_match, partialName: string) => {
    const partialPath = join(PROMPTS_DIR, 'partials', `${partialName}.txt`);
    if (!existsSync(partialPath)) {
      return `[MISSING PARTIAL: ${partialName}]`;
    }
    return readFileSync(partialPath, 'utf-8');
  });
}
