import type { BudgetLedger } from '../budget/ledger.js';
import type { ToolRegistry } from '../registry/registry.js';
import type { ScopeEnforcer } from '../scope/enforcer.js';
import { verifyScopeToken } from '../scope/lock.js';
import type { ScopeConfig, ToolRequest, ToolResult } from '../types.js';

export interface AuthorizeDeps {
  scopeConfig: ScopeConfig;
  scopeKey: string;
  enforcer: ScopeEnforcer;
  registry: ToolRegistry;
  ledger: BudgetLedger;
}

export interface ResolvedTarget {
  ip: string;
  path: string;
}

export type AuthorizeResult = { authorized: true; argv: string[] } | { authorized: false; result: ToolResult };

function denied(tool: string, status: ToolResult['status'], detail: string): AuthorizeResult {
  return { authorized: false, result: { tool, status, stderr: detail } };
}

// Order matters: verify the (free) scope authorization first, then evaluate the
// concrete IP/path, then validate the argv — and ONLY THEN consume budget, so a
// denied or malformed request never burns a budget unit.
export function authorizeRequest(req: ToolRequest, target: ResolvedTarget, deps: AuthorizeDeps): AuthorizeResult {
  if (!verifyScopeToken(req.scopeToken, deps.scopeConfig, deps.scopeKey)) {
    return denied(req.tool, 'scope', 'scope-lock token invalid');
  }

  const decision = deps.enforcer.evaluate(target.ip, target.path);
  if (!decision.allowed) {
    return denied(req.tool, 'scope', `${decision.reason}: ${decision.detail ?? ''}`.trim());
  }

  let argv: string[];
  try {
    argv = deps.registry.buildArgv(req.tool, req.params);
  } catch (e) {
    return denied(req.tool, 'blocked', e instanceof Error ? e.message : String(e));
  }

  const budget = deps.ledger.tryConsume('toolInvocations', 1);
  if (!budget.ok) {
    return denied(req.tool, 'budget', 'tool invocation budget exhausted');
  }

  return { authorized: true, argv };
}
