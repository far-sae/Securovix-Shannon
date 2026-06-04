import type { ToolDescriptor } from '../types.js';

const SHELL_METACHARS = /[$`;|&><\n\r]/;

export class ToolRegistry {
  private readonly byId: Map<string, ToolDescriptor>;

  constructor(descriptors: ToolDescriptor[]) {
    this.byId = new Map(descriptors.map((d) => [d.id, d]));
  }

  descriptor(toolId: string): ToolDescriptor {
    const d = this.byId.get(toolId);
    if (!d) throw new Error(`Unknown tool: ${toolId}`);
    return d;
  }

  buildArgv(toolId: string, params: Record<string, string | number>): string[] {
    const d = this.descriptor(toolId);
    const allowed = new Set(d.params.map((p) => p.name));

    for (const key of Object.keys(params)) {
      if (!allowed.has(key)) throw new Error(`Param not allowed for ${toolId}: ${key}`);
    }

    const argv: string[] = [d.bin];
    for (const spec of d.params) {
      const raw = params[spec.name];
      if (raw === undefined) {
        if (spec.required) throw new Error(`Missing required param for ${toolId}: ${spec.name}`);
        continue;
      }
      const value = String(raw);
      if (SHELL_METACHARS.test(value)) {
        throw new Error(`Invalid value for ${spec.name}: shell metacharacter rejected`);
      }
      if (spec.enumValues && !spec.enumValues.includes(value)) {
        throw new Error(`Invalid value for ${spec.name}: not in [${spec.enumValues.join(', ')}]`);
      }
      if (spec.pattern && !new RegExp(`^(?:${spec.pattern})$`).test(value)) {
        throw new Error(`Invalid value for ${spec.name}: does not match pattern`);
      }
      if (spec.flag) argv.push(spec.flag);
      argv.push(value);
    }

    for (const token of d.blocklist) {
      if (argv.includes(token)) throw new Error(`Blocklisted token in argv for ${toolId}: ${token}`);
    }
    return argv;
  }
}
