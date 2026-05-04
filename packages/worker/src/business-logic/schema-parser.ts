import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import type { DomainEntity, EntityField, WorkflowState } from './types.js';
import { type Result, ok, err } from '../result.js';

// Route patterns for common frameworks
const ROUTE_PATTERNS = {
  express: /(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  fastify: /(?:fastify|server)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g,
  django: /path\s*\(\s*['"`]([^'"`]+)['"`]/g,
  rails: /(?:get|post|put|patch|delete)\s+['"`]([^'"`]+)['"`]/g,
  nextjs: /export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)/g,
  spring: /@(?:Get|Post|Put|Patch|Delete)Mapping\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g,
};

const MODEL_PATTERNS = {
  mongoose: /new\s+(?:mongoose\.)?Schema\s*\(\s*\{([^}]+)\}/gs,
  sequelize: /\.define\s*\(\s*['"`](\w+)['"`]\s*,\s*\{([^}]+)\}/gs,
  typeorm: /@Entity\s*\(\s*\)\s*export\s+class\s+(\w+)/g,
  prisma: /model\s+(\w+)\s*\{([^}]+)\}/g,
  django: /class\s+(\w+)\s*\(\s*models\.Model\s*\)/g,
};

export class SchemaParser {
  parseSourceRoutes(repoPath: string): Result<WorkflowState[]> {
    if (!existsSync(repoPath)) {
      return err(new Error(`Repository path not found: ${repoPath}`));
    }

    try {
      const routes: WorkflowState[] = [];
      const files = this.findSourceFiles(repoPath);

      for (const file of files) {
        const content = readFileSync(file, 'utf-8');
        const fileRoutes = this.extractRoutes(content, file);
        routes.push(...fileRoutes);
      }

      return ok(routes);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  parseOpenAPI(specPath: string): Result<DomainEntity[]> {
    if (!existsSync(specPath)) {
      return err(new Error(`OpenAPI spec not found: ${specPath}`));
    }

    try {
      const content = readFileSync(specPath, 'utf-8');
      const spec = JSON.parse(content);
      const entities: DomainEntity[] = [];

      // Extract schemas/definitions
      const schemas = spec.components?.schemas ?? spec.definitions ?? {};
      for (const [name, schema] of Object.entries(schemas)) {
        const s = schema as Record<string, unknown>;
        const properties = (s.properties ?? {}) as Record<string, { type?: string }>;
        const required = (s.required ?? []) as string[];

        entities.push({
          name,
          fields: Object.entries(properties).map(([fieldName, fieldSchema]) => ({
            name: fieldName,
            type: fieldSchema.type ?? 'unknown',
            constraints: required.includes(fieldName) ? ['required'] : [],
            sensitive: this.isSensitiveField(fieldName),
          })),
          relationships: [],
        });
      }

      return ok(entities);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  extractDomainModels(repoPath: string): Result<DomainEntity[]> {
    if (!existsSync(repoPath)) {
      return err(new Error(`Repository path not found: ${repoPath}`));
    }

    try {
      const entities: DomainEntity[] = [];
      const files = this.findSourceFiles(repoPath);

      for (const file of files) {
        const content = readFileSync(file, 'utf-8');

        for (const [framework, pattern] of Object.entries(MODEL_PATTERNS)) {
          let match: RegExpExecArray | null;
          const regex = new RegExp(pattern.source, pattern.flags);
          while ((match = regex.exec(content)) !== null) {
            const name = match[1] ?? 'Unknown';
            entities.push({
              name,
              fields: this.extractFields(content, framework),
              relationships: [],
            });
          }
        }
      }

      return ok(entities);
    } catch (e) {
      return err(e instanceof Error ? e : new Error(String(e)));
    }
  }

  private findSourceFiles(dir: string, depth: number = 5): string[] {
    if (depth <= 0) return [];

    const files: string[] = [];
    const extensions = ['.ts', '.js', '.py', '.rb', '.java', '.go', '.rs', '.prisma'];

    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === 'vendor') continue;

        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);

        if (stat.isDirectory()) {
          files.push(...this.findSourceFiles(fullPath, depth - 1));
        } else if (extensions.includes(extname(entry))) {
          files.push(fullPath);
        }
      }
    } catch {
      // Skip unreadable directories
    }

    return files;
  }

  private extractRoutes(content: string, filePath: string): WorkflowState[] {
    const routes: WorkflowState[] = [];
    let routeCounter = 0;

    for (const [framework, pattern] of Object.entries(ROUTE_PATTERNS)) {
      let match: RegExpExecArray | null;
      const regex = new RegExp(pattern.source, pattern.flags);
      while ((match = regex.exec(content)) !== null) {
        const method = match[1] ?? 'GET';
        const path = match[2] ?? match[1] ?? '';
        routes.push({
          id: `route-${++routeCounter}`,
          name: `${method.toUpperCase()} ${path}`,
          endpoint: path,
          expectedPreconditions: this.inferPreconditions(content, path),
        });
      }
    }

    return routes;
  }

  private inferPreconditions(content: string, path: string): string[] {
    const preconditions: string[] = [];

    // Check for auth middleware near the route
    if (/auth|protect|guard|requireAuth|isAuthenticated|jwt|token/i.test(content)) {
      preconditions.push('authenticated');
    }
    if (/admin|isAdmin|requireAdmin|role.*admin/i.test(content)) {
      preconditions.push('admin-role');
    }

    return preconditions;
  }

  private extractFields(content: string, framework: string): EntityField[] {
    const fields: EntityField[] = [];

    // Simple field extraction based on common patterns
    const fieldPattern = /['"`]?(\w+)['"`]?\s*:\s*\{?\s*type\s*:\s*['"`]?(\w+)/g;
    let match: RegExpExecArray | null;
    while ((match = fieldPattern.exec(content)) !== null) {
      fields.push({
        name: match[1],
        type: match[2],
        constraints: [],
        sensitive: this.isSensitiveField(match[1]),
      });
    }

    return fields;
  }

  private isSensitiveField(name: string): boolean {
    return /password|secret|token|key|credit|ssn|social|phone|email|address|salary|dob|birth/i.test(name);
  }
}
