import type { VulnNode, Edge, AttackChain } from './types.js';

export class AttackGraph {
  private adjacency = new Map<string, Set<string>>();
  private reverseAdj = new Map<string, Set<string>>();
  private nodes = new Map<string, VulnNode>();
  private edges: Edge[] = [];

  addNode(node: VulnNode): void {
    this.nodes.set(node.id, node);
    if (!this.adjacency.has(node.id)) {
      this.adjacency.set(node.id, new Set());
    }
    if (!this.reverseAdj.has(node.id)) {
      this.reverseAdj.set(node.id, new Set());
    }
  }

  addEdge(edge: Edge): void {
    this.edges.push(edge);
    if (!this.adjacency.has(edge.from)) {
      this.adjacency.set(edge.from, new Set());
    }
    this.adjacency.get(edge.from)!.add(edge.to);

    if (!this.reverseAdj.has(edge.to)) {
      this.reverseAdj.set(edge.to, new Set());
    }
    this.reverseAdj.get(edge.to)!.add(edge.from);
  }

  getNode(id: string): VulnNode | undefined {
    return this.nodes.get(id);
  }

  getEdge(from: string, to: string): Edge | undefined {
    return this.edges.find((e) => e.from === from && e.to === to);
  }

  // Find all paths from entry points (no preconditions or preconditions met by unauthenticated access)
  // to nodes whose postconditions match the objective
  findChains(objective: string, maxDepth: number = 6): VulnNode[][] {
    const chains: VulnNode[][] = [];
    const entryPoints = this.findEntryPoints();

    for (const entry of entryPoints) {
      this.dfs(entry, objective, [entry], new Set([entry.id]), maxDepth, chains);
    }

    // Sort by composite score
    return chains.sort((a, b) => this.scoreChainNodes(b) - this.scoreChainNodes(a));
  }

  private findEntryPoints(): VulnNode[] {
    const entries: VulnNode[] = [];
    for (const node of this.nodes.values()) {
      // Entry points: no preconditions, or preconditions like "unauthenticated", "public"
      if (
        node.preconditions.length === 0 ||
        node.preconditions.every((p) =>
          ['unauthenticated', 'public', 'none', 'external'].includes(p.toLowerCase()),
        )
      ) {
        entries.push(node);
      }
    }
    return entries;
  }

  private dfs(
    current: VulnNode,
    objective: string,
    path: VulnNode[],
    visited: Set<string>,
    maxDepth: number,
    results: VulnNode[][],
  ): void {
    // Check if current node achieves the objective
    if (current.postconditions.some((p) => p.toLowerCase().includes(objective.toLowerCase()))) {
      results.push([...path]);
    }

    if (path.length >= maxDepth) return;

    const neighbors = this.adjacency.get(current.id) ?? new Set();
    for (const neighborId of neighbors) {
      if (visited.has(neighborId)) continue;

      const neighbor = this.nodes.get(neighborId);
      if (!neighbor) continue;

      // Check if current node's postconditions satisfy neighbor's preconditions
      const satisfied = neighbor.preconditions.every((pre) =>
        path.some((n) => n.postconditions.some((post) => post.toLowerCase().includes(pre.toLowerCase()))),
      );

      if (satisfied || neighbor.preconditions.length === 0) {
        visited.add(neighborId);
        path.push(neighbor);
        this.dfs(neighbor, objective, path, visited, maxDepth, results);
        path.pop();
        visited.delete(neighborId);
      }
    }
  }

  private scoreChainNodes(chain: VulnNode[]): number {
    if (chain.length === 0) return 0;

    // Product of feasibility scores * impact multiplier * brevity bonus
    let feasibility = 1;
    for (const node of chain) {
      feasibility *= node.feasibilityScore;
    }

    const impactMap = { critical: 4, high: 3, medium: 2, low: 1 };
    const lastNode = chain[chain.length - 1];
    const impact = impactMap[lastNode.severity] ?? 1;

    // Shorter chains are more feasible
    const brevityBonus = 1 / Math.sqrt(chain.length);

    return feasibility * impact * brevityBonus;
  }

  scoreChain(chain: VulnNode[], chainEdges: Edge[]): number {
    const nodeScore = this.scoreChainNodes(chain);

    // Factor in edge confidence
    let edgeConfidence = 1;
    for (const edge of chainEdges) {
      edgeConfidence *= edge.confidence;
    }

    return nodeScore * edgeConfidence;
  }

  topologicalSort(chain: VulnNode[]): VulnNode[] {
    const chainIds = new Set(chain.map((n) => n.id));
    const inDegree = new Map<string, number>();
    const adj = new Map<string, string[]>();

    for (const node of chain) {
      inDegree.set(node.id, 0);
      adj.set(node.id, []);
    }

    for (const edge of this.edges) {
      if (chainIds.has(edge.from) && chainIds.has(edge.to)) {
        adj.get(edge.from)!.push(edge.to);
        inDegree.set(edge.to, (inDegree.get(edge.to) ?? 0) + 1);
      }
    }

    const queue: string[] = [];
    for (const [id, degree] of inDegree) {
      if (degree === 0) queue.push(id);
    }

    const sorted: VulnNode[] = [];
    while (queue.length > 0) {
      const id = queue.shift()!;
      sorted.push(this.nodes.get(id)!);

      for (const neighbor of adj.get(id) ?? []) {
        const newDegree = (inDegree.get(neighbor) ?? 1) - 1;
        inDegree.set(neighbor, newDegree);
        if (newDegree === 0) queue.push(neighbor);
      }
    }

    return sorted;
  }

  toPromptContext(): string {
    const lines: string[] = ['## Attack Surface Graph\n'];

    lines.push('### Vulnerability Nodes\n');
    for (const node of this.nodes.values()) {
      lines.push(`- **${node.id}** [${node.category}] (${node.severity})`);
      lines.push(`  Endpoint: ${node.endpoint}`);
      lines.push(`  Preconditions: ${node.preconditions.join(', ') || 'none'}`);
      lines.push(`  Postconditions: ${node.postconditions.join(', ') || 'none'}`);
      lines.push(`  Feasibility: ${node.feasibilityScore}`);
      lines.push('');
    }

    lines.push('### Edges (Vulnerability Relationships)\n');
    for (const edge of this.edges) {
      lines.push(`- ${edge.from} --[${edge.transitionType}]--> ${edge.to} (confidence: ${edge.confidence})`);
    }

    return lines.join('\n');
  }

  getAllNodes(): VulnNode[] {
    return [...this.nodes.values()];
  }

  getAllEdges(): Edge[] {
    return [...this.edges];
  }
}
