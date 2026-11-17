// Turns the scanner's printed output into progress: which phase is running, which are done, and
// the lines to show. Used by the worker (which runs the scanner) and by the dashboard (which shows
// it), so both read the output the same way.

export const SCAN_PHASES = [
  { re: /\[Phase 0\]/, id: 'http-recon', name: 'HTTP Recon' },
  { re: /\[Phase 1\]/, id: 'pre-recon', name: 'Pre-Recon' },
  { re: /\[Phase 2\]/, id: 'recon', name: 'Deep Recon' },
  { re: /\[Phase 3\]/, id: 'red-team', name: 'Red Team Attack' },
  { re: /\[Phase 4\]/, id: 'purple-team', name: 'Purple Team (2 Red + 2 Blue)' },
  { re: /\[Phase 5\]/, id: 'exploit-verify', name: 'Exploit Verify' },
  { re: /\[Phase 6\]/, id: 'chain', name: 'Attack Chains' },
  { re: /\[Phase 7\]/, id: 'war-room', name: 'War Room' },
  { re: /\[Phase 8\]/, id: 'report', name: 'Report' },
  { re: /\[Phase 9\]/, id: 'forensic', name: 'Forensic' },
];

const MAX_LINE = 8000;

export function createProgress() {
  return { phases: [], current: null, carry: '' };
}

/**
 * Feeds a piece of scanner output. Output arrives in arbitrary pieces, so an unfinished last line
 * is kept until the rest of it arrives.
 * @returns {Array<{type: 'phase'|'phase-done'|'output', [key: string]: unknown}>} events, in order
 */
export function feedProgress(state, text) {
  const events = [];
  const lines = `${state.carry}${String(text ?? '')}`.split('\n');
  state.carry = lines.pop() || '';
  if (state.carry.length > MAX_LINE) {
    lines.push(state.carry);
    state.carry = '';
  }
  for (const raw of lines) {
    const line = raw.trim().slice(0, MAX_LINE);
    if (!line) continue;
    const phase = SCAN_PHASES.find((p) => p.re.test(line));
    if (phase && state.current?.id !== phase.id) {
      if (state.current?.status === 'running') state.current.status = 'done';
      state.current = { id: phase.id, name: phase.name, status: 'running' };
      state.phases.push(state.current);
      events.push({ type: 'phase', phase: phase.id, name: phase.name, status: 'running' });
    }
    if (/Done \(/.test(line) && state.current?.status === 'running') {
      state.current.status = 'done';
      const cost = /\$([0-9.]+)/.exec(line);
      if (cost) state.current.cost = Number.parseFloat(cost[1]);
      const seconds = /Done \((\d+\.?\d*)s/.exec(line);
      if (seconds) state.current.duration = Number.parseFloat(seconds[1]);
      events.push({
        type: 'phase-done',
        phase: state.current.id,
        cost: state.current.cost,
        duration: state.current.duration,
      });
    }
    events.push({ type: 'output', line });
  }
  return events;
}

/**
 * What a viewer has not seen yet of a scan that runs elsewhere. `result` is what the worker last
 * stored: the tail of the output, how much was printed in total, and the phases so far. `seen`
 * remembers what this viewer was already sent and is updated in place.
 * @returns {Array<object>} events to send
 */
export function progressSince(seen, result) {
  const events = [];
  // A scan that was started again prints from the beginning.
  if (Number(result?.outputChars || 0) < seen.chars) {
    seen.phases.clear();
    seen.chars = 0;
    seen.carry = '';
  }
  for (const phase of Array.isArray(result?.phases) ? result.phases : []) {
    const before = seen.phases.get(phase.id);
    if (!before) events.push({ type: 'phase', phase: phase.id, name: phase.name, status: 'running' });
    if (phase.status === 'done' && before !== 'done')
      events.push({ type: 'phase-done', phase: phase.id, cost: phase.cost, duration: phase.duration });
    seen.phases.set(phase.id, phase.status);
  }
  const total = Number(result?.outputChars || 0);
  const tail = String(result?.outputTail || '');
  if (total > seen.chars) {
    const fresh = tail.slice(-Math.min(total - seen.chars, tail.length));
    seen.chars = total;
    const lines = `${seen.carry}${fresh}`.split('\n');
    seen.carry = lines.pop() || '';
    for (const raw of lines) {
      const line = raw.trim();
      if (line) events.push({ type: 'output', line: line.slice(0, MAX_LINE) });
    }
  }
  return events;
}

export function createSeen() {
  return { phases: new Map(), chars: 0, carry: '' };
}
