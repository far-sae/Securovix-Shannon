import { randomUUID } from 'node:crypto';
import type {
  PurpleAgentRole,
  PurpleChannel,
  PurpleMessage,
  PurpleMessageType,
  Team,
} from './types.js';

export class PurpleProtocol {
  private messages: PurpleMessage[] = [];
  private round: number = 1;

  send(args: {
    channel: PurpleChannel;
    team: Team | 'cross';
    from: PurpleAgentRole;
    to: PurpleMessage['to'];
    type: PurpleMessageType;
    findingRef: string;
    content: string;
  }): PurpleMessage {
    const message: PurpleMessage = {
      id: randomUUID().slice(0, 8),
      round: this.round,
      timestamp: new Date().toISOString(),
      ...args,
    };
    this.messages.push(message);
    return message;
  }

  advanceRound(): void {
    this.round++;
  }

  currentRound(): number {
    return this.round;
  }

  transcript(): PurpleMessage[] {
    return [...this.messages];
  }

  forFinding(findingRef: string): PurpleMessage[] {
    return this.messages.filter((m) => m.findingRef === findingRef);
  }

  // What an agent can see: all messages on channels they participate in for this finding.
  visibleTo(role: PurpleAgentRole, findingRef: string): PurpleMessage[] {
    return this.forFinding(findingRef).filter((m) => this.canSee(role, m));
  }

  renderHistory(role: PurpleAgentRole, findingRef: string): string {
    const visible = this.visibleTo(role, findingRef);
    if (visible.length === 0) return '';
    return visible
      .map(
        (m) =>
          `[Round ${m.round} | ${m.channel} | ${m.from} -> ${m.to} | ${m.type}]\n${m.content}`,
      )
      .join('\n\n---\n\n');
  }

  private canSee(role: PurpleAgentRole, msg: PurpleMessage): boolean {
    if (role === 'moderator') return true;
    const isRed = role === 'red-strategist' || role === 'red-attacker';
    const isBlue = role === 'blue-defender' || role === 'blue-ir';

    if (msg.channel === 'cross-team') return true;
    if (msg.channel === 'red-internal') return isRed;
    if (msg.channel === 'blue-internal') return isBlue;
    return false;
  }
}
