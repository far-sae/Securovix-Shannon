import { randomUUID } from 'node:crypto';
import type { AgentRole, WarRoomMessage } from './types.js';

export class DebateProtocol {
  private messages: WarRoomMessage[] = [];
  private currentRound: number = 1;

  createMessage(
    from: AgentRole,
    to: AgentRole | 'all',
    type: WarRoomMessage['type'],
    findingRef: string,
    content: string,
    structuredData?: Record<string, unknown>,
  ): WarRoomMessage {
    const message: WarRoomMessage = {
      id: randomUUID().slice(0, 8),
      from,
      to,
      timestamp: new Date().toISOString(),
      round: this.currentRound,
      type,
      findingRef,
      content,
      structuredData,
    };

    this.messages.push(message);
    return message;
  }

  advanceRound(): void {
    this.currentRound++;
  }

  getCurrentRound(): number {
    return this.currentRound;
  }

  getTranscript(): WarRoomMessage[] {
    return [...this.messages];
  }

  getMessagesForFinding(findingRef: string): WarRoomMessage[] {
    return this.messages.filter((m) => m.findingRef === findingRef);
  }

  getLastMessageFrom(role: AgentRole, findingRef: string): WarRoomMessage | undefined {
    return [...this.messages]
      .reverse()
      .find((m) => m.from === role && m.findingRef === findingRef);
  }

  buildContextForAgent(role: AgentRole, findingRef: string): string {
    const relevantMessages = this.getMessagesForFinding(findingRef);
    if (relevantMessages.length === 0) return '';

    return relevantMessages
      .map((m) => `[Round ${m.round}] ${m.from} -> ${m.to} (${m.type}):\n${m.content}`)
      .join('\n\n---\n\n');
  }
}
