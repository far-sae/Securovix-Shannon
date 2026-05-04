import type { EvasionTechnique } from './types.js';

export class PayloadEncoder {
  encode(payload: string, technique: EvasionTechnique): string {
    switch (technique) {
      case 'payload-double-encode':
        return this.doubleEncode(payload);
      case 'payload-unicode':
        return this.unicodeEncode(payload);
      case 'payload-case-variation':
        return this.caseVariation(payload);
      case 'payload-comment-inject':
        return this.commentInject(payload);
      case 'payload-chunked':
        return this.chunkedPayload(payload);
      default:
        return payload;
    }
  }

  private doubleEncode(payload: string): string {
    return encodeURIComponent(encodeURIComponent(payload));
  }

  private unicodeEncode(payload: string): string {
    return payload
      .replace(/a/gi, (c) => (Math.random() > 0.5 ? '\u0061' : c))
      .replace(/e/gi, (c) => (Math.random() > 0.5 ? '\u0065' : c))
      .replace(/i/gi, (c) => (Math.random() > 0.5 ? '\u0069' : c))
      .replace(/o/gi, (c) => (Math.random() > 0.5 ? '\u006f' : c))
      .replace(/'/g, '\u0027')
      .replace(/"/g, '\u0022');
  }

  private caseVariation(payload: string): string {
    // SQL keyword case variation: SELECT -> SeLeCt
    const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|UNION|FROM|WHERE|AND|OR|DROP|TABLE|ALTER|CREATE|EXEC|EXECUTE)\b/gi;
    return payload.replace(sqlKeywords, (match) => {
      return match
        .split('')
        .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
        .join('');
    });
  }

  private commentInject(payload: string): string {
    // Insert inline comments into SQL keywords: SELECT -> S/**/E/**/L/**/E/**/C/**/T
    const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|UNION|FROM|WHERE|AND|OR)\b/gi;
    return payload.replace(sqlKeywords, (match) => {
      return match.split('').join('/**/');
    });
  }

  private chunkedPayload(payload: string): string {
    // Split payload into chunks with null bytes (for certain parsers)
    const chunkSize = Math.max(2, Math.floor(payload.length / 4));
    const chunks: string[] = [];
    for (let i = 0; i < payload.length; i += chunkSize) {
      chunks.push(payload.slice(i, i + chunkSize));
    }
    return chunks.join('%00');
  }
}
