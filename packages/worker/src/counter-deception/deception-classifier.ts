import type { DeceptionSignal, DeceptionVerdict } from './types.js';

export class DeceptionClassifier {
  classify(endpoint: string, signals: DeceptionSignal[]): DeceptionVerdict {
    if (signals.length === 0) {
      return {
        endpoint,
        isDecoy: false,
        confidence: 0.9,
        signals: [],
        recommendation: 'safe',
      };
    }

    // Weighted scoring
    const totalConfidence = signals.reduce((sum, s) => sum + s.confidence, 0);
    const avgConfidence = totalConfidence / signals.length;

    // Multiple high-confidence signals strongly indicate deception
    const highConfidenceSignals = signals.filter((s) => s.confidence >= 0.8);
    const hasCanary = signals.some((s) => s.type === 'canary-token');
    const hasHoneypot = signals.some((s) => s.type === 'honeypot' && s.confidence >= 0.8);
    const hasTarpit = signals.some((s) => s.type === 'tarpit');

    let isDecoy = false;
    let recommendation: DeceptionVerdict['recommendation'] = 'safe';

    if (highConfidenceSignals.length >= 2 || hasCanary || (hasHoneypot && hasTarpit)) {
      isDecoy = true;
      recommendation = 'skip';
    } else if (signals.length >= 2 && avgConfidence >= 0.6) {
      isDecoy = false;
      recommendation = 'proceed-cautiously';
    }

    return {
      endpoint,
      isDecoy,
      confidence: avgConfidence,
      signals,
      recommendation,
    };
  }
}
