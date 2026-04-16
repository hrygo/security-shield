// ============================================================
// Security Shield — Detector Base Class
// ============================================================

import type { DetectionResult, DetectionDimension, Confidence, NormalizedInput } from '../types.js';

export interface PatternRule {
  name: string;
  pattern: RegExp;
  weight: number;
}

export abstract class BaseDetector {
  public readonly dimension: DetectionDimension;

  constructor(dimension: DetectionDimension) {
    this.dimension = dimension;
  }

  protected abstract get patterns(): PatternRule[];

  protected get confidenceThresholds(): Record<string, { low: number; medium: number }> | undefined { return undefined; }

  detect(input: NormalizedInput): DetectionResult {
    try {
      const matchedRules: string[] = [];
      let totalScore = 0;

      for (const rule of this.patterns) {
        if (rule.pattern.test(input.cleaned) || rule.pattern.test(input.raw)) {
          matchedRules.push(rule.name);
          totalScore += rule.weight;
        }
      }

      // If no patterns matched, return no detection
      if (matchedRules.length === 0) {
        return {
          dimension: this.dimension,
          score: 0,
          confidence: 'low',
          matchedPatterns: [],
          shouldBlock: false,
        };
      }

      // Determine confidence based on matched rules count and score
      const confidence = this.calculateConfidence(totalScore, matchedRules.length);

      // Clamp score to 0-100
      const score = Math.min(Math.max(totalScore, 0), 100);

      return {
        dimension: this.dimension,
        score,
        confidence,
        matchedPatterns: matchedRules,
        shouldBlock: this.shouldBlock(score, confidence),
      };
    } catch (err) {
      // Fallback: return zero detection on error
      return {
        dimension: this.dimension,
        score: 0,
        confidence: 'low',
        matchedPatterns: [],
        shouldBlock: false,
      };
    }
  }

  protected calculateConfidence(score: number, matchCount: number): Confidence {
    if (score >= 60 && matchCount >= 2) return 'high';
    if (score >= 30 && matchCount >= 1) return 'medium';
    return 'low';
  }

  protected shouldBlock(score: number, confidence: Confidence): boolean {
    if (confidence === 'high' && score >= 50) return true;
    if (confidence === 'medium' && score >= 70) return true;
    return false;
  }
}
