// ============================================================
// Security Shield — Detector Index (Aggregator)
// ============================================================

import type { DetectionResult, DetectionContext } from '../types.js';
import { EncodingDetector } from './encoding.js';
import { InjectionDetector } from './injection.js';
import { SocialEngineeringDetector } from './social.js';
import { PrivilegeDetector } from './privilege.js';
import { InformationDetector } from './information.js';
import { BaseDetector } from './base.js';

const DETECTOR_MAP: Record<string, BaseDetector> = {
  encoding: new EncodingDetector('encoding'),
  injection: new InjectionDetector('injection'),
  social: new SocialEngineeringDetector('social'),
  privilege: new PrivilegeDetector('privilege'),
  information: new InformationDetector('information'),
};

export const ALL_DIMENSIONS = Object.keys(DETECTOR_MAP) as Array<
  'encoding' | 'injection' | 'social' | 'privilege' | 'information'
>;

export function runAllDetections(context: DetectionContext): DetectionResult[] {
  const results: DetectionResult[] = [];

  for (const dimension of ALL_DIMENSIONS) {
    const detector = DETECTOR_MAP[dimension];
    try {
      const result = detector.detect(context.input);
      if (result.score > 0 || result.matchedPatterns.length > 0) {
        results.push(result);
      }
    } catch {
      // Detector error: return zero detection for this dimension
      results.push({
        dimension,
        score: 0,
        confidence: 'low',
        matchedPatterns: [],
        shouldBlock: false,
      });
    }
  }

  return results;
}

export function getDetectorForDimension(
  dimension: DetectionResult['dimension']
): BaseDetector | undefined {
  return DETECTOR_MAP[dimension];
}

export { EncodingDetector } from './encoding.js';
export { InjectionDetector } from './injection.js';
export { SocialEngineeringDetector } from './social.js';
export { PrivilegeDetector } from './privilege.js';
export { InformationDetector } from './information.js';
export { BaseDetector } from './base.js';
export type { PatternRule } from './base.js';
