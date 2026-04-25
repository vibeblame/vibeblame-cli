/**
 * Scoring module — normalizes raw scanner scores to a 0-100 scale
 * and maps the final score to a human-readable verdict.
 */

import type { ScannerResult } from './types.js';

/**
 * Normalizes an array of scanner results into a 0–100 score.
 * Formula: Math.round(sum(scores) / sum(maxScores) * 100)
 *
 * @param scanners - Array of ScannerResult objects (subset when --only is used)
 * @returns Integer 0–100. Returns 100 if the array is empty (no scanners ran).
 */
export function normalizeScore(scanners: ScannerResult[]): number {
  const totalRaw = scanners.reduce((sum, s) => sum + s.score, 0);
  const totalMax = scanners.reduce((sum, s) => sum + s.maxScore, 0);
  if (totalMax === 0) return 100;
  return Math.round((totalRaw / totalMax) * 100);
}

export type Verdict = 'Excellent' | 'Needs work' | 'At risk' | 'Critical';

/**
 * Maps a normalized 0–100 score to a verdict label.
 *
 * @param score - Normalized score from normalizeScore()
 * @returns "Excellent" (90–100), "Needs work" (70–89), "At risk" (50–69), "Critical" (0–49)
 */
export function getVerdict(score: number): Verdict {
  if (score >= 90) return 'Excellent';
  if (score >= 70) return 'Needs work';
  if (score >= 50) return 'At risk';
  return 'Critical';
}
