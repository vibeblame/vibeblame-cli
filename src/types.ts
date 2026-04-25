/**
 * Shared TypeScript interfaces for vibeblame-cli.
 * All scanners and the runner use these types.
 */

export interface Issue {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  title: string;
  detail: string;
}

export interface ScannerResult {
  name: string;
  score: number;
  maxScore: number;
  issues: Issue[];
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  score: number;
  scanners: ScannerResult[];
  durationMs: number;
  stack?: string;
}

export type ScannerName = 'tls' | 'headers' | 'secrets' | 'seo';
