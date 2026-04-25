/**
 * Runner — orchestrates all scanners in parallel, resolves final URL
 * after redirects, and assembles the ScanResult.
 */

import { scanTLS } from './scanners/tls.js';
import { scanHeaders, detectStack } from './scanners/headers.js';
import { scanSecrets } from './scanners/secrets.js';
import { scanSEO } from './scanners/seo.js';
import { normalizeScore } from './scoring.js';
import type { ScanResult, ScannerName } from './types.js';

/**
 * Follows redirects via a HEAD request and collects response headers.
 * Used to get the final URL and detect the hosting stack before running scanners.
 *
 * @param url - Original URL entered by the user
 * @returns finalUrl (after all redirects) and lowercased response headers map.
 *          Falls back to the original URL and empty headers on any error.
 */
async function resolveUrl(url: string): Promise<{ finalUrl: string; headers: Record<string, string> }> {
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(10_000),
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { finalUrl: res.url || url, headers };
  } catch {
    return { finalUrl: url, headers: {} };
  }
}

/**
 * Runs the requested scanners in parallel and assembles the final ScanResult.
 *
 * @param url        - URL to scan (e.g. "https://example.com")
 * @param only       - List of scanner names to run (subset of tls/headers/secrets/seo)
 * @param onProgress - Optional callback fired after each scanner completes,
 *                     receives (completedCount, totalCount)
 * @returns ScanResult with normalized score, per-scanner results, detected stack, and duration
 */
export async function runScan(
  url: string,
  only: ScannerName[],
  onProgress?: (completed: number, total: number) => void
): Promise<ScanResult> {
  const start = Date.now();
  const total = only.length;
  let completed = 0;

  const tick = () => {
    completed++;
    onProgress?.(completed, total);
  };

  const { finalUrl, headers } = await resolveUrl(url);
  const stack = detectStack(headers);

  const tasks = only.map(async (name) => {
    switch (name) {
      case 'tls': {
        const result = await scanTLS(finalUrl);
        tick();
        return result;
      }
      case 'headers': {
        const result = await scanHeaders(finalUrl);
        tick();
        return result;
      }
      case 'secrets': {
        const result = await scanSecrets(finalUrl);
        tick();
        return result;
      }
      case 'seo': {
        const result = await scanSEO(finalUrl);
        tick();
        return result;
      }
    }
  });

  const scanners = await Promise.all(tasks);
  const score = normalizeScore(scanners);

  return {
    url,
    finalUrl,
    score,
    scanners,
    durationMs: Date.now() - start,
    stack,
  };
}
