/**
 * Secrets & Source Maps scanner — downloads page HTML, fetches all
 * linked JS bundles, checks for exposed source maps and leaked secrets.
 * maxScore: 30
 */

import * as cheerio from 'cheerio';
import type { Issue, ScannerResult } from '../types.js';

const MAX_SCORE = 30;

/** Max JS bundle size to scan (10 MB) — large bundles skipped to avoid OOM */
const MAX_JS_BYTES = 10 * 1024 * 1024;

interface SecretPattern {
  id: string;
  severity: Issue['severity'];
  title: string;
  /** Regex to match against JS content */
  pattern: RegExp;
}

/**
 * Patterns ordered by severity. Each has a comment explaining source.
 * Sources: GitHub secret scanning patterns, OWASP, common SaaS key formats.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'secrets.stripe_key',
    severity: 'CRITICAL',
    title: 'Stripe live secret key exposed',
    /** Stripe live secret keys start with sk_live_ followed by alphanumeric */
    pattern: /sk_live_[a-zA-Z0-9]{20,}/g,
  },
  {
    id: 'secrets.google_api_key',
    severity: 'CRITICAL',
    title: 'Google API key exposed',
    /** Google API keys: AIza prefix + 35 base64url chars */
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
  },
  {
    id: 'secrets.github_token',
    severity: 'CRITICAL',
    title: 'GitHub personal access token exposed',
    /** GitHub PATs: ghp_ prefix + 36 alphanumeric chars */
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
  },
  {
    id: 'secrets.slack_token',
    severity: 'CRITICAL',
    title: 'Slack bot token exposed',
    /** Slack bot tokens: xoxb- prefix + numeric ID + alphanumeric secret */
    pattern: /xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+/g,
  },
  {
    id: 'secrets.next_public_env',
    severity: 'HIGH',
    title: 'Next.js public env variable with long value',
    /** NEXT_PUBLIC_ vars with 10+ char values often contain API keys */
    pattern: /NEXT_PUBLIC_[A-Z_]+=["'][^"']{10,}["']/g,
  },
];

/**
 * Scans a JS string against all SECRET_PATTERNS. Deduplicates by pattern id
 * so the same key type is reported at most once per file.
 *
 * @param js       - Raw JS source code to scan
 * @param filename - Filename shown in issue detail (e.g. "main.abc123.js")
 * @returns Array of Issue objects, one per matched pattern type. Empty if nothing found.
 */
export function scanJSContent(js: string, filename: string): Issue[] {
  const issues: Issue[] = [];
  const seen = new Set<string>();

  for (const { id, severity, title, pattern } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(js);
    if (match && !seen.has(id)) {
      seen.add(id);
      issues.push({
        id,
        severity,
        title,
        detail: `Found in ${filename}: ${match[0].slice(0, 40)}…`,
      });
    }
  }

  return issues;
}

/**
 * Fetches a URL as text with a 10s timeout and a 10 MB size guard.
 *
 * @param url - URL to fetch
 * @returns Response body as string, or null if fetch fails, returns non-2xx, or body exceeds 10 MB
 */
async function fetchText(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return null;
    const contentLength = res.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_JS_BYTES) return null;
    const text = await res.text();
    if (text.length > MAX_JS_BYTES) return null;
    return text;
  } catch {
    return null;
  }
}

/**
 * Resolves a script src attribute (possibly relative) against the page's base URL.
 *
 * @param base - Absolute URL of the page (used as base for resolution)
 * @param src  - Value of the script's src attribute (absolute or relative)
 * @returns Resolved absolute URL string, or null if resolution fails
 */
function resolveUrl(base: string, src: string): string | null {
  try {
    return new URL(src, base).href;
  } catch {
    return null;
  }
}

/**
 * Full secrets scan: fetches page HTML, collects all <script src="..."> URLs,
 * then for each JS bundle in parallel:
 *   1. Checks if {bundle}.map returns 200 (exposed source map) → CRITICAL (-10)
 *   2. Checks for //# sourceMappingURL= comment inside JS → HIGH (-5)
 *   3. Runs scanJSContent() for leaked secrets → CRITICAL (-10) or HIGH (-5) per match
 *
 * @param url - Full URL of the page to scan (e.g. "https://example.com")
 * @returns ScannerResult with name "Secrets & Source Maps", score (0–30), maxScore 30, and issues list.
 *          Returns score 0 with a CRITICAL issue if the page HTML cannot be fetched.
 */
export async function scanSecrets(url: string): Promise<ScannerResult> {
  const issues: Issue[] = [];
  let score = MAX_SCORE;

  const html = await fetchText(url);
  if (!html) {
    return {
      name: 'Secrets & Source Maps',
      score: 0,
      maxScore: MAX_SCORE,
      issues: [
        {
          id: 'secrets.fetch.failed',
          severity: 'CRITICAL',
          title: 'Failed to fetch page HTML',
          detail: url,
        },
      ],
    };
  }

  const $ = cheerio.load(html);
  const scriptSrcs: string[] = [];

  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (!src) return;
    const resolved = resolveUrl(url, src);
    if (resolved) scriptSrcs.push(resolved);
  });

  const seenMapIssue = new Set<string>();

  await Promise.all(
    scriptSrcs.map(async (scriptUrl) => {
      const filename = new URL(scriptUrl).pathname.split('/').pop() ?? scriptUrl;
      const js = await fetchText(scriptUrl);
      if (!js) return;

      // Check for exposed source map file
      const mapUrl = scriptUrl + '.map';
      try {
        const mapRes = await fetch(mapUrl, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5_000),
        });
        if (mapRes.ok && !seenMapIssue.has(mapUrl)) {
          seenMapIssue.add(mapUrl);
          issues.push({
            id: 'secrets.sourcemap.exposed',
            severity: 'CRITICAL',
            title: 'Source map file publicly accessible',
            detail: `Source map exposed: ${filename}.map`,
          });
          score -= 10;
        }
      } catch {
        // map fetch failed — not exposed
      }

      // Check SourceMappingURL comment inside JS
      if (/\/\/# sourceMappingURL=/.test(js) && !seenMapIssue.has(scriptUrl + '#comment')) {
        seenMapIssue.add(scriptUrl + '#comment');
        issues.push({
          id: 'secrets.sourcemap.comment',
          severity: 'HIGH',
          title: 'SourceMappingURL comment found in JS',
          detail: `JS bundle references a source map: ${filename}`,
        });
        score -= 5;
      }

      // Scan for secrets
      const secretIssues = scanJSContent(js, filename);
      for (const issue of secretIssues) {
        issues.push(issue);
        score -= issue.severity === 'CRITICAL' ? 10 : 5;
      }
    })
  );

  return {
    name: 'Secrets & Source Maps',
    score: Math.max(0, score),
    maxScore: MAX_SCORE,
    issues,
  };
}
