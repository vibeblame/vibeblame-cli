/**
 * SEO scanner — checks HTML for title, meta description, h1, Open Graph tags,
 * canonical link, robots.txt, and llms.txt. maxScore: 15
 */

import * as cheerio from 'cheerio';
import type { Issue, ScannerResult } from '../types.js';

const MAX_SCORE = 15;

/**
 * Analyzes a parsed HTML document for SEO issues. Pure function — no network calls.
 *
 * Checks (with score penalties):
 *   - <title>: missing → HIGH (-4); length outside 30–60 chars → INFO (-1)
 *   - <meta name="description">: missing → HIGH (-3); length outside 120–160 → INFO (-1)
 *   - <h1>: missing → MEDIUM (-2); more than one → MEDIUM (-2)
 *   - og:title / og:description / og:image: each missing → MEDIUM (-1)
 *   - <link rel="canonical">: missing → INFO (-1)
 *   - robots.txt: not found → INFO (-1)
 *   - llms.txt: not found → INFO (-1)
 *
 * @param $          - Cheerio instance loaded with the page HTML
 * @param hasRobots  - Whether GET /robots.txt returned 2xx
 * @param hasLlmsTxt - Whether GET /llms.txt returned 2xx
 * @returns ScannerResult with name "SEO", score (0–15), maxScore 15, and issues list
 */
export function analyzeSEO(
  $: cheerio.CheerioAPI,
  hasRobots: boolean,
  hasLlmsTxt: boolean
): ScannerResult {
  const issues: Issue[] = [];
  let score = MAX_SCORE;

  // <title>
  const title = $('title').first().text().trim();
  if (!title) {
    issues.push({
      id: 'seo.title.missing',
      severity: 'HIGH',
      title: '<title> tag missing',
      detail: 'Page has no <title> tag',
    });
    score -= 4;
  } else if (title.length < 30 || title.length > 60) {
    issues.push({
      id: 'seo.title.length',
      severity: 'INFO',
      title: '<title> length not optimal',
      detail: `Title is ${title.length} chars (recommended: 30–60)`,
    });
    score -= 1;
  }

  // <meta name="description">
  const desc = $('meta[name="description"]').attr('content')?.trim() ?? '';
  if (!desc) {
    issues.push({
      id: 'seo.meta_description.missing',
      severity: 'HIGH',
      title: '<meta name="description"> missing',
      detail: 'Page has no meta description',
    });
    score -= 3;
  } else if (desc.length < 120 || desc.length > 160) {
    issues.push({
      id: 'seo.meta_description.length',
      severity: 'INFO',
      title: 'Meta description length not optimal',
      detail: `Description is ${desc.length} chars (recommended: 120–160)`,
    });
    score -= 1;
  }

  // <h1>
  const h1Count = $('h1').length;
  if (h1Count === 0) {
    issues.push({
      id: 'seo.h1.missing',
      severity: 'MEDIUM',
      title: '<h1> tag missing',
      detail: 'Page has no <h1> heading',
    });
    score -= 2;
  } else if (h1Count > 1) {
    issues.push({
      id: 'seo.h1.multiple',
      severity: 'MEDIUM',
      title: 'Multiple <h1> tags found',
      detail: `Found ${h1Count} <h1> tags — only one is recommended`,
    });
    score -= 2;
  }

  // Open Graph
  const ogTitle = $('meta[property="og:title"]').attr('content');
  const ogDesc = $('meta[property="og:description"]').attr('content');
  const ogImage = $('meta[property="og:image"]').attr('content');

  if (!ogTitle) {
    issues.push({
      id: 'seo.og.title_missing',
      severity: 'MEDIUM',
      title: 'og:title missing',
      detail: 'Open Graph title not set',
    });
    score -= 1;
  }
  if (!ogDesc) {
    issues.push({
      id: 'seo.og.description_missing',
      severity: 'MEDIUM',
      title: 'og:description missing',
      detail: 'Open Graph description not set',
    });
    score -= 1;
  }
  if (!ogImage) {
    issues.push({
      id: 'seo.og.image_missing',
      severity: 'MEDIUM',
      title: 'og:image missing',
      detail: 'Open Graph image not set — link previews will lack thumbnails',
    });
    score -= 1;
  }

  // Canonical
  if (!$('link[rel="canonical"]').attr('href')) {
    issues.push({
      id: 'seo.canonical.missing',
      severity: 'INFO',
      title: '<link rel="canonical"> missing',
      detail: 'Without canonical URL, duplicate content issues may arise',
    });
    score -= 1;
  }

  // robots.txt
  if (!hasRobots) {
    issues.push({
      id: 'seo.robots.missing',
      severity: 'INFO',
      title: 'robots.txt not found',
      detail: 'GET /robots.txt returned 404',
    });
    score -= 1;
  }

  // llms.txt
  if (!hasLlmsTxt) {
    issues.push({
      id: 'seo.llmstxt.missing',
      severity: 'INFO',
      title: 'llms.txt not found',
      detail: 'GET /llms.txt returned 404 — helps AI crawlers understand your site',
    });
    score -= 1;
  }

  return {
    name: 'SEO',
    score: Math.max(0, score),
    maxScore: MAX_SCORE,
    issues,
  };
}

/**
 * HEAD-requests a URL to check if it returns a 2xx response.
 *
 * @param url - Absolute URL to check (e.g. "https://example.com/robots.txt")
 * @returns true if response is 2xx, false on any error or non-2xx status
 */
async function exists(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      signal: AbortSignal.timeout(5_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Full SEO scan: fetches page HTML and checks /robots.txt + /llms.txt in parallel,
 * then delegates analysis to analyzeSEO().
 *
 * @param url  - Full URL of the page to scan (e.g. "https://example.com")
 * @param html - Optional pre-fetched HTML string; if provided, skips the page fetch
 * @returns ScannerResult with name "SEO", score (0–15), maxScore 15, and issues list.
 *          Returns score 0 with a CRITICAL issue if the page HTML cannot be fetched.
 */
export async function scanSEO(url: string, html?: string): Promise<ScannerResult> {
  const base = new URL(url);
  const origin = base.origin;

  const [pageHtml, hasRobots, hasLlmsTxt] = await Promise.all([
    html ? Promise.resolve(html) : fetch(url, { signal: AbortSignal.timeout(15_000) })
        .then(r => r.text())
        .catch(() => null),
    exists(`${origin}/robots.txt`),
    exists(`${origin}/llms.txt`),
  ]);

  if (!pageHtml) {
    return {
      name: 'SEO',
      score: 0,
      maxScore: MAX_SCORE,
      issues: [
        {
          id: 'seo.fetch.failed',
          severity: 'CRITICAL',
          title: 'Failed to fetch page HTML',
          detail: url,
        },
      ],
    };
  }

  const $ = cheerio.load(pageHtml);
  return analyzeSEO($, hasRobots, hasLlmsTxt);
}
