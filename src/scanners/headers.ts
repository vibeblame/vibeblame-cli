/**
 * Headers scanner — checks HTTP response headers for security best practices.
 * One GET request, pure analysis. maxScore: 25
 */

import type { Issue, ScannerResult } from '../types.js';

const MAX_SCORE = 25;

/**
 * Analyzes a map of HTTP response headers for security issues. Pure function — no network calls.
 *
 * Checks (with score penalties):
 *   - Content-Security-Policy: missing → HIGH (-8); unsafe-inline/unsafe-eval → MEDIUM (-3 each)
 *   - Strict-Transport-Security: missing → HIGH (-6); no includeSubDomains → INFO (-1)
 *   - X-Frame-Options: missing → MEDIUM (-4)
 *   - X-Content-Type-Options: not "nosniff" → MEDIUM (-3)
 *   - Referrer-Policy: missing → INFO (-1)
 *   - Permissions-Policy: missing → INFO (-1)
 *   - X-Powered-By: present → INFO (-1)
 *   - Server with version number (e.g. "nginx/1.18.0") → INFO (-1)
 *
 * @param headers - Lowercase header name → value map (e.g. from res.headers.forEach)
 * @returns ScannerResult with name "Headers", score (0–25), maxScore 25, and issues list
 */
export function analyzeHeaders(headers: Record<string, string>): ScannerResult {
  const issues: Issue[] = [];
  let score = MAX_SCORE;

  const h = (name: string) => headers[name.toLowerCase()];

  // Content-Security-Policy
  const csp = h('content-security-policy');
  if (!csp) {
    issues.push({
      id: 'headers.csp.missing',
      severity: 'HIGH',
      title: 'Content-Security-Policy header not set',
      detail: 'Missing CSP header allows XSS and injection attacks',
    });
    score -= 8;
  } else {
    if (csp.includes("'unsafe-inline'") || csp.includes('"unsafe-inline"')) {
      issues.push({
        id: 'headers.csp.unsafe_inline',
        severity: 'MEDIUM',
        title: "CSP contains 'unsafe-inline'",
        detail: "unsafe-inline in CSP weakens XSS protection",
      });
      score -= 3;
    }
    if (csp.includes("'unsafe-eval'") || csp.includes('"unsafe-eval"')) {
      issues.push({
        id: 'headers.csp.unsafe_eval',
        severity: 'MEDIUM',
        title: "CSP contains 'unsafe-eval'",
        detail: "unsafe-eval in CSP allows arbitrary JS execution",
      });
      score -= 3;
    }
  }

  // Strict-Transport-Security
  const hsts = h('strict-transport-security');
  if (!hsts) {
    issues.push({
      id: 'headers.hsts.missing',
      severity: 'HIGH',
      title: 'Strict-Transport-Security header not set',
      detail: 'Missing HSTS allows downgrade attacks',
    });
    score -= 6;
  } else if (!hsts.includes('includeSubDomains')) {
    issues.push({
      id: 'headers.hsts.no_subdomains',
      severity: 'INFO',
      title: 'HSTS does not include subdomains',
      detail: 'Add includeSubDomains to protect all subdomains',
    });
    score -= 1;
  }

  // X-Frame-Options
  if (!h('x-frame-options')) {
    issues.push({
      id: 'headers.xframe.missing',
      severity: 'MEDIUM',
      title: 'X-Frame-Options not set',
      detail: 'Missing X-Frame-Options allows clickjacking attacks',
    });
    score -= 4;
  }

  // X-Content-Type-Options
  if (h('x-content-type-options') !== 'nosniff') {
    issues.push({
      id: 'headers.xcto.missing',
      severity: 'MEDIUM',
      title: 'X-Content-Type-Options: nosniff not set',
      detail: 'Allows browsers to MIME-sniff responses, enabling attacks',
    });
    score -= 3;
  }

  // Referrer-Policy
  if (!h('referrer-policy')) {
    issues.push({
      id: 'headers.referrer.missing',
      severity: 'INFO',
      title: 'Referrer-Policy not set',
      detail: 'Without Referrer-Policy, full URL may leak to third parties',
    });
    score -= 1;
  }

  // Permissions-Policy
  if (!h('permissions-policy')) {
    issues.push({
      id: 'headers.permissions.missing',
      severity: 'INFO',
      title: 'Permissions-Policy not set',
      detail: 'Without Permissions-Policy, browser features are unrestricted',
    });
    score -= 1;
  }

  // X-Powered-By — information disclosure
  if (h('x-powered-by')) {
    issues.push({
      id: 'headers.xpoweredby.present',
      severity: 'INFO',
      title: 'X-Powered-By header present',
      detail: `Exposes technology stack: ${h('x-powered-by')}`,
    });
    score -= 1;
  }

  // Server with version number (e.g. nginx/1.18.0, Apache/2.4.51)
  const server = h('server');
  if (server && /\/\d/.test(server)) {
    issues.push({
      id: 'headers.server.version',
      severity: 'INFO',
      title: 'Server header exposes version',
      detail: `Server: ${server}`,
    });
    score -= 1;
  }

  return {
    name: 'Headers',
    score: Math.max(0, score),
    maxScore: MAX_SCORE,
    issues,
  };
}

/**
 * Detects the hosting platform and framework from response headers. Pure function.
 *
 * Signals used:
 *   - x-powered-by: "Next.js" → Next.js; "Express" → Express
 *   - server: "nginx" → Nginx; "apache" → Apache
 *   - x-vercel-id → Vercel; x-nf-request-id → Netlify; cf-ray → Cloudflare
 *
 * @param headers - Lowercase header name → value map
 * @returns Human-readable stack string like "Next.js · Vercel", or undefined if nothing detected
 */
export function detectStack(headers: Record<string, string>): string | undefined {
  const h = (name: string) => headers[name.toLowerCase()] ?? '';
  const parts: string[] = [];

  // Framework
  const powered = h('x-powered-by').toLowerCase();
  if (powered.includes('next.js') || powered === 'next.js') parts.push('Next.js');
  else if (powered.includes('express'))                      parts.push('Express');

  // Server
  const server = h('server').toLowerCase();
  if (server.includes('nginx'))       parts.push('Nginx');
  else if (server.includes('apache')) parts.push('Apache');

  // Hosting
  if (h('x-vercel-id'))          parts.push('Vercel');
  else if (h('x-nf-request-id')) parts.push('Netlify');
  else if (h('cf-ray'))          parts.push('Cloudflare');

  return parts.length > 0 ? parts.join(' · ') : undefined;
}

/**
 * Fetches the URL and runs analyzeHeaders() on the response.
 * Follows redirects automatically (fetch default). Lowercases all header names before analysis.
 *
 * @param url - Full URL to fetch (e.g. "https://example.com")
 * @returns ScannerResult. Returns score 0 with a CRITICAL issue if the fetch fails or times out (15s).
 */
export async function scanHeaders(url: string): Promise<ScannerResult> {
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(15_000),
    });

    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    return analyzeHeaders(headers);
  } catch (err) {
    return {
      name: 'Headers',
      score: 0,
      maxScore: MAX_SCORE,
      issues: [
        {
          id: 'headers.fetch.failed',
          severity: 'CRITICAL',
          title: 'Failed to fetch URL',
          detail: err instanceof Error ? err.message : String(err),
        },
      ],
    };
  }
}
