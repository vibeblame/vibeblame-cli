/**
 * TLS scanner — checks protocol version, certificate expiry,
 * self-signed certs, and domain mismatch via tls.connect().
 * maxScore: 20
 */

import tls from 'node:tls';
import type { Issue, ScannerResult } from '../types.js';

const MAX_SCORE = 20;

export interface TLSInfo {
  protocol: string;
  valid: boolean;
  validFrom: string;
  validTo: string;
  subject: { CN?: string };
  issuer: { CN?: string; O?: string };
  subjectAltName?: string;
}

/**
 * Opens a TLS connection to hostname:port and extracts certificate metadata.
 *
 * @param hostname - Hostname to connect to (e.g. "example.com")
 * @param port     - Port to connect to, defaults to 443
 * @returns Resolved TLSInfo with protocol version, cert validity dates, subject/issuer, and SANs.
 *          Rejects with an Error if the connection fails or times out (10s).
 */
export function getTLSInfo(hostname: string, port = 443): Promise<TLSInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(false);
        const protocol = socket.getProtocol() ?? '';
        socket.destroy();
        const cn = (v: string | string[] | undefined) =>
          Array.isArray(v) ? v[0] : v;
        resolve({
          protocol,
          valid: socket.authorized,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          subject: { CN: cn(cert.subject?.CN) },
          issuer: { CN: cn(cert.issuer?.CN), O: cn(cert.issuer?.O) },
          subjectAltName: cert.subjectaltname,
        });
      }
    );
    socket.on('error', reject);
    socket.setTimeout(10_000, () => {
      socket.destroy();
      reject(new Error('TLS connect timeout'));
    });
  });
}

/**
 * Interprets raw TLSInfo into a scored list of issues. Pure function — no network calls.
 *
 * Checks:
 *   - Protocol: TLSv1/TLSv1.1 → CRITICAL (-10)
 *   - Cert expired → CRITICAL (-10); expiring in < 14 days → HIGH (-5)
 *   - Self-signed (issuer.CN === subject.CN, no issuer.O) → HIGH (-8)
 *   - Domain mismatch (cert doesn't cover hostname) → CRITICAL (-10)
 *
 * @param info     - TLS metadata returned by getTLSInfo()
 * @param hostname - The hostname being scanned, used for domain mismatch check
 * @returns ScannerResult with name "TLS", score (0–20), maxScore 20, and issues list
 */
export function analyzeTLS(info: TLSInfo, hostname: string): ScannerResult {
  const issues: Issue[] = [];
  let score = MAX_SCORE;

  // Protocol version check
  if (info.protocol === 'TLSv1' || info.protocol === 'TLSv1.1') {
    issues.push({
      id: 'tls.version.outdated',
      severity: 'CRITICAL',
      title: 'Outdated TLS version',
      detail: `Server uses ${info.protocol} which is deprecated and insecure`,
    });
    score -= 10;
  }

  // Certificate expiry
  const now = Date.now();
  const expiry = new Date(info.validTo).getTime();
  const daysLeft = Math.floor((expiry - now) / 86_400_000);

  if (daysLeft < 0) {
    issues.push({
      id: 'tls.cert.expired',
      severity: 'CRITICAL',
      title: 'Certificate expired',
      detail: `Certificate expired ${Math.abs(daysLeft)} day(s) ago`,
    });
    score -= 10;
  } else if (daysLeft < 14) {
    issues.push({
      id: 'tls.cert.expiring',
      severity: 'HIGH',
      title: 'Certificate expiring soon',
      detail: `Certificate expires in ${daysLeft} day(s)`,
    });
    score -= 5;
  }

  // Self-signed: issuer CN equals subject CN and no known CA org
  const isSelfSigned =
    info.issuer.CN === info.subject.CN && !info.issuer.O;
  if (isSelfSigned) {
    issues.push({
      id: 'tls.cert.self_signed',
      severity: 'HIGH',
      title: 'Self-signed certificate',
      detail: 'Certificate is self-signed and not trusted by browsers',
    });
    score -= 8;
  }

  // Domain mismatch
  const sans = (info.subjectAltName ?? '').toLowerCase();
  const cn = (info.subject.CN ?? '').toLowerCase();
  const host = hostname.toLowerCase();
  const wildcardHost = host.replace(/^[^.]+/, '*');
  const domainMatch =
    sans.includes(`dns:${host}`) ||
    sans.includes(`dns:${wildcardHost}`) ||
    cn === host ||
    cn === wildcardHost;

  if (!domainMatch && (sans || cn)) {
    issues.push({
      id: 'tls.cert.domain_mismatch',
      severity: 'CRITICAL',
      title: 'Certificate domain mismatch',
      detail: `Certificate is not valid for ${hostname}`,
    });
    score -= 10;
  }

  return {
    name: 'TLS',
    score: Math.max(0, score),
    maxScore: MAX_SCORE,
    issues,
  };
}

/**
 * Entry point for TLS scanning. Connects to the URL's host and delegates to analyzeTLS().
 *
 * @param url - Full HTTPS URL to scan (e.g. "https://example.com")
 * @returns ScannerResult. Returns score 0 with a CRITICAL issue if:
 *          - URL is not HTTPS
 *          - TLS connection fails or times out
 */
export async function scanTLS(url: string): Promise<ScannerResult> {
  const hostname = new URL(url).hostname;

  if (!url.startsWith('https://')) {
    return {
      name: 'TLS',
      score: 0,
      maxScore: MAX_SCORE,
      issues: [
        {
          id: 'tls.no_https',
          severity: 'CRITICAL',
          title: 'Not using HTTPS',
          detail: 'URL must use HTTPS for TLS scanning',
        },
      ],
    };
  }

  try {
    const info = await getTLSInfo(hostname);
    return analyzeTLS(info, hostname);
  } catch (err) {
    return {
      name: 'TLS',
      score: 0,
      maxScore: MAX_SCORE,
      issues: [
        {
          id: 'tls.connect.failed',
          severity: 'CRITICAL',
          title: 'TLS connection failed',
          detail: err instanceof Error ? err.message : String(err),
        },
      ],
    };
  }
}
