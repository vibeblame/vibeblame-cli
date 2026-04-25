/**
 * Tests for the TLS scanner's pure analyzeTLS() function.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeTLS } from '../../src/scanners/tls.js';
import type { TLSInfo } from '../../src/scanners/tls.js';

const FUTURE = new Date(Date.now() + 90 * 86_400_000).toUTCString();
const PAST   = new Date(Date.now() - 1  * 86_400_000).toUTCString();
const SOON   = new Date(Date.now() + 7  * 86_400_000).toUTCString();

const GOOD_INFO: TLSInfo = {
  protocol: 'TLSv1.3',
  valid: true,
  validFrom: new Date(Date.now() - 30 * 86_400_000).toUTCString(),
  validTo: FUTURE,
  subject: { CN: 'example.com' },
  issuer: { CN: "Let's Encrypt R3", O: "Let's Encrypt" },
  subjectAltName: 'DNS:example.com, DNS:www.example.com',
};

test('good TLS 1.3 cert → score == maxScore, no issues', () => {
  const result = analyzeTLS(GOOD_INFO, 'example.com');
  assert.equal(result.score, result.maxScore);
  assert.equal(result.issues.length, 0);
});

test('TLS 1.1 → CRITICAL issue, score -= 10', () => {
  const info = { ...GOOD_INFO, protocol: 'TLSv1.1' };
  const result = analyzeTLS(info, 'example.com');
  const issue = result.issues.find(i => i.id === 'tls.version.outdated');
  assert.ok(issue);
  assert.equal(issue!.severity, 'CRITICAL');
  assert.equal(result.score, result.maxScore - 10);
});

test('TLS 1.0 → CRITICAL issue', () => {
  const info = { ...GOOD_INFO, protocol: 'TLSv1' };
  const result = analyzeTLS(info, 'example.com');
  assert.ok(result.issues.find(i => i.id === 'tls.version.outdated'));
});

test('TLS 1.2 → no version issue', () => {
  const info = { ...GOOD_INFO, protocol: 'TLSv1.2' };
  const result = analyzeTLS(info, 'example.com');
  assert.ok(!result.issues.find(i => i.id === 'tls.version.outdated'));
});

test('expired certificate → CRITICAL issue, score -= 10', () => {
  const info = { ...GOOD_INFO, validTo: PAST };
  const result = analyzeTLS(info, 'example.com');
  const issue = result.issues.find(i => i.id === 'tls.cert.expired');
  assert.ok(issue);
  assert.equal(issue!.severity, 'CRITICAL');
  assert.equal(result.score, result.maxScore - 10);
});

test('cert expiring in 7 days → HIGH issue, score -= 5', () => {
  const info = { ...GOOD_INFO, validTo: SOON };
  const result = analyzeTLS(info, 'example.com');
  const issue = result.issues.find(i => i.id === 'tls.cert.expiring');
  assert.ok(issue);
  assert.equal(issue!.severity, 'HIGH');
  assert.equal(result.score, result.maxScore - 5);
});

test('self-signed cert → HIGH issue, score -= 8', () => {
  const info = { ...GOOD_INFO, issuer: { CN: 'example.com' } };
  const result = analyzeTLS(info, 'example.com');
  const issue = result.issues.find(i => i.id === 'tls.cert.self_signed');
  assert.ok(issue);
  assert.equal(issue!.severity, 'HIGH');
  assert.equal(result.score, result.maxScore - 8);
});

test('domain mismatch → CRITICAL issue', () => {
  const info: TLSInfo = {
    ...GOOD_INFO,
    subject: { CN: 'other.com' },
    subjectAltName: 'DNS:other.com',
  };
  const result = analyzeTLS(info, 'example.com');
  const issue = result.issues.find(i => i.id === 'tls.cert.domain_mismatch');
  assert.ok(issue);
  assert.equal(issue!.severity, 'CRITICAL');
});

test('wildcard cert matches subdomain', () => {
  const info: TLSInfo = {
    ...GOOD_INFO,
    subject: { CN: '*.example.com' },
    subjectAltName: 'DNS:*.example.com',
  };
  const result = analyzeTLS(info, 'sub.example.com');
  assert.ok(!result.issues.find(i => i.id === 'tls.cert.domain_mismatch'));
});

test('score never below 0', () => {
  const info: TLSInfo = {
    protocol: 'TLSv1',
    valid: false,
    validFrom: PAST,
    validTo: PAST,
    subject: { CN: 'bad.com' },
    issuer: { CN: 'bad.com' },
    subjectAltName: 'DNS:bad.com',
  };
  const result = analyzeTLS(info, 'example.com');
  assert.ok(result.score >= 0);
});
