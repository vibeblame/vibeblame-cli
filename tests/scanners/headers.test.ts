/**
 * Tests for the headers scanner's pure analyzeHeaders() function.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHeaders } from '../../src/scanners/headers.js';

const ALL_GOOD: Record<string, string> = {
  'content-security-policy': "default-src 'self'",
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
};

test('all headers present → score == maxScore, no issues', () => {
  const result = analyzeHeaders(ALL_GOOD);
  assert.equal(result.score, result.maxScore);
  assert.equal(result.issues.length, 0);
});

test('CSP missing → HIGH issue, score -= 8', () => {
  const headers = { ...ALL_GOOD };
  delete headers['content-security-policy'];
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.csp.missing');
  assert.ok(issue, 'expected headers.csp.missing issue');
  assert.equal(issue!.severity, 'HIGH');
  assert.equal(result.score, result.maxScore - 8);
});

test("CSP with unsafe-inline → MEDIUM issue, score -= 3", () => {
  const headers = { ...ALL_GOOD, 'content-security-policy': "default-src 'self' 'unsafe-inline'" };
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.csp.unsafe_inline');
  assert.ok(issue, 'expected headers.csp.unsafe_inline issue');
  assert.equal(issue!.severity, 'MEDIUM');
  assert.equal(result.score, result.maxScore - 3);
});

test("CSP with unsafe-eval → MEDIUM issue, score -= 3", () => {
  const headers = { ...ALL_GOOD, 'content-security-policy': "default-src 'self' 'unsafe-eval'" };
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.csp.unsafe_eval');
  assert.ok(issue);
  assert.equal(issue!.severity, 'MEDIUM');
});

test('HSTS missing → HIGH issue, score -= 6', () => {
  const headers = { ...ALL_GOOD };
  delete headers['strict-transport-security'];
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.hsts.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'HIGH');
  assert.equal(result.score, result.maxScore - 6);
});

test('HSTS without includeSubDomains → INFO issue, score -= 1', () => {
  const headers = { ...ALL_GOOD, 'strict-transport-security': 'max-age=31536000' };
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.hsts.no_subdomains');
  assert.ok(issue);
  assert.equal(issue!.severity, 'INFO');
  assert.equal(result.score, result.maxScore - 1);
});

test('X-Frame-Options missing → MEDIUM issue, score -= 4', () => {
  const headers = { ...ALL_GOOD };
  delete headers['x-frame-options'];
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.xframe.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'MEDIUM');
  assert.equal(result.score, result.maxScore - 4);
});

test('X-Content-Type-Options missing → MEDIUM issue, score -= 3', () => {
  const headers = { ...ALL_GOOD };
  delete headers['x-content-type-options'];
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.xcto.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'MEDIUM');
  assert.equal(result.score, result.maxScore - 3);
});

test('X-Powered-By present → INFO issue, score -= 1', () => {
  const headers = { ...ALL_GOOD, 'x-powered-by': 'Express' };
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.xpoweredby.present');
  assert.ok(issue);
  assert.equal(issue!.severity, 'INFO');
  assert.equal(result.score, result.maxScore - 1);
});

test('Server with version → INFO issue, score -= 1', () => {
  const headers = { ...ALL_GOOD, 'server': 'nginx/1.18.0' };
  const result = analyzeHeaders(headers);
  const issue = result.issues.find(i => i.id === 'headers.server.version');
  assert.ok(issue);
  assert.equal(issue!.severity, 'INFO');
});

test('Server without version → no server issue', () => {
  const headers = { ...ALL_GOOD, 'server': 'nginx' };
  const result = analyzeHeaders(headers);
  assert.ok(!result.issues.find(i => i.id === 'headers.server.version'));
});

test('multiple missing headers → multiple issues, cumulative score deduction', () => {
  const headers = { ...ALL_GOOD };
  delete headers['content-security-policy']; // -8
  delete headers['x-frame-options'];          // -4
  delete headers['referrer-policy'];          // -1
  const result = analyzeHeaders(headers);
  assert.equal(result.issues.length, 3);
  assert.equal(result.score, result.maxScore - 13);
});

test('score never goes below 0', () => {
  const result = analyzeHeaders({});
  assert.ok(result.score >= 0);
});
