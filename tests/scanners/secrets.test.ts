/**
 * Tests for the secrets scanner's regex patterns via scanJSContent().
 * Note: test secrets are constructed via concatenation to avoid triggering
 * GitHub's push protection on this security-testing codebase.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanJSContent } from '../../src/scanners/secrets.js';

// Constructed at runtime so static secret scanners don't flag this file
const STRIPE_KEY  = 'sk_live_' + 'abcdefghijklmnopqrstuvwxyz123456';
const GOOGLE_KEY  = 'AIza' + 'SyD-9tSrke72I6e0DVCsJMoYqtMpke6HQMQ';
const GITHUB_PAT  = 'ghp_' + 'abcdefghijklmnopqrstuvwxyz1234567890AB';
const SLACK_TOKEN = 'xoxb-' + '123456789-987654321-abcdefghijklmnop';

test('clean JS → no issues', () => {
  const result = scanJSContent('const x = 1; console.log("hello");', 'app.js');
  assert.equal(result.length, 0);
});

test('Stripe live key → CRITICAL issue', () => {
  const js = `const key = "${STRIPE_KEY}";`;
  const result = scanJSContent(js, 'app.js');
  const issue = result.find(i => i.id === 'secrets.stripe_key');
  assert.ok(issue, 'expected secrets.stripe_key');
  assert.equal(issue!.severity, 'CRITICAL');
});

test('Google API key → CRITICAL issue', () => {
  const js = `apiKey: "${GOOGLE_KEY}"`;
  const result = scanJSContent(js, 'bundle.js');
  const issue = result.find(i => i.id === 'secrets.google_api_key');
  assert.ok(issue, 'expected secrets.google_api_key');
  assert.equal(issue!.severity, 'CRITICAL');
});

test('GitHub PAT → CRITICAL issue', () => {
  const js = `token = "${GITHUB_PAT}"`;
  const result = scanJSContent(js, 'bundle.js');
  const issue = result.find(i => i.id === 'secrets.github_token');
  assert.ok(issue, 'expected secrets.github_token');
  assert.equal(issue!.severity, 'CRITICAL');
});

test('Slack bot token → CRITICAL issue', () => {
  const js = `slackToken = "${SLACK_TOKEN}"`;
  const result = scanJSContent(js, 'bundle.js');
  const issue = result.find(i => i.id === 'secrets.slack_token');
  assert.ok(issue, 'expected secrets.slack_token');
  assert.equal(issue!.severity, 'CRITICAL');
});

test('NEXT_PUBLIC env with long value → HIGH issue', () => {
  const js = 'NEXT_PUBLIC_API_KEY="mysupersecretapikey123"';
  const result = scanJSContent(js, 'bundle.js');
  const issue = result.find(i => i.id === 'secrets.next_public_env');
  assert.ok(issue, 'expected secrets.next_public_env');
  assert.equal(issue!.severity, 'HIGH');
});

test('NEXT_PUBLIC env with short value (< 10 chars) → no issue', () => {
  const js = 'NEXT_PUBLIC_FLAG="true"';
  const result = scanJSContent(js, 'bundle.js');
  assert.ok(!result.find(i => i.id === 'secrets.next_public_env'));
});

test('multiple secrets in same file → multiple issues', () => {
  const js = `const stripe = "${STRIPE_KEY}";\nconst gh = "${GITHUB_PAT}";`;
  const result = scanJSContent(js, 'bundle.js');
  assert.equal(result.length, 2);
});

test('same secret pattern found twice → deduplicated to one issue', () => {
  const stripe2 = 'sk_live_' + 'zyxwvutsrqponmlkjihgfedcba98765432';
  const js = `const a = "${STRIPE_KEY}";\nconst b = "${stripe2}";`;
  const result = scanJSContent(js, 'bundle.js');
  const stripeIssues = result.filter(i => i.id === 'secrets.stripe_key');
  assert.equal(stripeIssues.length, 1);
});
