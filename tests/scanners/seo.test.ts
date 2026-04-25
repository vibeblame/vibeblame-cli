/**
 * Tests for the SEO scanner's pure analyzeSEO() function.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cheerio from 'cheerio';
import { analyzeSEO } from '../../src/scanners/seo.js';

function load(html: string) {
  return cheerio.load(html);
}

const FULL_HTML = `
<html>
<head>
  <title>My Great Site — Home Page for You</title>
  <meta name="description" content="This is a really great site that does amazing things for all kinds of people who love to use the web every day and want to learn more about things.">
  <meta property="og:title" content="My Great Site">
  <meta property="og:description" content="Amazing things">
  <meta property="og:image" content="https://example.com/og.png">
  <link rel="canonical" href="https://example.com/">
</head>
<body><h1>Welcome</h1></body>
</html>
`;

test('perfect HTML with robots + llms → score == maxScore, no issues', () => {
  const result = analyzeSEO(load(FULL_HTML), true, true);
  assert.equal(result.score, result.maxScore);
  assert.equal(result.issues.length, 0);
});

test('missing <title> → HIGH issue', () => {
  const html = FULL_HTML.replace(/<title>.*<\/title>/, '');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.title.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'HIGH');
});

test('title too short (< 30 chars) → INFO issue', () => {
  const html = FULL_HTML.replace(/<title>.*<\/title>/, '<title>Short</title>');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.title.length');
  assert.ok(issue);
  assert.equal(issue!.severity, 'INFO');
});

test('title too long (> 60 chars) → INFO issue', () => {
  const long = 'A'.repeat(61);
  const html = FULL_HTML.replace(/<title>.*<\/title>/, `<title>${long}</title>`);
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.title.length');
  assert.ok(issue);
});

test('missing meta description → HIGH issue', () => {
  const html = FULL_HTML.replace(/<meta name="description"[^>]*>/, '');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.meta_description.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'HIGH');
});

test('missing <h1> → MEDIUM issue', () => {
  const html = FULL_HTML.replace(/<h1>.*<\/h1>/, '');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.h1.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'MEDIUM');
});

test('multiple <h1> tags → MEDIUM issue', () => {
  const html = FULL_HTML.replace('<body><h1>Welcome</h1></body>', '<body><h1>One</h1><h1>Two</h1></body>');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.h1.multiple');
  assert.ok(issue);
  assert.equal(issue!.severity, 'MEDIUM');
});

test('missing og:image → MEDIUM issue', () => {
  const html = FULL_HTML.replace(/<meta property="og:image"[^>]*>/, '');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.og.image_missing');
  assert.ok(issue);
});

test('robots.txt missing → INFO issue', () => {
  const result = analyzeSEO(load(FULL_HTML), false, true);
  const issue = result.issues.find(i => i.id === 'seo.robots.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'INFO');
});

test('llms.txt missing → INFO issue', () => {
  const result = analyzeSEO(load(FULL_HTML), true, false);
  const issue = result.issues.find(i => i.id === 'seo.llmstxt.missing');
  assert.ok(issue);
  assert.equal(issue!.severity, 'INFO');
});

test('canonical missing → INFO issue', () => {
  const html = FULL_HTML.replace(/<link rel="canonical"[^>]*>/, '');
  const result = analyzeSEO(load(html), true, true);
  const issue = result.issues.find(i => i.id === 'seo.canonical.missing');
  assert.ok(issue);
});

test('score never below 0', () => {
  const result = analyzeSEO(load('<html><body></body></html>'), false, false);
  assert.ok(result.score >= 0);
});
