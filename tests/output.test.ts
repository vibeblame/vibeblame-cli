/**
 * Tests for the output module — JSON goes to stdout, progress/logs to stderr.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { printJSON, renderProgress } from '../src/output.js';
import type { ScanResult } from '../src/types.js';

const SAMPLE: ScanResult = {
  url: 'https://example.com',
  finalUrl: 'https://example.com',
  score: 73,
  scanners: [
    { name: 'Headers', score: 12, maxScore: 25, issues: [] },
  ],
  durationMs: 1234,
};

test('printJSON writes valid JSON to stdout', () => {
  const chunks: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  // Intercept stdout
  process.stdout.write = (chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : chunk.toString());
    return true;
  };

  printJSON(SAMPLE);
  process.stdout.write = orig;

  const output = chunks.join('');
  let parsed: unknown;
  assert.doesNotThrow(() => { parsed = JSON.parse(output); });
  assert.equal((parsed as ScanResult).score, 73);
  assert.equal((parsed as ScanResult).url, 'https://example.com');
});

test('renderProgress writes to stderr, not stdout', () => {
  let stdoutCalled = false;
  let stderrCalled = false;

  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);

  process.stdout.write = () => { stdoutCalled = true; return true; };
  process.stderr.write = () => { stderrCalled = true; return true; };

  renderProgress(2, 4);

  process.stdout.write = origOut;
  process.stderr.write = origErr;

  assert.equal(stdoutCalled, false, 'progress must not write to stdout');
  assert.equal(stderrCalled, true,  'progress must write to stderr');
});

test('printJSON output is a single JSON object (not array)', () => {
  const chunks: string[] = [];
  const orig = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === 'string' ? chunk : chunk.toString());
    return true;
  };

  printJSON(SAMPLE);
  process.stdout.write = orig;

  const parsed = JSON.parse(chunks.join(''));
  assert.equal(typeof parsed, 'object');
  assert.ok(!Array.isArray(parsed));
});
