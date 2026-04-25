/**
 * Tests for the scoring module — normalization and verdict mapping.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeScore, getVerdict } from '../src/scoring.js';
import type { ScannerResult } from '../src/types.js';

function scanner(score: number, maxScore: number): ScannerResult {
  return { name: 'Test', score, maxScore, issues: [] };
}

test('all scanners perfect → 100', () => {
  const result = normalizeScore([
    scanner(20, 20),
    scanner(25, 25),
    scanner(30, 30),
    scanner(15, 15),
  ]);
  assert.equal(result, 100);
});

test('all scanners failed → 0', () => {
  const result = normalizeScore([
    scanner(0, 20),
    scanner(0, 25),
    scanner(0, 30),
    scanner(0, 15),
  ]);
  assert.equal(result, 0);
});

test('half score → 50', () => {
  const result = normalizeScore([scanner(10, 20)]);
  assert.equal(result, 50);
});

test('rounds correctly', () => {
  // 73/100 → 73
  const result = normalizeScore([scanner(73, 100)]);
  assert.equal(result, 73);
});

test('--only headers → rawMax is only headers.maxScore', () => {
  const result = normalizeScore([scanner(20, 25)]);
  assert.equal(result, 80);
});

test('empty scanners → 100', () => {
  const result = normalizeScore([]);
  assert.equal(result, 100);
});

test('getVerdict: 100 → Excellent', () => assert.equal(getVerdict(100), 'Excellent'));
test('getVerdict: 90 → Excellent',  () => assert.equal(getVerdict(90),  'Excellent'));
test('getVerdict: 89 → Needs work', () => assert.equal(getVerdict(89),  'Needs work'));
test('getVerdict: 70 → Needs work', () => assert.equal(getVerdict(70),  'Needs work'));
test('getVerdict: 69 → At risk',    () => assert.equal(getVerdict(69),  'At risk'));
test('getVerdict: 50 → At risk',    () => assert.equal(getVerdict(50),  'At risk'));
test('getVerdict: 49 → Critical',   () => assert.equal(getVerdict(49),  'Critical'));
test('getVerdict: 0 → Critical',    () => assert.equal(getVerdict(0),   'Critical'));
