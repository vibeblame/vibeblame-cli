#!/usr/bin/env node
/**
 * CLI entrypoint — parses arguments, runs scan, outputs result.
 * Usage: npx vibeblame <url> [--json] [--prompt] [--only tls,headers,secrets,seo]
 */

import { parseArgs } from 'node:util';
import { runScan } from './runner.js';
import { renderProgress, printPretty, printJSON, printPrompt } from './output.js';
import type { ScannerName } from './types.js';

const ALL_SCANNERS: ScannerName[] = ['tls', 'headers', 'secrets', 'seo'];

function usage(): never {
  process.stderr.write(
    'Usage: vibeblame <url> [--json] [--prompt] [--only tls,headers,secrets,seo]\n'
  );
  process.exit(1);
}

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    json:   { type: 'boolean', default: false },
    prompt: { type: 'boolean', default: false },
    only:   { type: 'string' },
    help:   { type: 'boolean', default: false, short: 'h' },
  },
});

if (values.help) {
  process.stderr.write(
    'vibeblame — security & SEO scanner for web apps\n\n' +
    'Usage:\n' +
    '  vibeblame <url>                    Scan with all checks\n' +
    '  vibeblame <url> --json             Output raw JSON\n' +
    '  vibeblame <url> --prompt           Generate AI fix prompt (pipe-friendly)\n' +
    '  vibeblame <url> --prompt | pbcopy  Copy prompt to clipboard\n' +
    '  vibeblame <url> --only headers,seo Run specific scanners\n\n' +
    'Scanners: tls, headers, secrets, seo\n'
  );
  process.exit(0);
}

const url = positionals[0];
if (!url) usage();

try {
  new URL(url);
} catch {
  process.stderr.write(`Error: invalid URL "${url}"\n`);
  process.exit(1);
}

let scanners: ScannerName[];
if (values.only) {
  const requested = values.only.split(',').map(s => s.trim().toLowerCase());
  const invalid = requested.filter(s => !ALL_SCANNERS.includes(s as ScannerName));
  if (invalid.length > 0) {
    process.stderr.write(`Error: unknown scanner(s): ${invalid.join(', ')}\n`);
    process.stderr.write(`Available: ${ALL_SCANNERS.join(', ')}\n`);
    process.exit(1);
  }
  scanners = requested as ScannerName[];
} else {
  scanners = ALL_SCANNERS;
}

const isJson   = values.json   === true;
const isPrompt = values.prompt === true;
const isSilent = isJson || isPrompt;

if (!isSilent) {
  process.stderr.write(`\nvibeblame ${url}\n\n`);
}

try {
  const result = await runScan(url, scanners, isSilent ? undefined : renderProgress);

  if (isJson) {
    printJSON(result);
  } else if (isPrompt) {
    printPrompt(result);
  } else {
    printPretty(result);
  }
} catch (err) {
  process.stderr.write(
    `Fatal error: ${err instanceof Error ? err.message : String(err)}\n`
  );
  process.exit(1);
}
