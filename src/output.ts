/**
 * Output module — pretty-print to terminal (default), --json, or --prompt mode.
 * Progress and logs always go to stderr; final output goes to stdout.
 */

import kleur from 'kleur';
import type { ScanResult, Issue } from './types.js';
import { getVerdict } from './scoring.js';

const SCANNER_ICONS: Record<string, string> = {
  TLS: '🔒',
  Headers: '🛡',
  'Secrets & Source Maps': '🔍',
  SEO: '📄',
};

/**
 * Writes a progress bar to stderr. Called after each scanner completes.
 *
 * @param completed - Number of scanners that have finished
 * @param total     - Total number of scanners being run
 */
export function renderProgress(completed: number, total: number): void {
  const filled = Math.floor((completed / total) * 20);
  const empty = 20 - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  process.stderr.write(`\rScanning... ${bar} ${completed}/${total}  `);
  if (completed === total) process.stderr.write('\n');
}

/**
 * Returns a kleur color function for a given severity level.
 *
 * @param severity - Issue severity
 * @returns A kleur color function (e.g. kleur.red().bold)
 */
function severityColor(severity: Issue['severity']): (s: string) => string {
  switch (severity) {
    case 'CRITICAL': return kleur.red().bold;
    case 'HIGH':     return kleur.yellow().bold;
    case 'MEDIUM':   return kleur.yellow;
    case 'INFO':     return kleur.blue;
  }
}

/**
 * Returns a kleur color function based on the normalized score value.
 *
 * @param score - Normalized 0–100 score
 * @returns green (≥90), yellow bold (≥70), yellow (≥50), red bold (<50)
 */
function scoreColor(score: number): (s: string) => string {
  if (score >= 90) return kleur.green().bold;
  if (score >= 70) return kleur.yellow().bold;
  if (score >= 50) return kleur.yellow;
  return kleur.red().bold;
}

/**
 * Prints the full scan result as a formatted terminal report to stdout.
 * Shows a score box (with detected stack if available), per-scanner scores,
 * and all issues. If CRITICAL or HIGH issues are found, appends a --prompt hint.
 *
 * @param result - Completed ScanResult from runScan()
 */
export function printPretty(result: ScanResult): void {
  const verdict = getVerdict(result.score);

  const boxWidth = 37;
  const scoreLine = ` Score: ${result.score}/100 (${verdict}) `;
  const stackLine = result.stack ? ` Stack: ${result.stack} ` : null;
  const innerWidth = Math.max(
    scoreLine.length,
    stackLine ? stackLine.length : 0,
    boxWidth
  );
  const pad = (s: string) => ' '.repeat(Math.max(0, innerWidth - s.length));

  console.log('');
  console.log(kleur.dim('┌' + '─'.repeat(innerWidth) + '┐'));
  console.log(kleur.dim('│') + scoreColor(result.score)(scoreLine) + kleur.dim(pad(scoreLine) + '│'));
  if (stackLine) {
    console.log(kleur.dim('│') + kleur.cyan(stackLine) + kleur.dim(pad(stackLine) + '│'));
  }
  console.log(kleur.dim('└' + '─'.repeat(innerWidth) + '┘'));
  console.log('');

  for (const scanner of result.scanners) {
    const icon = SCANNER_ICONS[scanner.name] ?? '•';
    const scanScore = scanner.score === scanner.maxScore
      ? kleur.green(`${scanner.score} / ${scanner.maxScore}`)
      : kleur.yellow(`${scanner.score} / ${scanner.maxScore}`);

    console.log(`${icon} ${kleur.bold(scanner.name)}  ${scanScore}`);

    for (const issue of scanner.issues) {
      const color = severityColor(issue.severity);
      console.log(color(`  ● ${issue.severity} ${kleur.dim(issue.id)} — ${issue.title}`));
    }
  }

  console.log('');
  console.log(kleur.dim(`Scanned in ${(result.durationMs / 1000).toFixed(1)}s · vibeblame.com`));

  const hasActionable = result.scanners.some(s =>
    s.issues.some(i => i.severity === 'CRITICAL' || i.severity === 'HIGH')
  );
  if (hasActionable) {
    console.log('');
    console.log(kleur.dim('──────────────────────────────────────────'));
    console.log(kleur.cyan('Fix it with AI → ') + kleur.bold(`npx @vibeblame/cli ${result.url} --prompt | pbcopy`));
    console.log(kleur.dim('──────────────────────────────────────────'));
  }
}

/**
 * Serializes the full ScanResult as pretty-printed JSON to stdout.
 * Nothing else is written — all other output must go to stderr.
 *
 * @param result - Completed ScanResult from runScan()
 */
export function printJSON(result: ScanResult): void {
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}

/**
 * Generates a structured AI fix prompt from scan issues and writes it to stdout.
 * Groups issues by severity (CRITICAL → HIGH → MEDIUM). Designed for piping:
 *   vibeblame --prompt | pbcopy
 *   vibeblame --prompt > fix.txt
 * Nothing is written to stderr — the output is clean for piping.
 *
 * @param result - Completed ScanResult from runScan()
 */
export function printPrompt(result: ScanResult): void {
  const bySeverity = (sev: Issue['severity']) =>
    result.scanners.flatMap(s => s.issues.filter(i => i.severity === sev));

  const critical = bySeverity('CRITICAL');
  const high     = bySeverity('HIGH');
  const medium   = bySeverity('MEDIUM');

  const formatIssues = (issues: Issue[]) =>
    issues.map(i => `- ${i.title}\n  ${i.detail}`).join('\n');

  const stack = result.stack ?? 'unknown';

  let prompt = `My web app at ${result.finalUrl} has the following security issues.\n`;
  prompt += `Please provide specific fixes for each one.\n\n`;
  prompt += `Tech stack: ${stack}\n\n`;

  if (critical.length > 0) {
    prompt += `CRITICAL issues (fix immediately):\n${formatIssues(critical)}\n\n`;
  }
  if (high.length > 0) {
    prompt += `HIGH priority:\n${formatIssues(high)}\n\n`;
  }
  if (medium.length > 0) {
    prompt += `MEDIUM priority:\n${formatIssues(medium)}\n\n`;
  }

  prompt += `For each issue provide:\n`;
  prompt += `1. Exact code/config change needed\n`;
  prompt += `2. Where to make the change (file/location)\n`;
  prompt += `3. How to verify the fix\n`;

  process.stdout.write(prompt);
}
