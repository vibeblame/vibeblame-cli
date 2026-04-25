# vibeblame-cli

Security & SEO scanner built for vibe coders. No backend required.

> Part of **[vibeblame.com](https://vibeblame.com)** — the full web app audit platform.

[![npm version](https://img.shields.io/npm/v/vibeblame-cli)](https://www.npmjs.com/package/vibeblame-cli)
[![npm downloads](https://img.shields.io/npm/dm/vibeblame-cli)](https://www.npmjs.com/package/vibeblame-cli)
[![License](https://img.shields.io/badge/license-MIT-green)](#)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](#)
[![CI](https://github.com/vibeblame/vibeblame-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/vibeblame/vibeblame-cli/actions)
[![Docs](https://img.shields.io/badge/docs-vibeblame.github.io-blue)](https://vibeblame.github.io/vibeblame-cli/)

```
$ npx vibeblame https://my-app.vercel.app

Scanning... ████████████████████ 4/4

┌─────────────────────────────────────┐
│  Score: 73/100  (Needs work)        │
└─────────────────────────────────────┘

🔒 TLS/SSL           18 / 20
🛡  Headers           12 / 25
   ● CRITICAL  headers.csp.missing — Content-Security-Policy not set
   ● HIGH      secrets.sourcemap.exposed — sourcemap found: main.js.map
   ● MEDIUM    headers.xframe.missing — X-Frame-Options not set
🔍 Secrets & Maps    28 / 30
📄 SEO               10 / 15

Scanned in 4.2s · vibeblame.com
```

## Install

```bash
# One-off scan — no install needed
npx vibeblame https://example.com

# Global install
npm install -g vibeblame-cli
vibeblame https://example.com
```

## Usage

```bash
vibeblame <url> [options]

Options:
  --json           Output raw JSON to stdout (logs → stderr)
  --only <list>    Comma-separated scanners: tls,headers,secrets,seo
  -h, --help       Show help
```

### Examples

```bash
# Pretty terminal output (default)
npx vibeblame https://example.com

# JSON output for CI / scripting
npx vibeblame https://example.com --json | jq '.score'

# Run only specific scanners
npx vibeblame https://example.com --only headers,seo

# TLS check only
npx vibeblame https://example.com --only tls
```

## What it checks

| Scanner                  | Checks                                                                                        | Max score |
| ------------------------ | --------------------------------------------------------------------------------------------- | --------- |
| 🔒 TLS/SSL               | Protocol version (TLS 1.0/1.1 flagged), cert expiry, self-signed, domain mismatch             | 20        |
| 🛡 Headers               | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy       | 25        |
| 🔍 Secrets & Source Maps | Stripe/GitHub/Google/Slack keys in JS bundles, exposed `.map` files, `NEXT_PUBLIC_*` vars     | 30        |
| 📄 SEO                   | `<title>`, meta description, `<h1>`, Open Graph tags, canonical URL, `robots.txt`, `llms.txt` | 15        |

**Score verdicts:** 90–100 Excellent · 70–89 Needs work · 50–69 At risk · 0–49 Critical

## JSON output

```json
{
  "url": "https://example.com",
  "finalUrl": "https://example.com/",
  "score": 73,
  "scanners": [
    {
      "name": "TLS",
      "score": 18,
      "maxScore": 20,
      "issues": []
    },
    {
      "name": "Headers",
      "score": 12,
      "maxScore": 25,
      "issues": [
        {
          "id": "headers.csp.missing",
          "severity": "HIGH",
          "title": "Content-Security-Policy header not set",
          "detail": "Missing CSP header allows XSS and injection attacks"
        }
      ]
    }
  ],
  "durationMs": 4231
}
```

## Limitations

- The TLS scanner requires direct access to port 443 — it won't work behind a corporate MITM proxy
- JS bundles larger than 10 MB are skipped to avoid out-of-memory errors
- Source map detection only covers `<script src="...">` tags — inline scripts are not scanned
- Redirects are followed, but only the final URL is scanned

## Contributing

```bash
git clone https://github.com/USERNAME/vibeblame-cli
cd vibeblame-cli
npm install
npm test          # build + run 61 tests via node:test
```

## License

MIT
