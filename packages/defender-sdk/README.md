# @securovix/defender

Drop-in request inspection for Express/Connect apps, and for runtimes that use the Web Fetch API
(Vercel, Next.js middleware, Cloudflare Workers — see [below](#vercel-nextjs-middleware-cloudflare-workers)).
Detects attacks **inside your app** and optionally blocks them, then reports what it saw to your
Securovix dashboard.

```bash
npm install @securovix/defender
```

```js
import express from 'express';
import { shannonDefender } from '@securovix/defender';

const app = express();
app.use(express.json());          // mount AFTER a body parser so bodies can be inspected
app.use(shannonDefender({
  apiKey: 'sk_...',               // from your dashboard → Defender
  endpoint: 'https://origin.securovix.com',
  assetId: 'dsa_...',             // from Defender asset inventory
  mode: 'monitor',                // 'enforce' to start blocking
}));
```

## Why in-process rather than a proxy

A reverse proxy has to sit in front of your app, which means DNS changes, TLS, and — the part that
matters — **your site goes down when the proxy does.** This runs inside your process instead:

- no DNS change, no TLS to terminate, no port to expose
- **Securovix is not in your uptime path.** If our endpoint is unreachable, your app keeps serving;
  detections are queued and dropped rather than retried into a backlog.
- detection is local and synchronous — regex over URL and body, no network call on the hot path

## What it blocks, and what it only reports

Two tiers, and the split is deliberate.

**Enforced** (can return 403): `path-traversal`, `nosql`, `llm-prompt-injection`, and the strict
forms of `sqli`, `xss`, `cmd-injection`, `rce-ssti`, `ssrf` and `xxe`. These signatures are specific
enough that a match on live traffic is meaningful:

| Class | Blocked | Not blocked |
|---|---|---|
| `sqli` | A quote that breaks out into a tautology (`' OR '1'='1`), a comment (`admin'--`) or a stacked statement; `UNION SELECT` against a column list; timing and catalog probes | `O'Brien`, prose about SQL |
| `xss` | `<script>`, inline event handlers (`onerror=`), `javascript:` calls, embedded HTML documents | `<p>Hello</p>`, ordinary links, `javascript:void(0)` |
| `cmd-injection` | A shell separator followed by a command that reads a system file, fetches a payload, probes identity or timing, or opens a shell (`; cat /etc/…`, `&& curl http://…`, `$(id)`, `/dev/tcp/…`) | `Design & code; also coffee`, `a && b` in code, a bare `&` between query parameters |
| `rce-ssti` | Arithmetic probes (`{{7*7}}`, `${7*7}`), template expressions that reach interpreter internals (`__class__`, `getRuntime(`), the Log4Shell lookup (`${jndi:`) | `{{name}}`, `${price}`, `<%= user.name %>` |
| `ssrf` | Cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`), `gopher://` / `dict://`, `file:///etc/…`, loopback written in hex, decimal or octal | `http://localhost:3000/callback`, `ldap://` directory URLs, ordinary `https://` links |
| `xxe` | An external entity declaration (`<!ENTITY x SYSTEM "…">`) | Internal entities, which design tools write into ordinary SVG files |

**Detected only** (never blocked): the loose forms of the classes above, plus `crlf` and
`graphql-idor`. Against real traffic these match constantly — an apostrophe, any HTML tag, a
semicolon followed by a word, a newline in a textarea. Useful signal; unusable as a blocking rule.

**Honeypot paths** (opt-in with `honeypot: true`): requests for files a Node app never serves but
scanners always ask for — `/.env`, `/.git/config`, `/wp-login.php`, `*.php`, database dumps.
In enforce mode they get a plain 404 and are reported as `honeypot`. Off by default because a site
that genuinely serves one of these paths would trip it.

**Attack tools** (opt-in with `scanners: true`): requests whose `User-Agent` names a scanner or
exploitation tool — sqlmap, nikto, nuclei, wpscan, gobuster, masscan and others. In enforce mode
they get a 403 and are reported as `scanner-tool`. Off by default because your own security team may
run one of these on purpose. Browsers, search engines and HTTP libraries (curl, axios, python-httpx)
never match.

Inspection runs in time proportional to the request size: a megabyte of hostile input is checked in
a fraction of a second, so the defender cannot be used to stall the app it protects.

## Options

| Option | Default | Meaning |
|---|---|---|
| `apiKey` | — | Your key. Omit to run fully locally with no reporting. |
| `mode` | `'monitor'` | `'enforce'` returns 403 on a confirmed attack. |
| `endpoint` | `https://origin.securovix.com` | Where detections and heartbeats are reported. |
| `assetId` | — | Asset inventory ID. When set, the SDK reports live coverage every five minutes. |
| `skip` | `[]` | `RegExp[]` of paths to leave uninspected. |
| `honeypot` | `false` | `true` for the built-in scanner-bait list, or a `RegExp` of your own paths. |
| `scanners` | `false` | `true` for the built-in attack-tool list, or a `RegExp` of your own User-Agent patterns. |
| `onDetection` | — | Called locally for every detection. |
| `maxBody` | 1 MB | Inspect the first N bytes; larger bodies pass unexamined. |

Start in `monitor`. Watch what it *would* have blocked for a few days, then switch to `enforce`.

## Safety properties

- **Monitor by default.** A fresh install never starts dropping your traffic.
- **Fails open.** Any error inside inspection forwards the request. A fault in the defender must
  never take your app down.
- **Never holds the process open.** The reporting timer is `unref`'d.

## API

```js
const defender = shannonDefender({ ... });
app.use(defender);

defender.stats();          // { requests, detections, blocked, reported, dropped, queued, mode }
defender.setMode('enforce');
defender.getMode();
await defender.flush();    // force-send queued detections
await defender.heartbeat();// refresh asset coverage immediately
defender.stop();           // stop the reporting timer
```

## Vercel, Next.js middleware, Cloudflare Workers

`@securovix/defender/web` is the same inspection for runtimes that hand you a Web `Request` instead
of an Express `req`. `createWebDefender(options)` returns an async function: it resolves to a
`Response` when the request must be stopped, or `null` when it should continue.

**Vercel (any framework — Vite, Astro, plain static sites).** Create `middleware.js` in the project
root:

```js
import { createWebDefender, vercelNext } from '@securovix/defender/web';

const defend = createWebDefender({
  apiKey: process.env.SECUROVIX_DEFENDER_KEY, // from your dashboard → Defender; omit to run locally
  mode: 'monitor',                            // 'enforce' to start blocking
  honeypot: true,
  scanners: true,
  ban: { threshold: 5 },                      // refuse an address after 5 confirmed attacks a minute
});

export default async function middleware(request, context) {
  return (await defend(request, context)) ?? vercelNext();
}

// Leave static assets alone: they carry no input and this keeps them on the CDN fast path.
export const config = { matcher: ['/((?!assets/|.*\\.(?:js|css|png|jpg|jpeg|svg|webp|ico|woff2?)$).*)'] };
```

**Next.js.** In `middleware.js`, return `NextResponse.next()` instead of `vercelNext()`.

**Cloudflare Workers.** `const blocked = await defend(request, ctx); if (blocked) return blocked;`
then continue to your own handler.

A copy of the Vercel file is in [`examples/vercel-middleware.js`](examples/vercel-middleware.js).

The web adapter takes the same `mode`, `apiKey`, `endpoint`, `skip`, `honeypot`, `scanners` and
`onDetection` options as the Express middleware, plus:

| Option | Default | Meaning |
|---|---|---|
| `ban` | `null` | `{ threshold, windowMs, ttlMs }` — refuse an address after repeated confirmed attacks. A honeypot or attack-tool hit bans at once. |
| `platform` | detected | `'vercel'`, `'cloudflare'` or `'none'`: which host's client-address header to trust. Vercel overwrites `x-vercel-forwarded-for`, Cloudflare overwrites `cf-connecting-ip`; on any other host a visitor can send these headers themselves, so set `'none'` (bans and rate limits are then off) or supply `getIp`. Cloudflare Workers is detected automatically. |
| `getIp` | platform headers | `(request) => string`. Your own way to read the visitor's address, for hosts other than Vercel and Cloudflare. |
| `maxBody` | 256 KB | Text bodies up to this size are inspected. Larger bodies and uploads are not read. |

Things to know:

- **The ban is per instance.** Serverless platforms run many short-lived instances, each with its
  own memory. The ban slows a scanner down; it is not a shared blocklist.
- **Reports use `context.waitUntil`** when the platform provides it, so reporting never delays the
  response and is not cut off when the instance is frozen.
- **It fails open**, exactly like the Express middleware.

## Skipping your own tooling

If your app has endpoints that legitimately carry attack-shaped payloads (an admin console, a
request replayer, a security tool of your own), exclude them — otherwise you will flag your own
features, and in `enforce` mode break them:

```js
shannonDefender({ skip: [/^\/admin\/replay/, /^\/internal\//] })
```

## Settings from the dashboard

With an `apiKey`, the Fetch adapter (`createWebDefender`) takes its settings from the Securovix
dashboard (**Settings → Website protection**) instead of from code: watch-only or blocking, which
rules are on, pages never to inspect, scanner-bait pages, attack-tool refusal, the repeat-offender
ban and a per-address request limit. A change there reaches the site within a minute
(`policyTtlMs`), with no redeploy. If the dashboard cannot be reached the site keeps the last
settings it received; if it never reached it, the options given in code apply. Pass
`remotePolicy: false` to keep the settings in code.

The settings belong to the organization: every site that carries that organization's key shares
them. The same page offers the adapter as one file to download, for projects that do not install
the package.

## Your own tests

When the Securovix AI Agent (or its scheduled monitor) tests a site that carries this adapter, its
attack-shaped requests are detected like anyone else's. So they are not filed as attacks, each of
those requests carries a signed, short-lived mark in the `x-securovix-test` header, and the adapter
passes the mark on with its report. The dashboard checks the signature and files a run that carries
a valid mark as one "own test" entry, apart from the incidents.

The mark is not a pass. The adapter never reads it: a marked request is inspected, banned and
blocked exactly like an unmarked one. A mark that is made up, out of date, or signed for another
organization or another site is ignored, and the report is an attack.
