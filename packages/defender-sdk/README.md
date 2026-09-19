# @securovix/defender

Drop-in request inspection for Express/Connect apps. Detects attacks **inside your app** and
optionally blocks them, then reports what it saw to your Securovix dashboard.

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

**Enforced** (can return 403): `path-traversal`, `nosql`, `llm-prompt-injection`. These signatures
are specific enough that a match on live traffic is meaningful.

**Detected only** (never blocked): `sqli`, `xss`, `cmd-injection`, `crlf`, `rce-ssti`,
`graphql-idor`. These come from a scanner, where they only ever had to re-test a payload the scanner
had just sent. Against real traffic they match constantly — `sqli` fires on any apostrophe
(`O'Brien`), `xss` on any HTML tag, `crlf` on any newline in a textarea. Useful signal; unusable as a
blocking rule. They are reported so you can see them, never enforced.

## Options

| Option | Default | Meaning |
|---|---|---|
| `apiKey` | — | Your key. Omit to run fully locally with no reporting. |
| `mode` | `'monitor'` | `'enforce'` returns 403 on a confirmed attack. |
| `endpoint` | `https://origin.securovix.com` | Where detections and heartbeats are reported. |
| `assetId` | â€” | Asset inventory ID. When set, the SDK reports live coverage every five minutes. |
| `skip` | `[]` | `RegExp[]` of paths to leave uninspected. |
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

## Skipping your own tooling

If your app has endpoints that legitimately carry attack-shaped payloads (an admin console, a
request replayer, a security tool of your own), exclude them — otherwise you will flag your own
features, and in `enforce` mode break them:

```js
shannonDefender({ skip: [/^\/admin\/replay/, /^\/internal\//] })
```
