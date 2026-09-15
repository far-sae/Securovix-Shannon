// Proves the live defender blocks real attack payloads and never touches benign traffic (no network).
//   node workspaces/defender-verify.mjs
import http from 'node:http';
import { runDefender } from '../defender/agent.mjs';
import { httpProxyConnector } from '../defender/connectors.mjs';

let reached = 0;
const app = http.createServer((_req, res) => {
  reached++;
  res.writeHead(200);
  res.end('app-ok');
});
await new Promise((r) => app.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${app.address().port}`;

const d = await runDefender({
  connect: ({ onEvent }) => httpProxyConnector({ origin, onEvent }),
  mode: 'enforce',
});

const ATTACKS = ['/?q={{7*7}}', '/search?q=<script>alert(1)</script>'];
const BENIGN = ['/products?page=2&sort=price', '/api/users/42'];

let pass = 0;
let blocked = 0;
for (const a of ATTACKS) if ((await fetch(d.meta.url + a)).status === 403) blocked++;
if (blocked === ATTACKS.length) pass++, console.log(`PASS  blocked ${blocked}/${ATTACKS.length} attack payloads`);
else console.log(`FAIL  blocked only ${blocked}/${ATTACKS.length}`);

const before = reached;
let ok = 0;
for (const b of BENIGN) if ((await fetch(d.meta.url + b)).status === 200) ok++;
if (ok === BENIGN.length) pass++, console.log(`PASS  forwarded ${ok}/${BENIGN.length} benign requests (no FP)`);
else console.log(`FAIL  forwarded only ${ok}/${BENIGN.length}`);

if (reached - before === BENIGN.length) pass++, console.log('PASS  only benign traffic reached the app');
else console.log('FAIL  attack traffic leaked to the app');

d.setMode('monitor');
if ((await fetch(`${d.meta.url}/?q={{7*7}}`)).status === 200) pass++, console.log('PASS  monitor mode observes without blocking');
else console.log('FAIL  monitor mode blocked traffic');

if (d.stats().defenses >= ATTACKS.length) pass++, console.log(`PASS  recorded ${d.stats().defenses} defenses on the blackboard`);
else console.log('FAIL  defenses not recorded');

console.log(`\n${pass}/5 checks passed`);
await d.stop();
await new Promise((r) => app.close(r));
// Let libuv finish tearing down the fetch keep-alive sockets before the hard exit below —
// without this, Node on Windows can hit a libuv assertion (UV_HANDLE_CLOSING) mid-teardown.
await new Promise((r) => setTimeout(r, 50));
process.exit(pass === 5 ? 0 : 1);
