import assert from 'node:assert/strict';
import { test } from 'node:test';
import { injReq, injectParam, mergeCookies, setParam } from './purple-engine.mjs';

test('injectParam replaces all existing params, adds q when none', () => {
  assert.match(injectParam('http://x/p?a=1&b=2', 'PAY'), /a=PAY&b=PAY/);
  assert.match(injectParam('http://x/p', 'PAY'), /[?&]q=PAY/);
});

test('setParam replaces one param (or adds it)', () => {
  assert.match(setParam('http://x/p?a=1', 'a', 'Z'), /a=Z/);
  assert.match(setParam('http://x/p', 'k', 'v'), /[?&]k=v/);
});

test('injReq: GET string target -> query injection (no method)', () => {
  const r = injReq('http://x/p?a=1', 'PAY');
  assert.equal(r.opts.method, undefined);
  assert.match(r.url, /a=PAY/);
});

test('injReq: POST form target -> body injection', () => {
  const r = injReq({ url: 'http://x/c', method: 'post', params: ['c'] }, 'PAY');
  assert.equal(r.opts.method, 'POST');
  assert.match(r.opts.body, /c=PAY/);
  assert.equal(r.url, 'http://x/c');
});

test('injReq: GET form target -> query injection', () => {
  const r = injReq({ url: 'http://x/s', method: 'get', params: ['q'] }, 'PAY');
  assert.equal(r.opts.method, undefined);
  assert.match(r.url, /q=PAY/);
});

test('mergeCookies merges existing + Set-Cookie headers', () => {
  const h = new Headers();
  h.append('set-cookie', 'a=1; HttpOnly');
  h.append('set-cookie', 'b=2; Path=/');
  const c = mergeCookies('pre=0', h);
  assert.match(c, /pre=0/);
  assert.match(c, /a=1/);
  assert.match(c, /b=2/);
});
