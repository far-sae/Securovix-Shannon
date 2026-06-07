import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseForms } from './crawler.mjs';

test('parseForms extracts action, method, params, and CSRF token', () => {
  const html = '<form action="/c" method="POST"><input name="c"><input name="csrf_token" value="t1"></form>';
  const forms = parseForms(html, 'http://h/');
  assert.equal(forms.length, 1);
  assert.equal(forms[0].url, 'http://h/c');
  assert.equal(forms[0].method, 'post');
  assert.deepEqual(forms[0].params, ['c', 'csrf_token']);
  assert.equal(forms[0].csrf.value, 't1');
});

test('parseForms defaults method to get and resolves relative action', () => {
  const forms = parseForms('<form action="search"><input name="q"></form>', 'http://h/app/');
  assert.equal(forms[0].method, 'get');
  assert.equal(forms[0].url, 'http://h/app/search');
  assert.deepEqual(forms[0].params, ['q']);
});

test('parseForms handles multiple forms', () => {
  const html = '<form action="/a"><input name="x"></form><form action="/b" method="post"><input name="y"></form>';
  assert.equal(parseForms(html, 'http://h/').length, 2);
});
