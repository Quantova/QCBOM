// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

const OPTS = { network: 'testnet', requireAnchor: false, strict: false };

function records() {
  const key = Q.generateKey();
  const open = Q.open({ key, system: 'api.gov.example', scope: 'all TLS endpoints of the public API' });
  const asset = Q.asset({ key, inventory: open, assetId: 'tls-api-01', assetType: 'certificate', algorithm: 'RSA-2048', usage: 'TLS for the public API', quantumVulnerable: true });
  return { key, open, asset };
}

test('replay as another record type is refused', async () => {
  const { open } = records();
  const forged = JSON.parse(JSON.stringify(open));
  forged.type = 'asset';
  const r = await Q.verify(forged, Object.assign({ type: 'asset' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('replay onto another inventory id is refused', async () => {
  const { open } = records();
  const forged = JSON.parse(JSON.stringify(open));
  forged.statement.inventoryId = 'f'.repeat(32);
  const r = await Q.verify(forged, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('every signed field is bound, a change to any of them breaks the signature', async () => {
  const { asset } = records();
  const flipHex = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);
  const mutations = [
    (s) => { s.inventoryId = flipHex(s.inventoryId); },
    (s) => { s.openRef = flipHex(s.openRef); },
    (s) => { s.assetId = 'tls-api-02'; },
    (s) => { s.assetType = 'key'; },
    (s) => { s.algorithm = 'AES-128'; },
    (s) => { s.usage = 'other use'; },
    (s) => { s.quantumVulnerable = false; },
    (s) => { s.authorityKeyId = flipHex(s.authorityKeyId); },
    (s) => { s.recordedAt = '2000-01-01T00:00:00.000Z'; },
    (s) => { s.note = 'added'; },
  ];
  for (const mutate of mutations) {
    const forged = JSON.parse(JSON.stringify(asset));
    mutate(forged.statement);
    const r = await Q.verify(forged, Object.assign({ type: 'asset' }, OPTS));
    assert.strictEqual(r.status, 'invalid', JSON.stringify(forged.statement));
  }
});

test('a signature from a key other than the named signer does not verify', async () => {
  const a = records();
  const b = records();
  const forged = JSON.parse(JSON.stringify(a.open));
  forged.signer = b.open.signer;
  const r = await Q.verify(forged, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
});

test('a non canonical base64 public key or signature is rejected at parse', async () => {
  const { open } = records();
  const forged = JSON.parse(JSON.stringify(open));
  forged.signer.publicKey = forged.signer.publicKey.slice(0, -2) + '==';
  const r = await Q.verify(forged, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const bad = JSON.parse(JSON.stringify(open));
  bad.signature = bad.signature.slice(0, -4) + 'AAAA';
  const r2 = await Q.verify(bad, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('an envelope with an unexpected field is refused', async () => {
  const { open } = records();
  const forged = JSON.parse(JSON.stringify(open));
  forged.extra = 1;
  const r = await Q.verify(forged, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  const withStatementExtra = JSON.parse(JSON.stringify(open));
  withStatementExtra.statement.extra = 1;
  const r2 = await Q.verify(withStatementExtra, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r2.status, 'invalid');
});

test('a statement carrying a prototype polluting key is refused', async () => {
  const { open } = records();
  const forged = JSON.parse(JSON.stringify(open));
  forged.statement = JSON.parse('{"__proto__":{"polluted":true},"inventoryId":"' + open.statement.inventoryId + '"}');
  const r = await Q.verify(forged, Object.assign({ type: 'open' }, OPTS));
  assert.strictEqual(r.status, 'invalid');
  assert.strictEqual({}.polluted, undefined);
});

test('a signing key is never serialised by the SDK', () => {
  const key = Q.generateKey();
  assert.strictEqual(JSON.stringify({ key }), '{"key":"SecretKey [hidden]"}');
  assert.strictEqual(String(key), 'SecretKey [hidden]');
  assert.strictEqual(require('util').inspect(key), 'SecretKey [hidden]');
});

test('an anchor recorded under another record kind is not accepted', async () => {
  const { open } = records();
  const anchored = JSON.parse(JSON.stringify(open));
  anchored.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  const r = await Q.verify(anchored, Object.assign({ type: 'open', requireAnchor: true }, { network: 'testnet', strict: false }));
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => /anchor/.test(c.name) && !c.ok));
});
