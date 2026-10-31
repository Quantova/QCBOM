// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function openInventory(key) {
  return Q.open({ key, system: 'api.gov.example', scope: 'all TLS endpoints of the public API', authorityLabel: 'Office of the CIO' });
}

function assetOf(key, inventory) {
  return Q.asset({ key, inventory, assetId: 'tls-api-01', assetType: 'certificate', algorithm: 'RSA-2048', usage: 'TLS for the public API', quantumVulnerable: true });
}

test('an opened inventory is a well formed signed record of the authority', () => {
  const authority = freshKey();
  const env = openInventory(authority);
  assert.strictEqual(env.format, 'qcbom/1');
  assert.strictEqual(env.type, 'open');
  assert.strictEqual(env.algorithm, 'ML-DSA-65');
  assert.strictEqual(env.signer.id, Q.keyId(authority));
  assert.strictEqual(env.statement.authorityKeyId, Q.keyId(authority));
  assert.match(env.statement.inventoryId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(env.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(env.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the asset, assess, remediate and close records chain to the same inventory', () => {
  const authority = freshKey();
  const open = openInventory(authority);
  const asset = assetOf(authority, open);
  const assess = Q.assess({ key: authority, record: asset, posture: 'vulnerable', target: 'ML-DSA-65', dueBy: '2030-12-31T00:00:00.000Z' });
  const remediate = Q.remediate({ key: authority, record: assess, action: 'replaced', newAlgorithm: 'ML-DSA-65' });
  const close = Q.close({ key: authority, record: remediate, summary: 'the asset was migrated to a post quantum algorithm' });
  assert.strictEqual(asset.statement.inventoryId, open.statement.inventoryId);
  assert.strictEqual(asset.statement.openRef, Q.recordRef(open));
  assert.strictEqual(assess.statement.priorRef, Q.recordRef(asset));
  assert.strictEqual(remediate.statement.priorRef, Q.recordRef(assess));
  assert.strictEqual(close.statement.priorRef, Q.recordRef(remediate));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const open = openInventory(key);
  const base = { key, inventory: open, assetId: 'a1', assetType: 'key', algorithm: 'RSA-2048', usage: 'signing', quantumVulnerable: true };
  assert.throws(() => Q.asset(Object.assign({}, base, { assetType: 'widget' })), /assetType must be one of/);
  assert.throws(() => Q.asset(Object.assign({}, base, { assetId: '' })), /assetId is 1 to/);
  assert.throws(() => Q.asset(Object.assign({}, base, { quantumVulnerable: 'yes' })), /quantumVulnerable must be true or false/);
  assert.throws(() => Q.asset(Object.assign({}, base, { unknownField: 1 })), /is not an option of asset/);
  assert.throws(() => Q.assess({ key, record: open, posture: 'maybe', target: 'none', dueBy: '2030-12-31T00:00:00.000Z' }), /posture must be one of/);
  assert.throws(() => Q.remediate({ key, record: open, action: 'ignored' }), /action must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => Q.open({ key: new Uint8Array(16), system: 's', scope: 'x' }), /32 byte Uint8Array seed/);
  assert.throws(() => Q.open({ key: new Uint8Array(32), system: 's', scope: 'x' }), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const open = openInventory(authority);
  const ok = await Q.verify(open, { type: 'open', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'open');
  assert.strictEqual(ok.inventoryId, open.statement.inventoryId);
  const wrongType = await Q.verify(open, { type: 'asset', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(open, { type: 'open', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const open = openInventory(authority);
  const asset = assetOf(authority, open);
  const forged = JSON.parse(JSON.stringify(asset));
  forged.statement.quantumVulnerable = false;
  const r = await Q.verify(forged, { type: 'asset', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds an asset to the open it refers to', async () => {
  const authority = freshKey();
  const open = openInventory(authority);
  const asset = assetOf(authority, open);
  const good = await Q.verify(asset, { type: 'asset', network: 'testnet', requireAnchor: false, strict: false, prior: open });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherOpen = openInventory(authority);
  const bad = await Q.verify(asset, { type: 'asset', network: 'testnet', requireAnchor: false, strict: false, prior: otherOpen });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'host api.gov.example');
  const b = Q.subjectRef(secret, 'host api.gov.example');
  const c = Q.subjectRef(secret, 'host api2.gov.example');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the cbom line', () => {
  assert.strictEqual(Q.KIND, 1601);
  assert.strictEqual(Q.FORMAT, 'qcbom/1');
  assert.deepStrictEqual([...Q.TYPES], ['open', 'asset', 'assess', 'remediate', 'close']);
  assert.deepStrictEqual([...Q.ASSETTYPES], ['key', 'certificate', 'protocol', 'algorithm', 'library', 'token', 'service']);
  assert.deepStrictEqual([...Q.POSTURES], ['vulnerable', 'hybrid', 'quantum-safe', 'not-applicable']);
  assert.deepStrictEqual([...Q.ACTIONS], ['replaced', 'rotated', 'deprecated', 'accepted-risk', 'in-progress']);
});
