// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  if (value === undefined || value === null) return Object.create(null);
  if (typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) F.reject('the options are a plain object');
  return Object.assign(Object.create(null), value);
}

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array) && key.length === 32 && key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qcbom-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}


function subjectRef(secret, reference) {
  return F.subjectRefOf(secret, reference);
}

function nowIso() {
  return new Date().toISOString();
}

function seal(type, key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain);
  if (problem) F.reject(problem);
  const message = F.payload(type, plain);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(plain)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function badCbom(message) {
  const e = new Error(message);
  e.code = 'QCBOM_INVALID_RECORD';
  throw e;
}

function verifiedPrior(envelope, what) {
  const p = F.parse(envelope);
  if (p.signerId !== F.keyIdOf(p.publicKey)) badCbom('the ' + what + ' names a signer id that does not match its public key');
  if (!native.verify(p.publicKey, F.encoded(p), p.signature)) badCbom('the ' + what + ' signature does not verify');
  return p;
}

function open(options) {
  if (!options || typeof options !== 'object') F.reject('open needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.system === undefined) F.reject('system is required, the identifier of the system being inventoried');
  if (options.scope === undefined) F.reject('scope is required, what the inventory covers');
  return seal('open', options.key, {
    inventoryId: randomHex(16),
    system: options.system,
    scope: options.scope,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    openedAt: options.openedAt === undefined ? nowIso() : options.openedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function asset(options) {
  if (!options || typeof options !== 'object') F.reject('asset needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.inventory === undefined) F.reject('the open envelope the asset belongs to is required');
  if (options.assetId === undefined) F.reject('assetId is required, the identifier of the cryptographic asset');
  if (options.assetType === undefined) F.reject('assetType is required, one of ' + F.ASSETTYPES.join(', '));
  if (options.algorithm === undefined) F.reject('algorithm is required, the algorithm the asset uses');
  if (options.usage === undefined) F.reject('usage is required, what the asset protects');
  if (options.quantumVulnerable === undefined) F.reject('quantumVulnerable is required, true or false');
  const r = verifiedPrior(options.inventory, 'inventory');
  if (r.type !== 'open') badCbom('the referenced envelope is not an open');
  return seal('asset', options.key, {
    inventoryId: r.statement.inventoryId,
    openRef: F.refOf(r),
    assetId: options.assetId,
    assetType: options.assetType,
    algorithm: options.algorithm,
    usage: options.usage,
    quantumVulnerable: options.quantumVulnerable,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    recordedAt: options.recordedAt === undefined ? nowIso() : options.recordedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function assess(options) {
  if (!options || typeof options !== 'object') F.reject('assess needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior envelope this assessment follows is required');
  if (options.posture === undefined) F.reject('posture is required, one of ' + F.POSTURES.join(', '));
  if (options.target === undefined) F.reject('target is required, the target algorithm or none');
  if (options.dueBy === undefined) F.reject('dueBy is required, the time the migration is due');
  const prior = verifiedPrior(options.record, 'record');
  return seal('assess', options.key, {
    inventoryId: prior.statement.inventoryId,
    priorRef: F.refOf(prior),
    posture: options.posture,
    target: options.target,
    dueBy: options.dueBy,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    assessedAt: options.assessedAt === undefined ? nowIso() : options.assessedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function remediate(options) {
  if (!options || typeof options !== 'object') F.reject('remediate needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior envelope this remediation follows is required');
  if (options.action === undefined) F.reject('action is required, one of ' + F.ACTIONS.join(', '));
  const prior = verifiedPrior(options.record, 'record');
  return seal('remediate', options.key, {
    inventoryId: prior.statement.inventoryId,
    priorRef: F.refOf(prior),
    action: options.action,
    newAlgorithm: options.newAlgorithm === undefined ? '' : options.newAlgorithm,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    remediatedAt: options.remediatedAt === undefined ? nowIso() : options.remediatedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function close(options) {
  if (!options || typeof options !== 'object') F.reject('close needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior envelope this closure follows is required');
  if (options.summary === undefined) F.reject('summary is required, the outcome of the inventory');
  const prior = verifiedPrior(options.record, 'record');
  return seal('close', options.key, {
    inventoryId: prior.statement.inventoryId,
    priorRef: F.refOf(prior),
    summary: options.summary,
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    closedAt: options.closedAt === undefined ? nowIso() : options.closedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs'];

function strictOf(opts) {
  if (opts.strict === undefined) return true;
  if (typeof opts.strict !== 'boolean') F.reject('strict is true or false');
  return opts.strict;
}

function endpointOptions(opts) {
  const out = Object.create(null);
  for (const k of ENDPOINT_OPTIONS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

async function chainClock(opts, strict) {
  if (strict !== false && strictOf(opts) && opts.trustSingleEndpoint === true) {
    F.reject('strict mode takes the time of the chain only from at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to rely on one endpoint');
  }
  try {
    return await qstamp.chainTime(endpointOptions(opts));
  } catch (e) {
    const err = new Error('the chain time could not be established, so no decision was made, ' + ((e && e.message) || 'unknown error'));
    err.code = 'QCBOM_NO_CHAIN_TIME';
    throw err;
  }
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.encoded(p), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  return { list, parsed };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  options = own(options);
  const { list, parsed } = anchorBatch(envelopes);
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  const stampOptions = Object.assign(own(options), { records, kind: F.KIND });
  delete stampOptions.strict;
  return attach(list, await qstamp.stamp(stampOptions));
}

async function complete(envelopes, pending, options) {
  const opts = own(options);
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { list, parsed } = anchorBatch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  const completeOptions = own(opts);
  delete completeOptions.strict;
  return attach(list, await qstamp.complete(p, completeOptions));
}

const OPTIONS_OF = {
  open: ['key', 'system', 'scope', 'authorityLabel', 'openedAt', 'note'],
  asset: ['key', 'inventory', 'assetId', 'assetType', 'algorithm', 'usage', 'quantumVulnerable', 'authorityLabel', 'recordedAt', 'note'],
  assess: ['key', 'record', 'posture', 'target', 'dueBy', 'authorityLabel', 'assessedAt', 'note'],
  remediate: ['key', 'record', 'action', 'newAlgorithm', 'authorityLabel', 'remediatedAt', 'note'],
  close: ['key', 'record', 'summary', 'authorityLabel', 'closedAt', 'note'],
  anchor: ['allowLoopback', 'client', 'clients', 'clockSlackMs', 'endpointAllowList', 'index', 'maxFee', 'meter', 'network', 'onPending', 'rpc', 'seed', 'signal', 'strict', 'timeoutMs', 'trustCustomEndpoints', 'trustSingleEndpoint'],
};

function onlyKnown(name, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return;
  const unknown = Object.keys(options).find((k) => !OPTIONS_OF[name].includes(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

function strict(name, fn, at, isAsync) {
  return function strictly(...args) {
    try {
      onlyKnown(name, args[at]);
    } catch (e) {
      if (isAsync) return Promise.reject(e);
      throw e;
    }
    return fn.apply(this, args);
  };
}

module.exports = {
  own, generateKey, publicKey, keyId, describeKey, subjectRef, verifiedPrior, anchor, complete, chainClock, endpointOptions, strictOf,
};
Object.assign(module.exports, {
  open: strict('open', open, 0, false),
  asset: strict('asset', asset, 0, false),
  assess: strict('assess', assess, 0, false),
  remediate: strict('remediate', remediate, 0, false),
  close: strict('close', close, 0, false),
});
