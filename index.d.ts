// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type AssetType = 'key' | 'certificate' | 'protocol' | 'algorithm' | 'library' | 'token' | 'service';
export type Posture = 'vulnerable' | 'hybrid' | 'quantum-safe' | 'not-applicable';
export type Action = 'replaced' | 'rotated' | 'deprecated' | 'accepted-risk' | 'in-progress';
export type RecordType = 'open' | 'asset' | 'assess' | 'remediate' | 'close';

export interface KeyDescription {
  format: 'qcbom-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qcbom/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface OpenOptions {
  key: Uint8Array;
  system: string;
  scope: string;
  authorityLabel?: string;
  openedAt?: string;
  note?: string;
}

export interface AssetOptions {
  key: Uint8Array;
  inventory: Envelope;
  assetId: string;
  assetType: AssetType;
  algorithm: string;
  usage: string;
  quantumVulnerable: boolean;
  authorityLabel?: string;
  recordedAt?: string;
  note?: string;
}

export interface AssessOptions {
  key: Uint8Array;
  record: Envelope;
  posture: Posture;
  target: string;
  dueBy: string;
  authorityLabel?: string;
  assessedAt?: string;
  note?: string;
}

export interface RemediateOptions {
  key: Uint8Array;
  record: Envelope;
  action: Action;
  newAlgorithm?: string;
  authorityLabel?: string;
  remediatedAt?: string;
  note?: string;
}

export interface CloseOptions {
  key: Uint8Array;
  record: Envelope;
  summary: string;
  authorityLabel?: string;
  closedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  inventoryId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  inventoryId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function subjectRef(secret: Uint8Array, reference: string): string;
export function open(options: OpenOptions): Envelope;
export function asset(options: AssetOptions): Envelope;
export function assess(options: AssessOptions): Envelope;
export function remediate(options: RemediateOptions): Envelope;
export function close(options: CloseOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qcbom/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1601;
export const TYPES: readonly RecordType[];
export const ASSETTYPES: readonly AssetType[];
export const POSTURES: readonly Posture[];
export const ACTIONS: readonly Action[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
