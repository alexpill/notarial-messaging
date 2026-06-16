import { ed25519, x25519 } from '@noble/curves/ed25519.js';

export interface Keypair {
	signingKey: Uint8Array; // 32-byte seed
	verifyingKey: Uint8Array; // 32 bytes
}

export function generateKeypair(): Keypair {
	const signingKey = ed25519.utils.randomSecretKey();
	const verifyingKey = ed25519.getPublicKey(signingKey);
	return { signingKey, verifyingKey };
}

/** Ed25519 public key → X25519 public key (montgomery form) */
export function edPkToX25519(edPk: Uint8Array): Uint8Array {
	return ed25519.utils.toMontgomery(edPk);
}

/** Ed25519 private key (seed) → X25519 scalar. Same as Rust signing_key.to_scalar_bytes(). */
export function edSkToX25519(edSk: Uint8Array): Uint8Array {
	return ed25519.utils.toMontgomerySecret(edSk);
}

// ─── base64url (no padding) ───────────────────────────────────────────────────

export function toBase64url(bytes: Uint8Array): string {
	const b64 = btoa(String.fromCharCode(...bytes));
	return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function fromBase64url(s: string): Uint8Array {
	const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
	const binary = atob(padded);
	return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

// ─── Rust serde interop ───────────────────────────────────────────────────────

/** Convert Uint8Array to number[] for Rust serde JSON format */
export function toNumberArray(bytes: Uint8Array): number[] {
	return Array.from(bytes);
}

export function fromNumberArray(arr: number[]): Uint8Array {
	return new Uint8Array(arr);
}

/** Parse UUID string to 16-byte Uint8Array */
export function uuidToBytes(uuid: string): Uint8Array {
	const hex = uuid.replace(/-/g, '');
	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

/** Parse hex string to Uint8Array */
export function hexToBytes(hex: string): Uint8Array {
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return bytes;
}

/** Encode timestamp (i64) to 8 bytes little-endian */
export function timestampToLeBytes(ts: number): Uint8Array {
	const buf = new Uint8Array(8);
	const view = new DataView(buf.buffer);
	view.setBigInt64(0, BigInt(ts), true);
	return buf;
}

// ─── Identity persistence (sessionStorage) ───────────────────────────────────

export interface Identity {
	sn_hex: string;
	signingKey: string; // base64url
	verifyingKey: string; // base64url
	name: string;
	/** JSON-stringified LocalPKICert (tbs_json + signature_id as number[]) */
	cert_json: string;
	role: 'notaire' | 'client';
}

export function saveIdentity(identity: Identity): void {
	sessionStorage.setItem('notarial_identity', JSON.stringify(identity));
}

export function loadIdentity(): Identity | null {
	const s = sessionStorage.getItem('notarial_identity');
	return s ? (JSON.parse(s) as Identity) : null;
}

export function clearIdentity(): void {
	sessionStorage.removeItem('notarial_identity');
	sessionStorage.removeItem('notarial_session_token');
}

export function saveSessionToken(token: string): void {
	sessionStorage.setItem('notarial_session_token', token);
}

export function loadSessionToken(): string | null {
	return sessionStorage.getItem('notarial_session_token');
}

export { x25519 };
