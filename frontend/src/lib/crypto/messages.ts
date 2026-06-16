/**
 * Message crypto — matches the Rust messaging-crypto crate exactly.
 *
 * K_acte = HKDF(key=kMaster, info="notariat-msg-v1" || UUID(16), len=32)
 * K_send = HKDF(key=kActe, info="send" || SN(16), len=32)
 * encrypt: AES-256-GCM(K_send, plaintext, AAD=UUID(16)||ts(8 LE)||SN(16))
 * sign:    Ed25519(sk, SHA256(ciphertext || nonce(12) || UUID(16) || ts(8 LE) || SN(16)))
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { uuidToBytes, hexToBytes, timestampToLeBytes } from './keys';

const enc = new TextEncoder();

// ─── Key derivation ───────────────────────────────────────────────────────────

export function deriveKActe(kMaster: Uint8Array, acteUuid: string): Uint8Array {
	const prefix = enc.encode('notariat-msg-v1');
	const uuidBytes = uuidToBytes(acteUuid);
	const info = new Uint8Array(prefix.length + 16);
	info.set(prefix, 0);
	info.set(uuidBytes, prefix.length);
	return hkdf(sha256, kMaster, undefined, info, 32);
}

export function deriveKSend(kActe: Uint8Array, snHex: string): Uint8Array {
	const prefix = enc.encode('send');
	const snBytes = hexToBytes(snHex);
	const info = new Uint8Array(prefix.length + 16);
	info.set(prefix, 0);
	info.set(snBytes, prefix.length);
	return hkdf(sha256, kActe, undefined, info, 32);
}

// ─── AAD and signing payload ──────────────────────────────────────────────────

function buildAad(acteUuid: string, timestamp: number, snHex: string): Uint8Array {
	const aad = new Uint8Array(40);
	aad.set(uuidToBytes(acteUuid), 0);
	aad.set(timestampToLeBytes(timestamp), 16);
	aad.set(hexToBytes(snHex), 24);
	return aad;
}

// Signing payload: ciphertext || nonce(12) || UUID(16) || ts(8 LE) || SN(16)
// Mirrors messaging_crypto::messages::signing_payload in Rust.
function buildSigningPayload(
	ciphertext: Uint8Array,
	nonce: Uint8Array,
	acteUuid: string,
	timestamp: number,
	snHex: string
): Uint8Array {
	const uuidBytes = uuidToBytes(acteUuid);
	const tsBytes = timestampToLeBytes(timestamp);
	const snBytes = hexToBytes(snHex);
	const payload = new Uint8Array(ciphertext.length + 12 + 16 + 8 + 16);
	let offset = 0;
	payload.set(ciphertext, offset); offset += ciphertext.length;
	payload.set(nonce, offset);      offset += 12;
	payload.set(uuidBytes, offset);  offset += 16;
	payload.set(tsBytes, offset);    offset += 8;
	payload.set(snBytes, offset);
	return payload;
}

// ─── Encrypt / Decrypt ────────────────────────────────────────────────────────

export function encryptMessage(
	kActe: Uint8Array,
	plaintext: Uint8Array,
	acteUuid: string,
	senderSnHex: string,
	timestamp: number
): { ciphertext: Uint8Array; nonce: Uint8Array } {
	const kSend = deriveKSend(kActe, senderSnHex);
	const aad = buildAad(acteUuid, timestamp, senderSnHex);
	const nonce = randomBytes(12);
	const cipher = gcm(kSend, nonce, aad);
	const ciphertext = cipher.encrypt(plaintext);
	return { ciphertext, nonce };
}

export function decryptMessage(
	kActe: Uint8Array,
	senderSnHex: string,
	ciphertext: Uint8Array,
	nonce: Uint8Array,
	acteUuid: string,
	timestamp: number
): Uint8Array {
	const kSend = deriveKSend(kActe, senderSnHex);
	const aad = buildAad(acteUuid, timestamp, senderSnHex);
	const cipher = gcm(kSend, nonce, aad);
	return cipher.decrypt(ciphertext);
}

// ─── Sign / Verify ────────────────────────────────────────────────────────────

export function signMessage(
	signingKey: Uint8Array,
	ciphertext: Uint8Array,
	nonce: Uint8Array,
	acteUuid: string,
	senderSnHex: string,
	timestamp: number
): Uint8Array {
	const payload = buildSigningPayload(ciphertext, nonce, acteUuid, timestamp, senderSnHex);
	const digest = sha256(payload);
	return ed25519.sign(digest, signingKey);
}

export function verifyMessageSignature(
	verifyingKey: Uint8Array,
	ciphertext: Uint8Array,
	nonce: Uint8Array,
	acteUuid: string,
	senderSnHex: string,
	timestamp: number,
	signature: Uint8Array
): boolean {
	try {
		const payload = buildSigningPayload(ciphertext, nonce, acteUuid, timestamp, senderSnHex);
		const digest = sha256(payload);
		return ed25519.verify(signature, digest, verifyingKey);
	} catch {
		return false;
	}
}
