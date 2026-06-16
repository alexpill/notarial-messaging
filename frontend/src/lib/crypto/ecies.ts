/**
 * ECIES — manual implementation matching the Rust server exactly.
 * Scheme: ephemeral X25519 DH + HKDF(salt=ephemeral_pk, info="notariat-ecies-v1") + AES-256-GCM
 * Wire: ephemeral_pk(32) || nonce(12) || ciphertext+tag
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';

/** Rust serde format for EciesCiphertext */
export interface EciesCiphertext {
	ephemeral_pk: number[];
	nonce: number[];
	ciphertext: number[];
}

const ECIES_INFO = new TextEncoder().encode('notariat-ecies-v1');

export function eciesEncrypt(recipientX25519Pk: Uint8Array, plaintext: Uint8Array): EciesCiphertext {
	const ephemeralSk = x25519.utils.randomSecretKey();
	const ephemeralPk = x25519.getPublicKey(ephemeralSk);
	const shared = x25519.getSharedSecret(ephemeralSk, recipientX25519Pk);

	// HKDF(salt=ephemeral_pk, ikm=shared, info="notariat-ecies-v1", len=32)
	const symmetricKey = hkdf(sha256, shared, ephemeralPk, ECIES_INFO, 32);

	const nonce = randomBytes(12);
	const cipher = gcm(symmetricKey, nonce);
	const ciphertextWithTag = cipher.encrypt(plaintext);

	return {
		ephemeral_pk: Array.from(ephemeralPk),
		nonce: Array.from(nonce),
		ciphertext: Array.from(ciphertextWithTag)
	};
}

export function eciesDecrypt(recipientX25519Sk: Uint8Array, ct: EciesCiphertext): Uint8Array {
	const ephemeralPk = new Uint8Array(ct.ephemeral_pk);
	const nonce = new Uint8Array(ct.nonce);
	const ciphertextWithTag = new Uint8Array(ct.ciphertext);

	const shared = x25519.getSharedSecret(recipientX25519Sk, ephemeralPk);
	const symmetricKey = hkdf(sha256, shared, ephemeralPk, ECIES_INFO, 32);

	const cipher = gcm(symmetricKey, nonce);
	return cipher.decrypt(ciphertextWithTag);
}
