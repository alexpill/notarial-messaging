/**
 * Login proof of possession (PoP).
 * Mirrors localpki-core::authentication::auth_pop_payload:
 *   payload = "localpki-auth-pop-v1\0" || SN(16) || challenge_nonce(32)
 * signed directly with Ed25519 (internal hash, no explicit SHA-256).
 *
 * The client signs a fresh single-use server challenge to prove it holds sk —
 * the static SI alone is not a sufficient login credential.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { hexToBytes, fromBase64url, toBase64url } from './keys';

const AUTH_POP_TAG = new TextEncoder().encode('localpki-auth-pop-v1\0');

/** Sign the login challenge with sk. Returns the base64url signature. */
export function signAuthPop(signingKey: Uint8Array, snHex: string, challengeB64: string): string {
	const sn = hexToBytes(snHex);
	const nonce = fromBase64url(challengeB64);
	if (sn.length !== 16) throw new Error(`SN must be 16 bytes, got ${sn.length}`);
	if (nonce.length !== 32) throw new Error(`challenge nonce must be 32 bytes, got ${nonce.length}`);

	const payload = new Uint8Array(AUTH_POP_TAG.length + 16 + 32);
	payload.set(AUTH_POP_TAG, 0);
	payload.set(sn, AUTH_POP_TAG.length);
	payload.set(nonce, AUTH_POP_TAG.length + 16);

	return toBase64url(ed25519.sign(payload, signingKey));
}
