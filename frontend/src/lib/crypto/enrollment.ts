/**
 * LRA-side helpers for endorsing an enrollment certificate.
 * Mirrors the payload format expected by the server's POST /enroll:
 *   payload = SN(16) || SI.to_bytes()(64) || pk.as_bytes()(32) = 112 bytes
 *   signature = Ed25519(sk_lra, SHA256(payload))
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { fromNumberArray, toBase64url } from './keys';

export interface CertJson {
	tbs: {
		serial_number: number[]; // 16
		public_key: number[]; // 32
		subject_id: string;
		validity: { not_before: number; not_after: number };
		en_url: string;
	};
	signature_id: number[]; // 64
}

export function endorseCert(cert: CertJson, lraSigningKey: Uint8Array): string {
	const sn = fromNumberArray(cert.tbs.serial_number);
	const si = fromNumberArray(cert.signature_id);
	const pk = fromNumberArray(cert.tbs.public_key);

	if (sn.length !== 16) throw new Error(`SN must be 16 bytes, got ${sn.length}`);
	if (si.length !== 64) throw new Error(`SI must be 64 bytes, got ${si.length}`);
	if (pk.length !== 32) throw new Error(`pk must be 32 bytes, got ${pk.length}`);

	const payload = new Uint8Array(112);
	payload.set(sn, 0);
	payload.set(si, 16);
	payload.set(pk, 80);

	const digest = sha256(payload);
	const signature = ed25519.sign(digest, lraSigningKey);
	return toBase64url(signature);
}
