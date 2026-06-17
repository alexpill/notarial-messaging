/**
 * Typed HTTP client for the notarial messaging server.
 * All crypto stays client-side — this only wraps fetch.
 */

const BASE_URL = 'http://localhost:3000';

class ApiError extends Error {
	constructor(
		public status: number,
		message: string
	) {
		super(message);
	}
}

async function request<T>(
	method: string,
	path: string,
	body?: unknown,
	token?: string
): Promise<T> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (token) headers['Authorization'] = `Bearer ${token}`;

	const resp = await fetch(`${BASE_URL}${path}`, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});

	if (!resp.ok) {
		const text = await resp.text().catch(() => '');
		throw new ApiError(resp.status, `${method} ${path}: ${resp.status} — ${text}`);
	}
	return resp.json() as Promise<T>;
}

// ─── Enrollment ───────────────────────────────────────────────────────────────

export interface PrepareTbsRequest {
	subject_id: string;
	public_key: number[]; // 32 bytes
}

export interface PrepareTbsResponse {
	sn_bytes: number[]; // 16 bytes
	tbs_json: TbsJson;
	tbs_der_b64url: string;
}

export interface TbsJson {
	subject_id: string;
	public_key: number[]; // 32 bytes
	serial_number: number[]; // 16 bytes
	validity: { not_before: number; not_after: number };
	en_url: string;
}

export interface EnrollResponse {
	serial_number: string; // hex
	message: string;
}

export interface AuthVerifyResponse {
	authenticated: boolean;
	session_token: string | null;
}

export async function prepareTbs(req: PrepareTbsRequest): Promise<PrepareTbsResponse> {
	return request('POST', '/enroll/prepare', req);
}

export async function enroll(
	certJson: unknown,
	lraSn: string,
	lraSignature: string
): Promise<EnrollResponse> {
	return request('POST', '/enroll', { cert: certJson, lra_sn: lraSn, lra_signature: lraSignature });
}

export async function authVerify(certJson: unknown): Promise<AuthVerifyResponse> {
	return request('POST', '/auth/verify', { cert: certJson });
}

export async function enrollSelf(certJson: unknown): Promise<EnrollResponse> {
	return request('POST', '/enroll/self', { cert: certJson });
}

export async function getIdentity(
	sn: string
): Promise<{ sn: string; pk: string; display_name: string | null; registered_at: number }> {
	return request('GET', `/identity/${sn}`);
}

// ─── Actes ────────────────────────────────────────────────────────────────────

export interface ActeResponse {
	uuid: string;
	titre: string;
	notaire_sn: string;
	parties: string[];
	created_at: number;
}

export async function listActes(token: string): Promise<ActeResponse[]> {
	return request('GET', '/actes', undefined, token);
}

export async function createActe(
	token: string,
	titre: string,
	parties: string[]
): Promise<ActeResponse> {
	return request('POST', '/actes', { titre, parties }, token);
}

export async function getActe(token: string, id: string): Promise<ActeResponse> {
	return request('GET', `/actes/${id}`, undefined, token);
}

export async function getActeKey(token: string, id: string): Promise<{ c_acte_key: string }> {
	return request('GET', `/actes/${id}/keys`, undefined, token);
}

// ─── Participants ─────────────────────────────────────────────────────────────

export async function addParticipant(
	token: string,
	acteId: string,
	participantSn: string,
	grantHistory: boolean,
	notaireSignature: string
): Promise<{ acte_uuid: string; participant_sn: string; added_at: number }> {
	return request(
		'POST',
		`/actes/${acteId}/participants`,
		{
			participant_sn: participantSn,
			grant_history: grantHistory,
			notaire_signature: notaireSignature
		},
		token
	);
}

// ─── Messages ─────────────────────────────────────────────────────────────────

export interface MessageResponse {
	id: string;
	acte_uuid: string;
	sender_sn: string;
	c_message: string; // base64url
	nonce: string; // base64url
	signature: string; // base64url
	seq: number;
	sent_at: number;
}

export async function sendMessage(
	token: string,
	acteId: string,
	cMessage: string,
	nonce: string,
	signature: string,
	timestamp: number
): Promise<MessageResponse> {
	return request(
		'POST',
		`/actes/${acteId}/messages`,
		{ c_message: cMessage, nonce, signature, timestamp },
		token
	);
}

export async function listMessages(
	token: string,
	acteId: string,
	afterSeq?: number
): Promise<MessageResponse[]> {
	const qs = afterSeq !== undefined ? `?after_seq=${afterSeq}` : '';
	return request('GET', `/actes/${acteId}/messages${qs}`, undefined, token);
}

// ─── Merkle ───────────────────────────────────────────────────────────────────

// ─── WebSocket ticket ─────────────────────────────────────────────────────────

/// Trade the session token for a single-use, 30-second WebSocket ticket. The
/// ticket is safe to put in the WS URL because it is consumed on first use and
/// expires quickly. Always call this immediately before opening a WebSocket.
export async function getWsTicket(
	token: string
): Promise<{ ticket: string; expires_at: number }> {
	return request('POST', '/ws/ticket', undefined, token);
}

export async function getMerkleRoot(
	token: string,
	acteId: string
): Promise<{
	root: string | null;
	leaves_count: number;
	en_signature: string | null;
	signed_root: string | null;
	signed_at: number | null;
}> {
	return request('GET', `/actes/${acteId}/merkle`, undefined, token);
}

export { ApiError };
