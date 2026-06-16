import { writable } from 'svelte/store';
import type { ActeResponse, MessageResponse } from '$lib/api/client';

export const actesStore = writable<ActeResponse[]>([]);

export const currentActe = writable<ActeResponse | null>(null);

export interface DecryptedMessage {
	id: string;
	seq: number;
	sender_sn: string;
	display_name: string | null;
	sent_at: number;
	text: string | null; // null if decryption failed
	sigValid: boolean | null; // null = not yet verified or decryption failed
	rawMsg: MessageResponse;
}

export const messagesStore = writable<DecryptedMessage[]>([]);
