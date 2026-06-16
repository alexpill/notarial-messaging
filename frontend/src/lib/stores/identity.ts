import { writable, derived } from 'svelte/store';
import { loadIdentity, loadSessionToken, saveIdentity, saveSessionToken, clearIdentity } from '$lib/crypto/keys';
import type { Identity } from '$lib/crypto/keys';

function createIdentityStore() {
	const { subscribe, set } = writable<Identity | null>(null);

	return {
		subscribe,
		init() {
			set(loadIdentity());
		},
		save(identity: Identity) {
			saveIdentity(identity);
			set(identity);
		},
		clear() {
			clearIdentity();
			set(null);
		}
	};
}

function createTokenStore() {
	const { subscribe, set } = writable<string | null>(null);

	return {
		subscribe,
		init() {
			set(loadSessionToken());
		},
		save(token: string) {
			saveSessionToken(token);
			set(token);
		},
		clear() {
			sessionStorage.removeItem('notarial_session_token');
			set(null);
		}
	};
}

export const identityStore = createIdentityStore();
export const tokenStore = createTokenStore();

export const isAuthenticated = derived(
	[identityStore, tokenStore],
	([$identity, $token]) => $identity !== null && $token !== null
);
