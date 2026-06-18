<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { Button } from '$lib/components/ui/button';
	import { identityStore, tokenStore } from '$lib/stores/identity';
	import { currentActe, messagesStore } from '$lib/stores/actes';
	import type { DecryptedMessage } from '$lib/stores/actes';
	import {
		getActe,
		getActeKey,
		getIdentity,
		listMessages,
		sendMessage,
		getMerkleRoot,
		addParticipant,
		getWsTicket
	} from '$lib/api/client';
	import type { MessageResponse } from '$lib/api/client';
	import { fromBase64url, toBase64url, edSkToX25519 } from '$lib/crypto/keys';
	import { ed25519 } from '@noble/curves/ed25519.js';
	import { sha256 } from '@noble/hashes/sha2.js';
	import type { EciesCiphertext } from '$lib/crypto/ecies';
	import { eciesDecrypt } from '$lib/crypto/ecies';
	import { encryptMessage, decryptMessage, signMessage, verifyMessageSignature } from '$lib/crypto/messages';

	const acteId = $page.params.id!;

	let identity = $state($identityStore);
	let token = $state($tokenStore);
	let acte = $state($currentActe);
	let messages = $state<DecryptedMessage[]>([]);
	let kActe = $state<Uint8Array | null>(null);
	let input = $state('');
	let loading = $state(true);
	let sending = $state(false);
	let error = $state('');
	let merkleRoot = $state<string | null>(null);
	let merkleLeaves = $state(0);
	let merkleSignedAt = $state<number | null>(null);
	let showMerkle = $state(false);
	let lastSeq = $state(-1);
	let showAddParticipant = $state(false);
	let newParticipantSn = $state('');
	let grantHistory = $state(false);
	let addingParticipant = $state(false);
	let addParticipantError = $state('');

	// Cache sender public keys to avoid redundant fetches
	const pkCache = new Map<string, Uint8Array>();
	// Cache display names (extracted from tbs_cert.subject_id) to avoid redundant fetches
	const displayNameCache = new Map<string, string>();

	let ws: WebSocket | null = null;
	let wsRetryDelay = 1000;
	let wsRetryTimer: ReturnType<typeof setTimeout> | null = null;
	let wsDestroyed = false;

	$effect(() => {
		identity = $identityStore;
		token = $tokenStore;
	});

	onMount(async () => {
		identityStore.init();
		tokenStore.init();
		identity = $identityStore;
		token = $tokenStore;

		if (!identity || !token) {
			goto('/');
			return;
		}

		await initialize();
	});

	onDestroy(() => {
		wsDestroyed = true;
		if (wsRetryTimer) clearTimeout(wsRetryTimer);
		ws?.close();
	});

	async function initialize() {
		if (!identity || !token) return;
		loading = true;
		error = '';
		try {
			const acteData = await getActe(token, acteId);
			currentActe.set(acteData);
			acte = acteData;

			// Decrypt K_acte with our X25519 private key derived from Ed25519 seed.
			const keyResp = await getActeKey(token, acteId);
			// c_acte_key is a JSON-encoded string stored in DB (serde_json::to_string(&EciesCiphertext)).
			const cActeKey = JSON.parse(keyResp.c_acte_key) as EciesCiphertext;
			const signingKey = fromBase64url(identity.signingKey);
			const x25519Sk = edSkToX25519(signingKey);
			const kActeBytes = eciesDecrypt(x25519Sk, cActeKey);
			if (kActeBytes.length !== 32) throw new Error('K_acte invalide (longueur inattendue)');
			kActe = kActeBytes;

			await loadMessages();
			connectWebSocket();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	async function loadMessages(afterSeq?: number) {
		if (!token || !kActe || !identity) return;
		const raw = await listMessages(token, acteId, afterSeq);
		const decoded = await Promise.all(raw.map((m) => decryptAndVerify(m)));
		if (afterSeq === undefined) {
			messages = decoded;
			messagesStore.set(decoded);
		} else {
			messages = [...messages, ...decoded];
			messagesStore.set(messages);
		}
		if (raw.length > 0) lastSeq = raw[raw.length - 1].seq;
	}

	async function getSenderIdentity(sn: string): Promise<{ pk: Uint8Array | null; displayName: string | null }> {
		const cachedPk = pkCache.has(sn) ? pkCache.get(sn)! : null;
		const cachedName = displayNameCache.has(sn) ? displayNameCache.get(sn)! : null;
		if (cachedPk && cachedName) return { pk: cachedPk, displayName: cachedName };
		try {
			const idResp = await getIdentity(sn);
			const pkBytes = fromBase64url(idResp.pk);
			pkCache.set(sn, pkBytes);
			if (idResp.display_name) displayNameCache.set(sn, idResp.display_name);
			return { pk: pkBytes, displayName: idResp.display_name ?? null };
		} catch {
			return { pk: cachedPk, displayName: cachedName };
		}
	}

	async function getSenderPk(sn: string): Promise<Uint8Array | null> {
		return (await getSenderIdentity(sn)).pk;
	}

	async function decryptAndVerify(m: MessageResponse): Promise<DecryptedMessage> {
		const base: DecryptedMessage = {
			id: m.id,
			seq: m.seq,
			sender_sn: m.sender_sn,
			display_name: null,
			sent_at: m.sent_at,
			text: null,
			sigValid: null,
			rawMsg: m
		};
		if (!kActe) return base;

		const ciphertext = fromBase64url(m.c_message);
		const nonce = fromBase64url(m.nonce);

		let plaintext: Uint8Array;
		try {
			plaintext = decryptMessage(kActe, m.sender_sn, ciphertext, nonce, m.acte_uuid, m.sent_at);
		} catch {
			return base; // decryption failed, leave text + sigValid null
		}

		let sigValid: boolean | null = null;
		let display_name: string | null = null;
		try {
			const { pk: senderPk, displayName } = await getSenderIdentity(m.sender_sn);
			display_name = displayName;
			if (senderPk) {
				const sig = fromBase64url(m.signature);
				sigValid = verifyMessageSignature(senderPk, ciphertext, nonce, m.acte_uuid, m.sender_sn, m.sent_at, sig);
			}
		} catch {
			sigValid = false;
		}

		return {
			...base,
			display_name,
			text: new TextDecoder().decode(plaintext),
			sigValid
		};
	}

	async function connectWebSocket() {
		if (wsDestroyed || !token) return;
		// Trade the session token for a short-lived single-use ticket. The ticket
		// (not the session token) ends up in the WS URL, so browser/server logs
		// only ever see a value that's worthless after the handshake.
		let ticket: string;
		try {
			const resp = await getWsTicket(token);
			ticket = resp.ticket;
		} catch {
			// Ticket fetch failed (network or expired session) — back off and retry.
			if (wsDestroyed) return;
			wsRetryTimer = setTimeout(() => {
				wsRetryDelay = Math.min(wsRetryDelay * 2, 30_000);
				connectWebSocket();
			}, wsRetryDelay);
			return;
		}
		if (wsDestroyed) return;
		const wsUrl = `ws://localhost:3000/ws/${acteId}?ticket=${encodeURIComponent(ticket)}`;
		ws = new WebSocket(wsUrl);

		ws.onopen = () => {
			wsRetryDelay = 1000; // reset backoff on successful connection
		};

		ws.onmessage = async (evt) => {
			try {
				const data = JSON.parse(evt.data as string);
				if (data.event === 'new_message') {
					await loadMessages(lastSeq);
					// Keep the transparency-log panel live if it's open.
					if (showMerkle) await fetchMerkle();
				}
			} catch {}
		};

		ws.onclose = () => {
			if (wsDestroyed) return;
			// Exponential backoff: 1s → 2s → 4s → 8s → max 30s
			wsRetryTimer = setTimeout(() => {
				wsRetryDelay = Math.min(wsRetryDelay * 2, 30_000);
				connectWebSocket();
			}, wsRetryDelay);
		};

		ws.onerror = () => ws?.close();
	}

	async function send() {
		if (!input.trim() || !kActe || !identity || !token || sending) return;
		sending = true;
		const text = input.trim();
		input = '';
		try {
			const plaintext = new TextEncoder().encode(text);
			const timestamp = Math.floor(Date.now() / 1000);
			const signingKey = fromBase64url(identity.signingKey);

			const { ciphertext, nonce } = encryptMessage(kActe, plaintext, acteId, identity.sn_hex, timestamp);
			const sig = signMessage(signingKey, ciphertext, nonce, acteId, identity.sn_hex, timestamp);

			await sendMessage(
				token,
				acteId,
				toBase64url(ciphertext),
				toBase64url(nonce),
				toBase64url(sig),
				timestamp
			);
			// WS notification handles refresh; fallback if WS is not open
			if (!ws || ws.readyState !== WebSocket.OPEN) await loadMessages(lastSeq);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
			input = text;
		} finally {
			sending = false;
		}
	}

	function isNotaire() {
		return identity && acte && identity.sn_hex === acte.notaire_sn;
	}

	async function doAddParticipant() {
		const sn = newParticipantSn.trim();
		if (!sn || !identity || !token || !acte) return;
		addParticipantError = '';
		addingParticipant = true;
		try {
			// Validate participant exists
			await getIdentity(sn);

			// Sign SHA256(PARTICIPANT_DOMAIN_TAG || acte_uuid || participant_sn || grant_history)
			// Tag mirrors server::routes::participants::PARTICIPANT_DOMAIN_TAG (16+ bytes incl. trailing NUL).
			const payload = new Uint8Array([
				...new TextEncoder().encode('localpki-participant-v1\0'),
				...new TextEncoder().encode(acte.uuid),
				...new TextEncoder().encode(sn),
				grantHistory ? 1 : 0
			]);
			const hash = sha256(payload);
			const signingKey = fromBase64url(identity.signingKey);
			const sig = ed25519.sign(hash, signingKey);

			await addParticipant(token, acte.uuid, sn, grantHistory, toBase64url(sig));

			// Refresh acte to update participant list
			const updated = await getActe(token, acte.uuid);
			currentActe.set(updated);
			acte = updated;

			newParticipantSn = '';
			grantHistory = false;
			showAddParticipant = false;
		} catch (e) {
			addParticipantError = e instanceof Error ? e.message : String(e);
		} finally {
			addingParticipant = false;
		}
	}

	async function fetchMerkle() {
		if (!token) return;
		try {
			const resp = await getMerkleRoot(token, acteId);
			merkleRoot = resp.root;
			merkleLeaves = resp.leaves_count;
			merkleSignedAt = resp.en_signature ? resp.signed_at : null;
			showMerkle = true;
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	}

	function formatTime(ts: number) {
		return new Date(ts * 1000).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
	}

	function shortSn(sn: string) {
		return sn.slice(0, 8) + '…';
	}

	function isMe(sn: string) {
		return identity?.sn_hex === sn;
	}
</script>

<div class="flex flex-col h-screen bg-background">
	<!-- Header -->
	<div class="border-b px-4 py-3 flex items-center justify-between shrink-0">
		<div class="flex items-center gap-3">
			<Button variant="ghost" onclick={() => history.back()} class="text-muted-foreground p-1">←</Button>
			<div>
				<h1 class="font-semibold text-sm">{acte?.titre ?? 'Chargement…'}</h1>
				{#if acte}
					<p class="text-xs text-muted-foreground">{acte.parties.length} parties</p>
				{/if}
			</div>
		</div>
		<div class="flex gap-1">
			{#if isNotaire()}
				<Button variant="ghost" onclick={() => { showAddParticipant = !showAddParticipant; addParticipantError = ''; }} class="text-xs">
					+ Partie
				</Button>
			{/if}
			<Button variant="ghost" onclick={fetchMerkle} class="text-xs">Merkle</Button>
		</div>
	</div>

	<!-- Merkle panel -->
	{#if showMerkle}
		<div class="border-b bg-muted/50 px-4 py-2 text-xs">
			<div class="flex items-center justify-between mb-1">
				<span class="font-semibold uppercase tracking-wide text-[10px] text-muted-foreground">Journal de transparence (Merkle)</span>
				<button onclick={() => (showMerkle = false)} class="text-muted-foreground hover:text-foreground shrink-0">✕</button>
			</div>
			<div class="flex items-baseline gap-2">
				<span class="text-muted-foreground shrink-0">Racine :</span>
				<span class="font-mono truncate" title={merkleRoot ?? ''}>{merkleRoot ?? '(journal vide)'}</span>
			</div>
			<div class="flex items-center gap-3 mt-1 text-muted-foreground">
				<span>{merkleLeaves} message{merkleLeaves > 1 ? 's' : ''} scellé{merkleLeaves > 1 ? 's' : ''}</span>
				{#if merkleSignedAt}
					<span class="text-emerald-600 dark:text-emerald-400">● Racine signée par l'EN · {formatTime(merkleSignedAt)}</span>
				{/if}
			</div>
		</div>
	{/if}

	<!-- Add participant panel (notaire only) -->
	{#if showAddParticipant}
		<div class="border-b bg-muted/50 px-4 py-3 space-y-2">
			<p class="text-xs font-medium">Ajouter une partie</p>
			<div class="flex gap-2">
				<input
					type="text"
					bind:value={newParticipantSn}
					placeholder="SN hex de la partie (32 chars)"
					disabled={addingParticipant}
					onkeydown={(e) => e.key === 'Enter' && doAddParticipant()}
					class="flex-1 rounded-md border border-input bg-background px-3 py-1.5 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
				/>
				<Button onclick={doAddParticipant} disabled={addingParticipant || !newParticipantSn.trim()} class="text-xs h-8 px-3">
					{addingParticipant ? '…' : 'Ajouter'}
				</Button>
				<Button variant="ghost" onclick={() => (showAddParticipant = false)} class="text-xs h-8 px-2">✕</Button>
			</div>
			<label class="flex items-center gap-2 text-xs cursor-pointer">
				<input type="checkbox" bind:checked={grantHistory} disabled={addingParticipant} class="rounded" />
				Accès à l'historique des messages
			</label>
			{#if addParticipantError}
				<p class="text-xs text-destructive">{addParticipantError}</p>
			{/if}
		</div>
	{/if}

	<!-- Messages area -->
	<div class="flex-1 overflow-y-auto p-4 space-y-3">
		{#if loading}
			<div class="flex justify-center pt-12 text-muted-foreground text-sm">Chargement…</div>
		{:else if error}
			<div class="text-center pt-12">
				<p class="text-sm text-destructive">{error}</p>
				<Button variant="outline" onclick={initialize} class="mt-3">Réessayer</Button>
			</div>
		{:else if messages.length === 0}
			<div class="flex justify-center pt-12 text-muted-foreground text-sm">
				Aucun message — commencez la conversation.
			</div>
		{:else}
			{#each messages as msg (msg.id)}
				<div class="flex {isMe(msg.sender_sn) ? 'justify-end' : 'justify-start'}">
					<div
						class="max-w-xs lg:max-w-md rounded-2xl px-4 py-2 {isMe(msg.sender_sn)
							? 'bg-primary text-primary-foreground rounded-br-sm'
							: 'bg-muted rounded-bl-sm'}"
					>
						{#if !isMe(msg.sender_sn)}
							<p class="text-xs font-medium mb-1 opacity-70">{msg.display_name ?? shortSn(msg.sender_sn)}</p>
						{/if}

						{#if msg.text === null}
							<p class="text-xs italic opacity-60">[Déchiffrement impossible]</p>
						{:else if msg.sigValid === false}
							<!-- Signature invalide : K_send étant partagée par tous les participants,
							     la signature Ed25519 est la SEULE preuve de l'expéditeur. On ne
							     présente donc pas le contenu non vérifié comme un message normal —
							     il est mis en quarantaine derrière une action explicite. -->
							<div class="border border-red-500 bg-red-500/10 rounded p-2">
								<p class="text-xs font-medium text-red-400">⚠ Signature invalide — expéditeur non prouvé</p>
								<details class="mt-1">
									<summary class="text-xs cursor-pointer opacity-70">Afficher le contenu non vérifié</summary>
									<p class="text-sm opacity-60 mt-1">{msg.text}</p>
								</details>
							</div>
						{:else}
							<p class="text-sm">{msg.text}</p>
						{/if}

						<div class="flex items-center justify-end gap-1 mt-1">
							<!-- Signature indicator -->
							{#if msg.sigValid === true}
								<span class="text-xs opacity-60" title="Signature Ed25519 vérifiée">✓</span>
							{:else if msg.sigValid === false}
								<span class="text-xs text-red-400" title="Signature invalide">⚠</span>
							{/if}
							<span class="text-xs opacity-50">{formatTime(msg.sent_at)}</span>
						</div>
					</div>
				</div>
			{/each}
		{/if}
	</div>

	<!-- Input area -->
	<div class="border-t px-4 py-3 flex gap-2 shrink-0">
		<input
			type="text"
			bind:value={input}
			placeholder={kActe ? 'Votre message chiffré…' : 'Chargement des clés…'}
			disabled={!kActe || sending}
			onkeydown={(e) => e.key === 'Enter' && !e.shiftKey && send()}
			class="flex-1 rounded-full border border-input bg-background px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
		/>
		<Button onclick={send} disabled={!input.trim() || !kActe || sending} class="rounded-full px-4">
			{sending ? '…' : 'Envoyer'}
		</Button>
	</div>
</div>
