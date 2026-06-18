<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { identityStore, tokenStore } from '$lib/stores/identity';
	import { actesStore } from '$lib/stores/actes';
	import { createActe, getIdentity } from '$lib/api/client';

	let titre = $state('');
	let snInput = $state('');
	let parties = $state<string[]>([]);
	let partyName = $state('');
	let loading = $state(false);
	let loadingParty = $state(false);
	let error = $state('');
	let partyError = $state('');

	let identity = $state($identityStore);
	let token = $state($tokenStore);

	onMount(() => {
		identityStore.init();
		tokenStore.init();
		identity = $identityStore;
		token = $tokenStore;
		if (!identity || !token) goto('/');
	});

	$effect(() => {
		identity = $identityStore;
		token = $tokenStore;
	});

	async function addParty() {
		const sn = snInput.trim();
		if (!sn) return;
		if (parties.includes(sn)) {
			partyError = 'Ce SN est déjà dans la liste.';
			return;
		}
		partyError = '';
		loadingParty = true;
		try {
			await getIdentity(sn);
			parties = [...parties, sn];
			snInput = '';
		} catch {
			partyError = `SN introuvable : ${sn}`;
		} finally {
			loadingParty = false;
		}
	}

	function removeParty(sn: string) {
		parties = parties.filter((p) => p !== sn);
	}

	async function submit() {
		if (!titre.trim()) {
			error = 'Veuillez saisir un titre.';
			return;
		}
		if (!token || !identity) return;
		error = '';
		loading = true;
		try {
			const acte = await createActe(token, titre.trim(), parties);
			actesStore.update((list) => [acte, ...list]);
			goto(`/actes/${acte.uuid}`);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-screen bg-background p-6 max-w-2xl mx-auto">
	<div class="flex items-center gap-3 mb-8">
		<Button variant="ghost" href="/notaire/actes" class="text-muted-foreground">← Retour</Button>
		<h1 class="text-2xl font-bold">Nouvel acte</h1>
	</div>

	<Card.Root>
		<Card.Content class="space-y-5 pt-6">
			<div class="space-y-2">
				<label class="text-sm font-medium" for="titre">Titre de l'acte</label>
				<input
					id="titre"
					type="text"
					bind:value={titre}
					placeholder="Ex: Vente 12 rue de la Paix, Paris 75001"
					class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
					disabled={loading}
				/>
			</div>

			<div class="space-y-2">
				<label class="text-sm font-medium" for="sn">Ajouter une partie (SN hex)</label>
				<div class="flex gap-2">
					<input
						id="sn"
						type="text"
						bind:value={snInput}
						placeholder="Hex du serial number (32 chars)"
						class="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring"
						disabled={loadingParty || loading}
						onkeydown={(e) => e.key === 'Enter' && addParty()}
					/>
					<Button variant="outline" onclick={addParty} disabled={loadingParty || !snInput.trim()}>
						{loadingParty ? '…' : 'Ajouter'}
					</Button>
				</div>
				{#if partyError}
					<p class="text-xs text-destructive">{partyError}</p>
				{/if}
			</div>

			{#if parties.length > 0}
				<div class="space-y-2">
					<p class="text-sm font-medium">Parties ({parties.length})</p>
					<ul class="space-y-1">
						{#each parties as sn}
							<li class="flex items-center justify-between text-xs bg-muted rounded px-3 py-2">
								<span class="font-mono truncate">{sn}</span>
								<button
									onclick={() => removeParty(sn)}
									class="ml-2 text-muted-foreground hover:text-destructive shrink-0"
								>
									✕
								</button>
							</li>
						{/each}
					</ul>
					<p class="text-xs text-muted-foreground">
						Le notaire (vous) est ajouté automatiquement.
					</p>
				</div>
			{/if}

			{#if error}
				<p class="text-sm text-destructive">{error}</p>
			{/if}
		</Card.Content>
		<Card.Footer class="flex gap-2">
			<Button onclick={submit} disabled={loading || !titre.trim()} class="flex-1">
				{loading ? 'Création…' : "Créer l'acte"}
			</Button>
			<Button variant="outline" href="/notaire/actes" disabled={loading}>Annuler</Button>
		</Card.Footer>
	</Card.Root>
</div>
