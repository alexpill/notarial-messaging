<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import { identityStore, tokenStore } from '$lib/stores/identity';
	import { actesStore } from '$lib/stores/actes';
	import { listActes } from '$lib/api/client';

	let identity = $state($identityStore);
	let token = $state($tokenStore);
	let actes = $state($actesStore);
	let loading = $state(false);
	let error = $state('');

	$effect(() => {
		identity = $identityStore;
		token = $tokenStore;
		actes = $actesStore;
	});

	onMount(async () => {
		identityStore.init();
		tokenStore.init();
		identity = $identityStore;
		token = $tokenStore;

		if (!identity || !token) {
			goto('/login');
			return;
		}

		loading = true;
		try {
			const data = await listActes(token);
			actesStore.set(data);
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	});

	function formatDate(ts: number) {
		return new Date(ts * 1000).toLocaleDateString('fr-FR', {
			day: '2-digit',
			month: '2-digit',
			year: 'numeric'
		});
	}
</script>

<div class="min-h-screen bg-background p-6 max-w-4xl mx-auto">
	<div class="flex items-center justify-between mb-8">
		<div>
			<h1 class="text-2xl font-bold">Mes dossiers</h1>
			{#if identity}
				<p class="text-sm text-muted-foreground mt-1">{identity.name}</p>
			{/if}
		</div>
		<Button variant="outline" href="/">Accueil</Button>
	</div>

	{#if error}
		<p class="text-sm text-destructive mb-4">{error}</p>
	{/if}

	{#if loading}
		<p class="text-sm text-muted-foreground">Chargement des dossiers…</p>
	{:else if actes.length === 0}
		<Card.Root class="text-center py-12">
			<Card.Content>
				<p class="text-muted-foreground">Aucun dossier en cours.</p>
				<p class="text-sm text-muted-foreground mt-2">
					Votre notaire vous ajoutera à un dossier pour commencer les échanges.
				</p>
			</Card.Content>
		</Card.Root>
	{:else}
		<div class="space-y-3">
			{#each actes as acte}
				<Card.Root
					class="hover:shadow-md transition-shadow cursor-pointer"
					onclick={() => goto(`/actes/${acte.uuid}`)}
				>
					<Card.Header>
						<div class="flex items-start justify-between">
							<Card.Title class="text-base">{acte.titre}</Card.Title>
							<Badge variant="secondary">{acte.parties.length} parties</Badge>
						</div>
						<Card.Description class="font-mono text-xs">{acte.uuid.slice(0, 8)}…</Card.Description>
					</Card.Header>
					<Card.Footer class="text-xs text-muted-foreground">
						Créé le {formatDate(acte.created_at)}
					</Card.Footer>
				</Card.Root>
			{/each}
		</div>
	{/if}
</div>
