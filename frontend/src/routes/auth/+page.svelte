<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { identityStore, tokenStore } from '$lib/stores/identity';
	import { authVerify, ApiError } from '$lib/api/client';
	import { onMount } from 'svelte';

	let identity = $state<typeof $identityStore>(null);
	let loading = $state(false);
	let error = $state('');
	let info = $state('');

	onMount(() => {
		identityStore.init();
		tokenStore.init();
	});

	identityStore.subscribe((v) => (identity = v));

	async function tryAuth() {
		if (!identity) {
			error = "Aucune identité locale — utilise « S'enroller » d'abord.";
			return;
		}
		error = '';
		info = '';
		loading = true;
		try {
			const certJson = JSON.parse(identity.cert_json);
			const resp = await authVerify(certJson);
			if (!resp.authenticated || !resp.session_token) {
				error =
					"Tu n'es pas encore enregistré côté EN. Attends qu'un notaire ait approuvé ta demande.";
				return;
			}
			tokenStore.save(resp.session_token);
			info = 'Connexion réussie. Redirection…';
			setTimeout(() => goto('/'), 600);
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) {
				error =
					"Identité non reconnue par l'EN. Un notaire doit d'abord valider ton enrôlement.";
			} else {
				error = e instanceof Error ? e.message : String(e);
			}
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-background p-6">
	<Card.Root class="w-full max-w-md">
		<Card.Header>
			<Card.Title>Se connecter</Card.Title>
			<Card.Description>
				Vérifie ton certificat local auprès de l'EN. Si un notaire t'a déjà
				enregistré, tu obtiens un session token.
			</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-3">
			{#if identity}
				<div class="space-y-1 text-sm">
					<p>{identity.name}</p>
					<p class="font-mono text-xs text-muted-foreground break-all">{identity.sn_hex}</p>
				</div>
			{:else}
				<p class="text-sm text-muted-foreground">
					Aucune identité locale détectée. Commence par « S'enroller ».
				</p>
			{/if}
			{#if error}
				<p class="text-sm text-destructive">{error}</p>
			{/if}
			{#if info}
				<p class="text-sm text-green-600">{info}</p>
			{/if}
		</Card.Content>
		<Card.Footer class="flex gap-2">
			{#if identity}
				<Button onclick={tryAuth} disabled={loading} class="flex-1">
					{loading ? 'Vérification…' : 'Se connecter'}
				</Button>
			{:else}
				<Button href="/enroll" class="flex-1">S'enroller</Button>
			{/if}
			<Button href="/" variant="outline" disabled={loading}>Retour</Button>
		</Card.Footer>
	</Card.Root>
</div>
