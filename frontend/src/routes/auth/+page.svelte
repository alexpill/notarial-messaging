<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { identityStore, tokenStore } from '$lib/stores/identity';
	import { authChallenge, authVerify, ApiError } from '$lib/api/client';
	import { signAuthPop } from '$lib/crypto/auth';
	import { fromBase64url } from '$lib/crypto/keys';
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
			error = "Aucune identité locale — utilisez « S'enrôler » d'abord.";
			return;
		}
		error = '';
		info = '';
		loading = true;
		try {
			const certJson = JSON.parse(identity.cert_json);
			const chal = await authChallenge();
			const signingKey = fromBase64url(identity.signingKey);
			const popSig = signAuthPop(signingKey, identity.sn_hex, chal.challenge);
			const resp = await authVerify(certJson, chal.challenge, popSig);
			if (!resp.authenticated || !resp.session_token) {
				error =
					"Vous n'êtes pas encore enregistré côté EN. Attendez qu'un notaire ait approuvé votre demande.";
				return;
			}
			tokenStore.save(resp.session_token);
			info = 'Connexion réussie. Redirection…';
			setTimeout(() => goto('/'), 600);
		} catch (e) {
			if (e instanceof ApiError && e.status === 401) {
				error =
					"Identité non reconnue par l'EN. Un notaire doit d'abord valider votre enrôlement.";
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
				Vérifiez votre certificat local auprès de l'EN. Si un notaire vous a déjà
				enregistré, vous obtenez un session token.
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
					Aucune identité locale détectée. Commencez par « S'enrôler ».
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
				<Button href="/enroll" class="flex-1">S'enrôler</Button>
			{/if}
			<Button href="/" variant="outline" disabled={loading}>Retour</Button>
		</Card.Footer>
	</Card.Root>
</div>
