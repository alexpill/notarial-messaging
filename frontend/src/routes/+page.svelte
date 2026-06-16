<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '$lib/components/ui/button';
	import { Badge } from '$lib/components/ui/badge';
	import * as Card from '$lib/components/ui/card';
	import { identityStore, tokenStore, isAuthenticated } from '$lib/stores/identity';

	let identity = $state($identityStore);
	let authenticated = $state($isAuthenticated);

	onMount(() => {
		identityStore.init();
		tokenStore.init();
	});

	$effect(() => {
		identity = $identityStore;
		authenticated = $isAuthenticated;
	});

	function logout() {
		identityStore.clear();
		tokenStore.clear();
	}
</script>

<div class="min-h-screen bg-background flex flex-col items-center justify-center gap-10 p-8">
	<div class="text-center space-y-3">
		<Badge variant="secondary">Notariat français · LocalPKI</Badge>
		<h1 class="text-4xl font-bold tracking-tight">Messagerie notariale</h1>
		<p class="text-muted-foreground max-w-sm">
			Plateforme de messagerie sécurisée end-to-end pour les actes notariaux.
		</p>
	</div>

	{#if authenticated && identity}
		<div class="text-center space-y-1">
			<p class="text-sm font-medium">{identity.name}</p>
			<p class="text-xs text-muted-foreground font-mono">SN : {identity.sn_hex}</p>
		</div>
		<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 w-full max-w-xl">
			<Card.Root class="hover:shadow-md transition-shadow cursor-pointer">
				<Card.Header>
					<Card.Title>Espace notaire</Card.Title>
					<Card.Description
						>Gérez vos dossiers, enrollez vos clients, suivez les actes.</Card.Description
					>
				</Card.Header>
				<Card.Footer class="flex flex-col gap-2">
					<Button class="w-full" href="/notaire/actes">Accéder</Button>
					<Button variant="outline" class="w-full" href="/notaire/enroller">
						Enrôler un client
					</Button>
				</Card.Footer>
			</Card.Root>

			<Card.Root class="hover:shadow-md transition-shadow cursor-pointer">
				<Card.Header>
					<Card.Title>Espace client</Card.Title>
					<Card.Description
						>Consultez vos dossiers et échangez avec votre notaire.</Card.Description
					>
				</Card.Header>
				<Card.Footer>
					<Button variant="outline" class="w-full" href="/actes">Mes dossiers</Button>
				</Card.Footer>
			</Card.Root>
		</div>
		<Button variant="ghost" onclick={logout} class="text-xs text-muted-foreground">
			Se déconnecter
		</Button>
	{:else}
		<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 w-full max-w-xl">
			<Card.Root class="hover:shadow-md transition-shadow cursor-pointer">
				<Card.Header>
					<Card.Title>Nouvelle identité</Card.Title>
					<Card.Description>
						Génère ta paire de clés et ton certificat. Un notaire devra ensuite valider
						ton identité physiquement avant de t'enregistrer.
					</Card.Description>
				</Card.Header>
				<Card.Footer>
					<Button class="w-full" href="/enroll">S'enroller</Button>
				</Card.Footer>
			</Card.Root>

			<Card.Root class="hover:shadow-md transition-shadow cursor-pointer">
				<Card.Header>
					<Card.Title>Se connecter</Card.Title>
					<Card.Description>
						Déjà enrôlé ? Connecte-toi avec ton certificat local stocké en
						sessionStorage.
					</Card.Description>
				</Card.Header>
				<Card.Footer>
					<Button variant="outline" class="w-full" href="/auth">Se connecter</Button>
				</Card.Footer>
			</Card.Root>
		</div>
		<p class="text-xs text-muted-foreground max-w-sm text-center leading-relaxed">
			PoC — les clés sont stockées en <code>sessionStorage</code> : fermer l'onglet efface
			l'identité. Un nouvel enrollment est nécessaire à chaque session.
		</p>
	{/if}
</div>
