<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { Badge } from '$lib/components/ui/badge';
	import { ed25519 } from '@noble/curves/ed25519.js';
	import { generateKeypair, toBase64url, fromBase64url, toNumberArray } from '$lib/crypto/keys';
	import { prepareTbs, enrollSelf, authChallenge, authVerify } from '$lib/api/client';
	import { signAuthPop } from '$lib/crypto/auth';
	import { identityStore, tokenStore, isAuthenticated } from '$lib/stores/identity';

	type Role = 'notaire' | 'client';
	type StepState = 'pending' | 'active' | 'done' | 'error';

	const STEP_LABELS = [
		'Génération de la paire de clés Ed25519',
		'Construction du TBSCert (X.509v3)',
		'Auto-signature SI = Ed25519(sk, TBSCert_DER)',
		"Enrôlement auprès de l'EN",
		'Obtention du session token',
	];

	let identity = $state($identityStore);
	let authenticated = $state($isAuthenticated);
	let notaireName = $state('');
	let clientName = $state('');
	let enrollingRole = $state<Role | null>(null);
	let enrollDone = $state(false);
	let steps = $state<StepState[]>(STEP_LABELS.map(() => 'pending'));
	let enrollError = $state('');
	let snCopied = $state(false);
	// Client card: "PoC auto-enroll" ON = self-enroll (one click); OFF = generate a
	// cert to be endorsed by a notaire (real LocalPKI flow).
	let autoEnroll = $state(true);
	let certCopied = $state(false);

	onMount(() => {
		identityStore.init();
		tokenStore.init();
	});

	$effect(() => { identity = $identityStore; });
	$effect(() => { authenticated = $isAuthenticated; });

	function setStep(i: number, s: StepState) {
		steps = steps.map((v, idx) => (idx === i ? s : v));
	}

	async function startEnroll(role: Role, name: string) {
		if (!name.trim()) return;
		enrollError = '';
		enrollingRole = role;
		steps = STEP_LABELS.map(() => 'pending');

		try {
			setStep(0, 'active');
			const kp = generateKeypair();
			setStep(0, 'done');

			setStep(1, 'active');
			const prep = await prepareTbs({
				subject_id: name.trim(),
				public_key: toNumberArray(kp.verifyingKey)
			});
			setStep(1, 'done');

			setStep(2, 'active');
			const derBytes = fromBase64url(prep.tbs_der_b64url);
			const si = ed25519.sign(derBytes, kp.signingKey);
			const certJson = { tbs: prep.tbs_json, signature_id: toNumberArray(si) };
			setStep(2, 'done');

			setStep(3, 'active');
			const enrolled = await enrollSelf(certJson);
			setStep(3, 'done');

			setStep(4, 'active');
			const chal = await authChallenge();
			const popSig = signAuthPop(kp.signingKey, enrolled.serial_number, chal.challenge);
			const authResp = await authVerify(certJson, chal.challenge, popSig);
			if (!authResp.authenticated || !authResp.session_token)
				throw new Error("Échec d'authentification après enrôlement");
			tokenStore.save(authResp.session_token);
			identityStore.save({
				sn_hex: enrolled.serial_number,
				signingKey: toBase64url(kp.signingKey),
				verifyingKey: toBase64url(kp.verifyingKey),
				name: name.trim(),
				cert_json: JSON.stringify(certJson),
				role
			});
			setStep(4, 'done');
			enrollDone = true;
		} catch (e) {
			const active = steps.findIndex((s) => s === 'active');
			if (active >= 0) setStep(active, 'error');
			enrollError = e instanceof Error ? e.message : String(e);
			enrollingRole = null;
		}
	}

	// Client, "auto-enroll" OFF: generate keys + self-signed cert WITHOUT registering.
	// The identity is saved locally (no token); the client downloads the cert, a
	// notaire endorses it (POST /enroll via /notaire/enroller), then the client logs
	// in via /auth. sk stays in sessionStorage → same-session only (see PoC note).
	async function startRequestEndorsement(name: string) {
		if (!name.trim()) return;
		enrollError = '';
		try {
			const kp = generateKeypair();
			const prep = await prepareTbs({
				subject_id: name.trim(),
				public_key: toNumberArray(kp.verifyingKey)
			});
			const derBytes = fromBase64url(prep.tbs_der_b64url);
			const si = ed25519.sign(derBytes, kp.signingKey);
			const certJson = { tbs: prep.tbs_json, signature_id: toNumberArray(si) };
			const snHex = prep.sn_bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
			// No token saved → the {:else if identity} branch shows the pending state.
			identityStore.save({
				sn_hex: snHex,
				signingKey: toBase64url(kp.signingKey),
				verifyingKey: toBase64url(kp.verifyingKey),
				name: name.trim(),
				cert_json: JSON.stringify(certJson),
				role: 'client'
			});
		} catch (e) {
			enrollError = e instanceof Error ? e.message : String(e);
		}
	}

	function continueAfterEnroll() {
		const role = enrollingRole;
		enrollingRole = null;
		enrollDone = false;
		if (role === 'notaire') goto('/notaire/actes');
	}

	async function copySn() {
		if (!identity) return;
		await navigator.clipboard.writeText(identity.sn_hex);
		snCopied = true;
		setTimeout(() => (snCopied = false), 2000);
	}

	// Export the (public) cert JSON so a notaire can endorse it. sk is never included.
	function downloadCert() {
		if (!identity) return;
		const blob = new Blob([identity.cert_json], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `cert-${identity.sn_hex.slice(0, 8)}.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	async function copyCert() {
		if (!identity) return;
		await navigator.clipboard.writeText(identity.cert_json);
		certCopied = true;
		setTimeout(() => (certCopied = false), 2000);
	}

	function logout() {
		identityStore.clear();
		tokenStore.clear();
	}
</script>

<div class="min-h-screen bg-background flex flex-col items-center justify-center gap-8 p-8">

	<!-- Header -->
	<div class="text-center space-y-2">
		<Badge variant="secondary">Notariat français · LocalPKI</Badge>
		<h1 class="text-4xl font-bold tracking-tight">Messagerie notariale</h1>
		<p class="text-muted-foreground text-sm max-w-sm">
			Plateforme de messagerie chiffrée end-to-end pour les actes notariaux.
		</p>
	</div>

	{#if enrollingRole}
		<!-- ── Checklist d'enrôlement (priorité sur authenticated) ──────────── -->
		<Card.Root class="w-full max-w-sm">
			<Card.Header>
				<Card.Title class="capitalize">
					Entrée comme {enrollingRole}…
				</Card.Title>
				<Card.Description>Génération des clés et enrôlement en cours</Card.Description>
			</Card.Header>
			<Card.Content>
				<ol class="space-y-3">
					{#each STEP_LABELS as label, i}
						<li class="flex items-center gap-3 text-sm">
							{#if steps[i] === 'done'}
								<span class="flex-shrink-0 w-5 h-5 rounded-full bg-green-500 flex items-center justify-center">
									<svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
										<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
									</svg>
								</span>
								<span class="text-foreground">{label}</span>
							{:else if steps[i] === 'active'}
								<span class="flex-shrink-0 w-5 h-5 rounded-full bg-blue-500 flex items-center justify-center animate-pulse">
									<span class="w-2 h-2 bg-white rounded-full"></span>
								</span>
								<span class="text-foreground font-medium">{label}</span>
							{:else if steps[i] === 'error'}
								<span class="flex-shrink-0 w-5 h-5 rounded-full bg-red-500 flex items-center justify-center">
									<svg class="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
										<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
									</svg>
								</span>
								<span class="text-destructive">{label}</span>
							{:else}
								<span class="flex-shrink-0 w-5 h-5 rounded-full border-2 border-muted-foreground/30"></span>
								<span class="text-muted-foreground">{label}</span>
							{/if}
						</li>
					{/each}
				</ol>
				{#if enrollError}
					<p class="mt-4 text-sm text-destructive">{enrollError}</p>
				{/if}
			</Card.Content>
			{#if enrollDone}
				<Card.Footer>
					<Button class="w-full" onclick={continueAfterEnroll}>
						{enrollingRole === 'notaire' ? 'Accéder à mes actes →' : 'Continuer →'}
					</Button>
				</Card.Footer>
			{/if}
		</Card.Root>

	{:else if authenticated && identity}
		<!-- ── État connecté ────────────────────────────────────────────────── -->
		<div class="text-center space-y-1">
			<p class="font-medium">{identity.name}</p>
			<button
			onclick={copySn}
			title="Copier le SN"
			class="flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs transition-colors
				{snCopied
				? 'border-green-400 bg-green-50 text-green-700 dark:border-green-700 dark:bg-green-900/20 dark:text-green-400'
				: 'border-border bg-muted/40 text-muted-foreground hover:bg-muted hover:text-foreground'}"
		>
			<span class="font-mono">SN : {identity.sn_hex}</span>
			{#if snCopied}
				<svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
					<path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
				</svg>
			{:else}
				<svg class="w-3.5 h-3.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
					<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
					<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
				</svg>
			{/if}
		</button>
			<Badge variant="outline" class="text-xs capitalize">{identity.role ?? 'utilisateur'}</Badge>
		</div>

		<div class="grid grid-cols-1 gap-4 w-full max-w-xl
			{identity.role ? 'sm:max-w-xs sm:mx-auto' : 'sm:grid-cols-2'}">
			{#if !identity.role || identity.role === 'notaire'}
				<Card.Root class="hover:shadow-md transition-shadow">
					<Card.Header>
						<Card.Title>Espace notaire</Card.Title>
						<Card.Description>Gérez vos dossiers et suivez les actes.</Card.Description>
					</Card.Header>
					<Card.Footer class="flex flex-col gap-2">
						<Button class="w-full" href="/notaire/actes">Mes actes</Button>
						<Button variant="outline" class="w-full" href="/notaire/enroller">
							Enrôler un client
						</Button>
					</Card.Footer>
				</Card.Root>
			{/if}
			{#if !identity.role || identity.role === 'client'}
				<Card.Root class="hover:shadow-md transition-shadow">
					<Card.Header>
						<Card.Title>Espace client</Card.Title>
						<Card.Description>Consultez vos dossiers et échangez avec votre notaire.</Card.Description>
					</Card.Header>
					<Card.Footer>
						<Button class="w-full" href="/actes">Mes dossiers</Button>
					</Card.Footer>
				</Card.Root>
			{/if}
		</div>

		<Button variant="ghost" onclick={logout} class="text-xs text-muted-foreground">
			Se déconnecter
		</Button>

	{:else if identity}
		<!-- ── Identité générée, en attente d'endossement (switch OFF) ───────── -->
		<Card.Root class="w-full max-w-md">
			<Card.Header>
				<Card.Title>Certificat généré — en attente d'endossement</Card.Title>
				<Card.Description>
					Ton identité est créée localement mais pas encore enregistrée par l'EN.
				</Card.Description>
			</Card.Header>
			<Card.Content class="space-y-3 text-sm">
				<div class="space-y-1">
					<p class="font-medium">{identity.name}</p>
					<p class="font-mono text-xs text-muted-foreground break-all">SN : {identity.sn_hex}</p>
				</div>
				<ol class="list-decimal list-inside space-y-1 text-xs text-muted-foreground">
					<li>Télécharge ton certificat (ou copie-le).</li>
					<li>Transmets-le à ton notaire → « Enrôler un client ».</li>
					<li>Une fois endossé, reviens te connecter.</li>
				</ol>
				<div class="rounded-md border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
					Garde cet onglet ouvert : la clé privée vit en mémoire de session. La fermer
					avant de te connecter perdrait l'identité.
				</div>
				{#if enrollError}
					<p class="text-xs text-destructive">{enrollError}</p>
				{/if}
			</Card.Content>
			<Card.Footer class="flex flex-col gap-2">
				<div class="flex gap-2 w-full">
					<Button class="flex-1" onclick={downloadCert}>Télécharger mon certificat</Button>
					<Button variant="outline" onclick={copyCert}>{certCopied ? 'Copié ✓' : 'Copier'}</Button>
				</div>
				<Button variant="outline" class="w-full" href="/auth">Se connecter (après endossement)</Button>
				<Button variant="ghost" class="w-full text-xs text-muted-foreground" onclick={logout}>Annuler</Button>
			</Card.Footer>
		</Card.Root>

	{:else}
		<!-- ── Sélection du rôle ─────────────────────────────────────────────── -->
		<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 w-full max-w-xl">

			<!-- Carte notaire -->
			<Card.Root>
				<Card.Header>
					<Card.Title>Je suis notaire</Card.Title>
					<Card.Description>
						Créer et gérer des actes, inviter des clients.
					</Card.Description>
				</Card.Header>
				<Card.Content>
					<input
						type="text"
						bind:value={notaireName}
						placeholder="Votre nom complet"
						class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
						onkeydown={(e) => e.key === 'Enter' && startEnroll('notaire', notaireName)}
					/>
				</Card.Content>
				<Card.Footer>
					<Button
						class="w-full"
						onclick={() => startEnroll('notaire', notaireName)}
						disabled={!notaireName.trim()}
					>
						Entrer comme notaire
					</Button>
				</Card.Footer>
			</Card.Root>

			<!-- Carte client -->
			<Card.Root>
				<Card.Header>
					<Card.Title>Je suis client</Card.Title>
					<Card.Description>
						Consulter mes dossiers, échanger avec mon notaire.
					</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-3">
					<input
						type="text"
						bind:value={clientName}
						placeholder="Votre nom complet"
						class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
						onkeydown={(e) =>
							e.key === 'Enter' &&
							(autoEnroll ? startEnroll('client', clientName) : startRequestEndorsement(clientName))}
					/>
					<label class="flex items-start gap-2 text-xs cursor-pointer">
						<input type="checkbox" bind:checked={autoEnroll} class="mt-0.5 rounded" />
						<span class="text-muted-foreground">
							<span class="font-medium text-foreground">PoC : auto-enrôlement</span>
							{#if autoEnroll}
								— inscription immédiate, sans notaire (démo).
							{:else}
								— désactivé : génère ton certificat, un notaire devra l'endosser.
							{/if}
						</span>
					</label>
				</Card.Content>
				<Card.Footer>
					{#if autoEnroll}
						<Button
							variant="outline"
							class="w-full"
							onclick={() => startEnroll('client', clientName)}
							disabled={!clientName.trim()}
						>
							Entrer comme client
						</Button>
					{:else}
						<Button
							variant="outline"
							class="w-full"
							onclick={() => startRequestEndorsement(clientName)}
							disabled={!clientName.trim()}
						>
							Générer mon certificat
						</Button>
					{/if}
				</Card.Footer>
			</Card.Root>
		</div>

		{#if enrollError}
			<p class="text-sm text-destructive max-w-xl w-full text-center">{enrollError}</p>
		{/if}

		<!-- Badge PoC -->
		<div class="rounded-md border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30 px-4 py-3 text-xs text-amber-800 dark:text-amber-300 max-w-xl w-full space-y-1">
			<p class="font-semibold">PoC — simplifications intentionnelles</p>
			<ul class="list-disc list-inside space-y-0.5 text-amber-700 dark:text-amber-400">
				<li>Le self-enroll ci-dessus est un <strong>raccourci démo</strong> : l'identité est auto-déclarée, sans vérification.</li>
				<li>Flux réel : un notaire <strong>endosse</strong> la demande d'un client (Espace notaire → « Enrôler un client ») ; l'EN n'enregistre l'identité qu'avec cette caution signée.</li>
				<li>Le serveur ne distingue pas encore « notaire » de « client » : en production, le rôle notaire serait une habilitation provisionnée côté EN (registre des identités).</li>
				<li>Identité non persistante : les clés vivent en sessionStorage et sont effacées à la fermeture de l'onglet.</li>
			</ul>
		</div>
	{/if}
</div>
