<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { identityStore, tokenStore } from '$lib/stores/identity';
	import { fromBase64url } from '$lib/crypto/keys';
	import { endorseCert, type CertJson } from '$lib/crypto/enrollment';
	import { enroll } from '$lib/api/client';
	import { onMount } from 'svelte';

	let identity = $state<typeof $identityStore>(null);
	let token = $state<string | null>(null);
	let certInput = $state('');
	let parsedCert = $state<CertJson | null>(null);
	let parseError = $state('');
	let submitError = $state('');
	let loading = $state(false);
	let success = $state<{ sn: string; subject: string } | null>(null);

	onMount(() => {
		identityStore.init();
		tokenStore.init();
	});

	identityStore.subscribe((v) => (identity = v));
	tokenStore.subscribe((v) => (token = v));

	function tryParse() {
		parseError = '';
		parsedCert = null;
		if (!certInput.trim()) return;
		try {
			const parsed = JSON.parse(certInput) as CertJson;
			if (!parsed.tbs || !Array.isArray(parsed.signature_id)) {
				throw new Error('cert mal formé : champs `tbs` ou `signature_id` manquants');
			}
			if (!Array.isArray(parsed.tbs.serial_number) || parsed.tbs.serial_number.length !== 16) {
				throw new Error('cert mal formé : `tbs.serial_number` doit faire 16 octets');
			}
			parsedCert = parsed;
		} catch (e) {
			parseError = e instanceof Error ? e.message : String(e);
		}
	}

	$effect(() => {
		certInput;
		tryParse();
	});

	async function approve() {
		if (!parsedCert || !identity || !token) return;
		submitError = '';
		loading = true;
		try {
			const sk = fromBase64url(identity.signingKey);
			const lraSignature = endorseCert(parsedCert, sk);
			await enroll(parsedCert, identity.sn_hex, lraSignature);
			const sn = parsedCert.tbs.serial_number
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
			success = { sn, subject: parsedCert.tbs.subject_id };
			certInput = '';
		} catch (e) {
			submitError = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	function reset() {
		success = null;
		certInput = '';
		parsedCert = null;
		parseError = '';
		submitError = '';
	}
</script>

<div class="min-h-screen bg-background p-6">
	<div class="mx-auto max-w-2xl space-y-4">
		<Card.Root>
			<Card.Header>
				<Card.Title>Enrôler un client (rôle LRA)</Card.Title>
				<Card.Description>
					Tu agis ici comme LRA pour LocalPKI. Vérifie l'identité physique du client,
					colle le certificat qu'il t'a transmis, puis approuve. Ta clé privée signe
					l'endossement — l'EN ne stocke que le hash.
				</Card.Description>
			</Card.Header>

			{#if !identity || !token}
				<Card.Content>
					<p class="text-sm text-destructive">
						Tu dois être connecté comme notaire pour utiliser cette page.
					</p>
				</Card.Content>
				<Card.Footer>
					<Button href="/" variant="outline">Retour</Button>
				</Card.Footer>
			{:else if success}
				<Card.Content class="space-y-3">
					<div class="rounded-md border border-green-500/30 bg-green-500/10 p-4 text-sm">
						<p class="font-medium text-green-700 dark:text-green-300">
							✓ {success.subject} a été enrôlé
						</p>
						<p class="mt-1 text-xs text-muted-foreground">
							SN : <span class="font-mono">{success.sn}</span>
						</p>
						<p class="mt-2 text-xs">
							Tu peux confirmer au client qu'il peut se connecter avec sa session locale.
						</p>
					</div>
				</Card.Content>
				<Card.Footer class="flex gap-2">
					<Button onclick={reset} class="flex-1">Enrôler quelqu'un d'autre</Button>
					<Button href="/" variant="outline">Retour</Button>
				</Card.Footer>
			{:else}
				<Card.Content class="space-y-4">
					<div class="space-y-1">
						<p class="text-xs font-medium text-muted-foreground">Endossement par</p>
						<p class="text-sm">{identity.name}</p>
						<p class="font-mono text-xs text-muted-foreground break-all">{identity.sn_hex}</p>
					</div>

					<div class="space-y-2">
						<label for="cert" class="text-sm font-medium">
							Certificat du client (JSON)
						</label>
						<textarea
							id="cert"
							bind:value={certInput}
							rows="10"
							placeholder="Colle ici le JSON du certificat envoyé par le client"
							class="w-full rounded-md border border-input bg-background px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ring"
							disabled={loading}
						></textarea>
					</div>

					{#if parseError}
						<p class="text-sm text-destructive">{parseError}</p>
					{/if}

					{#if parsedCert}
						<div class="rounded-md border border-input bg-muted/50 p-3 text-xs space-y-1">
							<p>
								<span class="text-muted-foreground">Sujet :</span>
								<span class="font-medium">{parsedCert.tbs.subject_id}</span>
							</p>
							<p>
								<span class="text-muted-foreground">SN :</span>
								<span class="font-mono">
									{parsedCert.tbs.serial_number
										.map((b) => b.toString(16).padStart(2, '0'))
										.join('')}
								</span>
							</p>
							<p class="pt-1 text-muted-foreground italic">
								Vérifie en personne que cette identité est bien celle de la personne
								en face de toi avant d'approuver.
							</p>
						</div>
					{/if}

					{#if submitError}
						<p class="text-sm text-destructive">{submitError}</p>
					{/if}
				</Card.Content>
				<Card.Footer class="flex gap-2">
					<Button onclick={approve} disabled={!parsedCert || loading} class="flex-1">
						{loading ? 'Endossement en cours…' : 'Vérifié — approuver'}
					</Button>
					<Button href="/" variant="outline" disabled={loading}>Annuler</Button>
				</Card.Footer>
			{/if}
		</Card.Root>
	</div>
</div>
