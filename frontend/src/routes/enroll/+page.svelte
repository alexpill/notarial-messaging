<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { ed25519 } from '@noble/curves/ed25519.js';
	import { generateKeypair, toBase64url, fromBase64url, toNumberArray } from '$lib/crypto/keys';
	import { prepareTbs, enrollSelf } from '$lib/api/client';
	import { identityStore } from '$lib/stores/identity';

	type Stage = 'form' | 'enrolling' | 'done';

	let name = $state('');
	let error = $state('');
	let step = $state('');
	let loading = $state(false);
	let stage: Stage = $state('form');
	let snHex = $state('');

	async function generateAndEnroll() {
		if (!name.trim()) {
			error = 'Veuillez saisir votre nom.';
			return;
		}
		error = '';
		loading = true;
		stage = 'enrolling';
		try {
			step = 'Génération de la paire de clés Ed25519…';
			const kp = generateKeypair();

			step = 'Construction du certificat LocalPKI…';
			const prep = await prepareTbs({
				subject_id: name.trim(),
				public_key: toNumberArray(kp.verifyingKey)
			});

			step = 'Auto-signature du certificat (SI)…';
			const derBytes = fromBase64url(prep.tbs_der_b64url);
			const si = ed25519.sign(derBytes, kp.signingKey);

			const certJson = {
				tbs: prep.tbs_json,
				signature_id: toNumberArray(si)
			};

			snHex = prep.sn_bytes.map((b) => b.toString(16).padStart(2, '0')).join('');

			step = "Enrôlement auprès de l'EN…";
			await enrollSelf(certJson);

			identityStore.save({
				sn_hex: snHex,
				signingKey: toBase64url(kp.signingKey),
				verifyingKey: toBase64url(kp.verifyingKey),
				name: name.trim(),
				cert_json: JSON.stringify(certJson)
			});

			stage = 'done';
			step = '';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
			stage = 'form';
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-background p-6">
	<Card.Root class="w-full max-w-md">
		{#if stage === 'form' || stage === 'enrolling'}
			<Card.Header>
				<Card.Title>Créer une identité LocalPKI</Card.Title>
				<Card.Description>
					Génère ta paire de clés et enrôle-toi directement auprès de l'EN.
				</Card.Description>
			</Card.Header>
			<Card.Content class="space-y-4">
				<div class="space-y-2">
					<label class="text-sm font-medium" for="name">Nom complet</label>
					<input
						id="name"
						type="text"
						bind:value={name}
						placeholder="Ex: Alice Martin, Bob Leroy…"
						class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
						disabled={loading}
						onkeydown={(e) => e.key === 'Enter' && generateAndEnroll()}
					/>
				</div>
				{#if step}
					<p class="text-xs text-muted-foreground">{step}</p>
				{/if}
				{#if error}
					<p class="text-sm text-destructive">{error}</p>
				{/if}
			</Card.Content>
			<Card.Footer class="flex gap-2">
				<Button onclick={generateAndEnroll} disabled={loading || !name.trim()} class="flex-1">
					{loading ? 'Enrôlement…' : "Générer et s'enrôler"}
				</Button>
				<Button variant="outline" href="/" disabled={loading}>Annuler</Button>
			</Card.Footer>
		{:else}
			<Card.Header>
				<Card.Title>Enrôlement réussi</Card.Title>
				<Card.Description>
					Ton identité est enregistrée. Tu peux maintenant te connecter.
				</Card.Description>
			</Card.Header>
			<Card.Content class="space-y-3">
				<div class="space-y-1">
					<p class="text-xs font-medium text-muted-foreground">Nom</p>
					<p class="text-sm font-medium">{name}</p>
				</div>
				<div class="space-y-1">
					<p class="text-xs font-medium text-muted-foreground">SN (identifiant)</p>
					<p class="font-mono text-xs break-all">{snHex}</p>
				</div>
				<p class="text-xs text-muted-foreground">
					Tes clés sont stockées en <code>sessionStorage</code>. Fermer cet onglet les efface.
				</p>
			</Card.Content>
			<Card.Footer class="flex gap-2">
				<Button class="flex-1" onclick={() => goto('/auth')}>Se connecter</Button>
				<Button variant="outline" href="/">Accueil</Button>
			</Card.Footer>
		{/if}
	</Card.Root>
</div>
