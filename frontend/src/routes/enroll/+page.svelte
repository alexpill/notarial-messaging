<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { ed25519 } from '@noble/curves/ed25519.js';
	import { generateKeypair, toBase64url, fromBase64url, toNumberArray } from '$lib/crypto/keys';
	import { prepareTbs } from '$lib/api/client';
	import { identityStore } from '$lib/stores/identity';

	type Stage = 'form' | 'ready';

	let name = $state('');
	let error = $state('');
	let step = $state('');
	let loading = $state(false);
	let stage: Stage = $state('form');
	let certJsonText = $state('');
	let snHex = $state('');
	let copied = $state(false);

	async function generateRequest() {
		if (!name.trim()) {
			error = 'Veuillez saisir votre nom.';
			return;
		}
		error = '';
		loading = true;
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
			certJsonText = JSON.stringify(certJson, null, 2);

			// Persist keys + cert locally so the user can come back and authenticate
			// once a notaire has approved them server-side.
			identityStore.save({
				sn_hex: snHex,
				signingKey: toBase64url(kp.signingKey),
				verifyingKey: toBase64url(kp.verifyingKey),
				name: name.trim(),
				cert_json: JSON.stringify(certJson)
			});

			stage = 'ready';
			step = '';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	async function copyCert() {
		try {
			await navigator.clipboard.writeText(certJsonText);
			copied = true;
			setTimeout(() => (copied = false), 2000);
		} catch {
			error = 'Impossible de copier — sélectionne le texte manuellement.';
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-background p-6">
	<Card.Root class="w-full max-w-2xl">
		{#if stage === 'form'}
			<Card.Header>
				<Card.Title>Demander un enrôlement LocalPKI</Card.Title>
				<Card.Description>
					Cette page génère ta paire de clés Ed25519 et ton certificat auto-signé.
					Tu devras ensuite transmettre le certificat à un notaire qui validera ton
					identité en personne avant de t'enregistrer auprès de l'EN.
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
						onkeydown={(e) => e.key === 'Enter' && generateRequest()}
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
				<Button onclick={generateRequest} disabled={loading || !name.trim()} class="flex-1">
					{loading ? 'Génération…' : 'Générer ma demande'}
				</Button>
				<Button variant="outline" href="/" disabled={loading}>Annuler</Button>
			</Card.Footer>
		{:else}
			<Card.Header>
				<Card.Title>Demande prête</Card.Title>
				<Card.Description>
					Tes clés ont été enregistrées localement dans ce navigateur. Transmets ce
					certificat à un notaire (en personne, par copier-coller, ou par un canal
					hors-bande de ton choix).
				</Card.Description>
			</Card.Header>
			<Card.Content class="space-y-4">
				<div class="space-y-1">
					<p class="text-xs font-medium text-muted-foreground">Ton SN (identifiant)</p>
					<p class="font-mono text-sm break-all">{snHex}</p>
				</div>
				<div class="space-y-1">
					<p class="text-xs font-medium text-muted-foreground">Certificat à transmettre</p>
					<textarea
						readonly
						rows="10"
						class="w-full rounded-md border border-input bg-muted px-3 py-2 text-xs font-mono"
						value={certJsonText}
					></textarea>
				</div>
				<div class="rounded-md border border-input bg-muted/50 p-3 text-xs text-muted-foreground space-y-1">
					<p class="font-medium">Prochaines étapes :</p>
					<ol class="list-decimal list-inside space-y-1">
						<li>Va voir un notaire enrôlé avec une pièce d'identité.</li>
						<li>Donne-lui ce certificat (copier-coller, fichier, QR plus tard).</li>
						<li>Il vérifiera ton identité physique puis t'enregistrera auprès de l'EN.</li>
						<li>Reviens ensuite ici et clique sur « Se connecter ».</li>
					</ol>
				</div>
				{#if error}
					<p class="text-sm text-destructive">{error}</p>
				{/if}
			</Card.Content>
			<Card.Footer class="flex gap-2">
				<Button onclick={copyCert} class="flex-1">
					{copied ? 'Copié ✓' : 'Copier le certificat'}
				</Button>
				<Button variant="outline" href="/">Retour</Button>
			</Card.Footer>
		{/if}
	</Card.Root>
</div>
