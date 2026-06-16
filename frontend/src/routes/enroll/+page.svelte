<script lang="ts">
	import { goto } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { ed25519 } from '@noble/curves/ed25519.js';
	import { generateKeypair, toBase64url, fromBase64url, toNumberArray } from '$lib/crypto/keys';
	import { prepareTbs, lraSign, enroll, authVerify } from '$lib/api/client';
	import { identityStore, tokenStore } from '$lib/stores/identity';

	let name = $state('');
	let error = $state('');
	let step = $state('');
	let loading = $state(false);

	async function doEnroll() {
		if (!name.trim()) {
			error = 'Veuillez saisir votre nom.';
			return;
		}
		error = '';
		loading = true;
		try {
			// 1. Generate Ed25519 keypair
			step = 'Génération de la paire de clés Ed25519…';
			const kp = generateKeypair();

			// 2. Ask server to build TBSCert + DER
			step = 'Construction du certificat LocalPKI…';
			const prep = await prepareTbs({
				subject_id: name.trim(),
				public_key: toNumberArray(kp.verifyingKey)
			});

			// 3. Self-sign the DER to produce SI
			step = 'Auto-signature du certificat (SI)…';
			const derBytes = fromBase64url(prep.tbs_der_b64url);
			const si = ed25519.sign(derBytes, kp.signingKey);

			// 4. Build LocalPKICert JSON (Rust serde format)
			const certJson = {
				tbs: prep.tbs_json,
				signature_id: toNumberArray(si)
			};

			// 5. Get LRA signature from server Root LRA
			step = 'Signature LRA (simulation PoC)…';
			const lraResp = await lraSign(certJson);

			// 6. POST /enroll
			step = "Enregistrement auprès de l'EN…";
			await enroll(certJson, lraResp.lra_sn, lraResp.lra_signature);

			// 7. Authenticate
			step = 'Authentification…';
			const authResp = await authVerify(certJson);
			if (!authResp.authenticated || !authResp.session_token) {
				throw new Error('Authentification échouée après enrollment');
			}

			// 8. Persist identity
			identityStore.save({
				sn_hex: prep.sn_bytes.map((b) => b.toString(16).padStart(2, '0')).join(''),
				signingKey: toBase64url(kp.signingKey),
				verifyingKey: toBase64url(kp.verifyingKey),
				name: name.trim(),
				cert_json: JSON.stringify(certJson)
			});
			tokenStore.save(authResp.session_token);

			step = 'Enrollment réussi !';
			goto('/');
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-background p-6">
	<Card.Root class="w-full max-w-md">
		<Card.Header>
			<Card.Title>Enrollment LocalPKI</Card.Title>
			<Card.Description>
				Génération de votre paire de clés Ed25519 et enregistrement auprès de l'EN.
			</Card.Description>
		</Card.Header>
		<Card.Content class="space-y-4">
			<div class="space-y-2">
				<label class="text-sm font-medium" for="name">Nom complet</label>
				<input
					id="name"
					type="text"
					bind:value={name}
					placeholder="Ex: Maître Dupont, Alice Martin…"
					class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
					disabled={loading}
					onkeydown={(e) => e.key === 'Enter' && doEnroll()}
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
			<Button onclick={doEnroll} disabled={loading || !name.trim()} class="flex-1">
				{loading ? 'Enrollment en cours…' : "S'enroller"}
			</Button>
			<Button variant="outline" href="/" disabled={loading}>Annuler</Button>
		</Card.Footer>
	</Card.Root>
</div>
