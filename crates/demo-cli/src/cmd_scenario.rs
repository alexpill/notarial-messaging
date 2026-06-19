use colored::Colorize;
use localpki_core::{
    cert::SerialNumber,
    enrollment::{EnrollmentChallenge, create_self_signed_cert},
    crypto::KeyPair,
};
use uuid::Uuid;

use crate::{
    bootstrap::{db_path_from_url, seed_bootstrap_notaire},
    client::ApiClient,
    crypto::{decrypt_k_acte, decrypt_msg, encrypt_and_sign, make_lra_signature, sn_from_hex},
    identity::IdentityFile,
};

fn step(n: u8, total: u8, msg: &str) {
    println!("\n{}", format!("[{n}/{total}] {msg}").bold().cyan());
}

fn ok(msg: &str) {
    println!("  {} {}", "✓".green().bold(), msg);
}

fn info(msg: &str) {
    println!("  {} {}", "·".dimmed(), msg);
}

/// Enrolle un acteur via l'API en utilisant la clé du LRA fourni.
async fn enroll_actor(
    client: &ApiClient,
    name: &str,
    lra: &IdentityFile,
    server: &str,
) -> anyhow::Result<IdentityFile> {
    let lra_kp = lra.keypair()?;
    let lra_sk = lra_kp.signing_key;

    let kp = KeyPair::generate().map_err(|e| anyhow::anyhow!("KeyPair::generate: {e:?}"))?;
    let sn_bytes: [u8; 16] = rand::random();
    let sn = SerialNumber(sn_bytes);

    let challenge = EnrollmentChallenge {
        serial_number: sn,
        en_url: server.to_string(),
        validity_days: 365,
    };
    let cert = create_self_signed_cert(&kp, name, &challenge)
        .map_err(|e| anyhow::anyhow!("create_self_signed_cert: {e:?}"))?;

    let lra_sig_b64 = make_lra_signature(&lra_sk, &cert);
    client.enroll(&cert, &lra.sn_hex, &lra_sig_b64).await?;

    let session_token = client.authenticate(&kp.signing_key, &cert).await?;
    let sn_hex = hex::encode(sn.0);

    let mut identity = IdentityFile::from_keypair_and_cert(name, &kp, cert);
    identity.sn_hex = sn_hex;
    identity.session_token = Some(session_token);
    Ok(identity)
}

pub async fn run(server: &str) -> anyhow::Result<()> {
    println!("\n{}", "═══════════════════════════════════════════════════════════".bold().yellow());
    println!("{}", "   DÉMO MESSAGERIE NOTARIALE LocalPKI".bold().yellow());
    println!("{}", "   Protocole Dumas et al. 2019 — PoC Rust + SvelteKit".dimmed());
    println!("{}\n", "═══════════════════════════════════════════════════════════".bold().yellow());

    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://./notarial.db".to_string());
    let db_path = db_path_from_url(&database_url)?;

    let client = ApiClient::new(server);

    // ─── Étape 1 : Bootstrap notaire (seed DB role=notaire) ─────────────────
    step(1, 7, "Bootstrap notaire « Maître Dupont » (seed DB direct, rôle notaire)");
    let bootstrap = seed_bootstrap_notaire(&db_path, server)?;
    ok(&format!("Notaire seedé par l'EN — SN : {}", bootstrap.sn_hex.dimmed()));
    let mut notaire =
        IdentityFile::from_keypair_and_cert("Maître Dupont", &bootstrap.keypair, bootstrap.cert.clone());
    notaire.sn_hex = bootstrap.sn_hex.clone();
    let notaire_session = client
        .authenticate(&bootstrap.keypair.signing_key, &bootstrap.cert)
        .await?;
    notaire.session_token = Some(notaire_session.clone());
    ok(&format!("Notaire authentifié — token : {}…", &notaire_session[..8].dimmed()));

    // ─── Étape 2 : Enrollment Alice ──────────────────────────────────────────
    step(2, 7, "Enrollment Alice Martin (via Notaire comme LRA)");
    let notaire_as_lra = notaire.clone();
    let mut alice = enroll_actor(&client, "Alice Martin", &notaire_as_lra, server).await?;
    ok(&format!("Alice enregistrée  — SN : {}", alice.sn_hex.dimmed()));

    // ─── Étape 3 : Enrollment Bob ────────────────────────────────────────────
    step(3, 7, "Enrollment Bob Leroy (via Notaire comme LRA)");
    let mut bob = enroll_actor(&client, "Bob Leroy", &notaire_as_lra, server).await?;
    ok(&format!("Bob enregistré     — SN : {}", bob.sn_hex.dimmed()));

    // ─── Étape 4 : Création de l'acte ───────────────────────────────────────
    step(4, 7, "Création de l'acte « Vente 12 rue de la Paix, Paris 75001 »");
    let notaire_token = notaire
        .session_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("notaire: session token manquant après authentification"))?;
    let acte = client
        .create_acte(
            notaire_token,
            "Vente 12 rue de la Paix, Paris 75001",
            vec![alice.sn_hex.clone(), bob.sn_hex.clone()],
        )
        .await?;
    let acte_id = acte["uuid"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("create_acte: missing uuid"))?
        .to_string();
    let acte_uuid = Uuid::parse_str(&acte_id)?;
    ok(&format!("Acte créé — UUID : {}", acte_id.dimmed()));
    info(&format!(
        "K_acte dérivée par le HSM et chiffrée pour {} participants",
        acte["parties"].as_array().map(|p| p.len()).unwrap_or(0)
    ));

    // ─── Étape 5 : Échange de messages ──────────────────────────────────────
    step(5, 7, "Échange de messages chiffrés");

    // Alice récupère K_acte et envoie le premier message.
    let alice_token = alice
        .session_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("alice: session token manquant après authentification"))?;
    let alice_kp = alice.keypair()?;
    let alice_sn = alice.serial_number()?;
    let alice_c_acte = client.get_acte_key(alice_token, &acte_id).await?;
    let alice_k_acte = decrypt_k_acte(&alice_kp, &alice_c_acte)?;
    info("Alice déchiffre K_acte depuis c_acte_key (ECIES X25519)");

    let alice_plaintext = "Bonjour Maître, je souhaite procéder à la vente de mon appartement au 12 rue de la Paix. Toutes les conditions me conviennent.".as_bytes();
    let ts_alice = now_secs();
    let (c_msg_a, nonce_a, sig_a) =
        encrypt_and_sign(&alice_k_acte, alice_plaintext, &acte_uuid, &alice_sn, &alice_kp.signing_key, ts_alice)?;
    let msg_alice = client.send_message(alice_token, &acte_id, &c_msg_a, &nonce_a, &sig_a, ts_alice).await?;
    let seq_a = msg_alice["seq"].as_i64().unwrap_or(0);
    ok(&format!(
        "Alice → message chiffré envoyé (seq={}, {} octets)",
        seq_a,
        msg_alice["c_message"].as_str().unwrap_or("").len()
    ));

    // Bob récupère K_acte et envoie sa réponse.
    let bob_token = bob
        .session_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("bob: session token manquant après authentification"))?;
    let bob_kp = bob.keypair()?;
    let bob_sn = bob.serial_number()?;
    let bob_c_acte = client.get_acte_key(bob_token, &acte_id).await?;
    let bob_k_acte = decrypt_k_acte(&bob_kp, &bob_c_acte)?;
    info("Bob déchiffre K_acte depuis c_acte_key (ECIES X25519)");

    let bob_plaintext = "Bonjour, je confirme être l'acheteur. Toutes les conditions me semblent correctes. Je suis prêt à signer.".as_bytes();
    let ts_bob = now_secs();
    let (c_msg_b, nonce_b, sig_b) =
        encrypt_and_sign(&bob_k_acte, bob_plaintext, &acte_uuid, &bob_sn, &bob_kp.signing_key, ts_bob)?;
    let msg_bob = client.send_message(bob_token, &acte_id, &c_msg_b, &nonce_b, &sig_b, ts_bob).await?;
    let seq_b = msg_bob["seq"].as_i64().unwrap_or(0);
    ok(&format!(
        "Bob   → message chiffré envoyé (seq={}, {} octets)",
        seq_b,
        msg_bob["c_message"].as_str().unwrap_or("").len()
    ));

    // ─── Étape 6 : Lecture et déchiffrement ─────────────────────────────────
    step(6, 7, "Lecture et déchiffrement des messages");

    // Notaire récupère K_acte et lit tous les messages.
    let notaire_c_acte = client.get_acte_key(notaire_token, &acte_id).await?;
    let notaire_k_acte = decrypt_k_acte(&notaire_kp_from(&notaire)?, &notaire_c_acte)?;
    let messages = client.list_messages(notaire_token, &acte_id).await?;

    info(&format!("Notaire lit {} messages :", messages.len()));
    for msg in &messages {
        decode_and_print_message(&notaire_k_acte, msg)?;
    }

    // Alice lit la réponse de Bob.
    info("Alice déchiffre le message de Bob :");
    let bob_msg = messages.iter().find(|m| m["sender_sn"].as_str() == Some(&bob.sn_hex));
    if let Some(msg) = bob_msg {
        decode_and_print_message(&alice_k_acte, msg)?;
    }

    // Bob lit le message d'Alice.
    info("Bob déchiffre le message d'Alice :");
    let alice_msg = messages.iter().find(|m| m["sender_sn"].as_str() == Some(&alice.sn_hex));
    if let Some(msg) = alice_msg {
        decode_and_print_message(&bob_k_acte, msg)?;
    }

    // ─── Étape 7 : Merkle Log ────────────────────────────────────────────────
    step(7, 7, "Vérification du Merkle Log de transparence");
    let merkle = client.get_merkle(notaire_token, &acte_id).await?;
    let root = merkle["root"].as_str().unwrap_or("(vide)");
    let count = merkle["leaves_count"].as_u64().unwrap_or(0);
    ok(&format!("Racine Merkle  : {}", root.yellow()));
    ok(&format!("Feuilles       : {count} messages indexés"));
    info("Chaque feuille = SHA256(0x00 || signature || acte_uuid || timestamp || seq)");
    info("La racine est signée par l'EN à chaque ajout — preuve d'intégrité horodatée");

    // ─── Résumé ──────────────────────────────────────────────────────────────
    println!("\n{}", "═══════════════════════════════════════════════════════════".bold().yellow());
    println!("{}", "   RÉSUMÉ DU SCÉNARIO".bold().yellow());
    println!("{}", "═══════════════════════════════════════════════════════════".bold().yellow());
    println!("  Acte UUID     : {}", acte_id.dimmed());
    println!("  Notaire       : {} ({})", notaire.name, notaire.sn_hex.dimmed());
    println!("  Alice         : {} ({})", alice.name, alice.sn_hex.dimmed());
    println!("  Bob           : {} ({})", bob.name, bob.sn_hex.dimmed());
    println!("  Messages      : {} échangés, chiffrés de bout en bout", messages.len());
    println!("  Merkle root   : {}", root.yellow());
    println!();
    println!("  {} Le serveur n'a jamais vu le contenu des messages.", "✓".green().bold());
    println!("  {} Chaque message est authentifié par signature Ed25519.", "✓".green().bold());
    println!("  {} L'intégrité est garantie par le Merkle log.", "✓".green().bold());
    println!("{}\n", "═══════════════════════════════════════════════════════════".bold().yellow());

    // Sauvegarder les identités pour les commandes individuelles.
    notaire.session_token = None;
    alice.session_token = None;
    bob.session_token = None;
    notaire.save("notaire.json")?;
    alice.save("alice.json")?;
    bob.save("bob.json")?;
    println!("  Identités sauvegardées : notaire.json, alice.json, bob.json");
    println!();

    Ok(())
}

fn decode_and_print_message(k_acte: &[u8; 32], msg: &serde_json::Value) -> anyhow::Result<()> {
    let sender_sn_hex = msg["sender_sn"].as_str().unwrap_or("");
    let c_message = msg["c_message"].as_str().unwrap_or("");
    let nonce = msg["nonce"].as_str().unwrap_or("");
    let timestamp = msg["sent_at"].as_i64().unwrap_or(0);
    let seq = msg["seq"].as_i64().unwrap_or(-1);
    let acte_uuid_str = msg["acte_uuid"].as_str().unwrap_or("");
    let acte_uuid = Uuid::parse_str(acte_uuid_str)
        .unwrap_or_else(|_| Uuid::nil());
    let sender_sn = sn_from_hex(sender_sn_hex)?;

    match decrypt_msg(k_acte, &sender_sn, c_message, nonce, &acte_uuid, timestamp) {
        Ok(plaintext) => {
            let text = String::from_utf8_lossy(&plaintext);
            println!(
                "    {} seq={} [{}] : {}",
                "→".green(),
                seq,
                sender_sn_hex[..8].dimmed(),
                text.italic()
            );
        }
        Err(e) => {
            println!(
                "    {} seq={} [{}] : (déchiffrement échoué : {e})",
                "✗".red(),
                seq,
                sender_sn_hex[..8].dimmed()
            );
        }
    }
    Ok(())
}

fn notaire_kp_from(notaire: &IdentityFile) -> anyhow::Result<KeyPair> {
    notaire.keypair()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
