mod bootstrap;
mod client;
mod cmd_scenario;
mod crypto;
mod identity;

use anyhow::Context;
use clap::{Parser, Subcommand};
use colored::Colorize;
use localpki_core::{
    cert::SerialNumber,
    enrollment::{EnrollmentChallenge, create_self_signed_cert},
    crypto::KeyPair,
};
use uuid::Uuid;

use client::ApiClient;
use crypto::{decrypt_k_acte, decrypt_msg, encrypt_and_sign, make_lra_signature, sn_from_hex};
use identity::IdentityFile;

#[derive(Parser)]
#[command(name = "demo-cli", about = "Démo messagerie notariale LocalPKI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Simuler l'enrollment d'un utilisateur (rôle LRA)
    Enroll {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "http://localhost:3000")]
        server: String,
        /// Fichier d'identité du LRA qui parraine cet enrollment
        #[arg(long)]
        lra: String,
        /// Fichier de sortie pour stocker l'identité (keypair + cert)
        #[arg(long, default_value = "identity.json")]
        output: String,
    },

    /// Commandes sur les actes
    Acte {
        #[command(subcommand)]
        action: ActeCommands,
    },

    /// Commandes sur les messages
    Message {
        #[command(subcommand)]
        action: MessageCommands,
    },

    /// Inspecter le Merkle log d'un acte
    Merkle {
        #[arg(long)]
        acte: String,
        /// Fichier d'identité de l'appelant (doit être participant de l'acte)
        #[arg(long)]
        identity: String,
        #[arg(long, default_value = "http://localhost:3000")]
        server: String,
    },

    /// Scénario complet automatique (enrollment + acte + messages + vérification Merkle)
    Scenario {
        #[arg(long, default_value = "http://localhost:3000")]
        server: String,
    },
}

#[derive(Subcommand)]
enum ActeCommands {
    /// Créer un acte notarial
    Create {
        #[arg(long)]
        title: String,
        /// Fichiers d'identité séparés par des virgules (ex: alice.json,bob.json)
        #[arg(long)]
        parties: String,
        /// Fichier d'identité du notaire (créateur de l'acte)
        #[arg(long)]
        notaire: String,
        #[arg(long, default_value = "http://localhost:3000")]
        server: String,
    },
}

#[derive(Subcommand)]
enum MessageCommands {
    /// Envoyer un message chiffré
    Send {
        #[arg(long)]
        acte: String,
        /// Fichier d'identité de l'émetteur (keypair + cert)
        #[arg(long)]
        identity: String,
        #[arg(long)]
        text: String,
        #[arg(long, default_value = "http://localhost:3000")]
        server: String,
    },
    /// Lire et déchiffrer les messages d'un acte
    List {
        #[arg(long)]
        acte: String,
        #[arg(long)]
        identity: String,
        #[arg(long, default_value = "http://localhost:3000")]
        server: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    match cli.command {
        Commands::Enroll { name, server, lra, output } => {
            cmd_enroll(&name, &server, &lra, &output).await?;
        }
        Commands::Acte { action: ActeCommands::Create { title, parties, notaire, server } } => {
            cmd_acte_create(&title, &parties, &notaire, &server).await?;
        }
        Commands::Message { action: MessageCommands::Send { acte, identity, text, server } } => {
            cmd_message_send(&acte, &identity, &text, &server).await?;
        }
        Commands::Message { action: MessageCommands::List { acte, identity, server } } => {
            cmd_message_list(&acte, &identity, &server).await?;
        }
        Commands::Merkle { acte, identity, server } => {
            cmd_merkle_inspect(&acte, &identity, &server).await?;
        }
        Commands::Scenario { server } => {
            cmd_scenario::run(&server).await?;
        }
    }

    Ok(())
}

async fn cmd_enroll(name: &str, server: &str, lra_path: &str, output: &str) -> anyhow::Result<()> {
    let lra = IdentityFile::load(lra_path)?;
    let lra_kp = lra.keypair()?;

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

    let lra_sig_b64 = make_lra_signature(&lra_kp.signing_key, &cert);
    let client = ApiClient::new(server);
    let sn_hex = client.enroll(&cert, &lra.sn_hex, &lra_sig_b64).await?;
    let session_token = client.authenticate(&cert).await?;

    let mut identity = IdentityFile::from_keypair_and_cert(name, &kp, cert);
    identity.sn_hex = sn_hex.clone();
    identity.session_token = Some(session_token);
    identity.save(output)?;

    println!("{} {} enregistré — SN : {}", "✓".green().bold(), name, sn_hex.dimmed());
    println!("  Identité sauvegardée dans : {output}");
    Ok(())
}

async fn cmd_acte_create(title: &str, parties: &str, notaire_path: &str, server: &str) -> anyhow::Result<()> {
    let notaire = IdentityFile::load(notaire_path)?;
    let token = get_or_refresh_token(&notaire, server).await?;

    let party_paths: Vec<&str> = parties.split(',').collect();
    let mut party_sns: Vec<String> = Vec::new();
    for path in &party_paths {
        let id = IdentityFile::load(path.trim())
            .with_context(|| format!("failed to load party identity: {path}"))?;
        party_sns.push(id.sn_hex);
    }

    let client = ApiClient::new(server);
    let acte = client.create_acte(&token, title, party_sns).await?;
    let uuid = acte["uuid"].as_str().unwrap_or("?");
    println!("{} Acte créé — UUID : {}", "✓".green().bold(), uuid.yellow());
    println!("  Titre : {title}");
    Ok(())
}

async fn cmd_message_send(acte: &str, identity_path: &str, text: &str, server: &str) -> anyhow::Result<()> {
    let identity = IdentityFile::load(identity_path)?;
    let token = get_or_refresh_token(&identity, server).await?;
    let kp = identity.keypair()?;
    let sn = identity.serial_number()?;

    let client = ApiClient::new(server);
    let c_acte_key_json = client.get_acte_key(&token, acte).await?;
    let k_acte = decrypt_k_acte(&kp, &c_acte_key_json)?;

    let acte_uuid = Uuid::parse_str(acte).context("acte: invalid UUID")?;
    let timestamp = now_secs();
    let (c_msg, nonce, sig) =
        encrypt_and_sign(&k_acte, text.as_bytes(), &acte_uuid, &sn, &kp.signing_key, timestamp)?;

    let resp = client.send_message(&token, acte, &c_msg, &nonce, &sig, timestamp).await?;
    let seq = resp["seq"].as_i64().unwrap_or(-1);
    println!("{} Message envoyé — seq={seq}", "✓".green().bold());
    Ok(())
}

async fn cmd_message_list(acte: &str, identity_path: &str, server: &str) -> anyhow::Result<()> {
    let identity = IdentityFile::load(identity_path)?;
    let token = get_or_refresh_token(&identity, server).await?;
    let kp = identity.keypair()?;

    let client = ApiClient::new(server);
    let c_acte_key_json = client.get_acte_key(&token, acte).await?;
    let k_acte = decrypt_k_acte(&kp, &c_acte_key_json)?;

    let acte_uuid = Uuid::parse_str(acte).context("acte: invalid UUID")?;
    let messages = client.list_messages(&token, acte).await?;

    println!("{} {} messages dans l'acte {}", "→".cyan(), messages.len(), &acte[..8].dimmed());
    for msg in &messages {
        let sender_sn_hex = msg["sender_sn"].as_str().unwrap_or("");
        let c_message = msg["c_message"].as_str().unwrap_or("");
        let nonce = msg["nonce"].as_str().unwrap_or("");
        let timestamp = msg["sent_at"].as_i64().unwrap_or(0);
        let seq = msg["seq"].as_i64().unwrap_or(-1);
        let sender_sn = sn_from_hex(sender_sn_hex)?;

        match decrypt_msg(&k_acte, &sender_sn, c_message, nonce, &acte_uuid, timestamp) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                println!("  seq={seq} [{}] : {}", sender_sn_hex[..8].dimmed(), text.italic());
            }
            Err(e) => {
                println!("  seq={seq} [{}] : (déchiffrement impossible : {e})", sender_sn_hex[..8].dimmed());
            }
        }
    }
    Ok(())
}

async fn cmd_merkle_inspect(acte: &str, identity_path: &str, server: &str) -> anyhow::Result<()> {
    let identity = IdentityFile::load(identity_path)?;
    let token = get_or_refresh_token(&identity, server).await?;

    let client = ApiClient::new(server);
    let merkle = client.get_merkle(&token, acte).await?;
    let root = merkle["root"].as_str().unwrap_or("(vide)");
    let count = merkle["leaves_count"].as_u64().unwrap_or(0);

    println!("{} Merkle Log — acte {}", "→".cyan(), &acte[..8].dimmed());
    println!("  Racine : {}", root.yellow());
    println!("  Feuilles : {count}");
    Ok(())
}

/// Utilise le token du fichier ou en obtient un nouveau via authenticate.
async fn get_or_refresh_token(identity: &IdentityFile, server: &str) -> anyhow::Result<String> {
    if let Some(token) = &identity.session_token {
        return Ok(token.clone());
    }
    let client = ApiClient::new(server);
    client.authenticate(&identity.cert).await
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
