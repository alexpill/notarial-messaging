# Architecture logicielle — Workspace Rust + SvelteKit

> Document complémentaire à `ARCHITECTURE.md` (architecture cryptographique et protocoles).  
> Ce document couvre la structure du code, les responsabilités de chaque crate,
> et les conventions de développement.

---

## Table des matières

1. [Vue d'ensemble du workspace](#1-vue-densemble-du-workspace)
2. [Crate `localpki-core`](#2-crate-localpki-core)
3. [Crate `messaging-crypto`](#3-crate-messaging-crypto)
4. [Crate `server`](#4-crate-server)
5. [Crate `demo-cli`](#5-crate-demo-cli)
6. [Frontend SvelteKit](#6-frontend-sveltekit)
7. [Workspace `Cargo.toml`](#7-workspace-cargotoml)
8. [Conventions et règles de développement](#8-conventions-et-règles-de-développement)

---

## 1. Vue d'ensemble du workspace

```
notarial-messaging/
├── Cargo.toml                     # workspace root
├── ARCHITECTURE.md                # architecture crypto et protocoles
├── SOFTWARE_ARCHITECTURE.md       # ce document
├── README.md
├── CLAUDE.md                      # instructions pour Claude Code
├── .env.example
├── crates/
│   ├── localpki-core/             # lib — protocoles LocalPKI (papier)
│   ├── messaging-crypto/          # lib — crypto messagerie
│   ├── server/                    # bin — Axum (EN + messagerie)
│   └── demo-cli/                  # bin — démonstration CLI
└── frontend/                      # SvelteKit — hors workspace Rust
    ├── package.json
    └── src/
```

### Dépendances entre crates

```
localpki-core
    ↑
messaging-crypto
    ↑           ↑
  server      demo-cli
```

Les deux bibliothèques (`localpki-core`, `messaging-crypto`) sont des crates pures —
aucune dépendance réseau, aucun I/O. Elles peuvent être testées et utilisées
indépendamment du serveur.

---

## 2. Crate `localpki-core`

**Responsabilité** : implémenter fidèlement les protocoles du papier LocalPKI
(Dumas et al., 2019) — enregistrement, authentification, révocation.
Aucune logique applicative, aucun I/O.

### Structure des fichiers

```
crates/localpki-core/
├── Cargo.toml
└── src/
    ├── lib.rs              # exports publics
    ├── cert.rs             # structures TBSCert, LocalPKICert, SerialNumber, SI
    ├── crypto.rs           # génération de clés, conversions Ed25519↔X25519
    ├── enrollment.rs       # Algorithme 1 du papier (Registration)
    ├── authentication.rs   # Algorithmes 2 et 3 (mode privé)
    ├── revocation.rs       # Algorithme 4
    └── error.rs            # LocalPkiError
```

### Types publics principaux

```rust
// cert.rs
pub struct TBSCert {
    pub subject_id: String,
    pub public_key: ed25519_dalek::VerifyingKey,
    pub serial_number: SerialNumber,
    pub validity: Validity,
    pub en_url: String,
}

pub struct LocalPKICert {
    pub tbs: TBSCert,
    pub signature_id: SignatureId,  // SI = Sign(sk, Hash(TBSCert_DER))
}

pub struct SerialNumber(pub [u8; 16]);

pub struct SignatureId(pub ed25519_dalek::Signature);

// crypto.rs
pub struct KeyPair {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self;
    pub fn to_x25519_static_secret(&self) -> x25519_dalek::StaticSecret;
    pub fn to_x25519_public(&self) -> x25519_dalek::PublicKey;
}
```

### Fonctions publiques principales

```rust
// enrollment.rs
/// Côté utilisateur : créer le TBSCert auto-signé (étapes 1-5 de l'Algo 1)
pub fn create_self_signed_cert(
    keypair: &KeyPair,
    subject_id: &str,
    serial_number: SerialNumber,
    en_url: &str,
    validity_days: u32,
) -> Result<LocalPKICert, LocalPkiError>;

/// Côté LRA : vérifier la SI (étape 7 de l'Algo 1 — PoK de sk)
pub fn verify_signature_id(cert: &LocalPKICert) -> Result<(), LocalPkiError>;

/// Côté EN : enregistrer (SN, SI) en base
pub fn register_cert(
    cert: &LocalPKICert,
    lra_signature: &ed25519_dalek::Signature,
    lra_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<RegistrationEntry, LocalPkiError>;

// authentication.rs
/// Côté verifier : construire une AuthRequest (mode privé, Algo 2)
pub fn build_auth_request(cert: &LocalPKICert) -> AuthRequest;

/// Côté EN : répondre à une AuthRequest
pub fn respond_to_auth_request(
    request: &AuthRequest,
    database: &dyn EnDatabase,
    en_signing_key: &ed25519_dalek::SigningKey,
) -> AuthResponse;

/// Côté verifier : vérifier la réponse EN
pub fn verify_auth_response(
    response: &AuthResponse,
    en_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<AuthStatus, LocalPkiError>;

// revocation.rs
pub fn build_revocation_request(
    cert: &LocalPKICert,
    signing_key: &ed25519_dalek::SigningKey,
) -> RevocationRequest;
```

### Dépendances Cargo

```toml
[dependencies]
ed25519-dalek = { workspace = true, features = ["pkcs8", "pem", "zeroize", "rand_core", "serde"] }
x25519-dalek  = { workspace = true, features = ["static_secrets", "zeroize"] }
rcgen         = "0.13"
x509-cert     = { version = "0.2", features = ["builder"] }
sha2          = { workspace = true }
hkdf          = { workspace = true }
aes-gcm       = "0.10"
rand          = { workspace = true }
serde         = { workspace = true }
zeroize       = { workspace = true, features = ["derive"] }
thiserror     = { workspace = true }
time          = "0.3"
```

---

## 3. Crate `messaging-crypto`

**Responsabilité** : dérivation des clés de session, chiffrement/déchiffrement des
messages, signature, construction du Merkle log. Dépend de `localpki-core` pour
les types de clés — aucune autre dépendance externe métier.

### Structure des fichiers

```
crates/messaging-crypto/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── keys.rs       # dérivation K_acte, K_send, ECIES
    ├── messages.rs   # chiffrement AES-256-GCM, signature Ed25519
    ├── merkle.rs     # transparency log append-only
    └── error.rs      # CryptoError
```

### Fonctions publiques principales

```rust
// keys.rs

/// Dériver K_acte depuis K_master et l'UUID de l'acte
/// K_acte = HKDF-SHA256(K_master, "notariat-msg-v1" || acte_uuid)
pub fn derive_k_acte(k_master: &[u8; 32], acte_uuid: &uuid::Uuid) -> [u8; 32];

/// Dériver la clé d'envoi d'un participant
/// K_send = HKDF-SHA256(K_acte, "send" || sn)
pub fn derive_k_send(k_acte: &[u8; 32], sn: &SerialNumber) -> [u8; 32];

/// Chiffrer K_acte pour un participant via ECIES (X25519 + AES-256-GCM)
pub fn ecies_encrypt(
    recipient_x25519_pk: &x25519_dalek::PublicKey,
    plaintext: &[u8],
) -> Result<EciesCiphertext, CryptoError>;

/// Déchiffrer K_acte reçu du serveur
pub fn ecies_decrypt(
    recipient_x25519_sk: &x25519_dalek::StaticSecret,
    ciphertext: &EciesCiphertext,
) -> Result<Vec<u8>, CryptoError>;

// messages.rs

/// Chiffrer un message côté client
/// C_M = AES-256-GCM(K_send, M, nonce, AAD = acte_uuid || timestamp || sn)
pub fn encrypt_message(
    k_send: &[u8; 32],
    plaintext: &[u8],
    acte_uuid: &uuid::Uuid,
    sender_sn: &SerialNumber,
    timestamp: i64,
) -> Result<EncryptedMessage, CryptoError>;

/// Déchiffrer un message reçu
pub fn decrypt_message(
    k_acte: &[u8; 32],
    sender_sn: &SerialNumber,
    encrypted: &EncryptedMessage,
) -> Result<Vec<u8>, CryptoError>;

/// Signer un message (non-répudiation)
/// SIG = Ed25519.Sign(sk, Hash(M || acte_uuid || timestamp || sn))
pub fn sign_message(
    signing_key: &ed25519_dalek::SigningKey,
    plaintext: &[u8],
    acte_uuid: &uuid::Uuid,
    sender_sn: &SerialNumber,
    timestamp: i64,
) -> ed25519_dalek::Signature;

/// Vérifier la signature d'un message
pub fn verify_message_signature(
    verifying_key: &ed25519_dalek::VerifyingKey,
    plaintext: &[u8],
    acte_uuid: &uuid::Uuid,
    sender_sn: &SerialNumber,
    timestamp: i64,
    signature: &ed25519_dalek::Signature,
) -> Result<(), CryptoError>;

// merkle.rs

pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

impl MerkleLog {
    pub fn new() -> Self;

    /// Ajouter une feuille : Hash(SIG || acte_uuid || timestamp || seq)
    pub fn add_leaf(
        &mut self,
        signature: &ed25519_dalek::Signature,
        acte_uuid: &uuid::Uuid,
        timestamp: i64,
        seq: u64,
    ) -> [u8; 32];  // retourne le hash de la feuille

    /// Calculer la racine courante de l'arbre
    pub fn root(&self) -> Option<[u8; 32]>;

    /// Générer une preuve d'inclusion pour la feuille i
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof>;

    /// Vérifier une preuve d'inclusion
    pub fn verify_proof(
        root: &[u8; 32],
        leaf: &[u8; 32],
        proof: &MerkleProof,
    ) -> bool;
}
```

### Dépendances Cargo

```toml
[dependencies]
localpki-core = { path = "../localpki-core" }
aes-gcm       = "0.10"
hkdf          = { workspace = true }
sha2          = { workspace = true }
rand          = { workspace = true }
serde         = { workspace = true }
zeroize       = { workspace = true, features = ["derive"] }
uuid          = { workspace = true }
thiserror     = { workspace = true }
ed25519-dalek = { workspace = true, features = ["zeroize"] }
x25519-dalek  = { workspace = true, features = ["zeroize", "static_secrets"] }
```

---

## 4. Crate `server`

**Responsabilité** : serveur HTTP Axum jouant simultanément le rôle d'EN LocalPKI
(registre d'identités) et de serveur de messagerie (distribution des clés,
stockage chiffré, relay WebSocket, Merkle log). Inclut une simulation HSM pour
le PoC.

### Structure des fichiers

```
crates/server/
├── Cargo.toml
└── src/
    ├── main.rs
    ├── config.rs             # chargement .env, AppConfig
    ├── state.rs              # AppState partagé (DB, HSM, etc.)
    ├── error.rs              # AppError → réponses HTTP
    ├── hsm.rs                # simulation HSM (K_master en mémoire chiffrée)
    ├── middleware.rs         # extracteurs d'authentification Axum
    ├── utils.rs              # helpers partagés (encodage, conversion)
    ├── tests.rs              # tests d'intégration (base SQLite in-memory)
    ├── db.rs                 # pool Diesel + helpers de connexion
    ├── db/
    │   ├── models.rs         # structs Diesel (Queryable, Insertable)
    │   └── schema.rs         # schéma généré par diesel print-schema
    ├── en.rs                 # module Electronic Notary
    ├── en/
    │   ├── registry.rs       # CRUD (SN, SI) + vérification
    │   └── auth.rs           # réponses AuthRequest (mode privé)
    ├── routes.rs             # assemblage du Router Axum
    └── routes/
        ├── enrollment.rs     # POST /enroll
        ├── authentication.rs # POST /auth/verify
        ├── actes.rs          # POST /actes, GET /actes/:id
        ├── participants.rs   # POST /actes/:id/participants
        ├── messages.rs       # POST /actes/:id/messages, GET
        └── ws.rs             # WebSocket /ws/:acte_id
```

### Routes HTTP

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/enroll/prepare` | Génère SN + challenge pour un futur enrollment |
| `POST` | `/enroll` | LRA enregistre (SN, SI) pour un utilisateur |
| `POST` | `/auth/verify` | Vérification certificat LocalPKI (mode privé) |
| `GET` | `/identity/:sn` | Récupérer le TBSCert d'un SN |
| `GET` | `/actes` | Lister les actes du notaire connecté |
| `POST` | `/actes` | Notaire crée un acte + dérive K_acte |
| `GET` | `/actes/:id` | Récupérer un acte et ses participants |
| `GET` | `/actes/:id/keys` | Récupérer C_acte_participant (auth requise) |
| `POST` | `/actes/:id/participants` | Notaire ajoute un participant |
| `POST` | `/actes/:id/messages` | Envoyer un message chiffré + signature |
| `GET` | `/actes/:id/messages` | Historique (déchiffrement côté client) |
| `GET` | `/actes/:id/merkle` | Racine et preuve Merkle courante |
| `POST` | `/ws/ticket` | Émettre un ticket WebSocket éphémère (auth requise) |
| `WS` | `/ws/:acte_id` | Canal temps réel (nouveaux messages, ticket requis) |

### Simulation HSM (PoC)

Le HSM est simulé par une clé `K_master` de 32 octets chargée depuis une variable
d'environnement `HSM_MASTER_KEY_HEX` au démarrage. Elle est conservée en mémoire
dans un `Arc<Mutex<Zeroizing<[u8; 32]>>>`.

En production : remplacer `hsm.rs` par un client PKCS#11 vers un vrai HSM.

```rust
// hsm.rs
pub struct HsmSimulator {
    master_key: Zeroizing<[u8; 32]>,
}

impl HsmSimulator {
    pub fn from_env() -> Result<Self, ConfigError>;
    pub fn derive_k_acte(&self, acte_uuid: &uuid::Uuid) -> [u8; 32];
    pub fn decrypt_c_archive(&self, ciphertext: &EciesCiphertext) -> Result<[u8; 32], CryptoError>;
    pub fn encrypt_for_recipient(
        &self,
        k_acte: &[u8; 32],
        recipient_pk: &x25519_dalek::PublicKey,
    ) -> Result<EciesCiphertext, CryptoError>;
}
```

### Dépendances Cargo

```toml
[dependencies]
localpki-core    = { path = "../localpki-core" }
messaging-crypto = { path = "../messaging-crypto" }
axum             = { version = "0.7", features = ["ws", "macros"] }
tokio            = { workspace = true }
# ORM SQLite — spawn_blocking pour appeler Diesel depuis les handlers async
diesel           = { version = "2", features = ["sqlite", "r2d2", "returning_clauses_for_sqlite_3_35"] }
diesel_migrations = "2"
serde            = { workspace = true }
serde_json       = { workspace = true }
uuid             = { workspace = true }
tower-http       = { version = "0.5", features = ["cors", "trace"] }
tracing          = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
dotenvy          = "0.15"
thiserror        = { workspace = true }
zeroize          = { workspace = true, features = ["derive"] }
ed25519-dalek    = { workspace = true }
x25519-dalek     = { workspace = true }
hex              = "0.4"
base64           = { workspace = true }
hkdf             = { workspace = true }
sha2             = { workspace = true }
rand             = { workspace = true }
anyhow           = "1"
async-trait      = "0.1"
```

---

## 5. Crate `demo-cli`

**Responsabilité** : outil de démonstration en ligne de commande permettant de
jouer le flux complet d'enrollment → ouverture d'acte → échange de messages →
vérification Merkle. Utile pour la présentation technique sans avoir besoin de
l'interface web.

### Structure des fichiers

```
crates/demo-cli/
├── Cargo.toml
└── src/
    ├── main.rs          # point d'entrée + définition des sous-commandes clap
    ├── bootstrap.rs     # initialisation : génération keypair, enrollment auprès du serveur
    ├── client.rs        # client HTTP reqwest vers le serveur
    ├── cmd_scenario.rs  # scénario complet automatique (pour démo)
    ├── crypto.rs        # helpers crypto côté CLI (déchiffrement, signatures)
    └── identity.rs      # chargement/sauvegarde identité (alice.json, bob.json, notaire.json)
```

### Commandes CLI

```bash
# Enrollment : simuler le rôle LRA pour Alice
demo-cli enroll --name "Alice Dupont" --server http://localhost:3000

# Enrollment : simuler le rôle LRA pour Bob
demo-cli enroll --name "Bob Martin" --server http://localhost:3000

# Notaire : créer un acte et ajouter les parties
demo-cli acte create --title "Vente 12 rue de la Paix" \
  --parties alice.json,bob.json --server http://localhost:3000

# Envoyer un message (simule Alice)
demo-cli message send --acte <uuid> --identity alice.json \
  --text "Bonjour, j'ai bien reçu le compromis" \
  --server http://localhost:3000

# Inspecter le Merkle log
demo-cli merkle inspect --acte <uuid> --server http://localhost:3000

# Scénario complet automatique (pour démo)
demo-cli scenario --server http://localhost:3000
```

### Dépendances Cargo

```toml
[dependencies]
localpki-core    = { path = "../localpki-core" }
messaging-crypto = { path = "../messaging-crypto" }
tokio            = { workspace = true }
clap             = { version = "4", features = ["derive"] }
serde            = { workspace = true }
serde_json       = { workspace = true }
reqwest          = { version = "0.12", features = ["json"] }
colored          = "2"
indicatif        = "0.17"
ed25519-dalek    = { workspace = true }
x25519-dalek     = { workspace = true }
base64           = { workspace = true }
uuid             = { workspace = true }
zeroize          = { workspace = true, features = ["derive"] }
sha2             = { workspace = true }
rand             = { workspace = true }
thiserror        = { workspace = true }
anyhow           = "1"
hex              = "0.4"
dotenvy          = "0.15"
rusqlite         = { version = "0.31", features = ["bundled"] }
```

---

## 6. Frontend SvelteKit

**Responsabilité** : interface utilisateur avec différenciation par rôle (notaire /
client). Toute la cryptographie est effectuée côté client via `@noble` — le
serveur ne voit jamais les clés privées ni les messages en clair.

### Structure

```
frontend/
├── package.json
├── svelte.config.js
├── vite.config.ts
└── src/
    ├── app.css                    # styles globaux (Tailwind)
    ├── app.html
    ├── lib/
    │   ├── index.ts
    │   ├── utils.ts               # helpers partagés (clsx, tailwind-merge)
    │   ├── crypto/
    │   │   ├── keys.ts            # génération clés, conversions Ed25519↔X25519
    │   │   ├── ecies.ts           # ECIES X25519 + AES-256-GCM
    │   │   ├── messages.ts        # chiffrement, déchiffrement, signature
    │   │   └── enrollment.ts      # création du TBSCert et auto-signature (côté client)
    │   ├── api/
    │   │   └── client.ts          # fetch wrapper (toutes les routes serveur)
    │   ├── stores/
    │   │   ├── identity.ts        # clés + certificat de l'utilisateur courant
    │   │   └── actes.ts           # actes et messages en cours
    │   └── components/ui/         # composants shadcn-svelte (badge, button, card, …)
    └── routes/
        ├── +layout.svelte
        ├── +page.svelte           # page d'accueil / sélection rôle
        ├── auth/
        │   └── +page.svelte       # authentification LocalPKI (vérification EN)
        ├── enroll/
        │   └── +page.svelte       # auto-enrollment client (génération keypair + envoi)
        ├── actes/
        │   ├── +page.svelte       # liste des actes (vue partagée)
        │   └── [id]/
        │       └── +page.svelte   # messagerie d'un acte (vue partagée)
        └── notaire/
            ├── actes/
            │   ├── +page.svelte   # tableau de bord actes du notaire
            │   └── new/
            │       └── +page.svelte  # création d'un nouvel acte
            └── enroller/
                └── +page.svelte   # interface LRA (enrollment d'un client)
```

### Dépendances npm

```json
{
  "dependencies": {
    "@noble/ed25519": "^3.1.0",
    "@noble/hashes": "^2.2.0",
    "@noble/ciphers": "^2.2.0",
    "@noble/curves": "^2.2.0"
  },
  "devDependencies": {
    "@sveltejs/kit": "^2.63.0",
    "@sveltejs/adapter-auto": "latest",
    "@sveltejs/vite-plugin-svelte": "latest",
    "svelte": "^5.56.1",
    "typescript": "^6.0.3",
    "vite": "^8.0.16",
    "tailwindcss": "^4.3.0",
    "@tailwindcss/vite": "^4.3.0",
    "shadcn-svelte": "^1.3.0",
    "@lucide/svelte": "^1.17.0",
    "@fontsource-variable/inter": "^5.2.8"
  }
}
```

### Stockage des clés côté client

Les clés privées sont stockées dans `sessionStorage` (durée de session, jamais
persisté sur disque via localStorage). Elles sont effacées à la fermeture
de l'onglet.

> En production : utiliser l'API WebCrypto avec `extractable: false` pour les
> clés non-exportables, ou un hardware key comme WebAuthn.

---

## 7. Workspace `Cargo.toml`

```toml
[workspace]
members = [
    "crates/localpki-core",
    "crates/messaging-crypto",
    "crates/server",
    "crates/demo-cli",
]
resolver = "2"

[workspace.dependencies]
# Les features sont déclarées par chaque crate individuellement
ed25519-dalek = { version = "2" }
x25519-dalek  = { version = "2" }
serde         = { version = "1", features = ["derive"] }
serde_json    = { version = "1" }
sha2          = { version = "0.10" }
hkdf          = { version = "0.12" }
rand          = { version = "0.8" }
zeroize       = { version = "1", features = ["derive"] }
tokio         = { version = "1", features = ["full"] }
uuid          = { version = "1", features = ["v4", "serde"] }
thiserror     = { version = "1" }
base64        = { version = "0.22" }
```

---

## 8. Conventions et règles de développement

### Gestion des erreurs

Chaque crate définit son propre type d'erreur via `thiserror`. Les erreurs
remontent sans `unwrap()` ni `expect()` dans le code de production. Les `?`
sont autorisés partout dans les fonctions retournant `Result`.

```rust
// Pattern standard dans chaque crate
#[derive(Debug, thiserror::Error)]
pub enum LocalPkiError {
    #[error("signature invalide")]
    InvalidSignature,
    #[error("certificat expiré")]
    ExpiredCertificate,
    #[error("SN inconnu dans la base EN")]
    UnknownSerialNumber,
}
```

### Zéro copies de clés privées

Toutes les clés privées (`SigningKey`, `StaticSecret`, tableaux `[u8; 32]`
représentant des secrets) doivent être wrappées dans `Zeroizing<T>` dès qu'elles
ne sont pas dans un type qui implémente déjà `Zeroize` automatiquement.

### Tests

- `localpki-core` et `messaging-crypto` : tests unitaires et d'intégration dans
  `src/` (modules `#[cfg(test)]`) couvrant les vecteurs du papier.
- `server` : tests d'intégration dans `tests/` avec une base SQLite en mémoire.
- `demo-cli` : pas de tests automatisés — la démo elle-même fait office de test.

### Pas de `unsafe`

Aucun bloc `unsafe` dans ce projet. Les crates cryptographiques utilisées
(`ed25519-dalek`, `aes-gcm`, etc.) sont des crates RustCrypto auditées.

### Variables d'environnement (`.env`)

```bash
DATABASE_URL=sqlite://./notarial.db
HSM_MASTER_KEY_HEX=<64 hex chars — généré avec `openssl rand -hex 32`>
EN_SIGNING_KEY_HEX=<64 hex chars — clé de signature de l'EN>
SERVER_HOST=0.0.0.0
SERVER_PORT=3000
FRONTEND_ORIGIN=http://localhost:5173
RUST_LOG=server=debug,localpki_core=info
```
