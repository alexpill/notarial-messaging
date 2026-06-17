# notarial-messaging

Messagerie instantanée sécurisée pour le notariat français, basée sur le
paradigme **LocalPKI** (Dumas, Lafourcade, Melemedjian, Orfila, Thoniel, 2019).

Réalisé dans le cadre du sujet **S001 — Astéroïde 2026**.

---

## Contexte

Le notariat français s'appuie sur des infrastructures centralisées (RPN,
Cryptolis) où les identités des parties sont garanties par des CA PKIX distantes.

**LocalPKI** inverse ce modèle : les certificats sont auto-signés par les
utilisateurs eux-mêmes. Le notaire joue le rôle d'autorité de confiance locale
(Electronic Notary) en ne stockant que le hash `(SN, SI)` de chaque certificat
— jamais son contenu.

Ce projet construit un système de messagerie sur cette fondation :

- identités ancrées dans LocalPKI, vérifiées physiquement par le notaire
- chiffrement côté client — le serveur ne voit jamais les messages en clair
- non-répudiation via signatures Ed25519 ancrées dans les certificats LocalPKI
- transparency log Merkle pour la valeur probante de l'historique
- notaire orchestrateur : aucune conversation ne peut s'ouvrir sans lui

---

## Stack technique

| Composant | Technologie |
|---|---|
| Backend / EN | Rust — Axum 0.7, SQLite (Diesel 2) |
| Crypto Rust | RustCrypto — ed25519-dalek, x25519-dalek, aes-gcm, hkdf |
| Frontend | SvelteKit 5 + TypeScript + Tailwind CSS + shadcn-svelte |
| Crypto JS | @noble — ed25519, hashes, ciphers, curves |
| CLI démo | demo-cli (Rust, clap) |

---

## Structure du projet

```
notarial-messaging/
├── crates/
│   ├── localpki-core/     # protocoles LocalPKI du papier (lib pure)
│   ├── messaging-crypto/  # crypto messagerie — clés, chiffrement, Merkle (lib pure)
│   ├── server/            # serveur Axum (EN + messagerie + HSM simulé)
│   └── demo-cli/          # outil de démonstration CLI
└── frontend/              # interface SvelteKit (notaire + clients)
```

Pour l'architecture cryptographique et les protocoles : `ARCHITECTURE.md`.  
Pour la structure du code, voir l'arborescence des crates ci-dessus et les `lib.rs` de chaque crate.

---

## Prérequis

- **Rust** stable ≥ 1.75
- **Node.js** ≥ 20
- **SQLite 3** (libsqlite3-dev sur Debian/Ubuntu, inclus sur macOS)

---

## Démarrage rapide

### 1. Configurer l'environnement

```bash
cp .env.example .env
```

Générer les clés pour `.env` :

```bash
# Clé maître HSM simulée (256 bits)
echo "HSM_MASTER_KEY_HEX=$(openssl rand -hex 32)" >> .env

# Clé de signature de l'EN
echo "EN_SIGNING_KEY_HEX=$(openssl rand -hex 32)" >> .env
```

### 2. Démarrer le serveur

```bash
cargo run -p server
# Disponible sur http://localhost:3000
# Les migrations SQLite sont appliquées automatiquement au démarrage
```

### 3. Démarrer le frontend

```bash
cd frontend
npm install
npm run dev
# Interface disponible sur http://localhost:5173
```

### 4. Démonstration CLI (flux complet automatique)

```bash
# Enrollment + création d'acte + échange de messages + vérification Merkle
cargo run -p demo-cli -- scenario --server http://localhost:3000
```

> Le scénario insère d'abord un Root LRA directement en base (bootstrap
> nécessaire car `POST /enroll` requiert un LRA existant), puis fait tout le
> reste via l'API HTTP.

---

## Utilisation du CLI en détail

Les commandes CLI nécessitent des fichiers d'identité JSON générés lors de
l'enrollment. La commande `scenario` génère ces fichiers automatiquement.
Vous pouvez aussi les construire étape par étape :

```bash
# 1. Enrollment du notaire (nécessite un Root LRA — lancez scenario une fois d'abord)
cargo run -p demo-cli -- enroll \
  --name "Maître Dupont" \
  --lra root_lra.json \
  --output notaire.json

# 2. Enrollment d'Alice (notaire joue le rôle LRA)
cargo run -p demo-cli -- enroll \
  --name "Alice Martin" \
  --lra notaire.json \
  --output alice.json

# 3. Enrollment de Bob
cargo run -p demo-cli -- enroll \
  --name "Bob Durand" \
  --lra notaire.json \
  --output bob.json

# 4. Notaire crée un acte (dérive K_acte côté HSM)
cargo run -p demo-cli -- acte create \
  --title "Vente 12 rue de la Paix" \
  --parties alice.json,bob.json \
  --notaire notaire.json

# 5. Alice envoie un message chiffré
cargo run -p demo-cli -- message send \
  --acte <uuid> \
  --identity alice.json \
  --text "Bonjour, j'ai bien reçu le compromis"

# 6. Bob lit les messages (déchiffrement local)
cargo run -p demo-cli -- message list \
  --acte <uuid> \
  --identity bob.json

# 7. Inspecter le Merkle log
cargo run -p demo-cli -- merkle \
  --acte <uuid> \
  --identity alice.json

# 8. Endosser un cert généré côté frontend (notaire agit comme LRA)
cargo run -p demo-cli -- enroller \
  --notaire notaire.json \
  --cert client_cert.json
```

---

## Interface web

L'interface SvelteKit distingue deux rôles :

**Notaire** (`/notaire/`)
- `/enroll` — générer sa propre paire de clés et s'enregistrer
- `/notaire/actes` — tableau de bord des actes en cours
- `/notaire/actes/new` — créer un nouvel acte notarial
- `/notaire/enroller` — enrôler un client (face-à-face, rôle LRA)

**Clients** (Alice, Bob, …)
- `/enroll` — générer sa paire de clés, télécharger le cert pour la LRA
- `/auth` — s'authentifier avec son certificat LocalPKI
- `/actes` — liste des actes auxquels on participe
- `/actes/:id` — messagerie de l'acte (chiffrement/déchiffrement local)

La cryptographie est intégralement effectuée côté client via `@noble`. Le
serveur ne reçoit que des données chiffrées et des signatures.

---

## Flux principal

```
1. Enrollment (en présentiel — notaire joue le rôle LRA)
   Alice génère ses clés → TBSCert auto-signé → notaire enregistre (SN, SI) auprès de l'EN

2. Ouverture d'un canal (notaire)
   Notaire crée un acte → HSM dérive K_acte → K_acte chiffrée par participant (ECIES)

3. Connexion d'Alice
   Alice présente Cert_Alice → EN vérifie (SN, SI) → Alice reçoit C_acte_Alice chiffré
   Alice déchiffre K_acte avec sk_Alice côté client (serveur aveugle)

4. Échange de messages
   Alice chiffre M localement (AES-256-GCM) → signe le chiffré avec sk_Alice → envoie
   Serveur vérifie la signature, stocke le chiffré, met à jour le Merkle log, notifie Bob
   Bob déchiffre avec K_acte → vérifie la signature d'Alice

5. Vérification d'intégrité
   Quiconque peut vérifier qu'un message existait à l'instant T via le log Merkle
   signé par l'EN — sans en lire le contenu
```

---

## Décisions architecturales clés

**Pourquoi pas Signal ?** Le protocole Signal garantit la forward secrecy — les
clés de session sont éphémères et l'historique ne peut pas être rejoué. En
pratique notariale, l'archivage légal de l'historique est une exigence dure. Ces
deux propriétés sont fondamentalement contradictoires ; ce projet choisit
l'archivage. Voir `ARCHITECTURE.md` §10.1.

**Signature sur le chiffré, pas le clair.** Le serveur peut rejeter les forgeries
avant stockage sans jamais déchiffrer. La non-répudiation sur le contenu est
préservée transitivement : AES-256-GCM (AEAD) lie le chiffré à un unique clair.
Voir `ARCHITECTURE.md` §5.3.

**Paire de clés unique Ed25519.** Pragmatisme PoC — la même clé sert à la
signature (identité) et au chiffrement asymétrique (conversion Ed25519→X25519).
En production, deux paires distinctes seraient requises. Voir `ARCHITECTURE.md` §8.1.

**Chiffrement côté client.** Le serveur est aveugle au contenu, conforme aux
obligations de secret professionnel du notariat et à l'esprit LocalPKI où la
confiance n'est jamais déléguée à un intermédiaire pour le contenu.

---

## Limites connues (PoC)

- HSM simulé par variable d'environnement (pas de matériel réel)
- Timestamps serveur uniquement — pas de TSA qualifiée RFC 3161
- Paire de clés Ed25519 unique par utilisateur (cf. `ARCHITECTURE.md` §8.1)
- L'accès à l'historique pour un nouveau participant est une garantie UI, pas crypto
- La révocation en cours de session n'est pas propagée en temps réel
- Clés stockées en `sessionStorage` (fermer l'onglet efface l'identité)
- Rotation de `K_master` impossible sans re-chiffrement de tous les actes

Toutes les limites sont documentées et justifiées dans `ARCHITECTURE.md` §10.

---

## Références

- Dumas, Lafourcade, Melemedjian, Orfila, Thoniel. *LocalPKI: An Interoperable
  and IoT Friendly PKI*. 2019.
- Règlement eIDAS (UE) 910/2014
- ANSSI RGS v2
- RFC 5869 — HKDF
- RFC 6962 — Certificate Transparency
