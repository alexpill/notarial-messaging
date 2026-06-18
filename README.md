# notarial-messaging

Messagerie instantanée sécurisée pour le notariat français, basée sur le
paradigme **LocalPKI** (Dumas, Lafourcade, Melemedjian, Orfila, Thoniel, 2019).

Réalisé dans le cadre du sujet **S001 — Astéroïde 2026**.

> **Par où commencer** — pour la démarche, les choix de conception et le
> raisonnement (lecture courte), voir **[`docs/METHODOLOGIE.md`](docs/METHODOLOGIE.md)**.
> Pour une visite illustrée de l'interface, **[`docs/DEMO.md`](docs/DEMO.md)**. Pour
> la profondeur technique, **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** est un
> document de référence à parcourir par section (table des matières en tête).

---

## Contexte

Le notariat français s'appuie sur des infrastructures centralisées (RPN,
Cryptolis) où les identités des parties sont garanties par des CA PKIX distantes.

**LocalPKI** inverse ce modèle : les certificats sont auto-signés par les
utilisateurs eux-mêmes. Le notaire joue le rôle d'autorité de confiance locale
(Electronic Notary) en ne stockant que l'enregistrement `(SN, SI)` de chaque
certificat — étendu ici avec la clé publique pour la messagerie — jamais le
contenu des échanges.

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

Pour la structure du code, voir l'arborescence des crates ci-dessus et les `lib.rs` de chaque crate.

**Documentation (ordre de lecture suggéré) :**
- [`docs/METHODOLOGIE.md`](docs/METHODOLOGIE.md) — à lire en premier : démarche, choix de conception, raisonnement et usage de l'IA (document court).
- [`docs/DEMO.md`](docs/DEMO.md) — visite illustrée pas-à-pas (enrôlement → messagerie → Merkle).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — document de référence : protocoles LocalPKI, hiérarchie de clés, choix cryptographiques et limites assumées (dense, navigable par section).

---

## Prérequis

- **Rust** stable ≥ 1.75
- **Node.js** ≥ 20 + **pnpm** (`corepack enable`)
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

`.env.example` fixe aussi un `NOTAIRE_ENROLLMENT_TOKEN` de démo (le **jeton
d'enrôlement notaire** — l'autorité de l'EN pour désigner un notaire). En dev,
gardez la valeur par défaut et copiez la même dans `frontend/.env` pour que
l'interface puisse l'afficher. En production, laissez ce champ **vide** : un
jeton aléatoire est généré à chaque démarrage et imprimé une fois dans les logs
(secret opérateur, jamais envoyé au navigateur).

### 2. Démarrer le serveur

```bash
cargo run -p server
# Disponible sur http://localhost:3000
# Les migrations SQLite sont appliquées automatiquement au démarrage
```

### 3. Démarrer le frontend

```bash
cd frontend
cp .env.example .env   # jeton notaire de démo (doit matcher le .env racine)
pnpm install
pnpm dev
# Interface disponible sur http://localhost:5173
```

> En mode dev, la page d'accueil affiche un encart « PoC » avec le jeton
> d'enrôlement notaire prérempli — un correcteur devient notaire en un clic. La
> clé privée du notaire reste dans le navigateur ; seul le jeton transite.

### 4. Démonstration CLI (flux complet automatique)

```bash
# Enrollment + création d'acte + échange de messages + vérification Merkle
cargo run -p demo-cli -- scenario --server http://localhost:3000
```

> Le scénario **amorce un notaire** par insertion directe en base avec le rôle
> `notaire` (`bootstrap_notaire.json`) — c'est l'EN qui désigne son notaire,
> hors API (l'unique opération privilégiée). Ce notaire endosse ensuite les
> clients et crée l'acte via l'API HTTP.

---

## Utilisation du CLI en détail

Les commandes CLI nécessitent des fichiers d'identité JSON générés lors de
l'enrollment. La commande `scenario` génère ces fichiers automatiquement
(`bootstrap_notaire.json`, `notaire.json`, `alice.json`, `bob.json`). Vous
pouvez aussi les construire étape par étape :

```bash
# 1. Amorcer le notaire (l'EN le désigne — seed direct DB, role=notaire).
#    `scenario` le fait une fois et écrit notaire.json / bootstrap_notaire.json.
#    Le notaire (role=notaire) est l'endosseur requis pour enrôler des clients.

# 2. Enrollment d'Alice (le notaire joue le rôle LRA — endossement gaté role=notaire)
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

> 📸 **Tutoriel pas-à-pas en captures :** [`docs/DEMO.md`](docs/DEMO.md) — enrôler
> un notaire, des clients (mode démo *et* flux endossé), créer un acte, ajouter
> des participants (avec / sans historique).

L'interface SvelteKit distingue deux rôles :

**Notaire** (`/notaire/`)
- page d'accueil → « Je suis notaire » + **jeton d'enrôlement** → enregistré avec le rôle `notaire` (clé générée et conservée dans le navigateur)
- `/notaire/actes` — tableau de bord des actes en cours
- `/notaire/actes/new` — créer un nouvel acte (réservé au rôle `notaire`)
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
   Le journal Merkle est append-only et sa racine est signée par l'EN — toute
   altération de l'historique est détectable, sans en lire le contenu
```

---

## Décisions architecturales clés

**Pourquoi pas Signal ?** Le protocole Signal garantit la forward secrecy — les
clés de session sont éphémères et l'historique ne peut pas être rejoué. En
pratique notariale, l'archivage légal de l'historique est une exigence dure. Ces
deux propriétés sont fondamentalement contradictoires ; ce projet choisit
l'archivage. Voir [`ARCHITECTURE.md` §10.1](docs/ARCHITECTURE.md#101-limites-assumées-choix-délibérés).

**Signature sur le chiffré, pas le clair.** Le serveur peut rejeter les forgeries
avant stockage sans jamais déchiffrer. La non-répudiation sur le contenu est
préservée transitivement : AES-256-GCM (AEAD) lie le chiffré à un unique clair.
Voir [`ARCHITECTURE.md` §5.3](docs/ARCHITECTURE.md#53-envoi-dun-message).

**Paire de clés unique Ed25519.** Pragmatisme PoC — la même clé sert à la
signature (identité) et au chiffrement asymétrique (conversion Ed25519→X25519).
En production, deux paires distinctes seraient requises. Voir [`ARCHITECTURE.md` §8.1](docs/ARCHITECTURE.md#81-paire-de-clés-unique--décision-de-poc-et-ses-limites).

**Chiffrement côté client.** Le serveur est aveugle au contenu, conforme aux
obligations de secret professionnel du notariat et à l'esprit LocalPKI où la
confiance n'est jamais déléguée à un intermédiaire pour le contenu.

**Hiérarchie de confiance EN → notaire → client.** Le rôle (`notaire`/`client`)
vit dans le registre de l'EN, jamais dans le TBSCert auto-signé (qui serait
auto-déclaré). L'EN désigne ses notaires via un jeton d'enrôlement ; seul un
notaire peut endosser un client (`POST /enroll`) ou créer un acte (`POST /actes`).
C'est l'alignement avec le papier (§2.1 : « the LRA is registered by some EN »).
Voir [`ARCHITECTURE.md` §10.1](docs/ARCHITECTURE.md#101-limites-assumées-choix-délibérés).

---

## Limites connues (PoC)

- HSM simulé par variable d'environnement (pas de matériel réel)
- Timestamps serveur uniquement — pas de TSA qualifiée RFC 3161
- Paire de clés Ed25519 unique par utilisateur (cf. [`ARCHITECTURE.md` §8.1](docs/ARCHITECTURE.md#81-paire-de-clés-unique--décision-de-poc-et-ses-limites))
- L'accès à l'historique pour un nouveau participant est une garantie UI, pas crypto
- La révocation en cours de session n'est pas propagée en temps réel
- Clés stockées en `sessionStorage` (fermer l'onglet efface l'identité)
- Rotation de `K_master` impossible sans re-chiffrement de tous les actes

Toutes les limites sont documentées et justifiées dans [`ARCHITECTURE.md` §10](docs/ARCHITECTURE.md#10-limites-assumées-et-perspectives).

---

## Références

- Dumas, Lafourcade, Melemedjian, Orfila, Thoniel. *LocalPKI: An Interoperable
  and IoT Friendly PKI*. 2019.
- Règlement eIDAS (UE) 910/2014
- ANSSI RGS v2
- RFC 5869 — HKDF
- RFC 6962 — Certificate Transparency
