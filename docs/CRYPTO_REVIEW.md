# Revue cryptographique — Serveur + messagerie

> Audit complet du code crypto au regard du papier **LocalPKI (Dumas et al., 2019)**,
> des standards industriels de messagerie sécurisée, et des contraintes
> réglementaires françaises applicables au notariat.
>
> Date : 2026-06-16. Branche : `main`.

---

## Table des matières

- [TL;DR — Bugs critiques à corriger en priorité](#tldr--bugs-critiques-à-corriger-en-priorité)
- [A. Conformité au papier LocalPKI](#a-conformité-au-papier-localpki)
  - [A.1 Tableau de couverture des algorithmes](#a1-tableau-de-couverture-des-algorithmes)
  - [A.2 Écarts justifiés ou à connaître](#a2-écarts-justifiés-ou-à-connaître)
- [B. Bugs critiques](#b-bugs-critiques)
  - [B1 — Désynchronisation Rust ↔ JS sur la signature des messages](#b1--désynchronisation-rust--js-sur-la-signature-des-messages)
  - [B2 — `sent_at` serveur ≠ `timestamp` AAD client](#b2--sent_at-serveur--timestamp-aad-client)
  - [B3 — `seq` non couvert par la signature client](#b3--seq-non-couvert-par-la-signature-client)
- [C. Bugs moyens / hygiène](#c-bugs-moyens--hygiène)
  - [C1 — Clé EN signe AuthResponse ET Merkle root sans domain separation](#c1--clé-en-signe-authresponse-et-merkle-root-sans-domain-separation)
  - [C2 — `en_signature` du Merkle log ne signe que `root`](#c2--en_signature-du-merkle-log-ne-signe-que-root)
  - [C3 — Pas d'endpoint `/revoke`](#c3--pas-dendpoint-revoke)
  - [C4 — `req.timestamp` non borné](#c4--reqtimestamp-non-borné)
  - [C5 — Génération de nonce via `rand::random()` au lieu de `OsRng`](#c5--génération-de-nonce-via-randrandom-au-lieu-de-osrng)
  - [C6 — Colonne `parent_hash` mal nommée](#c6--colonne-parent_hash-mal-nommée)
- [D. Conformité aux standards industriels](#d-conformité-aux-standards-industriels)
- [E. Conformité juridique notariale française](#e-conformité-juridique-notariale-française)
- [F. Points solides à valoriser](#f-points-solides-à-valoriser)
- [G. Plan d'action priorisé](#g-plan-daction-priorisé)

---

## TL;DR — Bugs critiques à corriger en priorité

| # | Sévérité | Fichier | Résumé |
|---|---|---|---|
| **B1** | 🔴 Critique | `frontend/src/lib/crypto/messages.ts:110` | Le JS signe sur **plaintext** sans nonce, le Rust serveur vérifie sur **ciphertext + nonce** ⇒ tout envoi depuis le frontend est rejeté |
| **B2** | 🔴 Critique | `crates/server/src/routes/messages.rs:104` | `sent_at` (now serveur) ≠ `req.timestamp` (client), et `client_ts` n'est jamais renvoyé au destinataire ⇒ AAD GCM et signature non vérifiables en dehors du PoC local |
| **B3** | 🔴 À arbitrer | `crates/messaging-crypto/src/messages.rs` | Le `seq` est assigné serveur et **n'entre pas dans la signature client** ⇒ trou dans la chaîne de non-répudiation pour un audit judiciaire |
| **C1** | 🟠 Hygiène | `crates/server/src/state.rs:13` | Même clé EN pour signer `AuthResponse` et racines Merkle, sans tag de domaine |
| **C2** | 🟠 Conformité doc | `crates/server/src/routes/messages.rs:176` | `en_sk.sign(&root)` au lieu de `Sign(sk_EN, root \|\| timestamp \|\| "log-v1")` annoncé dans `ARCHITECTURE.md §6.1` |
| **C3** | 🟠 Couverture LocalPKI | `crates/server/src/routes.rs` | Aucune route `POST /revoke` — Algo 4 du papier inaccessible côté HTTP |

---

## A. Conformité au papier LocalPKI

### A.1 Tableau de couverture des algorithmes

| Algorithme du papier | Implémentation | Verdict |
|---|---|---|
| **Algo 1** — Enrollment | `localpki-core/enrollment.rs` + `routes/enrollment.rs` | ✅ fidèle (écart documenté ↓) |
| **Algo 2** — Auth privée (self-sig côté verifier) | `routes/authentication.rs` + `en/auth.rs` | ✅ conforme, anti-replay 32 octets correct |
| **Algo 3** — Auth privée (delegation EN) | Non implémenté | ⚠️ choix : algo 2 seul (`ARCHITECTURE.md §3.2`) |
| **Algo 4** — Révocation | `localpki-core/revocation.rs` | ✅ logique conforme — ❌ **aucun endpoint HTTP** |
| **CVL (mode public)** | Non implémenté | ✅ documenté §10.2 |
| **Cross-cert multi-EN (MPT)** | Non implémenté | ✅ documenté §10.2 |

### A.2 Écarts justifiés ou à connaître

#### A.2.1 `LraToEnMessage` ajoute `pk` au plaintext chiffré

Le papier (Algo 1 ligne 9) n'envoie que `{SN || SI}`. Le code envoie `SN(16) || SI(64) || pk(32)`.

**Justification** : le papier n'a pas de messagerie, donc l'EN n'a pas besoin de stocker `pk` ; le serveur, oui (pour vérifier les signatures de messages côté `routes/messages.rs:93`). C'est défendable mais à mentionner explicitement dans `ARCHITECTURE.md §3.1` — actuellement c'est silencieux.

Fichier : `crates/localpki-core/src/enrollment.rs:110-113`.

#### A.2.2 `AuthResponse` signe `SHA256(status || SN || SI || nonce)` au lieu de `H(Rep)` du papier

Sémantiquement équivalent : le papier encode implicitement la chaîne `"OK"` ou `"Unknown"`, ici on encode sur 1 octet (`0` ou `1`). OK.

Fichier : `crates/localpki-core/src/authentication.rs:87-99`.

#### A.2.3 Le payload signature notaire utilise le UUID textuel

Dans `crates/server/src/routes/participants.rs:74-77` :

```rust
payload.extend_from_slice(acte_id.as_bytes());  // bytes UTF-8 du UUID textuel
```

Au lieu de `uuid.as_bytes()` (les 16 octets binaires) — incohérent avec le reste du code qui utilise systématiquement la forme binaire. Pas de faille immédiate (la signature reste vérifiable), mais c'est une dette de cohérence à harmoniser.

---

## B. Bugs critiques

### B1 — Désynchronisation Rust ↔ JS sur la signature des messages

🔴 **Sévérité : critique**

**Symptôme** : tout message envoyé depuis le frontend est rejeté par le serveur avec `CryptoError::InvalidMessageSignature`. Le PoC ne fonctionne que via `demo-cli` qui, lui, est cohérent avec le Rust.

**Détails** :

| Source | Payload signé |
|---|---|
| Rust — `crates/messaging-crypto/src/messages.rs:80` | `SHA256(ciphertext \|\| nonce \|\| acte_uuid \|\| ts \|\| sn)` |
| JS — `frontend/src/lib/crypto/messages.ts:110` | `SHA256(plaintext \|\| acte_uuid \|\| ts \|\| sn)` |
| Serveur (vérif) — `crates/server/src/routes/messages.rs:93` | utilise le payload Rust sur le **ciphertext** |

**Fix recommandé** : garder le contrat *"signer le ciphertext"* (sécurité serveur + non-répudiation via AEAD documentés dans `ARCHITECTURE.md §5.3`) et corriger le frontend.

```ts
// frontend/src/lib/crypto/messages.ts
function buildSigningPayload(
    ciphertext: Uint8Array, nonce: Uint8Array,
    acteUuid: string, timestamp: number, snHex: string
): Uint8Array { /* ciphertext || nonce(12) || uuid(16) || ts(8 LE) || sn(16) */ }
```

Puis adapter `signMessage`, `verifyMessageSignature` et l'appel depuis `routes/actes/[id]/+page.svelte:242` pour passer `ciphertext` + `nonce` au lieu de `plaintext`.

---

### B2 — `sent_at` serveur ≠ `timestamp` AAD client

🔴 **Sévérité : critique**

**Symptôme** : déchiffrement et vérification de signature impossibles chez les destinataires dès qu'il y a la moindre dérive d'horloge entre client et serveur.

**Détails** :

1. Le client (`frontend/src/routes/actes/[id]/+page.svelte:238`) calcule `timestamp = Math.floor(Date.now() / 1000)` et l'utilise pour l'AAD AES-GCM **et** pour la signature.
2. Le serveur (`crates/server/src/routes/messages.rs:104,187`) stocke `sent_at = now` (horloge serveur) — **ignore** `req.timestamp` pour ce champ.
3. `MessageResponse` (`routes/messages.rs:36-45`) ne renvoie que `sent_at`. **`req.timestamp` est jeté**.
4. Le frontend récepteur (`routes/actes/[id]/+page.svelte:160`) déchiffre avec `m.sent_at` comme AAD — qui n'est pas la valeur scellée dans le tag GCM.

Cela marche par chance sur la démo locale (même seconde), mais cassera dès qu'un client a une horloge un peu décalée.

**Fix recommandé (option a)** : renvoyer aussi `client_ts` dans `MessageResponse`, le persister en DB en colonne distincte. C'est ce qui est déjà *promis* par le commentaire `routes/messages.rs:142-144` ("auditors compare the two to detect clock skew or client lies") — actuellement ce commentaire est faux puisque `client_ts` n'est jamais exposé.

**Option b** : forcer `sent_at = req.timestamp`. Mais alors le serveur fait confiance au client pour le timestamp — détourne le rôle de la feuille Merkle qui doit témoigner d'un timing serveur.

Recommandation : option (a).

---

### B3 — `seq` non couvert par la signature client

🔴 **Sévérité : à arbitrer** (architecturale)

`seq` est attribué par le serveur (`routes/messages.rs:135-139`) et inclus dans la feuille Merkle, mais le client n'a aucun moyen cryptographique de prouver *"j'ai envoyé exactement le N°23"*.

**Conséquence** : un opérateur malveillant peut réordonner des feuilles tout en conservant des signatures valides — seul l'arbre Merkle l'attesterait *a posteriori*, et uniquement si un auditeur a conservé une racine antérieure.

Pour un PoC c'est défendable, mais devant un tribunal la chaîne de non-répudiation a un trou :
- ✅ *"Alice a envoyé ce ciphertext-là"* — prouvable
- ❌ *"Alice a envoyé le message N°23 de l'acte"* — non

**Fix possible** : le serveur renvoie le `seq` attribué et Alice contresigne le couple `(ciphertext_hash, seq)` lors d'un round-trip supplémentaire. À arbitrer ; au minimum à documenter dans `ARCHITECTURE.md §10.1`.

---

## C. Bugs moyens / hygiène

### C1 — Clé EN signe AuthResponse ET Merkle root sans domain separation

🟠 **Sévérité : hygiène crypto**

Fichier : `crates/server/src/state.rs:13` — un seul `en_signing_key`.

- `routes/messages.rs:176` : `en_sk.sign(&root)` (32 octets)
- `routes/authentication.rs` (via `en/auth.rs`) : `en_signing_key.sign(SHA256(status || SN || SI || nonce))` (32 octets aussi)

Les deux contextes sont des messages arbitraires de 32 octets pour Ed25519. Pas de scénario d'attaque concret à court terme grâce à la résistance préimage de SHA-256, mais c'est une mauvaise hygiène : un futur changement de payload pourrait ouvrir une attaque cross-protocol.

**Fix simple** : préfixer chaque payload signé par une tag de domaine.

```rust
// auth_payload
payload.extend_from_slice(b"localpki-auth-v1\0");
// merkle root
let to_sign = [b"localpki-merkle-v1\0".as_ref(), &root, &now.to_le_bytes()].concat();
```

---

### C2 — `en_signature` du Merkle log ne signe que `root`

🟠 **Sévérité : conformité à la doc**

`ARCHITECTURE.md §6.1` prescrit :

```
signed_root = Sign(sk_EN, root_n || timestamp || "log-v1")
```

Or `crates/server/src/routes/messages.rs:176` fait juste `en_sk.sign(&root)`.

**Conséquence** : sans le timestamp, on perd la preuve *"cette racine était la racine au temps T"* — un attaquant qui rejoue une vieille racine signée passe inaperçu. À corriger en alignement avec ta propre doc (et cumulable avec le fix C1).

---

### C3 — Pas d'endpoint `/revoke`

🟠 **Sévérité : couverture LocalPKI**

`crates/localpki-core/src/revocation.rs` est entièrement câblé (`build_revocation_request`, `validate_revocation_request`), soft-delete prêt dans `crates/server/src/en/registry.rs:77` (`revoke_identity`). Mais **aucune route HTTP** dans `crates/server/src/routes.rs`.

La révocation n'est utilisable que par accès direct à la DB — non-conforme à l'Algo 4 du papier. Pour un PoC c'est une lacune ; pour une démo orale c'est un trou évident à corriger en ~30 minutes.

---

### C4 — `req.timestamp` non borné

🟠 **Sévérité : qualité d'audit**

Le serveur accepte n'importe quel `timestamp` (passé ou futur) dans `routes/messages.rs`. Sans vérification d'écart (`|req.timestamp - now| < tolérance`), un client malhonnête peut antidater/postdater ses propres messages dans la limite des AAD — et la divergence avec `sent_at` (B2) la masque même au démarrage.

**Fix recommandé** :

```rust
let now = crate::utils::unix_now()?;
if (req.timestamp - now).abs() > 300 {
    return Err(AppError::BadRequest("timestamp drift > 5min".into()));
}
```

---

### C5 — Génération de nonce via `rand::random()` au lieu de `OsRng`

🟠 **Sévérité : cohérence d'audit**

Occurrences :
- `crates/messaging-crypto/src/messages.rs:39`
- `crates/messaging-crypto/src/keys.rs:63`
- `crates/localpki-core/src/enrollment.rs:117`

`rand::random()` repose sur `thread_rng()` (ChaCha12 réseedé depuis l'OS) — c'est CSPRNG-acceptable, mais le reste du code utilise `rand::rngs::OsRng` explicitement. La cohérence d'audit voudrait `OsRng.fill_bytes(&mut nonce)` partout. Pas une faille — juste de l'audibilité.

---

### C6 — Colonne `parent_hash` mal nommée

🟠 **Sévérité : dette de doc**

Le schéma (`ARCHITECTURE.md §11`) annonce :

```
parent_hash  TEXT,               -- Hash de la feuille précédente (NULL pour la première)
```

Mais le code (`crates/server/src/routes/messages.rs:199-200`) y stocke la **racine post-insertion**.

**Fix** : renommer la colonne `root_after_insert` (migration), ou aligner la doc. C'est une dette qui rendra le futur audit confus.

---

## D. Conformité aux standards industriels

### D.1 Primitives — RAS

| Choix | Standard | Verdict |
|---|---|---|
| Ed25519 | RFC 8032 / ANSSI / NIST SP 800-186 | ✅ |
| X25519 | RFC 7748 | ✅ |
| AES-256-GCM | NIST SP 800-38D — AEAD obligatoire respecté | ✅ |
| HKDF-SHA256 | RFC 5869 | ✅ |
| Merkle | RFC 6962 — domain separation 0x00/0x01 correcte | ✅ |
| Nonce GCM | 96 bits CSPRNG | ✅ |

### D.2 Comparaison avec Signal / MLS / TLS 1.3

- **Pas de forward secrecy** : assumée et documentée (`ARCHITECTURE.md §10.1`). Antinomique avec l'archivage légal — choix défendable.
- **Pas de Double Ratchet, pas de X3DH** : assumés, à nouveau pour l'archivage.
- **Conversion Ed25519 → X25519** via `to_montgomery` / `to_scalar_bytes` : techniquement correcte, mais formellement non couverte par les preuves de sécurité indépendantes des deux schémas. C'est l'écueil `ARCHITECTURE.md §8.1` — bien documenté.
- **MLS (RFC 9420)** serait l'option moderne pour le groupe notarial (multi-parties), mais MLS est explicitement conçu *contre* l'archivage long. Hors périmètre, mais à mentionner en défense orale comme **la bonne alternative si la contrainte d'archivage tombait**.
- **OWASP ASVS 4.0** : les jetons de session sont hashés SHA-256 en DB (`crates/server/src/utils.rs:9`) — conforme V3.5.

---

## E. Conformité juridique notariale française

| Exigence | État | Verdict |
|---|---|---|
| eIDAS niveau Substantiel (échanges préalables) | enrôlement face-à-face LRA | ✅ acceptable |
| eIDAS niveau Élevé (AAE) | hors périmètre | ✅ documenté |
| eIDAS qualifié (PSCQ) | non | ✅ explicite §9.1 |
| Horodatage qualifié RFC 3161 | non (timestamps serveur) | ⚠️ documenté §6.4 |
| RGPD — localisation UE | côté hébergement | N/A code |
| Conservation vs droit à l'effacement | choix de conserver | ⚠️ documenté §9.3 |
| Secret professionnel — serveur aveugle | OK (E2EE confirmée) | ✅ |
| Article 1366 Code civil | OK échanges préalables | ✅ |
| Certification ADSN | hors PoC | ✅ documenté §9.6 |

### Lacunes pesantes pour un usage réel

1. **Horodatage non qualifié** : pour produire un effet probant complet devant un tribunal, intégrer une TSA RFC 3161 qualifiée (Universign, CertEurope, Docaposte). Le coût marginal est faible : signer la racine Merkle périodique via TSA.
2. **Pas de procédure de renouvellement** (`ARCHITECTURE.md §10.1`) : un certificat expiré force un re-enrollment physique. En production notariale, ça crève la productivité.
3. **K_master sans rotation** (`ARCHITECTURE.md §10.1`) : un changement de notaire (cessation, succession, rachat d'étude) implique aujourd'hui la perte d'accès à **tous** les actes archivés. Inacceptable réglementairement. Une cérémonie de clé HSM avec ré-encapsulation des `C_acte_archive` doit être conçue avant production.
4. **`EN_SIGNING_KEY_HEX` en `.env`** (`ARCHITECTURE.md §10.1`) : sa fuite casse la *soundness* (§6.5 du papier). En production, doit aller en HSM avec opération sign-only.

---

## F. Points solides à valoriser

À mettre en avant à l'oral — ce sont des marqueurs de maturité crypto rare pour un PoC :

- **`tbs_der` figé en DB** (`crates/server/src/routes/enrollment.rs:75-78`) : neutralisation explicite du risque de dérive d'encodeur `x509-cert`.
- **`C_acte_archive` plaintext = `K_acte || acte_uuid`** (`crates/server/src/hsm.rs:53`) avec vérification UUID au déchiffrement → bloque les attaques par swap de lignes archive.
- **Token de session hashé SHA-256 en DB** (`crates/server/src/utils.rs:9`).
- **Flow WebSocket ticket** (`crates/server/src/routes/ws.rs`) : sortie propre de la classique fuite de token via query string.
- **AAD AES-GCM** lie ciphertext à `(acte_uuid, ts, sn)` — empêche le rejeu cross-acte.
- **Re-vérification `pk` côté auth** (`crates/server/src/routes/authentication.rs:56`) : défense en profondeur contre le swap de clé post-enrollment.
- **Domain separation HKDF** : `"notariat-msg-v1"`, `"send"`, `"notariat-ecies-v1"`, `"notariat-hsm-x25519-v1"`, `"localpki-enrollment-v1"` — toutes distinctes et versionnées (`-v1`), excellente hygiène.
- **RFC 6962 strict** avec note explicite sur CVE-2012-2459 (orphan promotion, cf. `crates/messaging-crypto/src/merkle.rs:10-14`) → démontre une compréhension fine.
- **`Zeroizing`** appliqué consistement sur tous les secrets (K_master, K_acte transit, symétriques ECIES, scalaires X25519).

---

## G. Plan d'action priorisé

| Ordre | Effort | Action |
|---|---|---|
| 1 | ~15 min | **B1** — corriger `frontend/src/lib/crypto/messages.ts` pour signer sur `ciphertext \|\| nonce \|\| …` |
| 2 | ~30 min | **B2** — ajouter `client_ts` à `MessageResponse` + colonne DB + l'utiliser pour decrypt/verify côté client |
| 3 | ~30 min | **C3** — brancher `POST /revoke` (le `localpki-core` est prêt) |
| 4 | ~15 min | **C1 + C2** — domain separation sur la clé EN + intégrer `timestamp \|\| version` à la signature Merkle |
| 5 | ~15 min | **C4** — borner `\|req.timestamp - now\| < 300` |
| 6 | ~10 min | **A.2.3** — harmoniser la signature notaire avec `uuid.as_bytes()` |
| 7 | À arbitrer | **B3** — décider sur le `seq` non-signé : accepter et documenter, ou ajouter un round-trip |
| 8 | ~10 min | **C5** — homogénéiser sur `OsRng` partout |
| 9 | ~5 min + migration | **C6** — renommer `parent_hash` en `root_after_insert` ou aligner la doc |

Les sections **D** et **E** sont des sujets de défense orale plus que d'implémentation — déjà bien anticipés dans `ARCHITECTURE.md §9` et `§10`.

---

*Revue rédigée à partir du papier `docs/LocalPki2019.pdf`, de `ARCHITECTURE.md`, `SOFTWARE_ARCHITECTURE.md`, et de l'audit ligne à ligne des crates `localpki-core`, `messaging-crypto`, `server`, ainsi que du module crypto frontend.*
