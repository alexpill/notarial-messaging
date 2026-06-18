# Revue cryptographique — Serveur + messagerie

> Audit complet du code crypto au regard du papier **LocalPKI (Dumas et al., 2019)**,
> des standards industriels de messagerie sécurisée, et des contraintes
> réglementaires françaises applicables au notariat.
>
> Date : 2026-06-17. Branche : `main`.
> Cette revue **remplace** la précédente (2026-06-16) : tous ses bugs critiques
> ayant été corrigés depuis (passe d'hygiène `dc9f5bc`, fix `f08924b`), les
> findings ouverts se situent désormais à la couche **identité / authentification /
> bootstrap de confiance** et dans le **décalage doc↔code** — pas à la couche des
> primitives.

> **Mise à jour 2026-06-18** — passe de durcissement appliquée :
> - **A5 ✅** — étiquettes de domaine ajoutées aux signatures clé-utilisateur :
>   `localpki-msg-v1\0` (message, Rust + JS en lockstep), `localpki-participant-v1\0`
>   (ajout de participant), `localpki-revoke-v1\0` (révocation, remplace le préfixe
>   ASCII `"Revoke"`).
> - **A6 ✅** — `ecies_decrypt` rejette les points d'ordre faible (`was_contributory()`).
> - **A7 ✅ (documenté)** — hypothèse d'unicité de nonce énoncée en [`ARCHITECTURE.md §8.5`](ARCHITECTURE.md#85-hypothèse-dunicité-de-nonce-sous-k_send).
> - **A8 ✅** — le contenu `sigValid === false` est mis en quarantaine visuelle
>   (bandeau rouge + `details` à déplier), plus affiché comme un message normal.
> - **C5 ✅** — `build_auth_request` lit `OsRng` (cohérence ; c'était déjà un CSPRNG).
> - **Autz `get_acte` ✅** — `GET /actes/:id` exige désormais l'appartenance
>   (test `test_non_participant_cannot_get_acte`) — referme une fuite de métadonnées.
> - **`/login` mort ✅** — les 4 gardes frontend redirigent vers `/`.
> - **Self-enroll ✅ (gaté)** — `POST /enroll/self` est désactivé par défaut
>   (`ALLOW_SELF_ENROLL`), si bien qu'une config « production-like » impose le flux
>   endossé. Reste ouvert : la *dédup de message* (replay octet-pour-octet) et la
>   *persistance d'identité* frontend.

---

## Table des matières

- [Cadrage et verdict global](#cadrage-et-verdict-global)
- [Statut de la revue précédente (2026-06-16)](#statut-de-la-revue-précédente-2026-06-16)
- [A. Findings d'expert crypto (classés)](#a-findings-dexpert-crypto-classés)
  - [A1 — Le login ne prouve pas la possession de la clé privée](#a1--le-login-ne-prouve-pas-la-possession-de-la-clé-privée)
  - [A2 — `enroll_self` court-circuite l'ancre de confiance LocalPKI](#a2--enroll_self-court-circuite-lancre-de-confiance-localpki)
  - [A3 — Graphe de confiance plat](#a3--graphe-de-confiance-plat)
  - [A4 — Doc-vs-code : la SI est signée sur le DER brut](#a4--doc-vs-code--la-si-est-signée-sur-le-der-brut)
  - [A5 — Domain separation appliquée à la clé EN mais pas aux clés utilisateur](#a5--domain-separation-appliquée-à-la-clé-en-mais-pas-aux-clés-utilisateur)
  - [A6 — ECIES ne rejette pas les points d'ordre faible](#a6--ecies-ne-rejette-pas-les-points-dordre-faible)
  - [A7 — `K_send` déterministe longue durée + nonce aléatoire](#a7--k_send-déterministe-longue-durée--nonce-aléatoire)
  - [A8 — Le client affiche du contenu non vérifié](#a8--le-client-affiche-du-contenu-non-vérifié)
- [B. Findings ingénierie / correction](#b-findings-ingénierie--correction)
- [C. Conformité aux standards industriels](#c-conformité-aux-standards-industriels)
- [D. Conformité juridique notariale française](#d-conformité-juridique-notariale-française)
- [E. Points solides à valoriser](#e-points-solides-à-valoriser)
- [F. Lens interviewer — défense orale](#f-lens-interviewer--défense-orale)
- [G. Plan d'action priorisé](#g-plan-daction-priorisé)

---

## Cadrage et verdict global

Point d'équité qui cadre tout le reste : **les propriétés qui dépendent de la clé
privée sont solides.** Confidentialité par message (ECIES sur `K_acte`),
authenticité et non-répudiation par message (Ed25519 sur le chiffré), binding de
contexte AEAD, log Merkle RFC 6962, `tbs_der` figé, archive liée à l'UUID —
tout cela est correctement implémenté et l'interopérabilité Rust↔JS correspond.

Les faiblesses ouvertes se concentrent ailleurs :

1. **Couche identité / session** : le login prouve la possession de `sk` via
   challenge-response (A1 ✅ résolu). L'ancre de confiance est désormais imposée :
   attribut `role` côté EN, jeton d'enrôlement notaire, gates `role==notaire` sur
   `/enroll` et `/actes` (A2 + A3 ✅ résolus le 2026-06-17 ; « Root LRA » supprimé).
   Reste ouvert côté frontend : pas de flux « se reconnecter » (sessionStorage). Les
   redirections mortes `/login` sont corrigées (→ `/`, MàJ 2026-06-18 ; cf. §B).
2. **Décalage doc↔code** *(✅ résolu le 2026-06-17)* : plusieurs affirmations des
   documents (SI = `SHA256(DER)`, « rcgen pour la génération, x509-cert pour le
   parsing ») ne correspondaient pas au code — désormais réconciliées (cf. A4 et §B).

À noter : message-layer confidentialité + non-répudiation (les choses liées à `sk`)
tiennent ; c'est la couche de **binding identité/session** et le **bootstrap de
confiance** qui sont les raccourcis délibérés du PoC. Énoncer ça en premier rend
les findings ci-dessous des preuves de lucidité plutôt que des trous subis.

---

## Statut de la revue précédente (2026-06-16)

La revue précédente a fait son travail — voici l'état de ses items :

| Item | Statut actuel |
|---|---|
| **B1** — le JS signe le clair, le Rust vérifie le chiffré | ✅ Corrigé (`frontend/src/lib/crypto/messages.ts:104` signe `ciphertext‖nonce`) |
| **B2** — `sent_at` ≠ `timestamp` client | ✅ Corrigé (`crates/server/src/routes/messages.rs:207,250` round-trip `client_timestamp`) |
| **C1** — pas de domain separation sur la clé EN | ✅ Corrigé (`localpki-auth-v1`, `localpki-merkle-v1`) |
| **C2** — la sig Merkle omet le timestamp | ✅ Corrigé (`signed_root_payload` = `tag‖root‖ts`) |
| **C3** — pas d'endpoint `/revoke` | ✅ Corrigé ([`crates/server/src/routes/revocation.rs`](../crates/server/src/routes/revocation.rs)) |
| **C4** — `timestamp` non borné | ✅ Corrigé (cap de dérive ±300s, `messages.rs:71`) |
| **B3** — `seq` non signé par le client | ⚠️ Accepté + documenté ([`ARCHITECTURE.md §10.1`](ARCHITECTURE.md#101-limites-assumées-choix-délibérés)) |
| **C5** — `rand::random()` vs `OsRng` | ✅ Résolu (2026-06-18) : `build_auth_request` lit `OsRng` |
| **C6** — `parent_hash` mal nommé | 🟡 Documenté dans le SQL et §11, pas renommé |

---

## A. Findings d'expert crypto (classés)

### A1 — Le login ne prouve pas la possession de la clé privée

✅ **RÉSOLU (2026-06-17)** — challenge-response implémenté : `POST /auth/challenge`
émet un nonce 32 o single-use (TTL 60s, store `state.auth_challenges`), et
`/auth/verify` exige `Verify(pk_registre, "localpki-auth-pop-v1\0" || SN || nonce)`
avant d'émettre le token. Contrat partagé : `localpki_core::authentication::auth_pop_payload`
(répliqué en JS dans `frontend/src/lib/crypto/auth.ts`). Rejeu fermé — couvert par
le test `server::tests::test_auth_challenge_is_single_use`. Finding initial conservé
ci-dessous pour traçabilité.

🔴 **Sévérité (historique) : critique (architecturale)**

`POST /auth/verify` (`crates/server/src/routes/authentication.rs:23-100`) prend un
`cert` et émet un token de session après avoir vérifié : la SI vérifie contre le
`tbs_der`/`pk` stocké, la pk présentée correspond au registre, la fenêtre de
validité est OK, l'EN dit « enregistré ». **Nulle part le client ne signe un
challenge serveur frais.**

La SI est une *signature statique, non secrète*. Le credential qui ouvre une
session est donc une valeur fixe, et le flux est **rejouable** : capturez un seul
corps de `/auth/verify` (proxy de log, LB qui termine le TLS, un `alice.json`
sauvegardé, un cert exporté) et vous obtenez des sessions en tant que cet
utilisateur jusqu'à l'expiration du cert — sans aucun accès à son `sk`.

Ironie : `AuthRequest` porte déjà un nonce de 32 octets (`authentication.rs:41`),
mais il est signé par *l'EN* (prouve la fraîcheur de la réponse EN), pas par Alice
(ne prouve pas qu'Alice est présente). Toutes les primitives d'une vraie preuve de
possession sont là (le client signe le `nonce`), pour le coût d'une signature.

**Impact borné, à énoncer précisément** : une session rejouée ne peut pas
déchiffrer le contenu (il faut `sk`→X25519 pour déballer `K_acte`) ni forger de
messages (il faut `sk` pour signer). C'est donc une usurpation à la couche
session/identité + accès aux métadonnées (lister les actes, lire le chiffré, créer
des actes au nom de la victime), pas une compromission du contenu. Mais pour un
produit dont l'argument est « l'identité de confiance », un login rejouable est le
mauvais défaut.

**Fix recommandé** : challenge-response. Le serveur émet un nonce, le client le
signe avec `sk`, le serveur vérifie avec la `pk` du registre avant d'émettre le
token. Petit changement, ferme le finding.

---

### A2 — `enroll_self` court-circuite l'ancre de confiance LocalPKI

✅ **RÉSOLU (2026-06-17)** — un attribut `role ∈ {notaire, client}` a été ajouté
au registre EN (`identities.role`). `enroll_self` enregistre désormais **toujours**
`role = client` — il ne peut plus produire de notaire. Le rôle `notaire` n'est
accordé que par `POST /enroll/notaire` sur présentation du **jeton d'enrôlement
notaire** (l'EN désigne ses notaires, §2.1 du papier ; la clé privée ne transite
pas, seul le jeton circule). La notion « Root LRA » a été supprimée. Finding
initial conservé ci-dessous pour traçabilité ; voir A3 pour les gates.

🔴 **Sévérité (historique) : critique (architecturale)**

La page d'accueil auto-enrôle **les deux** rôles : `frontend/src/routes/+page.svelte:69`
appelle `enrollSelf()` → `POST /enroll/self`
(`crates/server/src/routes/enrollment.rs:196`), qui insère n'importe quel
certificat auto-signé valide avec **aucune LRA, aucun endossement, aucune
vérification physique**. Tapez un nom, cliquez, et vous êtes « notaire ».

Le flux *correct* existe — `/notaire/enroller` fait `endorseCert()` → `POST /enroll`
avec signature LRA (`enrollment.rs:30`) — mais ce n'est pas le chemin de la démo.
Toute la prémisse du sujet (« le notaire comme tiers de confiance numérique »,
« réutilisant l'environnement de confiance établi ») est donc **démontrée par la
plomberie mais contournée par l'UX par défaut**.

C'est *partiellement* reconnu ([`METHODOLOGIE.md`](METHODOLOGIE.md) ; [`ARCHITECTURE.md §10.1`](ARCHITECTURE.md#101-limites-assumées-choix-délibérés)), mais
les docs décrivent le modèle *notaire-endosse*, qui n'est **pas** ce que fait
`enroll_self`. Les docs survendent légèrement le défaut.

**Fix recommandé** : faire du flux endossé le flux principal (ou gater
`/enroll/self` derrière un flag de build), pour qu'un correcteur voie le modèle de
confiance *fonctionner*, pas être simulé.

> **MàJ 2026-06-17** : l'écart doc↔réalité est corrigé (les deux chemins sont
> décrits honnêtement en [`ARCHITECTURE.md §10.1`](ARCHITECTURE.md#101-limites-assumées-choix-délibérés), et le frontend affiche un badge
> qui qualifie le self-enroll de « raccourci démo » et pointe le flux endossé).
> Le **comportement** reste le finding ouvert, par décision de proportionnalité :
> imposer l'endossement exigerait d'ancrer le **rôle notaire**, et le faire dans le
> navigateur entraînerait un système d'habilitation + la persistance d'identité —
> hors budget d'un PoC, et au prix de l'expérience « un clic » attendue par un
> relecteur.
>
> **Le seam (où ça se branche, sans sur-ingénierie)** : le rôle ne peut pas vivre
> dans le TBSCert (auto-signé → auto-déclaré). Sa place est **côté EN** : un
> attribut `role` sur le SN dans le registre des identités, posé par un processus
> de confiance (seed au démarrage ou commande opérateur — *pas* un système d'admin
> web). La mise en application se réduit alors à **une vérification** dans
> `POST /enroll` : n'accepter un endossement que si `lra_sn.role == notaire`, d'où
> la chaîne **Root LRA → notaire → client**. La hiérarchie est déjà démontrable
> sans persistance navigateur via le `demo-cli` (identités sur disque) ; le web
> garde le self-enroll étiqueté « démo ».

---

### A3 — Graphe de confiance plat

✅ **RÉSOLU (2026-06-17)** — le graphe n'est plus plat. Deux gates ancrent la
hiérarchie EN → notaire → client sur l'attribut `identities.role` :
- `POST /enroll` (`enrollment.rs`) rejette tout endosseur dont `role != notaire`
  (403 Forbidden) — un client ne peut plus endosser.
- `POST /actes` (`actes.rs`) rejette la création d'acte si le créateur n'a pas
  `role == notaire` (403).
Couvert par les tests `test_client_cannot_endorse`, `test_client_cannot_create_acte`,
`test_enroll_notaire_bad_token_rejected`, `test_notaire_token_grants_acte_creation`.
Finding initial conservé ci-dessous pour traçabilité.

🟠 **Sévérité (historique) : architecturale (renforce A2)**

`enroll` (`enrollment.rs:47-48`) : « any enrolled and non-revoked identity can act
as LRA ». `create_acte` (`crates/server/src/routes/actes.rs:64`) : n'importe quel
SN authentifié devient notaire. Il n'existe aucune notion cryptographique de
« notaire » vs « client » vs « LRA » — tout le monde est tout le monde.

Documenté en §10.1, mais A1+A2+A3 ensemble signifient que dans le PoC déployé les
identités sont auto-déclarées *et* les sessions rejouables. La signature `sk` par
message est la seule chose qui ancre réellement l'authenticité — elle est donc
porteuse, et l'UI la sape (cf. A8).

---

### A4 — Doc-vs-code : la SI est signée sur le DER brut

✅ **RÉSOLU (2026-06-17)** — docs alignées sur `SI = Sign(sk, tbs_der)` dans
[`ARCHITECTURE.md §8.2`](ARCHITECTURE.md#82-format-du-certificat--x509v3-conforme-au-papier), [`CLAUDE.md`](../CLAUDE.md) (glossaire + instructions), et [`cert.rs:12`](../crates/localpki-core/src/cert.rs#L12).
Finding initial conservé ci-dessous pour traçabilité.

🟠 **Sévérité (historique) : conformité doc + cohérence**

Le glossaire ([`CLAUDE.md`](../CLAUDE.md)), [`ARCHITECTURE.md §8.2`](ARCHITECTURE.md#82-format-du-certificat--x509v3-conforme-au-papier), et le commentaire
[`crates/localpki-core/src/cert.rs:12`](../crates/localpki-core/src/cert.rs#L12) énoncent `SI = Ed25519.Sign(sk, SHA256(TBSCert_DER))`.
Le code signe le DER **directement** : `signing_key.sign(&tbs_der)`
(`enrollment.rs:75`), vérifié `verify(&tbs_der, …)` (`enrollment.rs:85`), et le
frontend correspond (`+page.svelte:64` `ed25519.sign(derBytes, …)`).

C'est *cryptographiquement correct* (Ed25519 hache en interne avec SHA-512) et
cohérent Rust+JS, donc ça marche. Mais (a) les docs sont fausses, et (b) c'est
**incohérent avec la signature des messages**, qui pré-hache explicitement :
`sign(&Sha256::digest(payload))` (`crates/messaging-crypto/src/messages.rs:82`).
Deux schémas, deux conventions, l'une mal documentée.

**Fix** : aligner les docs sur le code (SI = `Sign(sk, tbs_der)`), et décider si
l'on harmonise les deux conventions de signature ou si on documente pourquoi elles
diffèrent.

---

### A5 — Domain separation appliquée à la clé EN mais pas aux clés utilisateur

✅ **RÉSOLU (2026-06-18)** — tags de domaine ajoutés aux signatures clé-utilisateur,
en lockstep Rust/JS/demo-cli : `localpki-msg-v1\0` (message), `localpki-participant-v1\0`
(ajout participant), `localpki-revoke-v1\0` (révocation, remplace le préfixe `"Revoke"`).
Finding initial conservé ci-dessous pour traçabilité.

🟠 **Sévérité (historique) : hygiène crypto (incohérence)**

La passe d'hygiène a ajouté `localpki-auth-v1` / `localpki-merkle-v1` à la clé EN.
Mais la clé **utilisateur** signe dans quatre contextes sans tag versionné :

- SI → `tbs_der` brut (pas de tag)
- message → `SHA256(ct‖nonce‖uuid‖ts‖sn)` (pas de tag, `messages.rs:108`)
- ajout-participant → `SHA256(uuid_text‖sn_text‖byte)` (pas de tag, `participants.rs:74`)
- révocation → `SHA256("Revoke"‖SN‖SI)` (préfixe ASCII ad-hoc, `revocation.rs:51`)

La forgerie cross-contexte est majoritairement bloquée par les différences de
longueur/structure et le préfixe `"Revoke"` — donc hygiène, pas cassure active.
Mais c'est incohérent avec la discipline appliquée à la clé EN.

**Fix** : tags `localpki-msg-v1` / `localpki-participant-v1` par symétrie.

---

### A6 — ECIES ne rejette pas les points d'ordre faible

✅ **RÉSOLU (2026-06-18)** — `ecies_decrypt` rejette désormais un shared secret non
contributif (`was_contributory()`). Finding initial conservé ci-dessous.

🟡 **Sévérité (historique) : durcissement (impact faible)**

`ecies_decrypt` (`crates/messaging-crypto/src/keys.rs:78`) appelle
`diffie_hellman` et ne vérifie jamais `SharedSecret::was_contributory()`. Un
ephemeral_pk d'ordre faible produit un shared secret tout-à-zéro connu. Impact
pratique faible (les entrées d'ECIES — `c_acte_key`, `c_acte_archive` — sont
générées par le serveur/HSM ; l'exploiter nécessite une écriture en base), mais
pour une revendication « état de l'art » c'est un durcissement d'une ligne.

---

### A7 — `K_send` déterministe longue durée + nonce aléatoire

✅ **DOCUMENTÉ (2026-06-18)** — hypothèse d'unicité de nonce énoncée en
[`ARCHITECTURE.md §8.5`](ARCHITECTURE.md#85-hypothèse-dunicité-de-nonce-sous-k_send) (borne d'anniversaire ≈ 2³², issue propre = XChaCha20-Poly1305
si la contrainte AES-GCM tombe). Finding initial conservé ci-dessous.

🟡 **Sévérité (historique) : hypothèse à documenter**

`K_send = HKDF(K_acte, "send"‖SN)` est fixe pour toute la durée de vie de l'acte,
et chaque message réutilise cette clé avec un nonce GCM aléatoire de 96 bits
(`messages.rs:41`). Sûr aux volumes notariaux, mais cela repose entièrement sur le
hasard du nonce (borne d'anniversaire ≈ 2³² messages ; une réutilisation de nonce
GCM est catastrophique — fuite du XOR des clairs *et* forgerie possible). Une
phrase en §8 énonçant l'hypothèse suffit, puisqu'il n'y a pas de compteur en repli.

---

### A8 — Le client affiche du contenu non vérifié

✅ **RÉSOLU (2026-06-18)** — le contenu `sigValid === false` est mis en quarantaine
visuelle (bandeau rouge + `details` à déplier), plus présenté comme un message normal.
Finding initial conservé ci-dessous.

🟡 **Sévérité (historique) : UX de non-répudiation**

`decryptAndVerify` (`frontend/src/routes/actes/[id]/+page.svelte:161-184`) affiche
le texte déchiffré même quand `sigValid === false`, avec seulement un petit ⚠.
Comme `K_send` est *partagée par tous les participants*, la signature Ed25519 est
la **seule** chose qui distingue un vrai message d'Alice d'un message qu'un autre
participant pourrait fabriquer et qui se déchiffrerait quand même. Le serveur
rejette les mauvaises sigs à l'ingestion, donc ça ne se déclenche qu'en cas de
changement de clé/révocation/altération — mais pour un outil notarial, présenter du
contenu non vérifié comme du texte normal sape l'UX de non-répudiation.

**Fix** : retenir ou mettre en quarantaine visuelle le contenu `sigValid === false`.

---

## B. Findings ingénierie / correction

- **✅ RÉSOLU (2026-06-18) — `goto('/login')` (était une route morte)** : les 4 gardes
  (`actes/+page.svelte`, `actes/[id]/+page.svelte`, `notaire/actes/+page.svelte`,
  `notaire/actes/new/+page.svelte`) redirigent désormais vers `/` (le sélecteur de rôle,
  qui ne 404 jamais). *Reste ouvert :* aucun flux « se connecter avec une identité
  existante » (sessionStorage uniquement, §10.1).
- **✅ RÉSOLU (2026-06-17) — `root_lra_signing_key` (état mort) supprimé** de
  `AppState`, ainsi que `root_lra_sn`. *Finding initial :* la clé était seedée et
  stockée mais jamais lue (le compilateur le confirmait : *field never read*).
- **✅ RÉSOLU (2026-06-17) — `seed_root_lra` supprimée côté serveur.** *Finding
  initial :* elle insérait une ligne « Root LRA » aux pleins pouvoirs à **chaque**
  démarrage (non-idempotent — le commit `05bed03` ne corrigeait que la version
  *demo-cli*, pas celle du serveur). La notion « Root LRA » est entièrement
  retirée ; le serveur ne seede plus aucune identité. L'amorçage du premier
  notaire passe par le jeton (`/enroll/notaire`) ou le seed direct du `demo-cli`
  (`bootstrap_notaire.json`, idempotent via fichier + `INSERT OR IGNORE`).
- **✅ RÉSOLU (2026-06-17) — `rcgen` retiré + docs corrigées vers x509-cert.**
  *Finding initial :* `rcgen` était une dépendance inutilisée
  (`crates/localpki-core/Cargo.toml`). Les docs disaient « rcgen pour la génération,
  x509-cert pour le parsing » — mais la génération utilise le `TbsCertificate` de
  `x509-cert` et **rien n'est jamais parsé** (`tbs_der` figé, vérifié comme octets
  opaques). Les deux moitiés de cette phrase étaient inexactes.
- **`.unwrap()` en production** à [`crates/server/src/routes.rs:19`](../crates/server/src/routes.rs#L19) (parse de
  l'origine CORS) — viole la règle [CLAUDE.md](../CLAUDE.md) « no unwrap ». Fail-fast au boot donc
  peu d'enjeu, mais c'est le seul vrai unwrap de production (les `.expect()` HKDF
  sont réellement infaillibles).
- **Pas de dédup de message / unicité de nonce** — un expéditeur peut re-POST son
  propre `{c_message, nonce, signature, timestamp}` identique dans la fenêtre de
  300s et obtenir un second `seq`/leaf. Signature valide → le log montre le « même »
  message deux fois. Un log de transparence notarial ne devrait sans doute pas
  accepter les replays octet-pour-octet.
- **✅ RÉSOLU (2026-06-18) — Reliquat C5** : `build_auth_request` lit désormais `OsRng`
  (`authentication.rs`), homogène avec le reste du code (c'était déjà un CSPRNG).

---

## C. Conformité aux standards industriels

### C.1 Primitives — RAS

| Choix | Standard | Verdict |
|---|---|---|
| Ed25519 | RFC 8032 / ANSSI / NIST SP 800-186 | ✅ |
| X25519 | RFC 7748 | ✅ (cf. A6 pour le durcissement points d'ordre faible) |
| AES-256-GCM | NIST SP 800-38D — AEAD respecté | ✅ (cf. A7 sur l'unicité de nonce) |
| HKDF-SHA256 | RFC 5869 | ✅ |
| Merkle | RFC 6962 — domain separation 0x00/0x01 correcte | ✅ |
| Nonce GCM | 96 bits CSPRNG | ✅ |

### C.2 Comparaison avec Signal / MLS / TLS 1.3

- **Pas de forward secrecy** : assumée et documentée ([`ARCHITECTURE.md §10.1`](ARCHITECTURE.md#101-limites-assumées-choix-délibérés)).
  Antinomique avec l'archivage légal — choix défendable.
- **Pas de Double Ratchet, pas de X3DH** : assumés, pour l'archivage.
- **Pas de challenge-response à l'authentification** : c'est l'écart majeur (A1).
  Là où TLS 1.3 / Signal prouvent la possession de la clé à chaque session, ce PoC
  rejoue un credential statique. À corriger ou défendre explicitement.
- **Conversion Ed25519 → X25519** via `to_montgomery` / `to_scalar_bytes` :
  techniquement correcte, formellement non couverte par les preuves indépendantes
  des deux schémas ([`ARCHITECTURE.md §8.1`](ARCHITECTURE.md#81-paire-de-clés-unique--décision-de-poc-et-ses-limites) — bien documenté).
- **MLS (RFC 9420)** serait l'option moderne pour le groupe notarial, mais conçu
  *contre* l'archivage long — à mentionner comme la bonne alternative si la
  contrainte d'archivage tombait.
- **OWASP ASVS** : jetons de session hashés SHA-256 en DB
  (`crates/server/src/utils.rs:9`) — conforme V3.5.

---

## D. Conformité juridique notariale française

| Exigence | État | Verdict |
|---|---|---|
| eIDAS niveau Substantiel (échanges préalables) | face-à-face imposé par défaut — self-enroll gaté `ALLOW_SELF_ENROLL` (off hors dev), cf. A2 | ✅ conditionné au flag |
| eIDAS niveau Élevé (AAE) | hors périmètre | ✅ documenté |
| eIDAS qualifié (PSCQ) | non | ✅ explicite §9.1 |
| Horodatage qualifié RFC 3161 | non (timestamps serveur) | ⚠️ documenté §6.4 |
| RGPD — localisation UE | côté hébergement | N/A code |
| Conservation vs droit à l'effacement | choix de conserver | ⚠️ documenté §9.3 |
| Secret professionnel — serveur aveugle | OK (E2EE confirmée) | ✅ |
| Article 1366 Code civil | OK échanges préalables | ✅ |
| Certification ADSN | hors PoC | ✅ documenté §9.6 |

### Lacunes pesantes pour un usage réel

1. **Preuve de possession à l'authentification (A1)** : sans elle, la valeur
   probante de « telle session = telle personne » est faible — un credential
   rejouable n'établit pas la présence de la partie.
2. **Bootstrap d'identité (A2 — ✅ gaté 2026-06-18)** : `enroll_self` est désormais
   désactivé par défaut (`ALLOW_SELF_ENROLL`). En config production-like, seul le flux
   endossé face-à-face (base du niveau Substantiel) est possible. En dev le flag l'active
   pour garder l'onboarding « un clic ».
3. **Horodatage non qualifié** : intégrer une TSA RFC 3161 (Universign, CertEurope,
   Docaposte) — coût marginal faible (signer la racine Merkle périodique via TSA).
4. **`K_master` sans rotation** ([`ARCHITECTURE.md §10.1`](ARCHITECTURE.md#101-limites-assumées-choix-délibérés)) : un changement de notaire
   implique aujourd'hui la perte d'accès à tous les actes archivés. Cérémonie de
   clé HSM avec ré-encapsulation des `C_acte_archive` à concevoir avant production.
5. **`EN_SIGNING_KEY_HEX` en `.env`** : sa fuite casse la *soundness* (§6.5 du
   papier). En production, doit aller en HSM, opération sign-only.

---

## E. Points solides à valoriser

À mettre en avant — marqueurs de maturité crypto rares pour un PoC :

- **Non-répudiation via AEAD** ([`ARCHITECTURE.md §5.3`](ARCHITECTURE.md#53-envoi-dun-message)) : signer le chiffré pour
  qu'un serveur aveugle rejette les forgeries, tandis que l'AEAD préserve un
  binding bijectif chiffré↔clair pour un tribunal. Raisonnement réellement
  sophistiqué.
- **`tbs_der` figé en DB** (`crates/server/src/routes/enrollment.rs:75`) :
  neutralisation explicite du risque de dérive d'encodeur `x509-cert`.
- **`C_acte_archive` = `K_acte ‖ acte_uuid`** (`crates/server/src/hsm.rs:54`) avec
  vérification UUID au déchiffrement → bloque les attaques par swap de lignes
  archive.
- **Token de session hashé SHA-256 en DB** (`crates/server/src/utils.rs:9`).
- **Flow WebSocket ticket** (`crates/server/src/routes/ws.rs`) : évite la fuite de
  token via query string.
- **AAD AES-GCM** lie le chiffré à `(acte_uuid, ts, sn)` — empêche le rejeu
  cross-acte.
- **Re-vérification `pk` côté auth** (`crates/server/src/routes/authentication.rs:56`) :
  défense en profondeur contre le swap de clé post-enrollment.
- **Domain separation HKDF** : `"notariat-msg-v1"`, `"send"`, `"notariat-ecies-v1"`,
  `"notariat-hsm-x25519-v1"`, `"localpki-enrollment-v1"` — toutes distinctes et
  versionnées.
- **RFC 6962 strict** avec note explicite sur CVE-2012-2459 (orphan promotion,
  `crates/messaging-crypto/src/merkle.rs:10-14`).
- **`Zeroizing`** appliqué consistement sur tous les secrets (K_master, K_acte
  transit, symétriques ECIES, scalaires X25519).
- **Section §10 « limites assumées »** : nomme chaque compromis, le justifie, pointe
  la réponse de production (PRE, MLS, TSA, WebAuthn). Exactement la bonne façon de
  défendre un PoC.

---

## F. Lens interviewer — défense orale

Le raisonnement exposé est la partie forte, et c'est majoritairement le bon. Là où
un relecteur appuiera — et où il faut prendre les devants :

1. **« Déroulez-moi votre login. Qu'est-ce qui m'empêche de le rejouer ? »**
   Réponse : challenge-response (A1 ✅ résolu). Le serveur émet un nonce single-use,
   le client le signe avec `sk`, le serveur vérifie avec la `pk` du registre ; un
   `/auth/verify` rejoué échoue (nonce consommé). Montrer le test
   `test_auth_challenge_is_single_use`. Bon exemple à raconter : « j'ai audité mon
   propre login, trouvé qu'il était rejouable, et fermé le trou. »
2. **« Montrez-moi le modèle de confiance fonctionner de bout en bout. »** Le
   self-enroll est désormais gaté (off par défaut, A2 ✅) — en config production-like
   seul le flux endossé passe. Faire de `/notaire/enroller` (ou du scénario `demo-cli`)
   le flux phare en démo, plutôt que le raccourci « un clic ».
3. **« Vos docs disent SHA256(DER) et rcgen ; votre code ne fait ni l'un ni
   l'autre. »** (A4 + B — ✅ corrigés le 2026-06-17, mais sache l'expliquer). Petit individuellement, mais deux décalages doc/code
   amènent un relecteur à se méfier de *toutes* les docs — y compris des parties
   correctes et impressionnantes. Réconcilier, c'est une assurance peu coûteuse.
4. **Cadrage honnête à mettre en avant en premier** : « La confidentialité et la
   non-répudiation au niveau message sont solides et liées à la clé privée ; la
   couche identité/session-binding et le bootstrap de confiance sont les raccourcis
   délibérés du PoC. » Dit en premier, ça transforme les findings en preuves de
   lucidité.

Bilan : l'ingénierie cryptographique est solide ; les faiblesses se concentrent
dans la couche **identité / authentification / bootstrap de confiance** et dans le
**décalage doc↔code** — ni l'un ni l'autre n'était couvert par la revue précédente.

---

## G. Plan d'action priorisé

| Ordre | Effort | Action |
|---|---|---|
| 1 | ✅ fait | **A1** — challenge-response au login (`/auth/challenge` + PoP signée vérifiée dans `/auth/verify`) ; test anti-rejeu `test_auth_challenge_is_single_use` |
| 2 | ✅ fait | **A2 + A3** — attribut `role` côté EN ; jeton d'enrôlement notaire (`/enroll/notaire`) ; gates `role==notaire` sur `/enroll` et `/actes` ; suppression de « Root LRA » |
| 3 | ✅ fait | **A4 + B (docs)** — doc SI alignée sur `Sign(sk, tbs_der)` ; rcgen retiré ; docs → x509-cert |
| 4 | ✅ fait | **A5** — tags de domaine sur les signatures utilisateur (`localpki-msg-v1`, `localpki-participant-v1`, `localpki-revoke-v1`) |
| 5 | ✅ fait | **B** — `root_lra_signing_key`/`seed_root_lra` supprimés (A2/A3) ; `/login` → `/` dans les 4 gardes ; autz `get_acte` (appartenance) |
| 6 | ✅ fait | **A8** — quarantaine visuelle du contenu `sigValid === false` |
| 7 | ✅ fait | **A6 + C5** — `was_contributory()` sur ECIES ; `build_auth_request` sur `OsRng` |
| 8 | ✅ fait | **A7** — hypothèse d'unicité de nonce sous `K_send` documentée ([`ARCHITECTURE.md §8.5`](ARCHITECTURE.md#85-hypothèse-dunicité-de-nonce-sous-k_send)) |
| 9 | ouvert | **Dédup message** (replay octet-pour-octet) et **persistance d'identité** frontend |

Les sections **C** et **D** sont des sujets de défense orale plus que
d'implémentation — déjà bien anticipés dans [`ARCHITECTURE.md §9`](ARCHITECTURE.md#9-contraintes-réglementaires-françaises) et [`§10`](ARCHITECTURE.md#10-limites-assumées-et-perspectives).

---

*Revue rédigée à partir du papier [`LocalPki2019.pdf`](LocalPki2019.pdf), de [`ARCHITECTURE.md`](ARCHITECTURE.md),
et de l'audit ligne à ligne des crates `localpki-core`,
`messaging-crypto`, `server`, du `demo-cli`, et du module crypto frontend.
Remplace la revue du 2026-06-16.*
