# Architecture — Messagerie instantanée sécurisée pour le notariat
## Basée sur LocalPKI (Dumas et al., 2019)

> Document d'architecture technique — Sujet S001, Astéroïde 2026  
> Statut : document d'architecture — aligné sur l'implémentation

---

## Table des matières

1. [Contexte et positionnement](#1-contexte-et-positionnement)
2. [Entités et rôles](#2-entités-et-rôles)
3. [Couche identité — protocoles LocalPKI](#3-couche-identité--protocoles-localpki)
4. [Architecture des clés](#4-architecture-des-clés)
5. [Protocoles de messagerie](#5-protocoles-de-messagerie)
6. [Couche d'intégrité — Transparency log](#6-couche-dintégrité--transparency-log)
7. [Scénario multi-notaires](#7-scénario-multi-notaires)
8. [Choix algorithmiques](#8-choix-algorithmiques)
9. [Contraintes réglementaires françaises](#9-contraintes-réglementaires-françaises)
10. [Limites assumées et perspectives](#10-limites-assumées-et-perspectives)
11. [Modèle de données](#11-modèle-de-données)

---

## 1. Contexte et positionnement

### 1.1 Le problème adressé

Dans le notariat français actuel, les communications entre notaires et clients s'appuient sur des infrastructures centralisées (RPN — Réseau Privé des Notaires, messagerie Cryptolis) dont l'identité des parties repose sur des certificats PKIX émis par une autorité de certification centrale. Ce modèle reproduit les travers que LocalPKI cherche à corriger : dépendance à un tiers distant, coût, complexité, et point de défaillance unique systémique.

### 1.2 Ce que LocalPKI change

Dans PKIX, la CA signe le certificat de l'utilisateur — la confiance est déléguée vers le haut. Dans LocalPKI, **l'utilisateur signe lui-même son certificat** et le notaire n'enregistre, dans le modèle du papier, que l'empreinte `(SN, SI)` de ce certificat (notre implémentation l'étend pour la messagerie — cf. §2.2 et §11). La confiance est ancrée localement, vérifiable interactivement via l'EN, sans dépendance à une CA distante.

Ce changement de paradigme est directement applicable à une messagerie notariale : plutôt qu'un annuaire centralisé de comptes, les identités des parties sont ancrées dans le registre LocalPKI de chaque office notarial.

### 1.3 Périmètre du système de messagerie

Ce système couvre les **échanges préalables à l'acte** (avant-contrat, transmission de documents, coordination entre parties) — pas la signature de l'acte authentique électronique lui-même, qui relève d'une signature qualifiée eIDAS et sort du périmètre de ce sujet.

### 1.4 Le notaire comme orchestrateur

Contrairement à une messagerie grand public où les utilisateurs se cherchent et s'ajoutent mutuellement, **c'est le notaire qui ouvre les canaux de communication**. Aucune partie ne peut en contacter une autre sans avoir été mise en relation par le notaire. Ce choix est délibéré et conforme au rôle légal du notaire comme tiers de confiance.

---

## 2. Entités et rôles

Une distinction critique du papier LocalPKI est à maintenir ici : le **notaire physique** et l'**Electronic Notary (EN)** sont deux entités distinctes, même si dans un office de petite taille elles peuvent être hébergées au même endroit.

### 2.1 Local Registration Authority (LRA)

Dans notre contexte : **le notaire ou un collaborateur habilité de l'office notarial**.

Rôle :
- Vérification de l'identité physique des parties (face à face, pièce d'identité)
- Aide à la génération du certificat LocalPKI (selon le niveau technique de l'utilisateur)
- Transmission du hash `(SN, SI)` à l'EN pour enregistrement
- Ouverture des canaux de messagerie par acte

La LRA **ne voit jamais la clé privée** de l'utilisateur. Elle ne fait que transmettre le hash signé.

### 2.2 Electronic Notary (EN)

Dans notre contexte : **l'infrastructure d'Astéroïde** (ou à terme, une infrastructure mutualisée entre offices).

Rôle :
- Génération et distribution des Serial Numbers (SN)
- Stockage du registre `{(SN_i, SI_i)}` (enregistrement LocalPKI du papier), **étendu** pour la messagerie avec la clé publique `pk` et le `tbs_der` figé (cf. §11) — jamais le contenu des messages
- Réponse aux requêtes d'authentification (mode privé OCSP-like ou mode public CVL)
- Hébergement du HSM pour la gestion des clés de session
- Hébergement du Transparency log (intégrité des messages)

L'EN est le **seul point de confiance centralisé** du système — et c'est intentionnel. Sa compromission est le risque systémique principal (cf. section 6.5 du papier, attaque sur EN corrompu). Ce risque est mitigé par la nature locale et fédérée de l'architecture (chaque office peut avoir son propre EN) et par la protection matérielle du HSM.

### 2.3 Notaire participant

Le notaire est également un **utilisateur du système de messagerie**, avec son propre certificat LocalPKI `(sk_Notaire, pk_Notaire, Cert_Notaire)`. Il participe aux conversations au même titre que les autres parties, avec ses propres clés de déchiffrement.

Son rôle est triple : LRA (enregistrement des identités), administrateur du canal (ouverture, gestion des participants), et participant (envoi/réception de messages).

### 2.4 Utilisateurs finaux (clients)

Acheteur, vendeur, ou tout tiers impliqué dans le dossier. Ils génèrent leur propre paire de clés, font vérifier leur identité physiquement chez la LRA, et reçoivent un certificat LocalPKI auto-signé enregistré chez l'EN.

---

## 3. Couche identité — protocoles LocalPKI

Cette couche est reprise fidèlement du papier (Algorithme 1 et section 3). Elle n'est pas modifiée — la messagerie s'appuie sur ses garanties prouvées.

### 3.1 Enregistrement (Registration)

```
Alice génère (sk_Alice, pk_Alice)

LRA → Alice : SN_Alice, URL_EN, validity

Alice construit :
  TBSCert_Alice = X509(Alice, pk_Alice, SN_Alice, validity, URL_EN)
  SI_Alice = Sign(sk_Alice, Hash(TBSCert_Alice))
  Cert_Alice = TBSCert_Alice || SI_Alice

LRA vérifie SI_Alice (preuve de possession de sk_Alice)

LRA → EN :
  payload = {SN_Alice || SI_Alice}_{pk_EN}
  signature = Sign(sk_LRA, Hash(payload))
  Envoie : payload || signature

EN vérifie la signature LRA, ajoute (SN_Alice, SI_Alice) à sa base.
```

**Garantie** : à l'issue de l'enregistrement, l'EN a la preuve que quelqu'un possède sk_Alice (via SI_Alice), que cette personne a été vérifiée physiquement par une LRA de confiance, et que le couple `(SN_Alice, SI_Alice)` est unique dans sa base.

### 3.2 Authentification (mode privé)

Lors de la connexion d'Alice au serveur de messagerie, le serveur vérifie son certificat LocalPKI auprès de l'EN :

```
Alice → Serveur : demande de challenge
Serveur → Alice : nonce_PoP        (32 octets aléatoires, usage unique, TTL 60s)

Alice → Serveur : Cert_Alice,
                  PoP = Sign(sk_Alice, "localpki-auth-pop-v1\0" || SN_Alice || nonce_PoP)

Serveur vérifie localement :
  Hash(TBSCert_Alice) == {SI_Alice}_{pk_Alice}   (auto-signature valide)
  Verify(pk_Alice, PoP)                            (preuve de possession de sk_Alice)
  → nonce_PoP est consommé : un Cert_Alice rejoué seul ne suffit plus

Serveur → EN (URL_EN dans TBSCert_Alice) :
  AR = SN_Alice || SI_Alice || nonce_R

EN cherche (SN_Alice, SI_Alice) dans sa base.
  Si trouvé : Rep = "OK" || AR
  Sinon    : Rep = "Unknown" || AR
  EN signe : Rep || Sign(sk_EN, Hash(Rep))

Serveur vérifie la signature EN, authentifie ou rejette Alice.
```

**Preuve de possession (ajout par rapport au papier)** : le papier n'authentifie qu'un *certificat* (est-il enregistré ?). Une messagerie a besoin de prouver que *c'est bien Alice maintenant*. La SI étant une valeur publique statique, la présenter seule serait rejouable. Le serveur émet donc un challenge frais (single-use) qu'Alice signe avec `sk` — ce qui ferme le rejeu. Implémenté via `POST /auth/challenge` puis `POST /auth/verify`.

Cette vérification a lieu **à chaque ouverture de session**. Elle n'est pas répétée à chaque message — le coût d'un aller-retour EN par message serait prohibitif et contraire à l'esprit de LocalPKI qui distingue enrollment (lourd, physique) et authentification (légère, interactive).

> ⚠️ **Limite assumée — révocation en cours de session** : si Alice est révoquée pendant une session active (ex. téléphone signalé volé), le serveur ne le détecte pas avant la prochaine reconnexion. Les messages envoyés par Alice pendant cette fenêtre sont authentifiés par une clé techniquement toujours valide côté serveur. Ce risque est inhérent au modèle session-based et doit être mitigé en production par un mécanisme de révocation push (l'EN notifie activement les serveurs concernés lors d'une révocation) — hors périmètre du PoC.

### 3.3 Révocation

La révocation est gérée par le protocole LocalPKI standard (Algorithme 4 du papier) :

```
Alice (ou la LRA) → EN :
  SIRev = Cert_Alice || Sign(sk_Alice_ou_LRA, Hash("localpki-revoke-v1\0" || SN_Alice || SI_Alice))

EN vérifie la signature, supprime (SN_Alice, SI_Alice) de sa base.
```

Après révocation, toute tentative d'authentification d'Alice échoue. Un re-enregistrement complet (nouvelle paire de clés, nouvelle vérification physique) est nécessaire.

---

## 4. Architecture des clés

### 4.1 Vue d'ensemble de la hiérarchie

```
K_master  (HSM — ne quitte jamais le matériel)
    │
    └─ K_acte = HKDF-SHA256(K_master, "notariat-msg-v1" || acte_uuid)
                    │
                    ├─ Transmis chiffré à chaque participant :
                    │   C_acte_Alice   = ECIES(pk_Alice,   K_acte)
                    │   C_acte_Bob     = ECIES(pk_Bob,     K_acte)
                    │   C_acte_Notaire = ECIES(pk_Notaire, K_acte)
                    │
                    └─ Archive HSM :
                        C_acte_archive = ECIES(pk_HSM, K_acte || acte_uuid)
                        (stocké une fois par acte, à la création)
```

Les clés d'envoi par participant `K_send_Alice`, `K_send_Bob`, etc. sont dérivées de `K_acte` au moment de l'envoi des messages (cf. section 5.3). Elles ne sont jamais stockées — recalculables à la demande par quiconque possède `K_acte`.

**Propriété importante — pas d'isolation cryptographique inter-participants** : puisque `K_send_Alice = HKDF(K_acte, "send" || SN_Alice)` est entièrement déterminée par `K_acte`, tout participant qui possède `K_acte` peut dériver la clé d'envoi de n'importe quel autre participant et déchiffrer ses messages. Bob peut lire les messages d'Alice, et réciproquement. Ce n'est pas un oubli — c'est un choix assumé, documenté et justifié en section 10.1.

### 4.2 K_master — clé maître

Générée et stockée dans le HSM (Hardware Security Module) de l'office notarial. Ne quitte jamais le matériel.

Le HSM est sollicité **uniquement pour des opérations rares** :
- Dérivation de `K_acte` à la création d'un nouvel acte
- Déchiffrement de `C_acte_archive` lors d'un accès légal ou judiciaire
- Re-chiffrement de `K_acte` pour un nouveau participant (ajout ou récupération après perte de clé)

**Propriété fondamentale** : il est computationnellement impossible de retrouver `K_master` à partir de `K_acte` ou de n'importe quel ensemble de clés dérivées. HKDF est une fonction à sens unique basée sur HMAC-SHA256.

### 4.3 K_acte — clé de dossier

`K_acte = HKDF-Expand(K_master, "notariat-msg-v1" || acte_uuid, 32)`

Une clé de 256 bits par dossier notarial. Déterministe — recalculable depuis `K_master` et l'`acte_uuid` sans stockage. Chaque participant reçoit `K_acte` chiffrée avec sa propre clé publique LocalPKI à l'ouverture du canal.

**Durée de vie** : liée au dossier. À la clôture du dossier, `K_acte` est considérée comme archivée — le HSM reste capable de la recalculer si nécessaire, mais elle n'est plus distribuée.

### 4.4 C_acte_archive — garantie de dernier recours

À la création de chaque acte, le serveur stocke :

`C_acte_archive = ECIES(pk_HSM, K_acte || acte_uuid)`

C'est le mécanisme de récupération universelle. En cas de perte de toutes les clés des participants, le HSM peut déchiffrer `C_acte_archive`, retrouver `K_acte`, et reconstruire l'accès à toutes les messages du dossier.

`C_acte_archive` est **opaque pour le serveur** — il ne peut pas le lire. Seul le HSM peut le déchiffrer. Le serveur n'est jamais un intermédiaire de confiance pour le contenu.

### 4.5 Transmission sécurisée de K_acte aux participants

```
Notaire crée l'acte → HSM dérive K_acte

Pour chaque participant P :
  C_acte_P = ECIES(pk_P, K_acte)
  Serveur stocke C_acte_P associé à (acte_uuid, SN_P)

Participant P se connecte :
  Récupère C_acte_P
  Déchiffre avec sk_P → obtient K_acte
  K_acte stocké localement (mémoire sécurisée de l'application)
```

`pk_P` est extraite du `TBSCert_P` enregistré lors de l'enrollment LocalPKI — le serveur a toujours accès aux clés publiques de tous les participants enregistrés.

---

## 5. Protocoles de messagerie

### 5.1 Ouverture d'un canal (par le notaire)

```
Précondition : Alice et Bob ont tous deux un certificat LocalPKI valide
               enregistré chez l'EN. Le notaire également.

1. Notaire crée l'acte :
   acte_uuid = UUID-v4()
   acte = { uuid, titre, parties: [SN_Alice, SN_Bob], notaire: SN_Notaire, created_at }

2. HSM dérive K_acte = HKDF(K_master, "notariat-msg-v1" || acte_uuid)

3. Serveur prépare :
   C_acte_Alice   = ECIES(pk_Alice,   K_acte)
   C_acte_Bob     = ECIES(pk_Bob,     K_acte)
   C_acte_Notaire = ECIES(pk_Notaire, K_acte)
   C_acte_archive = ECIES(pk_HSM,     K_acte || acte_uuid)

4. Serveur stocke l'acte et les C_acte_* chiffrés.

5. Participants notifiés (push notification ou polling).
```

**Propriété** : aucun participant ne peut rejoindre une conversation sans y avoir été explicitement ajouté par le notaire. Il n'existe pas de mécanisme de découverte de contacts.

### 5.2 Connexion d'un participant

```
1. Alice demande un challenge ; le serveur renvoie un nonce_PoP frais (usage unique).
   Alice présente Cert_Alice + PoP = Sign(sk_Alice, tag || SN_Alice || nonce_PoP).

2. Serveur vérifie l'auto-signature ET la preuve de possession :
   Hash(TBSCert_Alice) == {SI_Alice}_{pk_Alice}
   Verify(pk_Alice, PoP)   (nonce consommé → pas de rejeu)

3. Serveur interroge l'EN (authentification mode privé, cf. 3.2).
   Si "Unknown" → connexion refusée.

4. Serveur délivre C_acte_Alice (chiffré avec pk_Alice).

5. Alice déchiffre avec sk_Alice → obtient K_acte.
   K_acte est conservé en mémoire volatile pour la durée de la session.
```

### 5.3 Envoi d'un message

```
Alice veut envoyer M dans l'acte A :

1. Alice dérive la clé d'envoi :
   K_send_Alice = HKDF-SHA256(K_acte, "send" || SN_Alice)

2. Alice génère un nonce aléatoire de 96 bits (nonce_msg)

3. Alice chiffre :
   C_M = AES-256-GCM.Encrypt(K_send_Alice, M, nonce_msg,
                               AAD = acte_uuid || timestamp || SN_Alice)

   (AAD = Additional Authenticated Data : lié au contexte, garantit
    qu'un chiffré valide dans un acte ne l'est pas dans un autre)

4. Alice signe le chiffré (étiquette de domaine `"localpki-msg-v1\0"` en tête) :
   SIG_Alice = Ed25519.Sign(sk_Alice,
                             Hash("localpki-msg-v1\0" || C_M || nonce_msg || acte_uuid || timestamp || SN_Alice))
   (l'étiquette empêche qu'une signature de message soit rejouée comme signature
    d'un autre usage de la clé d'Alice — SI, ajout de participant, révocation.)

5. Alice envoie au serveur :
   { C_M, nonce_msg, SIG_Alice, acte_uuid, timestamp, sender_sn: SN_Alice }

6. Serveur :
   a. Vérifie que SN_Alice est bien participant de l'acte.
   b. Vérifie SIG_Alice avec pk_Alice (extraite du registre LocalPKI).
      → Rejette les messages forgés avant tout stockage.
   c. Stocke le message.
   d. Ajoute une feuille au Transparency log :
      leaf = SHA-256(0x00 || SIG_Alice || acte_uuid || logged_at || seq)
   e. Notifie les autres participants.
```

**Propriété** : le serveur ne connaît jamais `K_send_Alice` (dérivée localement par Alice depuis `K_acte`). Il ne peut pas déchiffrer `C_M`. Il peut néanmoins vérifier `SIG_Alice` car la signature porte sur `C_M` (visible côté serveur) et `pk_Alice` est publique dans le registre LocalPKI.

**Pourquoi la signature porte sur le chiffré et non sur le clair**

La signature porte sur le ciphertext pour permettre au serveur de **rejeter les forgeries avant stockage**, sans jamais accéder au contenu. Cette propriété est essentielle : sans elle, un attaquant authentifié pourrait injecter un message avec `signature = random_bytes(64)`, qui serait stocké, intégré au Merkle log, et invaliderait toute la chaîne de non-répudiation.

**Cela n'affaiblit pas la non-répudiation sur le contenu.** AES-256-GCM est un mode AEAD : un tuple `(C_M, nonce, AAD, K_send_Alice)` se déchiffre vers **exactement un plaintext `M`** ou échoue. Devant un tribunal, on présente `C_M`, `SIG_Alice`, et `K_send_Alice` (recalculable depuis `K_acte` archivé via le HSM). Le tribunal :
1. Vérifie `SIG_Alice` avec `pk_Alice` → prouve qu'Alice a produit ce ciphertext exact.
2. Déchiffre `C_M` avec `K_send_Alice` → obtient `M`, sans ambiguïté (l'AEAD garantit l'unicité du résultat).

Alice ne peut pas arguer que le déchiffrement est falsifié : toute altération de `C_M` ou de `M` ferait échouer la vérification AEAD. Le lien cryptographique entre `SIG_Alice` et `M` est donc transitif et incontestable. C'est le même schéma que Signal, MLS et TLS 1.3.

### 5.4 Réception d'un message

```
Bob reçoit { C_M, nonce_msg, SIG_Alice, acte_uuid, timestamp, sender_sn }

1. Bob dérive la clé d'envoi d'Alice :
   K_send_Alice = HKDF-SHA256(K_acte, "send" || SN_Alice)
   (Bob peut faire ça car il a K_acte)

2. Bob déchiffre :
   M = AES-256-GCM.Decrypt(K_send_Alice, C_M, nonce_msg,
                             AAD = acte_uuid || timestamp || SN_Alice)
   Si déchiffrement échoue → message altéré, rejeter.

3. Bob vérifie la signature (sur le ciphertext, comme le serveur l'a fait) :
   Ed25519.Verify(pk_Alice,
                   Hash("localpki-msg-v1\0" || C_M || nonce_msg || acte_uuid || timestamp || SN_Alice),
                   SIG_Alice)
   Si invalide → non-authenticité, rejeter.
```

### 5.5 Ajout d'un participant a posteriori

Le notaire décide d'ajouter Charlie à un dossier existant, avec ou sans accès à l'historique.

```
Précondition : Charlie a un certificat LocalPKI valide chez l'EN.

1. Notaire fait une requête signée au serveur :
   { acte_uuid, add: SN_Charlie, grant_history: true/false,
     notaire_sig: Sign(sk_Notaire, Hash("localpki-participant-v1\0" || acte_uuid || SN_Charlie || grant_history)) }

2. Serveur vérifie que le demandeur est bien le notaire de l'acte.

3. HSM déchiffre C_acte_archive → K_acte

4. Serveur chiffre K_acte pour Charlie :
   C_acte_Charlie = ECIES(pk_Charlie, K_acte)
   Stocke C_acte_Charlie.

5. Si grant_history = false :
   Le serveur marque un "point de départ" pour Charlie dans le log.
   Charlie déchiffre C_acte_Charlie → K_acte, mais ne voit
   que les messages à partir de son point d'entrée.
   (L'historique antérieur est techniquement déchiffrable avec K_acte,
   mais l'interface n'y donne pas accès. Limite UI, pas crypto — documentée.)

6. Charlie est notifié et peut rejoindre la conversation.
```

**Note** : la gestion de l'accès à l'historique est une décision de politique (notaire), pas une garantie cryptographique forte ici. Une implémentation plus robuste nécessiterait des clés de session rotatives (ratchet) ou du PRE — cf. section 10.

### 5.6 Perte de clé et récupération

```
Alice perd sk_Alice (téléphone perdu ou volé).

1. Alice (ou le notaire) déclenche la révocation LocalPKI (cf. 3.3).
   → (SN_Alice, SI_Alice) supprimé de la base EN.
   → Alice ne peut plus s'authentifier.

2. Alice se présente physiquement chez la LRA.
   Nouveau processus d'enrollment : génération de (sk_Alice_new, pk_Alice_new),
   nouveau TBSCert, nouveau (SN_Alice_new, SI_Alice_new) enregistré chez l'EN.

3. Notaire met à jour les actes en cours :
   HSM déchiffre C_acte_archive → K_acte
   C_acte_Alice_new = ECIES(pk_Alice_new, K_acte)
   Serveur met à jour la table des participants.

4. Alice peut se reconnecter avec sk_Alice_new, récupère C_acte_Alice_new,
   déchiffre K_acte, et accède à l'historique complet.
```

**Cas compromission (vol avec accès)** : si l'attaquant a eu accès à sk_Alice ET à K_acte en cache, il a pu lire les messages passés et signer de faux messages pendant la fenêtre de compromission. La révocation coupe l'accès futur mais ne protège pas le passé. Ce risque est documenté et inhérent à tout modèle où les clés résident sur l'appareil client (cf. section 10).

---

## 6. Couche d'intégrité — Transparency log

Inspiré du principe d'attestation périodique signée par une autorité de confiance, dans la lignée de **Certificate Transparency** (Laurie et al., RFC 6962) — pas du CVL du papier LocalPKI, qui est une simple liste signée de `(SN, SI)` valides pour le statut des certificats. Ici on construit un arbre de Merkle append-only sur les **messages**, dont la racine est signée périodiquement par l'EN. La filiation conceptuelle commune avec le CVL se limite à *"structure signée par l'EN pour permettre la vérification distribuée"*.

### 6.1 Structure

Le Transparency log est un **journal append-only** structuré en arbre de Merkle. Chaque entrée est :

```
leaf_i = SHA-256(0x00 || SIG_i || acte_uuid || logged_at_i || seq_i)
```

Où `0x00` est le préfixe feuille RFC 6962 (séparation de domaine feuille/nœud interne), `logged_at_i` l'horloge serveur au moment de l'append, et `seq_i` le numéro de séquence monotone du message dans l'acte.

La racine de l'arbre `root_n` est signée **à chaque append** par l'EN, avec une étiquette de domaine pour éviter toute confusion avec d'autres usages de `sk_EN` (ex : `AuthResponse`) :
```
signed_root = Sign(sk_EN, "localpki-merkle-v1\0" || root_n || timestamp_le)
```
où `timestamp` est l'horloge serveur au moment de l'append (`logged_at`). `GET /actes/:id/merkle` renvoie la racine courante, la signature de l'EN et cet horodatage.

### 6.2 Propriétés garanties

- **Existence** : un message donné peut être prouvé *scellé* dans le journal par une **preuve d'inclusion** (chemin Merkle) — `proof`/`verify_proof` dans `merkle.rs` (RFC 6962). Voir la note de périmètre ci-dessous pour son exposition.
- **Ordre** : les messages ont un ordre total non falsifiable (numéro de séquence dans le leaf).
- **Intégrité** : toute modification d'un message invalide tous les hashes suivants dans la chaîne.
- **Non-répudiation** : `SIG_i` est inclus dans chaque leaf — la preuve d'authenticité est liée à la preuve d'existence.

> **Périmètre du PoC** : l'API expose la **racine signée** du journal (append-only, horodatée, signée par l'EN), ce qui démontre l'**anti-falsification** et l'**ordre total**. La génération de **preuves d'inclusion par message** est présente et testée dans `merkle.rs`, mais n'est pas branchée sur une route HTTP : son exposition (`GET …/merkle/proof/:seq`) est une étape de production simple, laissée hors périmètre.

### 6.3 Ce que le log ne garantit pas

Le log ne prouve **pas** le contenu des messages (qui reste chiffré et opaque). Il prouve que _quelqu'un possédant sk_Alice_ a envoyé _quelque chose_ à l'instant `t`. C'est la garantie attendue : authenticité de l'expéditeur et antériorité, sans exposition du contenu.

### 6.4 Horodatage — limite importante

Les timestamps utilisés ici sont des **timestamps serveur**, pas des horodatages qualifiés RFC 3161. Pour qu'un message ait une pleine valeur probante devant un tribunal français, il faudrait un horodatage qualifié émis par une Autorité d'Horodatage (TSA) agréée. C'est une limite connue du PoC — une intégration TSA est possible en production.

---

## 7. Scénario multi-notaires

Dans une transaction immobilière française, l'acheteur et le vendeur ont fréquemment **des notaires différents**. Les deux doivent participer au dossier.

### 7.1 Deux ENs distincts

Chaque office notarial peut gérer son propre EN (c'est l'objectif de décentralisation de LocalPKI). Les deux ENs doivent pouvoir valider les certificats de l'autre pour que la messagerie fonctionne entre clients de différents offices.

### 7.2 Cross-certification entre ENs

Le papier LocalPKI décrit ce mécanisme (section 4) via des **Merkle Patricia Trees partagés entre ENs** — une blockchain privée entre notaires. Chaque EN tague ses entrées avec un identifiant `TAG_k` pour éviter les collisions de SN.

Dans notre contexte, le Notaire B rejoint la conversation comme **participant standard** avec son propre certificat LocalPKI. Son EN d'appartenance est indiqué dans son `TBSCert` (champ `URL_EN`). Le serveur du Notaire A vérifie le certificat du Notaire B auprès de l'EN de B — cross-certification standard.

### 7.3 Responsabilité de l'archivage

Quand deux notaires participent à un acte, **les deux doivent archiver**. Dans notre modèle, chaque notaire reçoit `K_acte` chiffré avec sa propre clé publique et stocke `C_acte_archive` chiffré avec son propre HSM. L'acte est donc archivé de façon redondante dans les deux offices.

### 7.4 Limite ouverte

L'interopérabilité complète entre ENs (Merkle Patricia Tree partagé, consensus sur les révocations, gouvernance des cross-certifications) est un **problème ouvert** dans le papier LocalPKI lui-même (mentionné en "further work"). Pour le PoC, on simule un seul EN mais l'architecture est conçue pour être extensible.

---

## 8. Choix algorithmiques

Tous les algorithmes suivants sont qualifiés par l'ANSSI (RGS v2) ou recommandés par le NIST.

| Usage | Algorithme | Justification |
|---|---|---|
| Identité et signature | Ed25519 (EdDSA sur Curve25519) | Non-malléable, rapide, clés courtes (32 octets), recommandé ANSSI |
| Chiffrement asymétrique (ECIES) | X25519 + HKDF + AES-256-GCM | Dérivé de la clé Ed25519 (voir 8.1) |
| Chiffrement symétrique | AES-256-GCM | AEAD, qualifié ANSSI, authentification intégrée |
| Dérivation de clés | HKDF-SHA256 (RFC 5869) | Standard de facto, utilisé pour K_acte et K_send |
| Hachage | SHA-256 | Qualifié ANSSI, utilisé dans LocalPKI |
| Nonces | 96 bits CSPRNG | Taille recommandée pour AES-GCM |
| Format certificat | X.509v3 auto-signé (x509-cert) | Conforme à la section 5 du papier LocalPKI |

### 8.1 Paire de clés unique — décision de PoC et ses limites

Dans ce PoC, chaque utilisateur possède **une seule paire de clés Ed25519** `(sk, pk)` servant à la fois à la signature (non-répudiation) et au chiffrement asymétrique (transmission de `K_acte`).

Techniquement, cette dualité est rendue possible par la relation mathématique entre Ed25519 et X25519 : les deux reposent sur Curve25519, respectivement en représentation Edwards et Montgomery. La conversion est déterministe et supportée par `ed25519-dalek` :

```rust
// Conversion clé publique Ed25519 → X25519 pour ECIES
let x25519_pk = ed25519_verifying_key.to_montgomery();

// Conversion clé privée Ed25519 → X25519 pour déchiffrement
let x25519_sk = x25519_dalek::StaticSecret::from(
    ed25519_signing_key.to_scalar_bytes()
);
```

**Pourquoi cette approche n'est pas une fin en soi :**

- **Principe de séparation des usages** : une clé devrait servir à un seul but cryptographique. Les preuves de sécurité formelles d'Ed25519 (signature) et de X25519 (DH) sont indépendantes — leur composition sur le même matériel clé n'est pas couverte par ces preuves.
- **Granularité de révocation impossible** : renouveler la clé de chiffrement sans invalider l'identité de signature (ou l'inverse) est impossible avec une seule paire.
- **Agilité algorithmique contrainte** : migrer vers des algorithmes post-quantiques distincts pour la signature (ML-DSA) et le chiffrement (ML-KEM) impose mécaniquement deux paires.

En production, l'architecture devrait adopter deux paires distinctes, toutes deux référencées dans le TBSCert via une extension X.509v3 custom pour la clé de chiffrement X25519.

### 8.2 Format du certificat — X.509v3 conforme au papier

Conformément à la section 5 du papier LocalPKI, les certificats sont des X.509v3 auto-signés. La correspondance avec les champs standard est :

| Champ LocalPKI | Champ X.509v3 | Valeur |
|---|---|---|
| SN (Serial Number) | `serialNumber` | Alloué par l'EN à la LRA |
| SI (Signature Id) | Signature du certificat | `Sign(sk_user, TBSCert_DER)` |
| URL_EN | Extension custom ou `subjectAltName` | URL du serveur EN |
| Identité utilisateur | `subject` (CN, O, etc.) | Données vérifiées par la LRA |
| Validité | `notBefore` / `notAfter` | Définie par la LRA |

En Rust : crate `x509-cert` pour l'encodage DER du `TBSCertificate` ; il n'y a pas d'étape de parsing — le `tbs_der` signé est figé en base à l'enrollment (cf. §11), ce qui découple la vérification de SI des évolutions de l'encodeur. L'auto-signature remplace la signature CA — le certificat est techniquement un certificat racine auto-signé, exactement comme décrit dans le papier.

> **Précision sur SI** : l'implémentation signe le `TBSCert_DER` **directement** — `SI = Ed25519.Sign(sk_user, TBSCert_DER)`. Ed25519 applique son propre hachage interne (SHA-512) ; il n'y a pas de SHA-256 explicite avant signature. La notation `Hash(TBSCert)` du §3.1 reste l'abstraction du papier.

### 8.3 Granularité du Transparency log — décision de PoC et ses limites

Dans ce PoC, **chaque message génère immédiatement une feuille** dans le Merkle log. Cette approche est simple à implémenter et démontre le concept en temps réel.

**Pourquoi ce n'est pas optimal en production :**

Le Certificate Transparency (CT) standard, qui utilise la même structure, fonctionne avec un **Maximum Merge Delay (MMD)** — les feuilles sont accumulées sur une fenêtre de temps avant qu'une nouvelle racine soit calculée et signée par l'EN. Les raisons :

- **Coût des opérations de signature** : signer la racine à chaque message implique une signature EN par message — coûteux à l'échelle.
- **Atomicité des lots** : un lot signé atomiquement offre une meilleure garantie d'ordre que des feuilles individuelles.
- **Performances I/O** : une écriture groupée est plus efficace qu'une écriture par message.

En production, un MMD de 1 à 5 secondes serait raisonnable pour une messagerie notariale — assez court pour la valeur probante, assez long pour l'efficacité.

### 8.4 Note sur l'agilité algorithmique post-quantique

Le NIST a standardisé en 2024 ML-KEM (FIPS 203, issu de Kyber) et ML-DSA (FIPS 204, issu de Dilithium) comme algorithmes post-quantiques. Pour un système notarial destiné à archiver sur des décennies, la migration vers ces algorithmes est inévitable.

L'architecture actuelle est conçue pour permettre cette migration : les clés sont identifiées par `SN` dans LocalPKI, permettant une coexistence de plusieurs schémas cryptographiques dans la même base. La transition pourrait s'opérer par un re-enrollment progressif des utilisateurs avec de nouvelles clés ML-DSA/ML-KEM, sans rupture de service.

### 8.5 Hypothèse d'unicité de nonce sous `K_send`

`K_send_Alice = HKDF(K_acte, "send" || SN_Alice)` est **fixe pour toute la durée de vie de l'acte**. Chaque message chiffre avec cette même clé sous un **nonce AES-GCM aléatoire de 96 bits**. La sécurité repose donc entièrement sur la non-collision de ces nonces : une réutilisation de nonce sous GCM est catastrophique (fuite du XOR des clairs *et* récupération du sous-clé d'authentification ⇒ forgerie). La borne d'anniversaire place le risque à ≈ 2³² messages **par participant et par acte** — plusieurs ordres de grandeur au-dessus des volumes notariaux réalistes d'un dossier. L'hypothèse est donc tenue ici sans compteur de repli.

> **Renforcement (implémenté)** : un index unique `(acte_uuid, sender_sn, nonce)` rejette désormais (**409 Conflict**) toute réutilisation de nonce par un expéditeur dans un acte — l'invariant GCM n'est plus seulement probabiliste, il est imposé au niveau du stockage. Effet de bord : le rejeu octet-pour-octet d'un message est fermé.

Si cette marge devenait insuffisante (usage à très haut volume), deux réponses propres : (a) **XChaCha20-Poly1305** (nonce 192 bits ⇒ collision aléatoire négligeable, aucun état à maintenir), ou (b) un **nonce déterministe à compteur** par `K_send`. La première est préférable car sans état ; elle dévierait toutefois de la décision « AES-256-GCM » figée pour ce PoC (cf. [`CLAUDE.md`](../CLAUDE.md)).

---

## 9. Contraintes réglementaires françaises

### 9.1 Périmètre légal de ce système

Ce système couvre les **échanges préalables à l'acte** — il n'a pas vocation à remplacer la signature qualifiée eIDAS requise pour l'acte authentique électronique lui-même (décret n°2005-973 modifié 2021). LocalPKI n'est pas aujourd'hui un Prestataire de Services de Confiance Qualifié (PSCQ) au sens eIDAS — c'est une limite réglementaire à documenter.

### 9.2 eIDAS et niveaux d'assurance

Pour les échanges préalables, un niveau d'assurance **Substantiel** (eIDAS) est généralement suffisant. L'enrollment physique face à face de LocalPKI est compatible avec ce niveau. Un niveau **Élevé** (requis pour l'AAE) nécessiterait une certification formelle de l'EN comme PSCQ — perspective long terme pour Astéroïde.

### 9.3 RGPD

Les messages contiennent des données personnelles (parties, coordonnées, données patrimoniales). Le notaire est le **responsable de traitement**. Points critiques :

- **Droit à l'effacement vs. obligation de conservation** : tension irrésoluble. Un message dans le Merkle log ne peut pas être supprimé sans invalider la chaîne. On assume que l'obligation notariale de conservation prime sur le droit à l'effacement pour les échanges liés à un acte.
- **Localisation des données** : le serveur doit être hébergé en UE, idéalement en France.
- **Durée de conservation des échanges** : à définir par chaque office (différente des 75 ans du minutier — les échanges préalables n'ont pas de durée légale fixée, mais la prudence recommande la durée du dossier + quelques années).

### 9.4 Secret professionnel

Les notaires sont soumis au secret professionnel. L'architecture de chiffrement côté client (serveur aveugle au contenu) est un renforcement de cette obligation — le serveur ne peut pas lire les échanges confidentiels entre notaire et client.

### 9.5 Droit au refus du numérique

Toute personne peut légalement refuser les échanges numériques. Ce système est une option, pas une obligation. L'office doit maintenir une procédure papier parallèle.

### 9.6 Certification ADSN

En production, toute solution intégrée à l'infrastructure notariale française doit être certifiée par l'ADSN (Association pour le Développement du Service Notarial). C'est une contrainte d'entrée sur le marché, pas une contrainte technique immédiate pour le PoC.

---

## 10. Limites assumées et perspectives

### 10.1 Limites assumées (choix délibérés)

**Fusion des rôles LRA et EN sur un même serveur** : dans le papier LocalPKI, LRA (Local Registration Authority) et EN (Electronic Notary) sont deux entités distinctes sur le réseau. La LRA vérifie l'identité physique d'Alice, puis envoie `{SN||SI||pk}` chiffré en ECIES pour l'EN (Algorithm 1, étape 9). Dans ce PoC, les deux rôles sont joués par le même serveur Axum — ce qui a deux conséquences directes :

1. **Le canal LRA→EN est supprimé** : le serveur traite directement la requête `POST /enroll` sans passer par un message chiffré inter-entités. HTTPS remplace l'ECIES du papier pour le transport. La crate `localpki-core` contient néanmoins `prepare_lra_to_en_message()` qui implémente l'ECIES fidèle au papier — elle est utilisée par le `demo-cli` pour simuler le flux original, mais pas par le frontend.

2. **Trois chemins d'enrôlement, stratifiés par rôle** (le rôle vit dans le registre EN — cf. ci-dessous) :
   - `POST /enroll/notaire` — la personne génère ses clés **dans le navigateur**, auto-signe son TBSCert, et présente le **jeton d'enrôlement notaire**. Le serveur vérifie le jeton (comparaison constante-time) et enregistre l'identité avec `role = notaire`. La clé privée ne transite jamais ; seul le jeton (l'autorité d'amorçage de l'EN) circule.
   - `POST /enroll` (endossé) — `/notaire/enroller` fait jouer au notaire le rôle de LRA : il endosse le cert d'un client via `enrollment.ts::endorseCert()` (signature Ed25519 sur `SHA256(SN||SI||pk)`). Le serveur vérifie la signature **et que l'endosseur a `role = notaire`** avant d'enregistrer le client (`role = client`).
   - `POST /enroll/self` — raccourci démo : le client s'auto-enrôle en un clic, toujours avec `role = client`. Il ne peut **jamais** se déclarer notaire (cela exige le jeton). L'ancre de confiance n'est donc pas contournée pour les rôles privilégiés. **Ce chemin est désactivé par défaut** (flag `ALLOW_SELF_ENROLL`, secure-by-default) : une configuration « production-like » le coupe et force le flux endossé `POST /enroll` (vérification face-à-face, base du niveau eIDAS Substantiel). En dev, le `.env` l'active pour garder l'onboarding « un clic ».

**Gestion des rôles (implémentée)** : le registre des identités porte un attribut `role ∈ {notaire, client}` (colonne `identities.role`, défaut `client`). Le rôle **ne peut pas** vivre dans le TBSCert auto-signé (il serait auto-déclaré) ; sa place est **côté EN**. Il est posé par un processus de confiance : le **jeton d'enrôlement notaire** (l'EN désigne ses notaires — fidèle au papier §2.1 « the LRA is registered by some EN ») ou un seed opérateur (le `demo-cli` insère le notaire d'amorçage directement en base). Deux gates en découlent : `POST /enroll` n'accepte un endossement que si `lra_sn.role == notaire`, et `POST /actes` n'autorise la création d'acte que pour un `role == notaire`. La chaîne **EN → notaire → client** est ainsi *imposée*, pas seulement *possible*. Le jeton est réutilisable (plusieurs notaires) ; en dev il est fixe via `.env` et affiché dans l'UI, en prod il est aléatoire par démarrage et imprimé dans les logs (secret opérateur).

**Pas de forward secrecy sur les messages** : contrairement à Signal, les messages passés peuvent être déchiffrés si `K_acte` est compromise. Ce choix est délibéré et nécessaire pour l'archivage légal. Forward secrecy et archivage légal sont des propriétés fondamentalement contradictoires dans le modèle actuel.

**Pas d'isolation cryptographique entre participants d'un même acte** : dans le modèle actuel, tous les participants partagent `K_acte` et peuvent donc dériver la clé d'envoi de n'importe quel autre participant (`K_send_Alice = HKDF(K_acte, "send" || SN_Alice)`). Bob peut techniquement déchiffrer les messages d'Alice, et réciproquement. Ce choix est délibéré et cohérent avec la nature d'un dossier notarial : un acte est un espace de confiance partagé entre toutes les parties, pas un ensemble de conversations bilatérales privées.

Deux alternatives ont été étudiées et écartées :

*Alternative A — clés par participant dérivées de K_acte* : on pourrait introduire une clé intermédiaire `K_participant_Alice = HKDF(K_acte, "participant" || SN_Alice)` propre à Alice. Mais cette clé étant elle-même dérivée déterministiquement depuis `K_acte`, quiconque possède `K_acte` peut la recalculer instantanément. L'isolation serait purement symbolique — sans aucune valeur cryptographique réelle.

*Alternative B — clés par participant aléatoires et indépendantes* : des `K_Alice`, `K_Bob` générées aléatoirement, sans lien dérivationnel avec `K_acte`, offriraient une vraie isolation. Mais elles introduisent un problème opérationnel critique : lors de l'ajout d'un nouveau participant Charlie, le serveur ne peut pas recalculer `K_Alice` depuis `K_acte` — elle n'existe nulle part. La seule façon de rechiffrer l'historique pour Charlie serait soit qu'Alice soit connectée pour fournir `K_Alice` en temps réel, soit de stocker une archive HSM séparée pour chaque `K_<participant>` par acte, ce qui fait exploser la complexité de gestion des secrets et multiplie les surfaces d'attaque sans gain proportionnel.

La solution cryptographiquement correcte qui résoudrait ce problème sans ces compromis est le **Proxy Re-Encryption** — documenté en section 10.2.

**L'accès à l'historique pour un nouveau participant est une garantie UI, pas crypto** : quand `grant_history = false`, Charlie ne voit pas l'historique dans l'interface, mais il pourrait techniquement le déchiffrer avec `K_acte`. Découle directement de la limite précédente.

**Timestamp serveur non qualifié** : valeur probante limitée sans TSA qualifiée RFC 3161.

**Cas de compromission simultanée clé/device** : si l'appareil d'Alice est volé avec accès, l'attaquant peut lire les messages passés (K_acte en cache) et signer de faux messages (sk_Alice). La révocation coupe l'accès futur mais ne protège pas la fenêtre de compromission passée. C'est un risque inhérent aux modèles où les clés résident sur l'appareil.

**Vérification EN à la connexion, pas à chaque message** : une révocation intervenant pendant une session active n'est pas immédiatement effective.

**`seq` attesté par l'EN, pas contresigné par l'expéditeur** : la signature client porte sur `(ciphertext, nonce, acte_uuid, timestamp, SN)` mais pas sur `seq`, attribué par le serveur à l'insertion. La non-répudiation du couple *(message, position)* repose donc sur la signature de l'EN sur la racine Merkle après append (qui scelle `leaf = H(SIG || acte_uuid || timestamp || seq)`), pas sur une signature directe de l'expéditeur. Cohérent avec le rôle de l'EN comme tiers de confiance LocalPKI ; un schéma à round-trip où le client contresigne `(hash_ciphertext, seq)` après attribution est possible mais ajoute une latence pour fermer une fenêtre étroite (l'expéditeur reçoit `seq` et la racine signée dans la réponse et peut les conserver comme preuve).

**Renouvellement de certificat non traité** : le papier LocalPKI mentionne explicitement les *renewals* parmi les fonctions d'une PKI (§2). Notre PoC ne traite que la révocation et le re-enrollment après perte de clé — il n'existe pas de flux *"mon cert expire dans 30 jours, je veux le renouveler sans repasser par une vérification physique"*. En production, un protocole de renouvellement par chaîne de confiance (l'ancien `sk` signe le nouveau `pk`) éviterait un face-à-face inutile à chaque expiration.

**`K_acte` déterministe — pas de rotation de `K_master` possible** : `K_acte = HKDF(K_master, acte_uuid)` est recalculée à la volée sans stockage. Conséquence directe : si `K_master` doit tourner (fin de vie HSM, compromission soupçonnée, succession d'office), on perd l'accès à **tous les actes passés**, puisqu'une nouvelle `K_master` ne reproduit aucune ancienne `K_acte`. Une rotation propre exigerait soit (a) une réencryption massive de tous les `C_acte_archive` avec la nouvelle `K_master`, soit (b) un stockage explicite des `K_acte` chiffrées par `K_master` (au lieu de la dérivation déterministe). Le PoC accepte la rigidité au profit de la simplicité d'implémentation et de l'absence d'état dérivable.

**Clé de signature de l'EN également en clair dans `.env`** : `K_master` est wrappée dans `Zeroizing<T>` et destinée à un HSM en production. Mais `EN_SIGNING_KEY_HEX` — qui signe les `AuthResponse` et la racine du Merkle log — est traitée comme une simple variable d'environnement, alors que sa fuite équivaut à *"soundness cassée"* au sens du modèle de menace du papier (§6.5 : un attaquant qui a `sk_EN` peut s'enregistrer comme Alice, falsifier les `AuthResponse`, signer de fausses racines Merkle). En production, **cette clé doit aussi être en HSM** (opération de signature uniquement, pas d'export).

### 10.2 Perspectives d'évolution

**Proxy Re-Encryption (PRE)** : schéma Ateniese et al. (2006) sur couplages bilinéaires. C'est la solution qui résoudrait proprement le problème d'isolation inter-participants tout en conservant toutes les autres propriétés du système.

Le principe : Alice chiffre ses messages avec sa propre clé publique `C_alice = ECIES(pk_Alice, M)`. Elle génère une *re-encryption key* `rk_Alice→Bob = f(sk_Alice, pk_Bob)` qu'elle remet au serveur. Quand Bob veut lire, le serveur applique `ReEncrypt(rk_Alice→Bob, C_alice) → C_bob` que Bob déchiffre avec `sk_Bob`. Le serveur a transformé le chiffré sans jamais voir `M`.

Cette approche offrirait : isolation cryptographique réelle entre participants, ajout de Charlie sans personne connecté (le HSM détient `rk_Alice→HSM` permettant un accès judiciaire ciblé message par message sans exposer d'autres messages), et serveur toujours aveugle au contenu. Elle reste incompatible avec la forward secrecy — propriété fondamentalement contradictoire avec l'archivage, indépendamment du schéma de chiffrement.

Écarté pour le PoC en raison de la complexité d'implémentation : le PRE repose sur des couplages bilinéaires (courbes BN256 ou BLS12-381) qui représentent un ordre de magnitude supplémentaire par rapport à la cryptographie sur Curve25519 utilisée ici. Les crates Rust disponibles (`ark-works`) sont matures mais demandent une expertise significative pour une utilisation correcte et sécurisée.

**Post-quantique** : migration vers ML-KEM (Kyber, NIST FIPS 203) pour le chiffrement asymétrique et ML-DSA (Dilithium, NIST FIPS 204) pour les signatures. La bibliothèque `pqcrypto` en Rust expose ces primitives.

**Horodatage qualifié** : intégration d'une TSA qualifiée (ex. Universign, CertEurope) pour produire des preuves d'existence RFC 3161 sur chaque feuille du Merkle log.

**Multi-EN avec blockchain privée** : implémentation du mécanisme Merkle Patricia Tree décrit en section 4 du papier pour l'interopérabilité entre offices notariaux.

**HSM rotation et succession** : protocole de cérémonie de clé pour la passation entre notaires (retraite, succession d'office), et procédure de sauvegarde sécurisée du HSM.

**Transparency log sur les actions de l'EN (auditabilité)** : la sécurité prouvée du papier LocalPKI repose sur l'hypothèse *"EN honnête"* (§6.5 du papier). Si un EN devient malveillant — ou si son `sk_EN` est compromis — il peut enregistrer une fausse identité, signer des `AuthResponse` mensongères, ou exclure silencieusement des entrées de sa base. Le papier lui-même cite **ARPKI** (Basin et al., 2014) et les **enhanced Certificate Transparency** schemes (Ryan, 2014) comme évolutions naturelles. Concrètement : tenir un second arbre de Merkle public listant toutes les actions de l'EN (enregistrements, révocations, signatures de racines), publié en append-only et auditable par n'importe quel tiers. Toute divergence entre ce que voit l'utilisateur et ce que voit l'audit deviendrait une preuve cryptographique de compromission. Ce serait l'équivalent pour LocalPKI de ce que CT a apporté à PKIX face aux CA malveillantes.

**Cross-certification multi-EN** : §7 documente la limite, mais répétons — le papier LocalPKI §4 décrit en détail un protocole de **Merkle Patricia Tree partagé** entre ENs (blockchain privée notariale) avec tags `TAG_k` pour éviter les collisions de SN. Notre PoC simule un seul EN. Une mise en production réelle dans le notariat français (où acheteur/vendeur ont fréquemment des notaires distincts) impose d'implémenter ce mécanisme. C'est une *"further work"* explicite du papier original — pas un oubli de notre part, mais un travail substantiel à part entière.

**Mode public (CVL) en complément du mode privé** : le papier propose deux modes d'authentification — privé (interactif EN, toujours à jour, coûteux par opération) et public (CVL bufferisé, refresh "in days", faible coût par opération). Nous n'implémentons que le mode privé. À grande échelle, un mode CVL permettrait de réduire fortement la charge sur l'EN — chaque LRA/serveur cache localement la CVL signée de son sous-domaine de SN et l'utilise pour authentifier sans round-trip. Compromis acceptable pour la plupart des actes (latence de révocation = jours plutôt qu'instantané), à coupler avec une notification push pour les révocations urgentes.

**Choix de `@noble` plutôt que Web Crypto API (`SubtleCrypto`)** : le frontend utilise les librairies `@noble/curves` et `@noble/ciphers` plutôt que l'API native du navigateur `SubtleCrypto`. Bien que `SubtleCrypto` protège les clés dans un espace mémoire isolé (les clés `CryptoKey` ne sont pas exportables par défaut), deux contraintes ont motivé ce choix : (1) le support d'Ed25519 dans `SubtleCrypto` est arrivé tardivement et reste inégal selon les navigateurs — Firefox l'a activé en 2024, Safari en 2025 — ce qui rend `SubtleCrypto` risqué pour un PoC devant tourner sur plusieurs navigateurs même en 2026 ; (2) `SubtleCrypto` ne propose pas de conversion Ed25519→X25519 native, opération centrale dans ce projet (une seule paire de clés pour signature et chiffrement). `@noble` offre cette conversion de façon explicite et auditée. Contrepartie : les clés privées manipulées via `@noble` sont de simples `Uint8Array` dans le heap JS, sans protection mémoire — contrairement à `Zeroizing<T>` côté Rust qui efface le contenu à la fin du scope. En JS, le GC ne garantit ni le moment ni la complétude de l'effacement : une clé privée peut rester en mémoire indéfiniment après sa dernière utilisation. Une alternative architecturale serait de basculer vers une application **desktop** (Electron, Tauri) qui aurait accès à des primitives système de zeroing et pourrait stocker les clés dans le keychain OS — mais cette piste est hors périmètre du PoC. En production web, la solution serait WebAuthn + PRF (voir ci-dessous).

**Persistence de l'identité entre sessions (limite PoC)** : les clés privées et le certificat sont stockés en `sessionStorage` — fermer l'onglet (ou rafraîchir après fermeture) efface tout, forçant un nouvel enrollment. Il n'existe pas de flux "se connecter avec une identité existante" dans ce PoC.

L'alternative la plus simple sans matériel spécialisé serait `localStorage` chiffré par mot de passe via PBKDF2 ou Argon2 : l'utilisateur choisit un mot de passe à l'enrollment, la clé privée est chiffrée (AES-256-GCM, clé dérivée du mot de passe + sel aléatoire), et le blob chiffré est persisté dans `localStorage`. À l'ouverture de session, l'utilisateur saisit son mot de passe pour déchiffrer et recharger ses clés — sans ré-enrollment. Cette approche a été écartée ici pour garder le flux de démonstration linéaire et éviter d'introduire une primitive de dérivation de clé depuis un secret humain (PBKDF2/Argon2) non couverte par les exigences du PoC.

**WebAuthn / FIDO2 pour la protection des clés côté client** : dans ce PoC, les clés privées des clients sont stockées en `sessionStorage` côté navigateur — extractibles par XSS et sans preuve de présence physique. Une cible production devrait s'appuyer sur WebAuthn (W3C) / FIDO2 pour ancrer les clés dans du matériel (YubiKey, Secure Enclave macOS/iOS, TPM Windows Hello).

Le principe : une YubiKey ou un TPM génère la paire de clés *à l'intérieur du hardware* — la clé privée n'en sort jamais. Le navigateur lui soumet un hash à signer, récupère la signature, sans jamais accéder à la clé privée.

```
Navigateur JS          YubiKey / TPM
      │                      │
      │── "signe ce hash" ──►│
      │                      │  (opération interne)
      │◄── signature ────────│
      │   (sk jamais visible côté JS)
```

Comparaison avec le modèle `sessionStorage` actuel :

| Propriété | sessionStorage (PoC) | WebAuthn hardware |
|---|---|---|
| Résistance XSS | Non — clé extractible | Oui — clé dans hardware |
| Extractable en console | Oui | Impossible |
| Présence physique requise | Non | Oui (PIN + tap) |
| Non-répudiation légale | Faible | Forte |

**Contrainte architecturale** : WebAuthn est conçu pour l'*authentification*, pas pour le chiffrement/déchiffrement. Or ce système requiert les deux opérations — signer des messages (compatible WebAuthn) **et** dériver `K_send` / déchiffrer via X25519 DH (incompatible WebAuthn — la clé privée ne sortant pas du hardware, le DH est impossible).

La solution hybride réaliste serait :

- **WebAuthn** → protège la clé de signature Ed25519, authentifie l'utilisateur avec preuve de présence physique
- **sessionStorage chiffré** → stocke `K_send` et le matériel de dérivation X25519, chiffré par une clé dérivée du credential WebAuthn (ex. PRF extension FIDO2)

WebAuthn deviendrait ainsi le "coffre-fort" matériel déverrouillant le reste des secrets de session. La FIDO2 PRF extension (disponible sur YubiKey 5 et Secure Enclave récents) permet précisément de dériver un secret déterministe depuis un credential hardware — ce qui couvrirait le besoin de dérivation symétrique sans exposer de clé privée.

---

## 11. Modèle de données

### Tables principales

> Les timestamps sont stockés en `BIGINT` (Unix seconds), pas en `TIMESTAMP` SQL.
> Le schéma est généré via `diesel print-schema` dans `crates/server/src/db/schema.rs`.

```sql
-- Registre LocalPKI (géré par l'EN)
identities (
  sn            TEXT PRIMARY KEY,  -- Serial Number
  si            TEXT NOT NULL,     -- Signature Id = Sign(sk_user, TBSCert_DER)
  pk            TEXT NOT NULL,     -- Clé publique Ed25519 (base64url, 32 octets)
  tbs_der       TEXT NOT NULL,     -- Bytes DER exacts du TBSCert signés à l'enrollment
                                   -- (figés pour découpler la vérification de SI de la
                                   --  version de la crate x509-cert — cf. ORAL_DEFENSE §17)
  subject_id    TEXT NOT NULL,     -- Label d'affichage (UI), hors noyau crypto
  lra_id        TEXT NOT NULL,     -- LRA ayant vérifié l'identité (ou sentinelle
                                   --  "en:notaire-token" / "en:self-enroll-demo")
  registered_at BIGINT NOT NULL,   -- Unix timestamp
  revoked_at    BIGINT,            -- NULL si actif
  role          TEXT NOT NULL      -- "notaire" | "client" (défaut "client").
                                   --  Ancre EN→notaire→client : gate /enroll et /actes.
)

-- Actes notariaux (dossiers)
actes (
  uuid           TEXT PRIMARY KEY,
  titre          TEXT NOT NULL,
  notaire_sn     TEXT REFERENCES identities(sn),
  created_at     BIGINT NOT NULL,  -- Unix timestamp
  closed_at      BIGINT,           -- NULL si actif
  c_acte_archive TEXT NOT NULL     -- ECIES(pk_HSM, K_acte || acte_uuid) — opaque serveur
)

-- Participants par acte
acte_participants (
  acte_uuid      TEXT REFERENCES actes(uuid),
  participant_sn TEXT REFERENCES identities(sn),
  c_acte_key     TEXT NOT NULL,    -- ECIES(pk_participant, K_acte)
  added_at       BIGINT NOT NULL,  -- Unix timestamp
  added_by_sn    TEXT NOT NULL,    -- SN du notaire ayant ajouté le participant
  history_from   BIGINT,           -- NULL = accès complet, sinon Unix timestamp du point de départ
  PRIMARY KEY (acte_uuid, participant_sn)
)

-- Messages
messages (
  id         TEXT PRIMARY KEY,     -- UUID v4 (stocké en TEXT)
  acte_uuid  TEXT REFERENCES actes(uuid),
  sender_sn  TEXT REFERENCES identities(sn),
  c_message  TEXT NOT NULL,        -- AES-256-GCM(K_send_sender, M) — opaque serveur
  nonce      TEXT NOT NULL,        -- 96-bit nonce base64
  signature  TEXT NOT NULL,        -- Ed25519(sk_sender, SHA256("localpki-msg-v1\0" || c_message || nonce || acte_uuid || sent_at || sender_sn))
                                   -- signe le CHIFFRÉ (pas le clair) — cf. §5.3

  seq        BIGINT NOT NULL,      -- Numéro de séquence dans l'acte
  sent_at    BIGINT NOT NULL       -- Unix timestamp
)

-- Transparency log
merkle_log (
  id           BIGINT PRIMARY KEY,
  acte_uuid    TEXT REFERENCES actes(uuid),
  message_id   TEXT REFERENCES messages(id),
  leaf_hash    TEXT NOT NULL,      -- SHA256(0x00 || signature || acte_uuid || logged_at || seq), 0x00 = préfixe feuille RFC 6962
  parent_hash  TEXT,               -- Racine du Merkle log après insertion de cette feuille (hex 32 bytes). NULL si l'append a échoué après l'INSERT (jamais en pratique).
  en_signature TEXT,               -- Sign(sk_EN, "localpki-merkle-v1\0" || root || logged_at) — signé à chaque append (une signature EN par message)
  logged_at    BIGINT NOT NULL     -- Unix timestamp
)

-- Sessions HTTP (tickets d'authentification)
sessions (
  token      TEXT PRIMARY KEY,     -- Token opaque hashé (BLAKE3 ou SHA256)
  sn         TEXT REFERENCES identities(sn),
  created_at BIGINT NOT NULL,      -- Unix timestamp
  expires_at BIGINT NOT NULL       -- Unix timestamp — le serveur rejette les tokens expirés
)
```

---

*Document rédigé dans le cadre du sujet S001 — Astéroïde 2026.  
Fondations cryptographiques : LocalPKI (Dumas, Lafourcade, Melemedjian, Orfila, Thoniel, 2019).  
Implémentation cible : Rust (backend Axum) + SvelteKit (frontend).*
