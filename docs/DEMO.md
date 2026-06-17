# Guide de démonstration — interface web

Ce guide montre, en captures, comment exercer les principaux parcours de
l'interface : enrôler un notaire, enrôler des clients (mode démo **et** flux
endossé réel), créer un acte et y ajouter des participants.

> Pour lancer le serveur et le frontend, voir le **[README](../README.md)**
> (« Démarrage rapide »). Une fois le frontend ouvert sur `http://localhost:5173`,
> tout part de la page d'accueil.

### Astuce : une identité par onglet

Les clés vivent en `sessionStorage`, qui est **propre à chaque onglet**. Pour
jouer plusieurs personnes (notaire, Alice, Bob…), ouvre simplement
**un onglet par identité** — elles n'interfèrent pas. Le bouton **« Se
déconnecter »** abandonne l'identité de l'onglet courant pour repartir de zéro.

---

## La page d'accueil

Deux portes d'entrée (notaire / client) et un encart qui explique honnêtement les
simplifications du PoC.

<img src="images/01-accueil.png" alt="Page d'accueil" width="500" />

---

## 1. Enrôler un notaire

Carte **« Je suis notaire »** → saisis un nom → **« Entrer comme notaire »**.

L'application génère la paire de clés, construit le certificat auto-signé et
enregistre l'identité — chaque étape est affichée :

<img src="images/02-notaire-enrole.png" alt="Enrôlement notaire" width="500" />

Tu arrives dans l'espace notaire (vide au départ) :

<img src="images/03-notaire-dashboard.png" alt="Espace notaire" width="500" />

---

## 2. Enrôler un client (auto-signé — mode démo)

Dans **un nouvel onglet**, carte **« Je suis client »**. Le switch
**« PoC : auto-enrôlement »** est **activé** par défaut → saisis un nom →
**« Entrer comme client »**.

Le client est inscrit immédiatement. Sa fiche affiche son **SN** (cliquable pour
le copier) — garde-le, il servira à l'ajouter à un acte.

<img src="images/04-client-auto-connecte.png" alt="Client auto-enrôlé" width="500" />

---

## 3. Créer un acte

Côté **notaire** → **« Nouvel acte »** → saisis un titre, colle le **SN du
client** puis **« Ajouter »** (le notaire est ajouté automatiquement) :

<img src="images/05-acte-creation.png" alt="Création d'acte" width="500" />

**« Créer l'acte »** ouvre directement la messagerie chiffrée du dossier :

<img src="images/06-acte-cree.png" alt="Acte créé" width="500" />

---

## 4. Enrôler un client **sans** auto-signé (flux endossé réel)

C'est le flux conforme à LocalPKI : le client génère son certificat, le notaire
l'endosse.

**a.** Dans un nouvel onglet, carte **« Je suis client »**, **désactive** le
switch → le bouton devient **« Générer mon certificat »** :

<img src="images/07-client-switch-off.png" alt="Switch désactivé" width="500" />

**b.** Le certificat est généré localement (pas encore enregistré). Le client le
**télécharge** (ou le copie) et le transmet à son notaire :

<img src="images/08-client-attente-endossement.png" alt="En attente d'endossement" width="500" />

**c.** Côté **notaire** → espace notaire → **« Enrôler un client »** → colle le
certificat reçu. L'aperçu confirme le sujet et le SN avant validation :

<img src="images/09-notaire-endosse.png" alt="Endossement notaire" width="500" />

Après **« Vérifié — approuver »**, l'identité est enregistrée auprès de l'EN :

<img src="images/10-endossement-succes.png" alt="Endossement réussi" width="500" />

**d.** Le client revient sur **« Se connecter »** : il prouve la possession de sa
clé (signature d'un challenge) et obtient sa session :

<img src="images/11-bob-connecte.png" alt="Client connecté" width="500" />

---

## 5. Ajouter un client à un acte (avec historique)

Côté **notaire**, dans l'acte → **« + Participant »** → colle le SN du client →
**coche « Accès à l'historique des messages »** → **« Ajouter »**.

<img src="images/12-ajout-participant-historique.png" alt="Ajout participant avec historique" width="500" />

Le participant pourra lire l'historique complet du dossier.

---

## 6. Ajouter un client à un acte **sans** historique

Même panneau, mais **laisse « Accès à l'historique » décoché** :

<img src="images/13-ajout-participant-sans-historique.png" alt="Ajout participant sans historique" width="500" />

Le participant ne verra que les messages **postérieurs** à son ajout.

> Remarque : « sans historique » est une restriction d'**interface**, pas une
> garantie cryptographique (le détenteur de `K_acte` pourrait techniquement
> déchiffrer l'historique). C'est documenté dans `ARCHITECTURE.md` §5.5 / §10.1.

---

## En action — messagerie chiffrée + journal Merkle

Les participants échangent des messages **chiffrés de bout en bout**. Chaque
message porte un indicateur de **signature vérifiée** (✓) :

<img src="images/14-messagerie.png" alt="Messagerie" width="500" />

Le panneau **« Merkle »** affiche la racine du journal de transparence, qui
scelle l'ordre et l'intégrité des messages :

<img src="images/15-merkle.png" alt="Racine Merkle" width="500" />

---

## Bon à savoir (limites assumées du PoC)

- **Mode démo vs flux réel** : le self-enrôlement (switch activé) est un raccourci
  pour tester sans friction ; le flux endossé (switch désactivé + `/notaire/enroller`)
  est le vrai parcours de confiance. Détails dans `ARCHITECTURE.md` §10.1.
- **Identité non persistante** : fermer l'onglet efface l'identité (clés en
  `sessionStorage`). Il n'y a pas de « se reconnecter plus tard comme Alice » —
  garde l'onglet ouvert le temps de la démo.
- **Une identité par onglet** : utilise des onglets séparés pour jouer plusieurs
  personnes en parallèle.

Toutes les limites sont documentées et justifiées dans `ARCHITECTURE.md` §10 et
`CRYPTO_REVIEW.md`.
