# Méthodologie du test technique

## Avant propos
Ce document a pour but de détailler comment j'ai travaillé sur ce tests technique.

L'IA ayant été autorisée, je me suis permis d'en utiliser plusieurs pour m'aider dans ce travail, aussi bien pour la recherche de documentation et de sources que pour la rédaction des documents d'architecture et la génération de code.

## Choix du sujet
Pour choisir un des trois sujets je me suis basé sur ce que je considérais être mes connaissances dans chacun des 3 sujets ainsi que sur l'intérêts que je pouvais porter à chacun.
Ayant déjà travaillé dans un projet personnel sur une messagerie et pensant dans un premier temps que je pourrais appliquer efficacement ce que je connaissais du sujet j'ai décidé de partir sur celui-ci. J'ai également choisi d'écarter les autres sujets car à mon sens il pouvaient être plus compliqués.

## Recherche de documentation et lecture des sources
Une première étape dans la réaliser de ce test technique à été de lire le papier de recherche *LocalPKI* (ie: `./docs/LocalPKI.pdf`) pour avoir un début de vision de la solution proposée par Trust4Sig. Suite à la lecture de ce document je me suis aidé de *NotebookLLM*, un outil de google, pour chercher des sources associés au papier de recherche et ainsi pouvoir les centraliser et les interroger pour commencer à anticiper une solution pour le sujet de messagerie.

Après des recherches sur les différents protocols, il s'est avéré que le protocol de communication que je pensais être une bonne solution à savoir le protocol Signal n'est pas applicable dans le cas du notariat, ou tout du moins dans l'idée que je me fais du notariat. En effet le protocol Signal garantie la confidentialité mais ne mets pas en place un systeme de stockage des messages, ces derniers étant seulement sur les appareils des personnes échangeant les messages. Ainsi il n'est pas possible, par exemple lors d'un éventuel litige, de pouvoir être certain d'accéder aux messages.

- exploration des autres solutions

- exploration d'une architecture

- mise en place d'un architecture

- mise en place d'un skelette de code

- c'reation des fonction de localpji-core avec l'ia comme conseiller

- supervisation de l'ia dans l'implementation des autres taches

## Concernant la décision technique


## Résultat et limites

- on a pk dans l'en
- si on invalide la personne comme on appel en qu'a la connexion pour le moment on a pas de revocation mid-conversation
- tous les particpants peuvent retrouver k_send_alice mais seulement alice peut signer avec sa clé privée ed25519 et prouvé que c'set bien elle
  - l'avantage c'est que on peut toujours lire les message via notaire genre cas juridique
- on a plus de chose dans l'enregistrement en (seulement coté en pas dans la communication) pour notamment permettre d'auditer (alice a été revoquée le 13 juin) c'est une déviation par rapport  au papier  
- dans localpki-core on considère dans authentication que c'est le serveur qui check alros que normalement on devrait faire en sorte que alice puisse checker bob et vice versa. On fait ça parce que l'on est dans le ccas d'une messagerie mais du cuop ça couple fortement localpki-core a notre systeme de messagerie. on pourrait faire la vérification mais il faudrait dans tous les cas aussi le faire sur le serveur aprce qu ón peut pas faire confiancce a alice qui dirant "si si tqt j'ai vérifié bob" 
- pour le moment aps de cross-certification accross différente EN donc si bob est sur le meme EN qu'alice pour le moment on fait pas
- on a deux fois la meme définition des foncion messaging une fois dans la crate messaging-crypto et l'autre dans le frontend et c'est normal parce qu'il faut bien que le forntend puisse faire tout ce qui est derive_k_send et aussi ecies pour les messages
- pour des raisons de simplification notre serveur fait a la fois EN et LRA puisque c'est pas tant le sujet du projet 
- on a maintenant une vraie gestion de role (notaire/client) côté EN dans identities.role. le role notaire s'obtient via un jeton d'enrôlement (POST /enroll/notaire — l'EN désigne ses notaires, la clé privée reste dans le navigateur, seul le jeton transite) et on gate /enroll (seul un notaire peut endosser un client) et /actes (seul un notaire peut créer un acte). la chaine EN -> notaire -> client est donc imposée. plus de "Root LRA" (c'était source de confusion + non-idempotent au démarrage). le notaire.notaire_sn de l'acte reste celui qui l'a créé mais maintenant il faut etre role=notaire pour ça
- juste une auth par session token