# Méthodologie du test technique

## Avant propos
Ce document a pour but de détailler comment j'ai travaillé sur ce tests technique.

L'IA ayant été autorisée, je me suis d'en utiliser différentes aussi bien pour la recherche de documentation et de sources que pour la rédaction des documents d'architecture et la génération de code.

## Choix du sujet
Pour choisir un des trois sujets je me suis basé sur ce que je considérais être mes connaissances dans chacun des 3 sujets ainsi que sur l'intérêts que je pouvais porter à chacun.
Ayant déjà travaillé dans un projet personnel sur une messagerie et pensant dans un premier temps que je pourrais appliquer efficacement ce que je connaissais du sujet j'ai décidé de partir sur celui-ci. J'ai également choisi d'écarter les autres sujets car à mon sens il pouvaient être plus compliqués.

## Recherche de documentation et lecture des sources
Une première étape dans la réaliser de ce test technique à été de lire le papier de recherche *LocalPKI* (ie: `./docs/LocalPKI.pdf`) pour avoir un début de vision de la solution proposée par Trust4Sig. Suite à la lecture de ce document je me suis aidé de *NotebookLLM*, un outil de google, pour chercher des sources associés au papier de recherche et ainsi pouvoir les centraliser et les interroger pour commencer à anticiper une solution pour le sujet de messagerie.

Après des recherches sur les différents protocols, il s'est avéré que le protocol de communication que je pensais être une bonne solution à savoir le protocol Signal n'est pas applicable dans le cas du notariat, ou tout du moins dans l'idée que je me fais du notariat. En effet le protocol Signal garantie la confidentialité mais ne mets pas en place un systeme de stockage des messages, ces derniers étant seulement sur les appareils des personnes échangeant les messages. Ainsi il n'est pas possible, par exemple lors d'un éventuel litige, de pouvoir être certain d'accéder aux messages.