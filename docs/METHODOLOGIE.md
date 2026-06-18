# Méthodologie du test technique

## Avant propos

Ce document a pour but de détailler comment j'ai travaillé sur ce test technique.

L'IA ayant été autorisée, je me suis permis d'utiliser principalement deux outils d'IA : _NotebookLM_ (Google) pour la recherche de documentation, de sources et pour l'interrogation de ces sources et _Claude_ (Anthropic) avec notamment son outil _Claude Code_ pour la génération de code et la rédaction de documents.

À ce titre, ce document est le seul entièrement rédigé à la main, les autres documents ayant été produits à des degrés divers avec l'aide de l'IA.

## Choix du sujet

Pour choisir un des trois sujets, je me suis basé sur ce que je considérais être mes connaissances préalables ainsi que sur l'intérêt que je pouvais porter à chacun d'eux.

Ayant déjà travaillé dans un projet personnel sur une messagerie (basée sur le protocole Signal) j'ai d'emblée été attiré par le sujet, pensant pouvoir appliquer ce que je connaissais de ce dernier. D'autre part, j'estimais que ce sujet offrait davantage de possibilités en termes de retour visuel et d'interactivité, deux aspects que je voulais explorer, ayant travaillé comme développeur frontend.

Il s'est cependant vite avéré que mon expérience n'était pas directement transposable, le contexte notarial imposant des contraintes différentes, comme la non-répudiation et l'archivage légal, auxquelles je n'avais pas été exposé en travaillant avec le protocole Signal. J'ai donc dû me familiariser avec ces concepts et partir sur une autre approche de la messagerie comme décrit dans la suite de ce document.

## Recherche de documentation et lecture des sources

La première étape de ce test, outre la lecture du sujet, a été de récupérer le papier de recherche LocalPKI et de le lire, pour avoir une bonne vision du contexte dans lequel allait se dérouler le test.

Une fois cette lecture terminée et quelques prises de notes, j'ai cherché à accumuler un certain nombre de ressources pour avancer au mieux. Je me suis donc appuyé sur _NotebookLM_ (Google), qui me permet de centraliser notes et documents, et d'interroger ces sources directement. Cet outil a été un grand plus pour moi qui n'avais jamais travaillé dans le contexte notarial ni avec de la cryptographie aussi prépondérante.

En parallèle j'ai échangé avec _Claude_ sur les différentes solutions que je commençais à entrevoir en lui soumettant mes interrogations quant au domaine notarial et en lui apportant les sources, ou les résultats d'interrogations des sources via _NotebookLM_.

### Analyse des protocoles existants

Mon idée initiale était de m'appuyer sur le protocole Signal, reconnu pour son élégance et sa robustesse et qui, dans le cas d'une messagerie sécurisée, me semblait le plus adapté. Il s'est vite avéré qu'appliqué au notariat, ce protocole n'était pas le plus adapté. En effet, le protocole Signal offre notamment une forme de deniability, un moyen de nier qu'on a envoyé un message, alors que dans le cas du notariat il est important d'avoir de la non-répudiation et donc une impossibilité de nier le fait qu'un message a été envoyé. De plus le multi-device est contraignant dans le protocole Signal, bien que le sujet du multi-device n'ait pas été abordé dans la réalisation du test. Un autre souci du protocole Signal est que le serveur est complètement aveugle au niveau des messages qui transitent, ce qui est certes un avantage dans le cas d'une messagerie sécurisée mais peut devenir une contrainte pour un agent de l'état qui est censé pouvoir apporter la preuve de l'échange, aussi bien pour les différentes parties qu'en cas de litige.

Un autre protocole serait le protocole MLS (RFC 9420) mais tout comme le protocole Signal, il impose le forward secrecy qui est certes un très bon niveau de sécurité mais qui, à mon sens, n'est pas compatible avec un notaire qui doit pouvoir accéder aux messages dans certains cas spécifiques et ainsi peu compatible avec le besoin d'archivage long du notariat. Même raisonnement pour le post-compromise security et l'effacement irréversible des clés qui empêche l'archivage légal. De plus, si l'on souhaite ajouter une nouvelle partie à la conversation on ne pourra pas lui permettre de déchiffrer les messages précédents. Une solution à ce problème serait de renvoyer les messages depuis un autre participant mais cela implique qu'il faut gérer le fait que la personne est bien connectée, de quelle manière, est-ce que cette personne a aussi tous les messages etc.

Ces contraintes m'ont conduit à concevoir une approche sur mesure, décrite dans la section suivante.

## Concernant la décision architecturale

J'ai donc décidé de partir sur un modèle serveur centralisé, avec une dérivation de clé par actes depuis une clé maître, dans mon cas une clé matérielle (ex: Yubikey). Ainsi chaque participant aura ensuite une clé dérivée de la clé acte qui lui permettra de déchiffrer et chiffrer ces messages localement. L'idée est que tout reste opaque durant les communications sur le serveur mais que dans certains cas spécifiques, on puisse déchiffrer les messages sur le serveur avec la clé maître. Cela transfère la responsabilité de la sécurité au notaire mais c'est déjà un rôle qui est endossé par cette profession en France concernant notamment tous les documents qu'il délivre, archive etc...

Le document [ARCHITECTURE.md — §3 Couche identité](ARCHITECTURE.md#3-couche-identité--protocoles-localpki) détaille plus précisément comment fonctionne le protocole mais dans les grandes lignes je reprends déjà toute la partie enrôlement et authentification du papier LocalPKI.

Pour ce qui est de la messagerie, les clés `K_acte` sont dérivées via HKDF depuis la clé HSM (matérielle) `K_master`. Ces clés sont ensuite envoyées aux participants via le protocole `ECIES` (`C_acte_Alice`, `C_acte_Bob`) afin de garantir la sécurité de leur envoi. Pour l'envoi d'un message, chaque participant va devoir générer sa clé `K_send_participant` puis appliquer `AES-256-GCM` sur son message puis signer le message.

Deux points méritent d'être précisés, le premier étant qu'en l'état n'importe quel participant peut créer la clé K_send d'un autre participant mais l'on règle ce problème en vérifiant la signature qui n'est pas falsifiable. Le deuxième point est que l'on ne signe pas le plaintext mais bien le ciphertext, ce qui permet au serveur de vérifier la signature sans devoir déchiffrer le message.

Pour ce qui est du déchiffrement, la clé `K_send` de chaque participant étant facilement dérivable on peut facilement déchiffrer un message. Ainsi tout participant ayant `K_acte` peut lire les messages envoyés par n'importe quel autre participant. C'est notamment voulu pour l'archivage légal puisqu'ainsi le notaire peut accéder aux messages si une situation légale l'exige.

Je suis conscient que cela veut dire que si la clé K_acte est compromise alors on peut lire tous les messages bien que forger un message nécessiterait en plus la clé privée du participant ciblé et donc une double compromission. Ce sujet est abordé dans [ARCHITECTURE.md — §10.2 Perspectives d'évolution](ARCHITECTURE.md#102-perspectives-dévolution), par exemple via Proxy Re-encryption.

Au sujet maintenant des choix architecturaux purs, j'ai décidé pour me faciliter la tâche de n'avoir qu'un seul serveur et donc ne pas faire de différence spécifique entre EN et LRA du papier. Les différentes fonctions de la bibliothèque `localpki-core` recensent bien les différentes étapes (via des fonctions) de la communication entre LRA et EN mais j'ai choisi de ne pas rajouter une couche de communication supplémentaire, qu'elle soit cross-process ou cross-machine. C'est un choix discutable mais j'ai décidé de me concentrer sur la partie communication messagerie et non sur la partie communication entre les différents acteurs. De plus, le papier ne parle de ne stocker que le Serial Number et le Signature ID dans la base de données du EN et j'ai donc décidé d'étendre ces enregistrements avec notamment la clé publique du participant afin de faciliter la vérification de la signature des messages de ce dernier.

## Concernant la stack technique

J'ai suivi la stack technique que nous avions évoquée lors de notre entretien c'est-à-dire :

- `rust` pour le backend et les différentes lib
- `sveltekit` pour le frontend avec `shadcn` et donc `tailwindcss` pour le style
- `sqlite` pour la base de données par souci de simplicité

## Concernant la méthode d'implémentation

La première étape a été de définir un squelette de projet, afin d'avoir une bonne base de travail et une vision claire de ce qu'il fallait réaliser.

J'ai ensuite implémenté la bibliothèque `localpki-core` en utilisant l'IA comme conseiller et tuteur, notamment pour m'approprier les différentes crates de cryptographie et monter en compétence dans le domaine. Cela sous-entend des prompts comme _"Ne me donne pas directement les réponses"_, _"Comment je pourrais améliorer mon code pour être plus rust-idiomatic"_, _"Explique moi les grands concepts et à la demande donne moi des indices pour avancer"_.

Pour la partie `server` j'ai supervisé finement l'IA, en étant assez directif et en spécifiant précisément ce que je voulais à chaque étape.

Pour la partie `demo-cli`, j'ai fourni un cadrage général et laissé l'IA produire le code, que j'ai ensuite vérifié.

Pour le frontend, j'ai laissé l'IA travailler de façon plus autonome, n'ayant pas d'expérience préalable avec SvelteKit et considérant que ce n'était pas forcément le point attendu pour ce test technique. J'ai néanmoins relu en détail toute la partie cryptographique et les échanges avec le serveur.

Une fois l'implémentation terminée, j'ai testé l'ensemble des fonctionnalités et ajouté des tests unitaires en spécifiant les cas à couvrir et en relisant le code produit par l'IA.

Pour la documentation, j'ai demandé à l'IA de compléter au fur et à mesure de mes retours, mes interrogations et critiques, en veillant à maintenir la cohérence avec le code.

En bonus, j'ai demandé à l'IA de générer le document `DEMO.md` de façon entièrement autonome, afin d'évaluer sa capacité à produire un contenu illustré avec captures d'écran et explications.

## Résultat et limites

Le résultat couvre les fonctionnalités attendues mais comporte des limites et quelques déviations par rapport au papier.

La première déviation concerne le stockage côté EN. Dans le papier il est indiqué qu'on ne stocke que le Serial Number (SN) et la Signature ID (SI) mais par souci de simplicité j'ai choisi d'y ajouter notamment la clé publique du participant pour faciliter la vérification des signatures de messages. De plus, notre serveur joue à la fois le rôle de notaire électronique (_Electronic Notary_ ou _EN_) et de serveur d'autorité d'enregistrement local (_Local Registration Authority_ ou _LRA_) ce qui est un choix discutable mais que je pense cohérent dans la mesure où le sujet principal est la messagerie et non pas la communication inter-acteurs. Cette simplification n'est que sur la partie communication dans le sens où les différentes fonctions sont bien présentes dans le code mais nous faisons abstraction du déploiement sur plusieurs machines.

Concernant la vérification des identités, c'est `localpki-core` donc le serveur qui effectue la vérification LocalPKI. Normalement dans le papier c'est Alice qui vérifie l'identité de Bob et vice versa mais dans le contexte de messagerie le serveur doit aussi vérifier l'identité car il est partie prenante dans la communication et il ne peut pas faire confiance à Alice pour vérifier Bob. Il est aussi bon de noter que cette vérification n'est faite qu'à la connexion et que donc si un participant est révoqué en cours de session, il n'est pas immédiatement déconnecté.

Pour revenir sur la confidentialité des messages, tous les participants peuvent dériver la clé `K_send` d'un autre participant mais ne peuvent pas signer avec la clé de cet autre participant. C'est notre solution pour garantir la non-répudiation. L'avantage de ce choix c'est que le notaire peut toujours accéder aux messages en cas de besoin.

Quelques points restent ouverts : l'absence de cross-certification entre ENs, un problème dans le cas où Alice et Bob n'ont pas le même notaire, et une duplication de logique entre le backend et le frontend pour les fonctions cryptographiques. Ce dernier point est intentionnel puisque le frontend doit pouvoir effectuer ces opérations localement mais peut-être que la solution est plus à chercher du côté d'une solution desktop que d'une solution web ou a minima utiliser une API WebAssembly pour partager du code entre le backend et le frontend.

Une liste plus complète des limites et perspectives est disponible dans [ARCHITECTURE.md — §10 Limites assumées et perspectives](ARCHITECTURE.md#10-limites-assumées-et-perspectives).

