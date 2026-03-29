---
title: "HTB — NomDeLaBox"
date: 2026-03-27
draft: false
tags: ["ctf", "htb", "linux", "privesc"]
# ↑ Adapte les tags : htb/thm/root-me, linux/windows, techniques utilisées
categories: ["CTF Write-ups"]
summary: "Résolution de la box NomDeLaBox sur HackTheBox — énumération, exploitation, escalade de privilèges, et analyse défensive."
ShowToc: true
TocOpen: true
---

## Résumé

| Info       | Détail            |
|------------|-------------------|
| Plateforme | HackTheBox        |
| Difficulté | Medium            |
| OS         | Linux             |
| Techniques | Enum, SQLi, PrivEsc |

---

## Reconnaissance

### Nmap

```bash
nmap -sC -sV -oN scan.txt 10.10.10.XX
```

<!-- Résultats et analyse ici -->

### Énumération web

<!-- Détaille ta démarche, pas juste les commandes -->

---

## Exploitation — Accès initial

<!-- Explique POURQUOI tu as choisi cette approche, pas juste ce que tu as fait -->

---

## Escalade de privilèges

<!-- Même principe : méthodologie > commandes -->

---

## 🛡️ Volet défensif — Comment détecter cette attaque

C'est la section qui te différencie. Pour chaque étape de l'attaque, pose-toi la question : **comment un défenseur aurait-il pu voir ça ?**

### Indicateurs de compromission (IOCs)

<!-- IPs, hashs, fichiers suspects, comportements anormaux -->

### Logs à surveiller

<!-- Quels logs système/applicatifs auraient trahi l'attaquant ? -->

### Règles de détection

```yaml
# Exemple de règle Sigma
title: Détection de [technique utilisée]
status: experimental
logsource:
    product: linux
    service: syslog
detection:
    selection:
        # Adapte selon la technique
    condition: selection
level: medium
```

### Recommandations de durcissement

<!-- Quelles mesures auraient empêché ou limité l'attaque ? -->

---

## Ce que j'ai appris

<!-- 2-3 bullet points : les takeaways techniques et méthodologiques -->
