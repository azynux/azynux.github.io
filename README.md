# Blog Cybersécurité — Portfolio Blue Team

Blog statique Hugo + PaperMod, déployé sur GitHub Pages.

## Setup rapide

### 1. Prérequis

Installe Hugo extended :

```bash
# macOS
brew install hugo

# Windows (chocolatey)
choco install hugo-extended

# Linux (snap)
snap install hugo
```

### 2. Clone et initialise le projet

```bash
# Crée le repo sur GitHub (azynux.github.io) puis :
git clone https://github.com/azynux/azynux.github.io.git
cd azynux.github.io

# Copie le contenu de ce dossier dans le repo cloné, puis :
# Ajoute PaperMod comme sous-module Git
git submodule add --depth=1 https://github.com/adityatelange/hugo-PaperMod.git themes/PaperMod
```

### 3. Personnalise

Ouvre `hugo.yaml` et remplace tous les `azynux` par ton username GitHub.
Édite la section `homeInfoParams` et la page `content/about.md`.

### 4. Teste en local

```bash
hugo server -D
# → Ouvre http://localhost:1313
```

### 5. Déploie

```bash
git add .
git commit -m "Initial setup"
git push origin main
```

Le GitHub Action (`.github/workflows/hugo.yaml`) build et déploie automatiquement.

**Important** : Dans les settings du repo GitHub → Pages → Source, sélectionne **GitHub Actions**.

## Écrire un nouvel article

### Write-up CTF

```bash
# Copie le template
cp content/posts/ctf-writeups/TEMPLATE-ctf-writeup.md content/posts/ctf-writeups/htb-nomdelabox.md

# Édite, puis quand c'est prêt, passe draft: false
```

### Article Blue Team

```bash
cp content/posts/blue-team/TEMPLATE-blue-team.md content/posts/blue-team/mon-analyse.md
```

### Ou via Hugo directement

```bash
hugo new posts/ctf-writeups/htb-nouvelle-box.md
```

## Structure

```
content/
├── about.md                          # Page À propos
├── search.md                         # Page recherche
└── posts/
    ├── ctf-writeups/                 # Write-ups CTF (offensif + volet défensif)
    │   └── TEMPLATE-ctf-writeup.md
    ├── blue-team/                    # Analyses DFIR, challenges défensifs
    │   └── TEMPLATE-blue-team.md
    └── veille-threat-intel/          # Veille (à venir)
```

## Tags recommandés

- **Catégories** : `CTF Write-ups`, `Blue Team`, `Threat Intel`
- **Tags techniques** : `htb`, `thm`, `root-me`, `linux`, `windows`, `privesc`, `web`, `forensic`, `dfir`, `malware-analysis`, `sigma`, `yara`, `wireshark`, `volatility`
- **Tags MITRE** : `initial-access`, `lateral-movement`, `persistence`, etc.
