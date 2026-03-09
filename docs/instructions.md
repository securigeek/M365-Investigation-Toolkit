# 📚 Instructions d'Utilisation

## Démarrage Rapide

### 1. Prérequis

```bash
# Vérifier PowerShell 7+
pwsh --version  # Doit afficher 7.5.0 ou supérieur

# Si non installé:
# macOS: brew install --cask powershell
# Windows: winget install Microsoft.PowerShell
```

### 2. Installation

```bash
git clone https://github.com/securigeek/M365-Investigation-Toolkit.git
cd M365-Investigation-Toolkit
```

### 3. Première Investigation

```bash
# Mode interactif (recommandé)
pwsh -File ./Run-Investigation-Collector.ps1

# Le script va:
# 1. Vérifier les prérequis
# 2. Installer les modules manquants
# 3. Ouvrir une fenêtre de navigateur pour l'authentification Microsoft
# 4. Collecter les données
# 5. Générer les rapports
```

**Inputs demandés:**
- Case name: `investigation-phishing-001`
- Days back: `14`

### 4. Voir les Résultats

```bash
# Dernier rapport
cd output/incidents/$(ls -t output/incidents | head -1)

# Fichiers clés:
cat verdict.json              # Verdict global
cat findings-summary.md       # Rapport lisible
cat detections.json           # Menaces détectées
```

---

## Scénarios d'Usage

### Investigation Phishing

```bash
pwsh -File ./Run-Investigation-Collector.ps1 `
  -CaseName "phishing-report" `
  -DaysBack 3 `
  -Sender "suspicious@external.com" `
  -SubjectContains "urgent invoice"
```

### Vérification Post-Incident

```bash
pwsh -File ./Run-Investigation-Collector.ps1 `
  -CaseName "post-incident-check" `
  -DaysBack 30 `
  -UserPrincipalName "victim@company.com"
```

### Baseline Automatisée

```bash
pwsh -File ./Run-Investigation-Collector.ps1 `
  -CaseName "daily-baseline-$(date +%Y%m%d)" `
  -DaysBack 1 `
  -SkipPrompt
```

---

## Configuration Environnement de Démo

### Créer les scénarios de test

```bash
# Dans votre tenant de test UNIQUEMENT
pwsh -File ./Setup-DemoEnvironment.ps1

# Authentification via navigateur (device code)
# Cela crée:
# - Utilisateur demo.victim avec forwarding suspect
# - Inbox rules malveillantes
# - Application OAuth avec permissions excessives
# - Compte dormant
```

### Nettoyer après démo

```bash
pwsh -File ./Setup-DemoEnvironment.ps1 -Cleanup
```

---

## Génération de Présentations

```bash
# Trouver le dossier d'investigation
$path = "./output/incidents/nom-du-case-*"

# Générer PPT
pwsh -File ./Generate-BrandedPresentation.ps1 `
  -InvestigationPath $path
```

---

## Dépannage

### Erreur: "Connect-MgGraph not recognized"

```powershell
Install-Module Microsoft.Graph.Authentication -Force
```

### Erreur: "Exchange Online connection failed"

```powershell
Install-Module ExchangeOnlineManagement -Force
```

### Vider le cache

```bash
rm -rf output/incidents/*
```

---

## Commandes Rapides

| Action | Commande |
|--------|----------|
| Vérifier prérequis | `pwsh -File ./Test-Prerequisites.ps1` |
| Lancer investigation | `pwsh -File ./Run-Investigation-Collector.ps1` |
| Dernier rapport | `ls -t output/incidents \| head -1` |
| Voir verdict | `cat output/incidents/*/verdict.json` |
| Cleanup démo | `pwsh -File ./Setup-DemoEnvironment.ps1 -Cleanup` |
