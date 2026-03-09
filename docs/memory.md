# 🧠 Mémoire du Projet

## Contexte

Ce projet est le **M365 Investigation Toolkit** - un framework PowerShell open-source pour les investigations de sécurité Microsoft 365.

**Propriétaire:** Securigeek (securigeek)  
**Licence:** MIT  
**Repository:** https://github.com/securigeek/M365-Investigation-Toolkit

---

## Architecture

```
M365-Toolkit-Public/
├── Run-Investigation-Collector.ps1     # Point d'entrée principal
├── Test-Prerequisites.ps1              # Vérification env
├── Generate-BrandedPresentation.ps1    # Génération PPT
├── Setup-DemoEnvironment.ps1           # ⚠️ LOCAL ONLY - Démo scenarios
│
├── src/
│   ├── Invoke-InvestigationCollector.ps1    # Orchestrateur
│   ├── collectors/                          # 18 modules de collecte
│   │   ├── Get-TenantMailboxForwarding.ps1
│   │   ├── Get-TenantRiskySignins.ps1
│   │   └── ...
│   └── lib/
│       ├── auth.ps1
│       ├── detections.ps1
│       ├── reporting.ps1
│       └── branding.ps1
│
├── tests/                               # 15 suites de tests Pester
├── docs/                                # Documentation
│   ├── instructions.md
│   ├── DEMO-SCENARIOS.md               # ⚠️ LOCAL ONLY
│   └── images/
│       ├── github-banner.png
│       └── repository-social-preview.png
│
└── output/                              # Résultats investigations
    └── incidents/
```

---

## Décisions Clés

### Read-Only par Design
- Aucune action de remédiation
- Pure collecte d'évidence
- GET operations uniquement

### Authentification
- Device code flow (pas de secrets stockés)
- ContextScope Process (pas de tokens persistants)
- Delegated permissions uniquement

### Modulaire
- 18 collecteurs indépendants
- Chaque module peut échouer sans bloquer les autres
- API capabilities detection

### Output
- JSON brut pour intégration
- Markdown pour analystes
- PowerPoint pour exécutifs

---

## Scénarios de Détection (5 types)

| Détection | Fichier Source | Sévérité |
|-----------|---------------|----------|
| BEC_Indicator | detections.ps1 | HIGH |
| OAuthAbuse | detections.ps1 | HIGH |
| PasswordSpray | detections.ps1 | HIGH |
| DormantAccount | detections.ps1 | MEDIUM |
| AuditEvasion | detections.ps1 | MEDIUM |

---

## Fichiers Sensibles (Ne pas commiter)

- `Setup-DemoEnvironment.ps1` - Crée des données de test
- `docs/DEMO-SCENARIOS.md` - Documentation interne scénarios
- `output/` - Résultats d'investigation (déjà dans .gitignore)
- `*.json` dans output/ - Contient des données tenant

---

## Workflows

### Investigation Standard
1. Lancer `Run-Investigation-Collector.ps1`
2. Authentification browser
3. Collecte automatique (18 modules)
4. Génération verdict
5. Review `findings-summary.md`

### Avec Pivots
1. Spécifier `-Sender`, `-Domain`, `-UserPrincipalName`, `-SubjectContains`
2. Collection filtrée
3. Focus sur indicateurs spécifiques

### Génération Présentation
1. Investigation complète d'abord
2. `Generate-BrandedPresentation.ps1 -InvestigationPath <path>`
3. PowerPoint généré avec branding

---

## Tests

```bash
# Tous les tests
pwsh -Command "Invoke-Pester tests/powershell -Output Detailed"

# Un fichier spécifique
pwsh -Command "Invoke-Pester tests/powershell/Detection.Tests.ps1"
```

---

## Release Checklist

- [ ] Version bumpée dans les fichiers
- [ ] RELEASE_NOTES.md à jour
- [ ] Tests passent
- [ ] Pas de secrets dans le code
- [ ] Pas de emails réels
- [ ] `Setup-DemoEnvironment.ps1` NON inclus dans le release

---

## Contact & Support

- Issues: GitHub Issues
- Discussions: GitHub Discussions
- Security: security@securigeek.com

---

*Dernière mise à jour: 2026-03-07*
