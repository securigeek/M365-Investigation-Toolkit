# M365 Investigation Toolkit v1.0.0

## 🎉 First Release

A free, open-source PowerShell toolkit for Microsoft 365 security investigations.

---

## ✨ What's Included

### Core Features
- **🔒 100% Read-Only** - Zero risk to your tenant
- **⚡ Single Command** - `./Run-Investigation-Collector.ps1`
- **🔐 Delegated Auth** - Browser sign-in, no secrets stored
- **📊 18 Evidence Collectors** - Exchange, Entra ID, Audit Logs
- **🛡️ 10 Threat Detections** - Modern attack patterns

### Collectors
- Mailbox Forwarding, Inbox Rules, Transport Rules
- Risky Sign-ins, Interactive/Non-Interactive Sign-ins
- Directory Audit, Consent Grants, Role Assignments
- Unified Audit Log, App Changes, Connectors

### Detections
OAuth Abuse, BEC, Password Spray, Dormant Account Takeover,
Audit Evasion, Service Principal Backdoors, Data Exfiltration

---

## 🚀 Quick Start

```powershell
# Run investigation
./Run-Investigation-Collector.ps1

# With parameters
./Run-Investigation-Collector.ps1 `
  -CaseName "incident-001" `
  -DaysBack 7 `
  -Sender "suspicious@domain.com"
```

---

## 🔒 Security & Privacy

- All data stays **local** on your computer
- **Read-only** operations (no modifications)
- **No cloud upload**, no external servers
- MIT Licensed

---

## 🧪 Tests

```powershell
Invoke-Pester tests/powershell -Output Detailed
```

66+ automated tests included.

---

## 📞 Support

- Issues: GitHub Issues
- Contact: contact@securigeek.com

**Built with 🔒 for the security community**
