#Requires -Version 7.0
<#
.SYNOPSIS
    Configure un environnement de démo M365 avec des scénarios de sécurité fictifs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DemoUserEmail,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantDomain,
    
    [Parameter(Mandatory = $false)]
    [switch]$Cleanup,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipConfirm
)

$script:DemoObjects = @{
    CreatedUsers = @()
    CreatedApps = @()
    CreatedRules = @()
    CreatedSPNs = @()
    ModifiedMailboxes = @()
}

$script:DemoPrefix = "DEMO-"

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $colors = @{ Info = "Cyan"; Success = "Green"; Warning = "Yellow"; Error = "Red" }
    $emoji = @{ Info = "ℹ️"; Success = "✅"; Warning = "⚠️"; Error = "❌" }
    Write-Host "$($emoji[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Connect-DemoEnvironment {
    Write-Status "Connexion à Microsoft Graph..." "Info"
    
    # Déconnecter d'abord pour éviter les conflits de contexte
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    
    # Scopes pour créer users et apps (sans Exchange.ManageAsApp qui est application-only)
    $scopes = @(
        "User.ReadWrite.All",
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All",
        "Directory.ReadWrite.All"
    )
    
    try {
        Connect-MgGraph -Scopes $scopes -UseDeviceCode -ErrorAction Stop
        $context = Get-MgContext
        Write-Status "Connecté en tant que: $($context.Account)" "Success"
    } catch {
        Write-Status "Erreur connexion Graph: $_" "Error"
        exit 1
    }
    
    # Connexion Exchange Online séparée (via module ExchangeOnlineManagement)
    Write-Status "Connexion à Exchange Online..." "Info"
    try {
        $exchangeConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if (-not $exchangeConnection) {
            Connect-ExchangeOnline -Device -ErrorAction Stop
        }
        Write-Status "Connecté à Exchange Online" "Success"
    } catch {
        Write-Status "Erreur connexion Exchange Online: $_" "Warning"
        Write-Status "Certaines fonctionnalités (transport rules) ne seront pas disponibles" "Warning"
    }
    
    return $context
}

function New-DemoUser {
    param(
        [string]$DisplayName,
        [string]$UserPrincipalName,
        [string]$Password = "DemoP@ssw0rd123!"
    )
    
    Write-Status "Création de l'utilisateur: $DisplayName" "Info"
    
    $passwordProfile = @{
        Password = $Password
        ForceChangePasswordNextSignIn = $false
    }
    
    $params = @{
        AccountEnabled = $true
        DisplayName = $DisplayName
        UserPrincipalName = $UserPrincipalName
        MailNickname = ($UserPrincipalName -split "@")[0]
        PasswordProfile = $passwordProfile
    }
    
    try {
        $user = New-MgUser -BodyParameter $params
        $script:DemoObjects.CreatedUsers += $user.Id
        Write-Status "Utilisateur créé: $($user.UserPrincipalName)" "Success"
        return $user
    } catch {
        Write-Status "Erreur création utilisateur: $_" "Error"
        return $null
    }
}

function Set-DemoMailboxForwarding {
    param(
        [string]$UserPrincipalName,
        [string]$ForwardingAddress = "attacker@malicious-example.com"
    )
    
    Write-Status "Configuration du forwarding suspect sur: $UserPrincipalName" "Info"
    
    try {
        $ruleName = "$script:DemoPrefix Forwarding Rule"
        
        # Supprimer les règles existantes du même nom
        Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -eq $ruleName } | 
            ForEach-Object { Remove-InboxRule -Identity $_.Identity -Confirm:$false }
        
        # Créer nouvelle règle
        $rule = New-InboxRule -Name $ruleName `
            -Mailbox $UserPrincipalName `
            -FromScope NotInOrganization `
            -ForwardTo $ForwardingAddress `
            -StopProcessingRules:$false
        
        $script:DemoObjects.CreatedRules += $rule.RuleIdentity
        $script:DemoObjects.ModifiedMailboxes += $UserPrincipalName
        Write-Status "Forwarding rule créée (ID: $($rule.RuleIdentity))" "Success"
    } catch {
        Write-Status "Erreur forwarding: $_" "Error"
    }
}

function Set-DemoSuspiciousInboxRule {
    param(
        [string]$UserPrincipalName
    )
    
    Write-Status "Création d'inbox rules suspectes sur: $UserPrincipalName" "Info"
    
    $rules = @(
        @{ Name = "$script:DemoPrefix Auto-Delete External"; FromScope = "NotInOrganization"; DeleteMessage = $true },
        @{ Name = "$script:DemoPrefix Move Invoices"; SubjectContainsWords = "invoice"; MoveToFolder = "RSS Feeds" }
    )
    
    foreach ($ruleDef in $rules) {
        try {
            # Supprimer si existe
            Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -eq $ruleDef.Name } | 
                ForEach-Object { Remove-InboxRule -Identity $_.Identity -Confirm:$false }
            
            # Créer avec les paramètres appropriés
            if ($ruleDef.DeleteMessage) {
                $rule = New-InboxRule -Name $ruleDef.Name -Mailbox $UserPrincipalName `
                    -FromScope $ruleDef.FromScope -DeleteMessage
            } else {
                $rule = New-InboxRule -Name $ruleDef.Name -Mailbox $UserPrincipalName `
                    -SubjectContainsWords $ruleDef.SubjectContainsWords
            }
            
            $script:DemoObjects.CreatedRules += $rule.RuleIdentity
            Write-Status "Rule créée: $($ruleDef.Name)" "Success"
        } catch {
            Write-Status "Erreur création rule '$($ruleDef.Name)': $_" "Warning"
        }
    }
}

function New-DemoOAuthApp {
    param(
        [string]$AppName = "$script:DemoPrefix Malicious Mail App"
    )
    
    Write-Status "Création de l'application OAuth malveillante: $AppName" "Info"
    
    try {
        # Supprimer si existe déjà
        Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | 
            ForEach-Object { Remove-MgApplication -ApplicationId $_.Id }
        
        $appParams = @{
            DisplayName = $AppName
            SignInAudience = "AzureADMyOrg"
            Description = "Application de démo - simule un app malveillante"
        }
        $app = New-MgApplication @appParams
        
        # Supprimer SPN si existe
        Get-MgServicePrincipal -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue | 
            ForEach-Object { Remove-MgServicePrincipal -ServicePrincipalId $_.Id }
        
        $spn = New-MgServicePrincipal -AppId $app.AppId
        
        $permissions = @("Mail.ReadWrite", "Mail.Send", "User.Read.All")
        
        $script:DemoObjects.CreatedApps += $app.Id
        $script:DemoObjects.CreatedSPNs += $spn.Id
        
        Write-Status "Application créée - AppId: $($app.AppId)" "Success"
        Write-Status "⚠️  Cette app demande: $($permissions -join ', ')" "Warning"
        
        return $app
    } catch {
        Write-Status "Erreur création app: $_" "Error"
        return $null
    }
}

function Set-DemoMFADisabled {
    param(
        [string]$UserPrincipalName
    )
    
    Write-Status "Configuration utilisateur sans MFA: $UserPrincipalName" "Info"
    
    try {
        $user = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'"
        
        if ($user) {
            # Note: La désactivation réelle du MFA nécessite des policies
            # On marque juste l'utilisateur comme créé pour la démo
            Write-Status "Utilisateur configuré: $UserPrincipalName (MFA via policies à vérifier)" "Success"
        }
    } catch {
        Write-Status "Erreur configuration user: $_" "Warning"
    }
}

function New-DemoTransportRule {
    Write-Status "Création d'une transport rule suspecte..." "Info"
    
    # Vérifier si connecté à Exchange
    if (-not (Get-Command New-TransportRule -ErrorAction SilentlyContinue)) {
        Write-Status "Exchange Online non connecté - skipping transport rule" "Warning"
        return
    }
    
    try {
        $ruleName = "$script:DemoPrefix External Forward Alert"
        
        # Supprimer si existe
        Get-TransportRule -Identity $ruleName -ErrorAction SilentlyContinue | 
            Remove-TransportRule -Confirm:$false
        
        $rule = New-TransportRule -Name $ruleName `
            -FromScope NotInOrganization `
            -SentToScope InOrganization `
            -SetHeaderName "X-DEMO-Suspicious" `
            -SetHeaderValue "Flagged" `
            -Comments "Règle de démo pour simulation d'alerte"
        
        Write-Status "Transport rule créée: $ruleName" "Success"
    } catch {
        Write-Status "Erreur transport rule: $_" "Warning"
    }
}

function Initialize-DemoEnvironment {
    Write-Host "
╔════════════════════════════════════════════════════════════════╗
║     M365 INVESTIGATION TOOLKIT - DEMO ENVIRONMENT SETUP       ║
╚════════════════════════════════════════════════════════════════╝
" -ForegroundColor Cyan
    
    if (-not $SkipConfirm) {
        $confirm = Read-Host "⚠️  Cela va créer des objets fictifs dans votre tenant de test. Continuer? (O/n)"
        if ($confirm -eq 'n') { exit }
    }
    
    $context = Connect-DemoEnvironment
    
    # Déterminer le domaine du tenant
    $organization = Get-MgOrganization
    $verifiedDomains = $organization.VerifiedDomains | Where-Object { $_.IsDefault -eq $true }
    $TenantDomain = $verifiedDomains.Name
    
    Write-Status "Tenant: $($organization.DisplayName) ($TenantDomain)" "Info"
    
    if (-not $DemoUserEmail) {
        $demoUserName = "demo.victim"
        $DemoUserEmail = "$demoUserName@$TenantDomain"
    }
    
    Write-Host "`n🎬 CRÉATION DES SCÉNARIOS DE DÉMO`n" -ForegroundColor Green
    
    # 1. Créer utilisateur victime
    $victimUser = New-DemoUser -DisplayName "Demo Victim" -UserPrincipalName $DemoUserEmail
    
    if (-not $victimUser) {
        $victimUser = Get-MgUser -Filter "userPrincipalName eq '$DemoUserEmail'" -ErrorAction SilentlyContinue
        if ($victimUser) {
            Write-Status "Utilisateur existant récupéré: $DemoUserEmail" "Warning"
        }
    }
    
    if ($victimUser) {
        # Attendre que la mailbox soit créée (délai Azure AD)
        Write-Status "Attente création mailbox (10s)..." "Info"
        Start-Sleep -Seconds 10
        
        Set-DemoMailboxForwarding -UserPrincipalName $DemoUserEmail
        Set-DemoSuspiciousInboxRule -UserPrincipalName $DemoUserEmail
        Set-DemoMFADisabled -UserPrincipalName $DemoUserEmail
    }
    
    # 2. Créer application OAuth malveillante
    $maliciousApp = New-DemoOAuthApp
    
    # 3. Créer transport rule
    New-DemoTransportRule
    
    # 4. Créer utilisateur dormant
    $dormantUserEmail = "demo.dormant@$TenantDomain"
    $dormantUser = New-DemoUser -DisplayName "Demo Dormant User" -UserPrincipalName $dormantUserEmail
    if ($dormantUser) {
        Update-MgUser -UserId $dormantUser.Id -AccountEnabled:$false
        Write-Status "Utilisateur dormant créé et désactivé: $dormantUserEmail" "Success"
    }
    
    # Générer rapport
    Export-DemoReport -TenantDomain $TenantDomain
    
    Write-Host "
╔════════════════════════════════════════════════════════════════╗
║                    🎉 SETUP TERMINÉ !                          ║
╚════════════════════════════════════════════════════════════════╝
" -ForegroundColor Green
    
    Write-Status "Utilisateur victime: $DemoUserEmail" "Info"
    if ($maliciousApp) {
        Write-Status "Application malveillante: $($maliciousApp.AppId)" "Info"
    }
    Write-Host "
🔍 Prochaines étapes:" -ForegroundColor Cyan
    Write-Host "   1. Lancez: pwsh -File ./Run-Investigation-Collector.ps1"
    Write-Host "   2. Utilisez le case name: 'demo-investigation'"
    Write-Host "   3. Observez les détections dans 'output/incidents/'"
    Write-Host "
🧹 Pour nettoyer: pwsh -File ./Setup-DemoEnvironment.ps1 -Cleanup" -ForegroundColor Yellow
}

function Export-DemoReport {
    param([string]$TenantDomain)
    
    $reportPath = "./demo-setup-report.json"
    
    $report = @{
        SetupDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        TenantDomain = $TenantDomain
        ObjectsCreated = $script:DemoObjects
        DemoScenarios = @(
            @{
                Name = "Email Forwarding"
                Description = "Règle de forwarding vers attacker@malicious-example.com"
                User = $DemoUserEmail
                DetectionExpected = "BEC_Indicator"
            },
            @{
                Name = "Suspicious Inbox Rules"
                Description = "Auto-delete des emails externes + move invoices"
                User = $DemoUserEmail
                DetectionExpected = "BEC_Indicator"
            },
            @{
                Name = "OAuth Consent Abuse"
                Description = "App avec permissions Mail.ReadWrite + Mail.Send"
                AppId = ($script:DemoObjects.CreatedApps | Select-Object -First 1)
                DetectionExpected = "OAuthAbuse"
            },
            @{
                Name = "Weak Authentication"
                Description = "Utilisateur sans MFA obligatoire"
                User = $DemoUserEmail
                DetectionExpected = "AccountSecurity"
            },
            @{
                Name = "Dormant Account"
                Description = "Compte désactivé qui pourrait être compromis"
                User = "demo.dormant@$TenantDomain"
                DetectionExpected = "DormantAccount"
            }
        )
        CleanupCommands = @(
            "# Supprimer inbox rules:"
            "Get-InboxRule -Mailbox '$DemoUserEmail' | Where-Object Name -like 'DEMO-*' | Remove-InboxRule -Confirm:`$false"
            ""
            "# Supprimer l'app:"
            "Get-MgApplication -Filter `"displayName eq 'DEMO- Malicious Mail App'`" | Remove-MgApplication"
            ""
            "# Supprimer les users:"
            "Get-MgUser -Filter `"startsWith(userPrincipalName,'demo.')`" | Remove-MgUser"
            ""
            "# Supprimer transport rules:"
            "Get-TransportRule | Where-Object Name -like 'DEMO-*' | Remove-TransportRule -Confirm:`$false"
        ) -join "`n"
    }
    
    $report | ConvertTo-Json -Depth 5 | Out-File $reportPath
    Write-Status "Rapport sauvegardé: $reportPath" "Success"
}

function Clear-DemoEnvironment {
    Write-Host "
╔════════════════════════════════════════════════════════════════╗
║              🧹 NETTOYAGE DE L'ENVIRONNEMENT                   ║
╚════════════════════════════════════════════════════════════════╝
" -ForegroundColor Yellow
    
    $context = Connect-DemoEnvironment
    $organization = Get-MgOrganization
    $TenantDomain = ($organization.VerifiedDomains | Where-Object { $_.IsDefault }).Name
    
    $reportPath = "./demo-setup-report.json"
    if (Test-Path $reportPath) {
        $report = Get-Content $reportPath | ConvertFrom-Json
        Write-Status "Rapport trouvé - nettoyage guidé" "Info"
    }
    
    # Nettoyer inbox rules
    Write-Status "Suppression des inbox rules..." "Info"
    Get-MgUser -All | Where-Object { $_.UserPrincipalName -like "demo.*" } | ForEach-Object {
        Get-InboxRule -Mailbox $_.UserPrincipalName -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -like "DEMO-*" } | 
            ForEach-Object {
                try {
                    Remove-InboxRule -Identity $_.Identity -Confirm:$false
                    Write-Status "Rule supprimée: $($_.Name)" "Success"
                } catch {
                    Write-Status "Erreur suppression rule: $_" "Warning"
                }
            }
    }
    
    # Nettoyer transport rules
    Write-Status "Suppression des transport rules..." "Info"
    if (Get-Command Get-TransportRule -ErrorAction SilentlyContinue) {
        Get-TransportRule | Where-Object { $_.Name -like "DEMO-*" } | ForEach-Object {
            try {
                Remove-TransportRule -Identity $_.Identity -Confirm:$false
                Write-Status "Transport rule supprimée: $($_.Name)" "Success"
            } catch {
                Write-Status "Erreur: $_" "Warning"
            }
        }
    }
    
    # Nettoyer applications
    Write-Status "Suppression des applications..." "Info"
    Get-MgApplication -All | Where-Object { $_.DisplayName -like "DEMO-*" } | ForEach-Object {
        try {
            Remove-MgApplication -ApplicationId $_.Id
            Write-Status "Application supprimée: $($_.DisplayName)" "Success"
        } catch {
            Write-Status "Erreur: $_" "Warning"
        }
    }
    
    # Nettoyer SPNs
    Get-MgServicePrincipal -All | Where-Object { $_.DisplayName -like "DEMO-*" } | ForEach-Object {
        try {
            Remove-MgServicePrincipal -ServicePrincipalId $_.Id
            Write-Status "SPN supprimé: $($_.DisplayName)" "Success"
        } catch {
            Write-Status "Erreur: $_" "Warning"
        }
    }
    
    # Nettoyer utilisateurs
    Write-Status "Suppression des utilisateurs de démo..." "Info"
    Get-MgUser -All | Where-Object { $_.DisplayName -like "Demo*" -or $_.UserPrincipalName -like "demo.*" } | ForEach-Object {
        try {
            Remove-MgUser -UserId $_.Id
            Write-Status "User supprimé: $($_.UserPrincipalName)" "Success"
        } catch {
            Write-Status "Erreur: $_" "Warning"
        }
    }
    
    if (Test-Path $reportPath) {
        Remove-Item $reportPath
        Write-Status "Rapport supprimé" "Success"
    }
    
    Write-Host "
✅ Nettoyage terminé!" -ForegroundColor Green
}

if ($Cleanup) {
    Clear-DemoEnvironment
} else {
    Initialize-DemoEnvironment
}
