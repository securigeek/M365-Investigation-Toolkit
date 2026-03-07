Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "common.ps1")
. (Join-Path $PSScriptRoot "auth.ps1")

function Get-InvestigationCollectorRegistry {
    return @(
        [pscustomobject]@{
            Name = "mailboxForwarding"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-EXOMailbox"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "inboxRules"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-InboxRule"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "transportRules"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-TransportRule"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "connectors"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-InboundConnector"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "riskySignins"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgAuditLogSignIn"
            AllowBetaFallback = $true
            BetaCommand = "Get-MgBetaAuditLogSignIn"
            RequiredScopes = @("AuditLog.Read.All")
            RoleAssumptions = @("Security Reader", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "appChanges"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgApplication"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @("Application.Read.All", "Directory.Read.All")
            RoleAssumptions = @("Application Administrator", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "auditCoverage"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-AdminAuditLogConfig"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "directoryAuditLog"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgAuditLogDirectoryAudit"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @("AuditLog.Read.All")
            RoleAssumptions = @("Security Reader", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "interactiveSignins"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgAuditLogSignIn"
            AllowBetaFallback = $true
            BetaCommand = "Get-MgBetaAuditLogSignIn"
            RequiredScopes = @("AuditLog.Read.All")
            RoleAssumptions = @("Security Reader", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "nonInteractiveSignins"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgAuditLogSignIn"
            AllowBetaFallback = $true
            BetaCommand = "Get-MgBetaAuditLogSignIn"
            RequiredScopes = @("AuditLog.Read.All")
            RoleAssumptions = @("Security Reader", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "servicePrincipalSignins"
            Surface = "Graph"
            PreferredProfile = "beta"
            PreferredCommand = "Get-MgBetaAuditLogServicePrincipalSignIn"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @("AuditLog.Read.All")
            RoleAssumptions = @("Security Reader", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "unifiedAuditLog"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Search-UnifiedAuditLog"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Audit Reader", "Compliance Administrator", "Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "roleAssignments"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgAuditLogDirectoryAudit"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @("AuditLog.Read.All", "RoleManagement.Read.Directory")
            RoleAssumptions = @("Security Reader", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "consentGrants"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgOauth2PermissionGrant"
            AllowBetaFallback = $true
            BetaCommand = "Get-MgBetaOauth2PermissionGrant"
            RequiredScopes = @("Directory.Read.All")
            RoleAssumptions = @("Cloud Application Administrator", "Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "acceptedDomains"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgDomain"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @("Domain.Read.All", "Directory.Read.All", "Organization.Read.All")
            RoleAssumptions = @("Global Reader")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "mailboxAuditPosture"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-EXOMailbox"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $false
        },
        [pscustomobject]@{
            Name = "messageTracePivot"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-MessageTraceV2"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $true
        },
        [pscustomobject]@{
            Name = "quarantinePivot"
            Surface = "Exchange"
            PreferredProfile = $null
            PreferredCommand = "Get-QuarantineMessage"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @()
            RoleAssumptions = @("Security Administrator", "Exchange Administrator")
            FallbackBehavior = "skip"
            RequiresPivots = $true
        }
    )
}

function Resolve-InvestigationModuleStatus {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Definition,

        [Parameter(Mandatory = $true)]
        [hashtable]$CommandSupport
    )

    if ($Definition.Surface -eq "Exchange") {
        $available = [bool]$CommandSupport["exchange:$($Definition.PreferredCommand)"]
        return [pscustomobject]@{
            Name = $Definition.Name
            Surface = $Definition.Surface
            Status = if ($available) { "available" } else { "unavailable" }
            Profile = $null
            Command = $Definition.PreferredCommand
            RequiredScopes = $Definition.RequiredScopes
        }
    }

    $preferredKey = "$($Definition.PreferredProfile):$($Definition.PreferredCommand)"
    if ([bool]$CommandSupport[$preferredKey]) {
        return [pscustomobject]@{
            Name = $Definition.Name
            Surface = $Definition.Surface
            Status = "available"
            Profile = $Definition.PreferredProfile
            Command = $Definition.PreferredCommand
            RequiredScopes = $Definition.RequiredScopes
        }
    }

    if ($Definition.AllowBetaFallback -and $Definition.BetaCommand) {
        $betaKey = "beta:$($Definition.BetaCommand)"
        if ([bool]$CommandSupport[$betaKey]) {
            return [pscustomobject]@{
                Name = $Definition.Name
                Surface = $Definition.Surface
                Status = "beta-fallback"
                Profile = "beta"
                Command = $Definition.BetaCommand
                RequiredScopes = $Definition.RequiredScopes
            }
        }
    }

    return [pscustomobject]@{
        Name = $Definition.Name
        Surface = $Definition.Surface
        Status = "unavailable"
        Profile = $null
        Command = $Definition.PreferredCommand
        RequiredScopes = $Definition.RequiredScopes
    }
}

function Get-InvestigationCommandSupportMap {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Registry
    )

    $commandSupport = @{}

    foreach ($definition in $Registry) {
        if ($definition.Surface -eq "Exchange") {
            $commandSupport["exchange:$($definition.PreferredCommand)"] = [bool](Get-Command $definition.PreferredCommand -ErrorAction SilentlyContinue)
            continue
        }

        if ($definition.PreferredCommand) {
            $v1Matches = @(Find-MgGraphCommand -Command $definition.PreferredCommand -ApiVersion $definition.PreferredProfile -ErrorAction SilentlyContinue)
            $commandSupport["$($definition.PreferredProfile):$($definition.PreferredCommand)"] = $v1Matches.Count -gt 0
        }

        if ($definition.AllowBetaFallback -and $definition.BetaCommand) {
            $betaMatches = @(Find-MgGraphCommand -Command $definition.BetaCommand -ApiVersion "beta" -ErrorAction SilentlyContinue)
            $commandSupport["beta:$($definition.BetaCommand)"] = $betaMatches.Count -gt 0
        }
    }

    return $commandSupport
}

function Get-InvestigationPermissionCatalog {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Registry
    )

    $scopes = @(
        $Registry |
            ForEach-Object { $_.RequiredScopes } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    return @(
        $scopes |
            ForEach-Object {
                $permission = Find-MgGraphPermission -SearchString $_ -PermissionType "Delegated" -ExactMatch -Online -ErrorAction SilentlyContinue |
                    Select-Object -First 1

                [pscustomobject]@{
                    Name = $_
                    Found = [bool]$permission
                    Permission = $permission
                }
            }
    )
}

function Get-InvestigationGraphMetadataSnapshot {
    $profiles = @("v1.0", "beta")
    $snapshots = @()

    foreach ($profile in $profiles) {
        $uri = "https://graph.microsoft.com/$profile/`$metadata"
        try {
            $response = Invoke-WebRequest -Uri $uri -Method GET -ErrorAction Stop
            $snapshots += [pscustomobject]@{
                Profile = $profile
                Status = "available"
                Uri = $uri
                StatusCode = [int]$response.StatusCode
                Length = $response.Content.Length
            }
        } catch {
            $snapshots += [pscustomobject]@{
                Profile = $profile
                Status = "unavailable"
                Uri = $uri
                Error = $_.Exception.Message
            }
        }
    }

    return $snapshots
}

function Get-InvestigationApiCatalog {
    $registry = Get-InvestigationCollectorRegistry
    $commandSupport = Get-InvestigationCommandSupportMap -Registry $registry
    $permissionCatalog = Get-InvestigationPermissionCatalog -Registry $registry
    $metadataSnapshot = Get-InvestigationGraphMetadataSnapshot

    $moduleStatuses = @(
        $registry |
            ForEach-Object { Resolve-InvestigationModuleStatus -Definition $_ -CommandSupport $commandSupport }
    )

    return [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        DelegatedScopes = Get-InvestigationDelegatedScopes
        Registry = $registry
        CommandSupport = $commandSupport
        PermissionCatalog = $permissionCatalog
        Metadata = $metadataSnapshot
        Modules = $moduleStatuses
    }
}
