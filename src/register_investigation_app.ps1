<#
.SYNOPSIS
Registers (or updates) a dedicated M365 investigation app and grants consent.

.DESCRIPTION
Creates an Entra app registration and service principal, enables public client
for device code auth, configures required API permissions, and grants:
- Application permissions (app roles)
- Delegated permissions (tenant-wide admin consent)

This script is read/write on Entra objects only. It does not modify mailboxes.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter()]
    [string]$AppName = "M365-Investigation-App",

    [Parameter()]
    [string]$AppId,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$ProfileRoot,

    [Parameter()]
    [string]$CustomerName,

    [Parameter()]
    [string]$TenantDomain,

    [Parameter()]
    [ValidateSet("Interactive", "Device")]
    [string]$AuthMode = "Interactive",

    [Parameter()]
    [switch]$SkipPrompt
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputPath) {
    $OutputPath = Join-Path $projectRoot "output/app-registration"
}
if (-not $ProfileRoot) {
    $ProfileRoot = Join-Path $projectRoot "profiles"
}

. (Join-Path $PSScriptRoot "lib/onboarding.ps1")

# Graph SDK submodules in this workspace are aligned at 2.28.0 for app mgmt.
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.28.0 -ErrorAction Stop
Import-Module Microsoft.Graph.Applications -RequiredVersion 2.28.0 -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -RequiredVersion 2.28.0 -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.SignIns -RequiredVersion 2.28.0 -ErrorAction Stop

$requiredCmdlets = @(
    "Connect-MgGraph",
    "Get-MgOrganization",
    "Get-MgDomain",
    "Get-MgApplication",
    "New-MgApplication",
    "Update-MgApplication",
    "Get-MgServicePrincipal",
    "New-MgServicePrincipal",
    "Get-MgServicePrincipalAppRoleAssignment",
    "New-MgServicePrincipalAppRoleAssignment",
    "Get-MgOauth2PermissionGrant",
    "New-MgOauth2PermissionGrant",
    "Update-MgOauth2PermissionGrant"
)

foreach ($cmd in $requiredCmdlets) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Required Graph cmdlet '$cmd' is not available. Install/update Microsoft.Graph modules before running this script."
    }
}

function Get-PermissionDefinition {
    param(
        [Parameter(Mandatory = $true)]
        [object]$ResourceSp,

        [Parameter(Mandatory = $true)]
        [string]$PermissionName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Role", "Scope")]
        [string]$Type
    )

    if ($Type -eq "Role") {
        return $ResourceSp.AppRoles |
            Where-Object { $_.Value -eq $PermissionName -and ($_.AllowedMemberTypes -contains "Application") } |
            Select-Object -First 1
    }

    return $ResourceSp.Oauth2PermissionScopes |
        Where-Object { $_.Value -eq $PermissionName } |
        Select-Object -First 1
}

function Add-UniqueScope {
    param(
        [string[]]$Current,
        [string[]]$Additional
    )

    return ($Current + $Additional | Where-Object { $_ } | Sort-Object -Unique)
}

Write-Host "Connecting to Microsoft Graph ($AuthMode auth)..." -ForegroundColor Cyan
$setupScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Directory.Read.All",
    "RoleManagement.ReadWrite.Directory"
)
$ctx = Get-MgContext -ErrorAction SilentlyContinue
$reuseContext = $false
if ($ctx -and $ctx.TenantId -eq $TenantId) {
    $missing = $setupScopes | Where-Object { $_ -notin $ctx.Scopes }
    if ($missing.Count -eq 0) {
        $reuseContext = $true
    }
}

if ($reuseContext) {
    Write-Host "Using existing Graph context for tenant $TenantId" -ForegroundColor Green
} else {
    if ($AuthMode -eq "Device") {
        Connect-MgGraph -TenantId $TenantId -Scopes $setupScopes -UseDeviceAuthentication -NoWelcome | Out-Null
    } else {
        Connect-MgGraph -TenantId $TenantId -Scopes $setupScopes -NoWelcome | Out-Null
    }
}

$org = Get-MgOrganization | Select-Object -First 1
Write-Host "Connected tenant: $($org.DisplayName) ($($org.Id))" -ForegroundColor Green

$summaryFile = Join-Path $OutputPath "investigation-app-registration.json"
$selectedBy = "DisplayName"
$appCandidates = @()
$app = $null

if (-not $AppId -and (Test-Path $summaryFile)) {
    try {
        $previousSummary = Get-Content $summaryFile -Raw | ConvertFrom-Json -ErrorAction Stop
        if ($previousSummary.AppName -eq $AppName -and $previousSummary.AppId) {
            $AppId = $previousSummary.AppId
            $selectedBy = "PreviousSummary"
            Write-Host "Using AppId from prior summary: $AppId" -ForegroundColor Gray
        }
    } catch {
        Write-Warning "Could not parse existing summary file at $summaryFile. Continuing with tenant lookup."
    }
}

if ($AppId) {
    $app = Get-MgApplication -Filter "appId eq '$AppId'" -ConsistencyLevel eventual -CountVariable null -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $app) {
        $appCandidates = @(
            Get-MgApplication -Filter "displayName eq '$AppName'" -ConsistencyLevel eventual -All -ErrorAction SilentlyContinue
        )
        $app = $appCandidates | Where-Object { $_.AppId -eq $AppId } | Select-Object -First 1
    }
    if ($app) {
        $selectedBy = "AppId"
        Write-Host "Using existing app by AppId: $($app.AppId)" -ForegroundColor Yellow
    } else {
        Write-Warning "AppId '$AppId' was not found in tenant $TenantId. Falling back to display name lookup."
    }
}

if (-not $app) {
    if ($appCandidates.Count -eq 0) {
        $appCandidates = @(
            Get-MgApplication -Filter "displayName eq '$AppName'" -ConsistencyLevel eventual -All -ErrorAction SilentlyContinue
        )
    }

    if ($appCandidates.Count -gt 1) {
        $app = $appCandidates | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
        Write-Warning "Found $($appCandidates.Count) apps named '$AppName'. Using newest app: $($app.AppId) (created $($app.CreatedDateTime))."
    } elseif ($appCandidates.Count -eq 1) {
        $app = $appCandidates[0]
    }
}

if (-not $app) {
    Write-Host "Creating app registration: $AppName" -ForegroundColor Cyan
    $app = New-MgApplication -DisplayName $AppName `
        -SignInAudience "AzureADMyOrg" `
        -Description "Investigation app for M365 tenant hunting and evidence collection"
    $selectedBy = "Created"
} else {
    Write-Host "App already exists: $AppName" -ForegroundColor Yellow
}

# Ensure public-client redirect URIs exist for interactive/device auth flows.
$publicClientPatch = @{
    isFallbackPublicClient = $true
    publicClient           = @{
        redirectUris = @(
            "http://localhost",
            "https://login.microsoftonline.com/common/oauth2/nativeclient"
        )
    }
} | ConvertTo-Json -Depth 6
Invoke-MgGraphRequest -Method PATCH `
    -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)" `
    -Body $publicClientPatch `
    -ContentType "application/json" | Out-Null
$app = Get-MgApplication -ApplicationId $app.Id

$appSp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $appSp) {
    Write-Host "Creating service principal for app..." -ForegroundColor Cyan
    $appSp = New-MgServicePrincipal -AppId $app.AppId
} else {
    Write-Host "Service principal already exists." -ForegroundColor Yellow
}

$permissionPlan = @(
    @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        Permissions   = @(
            @{ Name = "User.Read"; Type = "Scope" },
            @{ Name = "Mail.Read"; Type = "Scope" },
            @{ Name = "Mail.ReadBasic"; Type = "Scope" },
            @{ Name = "Application.Read.All"; Type = "Role" },
            @{ Name = "User.Read.All"; Type = "Role" },
            @{ Name = "Mail.Read"; Type = "Role" },
            @{ Name = "Mail.ReadBasic.All"; Type = "Role" },
            @{ Name = "AuditLog.Read.All"; Type = "Role" },
            @{ Name = "SecurityEvents.Read.All"; Type = "Role" },
            @{ Name = "ThreatHunting.Read.All"; Type = "Role" }
        )
    },
    @{
        ResourceAppId = "00000002-0000-0ff1-ce00-000000000000" # Office 365 Exchange Online
        Permissions   = @(
            @{ Name = "Exchange.ManageAsApp"; Type = "Role" },
            @{ Name = "ExchangeMessageTrace.Read.All"; Type = "Role" }
        )
    }
)

$resolvedByResource = @{}
$missingPermissions = @()

foreach ($plan in $permissionPlan) {
    $resourceAppId = $plan.ResourceAppId
    $resourceSp = Get-MgServicePrincipal -Filter "appId eq '$resourceAppId'" | Select-Object -First 1
    if (-not $resourceSp) {
        $missingPermissions += [pscustomobject]@{
            ResourceAppId = $resourceAppId
            Permission    = "<resource-not-found>"
            Type          = "<n/a>"
        }
        continue
    }

    $resolvedByResource[$resourceAppId] = [ordered]@{
        ResourceSpId = $resourceSp.Id
        ResourceName = $resourceSp.DisplayName
        Access       = @()
    }

    foreach ($perm in $plan.Permissions) {
        $definition = Get-PermissionDefinition -ResourceSp $resourceSp -PermissionName $perm.Name -Type $perm.Type
        if ($definition) {
            $resolvedByResource[$resourceAppId].Access += [pscustomobject]@{
                Name = $perm.Name
                Type = $perm.Type
                Id   = $definition.Id
            }
        } else {
            $missingPermissions += [pscustomobject]@{
                ResourceAppId = $resourceAppId
                Permission    = $perm.Name
                Type          = $perm.Type
            }
        }
    }
}

$requiredResourceAccess = @()
foreach ($resourceAppId in $resolvedByResource.Keys) {
    $entries = $resolvedByResource[$resourceAppId].Access
    if (-not $entries -or $entries.Count -eq 0) {
        continue
    }

    $requiredResourceAccess += @{
        ResourceAppId  = $resourceAppId
        ResourceAccess = @(
            $entries | ForEach-Object {
                @{
                    Id   = $_.Id
                    Type = $_.Type
                }
            }
        )
    }
}

if ($requiredResourceAccess.Count -gt 0) {
    Write-Host "Updating RequiredResourceAccess..." -ForegroundColor Cyan
    Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $requiredResourceAccess | Out-Null
}

# Grant application permissions (app roles)
$existingAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $appSp.Id -All -ErrorAction SilentlyContinue
$newAppRoleAssignments = @()

foreach ($resourceAppId in $resolvedByResource.Keys) {
    $resource = $resolvedByResource[$resourceAppId]
    $rolePerms = $resource.Access | Where-Object { $_.Type -eq "Role" }
    foreach ($rolePerm in $rolePerms) {
        $already = $existingAssignments | Where-Object {
            $_.ResourceId -eq $resource.ResourceSpId -and $_.AppRoleId -eq $rolePerm.Id
        } | Select-Object -First 1

        if (-not $already) {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $appSp.Id `
                -PrincipalId $appSp.Id `
                -ResourceId $resource.ResourceSpId `
                -AppRoleId $rolePerm.Id | Out-Null

            $newAppRoleAssignments += "$($resource.ResourceName):$($rolePerm.Name)"
        }
    }
}

# Grant delegated permissions (AllPrincipals)
$scopeGrantChanges = @()
foreach ($resourceAppId in $resolvedByResource.Keys) {
    $resource = $resolvedByResource[$resourceAppId]
    $scopePerms = $resource.Access | Where-Object { $_.Type -eq "Scope" } | Select-Object -ExpandProperty Name -Unique
    if (-not $scopePerms -or $scopePerms.Count -eq 0) {
        continue
    }

    $existingGrant = Get-MgOauth2PermissionGrant `
        -Filter "clientId eq '$($appSp.Id)' and resourceId eq '$($resource.ResourceSpId)' and consentType eq 'AllPrincipals'" `
        -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($existingGrant) {
        $current = @()
        if ($existingGrant.Scope) {
            $current = $existingGrant.Scope -split " "
        }
        $merged = Add-UniqueScope -Current $current -Additional $scopePerms
        $mergedString = $merged -join " "
        if ($mergedString -ne $existingGrant.Scope) {
            Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $existingGrant.Id -Scope $mergedString | Out-Null
            $scopeGrantChanges += "$($resource.ResourceName):updated:$mergedString"
        }
    } else {
        $scopeString = ($scopePerms | Sort-Object -Unique) -join " "
        New-MgOauth2PermissionGrant `
            -ClientId $appSp.Id `
            -ConsentType "AllPrincipals" `
            -ResourceId $resource.ResourceSpId `
            -Scope $scopeString | Out-Null
        $scopeGrantChanges += "$($resource.ResourceName):created:$scopeString"
    }
}

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$defaultTenantDomain = $TenantDomain
if (-not $defaultTenantDomain) {
    $defaultTenantDomain = @(
        Get-MgDomain -All -ErrorAction SilentlyContinue |
            Where-Object { $_.IsDefault -or $_.IsInitial -or $_.IsVerified } |
            Select-Object -ExpandProperty Id
    ) | Select-Object -First 1
}

$summary = [pscustomobject]@{
    TimestampUtc            = (Get-Date).ToUniversalTime().ToString("o")
    TenantId                = $org.Id
    TenantDisplayName       = $org.DisplayName
    AppName                 = $app.DisplayName
    AppId                   = $app.AppId
    ApplicationObjectId     = $app.Id
    ServicePrincipalObjectId = $appSp.Id
    SelectedBy              = $selectedBy
    DuplicateNameCount      = $appCandidates.Count
    PublicClientRedirectUris = @($app.PublicClient.RedirectUris)
    IsFallbackPublicClient  = $true
    SetupScopesUsed         = $setupScopes
    NewAppRoleAssignments   = $newAppRoleAssignments
    ScopeGrantChanges       = $scopeGrantChanges
    MissingPermissions      = $missingPermissions
    Notes                   = @(
        "Use scripts/connect_investigation_device_auth.ps1 for Graph + Exchange device auth.",
        "For EXO app-only later, certificate setup and Exchange RBAC service-principal role assignment are still required."
    )
}

$profilePath = Save-OnboardedTenantProfile `
    -RootPath $ProfileRoot `
    -Summary $summary `
    -CustomerName $CustomerName `
    -TenantDomain $defaultTenantDomain `
    -AuthMetadata @{
        AuthMode = "AppRegistration"
        AppId = $app.AppId
        TenantId = $org.Id
    } `
    -SkipPrompt:$SkipPrompt

$summary | Add-Member -NotePropertyName ProfilePath -NotePropertyValue $profilePath

$outFile = Join-Path $OutputPath "investigation-app-registration.json"
$summary | ConvertTo-Json -Depth 10 | Set-Content $outFile

Write-Host ""
Write-Host "Registration summary saved to: $outFile" -ForegroundColor Green
Write-Host "Tenant profile saved to: $profilePath" -ForegroundColor Green
Write-Host "AppId: $($app.AppId)" -ForegroundColor Green
if ($missingPermissions.Count -gt 0) {
    Write-Host "Some permissions were not found and were skipped. Check summary JSON." -ForegroundColor Yellow
}

$summary | ConvertTo-Json -Depth 10
