Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "profiles.ps1")

function Get-InvestigationDelegatedScopes {
    return @(
        "User.Read",
        "Organization.Read.All",
        "Directory.Read.All",
        "Domain.Read.All",
        "Application.Read.All",
        "AuditLog.Read.All",
        "RoleManagement.Read.Directory"
    )
}

function Test-InvestigationGrantedScopes {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredScopes,

        [Parameter(Mandatory = $true)]
        [string[]]$GrantedScopes
    )

    $missing = @(
        $RequiredScopes |
            Where-Object { $_ -and ($_ -notin $GrantedScopes) } |
            Sort-Object -Unique
    )

    return [pscustomobject]@{
        Granted = $missing.Count -eq 0
        MissingScopes = $missing
    }
}

function Resolve-InvestigationTenantProfile {
    param(
        [Parameter()]
        [string]$ProfilePath,

        [Parameter()]
        [string]$ProfileRoot,

        [Parameter()]
        [string]$TenantId
    )

    if ($ProfilePath) {
        if (-not (Test-Path $ProfilePath)) {
            throw "Tenant profile not found: $ProfilePath"
        }
        return Read-InvestigationJsonFile -Path $ProfilePath
    }

    if ($ProfileRoot -and $TenantId) {
        return Get-InvestigationTenantProfile -RootPath $ProfileRoot -TenantId $TenantId
    }

    return $null
}

function Get-AcceptedDomainNames {
    param(
        [Parameter()]
        [object[]]$AcceptedDomains
    )

    return @(
        $AcceptedDomains |
            ForEach-Object {
                if ($null -eq $_) {
                    return
                }

                if ($_ -is [string]) {
                    $_
                } elseif ($_.PSObject.Properties.Name -contains "DomainName" -and $_.DomainName) {
                    $_.DomainName.ToString()
                } elseif ($_.PSObject.Properties.Name -contains "Name" -and $_.Name) {
                    $_.Name
                }
            } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}

function Test-InvestigationTenantMatch {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedTenantId,

        [Parameter(Mandatory = $true)]
        [string]$GraphTenantId,

        [Parameter()]
        [string[]]$AcceptedDomains,

        [Parameter()]
        [string]$ExpectedDomain
    )

    if ($ExpectedTenantId -ne $GraphTenantId) {
        throw "Graph tenant mismatch. Expected '$ExpectedTenantId' but got '$GraphTenantId'."
    }

    if ($ExpectedDomain) {
        $resolvedAcceptedDomains = @(Get-AcceptedDomainNames -AcceptedDomains $AcceptedDomains)
        if ($ExpectedDomain -notin $resolvedAcceptedDomains) {
            throw "Exchange accepted-domain mismatch. Expected '$ExpectedDomain' but found '$($resolvedAcceptedDomains -join ", ")'."
        }
    }

    return $true
}

function Connect-InvestigationTenantDelegated {
    param(
        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$TenantDomain,

        [Parameter()]
        [string[]]$Scopes = (Get-InvestigationDelegatedScopes)
    )

    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    try {
        if ($TenantDomain) {
            Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false | Out-Null
            Connect-IPPSSession -Organization $TenantDomain -EnableSearchOnlySession -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null
        } else {
            Connect-ExchangeOnline -ShowBanner:$false | Out-Null
            Connect-IPPSSession -EnableSearchOnlySession -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null
        }

        $mgParams = @{
            Scopes = $Scopes
            NoWelcome = $true
            ContextScope = "Process"
        }
        if ($TenantId) {
            $mgParams.TenantId = $TenantId
        }
        Connect-MgGraph @mgParams | Out-Null

        $mgContext = Get-MgContext
        $scopeStatus = Test-InvestigationGrantedScopes -RequiredScopes $Scopes -GrantedScopes @($mgContext.Scopes)
        if (-not $scopeStatus.Granted) {
            throw "Missing delegated consent for scope(s): $($scopeStatus.MissingScopes -join ", ")."
        }

        $exoContext = Get-ConnectionInformation | Select-Object -First 1
        $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)

        if ($TenantId -and $TenantDomain) {
            Test-InvestigationTenantMatch `
                -ExpectedTenantId $TenantId `
                -GraphTenantId $mgContext.TenantId `
                -AcceptedDomains $acceptedDomains `
                -ExpectedDomain $TenantDomain | Out-Null
        }

        $resolvedTenantDomain = $TenantDomain
        if (-not $resolvedTenantDomain) {
            $resolvedTenantDomain = @(
                Get-AcceptedDomainNames -AcceptedDomains $acceptedDomains |
                    Select-Object -First 1
            )[0]
        }

        return [pscustomobject]@{
            ExchangeOnline = $exoContext
            Graph = $mgContext
            AcceptedDomains = $acceptedDomains
            TenantId = if ($TenantId) { $TenantId } else { $mgContext.TenantId }
            TenantDomain = $resolvedTenantDomain
            Connected = $true
        }
    } catch {
        Clear-InvestigationConnections
        throw
    }
}

function Clear-InvestigationConnections {
    $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
    $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
