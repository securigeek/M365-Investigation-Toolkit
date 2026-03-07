Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "common.ps1")

function Initialize-InvestigationProfileStore {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    Resolve-InvestigationPath -Path $RootPath | Out-Null
    $tenantRoot = Join-Path $RootPath "tenants"
    Resolve-InvestigationPath -Path $tenantRoot | Out-Null
    return (Resolve-InvestigationPath -Path $RootPath)
}

function Save-InvestigationTenantProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [psobject]$Profile
    )

    if ([string]::IsNullOrWhiteSpace($Profile.TenantId)) {
        throw "Profile.TenantId is required."
    }

    Initialize-InvestigationProfileStore -RootPath $RootPath | Out-Null
    $tenantPath = Join-Path (Join-Path $RootPath "tenants") "$($Profile.TenantId).json"
    return Write-InvestigationJsonFile -Path $tenantPath -Data $Profile
}

function Get-InvestigationTenantProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $tenantPath = Join-Path (Join-Path $RootPath "tenants") "$TenantId.json"
    if (-not (Test-Path $tenantPath)) {
        throw "Tenant profile not found: $tenantPath. Run Register-InvestigationApp.ps1 for this tenant first or provide -ProfilePath."
    }

    return Read-InvestigationJsonFile -Path $tenantPath
}
