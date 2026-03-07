Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "profiles.ps1")

function Prompt-InvestigationValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter()]
        [string]$DefaultValue,

        [Parameter()]
        [switch]$SkipPrompt
    )

    if (-not [string]::IsNullOrWhiteSpace($DefaultValue)) {
        return $DefaultValue.Trim()
    }

    if ($SkipPrompt) {
        throw "$Label is required."
    }

    $value = Read-Host $Label
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "$Label is required."
    }

    return $value.Trim()
}

function Test-MissingPermission {
    param(
        [Parameter()]
        [string[]]$MissingPermissions,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($name -in $MissingPermissions) {
            return $true
        }
    }

    return $false
}

function New-InvestigationModuleCapabilityMap {
    param(
        [Parameter()]
        [object[]]$MissingPermissions
    )

    $missingPermissionNames = @(
        $MissingPermissions |
            ForEach-Object {
                if ($_ -is [string]) {
                    $_
                } elseif ($_.PSObject.Properties.Name -contains "Permission") {
                    $_.Permission
                }
            } |
            Where-Object { $_ } |
            Sort-Object -Unique
    )

    $exchangeMissing = Test-MissingPermission -MissingPermissions $missingPermissionNames -Names @("Exchange.ManageAsApp")
    $auditMissing = Test-MissingPermission -MissingPermissions $missingPermissionNames -Names @("AuditLog.Read.All")
    $appMissing = Test-MissingPermission -MissingPermissions $missingPermissionNames -Names @("Application.Read.All")

    return [ordered]@{
        mailboxForwarding = [pscustomobject]@{
            Enabled = -not $exchangeMissing
            RequiredPermissions = @("Exchange.ManageAsApp")
        }
        inboxRules = [pscustomobject]@{
            Enabled = -not $exchangeMissing
            RequiredPermissions = @("Exchange.ManageAsApp")
        }
        transportRules = [pscustomobject]@{
            Enabled = -not $exchangeMissing
            RequiredPermissions = @("Exchange.ManageAsApp")
        }
        connectors = [pscustomobject]@{
            Enabled = -not $exchangeMissing
            RequiredPermissions = @("Exchange.ManageAsApp")
        }
        riskySignins = [pscustomobject]@{
            Enabled = -not $auditMissing
            RequiredPermissions = @("AuditLog.Read.All")
        }
        appChanges = [pscustomobject]@{
            Enabled = -not $appMissing
            RequiredPermissions = @("Application.Read.All")
        }
        auditCoverage = [pscustomobject]@{
            Enabled = -not $auditMissing
            RequiredPermissions = @("AuditLog.Read.All")
        }
    }
}

function Convert-AppRegistrationSummaryToTenantProfile {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Summary,

        [Parameter(Mandatory = $true)]
        [string]$TenantDomain,

        [Parameter()]
        [string]$CustomerName,

        [Parameter()]
        [hashtable]$AuthMetadata
    )

    $summaryCustomerName = if ($Summary.PSObject.Properties.Name -contains "CustomerName") { $Summary.CustomerName } else { $null }
    $summaryDisplayName = if ($Summary.PSObject.Properties.Name -contains "TenantDisplayName") { $Summary.TenantDisplayName } else { $null }
    $summaryAppName = if ($Summary.PSObject.Properties.Name -contains "AppName") { $Summary.AppName } else { $null }
    $resolvedCustomerName = if ($CustomerName) { $CustomerName } elseif ($summaryCustomerName) { $summaryCustomerName } else { $summaryDisplayName }
    $missingPermissions = @($Summary.MissingPermissions)

    return [pscustomobject]@{
        ProfileVersion = 1
        CustomerName = $resolvedCustomerName
        TenantId = $Summary.TenantId
        TenantDomain = $TenantDomain
        TenantDisplayName = $summaryDisplayName
        AppName = $summaryAppName
        AppId = $Summary.AppId
        OnboardedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        MissingPermissions = $missingPermissions
        Modules = New-InvestigationModuleCapabilityMap -MissingPermissions $missingPermissions
        Auth = if ($AuthMetadata) { [pscustomobject]$AuthMetadata } else { $null }
    }
}

function Save-OnboardedTenantProfile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootPath,

        [Parameter(Mandatory = $true)]
        [psobject]$Summary,

        [Parameter()]
        [string]$CustomerName,

        [Parameter()]
        [string]$TenantDomain,

        [Parameter()]
        [hashtable]$AuthMetadata,

        [Parameter()]
        [switch]$SkipPrompt
    )

    $resolvedCustomerName = Prompt-InvestigationValue `
        -Label "Customer name" `
        -DefaultValue $(if ($CustomerName) { $CustomerName } else { $Summary.TenantDisplayName }) `
        -SkipPrompt:$SkipPrompt

    $resolvedTenantDomain = Prompt-InvestigationValue `
        -Label "Primary tenant domain" `
        -DefaultValue $TenantDomain `
        -SkipPrompt:$SkipPrompt

    $profile = Convert-AppRegistrationSummaryToTenantProfile `
        -Summary $Summary `
        -TenantDomain $resolvedTenantDomain `
        -CustomerName $resolvedCustomerName `
        -AuthMetadata $AuthMetadata

    return Save-InvestigationTenantProfile -RootPath $RootPath -Profile $profile
}
