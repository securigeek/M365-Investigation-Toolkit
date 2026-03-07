Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")
. (Join-Path $PSScriptRoot "../lib/forensic-normalization.ps1")

function Get-InvestigationSignInPropertyValue {
    param(
        [Parameter()]
        [psobject]$Record,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyNames,

        [Parameter()]
        [object]$DefaultValue = $null
    )

    if ($null -eq $Record) {
        return $DefaultValue
    }

    foreach ($propertyName in @($PropertyNames)) {
        if ($Record.PSObject.Properties.Name -contains $propertyName) {
            return $Record.$propertyName
        }
    }

    return $DefaultValue
}

function ConvertTo-InvestigationSignInRows {
    param(
        [Parameter()]
        [object[]]$Records
    )

    return @(
        $Records |
            ForEach-Object {
                $isInteractiveValue = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("IsInteractive", "isInteractive")
                $status = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("Status")

                [pscustomobject]@{
                    CreatedDateTime = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("CreatedDateTime", "createdDateTime")
                    UserPrincipalName = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("UserPrincipalName", "userPrincipalName")
                    AppDisplayName = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("AppDisplayName", "appDisplayName")
                    ClientApp = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("ClientAppUsed", "clientAppUsed")
                    AuthenticationProtocol = Resolve-ForensicAuthenticationProtocol -Protocol (Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("AuthenticationProtocol", "authenticationProtocol"))
                    IPAddress = Get-InvestigationSignInPropertyValue -Record $_ -PropertyNames @("IPAddress", "ipAddress")
                    IsInteractive = if ($null -eq $isInteractiveValue) { $null } else { [bool]$isInteractiveValue }
                    SignInEventTypes = @(
                        if ($_.PSObject.Properties.Name -contains "SignInEventTypes" -and $_.SignInEventTypes) {
                            @($_.SignInEventTypes)
                        } elseif ($_.PSObject.Properties.Name -contains "signInEventTypes" -and $_.signInEventTypes) {
                            @($_.signInEventTypes)
                        }
                    )
                    ResultType = Get-InvestigationSignInPropertyValue -Record $status -PropertyNames @("ErrorCode", "errorCode")
                    FailureReason = Get-InvestigationSignInPropertyValue -Record $status -PropertyNames @("FailureReason", "failureReason")
                }
            }
    )
}

function Get-InvestigationSignInBaseFilter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SinceIso
    )

    return "createdDateTime ge $SinceIso"
}

function Get-InvestigationSignInEventTypes {
    param(
        [Parameter()]
        [psobject]$Record
    )

    if ($null -eq $Record) {
        return @()
    }

    foreach ($propertyName in @("SignInEventTypes", "signInEventTypes")) {
        if ($Record.PSObject.Properties.Name -contains $propertyName -and $Record.$propertyName) {
            return @($Record.$propertyName | ForEach-Object { [string]$_ })
        }
    }

    return @()
}

function Test-InvestigationInteractiveSignInRecord {
    param(
        [Parameter()]
        [psobject]$Record
    )

    if ($null -eq $Record) {
        return $false
    }

    $eventTypes = @(Get-InvestigationSignInEventTypes -Record $Record)
    if ($eventTypes -contains "nonInteractiveUser") {
        return $false
    }
    if ($eventTypes -contains "interactiveUser") {
        return $true
    }
    $isInteractiveValue = Get-InvestigationSignInPropertyValue -Record $Record -PropertyNames @("IsInteractive", "isInteractive")
    if ($null -ne $isInteractiveValue) {
        return [bool]$isInteractiveValue
    }

    return $false
}

function Test-InvestigationNonInteractiveSignInRecord {
    param(
        [Parameter()]
        [psobject]$Record
    )

    if ($null -eq $Record) {
        return $false
    }

    $eventTypes = @(Get-InvestigationSignInEventTypes -Record $Record)
    if ($eventTypes -contains "nonInteractiveUser") {
        return $true
    }
    if ($eventTypes -contains "interactiveUser") {
        return $false
    }
    $isInteractiveValue = Get-InvestigationSignInPropertyValue -Record $Record -PropertyNames @("IsInteractive", "isInteractive")
    if ($null -ne $isInteractiveValue) {
        return -not [bool]$isInteractiveValue
    }

    return $false
}

function Invoke-TenantInteractiveSigninsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter()]
        [string]$CommandName = "Get-MgAuditLogSignIn"
    )

    $moduleName = "interactiveSignins"
    $filter = Get-InvestigationSignInBaseFilter -SinceIso $SinceIso

    try {
        $records = @(& $CommandName -Filter $filter -All)
        $rows = ConvertTo-InvestigationSignInRows -Records @($records | Where-Object { Test-InvestigationInteractiveSignInRecord -Record $_ })
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
            Filter = $filter
            Records = $records
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            SinceUtc = $SinceIso
            TotalRows = @($rows).Count
            Rows = $rows
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{ TotalRows = @($rows).Count }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); SinceUtc = $SinceIso; Rows = @(); TotalRows = 0 }) `
            -Metrics @{ TotalRows = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
