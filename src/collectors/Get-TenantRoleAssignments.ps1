Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantRoleAssignmentsCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter()]
        [string]$CommandName = "Get-MgAuditLogDirectoryAudit"
    )

    $moduleName = "roleAssignments"

    try {
        $events = @(
            & $CommandName -Filter "activityDateTime ge $SinceIso and category eq 'RoleManagement'" -All |
                Select-Object `
                    ActivityDateTime,
                    ActivityDisplayName,
                    Category,
                    Result,
                    LoggedByService,
                    @{ Name = "InitiatedByUser"; Expression = { $_.InitiatedBy.User.UserPrincipalName } },
                    TargetResources
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
            Events = $events
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            SinceUtc = $SinceIso
            TotalRows = @($events).Count
            Rows = $events
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{ TotalRows = @($events).Count }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
                SinceUtc = $SinceIso
                Rows = @()
            }) `
            -Metrics @{ TotalRows = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
