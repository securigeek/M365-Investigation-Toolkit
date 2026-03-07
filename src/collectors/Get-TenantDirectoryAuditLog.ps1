Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")
. (Join-Path $PSScriptRoot "../lib/forensic-normalization.ps1")

function ConvertTo-InvestigationDirectoryAuditActor {
    param(
        [Parameter()]
        [psobject]$Record
    )

    return Resolve-ForensicActor -Record $Record
}

function ConvertTo-InvestigationDirectoryAuditModifiedProperties {
    param(
        [Parameter()]
        [object[]]$TargetResources
    )

    return ConvertTo-ForensicPropertyMap -Properties @(
        $TargetResources |
            ForEach-Object { $_.ModifiedProperties }
    )
}

function Invoke-TenantDirectoryAuditLogCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$SinceIso,

        [Parameter()]
        [string]$CommandName = "Get-MgAuditLogDirectoryAudit"
    )

    $moduleName = "directoryAuditLog"

    try {
        $records = @(& $CommandName -Filter "activityDateTime ge $SinceIso" -All)
        $rows = @(
            $records |
                ForEach-Object {
                    $target = Resolve-ForensicTarget -Targets $_.TargetResources

                    [pscustomobject]@{
                        ActivityDateTime = $_.ActivityDateTime
                        Operation = $_.ActivityDisplayName
                        Category = $_.Category
                        Result = $_.Result
                        Actor = ConvertTo-InvestigationDirectoryAuditActor -Record $_
                        Target = $target.Name
                        TargetId = $target.Id
                        TargetType = $target.Type
                        ModifiedProperties = ConvertTo-InvestigationDirectoryAuditModifiedProperties -TargetResources $_.TargetResources
                    }
                }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            SinceUtc = $SinceIso
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
