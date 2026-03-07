Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")
. (Join-Path $PSScriptRoot "../lib/unified-audit.ps1")

function Invoke-TenantUnifiedAuditLogCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$Operations = (Get-InvestigationDefaultUnifiedAuditOperations),

        [Parameter()]
        [int]$ResultSize = 5000,

        [Parameter()]
        [string]$CommandName = "Search-UnifiedAuditLog"
    )

    $moduleName = "unifiedAuditLog"

    try {
        $records = Invoke-InvestigationUnifiedAuditSearch `
            -StartDate $StartDate `
            -EndDate $EndDate `
            -Operations $Operations `
            -ResultSize $ResultSize `
            -CommandName $CommandName

        $rows = @(
            $records |
                ForEach-Object {
                    $audit = ConvertFrom-InvestigationUnifiedAuditData -AuditData $_.AuditData

                    [pscustomobject]@{
                        CreationDate = $_.CreationDate
                        Operation = if ($audit.PSObject.Properties.Name -contains "Operation" -and $audit.Operation) { $audit.Operation } else { $_.Operations }
                        UserId = if ($audit.PSObject.Properties.Name -contains "UserId" -and $audit.UserId) { $audit.UserId } else { $_.UserIds }
                        Workload = if ($audit.PSObject.Properties.Name -contains "Workload") { $audit.Workload } else { $null }
                        ClientInfoString = if ($audit.PSObject.Properties.Name -contains "ClientInfoString") { $audit.ClientInfoString } else { $null }
                        ExternalAccess = if ($audit.PSObject.Properties.Name -contains "ExternalAccess") { $audit.ExternalAccess } else { $null }
                        ItemCount = if ($audit.PSObject.Properties.Name -contains "ItemCount") { $audit.ItemCount } else { $null }
                        ObjectId = $_.ObjectId
                        ExtendedProperties = ConvertTo-InvestigationUnifiedAuditPropertyMap -Properties $audit.ExtendedProperties
                        ModifiedProperties = ConvertTo-InvestigationUnifiedAuditPropertyMap -Properties $audit.ModifiedProperties
                    }
                }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            StartUtc = $StartDate.ToUniversalTime().ToString("o")
            EndUtc = $EndDate.ToUniversalTime().ToString("o")
            Operations = @($Operations)
            Records = $records
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            StartUtc = $rawData.StartUtc
            EndUtc = $rawData.EndUtc
            Operations = @($Operations)
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
            -NormalizedData ([pscustomobject]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
                StartUtc = $StartDate.ToUniversalTime().ToString("o")
                EndUtc = $EndDate.ToUniversalTime().ToString("o")
                Operations = @($Operations)
                TotalRows = 0
                Rows = @()
            }) `
            -Metrics @{ TotalRows = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
