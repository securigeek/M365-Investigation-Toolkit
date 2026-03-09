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
        [int]$ResultSize = 500,  # Reduced from 5000 for performance

        [Parameter()]
        [string]$CommandName = "Search-UnifiedAuditLog"
    )

    $moduleName = "unifiedAuditLog"
    $startTime = Get-Date
    $timeoutSeconds = 120  # 2 minute timeout

    try {
        Write-Host "  📋 Searching Unified Audit Log (timeout: ${timeoutSeconds}s)..." -ForegroundColor DarkGray

        # Use a job with timeout for the search
        $job = Start-Job -ScriptBlock {
            param($StartDate, $EndDate, $Operations, $ResultSize, $CommandName, $PSScriptRoot)
            
            # Re-import required functions
            . (Join-Path $PSScriptRoot "../lib/unified-audit.ps1")
            
            try {
                $records = Invoke-InvestigationUnifiedAuditSearch `
                    -StartDate $StartDate `
                    -EndDate $EndDate `
                    -Operations $Operations `
                    -ResultSize $ResultSize `
                    -CommandName $CommandName
                return @{ Success = $true; Records = $records; Error = $null }
            } catch {
                return @{ Success = $false; Records = @(); Error = $_.Exception.Message }
            }
        } -ArgumentList $StartDate, $EndDate, $Operations, $ResultSize, $CommandName, $PSScriptRoot

        # Wait for job with timeout
        $jobCompleted = $job | Wait-Job -Timeout $timeoutSeconds
        
        if (-not $jobCompleted) {
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -ErrorAction SilentlyContinue
            throw "Unified Audit Log search timed out after ${timeoutSeconds} seconds. The tenant may have too many audit events."
        }

        $jobResult = Receive-Job $job
        Remove-Job $job

        if (-not $jobResult.Success) {
            throw $jobResult.Error
        }

        $records = $jobResult.Records
        Write-Host "  📋 Processing $($records.Count) audit records..." -ForegroundColor DarkGray

        # Process records in batches to reduce memory
        $rows = [System.Collections.Generic.List[object]]::new()
        $batchSize = 100
        $processed = 0

        foreach ($record in $records) {
            $processed++
            if ($processed % $batchSize -eq 0) {
                Write-Host "  📋 Processed $processed/$($records.Count) records..." -ForegroundColor DarkGray
            }

            try {
                $audit = ConvertFrom-InvestigationUnifiedAuditData -AuditData $record.AuditData

                $row = [pscustomobject]@{
                    CreationDate = $record.CreationDate
                    Operation = if ($audit.PSObject.Properties.Name -contains "Operation" -and $audit.Operation) { $audit.Operation } else { $record.Operations }
                    UserId = if ($audit.PSObject.Properties.Name -contains "UserId" -and $audit.UserId) { $audit.UserId } else { $record.UserIds }
                    Workload = if ($audit.PSObject.Properties.Name -contains "Workload") { $audit.Workload } else { $null }
                    ClientInfoString = if ($audit.PSObject.Properties.Name -contains "ClientInfoString") { $audit.ClientInfoString } else { $null }
                    ExternalAccess = if ($audit.PSObject.Properties.Name -contains "ExternalAccess") { $audit.ExternalAccess } else { $null }
                    ItemCount = if ($audit.PSObject.Properties.Name -contains "ItemCount") { $audit.ItemCount } else { $null }
                    ObjectId = $record.ObjectId
                }
                $rows.Add($row)
            } catch {
                # Skip records that can't be parsed
                continue
            }
        }

        # Store limited raw data
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            StartUtc = $StartDate.ToUniversalTime().ToString("o")
            EndUtc = $EndDate.ToUniversalTime().ToString("o")
            Operations = @($Operations)
            RecordCount = $records.Count
            Note = "Raw records excluded to save memory. Use normalized data."
        }

        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            StartUtc = $rawData.StartUtc
            EndUtc = $rawData.EndUtc
            Operations = @($Operations)
            TotalRows = $rows.Count
            Rows = @($rows | Select-Object -First 1000)  # Limit normalized rows
            Note = if ($rows.Count -gt 1000) { "Limited to first 1000 rows. Full count: $($rows.Count)" } else { $null }
        }

        # Clear memory
        $records = $null
        $rows = $null
        [System.GC]::Collect() | Out-Null

        $duration = ([System.DateTime]::Now - $startTime).TotalSeconds

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{ 
                TotalRows = $normalizedData.TotalRows
                ProcessingTimeSeconds = [math]::Round($duration, 2)
            }
    } catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg.Length -gt 200) { $errorMsg = $errorMsg.Substring(0, 200) + "..." }
        
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
            -Metrics @{ TotalRows = 0; ProcessingTimeSeconds = ([System.DateTime]::Now - $startTime).TotalSeconds } `
            -ErrorMessage $errorMsg
    }
}
