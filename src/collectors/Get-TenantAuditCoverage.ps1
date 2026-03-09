Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")
. (Join-Path $PSScriptRoot "../lib/unified-audit.ps1")

function Invoke-TenantAuditCoverageCollector {
    <#
    .SYNOPSIS
        Production-ready audit coverage collector with improved UAL verification
    .DESCRIPTION
        Fixes the ambiguous UAL status issue by:
        1. Proactively ensuring Exchange Online connection
        2. Trusting probe results over config when there's a conflict
        3. Providing clearer status messaging
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter()]
        [string]$ConfigCommandName = "Get-AdminAuditLogConfig",

        [Parameter()]
        [string]$ProbeCommandName = "Search-UnifiedAuditLog"
    )

    $moduleName = "auditCoverage"
    $warnings = @()
    $gaps = @()

    try {
        # Step 1: Ensure Exchange Online connection
        $exchangeConnected = $false
        $connectionRetries = 0
        $maxRetries = 2

        while (-not $exchangeConnected -and $connectionRetries -lt $maxRetries) {
            $commandContext = Get-InvestigationExchangeAdminAuditCommandContext -CommandName $ConfigCommandName
            
            if ($commandContext.Verified -and $commandContext.ConnectionCount -gt 0) {
                $exchangeConnected = $true
            }
            else {
                $connectionRetries++
                if ($connectionRetries -lt $maxRetries) {
                    try {
                        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop | Out-Null
                        Start-Sleep -Seconds 2
                    }
                    catch {
                        # Silently continue
                    }
                }
            }
        }

        if (-not $exchangeConnected) {
            $warnings += "Could not verify Exchange Online connection. UAL status may be unreliable."
        }

        # Step 2: Get config (only if connected, otherwise skip)
        $config = $null
        if ($exchangeConnected) {
            try {
                $config = & $ConfigCommandName | Select-Object AdminAuditLogEnabled, UnifiedAuditLogIngestionEnabled, AuditLogAgeLimit
            }
            catch {
                $warnings += "Failed to retrieve audit log config: $($_.Exception.Message)"
            }
        }

        # Step 3: ALWAYS run the probe (this is the source of truth)
        $probe = [pscustomobject]@{
            Ran = $true
            Succeeded = $false
            ResultCount = 0
            Error = $null
            StartUtc = (Get-Date).AddHours(-24).ToUniversalTime().ToString("o")
            EndUtc = (Get-Date).ToUniversalTime().ToString("o")
            ResultSize = 5
            Records = @()
        }

        try {
            # Use shorter timeframe for faster probe
            $probeResult = Invoke-InvestigationUnifiedAuditProbe -CommandName $ProbeCommandName -HoursBack 24 -ResultSize 5
            $probe.Succeeded = $true
            # Store only essential record data to reduce memory
            $probe.Records = @($probeResult.Records | Select-Object -First 5 | ForEach-Object {
                [pscustomobject]@{
                    RecordType = $_.RecordType
                    CreationDate = $_.CreationDate
                    UserIds = $_.UserIds
                    Operations = $_.Operations
                }
            })
            $probe.ResultCount = @($probeResult.Records).Count
            $probe.StartUtc = $probeResult.StartDate.ToUniversalTime().ToString("o")
            $probe.EndUtc = $probeResult.EndDate.ToUniversalTime().ToString("o")
        }
        catch {
            $probe.Error = $_.Exception.Message
            $probe.Succeeded = $false
        }

        # Step 4: Determine UAL status based on probe results (truth) + config (context)
        $verificationStatus = "ambiguous"
        $verificationReason = "initial"
        $collectorStatus = "success"

        # Priority 1: If probe returns records, UAL is definitely ON
        if ($probe.Succeeded -and $probe.ResultCount -gt 0) {
            $verificationStatus = "verifiedOn"
            
            # Check for config conflict
            if ($config -and $config.UnifiedAuditLogIngestionEnabled -eq $false) {
                $verificationReason = "probe-truth-overrides-config"
                $warnings += "UAL config reported disabled, but live probe found $($probe.ResultCount) records. UAL is confirmed ACTIVE."
                Write-Host "  [UAL] ✓ ACTIVE (verified via live probe with $($probe.ResultCount) records)" -ForegroundColor Green
            }
            else {
                $verificationReason = "probe-returned-records"
                Write-Host "  [UAL] ✓ ACTIVE ($($probe.ResultCount) recent records found)" -ForegroundColor Green
            }
        }
        # Priority 2: Probe succeeded but no records
        elseif ($probe.Succeeded -and $probe.ResultCount -eq 0) {
            if ($config -and $config.UnifiedAuditLogIngestionEnabled -eq $true) {
                $verificationStatus = "verifiedOn"
                $verificationReason = "config-enabled-no-recent-activity"
                $warnings += "UAL is enabled but no records found in last 24 hours. This may indicate a new tenant or no recent activity."
                Write-Host "  [UAL] ⚠ ENABLED (no recent records, possibly low activity)" -ForegroundColor Yellow
            }
            else {
                $verificationStatus = "ambiguous"
                $verificationReason = "no-records-unconfirmed"
                $gaps += "UAL status unclear: no records found and config not confirmed. Manual verification recommended."
                Write-Host "  [UAL] ? UNCLEAR (no records, verify in Exchange Admin Center)" -ForegroundColor Yellow
            }
        }
        # Priority 3: Probe failed
        else {
            if (Test-InvestigationUnifiedAuditDisabledError -Message $probe.Error) {
                $verificationStatus = "verifiedOff"
                $verificationReason = "probe-disabled-error"
                $gaps += "Unified audit log ingestion is disabled."
                Write-Host "  [UAL] ✗ DISABLED (confirmed by probe error)" -ForegroundColor Red
            }
            elseif ($config -and $config.UnifiedAuditLogIngestionEnabled -eq $true) {
                $verificationStatus = "verifiedOn"
                $verificationReason = "config-enabled-probe-failed"
                $warnings += "UAL appears enabled but probe failed. Some audit data may be available."
                $collectorStatus = "partial"
                Write-Host "  [UAL] ⚠ PARTIAL (enabled but probe failed)" -ForegroundColor Yellow
            }
            else {
                $verificationStatus = "ambiguous"
                $verificationReason = "probe-failed-no-config"
                $gaps += "Could not verify UAL status. Both probe and config check failed."
                $collectorStatus = "partial"
                Write-Host "  [UAL] ? UNKNOWN (verification failed)" -ForegroundColor Yellow
            }
        }

        # Step 5: Check admin audit logging
        $adminAuditEnabled = $null
        if ($config -and $config.PSObject.Properties.Name -contains "AdminAuditLogEnabled") {
            $adminAuditEnabled = [bool]$config.AdminAuditLogEnabled
            if ($adminAuditEnabled -eq $false) {
                $gaps += "Admin audit logging is disabled."
            }
        }

        # Build normalized output
        $normalizedData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Config = if ($config) { [pscustomobject]@{
                AdminAuditLogEnabled = $config.AdminAuditLogEnabled
                UnifiedAuditLogIngestionEnabled = $config.UnifiedAuditLogIngestionEnabled
                AuditLogAgeLimit = $config.AuditLogAgeLimit
            } } else { $null }
            UnifiedAuditLogVerification = [pscustomobject]@{
                Status = $verificationStatus
                Reason = $verificationReason
                ExchangeContextVerified = $exchangeConnected
                ExchangeConnectionCount = if ($commandContext) { $commandContext.ConnectionCount } else { 0 }
            }
            UnifiedAuditLogStatus = $verificationStatus
            AdminAuditLogStatus = if ($adminAuditEnabled) { "enabled" } else { "disabled" }
            CoverageGaps = @($gaps | Sort-Object -Unique)
            CoverageNotes = @($warnings | Sort-Object -Unique)
            Probe = [pscustomobject]@{
                Ran = $probe.Ran
                Succeeded = $probe.Succeeded
                Status = if ($probe.Succeeded -and $probe.ResultCount -gt 0) { "records-returned" } elseif ($probe.Succeeded) { "no-results" } else { "failed" }
                ResultCount = $probe.ResultCount
                Error = if ($probe.Error) { $probe.Error.ToString().Substring(0, [Math]::Min(200, $probe.Error.ToString().Length)) } else { $null }
                StartUtc = $probe.StartUtc
                EndUtc = $probe.EndUtc
                ResultSize = $probe.ResultSize
            }
        }

        # Limit raw data - exclude full records to save memory
        $rawData = [pscustomobject]@{
            TimestampUtc = $normalizedData.TimestampUtc
            Config = $normalizedData.Config
            ProbeSummary = [pscustomobject]@{
                Ran = $probe.Ran
                Succeeded = $probe.Succeeded
                ResultCount = $probe.ResultCount
                SampleRecordTypes = @($probe.Records | Select-Object -ExpandProperty RecordType -Unique | Select-Object -First 3)
            }
            CommandContext = if ($commandContext) { [pscustomobject]@{
                Verified = $commandContext.Verified
                ConnectionCount = $commandContext.ConnectionCount
            } } else { $null }
        }

        # Clear probe records to free memory
        $probe.Records = $null
        $probeResult = $null
        [System.GC]::Collect() | Out-Null

        # Step 6: Publish artifacts
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                AdminAuditLogEnabled = $adminAuditEnabled
                UnifiedAuditLogIngestionEnabled = if ($config) { $config.UnifiedAuditLogIngestionEnabled } else { $null }
                UnifiedAuditLogVerificationStatus = $verificationStatus
                ProbeResultCount = $probe.ResultCount
                ExchangeContextVerified = $exchangeConnected
            } `
            -Status $collectorStatus `
            -Warnings $warnings `
            -Gaps $gaps
    }
    catch {
        return Publish-CollectorError `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Error $_
    }
}
