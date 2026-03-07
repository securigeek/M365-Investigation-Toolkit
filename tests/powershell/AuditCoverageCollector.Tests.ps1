BeforeAll {
    . (Join-Path $PSScriptRoot "../../scripts/lib/common.ps1")
    . (Join-Path $PSScriptRoot "../../scripts/lib/collectors.ps1")

    $collectorPath = Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantAuditCoverage.ps1"
    if (Test-Path $collectorPath) {
        . $collectorPath
    }

    function Invoke-TestExchangeAuditConfigDisabled {
        return [pscustomobject]@{
            AdminAuditLogEnabled = $true
            UnifiedAuditLogIngestionEnabled = $false
        }
    }

    function Invoke-TestCustomAuditConfigDisabled {
        return [pscustomobject]@{
            AdminAuditLogEnabled = $true
            UnifiedAuditLogIngestionEnabled = $false
        }
    }

    function New-TestAuditCoverageCommandContext {
        param(
            [Parameter()]
            [bool]$Verified,

            [Parameter()]
            [string]$Name = "Invoke-TestExchangeAuditConfigDisabled",

            [Parameter()]
            [string]$Source = "ExchangeOnlineManagement",

            [Parameter()]
            [string]$ModuleName = "ExchangeOnlineManagement"
        )

        return [pscustomobject]@{
            Verified = $Verified
            Command = if ($Verified) {
                [pscustomobject]@{
                    Name = $Name
                    Source = $Source
                    ModuleName = $ModuleName
                }
            } else {
                $null
            }
            Candidates = @()
            ConnectionCount = 1
        }
    }
}

Describe "Tenant audit coverage collector" {
    It "marks UAL ambiguous when admin audit config does not resolve from Exchange Online context" {
        Mock Invoke-InvestigationUnifiedAuditProbe {}

        $result = Invoke-TenantAuditCoverageCollector `
            -OutputPath $TestDrive `
            -ConfigCommandName "Invoke-TestCustomAuditConfigDisabled" `
            -CommandContext (New-TestAuditCoverageCommandContext -Verified $false -Name "Invoke-TestCustomAuditConfigDisabled" -Source "Contoso.CustomModule" -ModuleName "Contoso.CustomModule")

        $result.Status | Should -Be "partial"
        $result.Data.UnifiedAuditLogVerification.Status | Should -Be "ambiguous"
        $result.Data.CoverageGaps | Should -Contain "Unified audit log status is ambiguous and must be verified from an Exchange Online session."
        $result.Data.Probe.Ran | Should -BeFalse
        $result.Metrics.UnifiedAuditLogVerificationStatus | Should -Be "ambiguous"
        Should -Invoke Invoke-InvestigationUnifiedAuditProbe -Times 0
    }

    It "verifies UAL on when the Exchange probe returns records" {
        Mock Invoke-InvestigationUnifiedAuditProbe {
            return [pscustomobject]@{
                StartDate = [datetime]"2026-03-05T00:00:00Z"
                EndDate = [datetime]"2026-03-06T00:00:00Z"
                ResultSize = 5
                Records = @(
                    [pscustomobject]@{
                        CreationDate = [datetime]"2026-03-06T09:00:00Z"
                    }
                )
            }
        }

        $result = Invoke-TenantAuditCoverageCollector `
            -OutputPath $TestDrive `
            -ConfigCommandName "Invoke-TestExchangeAuditConfigDisabled" `
            -ProbeCommandName "Invoke-TestUalProbeWithRows" `
            -CommandContext (New-TestAuditCoverageCommandContext -Verified $true)

        $result.Status | Should -Be "partial"
        $result.Data.UnifiedAuditLogVerification.Status | Should -Be "verifiedOn"
        $result.Data.CoverageGaps | Should -Not -Contain "Unified audit log ingestion is disabled."
        $result.Data.Probe.Ran | Should -BeTrue
        $result.Data.Probe.ResultCount | Should -Be 1
        $result.Metrics.UnifiedAuditLogVerificationStatus | Should -Be "verifiedOn"
        Should -Invoke Invoke-InvestigationUnifiedAuditProbe -Times 1
    }

    It "keeps UAL ambiguous when Exchange config says off and the probe returns no events" {
        Mock Invoke-InvestigationUnifiedAuditProbe {
            return [pscustomobject]@{
                StartDate = [datetime]"2026-03-05T00:00:00Z"
                EndDate = [datetime]"2026-03-06T00:00:00Z"
                ResultSize = 5
                Records = @()
            }
        }

        $result = Invoke-TenantAuditCoverageCollector `
            -OutputPath $TestDrive `
            -ConfigCommandName "Invoke-TestExchangeAuditConfigDisabled" `
            -ProbeCommandName "Invoke-TestUalProbeEmpty" `
            -CommandContext (New-TestAuditCoverageCommandContext -Verified $true)

        $result.Status | Should -Be "partial"
        $result.Data.UnifiedAuditLogVerification.Status | Should -Be "ambiguous"
        $result.Data.CoverageGaps | Should -Contain "Unified audit log status is ambiguous and must be verified from an Exchange Online session."
        $result.Data.Probe.Ran | Should -BeTrue
        $result.Data.Probe.ResultCount | Should -Be 0
        $result.Metrics.UnifiedAuditLogVerificationStatus | Should -Be "ambiguous"
    }

    It "verifies UAL off when the Exchange probe returns an explicit disabled error" {
        Mock Invoke-InvestigationUnifiedAuditProbe {
            throw "Unified audit log ingestion is disabled for this organization."
        }

        $result = Invoke-TenantAuditCoverageCollector `
            -OutputPath $TestDrive `
            -ConfigCommandName "Invoke-TestExchangeAuditConfigDisabled" `
            -ProbeCommandName "Invoke-TestUalProbeDisabled" `
            -CommandContext (New-TestAuditCoverageCommandContext -Verified $true)

        $result.Status | Should -Be "success"
        $result.Data.UnifiedAuditLogVerification.Status | Should -Be "verifiedOff"
        $result.Data.CoverageGaps | Should -Contain "Unified audit log ingestion is disabled."
        $result.Data.Probe.Ran | Should -BeTrue
        $result.Data.Probe.Succeeded | Should -BeFalse
        $result.Metrics.UnifiedAuditLogVerificationStatus | Should -Be "verifiedOff"
    }
}
