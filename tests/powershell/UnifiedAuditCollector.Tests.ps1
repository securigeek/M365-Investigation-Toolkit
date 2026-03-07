BeforeAll {
    . (Join-Path $PSScriptRoot "../../scripts/lib/common.ps1")
    . (Join-Path $PSScriptRoot "../../scripts/lib/collectors.ps1")

    $helperPath = Join-Path $PSScriptRoot "../../scripts/lib/unified-audit.ps1"
    if (Test-Path $helperPath) {
        . $helperPath
    }

    $collectorPath = Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantUnifiedAuditLog.ps1"
    if (Test-Path $collectorPath) {
        . $collectorPath
    }

    $script:UnifiedAuditPageCallCount = 0

    function Search-UnifiedAuditLog {
        param(
            [Parameter()]
            [datetime]$StartDate,

            [Parameter()]
            [datetime]$EndDate,

            [Parameter()]
            [string[]]$Operations,

            [Parameter()]
            [string]$SessionId,

            [Parameter()]
            [string]$SessionCommand,

            [Parameter()]
            [int]$ResultSize
        )

        $script:UnifiedAuditPageCallCount++

        if ($script:UnifiedAuditPageCallCount -eq 1) {
            return @(
                [pscustomobject]@{
                    CreationDate = [datetime]"2026-03-05T09:00:00Z"
                    UserIds = "user@contoso.com"
                    Operations = "UserLoggedIn"
                    ObjectId = "user@contoso.com"
                    AuditData = '{"Operation":"UserLoggedIn","UserId":"user@contoso.com","Workload":"AzureActiveDirectory","ClientInfoString":"Browser","ExtendedProperties":[{"Name":"RequestType","Value":"CMSI"}],"ModifiedProperties":[]}'
                },
                [pscustomobject]@{
                    CreationDate = [datetime]"2026-03-05T09:05:00Z"
                    UserIds = "user@contoso.com"
                    Operations = "MailItemsAccessed"
                    ObjectId = "mailbox-1"
                    AuditData = '{"Operation":"MailItemsAccessed","UserId":"user@contoso.com","Workload":"Exchange","ClientInfoString":"REST","ItemCount":42,"ExtendedProperties":[],"ModifiedProperties":[]}'
                }
            )
        }

        if ($script:UnifiedAuditPageCallCount -eq 2) {
            return @(
                [pscustomobject]@{
                    CreationDate = [datetime]"2026-03-05T09:10:00Z"
                    UserIds = "user@contoso.com"
                    Operations = "SearchQueryInitiated"
                    ObjectId = "search-1"
                    AuditData = '{"Operation":"SearchQueryInitiated","UserId":"user@contoso.com","Workload":"SecurityComplianceCenter","ClientInfoString":"ComplianceCenter","ExtendedProperties":[],"ModifiedProperties":[{"Name":"Query","NewValue":"invoice"}]}'
                }
            )
        }

        return @()
    }
}

Describe "Tenant unified audit collector" {
    BeforeEach {
        $script:UnifiedAuditPageCallCount = 0
    }

    It "merges paged Search-UnifiedAuditLog results into a normalized collector result" {
        $result = Invoke-TenantUnifiedAuditLogCollector `
            -OutputPath $TestDrive `
            -StartDate ([datetime]"2026-03-01T00:00:00Z") `
            -EndDate ([datetime]"2026-03-06T00:00:00Z") `
            -Operations @("UserLoggedIn", "MailItemsAccessed", "SearchQueryInitiated") `
            -ResultSize 2 `
            -CommandName "Search-UnifiedAuditLog"

        $result.Module | Should -Be "unifiedAuditLog"
        $result.Status | Should -Be "success"
        $result.Data.TotalRows | Should -Be 3
        $result.Data.Rows[0].Operation | Should -Be "UserLoggedIn"
        $result.Data.Rows[0].ExtendedProperties.RequestType | Should -Be "CMSI"
        $result.Data.Rows[1].ClientInfoString | Should -Be "REST"
        $result.Data.Rows[2].ModifiedProperties.Query | Should -Be "invoice"
    }
}
