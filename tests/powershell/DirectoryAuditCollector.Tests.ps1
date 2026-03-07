BeforeAll {
    . (Join-Path $PSScriptRoot "../../scripts/lib/common.ps1")
    . (Join-Path $PSScriptRoot "../../scripts/lib/collectors.ps1")

    $collectorPath = Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantDirectoryAuditLog.ps1"
    if (Test-Path $collectorPath) {
        . $collectorPath
    }

    function Invoke-TestDirectoryAudit {
        param(
            [Parameter()]
            [string]$Filter,

            [Parameter()]
            [switch]$All
        )

        return @(
            [pscustomobject]@{
                ActivityDateTime = "2026-03-05T09:15:00Z"
                ActivityDisplayName = "Consent to application"
                Category = "ApplicationManagement"
                LoggedByService = "Core Directory"
                Result = "success"
                InitiatedBy = [pscustomobject]@{
                    User = [pscustomobject]@{
                        UserPrincipalName = "analyst@contoso.com"
                        Id = "11111111-1111-1111-1111-111111111111"
                    }
                }
                TargetResources = @(
                    [pscustomobject]@{
                        DisplayName = "Suspicious App"
                        Id = "app-1"
                        Type = "ServicePrincipal"
                        ModifiedProperties = @(
                            [pscustomobject]@{
                                DisplayName = "ConsentAction.Permissions"
                                NewValue = "Mail.ReadWrite Files.ReadWrite.All"
                            }
                        )
                    }
                )
            }
        )
    }
}

Describe "Tenant directory audit collector" {
    It "normalizes directory audit records into actor, operation, target, and modified properties" {
        $result = Invoke-TenantDirectoryAuditLogCollector -OutputPath $TestDrive -SinceIso "2026-03-01T00:00:00Z" -CommandName "Invoke-TestDirectoryAudit"

        $result.Module | Should -Be "directoryAuditLog"
        $result.Status | Should -Be "success"
        $result.Data.TotalRows | Should -Be 1
        $result.Data.Rows[0].Operation | Should -Be "Consent to application"
        $result.Data.Rows[0].Actor | Should -Be "analyst@contoso.com"
        $result.Data.Rows[0].Target | Should -Be "Suspicious App"
        $result.Data.Rows[0].ModifiedProperties."ConsentAction.Permissions" | Should -Be "Mail.ReadWrite Files.ReadWrite.All"
    }
}
