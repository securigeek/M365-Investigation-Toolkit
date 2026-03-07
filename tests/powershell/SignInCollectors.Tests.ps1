BeforeAll {
    . (Join-Path $PSScriptRoot "../../scripts/lib/common.ps1")
    . (Join-Path $PSScriptRoot "../../scripts/lib/collectors.ps1")

    foreach ($collectorPath in @(
        (Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantInteractiveSignins.ps1"),
        (Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantNonInteractiveSignins.ps1"),
        (Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantServicePrincipalSignins.ps1")
    )) {
        if (Test-Path $collectorPath) {
            . $collectorPath
        }
    }

    function Invoke-TestBroadSignins {
        param(
            [Parameter()]
            [string]$Filter,

            [Parameter()]
            [switch]$All
        )

        $script:LastBroadFilter = $Filter

        return @(
            [pscustomobject]@{
                CreatedDateTime = "2026-03-05T10:00:00Z"
                UserPrincipalName = "user@contoso.com"
                AppDisplayName = "Microsoft Graph"
                ClientAppUsed = "Mobile Apps and Desktop clients"
                AuthenticationProtocol = "deviceCode"
                IPAddress = "203.0.113.10"
                IsInteractive = $true
                Status = [pscustomobject]@{
                    ErrorCode = 0
                    FailureReason = $null
                }
            },
            [pscustomobject]@{
                CreatedDateTime = "2026-03-05T11:00:00Z"
                UserPrincipalName = "svc@contoso.com"
                AppDisplayName = "Office 365 Exchange Online"
                ClientAppUsed = "Other clients"
                AuthenticationProtocol = "none"
                IPAddress = "203.0.113.20"
                IsInteractive = $false
                SignInEventTypes = @("nonInteractiveUser")
                Status = [pscustomobject]@{
                    ErrorCode = 50058
                    FailureReason = "Silent token request failed"
                }
            },
            [pscustomobject]@{
                CreatedDateTime = "2026-03-05T12:00:00Z"
                UserPrincipalName = "service@contoso.com"
                AppDisplayName = "Microsoft Teams"
                ClientAppUsed = "Browser"
                AuthenticationProtocol = "none"
                IPAddress = "203.0.113.40"
                SignInEventTypes = @("nonInteractiveUser")
                Status = [pscustomobject]@{
                    ErrorCode = 0
                    FailureReason = $null
                }
            }
        )
    }

    function Invoke-TestServicePrincipalSignins {
        param(
            [Parameter()]
            [string]$Filter,

            [Parameter()]
            [switch]$All
        )

        return @(
            [pscustomobject]@{
                CreatedDateTime = "2026-03-05T12:00:00Z"
                AppDisplayName = "Contoso Automation"
                ServicePrincipalId = "spn-1"
                AppId = "app-1"
                IPAddress = "203.0.113.30"
                ResourceDisplayName = "Microsoft Graph"
                ClientAppUsed = "confidentialClient"
                Status = [pscustomobject]@{
                    ErrorCode = 0
                    FailureReason = $null
                }
            }
        )
    }
}

Describe "Tenant sign-in collectors" {
    It "collects sign-ins broadly and classifies interactive rows locally" {
        $result = Invoke-TenantInteractiveSigninsCollector -OutputPath $TestDrive -SinceIso "2026-03-01T00:00:00Z" -CommandName "Invoke-TestBroadSignins"

        $result.Module | Should -Be "interactiveSignins"
        $result.Status | Should -Be "success"
        $result.Data.TotalRows | Should -Be 1
        $result.Data.Rows[0].AuthenticationProtocol | Should -Be "deviceCode"
        $result.Data.Rows[0].ResultType | Should -Be 0
        $result.Data.Rows[0].ClientApp | Should -Be "Mobile Apps and Desktop clients"
        $script:LastBroadFilter | Should -Be "createdDateTime ge 2026-03-01T00:00:00Z"
    }

    It "collects sign-ins broadly and classifies non-interactive rows locally" {
        $result = Invoke-TenantNonInteractiveSigninsCollector -OutputPath $TestDrive -SinceIso "2026-03-01T00:00:00Z" -CommandName "Invoke-TestBroadSignins"

        $result.Module | Should -Be "nonInteractiveSignins"
        $result.Status | Should -Be "success"
        $result.Data.TotalRows | Should -Be 2
        $result.Data.Rows[0].IsInteractive | Should -BeFalse
        $result.Data.Rows[0].ResultType | Should -Be 50058
        $result.Data.Rows[1].UserPrincipalName | Should -Be "service@contoso.com"
        $script:LastBroadFilter | Should -Be "createdDateTime ge 2026-03-01T00:00:00Z"
    }

    It "normalizes service principal sign-ins into app, principal, and result fields" {
        $result = Invoke-TenantServicePrincipalSigninsCollector -OutputPath $TestDrive -SinceIso "2026-03-01T00:00:00Z" -CommandName "Invoke-TestServicePrincipalSignins"

        $result.Module | Should -Be "servicePrincipalSignins"
        $result.Status | Should -Be "success"
        $result.Data.TotalRows | Should -Be 1
        $result.Data.Rows[0].AppDisplayName | Should -Be "Contoso Automation"
        $result.Data.Rows[0].ServicePrincipalId | Should -Be "spn-1"
        $result.Data.Rows[0].ResultType | Should -Be 0
    }
}
