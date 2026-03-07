BeforeAll {
    $authPath = Join-Path $PSScriptRoot "../../scripts/lib/auth.ps1"
    if (Test-Path $authPath) {
        . $authPath
    }

    foreach ($commandName in @(
        "Connect-ExchangeOnline",
        "Connect-IPPSSession",
        "Connect-MgGraph",
        "Get-MgContext",
        "Get-ConnectionInformation",
        "Get-AcceptedDomain"
    )) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            Set-Item -Path ("Function:$commandName") -Value ([scriptblock]::Create("param()")) | Out-Null
        }
    }
}

Describe "Investigation auth" {
    It "returns the delegated scopes required for self-service collection" {
        $scopes = Get-InvestigationDelegatedScopes

        $scopes | Should -Contain "User.Read"
        $scopes | Should -Contain "AuditLog.Read.All"
        $scopes | Should -Contain "Application.Read.All"
        $scopes | Should -Contain "Directory.Read.All"
        $scopes | Should -Contain "RoleManagement.Read.Directory"
        $scopes | Should -Not -Contain "DelegatedPermissionGrant.Read.All"
    }

    It "rejects a mismatched Graph tenant id" {
        {
            Test-InvestigationTenantMatch `
                -ExpectedTenantId "expected" `
                -GraphTenantId "actual" `
                -AcceptedDomains @("contoso.onmicrosoft.com") `
                -ExpectedDomain "contoso.onmicrosoft.com"
        } | Should -Throw "Graph tenant mismatch*"
    }

    It "rejects a mismatched accepted domain" {
        {
            Test-InvestigationTenantMatch `
                -ExpectedTenantId "expected" `
                -GraphTenantId "expected" `
                -AcceptedDomains @("fabrikam.onmicrosoft.com") `
                -ExpectedDomain "contoso.onmicrosoft.com"
        } | Should -Throw "Exchange accepted-domain mismatch*"
    }

    It "establishes a search-only compliance session during delegated auth" {
        Mock Import-Module {}
        Mock Connect-ExchangeOnline {}
        Mock Connect-IPPSSession {}
        Mock Connect-MgGraph {}
        Mock Get-MgContext {
            [pscustomobject]@{
                TenantId = "11111111-1111-1111-1111-111111111111"
                Scopes = Get-InvestigationDelegatedScopes
                Account = "analyst@contoso.com"
            }
        }
        Mock Get-ConnectionInformation { [pscustomobject]@{ UserPrincipalName = "analyst@contoso.com" } }
        Mock Get-AcceptedDomain { [pscustomobject]@{ DomainName = "contoso.onmicrosoft.com" } }

        $null = Connect-InvestigationTenantDelegated -TenantDomain "contoso.onmicrosoft.com"

        Should -Invoke Connect-IPPSSession -Times 1 -Exactly -Scope It
    }

    It "does not emit disconnect output during cleanup" {
        Mock Disconnect-MgGraph { "graph-output" }
        Mock Disconnect-ExchangeOnline { "exchange-output" }

        $result = Clear-InvestigationConnections

        $result | Should -BeNullOrEmpty
    }
}
