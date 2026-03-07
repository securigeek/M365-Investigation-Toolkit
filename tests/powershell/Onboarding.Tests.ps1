BeforeAll {
    $onboardingPath = Join-Path $PSScriptRoot "../../scripts/lib/onboarding.ps1"
    if (Test-Path $onboardingPath) {
        . $onboardingPath
    }
}

Describe "Investigation onboarding" {
    It "maps registration summary into a tenant profile with module capability flags" {
        $summary = [pscustomobject]@{
            TenantId = "11111111-1111-1111-1111-111111111111"
            TenantDisplayName = "Contoso"
            AppId = "22222222-2222-2222-2222-222222222222"
            MissingPermissions = @()
        }

        $profile = Convert-AppRegistrationSummaryToTenantProfile -Summary $summary -TenantDomain "contoso.onmicrosoft.com"

        $profile.Modules.mailboxForwarding.Enabled | Should -BeTrue
        $profile.TenantDomain | Should -Be "contoso.onmicrosoft.com"
    }

    It "disables app changes when Application.Read.All is missing" {
        $summary = [pscustomobject]@{
            TenantId = "11111111-1111-1111-1111-111111111111"
            TenantDisplayName = "Contoso"
            AppId = "22222222-2222-2222-2222-222222222222"
            MissingPermissions = @(
                [pscustomobject]@{ Permission = "Application.Read.All" }
            )
        }

        $profile = Convert-AppRegistrationSummaryToTenantProfile -Summary $summary -TenantDomain "contoso.onmicrosoft.com"

        $profile.Modules.appChanges.Enabled | Should -BeFalse
    }
}
