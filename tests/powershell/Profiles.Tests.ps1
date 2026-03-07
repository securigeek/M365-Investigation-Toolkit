BeforeAll {
    $commonPath = Join-Path $PSScriptRoot "../../scripts/lib/common.ps1"
    $profilesPath = Join-Path $PSScriptRoot "../../scripts/lib/profiles.ps1"

    if (Test-Path $commonPath) {
        . $commonPath
    }
    if (Test-Path $profilesPath) {
        . $profilesPath
    }
}

Describe "Investigation tenant profiles" {
    It "saves and reloads a tenant profile by tenant id" {
        $root = Join-Path TestDrive: "profiles"

        Initialize-InvestigationProfileStore -RootPath $root | Out-Null

        $profile = [pscustomobject]@{
            CustomerName = "Contoso"
            TenantId = "11111111-1111-1111-1111-111111111111"
            TenantDomain = "contoso.onmicrosoft.com"
            AppId = "22222222-2222-2222-2222-222222222222"
        }

        Save-InvestigationTenantProfile -RootPath $root -Profile $profile | Out-Null
        $loaded = Get-InvestigationTenantProfile -RootPath $root -TenantId $profile.TenantId

        $loaded.TenantDomain | Should -Be "contoso.onmicrosoft.com"
    }
}
