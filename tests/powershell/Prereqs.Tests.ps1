BeforeAll {
    $prereqPath = Join-Path $PSScriptRoot "../../scripts/lib/prereqs.ps1"
    if (Test-Path $prereqPath) {
        . $prereqPath
    }
}

Describe "Investigation prerequisites" {
    It "detects missing and outdated modules" {
        $requirements = @(
            [pscustomobject]@{ Name = "Microsoft.Graph.Authentication"; MinimumVersion = [version]"2.35.1" },
            [pscustomobject]@{ Name = "ExchangeOnlineManagement"; MinimumVersion = [version]"3.9.2" }
        )

        $installed = @(
            [pscustomobject]@{ Name = "Microsoft.Graph.Authentication"; Version = [version]"2.28.0" }
        )

        $result = Test-InvestigationPrerequisites `
            -CurrentPwshVersion ([version]"7.5.4") `
            -RequiredModules $requirements `
            -InstalledModules $installed `
            -BrowserCapability ([pscustomobject]@{ Supported = $true; Method = "open" })

        $result.Ready | Should -BeFalse
        @($result.MissingModules).Count | Should -Be 1
        @($result.OutdatedModules).Count | Should -Be 1
    }

    It "accepts a supported PowerShell and browser environment" {
        $requirements = @(
            [pscustomobject]@{ Name = "Microsoft.Graph.Authentication"; MinimumVersion = [version]"2.35.1" }
        )

        $installed = @(
            [pscustomobject]@{ Name = "Microsoft.Graph.Authentication"; Version = [version]"2.35.1" }
        )

        $result = Test-InvestigationPrerequisites `
            -CurrentPwshVersion ([version]"7.5.4") `
            -RequiredModules $requirements `
            -InstalledModules $installed `
            -BrowserCapability ([pscustomobject]@{ Supported = $true; Method = "open" })

        $result.Ready | Should -BeTrue
        $result.Browser.Supported | Should -BeTrue
    }
}
