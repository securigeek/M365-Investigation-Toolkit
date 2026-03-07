BeforeAll {
    $collectorLibPath = Join-Path $PSScriptRoot "../../scripts/lib/collectors.ps1"
    if (Test-Path $collectorLibPath) {
        . $collectorLibPath
    }
}

Describe "Investigation collectors" {
    It "returns a normalized collector envelope" {
        $result = New-CollectorResult `
            -ModuleName "mailboxForwarding" `
            -Status "success" `
            -RawPath "raw/test.json" `
            -NormalizedPath "normalized/test.json" `
            -Data @()

        $result.Module | Should -Be "mailboxForwarding"
        $result.Status | Should -Be "success"
        $result.RawPath | Should -Be "raw/test.json"
        $result.NormalizedPath | Should -Be "normalized/test.json"
    }

    It "does not emit null warning placeholders when warnings are omitted" {
        $result = New-CollectorResult `
            -ModuleName "mailboxForwarding" `
            -Status "success" `
            -RawPath "raw/test.json" `
            -NormalizedPath "normalized/test.json"

        @($result.Warnings).Count | Should -Be 0
    }
}
