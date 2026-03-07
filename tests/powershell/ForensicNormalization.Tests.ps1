BeforeAll {
    $helperPath = Join-Path $PSScriptRoot "../../scripts/lib/forensic-normalization.ps1"
    if (Test-Path $helperPath) {
        . $helperPath
    }
}

Describe "Forensic normalization helpers" {
    It "extracts named modified properties from Graph and UAL records" {
        $properties = ConvertTo-ForensicPropertyMap -Properties @(
            [pscustomobject]@{ DisplayName = "ConsentAction.Permissions"; NewValue = "Mail.ReadWrite Files.ReadWrite.All" },
            [pscustomobject]@{ Name = "RequestType"; Value = "CMSI" }
        )

        $properties."ConsentAction.Permissions" | Should -Be "Mail.ReadWrite Files.ReadWrite.All"
        $properties.RequestType | Should -Be "CMSI"
    }

    It "builds deterministic time bucket keys for spray-style clustering windows" {
        $bucket = Get-ForensicTimeBucketKey -Timestamp ([datetime]"2026-03-06T12:34:05Z") -WindowSeconds 3

        $bucket | Should -Be "2026-03-06T12:34:03.0000000Z"
    }

    It "calculates dormancy days from the last successful sign-in timestamp" {
        $days = Get-ForensicDormancyDays `
            -LastSeen ([datetime]"2026-02-01T00:00:00Z") `
            -ReferenceTime ([datetime]"2026-03-06T00:00:00Z")

        $days | Should -Be 33
    }
}
