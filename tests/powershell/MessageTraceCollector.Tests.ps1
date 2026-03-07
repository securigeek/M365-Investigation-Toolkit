BeforeAll {
    $commonPath = Join-Path $PSScriptRoot "../../scripts/lib/common.ps1"
    $collectorLibPath = Join-Path $PSScriptRoot "../../scripts/lib/collectors.ps1"
    $collectorPath = Join-Path $PSScriptRoot "../../scripts/collectors/Get-TenantMessageTracePivot.ps1"

    if (Test-Path $commonPath) {
        . $commonPath
    }
    if (Test-Path $collectorLibPath) {
        . $collectorLibPath
    }
    if (Test-Path $collectorPath) {
        . $collectorPath
    }
}

Describe "Message trace pivot collector" {
    It "splits long lookbacks into Exchange-compliant query windows" {
        $windows = @(Get-InvestigationMessageTraceWindows -StartDate ([datetime]"2026-03-01T00:00:00Z") -EndDate ([datetime]"2026-03-15T00:00:00Z"))

        $windows.Count | Should -Be 2
        (($windows[0].EndDate) - ($windows[0].StartDate)).TotalDays | Should -BeLessOrEqual 10
        (($windows[1].EndDate) - ($windows[1].StartDate)).TotalDays | Should -BeLessOrEqual 10
    }

    It "uses Get-MessageTraceV2 and succeeds across multiple windows" {
        function Invoke-TestMessageTrace {
            param(
                [Parameter(ValueFromRemainingArguments = $true)]
                $RemainingArguments
            )
        }

        Mock Invoke-TestMessageTrace {
            @(
                [pscustomobject]@{
                    MessageTraceId = [guid]::NewGuid().ToString()
                    Received = [datetime]"2026-03-02T12:00:00Z"
                    SenderAddress = "bad@contoso.com"
                    RecipientAddress = "alice@contoso.com"
                    Subject = "wire"
                    Status = "Delivered"
                    MessageId = [guid]::NewGuid().ToString()
                    FromIP = "1.1.1.1"
                    ToIP = "2.2.2.2"
                    Size = 1234
                }
            )
        }

        $result = Invoke-TenantMessageTracePivotCollector `
            -OutputPath (Join-Path TestDrive: "out") `
            -StartDate ([datetime]"2026-03-01T00:00:00Z") `
            -EndDate ([datetime]"2026-03-15T00:00:00Z") `
            -Pivots @{
                Sender = "bad@contoso.com"
                Domain = $null
                UserPrincipalName = $null
                SubjectContains = $null
            } `
            -CommandName "Invoke-TestMessageTrace"

        $result.Status | Should -Be "success"
        Assert-MockCalled Invoke-TestMessageTrace -Times 2 -Exactly
    }
}
