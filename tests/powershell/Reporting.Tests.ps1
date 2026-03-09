BeforeAll {
    $libPath = Join-Path $PSScriptRoot "../../src/lib"
    $reportingPath = Join-Path $libPath "reporting.ps1"
    if (Test-Path $reportingPath) {
        . (Join-Path $libPath "common.ps1")
        . $reportingPath
    }
}

Describe "Investigation reporting" {
    It "flags forwarding and risky sign-ins in the Markdown summary" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "mailboxForwarding"
                Status = "success"
                Data = [pscustomobject]@{
                    ForwardingHits = @([pscustomobject]@{ UserPrincipalName = "a@contoso.com" })
                }
                Metrics = [pscustomobject]@{ ForwardingHitCount = 1 }
                Error = $null
                Warnings = @()
            },
            [pscustomobject]@{
                Module = "riskySignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @([pscustomobject]@{ UserPrincipalName = "a@contoso.com" })
                }
                Metrics = [pscustomobject]@{ TotalRows = 1 }
                Error = $null
                Warnings = @()
            }
        )

        $summary = New-InvestigationMarkdownSummary `
            -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com" }) `
            -CollectorResults $collectorResults

        $summary | Should -Match "forwarding"
        $summary | Should -Match "risky sign-in"
    }

    It "describes zero inbox and transport hits as baseline heuristics not firing" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "inboxRules"
                Status = "success"
                Data = [pscustomobject]@{
                    SuspiciousRules = @()
                }
                Metrics = [pscustomobject]@{}
                Error = $null
                Warnings = @()
            },
            [pscustomobject]@{
                Module = "transportRules"
                Status = "success"
                Data = [pscustomobject]@{
                    SuspiciousRules = @()
                }
                Metrics = [pscustomobject]@{}
                Error = $null
                Warnings = @()
            }
        )

        $summary = New-InvestigationMarkdownSummary `
            -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com" }) `
            -CollectorResults $collectorResults

        $summary | Should -Match "baseline inbox-rule heuristics"
        $summary | Should -Match "baseline transport-rule heuristics"
    }

    It "scores a high triage verdict when multiple severe signals are present" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "mailboxForwarding"
                Status = "success"
                Data = [pscustomobject]@{
                    ForwardingHits = @(
                        [pscustomobject]@{ UserPrincipalName = "a@contoso.com" },
                        [pscustomobject]@{ UserPrincipalName = "b@contoso.com" }
                    )
                }
                Metrics = [pscustomobject]@{ ForwardingHitCount = 2 }
                Error = $null
                Warnings = @()
            },
            [pscustomobject]@{
                Module = "riskySignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{ UserPrincipalName = "a@contoso.com" },
                        [pscustomobject]@{ UserPrincipalName = "b@contoso.com" }
                    )
                }
                Metrics = [pscustomobject]@{ TotalRows = 2 }
                Error = $null
                Warnings = @()
            },
            [pscustomobject]@{
                Module = "roleAssignments"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @([pscustomobject]@{ PrincipalDisplayName = "Global Admin" })
                }
                Metrics = [pscustomobject]@{ TotalRows = 1 }
                Error = $null
                Warnings = @()
            }
        )

        $verdict = New-InvestigationVerdict `
            -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com" }) `
            -CollectorResults $collectorResults

        $verdict.Severity | Should -Be "High"
        @($verdict.TopFindings).Count | Should -BeGreaterThan 0
    }

    It "writes a verdict artifact alongside the summary bundle" {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("investigation-reporting-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

        try {
            $bundle = Write-InvestigationReportBundle `
                -OutputPath $tempRoot `
                -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com" }) `
                -CollectorResults @()

            (Test-Path (Join-Path $tempRoot "verdict.json")) | Should -BeTrue
            $bundle.PSObject.Properties.Name | Should -Contain "VerdictJsonPath"
        } finally {
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "writes detection and confidence artifacts alongside the summary bundle" {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("investigation-reporting-detections-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

        try {
            $bundle = Write-InvestigationReportBundle `
                -OutputPath $tempRoot `
                -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com" }) `
                -CollectorResults @() `
                -Detections @(
                    [pscustomobject]@{
                        Name = "deviceCodePhishing"
                        Severity = "High"
                        Confidence = "Medium"
                        Summary = "Device code sign-in correlated with CMSI evidence."
                        EvidenceSources = @("interactiveSignins", "unifiedAuditLog")
                        Entities = @("user@contoso.com")
                        NextSteps = @("Review follow-on Graph activity.")
                    }
                )

            (Test-Path (Join-Path $tempRoot "detections.json")) | Should -BeTrue
            (Test-Path (Join-Path $tempRoot "confidence-assessment.json")) | Should -BeTrue
            $bundle.PSObject.Properties.Name | Should -Contain "DetectionsJsonPath"
            $bundle.PSObject.Properties.Name | Should -Contain "ConfidenceJsonPath"
        } finally {
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "records evidence-limit notes when the lookback window is shorter than detector requirements" {
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("investigation-reporting-confidence-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

        try {
            $null = Write-InvestigationReportBundle `
                -OutputPath $tempRoot `
                -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com"; DaysBack = 14 }) `
                -CollectorResults @()

            $confidence = Get-Content -Path (Join-Path $tempRoot "confidence-assessment.json") -Raw | ConvertFrom-Json

            @($confidence.EvidenceLimitations).Count | Should -Be 1
            @($confidence.EvidenceLimitations)[0] | Should -Match "30 days"
        } finally {
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "does not throw when skipped pivot modules omit success-only properties" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "messageTracePivot"
                Status = "skipped"
                Data = [pscustomobject]@{ Reason = "no-pivot-input" }
                Metrics = [pscustomobject]@{}
                Error = $null
                Warnings = @("no-pivot-input")
            },
            [pscustomobject]@{
                Module = "quarantinePivot"
                Status = "skipped"
                Data = [pscustomobject]@{ Reason = "no-pivot-input" }
                Metrics = [pscustomobject]@{}
                Error = $null
                Warnings = @("no-pivot-input")
            }
        )

        {
            New-InvestigationSummaryObject `
                -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com" }) `
                -CollectorResults $collectorResults
        } | Should -Not -Throw
    }

    It "builds a readable terminal summary with coverage and skipped modules" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "riskySignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @([pscustomobject]@{ UserPrincipalName = "a@contoso.com" })
                }
                Metrics = [pscustomobject]@{ TotalRows = 1 }
                Error = $null
                Warnings = @()
            },
            [pscustomobject]@{
                Module = "messageTracePivot"
                Status = "skipped"
                Data = [pscustomobject]@{ Reason = "no-pivot-input" }
                Metrics = [pscustomobject]@{}
                Error = $null
                Warnings = @("no-pivot-input")
            }
        )

        $output = Write-InvestigationTerminalSummary `
            -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com"; CaseName = "sg-check"; DaysBack = 14 }) `
            -CollectorResults $collectorResults `
            -OutputPath "/tmp/example" 6>&1

        $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
        $text | Should -Match "SECURITY INVESTIGATION"
        $text | Should -Match "SKIPPED MODULES"
        $text | Should -Match "no pivot input"
        $text | Should -Match "COVERAGE"
    }

    It "prints top forensic detections when detections are present" {
        $output = Write-InvestigationTerminalSummary `
            -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com"; CaseName = "forensic-check"; DaysBack = 14 }) `
            -CollectorResults @() `
            -Detections @(
                [pscustomobject]@{
                    Name = "deviceCodePhishing"
                    Severity = "High"
                    Confidence = "High"
                    Summary = "Device code sign-in aligns with CMSI evidence."
                }
            ) `
            -OutputPath "/tmp/example" 6>&1

        $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
        $text | Should -Match "DETECTIONS"
        $text | Should -Match "deviceCodePhishing"
        $text | Should -Match "CONFIDENCE"
    }

    It "prints evidence-limit notes in the terminal summary" {
        $output = Write-InvestigationTerminalSummary `
            -Manifest ([pscustomobject]@{ TenantDomain = "contoso.onmicrosoft.com"; CaseName = "short-lookback"; DaysBack = 14 }) `
            -CollectorResults @() `
            -OutputPath "/tmp/example" 6>&1

        $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
        $text | Should -Match "CONFIDENCE"
        $text | Should -Match "Dormant"
    }
}

