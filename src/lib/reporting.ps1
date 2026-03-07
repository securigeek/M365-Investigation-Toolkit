Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "common.ps1")

function Get-CollectorResultByModule {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    return $CollectorResults | Where-Object { $_.Module -eq $ModuleName } | Select-Object -First 1
}

function New-InvestigationFindingRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Summary,

        [Parameter(Mandatory = $true)]
        [int]$Weight,

        [Parameter(Mandatory = $true)]
        [string]$Module
    )

    return [pscustomobject]@{
        Summary = $Summary
        Weight = $Weight
        Module = $Module
    }
}

function Resolve-InvestigationSkipReasonLabel {
    param(
        [Parameter()]
        [string]$Reason
    )

    switch ($Reason) {
        "no-pivot-input" { return "no pivot input supplied" }
        "unavailable-command-or-api" { return "required command or API unavailable in this session" }
        "module-disabled-in-profile" { return "module disabled in legacy profile" }
        "ual-verified-off" { return "unified audit log is verified disabled; skipped large audit search" }
        "ual-status-ambiguous" { return "unified audit log status is ambiguous; verify in Exchange Online PowerShell before running large audit searches" }
        default { return $(if ([string]::IsNullOrWhiteSpace($Reason)) { "not specified" } else { $Reason }) }
    }
}

function Get-InvestigationSkipGuidance {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $guidance = @()
    $pivotSkipped = @(
        $CollectorResults |
            Where-Object { $_.Module -in @("messageTracePivot", "quarantinePivot") -and $_.Status -eq "skipped" -and (Resolve-InvestigationSkipReasonLabel -Reason (@($_.Warnings | Select-Object -First 1)[0])) -eq "no pivot input supplied" }
    )
    if ($pivotSkipped.Count -gt 0) {
        $guidance += "Rerun with one of: -Sender, -Domain, -UserPrincipalName, or -SubjectContains to enable message trace and quarantine pivots."
    }

    return @($guidance | Sort-Object -Unique)
}

function Get-InvestigationCoverageSummary {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $statusGroups = @{
        success = 0
        partial = 0
        skipped = 0
        failed = 0
    }

    foreach ($result in @($CollectorResults)) {
        if ($statusGroups.ContainsKey($result.Status)) {
            $statusGroups[$result.Status]++
        }
    }

    return [pscustomobject]@{
        Collected = $statusGroups.success + $statusGroups.partial
        Partial = $statusGroups.partial
        Skipped = $statusGroups.skipped
        Failed = $statusGroups.failed
        Total = @($CollectorResults).Count
    }
}

function Get-InvestigationTopFindingRecords {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Assessment
    )

    return @(
        $Assessment.FindingRecords |
            Sort-Object Weight -Descending |
            Select-Object -First 4
    )
}

function Resolve-InvestigationFindingPriorityLabel {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Weight
    )

    if ($Weight -ge 30) {
        return "HIGH"
    }
    if ($Weight -ge 15) {
        return "MED "
    }

    return "LOW "
}

function Format-InvestigationConsoleValue {
    param(
        [Parameter()]
        [string]$Value,

        [Parameter()]
        [int]$Width = 39
    )

    $resolved = if ($null -eq $Value) { "" } else { [string]$Value }
    if ($resolved.Length -le $Width) {
        return $resolved.PadRight($Width)
    }

    if ($Width -le 3) {
        return $resolved.Substring(0, $Width)
    }

    return ($resolved.Substring(0, $Width - 3) + "...").PadRight($Width)
}

function New-InvestigationSkippedModuleLines {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    return @(
        $CollectorResults |
            Where-Object { $_.Status -eq "skipped" } |
            ForEach-Object {
                $reason = Resolve-InvestigationSkipReasonLabel -Reason (@($_.Warnings | Select-Object -First 1)[0])
                "[SKIP] $($_.Module): $reason"
            }
    )
}

function Get-InvestigationCollectorDataProperty {
    param(
        [Parameter()]
        [psobject]$CollectorResult,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName,

        [Parameter()]
        [object]$DefaultValue = $null
    )

    if (-not $CollectorResult) {
        return $DefaultValue
    }
    if ($CollectorResult.PSObject.Properties.Name -notcontains "Data") {
        return $DefaultValue
    }
    if ($null -eq $CollectorResult.Data) {
        return $DefaultValue
    }
    if ($CollectorResult.Data.PSObject.Properties.Name -notcontains $PropertyName) {
        return $DefaultValue
    }

    return $CollectorResult.Data.$PropertyName
}

function Get-InvestigationEvidenceLimitations {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest
    )

    $limitations = @()

    if ($Manifest.PSObject.Properties.Name -contains "DaysBack" -and $Manifest.DaysBack -is [int] -and $Manifest.DaysBack -lt 30) {
        $limitations += "Dormant-account MFA takeover can only be fully evaluated with at least 30 days of sign-in history; current lookback is $($Manifest.DaysBack) days."
    }

    return @($limitations)
}

function Get-InvestigationAssessment {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $suspiciousFindings = @()
    $benignFindings = @()
    $collectionGaps = @()
    $nextSteps = @()
    $findingRecords = @()

    foreach ($result in @($CollectorResults)) {
        switch ($result.Status) {
            "failed" { $collectionGaps += "Failed to collect $($result.Module): $($result.Error)" }
            "skipped" { $collectionGaps += "Skipped $($result.Module): $(Resolve-InvestigationSkipReasonLabel -Reason (@($result.Warnings | Select-Object -First 1)[0]))" }
            "partial" {
                if (@($result.Warnings).Count -gt 0) {
                    $readableWarnings = @(
                        $result.Warnings |
                            ForEach-Object { Resolve-InvestigationSkipReasonLabel -Reason $_ }
                    )
                    $collectionGaps += "Partially collected $($result.Module): $($readableWarnings -join '; ')"
                }
            }
        }
    }

    $mailboxForwarding = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "mailboxForwarding"
    if ($mailboxForwarding) {
        $forwardingHitCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $mailboxForwarding -PropertyName "ForwardingHits" -DefaultValue @())).Count
        if ($forwardingHitCount -gt 0) {
            $summary = "$forwardingHitCount mailbox forwarding configuration(s) detected."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 45 -Module "mailboxForwarding"
            $nextSteps += "Review forwarding targets and confirm whether they are approved business routes."
        } else {
            $benignFindings += "No mailbox forwarding was detected."
        }
    }

    $inboxRules = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "inboxRules"
    if ($inboxRules) {
        $suspiciousRuleCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $inboxRules -PropertyName "SuspiciousRules" -DefaultValue @())).Count
        if ($suspiciousRuleCount -gt 0) {
            $summary = "$suspiciousRuleCount inbox rule(s) perform forwarding, redirection, or deletion actions."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 30 -Module "inboxRules"
            $nextSteps += "Review suspicious inbox rules per mailbox and validate whether any were recently introduced."
        } else {
            $benignFindings += "No baseline inbox-rule heuristics fired in the collected set."
        }
    }

    $transportRules = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "transportRules"
    if ($transportRules) {
        $suspiciousTransportRuleCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $transportRules -PropertyName "SuspiciousRules" -DefaultValue @())).Count
        if ($suspiciousTransportRuleCount -gt 0) {
            $summary = "$suspiciousTransportRuleCount transport rule(s) perform redirect, blind copy, or delete actions."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 25 -Module "transportRules"
            $nextSteps += "Validate transport rule intent and compare with approved mail flow changes."
        } else {
            $benignFindings += "No baseline transport-rule heuristics fired in the collected set."
        }
    }

    $connectors = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "connectors"
    if ($connectors) {
        $connectorAnomalyCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $connectors -PropertyName "Anomalies" -DefaultValue @())).Count
        if ($connectorAnomalyCount -gt 0) {
            $summary = "$connectorAnomalyCount connector configuration anomaly/anomalies detected."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 15 -Module "connectors"
            $nextSteps += "Review inbound and outbound connector changes for unauthorized relaying or trust changes."
        } else {
            $benignFindings += "No connector anomalies were flagged by the baseline rules."
        }
    }

    $riskySignins = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "riskySignins"
    if ($riskySignins) {
        $riskySigninCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $riskySignins -PropertyName "Rows" -DefaultValue @())).Count
        if ($riskySigninCount -gt 0) {
            $summary = "$riskySigninCount risky sign-in record(s) found in the lookback."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 35 -Module "riskySignins"
            $nextSteps += "Pivot into the risky sign-in rows for IP, app, and user triage."
        } else {
            $benignFindings += "No risky sign-ins were returned for the lookback."
        }
    }

    $appChanges = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "appChanges"
    if ($appChanges) {
        $changeCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $appChanges -PropertyName "Applications" -DefaultValue @())).Count + @((Get-InvestigationCollectorDataProperty -CollectorResult $appChanges -PropertyName "ServicePrincipals" -DefaultValue @())).Count
        if ($changeCount -gt 0) {
            $summary = "$changeCount recent application or service principal object(s) were created."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 15 -Module "appChanges"
            $nextSteps += "Review newly created app objects for ownership, consent path, and expected use."
        } else {
            $benignFindings += "No recent application or service principal creations were found."
        }
    }

    $auditCoverage = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "auditCoverage"
    if ($auditCoverage) {
        $coverageGaps = @((Get-InvestigationCollectorDataProperty -CollectorResult $auditCoverage -PropertyName "CoverageGaps" -DefaultValue @()))
        if ($coverageGaps.Count -gt 0) {
            foreach ($gap in $coverageGaps) {
                $suspiciousFindings += $gap
                $findingRecords += New-InvestigationFindingRecord -Summary $gap -Weight 25 -Module "auditCoverage"
            }
            $nextSteps += "Restore audit coverage before drawing strong conclusions from this triage run."
        } else {
            $benignFindings += "Audit coverage appears enabled for both admin and unified audit logs."
        }
    }

    $roleAssignments = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "roleAssignments"
    if ($roleAssignments) {
        $roleChangeCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $roleAssignments -PropertyName "Rows" -DefaultValue @())).Count
        if ($roleChangeCount -gt 0) {
            $summary = "$roleChangeCount role-management audit event(s) were observed in the lookback."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 30 -Module "roleAssignments"
            $nextSteps += "Review role-management audit events for privileged access changes tied to the incident window."
        }
    }

    $consentGrants = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "consentGrants"
    if ($consentGrants) {
        $highRiskGrantCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $consentGrants -PropertyName "HighRiskGrants" -DefaultValue @())).Count
        if ($highRiskGrantCount -gt 0) {
            $summary = "$highRiskGrantCount OAuth grant(s) include high-risk delegated scopes."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 25 -Module "consentGrants"
            $nextSteps += "Validate the principals behind the flagged OAuth grants and review consent provenance."
        } elseif (@((Get-InvestigationCollectorDataProperty -CollectorResult $consentGrants -PropertyName "Grants" -DefaultValue @())).Count -gt 0) {
            $benignFindings += "OAuth delegated grants were collected with no high-risk scope matches in the baseline rules."
        }
    }

    $acceptedDomains = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "acceptedDomains"
    if ($acceptedDomains) {
        $anomalyCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $acceptedDomains -PropertyName "Anomalies" -DefaultValue @())).Count
        if ($anomalyCount -gt 0) {
            $summary = "$anomalyCount accepted-domain anomaly/anomalies detected."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 15 -Module "acceptedDomains"
            $nextSteps += "Review domain verification and availability status for unexpected tenant mail routes."
        } else {
            $benignFindings += "Accepted domain inventory did not surface baseline anomalies."
        }
    }

    $mailboxAuditPosture = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "mailboxAuditPosture"
    if ($mailboxAuditPosture) {
        $auditDisabledCount = @((Get-InvestigationCollectorDataProperty -CollectorResult $mailboxAuditPosture -PropertyName "AuditDisabledMailboxes" -DefaultValue @())).Count
        if ($auditDisabledCount -gt 0) {
            $summary = "$auditDisabledCount mailbox(es) have mailbox auditing disabled."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 20 -Module "mailboxAuditPosture"
            $nextSteps += "Re-enable mailbox auditing where appropriate and validate whether any disabled mailbox is in scope."
        } else {
            $benignFindings += "Collected mailboxes report mailbox auditing enabled."
        }
    }

    $messageTracePivot = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "messageTracePivot"
    if ($messageTracePivot) {
        $matchedTraceRows = @((Get-InvestigationCollectorDataProperty -CollectorResult $messageTracePivot -PropertyName "MatchedRows" -DefaultValue @())).Count
        if ($matchedTraceRows -gt 0) {
            $summary = "$matchedTraceRows message trace row(s) matched the supplied pivots."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 20 -Module "messageTracePivot"
            $nextSteps += "Use matched message-trace records to pivot into users, routing, and related indicators."
        }
    }

    $quarantinePivot = Get-CollectorResultByModule -CollectorResults $CollectorResults -ModuleName "quarantinePivot"
    if ($quarantinePivot) {
        $matchedQuarantineRows = @((Get-InvestigationCollectorDataProperty -CollectorResult $quarantinePivot -PropertyName "MatchedRows" -DefaultValue @())).Count
        if ($matchedQuarantineRows -gt 0) {
            $summary = "$matchedQuarantineRows quarantine message(s) matched the supplied pivots."
            $suspiciousFindings += $summary
            $findingRecords += New-InvestigationFindingRecord -Summary $summary -Weight 10 -Module "quarantinePivot"
            $nextSteps += "Review quarantine actions to determine whether Microsoft 365 already contained related malicious messages."
        }
    }

    if ($nextSteps.Count -eq 0) {
        $nextSteps += "Review normalized collector outputs for tenant-wide anomalies and validate the collection gaps before concluding."
    }

    $score = 0
    if (@($findingRecords).Count -gt 0) {
        $score = [int](($findingRecords | Measure-Object -Property Weight -Sum).Sum)
    }

    $skippedOrFailedCount = @(
        $CollectorResults |
            Where-Object { $_.Status -in @("skipped", "failed") }
    ).Count
    $confidenceNote = if ($skippedOrFailedCount -ge 4) {
        "Confidence is limited by multiple skipped or failed evidence modules."
    } elseif ($skippedOrFailedCount -gt 0) {
        "Confidence is partially limited by skipped or failed evidence modules."
    } else {
        "Confidence is stronger because all planned modules returned data or partial data."
    }

    $severity = if ($score -ge 70) {
        "High"
    } elseif ($score -ge 25) {
        "Medium"
    } else {
        "Low"
    }

    return [pscustomobject]@{
        TenantDomain = $Manifest.TenantDomain
        SuspiciousFindings = $suspiciousFindings
        BenignFindings = $benignFindings
        CollectionGaps = $collectionGaps
        Coverage = Get-InvestigationCoverageSummary -CollectorResults $CollectorResults
        SkipGuidance = Get-InvestigationSkipGuidance -CollectorResults $CollectorResults
        NextSteps = @($nextSteps | Sort-Object -Unique)
        FindingRecords = $findingRecords
        Score = $score
        Severity = $severity
        ConfidenceNote = $confidenceNote
        CollectorResults = $CollectorResults
    }
}

function New-InvestigationVerdict {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Detections = @()
    )

    $assessment = Get-InvestigationAssessment -Manifest $Manifest -CollectorResults $CollectorResults
    $topFindings = if (@($Detections).Count -gt 0) {
        @($Detections | Select-Object -ExpandProperty Summary -First 3)
    } else {
        @(Get-InvestigationTopFindingRecords -Assessment $assessment | Select-Object -ExpandProperty Summary -First 3)
    }
    $severity = if (@($Detections).Count -gt 0) {
        if (@($Detections | Where-Object { $_.Severity -eq "High" }).Count -gt 0) {
            "High"
        } elseif (@($Detections | Where-Object { $_.Severity -eq "Medium" }).Count -gt 0) {
            "Medium"
        } else {
            "Low"
        }
    } else {
        $assessment.Severity
    }
    $confidenceNote = if (@($Detections).Count -gt 0) {
        "Detection confidence is based on collected evidence sources and remaining collection gaps."
    } else {
        $assessment.ConfidenceNote
    }

    return [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        Severity = $severity
        Score = $assessment.Score
        TopFindings = $topFindings
        ConfidenceNote = $confidenceNote
        CollectionGapCount = @($assessment.CollectionGaps).Count
        Note = "Triage severity only. This output does not prove absence of compromise."
    }
}

function New-InvestigationSummaryObject {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Detections = @()
    )

    $assessment = Get-InvestigationAssessment -Manifest $Manifest -CollectorResults $CollectorResults
    $verdict = New-InvestigationVerdict -Manifest $Manifest -CollectorResults $CollectorResults -Detections $Detections
    $evidenceLimitations = @(Get-InvestigationEvidenceLimitations -Manifest $Manifest)

    return [pscustomobject]@{
        TenantDomain = $Manifest.TenantDomain
        Verdict = $verdict
        Coverage = $assessment.Coverage
        SkipGuidance = $assessment.SkipGuidance
        EvidenceLimitations = $evidenceLimitations
        Detections = @($Detections)
        SuspiciousFindings = $assessment.SuspiciousFindings
        BenignFindings = $assessment.BenignFindings
        CollectionGaps = $assessment.CollectionGaps
        NextSteps = $assessment.NextSteps
        CollectorResults = $CollectorResults
    }
}

function New-InvestigationTerminalSummary {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Detections = @(),

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $assessment = Get-InvestigationAssessment -Manifest $Manifest -CollectorResults $CollectorResults
    $verdict = New-InvestigationVerdict -Manifest $Manifest -CollectorResults $CollectorResults -Detections $Detections
    $topRecords = @(Get-InvestigationTopFindingRecords -Assessment $assessment)
    $skippedLines = @(New-InvestigationSkippedModuleLines -CollectorResults $CollectorResults)
    $topDetections = @($Detections | Select-Object -First 3)
    $evidenceLimitations = @(Get-InvestigationEvidenceLimitations -Manifest $Manifest)

    $lines = @(
        "+--------------------------------------------------+",
        "| M365 COMPROMISE TRIAGE                           |",
        "| Verdict: $(Format-InvestigationConsoleValue -Value $verdict.Severity -Width 38)|",
        "| Tenant: $(Format-InvestigationConsoleValue -Value ([string]$Manifest.TenantDomain) -Width 39)|",
        "| Case: $(Format-InvestigationConsoleValue -Value ([string]$Manifest.CaseName) -Width 41)|",
        "+--------------------------------------------------+",
        "Output Folder: $OutputPath"
    )

    if ($topDetections.Count -gt 0) {
        $lines += @("", "Top Detections")
        foreach ($detection in $topDetections) {
            $lines += "[$($detection.Severity.ToUpperInvariant())] $($detection.Name): $($detection.Summary)"
        }
    } else {
        $lines += @("", "Top Findings")
        if ($topRecords.Count -eq 0) {
            $lines += "[INFO] No suspicious findings met the current verdict thresholds."
        } else {
            foreach ($record in $topRecords) {
                $priority = Resolve-InvestigationFindingPriorityLabel -Weight $record.Weight
                $lines += "[$priority] $($record.Summary)"
            }
        }
    }

    $lines += @("", "Confidence Limits", "[INFO] $($verdict.ConfidenceNote)")
    foreach ($limitation in $evidenceLimitations) {
        $lines += "[INFO] $limitation"
    }

    $lines += @(
        "",
        "Coverage",
        "[OK  ] $($assessment.Coverage.Collected) modules collected"
    )
    if ($assessment.Coverage.Skipped -gt 0) {
        $lines += "[SKIP] $($assessment.Coverage.Skipped) modules skipped by design"
    }
    if ($assessment.Coverage.Failed -gt 0) {
        $lines += "[FAIL] $($assessment.Coverage.Failed) modules failed"
    } else {
        $lines += "[FAIL] 0 modules failed"
    }

    if ($skippedLines.Count -gt 0) {
        $lines += @("", "Skipped Modules")
        $lines += $skippedLines
    }

    if (@($assessment.CollectionGaps).Count -gt 0) {
        $lines += @("", "Collection Gaps")
        $lines += @(
            $assessment.CollectionGaps |
                Where-Object { $_ -notmatch "^Skipped " } |
                ForEach-Object { "[GAP ] $_" }
        )
    }

    if (@($assessment.SkipGuidance).Count -gt 0) {
        $lines += @("", "How To Enable Skipped Pivots")
        $lines += $assessment.SkipGuidance
    }

    return ($lines -join [Environment]::NewLine).TrimEnd()
}

function New-InvestigationMarkdownSummary {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Detections = @()
    )

    $summary = New-InvestigationSummaryObject -Manifest $Manifest -CollectorResults $CollectorResults -Detections $Detections
    $verdict = $summary.Verdict
    $assessment = Get-InvestigationAssessment -Manifest $Manifest -CollectorResults $CollectorResults
    $topRecords = @(Get-InvestigationTopFindingRecords -Assessment $assessment)
    $topDetections = @($summary.Detections | Select-Object -First 5)
    $lines = @(
        "# Investigation Summary",
        "",
        "Tenant: $($summary.TenantDomain)",
        "Verdict: $($verdict.Severity)",
        "Confidence: $($verdict.ConfidenceNote)",
        "Score: $($verdict.Score)",
        ""
    )

    if ($topDetections.Count -gt 0) {
        $lines += "## Top Detections"
        foreach ($detection in $topDetections) {
            $lines += "- [$($detection.Severity)] $($detection.Name): $($detection.Summary)"
        }
        $lines += ""
    } elseif ($topRecords.Count -gt 0) {
        $lines += "## Top Findings"
        foreach ($record in $topRecords) {
            $priority = Resolve-InvestigationFindingPriorityLabel -Weight $record.Weight
            $lines += "- [$priority] $($record.Summary)"
        }
        $lines += ""
    }

    if (@($summary.Detections).Count -gt 0) {
        $lines += "## Detections"
        foreach ($detection in @($summary.Detections)) {
            $lines += "- [$($detection.Severity)] $($detection.Name): $($detection.Summary)"
        }
        $lines += ""
    }

    $lines += @("## Confidence Limits", "- $($verdict.ConfidenceNote)")
    foreach ($limitation in @($summary.EvidenceLimitations)) {
        $lines += "- $limitation"
    }
    $lines += ""

    $lines += @(
        "## Coverage",
        "- Collected modules: $($summary.Coverage.Collected)",
        "- Skipped modules: $($summary.Coverage.Skipped)",
        "- Failed modules: $($summary.Coverage.Failed)",
        ""
    )

    $skippedLines = @(New-InvestigationSkippedModuleLines -CollectorResults $CollectorResults)
    if ($skippedLines.Count -gt 0) {
        $lines += "## Skipped Modules"
        foreach ($line in $skippedLines) {
            $lines += "- $($line -replace '^\[SKIP\] ', '')"
        }
        $lines += ""
    }

    $sectionMap = [ordered]@{
        "Suspicious Findings" = $summary.SuspiciousFindings
        "Benign Findings" = $summary.BenignFindings
        "Collection Gaps" = $summary.CollectionGaps
        "Next Steps" = $summary.NextSteps
    }

    foreach ($section in $sectionMap.Keys) {
        $lines += "## $section"
        $items = @($sectionMap[$section])
        if ($items.Count -eq 0) {
            $lines += "- None"
        } else {
            foreach ($item in $items) {
                $lines += "- $item"
            }
        }
        $lines += ""
    }

    if (@($summary.SkipGuidance).Count -gt 0) {
        $lines += "## How To Enable Skipped Pivots"
        foreach ($item in @($summary.SkipGuidance)) {
            $lines += "- $item"
        }
        $lines += ""
    }

    $lines += "_Triage severity only. This summary does not prove absence of compromise._"

    return ($lines -join [Environment]::NewLine).TrimEnd()
}

function Write-InvestigationReportBundle {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Detections = @()
    )

    $summary = New-InvestigationSummaryObject -Manifest $Manifest -CollectorResults $CollectorResults -Detections $Detections
    $markdown = New-InvestigationMarkdownSummary -Manifest $Manifest -CollectorResults $CollectorResults -Detections $Detections
    $verdict = New-InvestigationVerdict -Manifest $Manifest -CollectorResults $CollectorResults -Detections $Detections
    $confidenceAssessment = [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        DetectionCount = @($Detections).Count
        ConfidenceNote = $verdict.ConfidenceNote
        EvidenceLimitations = @($summary.EvidenceLimitations)
        Coverage = $summary.Coverage
    }

    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "manifest.json") -Data $Manifest | Out-Null
    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "collection-status.json") -Data @{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        Results = @(
            $CollectorResults |
                Select-Object Module, Status, RawPath, NormalizedPath, Metrics, Error, Warnings
        )
    } | Out-Null
    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "findings-summary.json") -Data $summary | Out-Null
    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "verdict.json") -Data $verdict | Out-Null
    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "detections.json") -Data @($Detections) | Out-Null
    Write-InvestigationJsonFile -Path (Join-Path $OutputPath "confidence-assessment.json") -Data $confidenceAssessment | Out-Null
    Set-Content -Path (Join-Path $OutputPath "findings-summary.md") -Value $markdown

    return [pscustomobject]@{
        Summary = $summary
        Verdict = $verdict
        MarkdownPath = Join-Path $OutputPath "findings-summary.md"
        SummaryJsonPath = Join-Path $OutputPath "findings-summary.json"
        VerdictJsonPath = Join-Path $OutputPath "verdict.json"
        DetectionsJsonPath = Join-Path $OutputPath "detections.json"
        ConfidenceJsonPath = Join-Path $OutputPath "confidence-assessment.json"
    }
}
