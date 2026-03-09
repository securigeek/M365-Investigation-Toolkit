Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "forensic-normalization.ps1")

function Get-InvestigationDetectorRegistry {
    return @(
        [pscustomobject]@{
            Name = "oauthConsentAbuse"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationOauthConsentAbuse -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "servicePrincipalBackdoor"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationServicePrincipalBackdoor -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "federatedBackdoor"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationFederatedBackdoor -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "deviceCodePhishing"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationDeviceCodePhishing -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "dormantAccountMfaTakeover"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationDormantAccountMfaTakeover -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "passwordSpray"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationPasswordSpray -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "becDataExfiltration"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationBecDataExfiltration -Manifest $Manifest -CollectorResults $CollectorResults
            }
        },
        [pscustomobject]@{
            Name = "auditDefenseEvasion"
            ScriptBlock = {
                param($Manifest, $CollectorResults, $OutputPath)
                Find-InvestigationAuditDefenseEvasion -Manifest $Manifest -CollectorResults $CollectorResults
            }
        }
    )
}

function Get-InvestigationCollectorResultByName {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    return $CollectorResults | Where-Object { $_.Module -eq $ModuleName } | Select-Object -First 1
}

function Get-InvestigationCollectorRows {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $result = Get-InvestigationCollectorResultByName -CollectorResults $CollectorResults -ModuleName $ModuleName
    if (-not $result -or $result.Status -ne "success" -or -not $result.Data) {
        return @()
    }
    if (-not (Test-InvestigationObjectProperty -Object $result.Data -PropertyName "Rows")) {
        return @()
    }

    return @($result.Data.Rows)
}

function Test-InvestigationObjectProperty {
    param(
        [Parameter()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $false
    }

    return @(
        $Object.PSObject.Properties |
            Where-Object { $_.Name -eq $PropertyName }
    ).Count -gt 0
}

function New-DetectionRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Low", "Medium", "High")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Low", "Medium", "High")]
        [string]$Confidence,

        [Parameter(Mandatory = $true)]
        [string]$Summary,

        [Parameter()]
        [string[]]$EvidenceSources,

        [Parameter()]
        [object[]]$Entities,

        [Parameter()]
        [string[]]$NextSteps
    )

    return [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        Name = $Name
        Severity = $Severity
        Confidence = $Confidence
        Summary = $Summary
        EvidenceSources = @($EvidenceSources)
        Entities = @($Entities)
        NextSteps = @($NextSteps)
    }
}

function ConvertTo-InvestigationDateTimeOrNull {
    param(
        [Parameter()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $resolved = [string]$Value
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        return $null
    }

    return [datetime]$Value
}

function Find-InvestigationOauthConsentAbuse {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $rows = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "directoryAuditLog")
    $dangerousScopes = @(
        "MailboxSettings.ReadWrite",
        "Directory.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Mail.ReadWrite",
        "Files.ReadWrite.All"
    )
    $hits = @()

    foreach ($row in $rows) {
        if ($row.Operation -notin @("Consent to application", "Add app role assignment grant to user", "Add delegated permission grant")) {
            continue
        }

        $scopeText = $null
        if ($row.ModifiedProperties -and (Test-InvestigationObjectProperty -Object $row.ModifiedProperties -PropertyName "ConsentAction.Permissions")) {
            $scopeText = [string]$row.ModifiedProperties."ConsentAction.Permissions"
        } elseif ($row.ModifiedProperties -and (Test-InvestigationObjectProperty -Object $row.ModifiedProperties -PropertyName "DelegatedPermissionGrant.Scope")) {
            $scopeText = [string]$row.ModifiedProperties."DelegatedPermissionGrant.Scope"
        }

        if ([string]::IsNullOrWhiteSpace($scopeText)) {
            continue
        }

        $matchedScopes = @(
            $dangerousScopes |
                Where-Object { $scopeText -match [regex]::Escape($_) }
        )
        if ($matchedScopes.Count -eq 0) {
            continue
        }

        $hits += New-DetectionRecord `
            -Name "oauthConsentAbuse" `
            -Severity "High" `
            -Confidence "Medium" `
            -Summary "App consent granted to '$($row.Target)' with dangerous scopes: $($matchedScopes -join ', ')." `
            -EvidenceSources @("directoryAuditLog") `
            -Entities @($row.Actor, $row.Target) `
            -NextSteps @("Review the application's publisher, consent provenance, and whether the grant is still active.")
    }

    return @($hits)
}

function Find-InvestigationServicePrincipalBackdoor {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $auditRows = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "directoryAuditLog")
    $signInRows = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "servicePrincipalSignins")
    $hits = @()

    foreach ($row in $auditRows) {
        if ($row.Operation -notin @("Update application", "Update service principal", "Update application - Certificates and secrets management")) {
            continue
        }

        $credentialEvidence = @(
            $row.ModifiedProperties.PSObject.Properties |
                Where-Object {
                    $_.Name -match "Key|Password|Certificate" -and
                    -not [string]::IsNullOrWhiteSpace([string]$_.Value)
                }
        )
        if ($credentialEvidence.Count -eq 0) {
            continue
        }

        $servicePrincipalId = $null
        if ((Test-InvestigationObjectProperty -Object $row -PropertyName "TargetType") -and $row.TargetType -eq "ServicePrincipal" -and (Test-InvestigationObjectProperty -Object $row -PropertyName "TargetId") -and $row.TargetId) {
            $servicePrincipalId = [string]$row.TargetId
        }

        $appIds = @()
        if ((Test-InvestigationObjectProperty -Object $row -PropertyName "ModifiedProperties") -and $row.ModifiedProperties) {
            foreach ($propertyName in @("AppId", "ApplicationId", "ClientId")) {
                if ((Test-InvestigationObjectProperty -Object $row.ModifiedProperties -PropertyName $propertyName) -and $row.ModifiedProperties.$propertyName) {
                    $appIds += [string]$row.ModifiedProperties.$propertyName
                }
            }
        }

        $matchingSignIns = @(
            if ($servicePrincipalId) {
                $signInRows |
                    Where-Object { $_.ServicePrincipalId -eq $servicePrincipalId }
            } elseif ($appIds.Count -gt 0) {
                $signInRows |
                    Where-Object { $_.AppId -in $appIds }
            } else {
                $signInRows |
                    Where-Object { $_.AppDisplayName -eq $row.Target }
            }
        )

        $severity = if ($matchingSignIns.Count -gt 0) { "High" } else { "Medium" }
        $confidence = if ($matchingSignIns.Count -gt 0) { "High" } else { "Medium" }
        $summary = if ($matchingSignIns.Count -gt 0) {
            "Service principal '$($row.Target)' had credential changes followed by sign-in activity."
        } else {
            "Service principal '$($row.Target)' had credential changes that may indicate a persistence backdoor."
        }

        $hits += New-DetectionRecord `
            -Name "servicePrincipalBackdoor" `
            -Severity $severity `
            -Confidence $confidence `
            -Summary $summary `
            -EvidenceSources @("directoryAuditLog", "servicePrincipalSignins") `
            -Entities @($row.Actor, $row.Target) `
            -NextSteps @("Review recent secret or certificate additions and validate whether the app should be signing in.")
    }

    return @($hits)
}

function Find-InvestigationFederatedBackdoor {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $auditRows = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "directoryAuditLog")
    $hits = @()

    foreach ($row in $auditRows) {
        $issuerUri = $null
        if ($row.ModifiedProperties -and (Test-InvestigationObjectProperty -Object $row.ModifiedProperties -PropertyName "IssuerUri")) {
            $issuerUri = [string]$row.ModifiedProperties.IssuerUri
        }

        $hasSourceAnchorChange = $row.ModifiedProperties -and @($row.ModifiedProperties.PSObject.Properties | Where-Object { $_.Name -match "SourceAnchor|ImmutableId" }).Count -gt 0
        $isSuspiciousFederation = ($row.Operation -eq "Set domain authentication" -and $issuerUri -match "any\.sts") -or $hasSourceAnchorChange
        if (-not $isSuspiciousFederation) {
            continue
        }

        $summary = if ($issuerUri -match "any\.sts") {
            "Domain federation change for '$($row.Target)' references suspicious issuer URI '$issuerUri'."
        } else {
            "User or domain identity anchor changes were observed for '$($row.Target)'."
        }

        $hits += New-DetectionRecord `
            -Name "federatedBackdoor" `
            -Severity "High" `
            -Confidence "Medium" `
            -Summary $summary `
            -EvidenceSources @("directoryAuditLog") `
            -Entities @($row.Actor, $row.Target) `
            -NextSteps @("Review federation settings and immutable ID changes for unauthorized tampering.")
    }

    return @($hits)
}

function Find-InvestigationDeviceCodePhishing {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $signIns = @(
        Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "interactiveSignins" |
            Where-Object {
                (Test-InvestigationObjectProperty -Object $_ -PropertyName "AuthenticationProtocol") -and
                $_.AuthenticationProtocol -eq "deviceCode"
            }
    )
    $allUalRows = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "unifiedAuditLog")
    $cmsiRows = @(
        $allUalRows |
            Where-Object {
                $_.Operation -eq "UserLoggedIn" -and
                $_.ExtendedProperties -and
                (Test-InvestigationObjectProperty -Object $_.ExtendedProperties -PropertyName "RequestType") -and
                $_.ExtendedProperties.RequestType -eq "CMSI"
            }
    )
    $hits = @()

    foreach ($signIn in $signIns) {
        $signInTime = ConvertTo-InvestigationDateTimeOrNull -Value $signIn.CreatedDateTime
        if ($null -eq $signInTime) {
            continue
        }

        $matchingUal = @(
            $cmsiRows |
                Where-Object {
                    $_.UserId -eq $signIn.UserPrincipalName -and
                    ($cmsiTime = ConvertTo-InvestigationDateTimeOrNull -Value $_.CreationDate) -and
                    [math]::Abs((New-TimeSpan -Start $signInTime -End $cmsiTime).TotalMinutes) -le 10
                }
        )
        if ($matchingUal.Count -eq 0) {
            continue
        }

        $followOnActivity = @(
            $allUalRows |
                Where-Object {
                    $_.UserId -eq $signIn.UserPrincipalName -and
                    $_.Operation -ne "UserLoggedIn" -and
                    ($activityTime = ConvertTo-InvestigationDateTimeOrNull -Value $_.CreationDate) -and
                    $activityTime -gt $signInTime -and
                    $activityTime -le $signInTime.AddMinutes(60)
                }
        )

        $severity = if ($followOnActivity.Count -gt 0) { "High" } else { "Medium" }
        $confidence = if ($followOnActivity.Count -gt 0) { "High" } else { "Medium" }
        $summary = if ($followOnActivity.Count -gt 0) {
            "Device code sign-in for '$($signIn.UserPrincipalName)' aligns with CMSI evidence and follow-on activity."
        } else {
            "Device code sign-in for '$($signIn.UserPrincipalName)' aligns with CMSI evidence, but no follow-on activity was captured in the current window."
        }

        $hits += New-DetectionRecord `
            -Name "deviceCodePhishing" `
            -Severity $severity `
            -Confidence $confidence `
            -Summary $summary `
            -EvidenceSources @("interactiveSignins", "unifiedAuditLog") `
            -Entities @($signIn.UserPrincipalName, $signIn.IPAddress, $signIn.AppDisplayName) `
            -NextSteps @("Review follow-on Graph and mailbox activity from the same user and IP range.")
    }

    return @($hits)
}

function Find-InvestigationDormantAccountMfaTakeover {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $auditRows = @(
        Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "directoryAuditLog" |
            Where-Object {
                $_.Operation -in @("User registered all required security info", "User started security info registration") -or
                ($_.Operation -eq "Update user" -and $_.Actor -eq "Azure MFA Strong Authentication Service")
            }
    )
    $signIns = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "interactiveSignins")
    $hits = @()

    foreach ($row in $auditRows) {
        $registrationTime = [datetime]$row.ActivityDateTime
        $userSignIns = @(
            $signIns |
                Where-Object { $_.UserPrincipalName -eq $row.Target } |
                Sort-Object { [datetime]$_.CreatedDateTime }
        )
        $previousSignIn = $userSignIns |
            Where-Object { [datetime]$_.CreatedDateTime -lt $registrationTime } |
            Select-Object -Last 1
        
        $nextSignIn = $userSignIns |
            Where-Object { [datetime]$_.CreatedDateTime -gt $registrationTime } |
            Select-Object -First 1

        if (-not $previousSignIn -or -not $nextSignIn) {
            continue
        }

        $dormancyDays = Get-ForensicDormancyDays -LastSeen ([datetime]$previousSignIn.CreatedDateTime) -ReferenceTime $registrationTime
        if ($dormancyDays -lt 30) {
            continue
        }

        $deviceDetail = if ($row.ModifiedProperties -and (Test-InvestigationObjectProperty -Object $row.ModifiedProperties -PropertyName "Strong Authentication Phone App Detail")) {
            [string]$row.ModifiedProperties."Strong Authentication Phone App Detail"
        } else {
            "not available"
        }

        $hits += New-DetectionRecord `
            -Name "dormantAccountMfaTakeover" `
            -Severity "High" `
            -Confidence "Medium" `
            -Summary "Dormant account '$($row.Target)' registered new security info after $dormancyDays days of inactivity." `
            -EvidenceSources @("directoryAuditLog", "interactiveSignins") `
            -Entities @($row.Target, $deviceDetail) `
            -NextSteps @("Validate who registered the MFA method and review sign-ins that followed the registration event.")
    }

    return @($hits)
}

function Find-InvestigationPasswordSpray {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $failedRows = @(
        Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "interactiveSignins" |
            Where-Object {
                (Test-InvestigationObjectProperty -Object $_ -PropertyName "ResultType") -and
                $_.ResultType -eq 50126
            }
    )
    $groups = @{}

    foreach ($row in $failedRows) {
        $bucket = Get-ForensicTimeBucketKey -Timestamp ([datetime]$row.CreatedDateTime) -WindowSeconds 3
        $groupKey = "$($row.IPAddress)|$bucket"
        if (-not $groups.ContainsKey($groupKey)) {
            $groups[$groupKey] = New-Object System.Collections.ArrayList
        }

        [void]$groups[$groupKey].Add($row)
    }

    $hits = @()

    foreach ($groupKey in $groups.Keys) {
        $rows = @($groups[$groupKey])
        $distinctUsers = @(
            $rows |
                Select-Object -ExpandProperty UserPrincipalName -Unique
        )
        if ($distinctUsers.Count -lt 3) {
            continue
        }

        $ipAddress = @($rows | Select-Object -ExpandProperty IPAddress -First 1)[0]
        $appNames = @(
            $rows |
                Select-Object -ExpandProperty AppDisplayName -Unique
        )
        $severity = if ($appNames -contains "Azure Active Directory PowerShell") { "High" } else { "Medium" }
        $entities = @($ipAddress) + @($distinctUsers)

        $hits += New-DetectionRecord `
            -Name "passwordSpray" `
            -Severity $severity `
            -Confidence "High" `
            -Summary "Password spray pattern from IP '$ipAddress' targeted $($distinctUsers.Count) users inside a 3-second window." `
            -EvidenceSources @("interactiveSignins") `
            -Entities $entities `
            -NextSteps @("Review the targeted users, IP reputation, and whether any subsequent sign-ins indicate a valid credential hit.")
    }

    return @($hits)
}

function Find-InvestigationBecDataExfiltration {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $forwarding = Get-InvestigationCollectorResultByName -CollectorResults $CollectorResults -ModuleName "mailboxForwarding"
    $ualRows = @(Get-InvestigationCollectorRows -CollectorResults $CollectorResults -ModuleName "unifiedAuditLog")
    $forwardingHits = @(
        if ($forwarding -and $forwarding.Data -and (Test-InvestigationObjectProperty -Object $forwarding.Data -PropertyName "ForwardingHits")) {
            $forwarding.Data.ForwardingHits
        }
    )
    $mailAccessRows = @(
        $ualRows |
            Where-Object { $_.Operation -eq "MailItemsAccessed" -and $_.ClientInfoString -eq "REST" }
    )
    $searchRows = @(
        $ualRows |
            Where-Object { $_.Operation -in @("SearchQueryInitiated", "SearchExportDownloaded", "ComplianceSearch") }
    )

    if ($forwardingHits.Count -eq 0 -or ($mailAccessRows.Count + $searchRows.Count) -eq 0) {
        return @()
    }

    $severity = if ($mailAccessRows.Count -gt 0 -and $searchRows.Count -gt 0) { "High" } else { "Medium" }

    return @(
        New-DetectionRecord `
            -Name "becDataExfiltration" `
            -Severity $severity `
            -Confidence "Medium" `
            -Summary "Mailbox forwarding and UAL evidence indicate potential BEC or data exfiltration behavior." `
            -EvidenceSources @("mailboxForwarding", "unifiedAuditLog") `
            -Entities @($forwardingHits.UserPrincipalName) `
            -NextSteps @("Review message access, compliance searches, and forwarding targets for the affected mailboxes.")
    )
}

function Find-InvestigationAuditDefenseEvasion {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults
    )

    $auditCoverage = Get-InvestigationCollectorResultByName -CollectorResults $CollectorResults -ModuleName "auditCoverage"
    $mailboxAudit = Get-InvestigationCollectorResultByName -CollectorResults $CollectorResults -ModuleName "mailboxAuditPosture"
    $coverageGaps = @(
        if ($auditCoverage -and $auditCoverage.Data -and (Test-InvestigationObjectProperty -Object $auditCoverage.Data -PropertyName "CoverageGaps")) {
            $auditCoverage.Data.CoverageGaps
        }
    )
    $auditDisabledMailboxes = @(
        if ($mailboxAudit -and $mailboxAudit.Data -and (Test-InvestigationObjectProperty -Object $mailboxAudit.Data -PropertyName "AuditDisabledMailboxes")) {
            $mailboxAudit.Data.AuditDisabledMailboxes
        }
    )

    if ($coverageGaps.Count -eq 0 -and $auditDisabledMailboxes.Count -eq 0) {
        return @()
    }

    $severity = if ($coverageGaps.Count -gt 0 -and $auditDisabledMailboxes.Count -gt 0) { "High" } else { "Medium" }

    return @(
        New-DetectionRecord `
            -Name "auditDefenseEvasion" `
            -Severity $severity `
            -Confidence "High" `
            -Summary "Audit coverage gaps or mailbox audit bypass conditions reduce investigative visibility." `
            -EvidenceSources @("auditCoverage", "mailboxAuditPosture") `
            -Entities @($auditDisabledMailboxes.UserPrincipalName) `
            -NextSteps @("Restore audit coverage and validate whether the reduced logging state was intentional.")
    )
}

function Invoke-InvestigationDetectors {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Manifest,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$CollectorResults,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $registry = @(Get-InvestigationDetectorRegistry)
    $hits = @()

    foreach ($detector in $registry) {
        $result = & $detector.ScriptBlock -Manifest $Manifest -CollectorResults $CollectorResults -OutputPath $OutputPath
        if ($null -eq $result) {
            continue
        }

        $hits += @($result)
    }

    return $hits
}
