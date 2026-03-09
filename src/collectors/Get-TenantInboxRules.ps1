Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantInboxRulesCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "inboxRules"
    $startTime = Get-Date

    try {
        # Stream mailboxes with pagination to reduce memory usage
        $mailboxBatchSize = 50
        $allRules = [System.Collections.Generic.List[object]]::new()
        $warnings = [System.Collections.Generic.List[string]]::new()
        $mailboxCount = 0
        $batchCount = 0

        Write-Host "  📧 Fetching mailboxes (batched)..." -ForegroundColor DarkGray

        # Get mailboxes in batches
        $mailboxes = Get-EXOMailbox -ResultSize 500 -Properties PrimarySmtpAddress, UserPrincipalName
        $mailboxCount = @($mailboxes).Count
        
        Write-Host "  📧 Found $mailboxCount mailboxes, scanning rules..." -ForegroundColor DarkGray

        foreach ($mailbox in $mailboxes) {
            $batchCount++
            if ($batchCount % 10 -eq 0) {
                Write-Host "  📧 Processing mailbox $batchCount/$mailboxCount..." -ForegroundColor DarkGray
                # Force garbage collection every 10 mailboxes
                [System.GC]::Collect()
            }

            try {
                $mailboxRules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction Stop | 
                    Select-Object -First 20 |
                    Select-Object `
                        @{ Name = "Mailbox"; Expression = { $mailbox.UserPrincipalName } },
                        Name, Enabled, Priority, Description, DeleteMessage, 
                        MoveToFolder, ForwardTo, ForwardAsAttachmentTo, RedirectTo, 
                        StopProcessingRules, FromAddressContainsWords, SubjectContainsWords
                
                if ($mailboxRules) {
                    $allRules.AddRange(@($mailboxRules))
                }
            } catch {
                $warnings.Add("inbox-rules:$($mailbox.UserPrincipalName): $($_.Exception.Message)")
            }
        }

        # Identify suspicious rules
        $suspiciousRules = @($allRules | Where-Object {
            $_.Enabled -and (
                $_.ForwardTo -or
                $_.ForwardAsAttachmentTo -or  
                $_.RedirectTo -or
                $_.DeleteMessage -or
                ($_.FromAddressContainsWords -and $_.DeleteMessage) -or
                ($_.SubjectContainsWords -match "invoice|payment|wire|urgent" -and $_.MoveToFolder)
            )
        })

        # Build raw data (limited to reduce memory)
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            MailboxCount = $mailboxCount
            RuleCount = $allRules.Count
            Rules = @($allRules | Select-Object -First 100)  # Limit in raw data
            SuspiciousRules = @($suspiciousRules)
            Warnings = @($warnings)
            Note = "Limited to first 100 rules in raw output to prevent memory issues"
        }

        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            MailboxCount = $mailboxCount
            RuleCount = $allRules.Count
            Rules = @($allRules | Select-Object Mailbox, Name, Enabled, ForwardTo, DeleteMessage, MoveToFolder | Select-Object -First 100)
            SuspiciousRules = @($suspiciousRules)
            SuspiciousRuleCount = $suspiciousRules.Count
            Warnings = @($warnings)
        }

        $status = if ($warnings.Count -gt 0) { "partial" } else { "success" }

        # Clear large variables before publishing
        $mailboxes = $null
        $allRules = $null
        [System.GC]::Collect()

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                MailboxCount = $mailboxCount
                RuleCount = $normalizedData.RuleCount
                SuspiciousRuleCount = $suspiciousRules.Count
                WarningCount = $warnings.Count
                ProcessingTimeSeconds = ([System.DateTime]::Now - $startTime).TotalSeconds
            } `
            -Status $status `
            -Warnings @($warnings)

    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ 
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o") 
                Rules = @() 
                SuspiciousRules = @() 
                Warnings = @() 
            }) `
            -Metrics @{ 
                MailboxCount = 0 
                RuleCount = 0 
                SuspiciousRuleCount = 0 
                WarningCount = 0 
                ProcessingTimeSeconds = ([System.DateTime]::Now - $startTime).TotalSeconds
            } `
            -ErrorMessage $_.Exception.Message
    }
}
