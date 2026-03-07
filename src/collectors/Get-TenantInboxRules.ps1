Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantInboxRulesCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "inboxRules"

    try {
        $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties PrimarySmtpAddress)
        $rules = @()
        $warnings = @()

        foreach ($mailbox in $mailboxes) {
            try {
                $mailboxRules = @(
                    Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction Stop |
                        Select-Object `
                            @{ Name = "Mailbox"; Expression = { $mailbox.UserPrincipalName } },
                            Name, Enabled, Priority, Description, DeleteMessage, MoveToFolder, ForwardTo, ForwardAsAttachmentTo, RedirectTo, StopProcessingRules
                )
                $rules += $mailboxRules
            } catch {
                $warnings += "inbox-rules:$($mailbox.UserPrincipalName): $($_.Exception.Message)"
            }
        }

        $status = if ($warnings.Count -gt 0) { "partial" } else { "success" }
        $suspiciousRules = @(
            $rules |
                Where-Object {
                    $_.Enabled -and (
                        $_.ForwardTo -or
                        $_.ForwardAsAttachmentTo -or
                        $_.RedirectTo -or
                        $_.DeleteMessage
                    )
                }
        )
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Mailboxes = $mailboxes
            Rules = $rules
            Warnings = $warnings
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            MailboxCount = @($mailboxes).Count
            RuleCount = @($rules).Count
            Rules = $rules
            SuspiciousRules = $suspiciousRules
            Warnings = $warnings
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                MailboxCount = @($mailboxes).Count
                RuleCount = @($rules).Count
                SuspiciousRuleCount = @($suspiciousRules).Count
                WarningCount = @($warnings).Count
            } `
            -Status $status `
            -Warnings $warnings
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); Rules = @(); SuspiciousRules = @(); Warnings = @() }) `
            -Metrics @{ MailboxCount = 0; RuleCount = 0; SuspiciousRuleCount = 0; WarningCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
