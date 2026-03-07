Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantMailboxAuditPostureCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "mailboxAuditPosture"

    try {
        $mailboxes = @(
            Get-EXOMailbox -ResultSize Unlimited -Properties AuditEnabled, DefaultAuditSet, RecipientTypeDetails, PrimarySmtpAddress |
                Select-Object UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails, AuditEnabled, DefaultAuditSet
        )
        $auditDisabledMailboxes = @(
            $mailboxes |
                Where-Object { $_.AuditEnabled -eq $false }
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Mailboxes = $mailboxes
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            TotalMailboxes = @($mailboxes).Count
            AuditDisabledMailboxes = $auditDisabledMailboxes
            Mailboxes = $mailboxes
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalMailboxes = @($mailboxes).Count
                AuditDisabledCount = @($auditDisabledMailboxes).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
                Mailboxes = @()
                AuditDisabledMailboxes = @()
            }) `
            -Metrics @{ TotalMailboxes = 0; AuditDisabledCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
