Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantMailboxForwardingCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "mailboxForwarding"

    try {
        $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward, PrimarySmtpAddress)
        $forwardingHits = @(
            $mailboxes |
                Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } |
                Select-Object UserPrincipalName, PrimarySmtpAddress, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
        )

        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            Mailboxes = $mailboxes
        }
        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            TotalMailboxes = @($mailboxes).Count
            ForwardingHits = $forwardingHits
        }

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalMailboxes = @($mailboxes).Count
                ForwardingHitCount = @($forwardingHits).Count
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); ForwardingHits = @() }) `
            -Metrics @{ TotalMailboxes = 0; ForwardingHitCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
