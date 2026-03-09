Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "../lib/collectors.ps1")

function Invoke-TenantMailboxForwardingCollector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    $moduleName = "mailboxForwarding"

    try {
        Write-Host "  📧 Fetching mailboxes with forwarding..." -ForegroundColor DarkGray

        # Limit to 500 mailboxes to prevent memory issues
        $mailboxes = @(Get-EXOMailbox -ResultSize 500 -Properties ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward, PrimarySmtpAddress, UserPrincipalName)
        
        $forwardingHits = @(
            $mailboxes |
                Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress } |
                Select-Object UserPrincipalName, PrimarySmtpAddress, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
        )

        # Limit raw data size
        $rawData = [pscustomobject]@{
            TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
            MailboxCount = @($mailboxes).Count
            ForwardingHits = @($forwardingHits)
            SampleMailboxes = @($mailboxes | Select-Object -First 10 UserPrincipalName, PrimarySmtpAddress, ForwardingAddress)
        }

        $normalizedData = [pscustomobject]@{
            TimestampUtc = $rawData.TimestampUtc
            TotalMailboxes = @($mailboxes).Count
            ForwardingHits = @($forwardingHits)
            ForwardingHitCount = @($forwardingHits).Count
        }

        # Clear variable to free memory
        $mailboxes = $null
        [System.GC]::Collect() | Out-Null

        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -RawData $rawData `
            -NormalizedData $normalizedData `
            -Metrics @{
                TotalMailboxes = $normalizedData.TotalMailboxes
                ForwardingHitCount = $normalizedData.ForwardingHitCount
            }
    } catch {
        return Publish-CollectorArtifacts `
            -OutputPath $OutputPath `
            -ModuleName $moduleName `
            -Status "failed" `
            -NormalizedData ([pscustomobject]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString("o"); ForwardingHits = @(); ForwardingHitCount = 0 }) `
            -Metrics @{ TotalMailboxes = 0; ForwardingHitCount = 0 } `
            -ErrorMessage $_.Exception.Message
    }
}
