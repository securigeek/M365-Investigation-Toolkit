param(
    [Parameter(Mandatory = $true)]
    [string]$Tenant,

    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string[]]$ExchangeLocation,

    [Parameter(Mandatory = $true)]
    [string]$ContentMatchQuery,

    [int]$PollSeconds = 5,

    [int]$TimeoutMinutes = 20
)

$ErrorActionPreference = "Stop"

# Use the newest installed EXO module so Purview search-only sessions are available.
Import-Module ExchangeOnlineManagement -RequiredVersion 3.9.2

$normalizedLocations = @()
foreach ($entry in $ExchangeLocation) {
    foreach ($value in ($entry -split ",")) {
        $trimmed = $value.Trim()
        if ($trimmed) {
            $normalizedLocations += $trimmed
        }
    }
}

Connect-IPPSSession -Organization $Tenant `
    -EnableSearchOnlySession `
    -CommandName New-ComplianceSearch,Start-ComplianceSearch,Get-ComplianceSearch `
    -ShowBanner:$false `
    -WarningAction SilentlyContinue | Out-Null

$existing = Get-ComplianceSearch -Identity $Name -ErrorAction SilentlyContinue
if (-not $existing) {
    New-ComplianceSearch -Name $Name `
        -ExchangeLocation $normalizedLocations `
        -ContentMatchQuery $ContentMatchQuery | Out-Null
}

Start-ComplianceSearch -Identity $Name | Out-Null

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
do {
    Start-Sleep -Seconds $PollSeconds
    $search = Get-ComplianceSearch -Identity $Name
    if ((Get-Date) -gt $deadline) {
        throw "Compliance search '$Name' timed out after $TimeoutMinutes minute(s). Last status: $($search.Status)"
    }
} while ($search.Status -in @("Starting", "NotStarted", "Running"))

$search | Select-Object Name, Status, Items, Size, JobProgress, NumBindings, ContentMatchQuery |
    ConvertTo-Json -Depth 8
