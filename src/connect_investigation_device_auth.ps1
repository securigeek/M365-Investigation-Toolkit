<#
.SYNOPSIS
Connects to Graph and Exchange using device authentication for investigation work.

.DESCRIPTION
Uses the dedicated investigation app (public client) for Graph device code auth,
then connects to Exchange Online with device auth using the admin account.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$TenantDomain,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string[]]$GraphScopes = @(
        "User.Read",
        "Mail.Read",
        "Mail.ReadBasic",
        "User.Read.All",
        "AuditLog.Read.All"
    ),

    [ValidateSet("Interactive", "Device")]
    [string]$AuthMode = "Device",

    [switch]$ConnectPurview
)

$ErrorActionPreference = "Stop"

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.28.0 -ErrorAction Stop
Import-Module Microsoft.Graph.Mail -RequiredVersion 2.28.0 -ErrorAction Stop
Import-Module ExchangeOnlineManagement -ErrorAction Stop

$requiredCmdlets = @(
    "Connect-MgGraph",
    "Get-MgContext",
    "Connect-ExchangeOnline",
    "Get-ConnectionInformation"
)

foreach ($cmd in $requiredCmdlets) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Required cmdlet '$cmd' is not available in the current PowerShell environment."
    }
}

Write-Host "Connecting to Microsoft Graph ($AuthMode auth)..." -ForegroundColor Cyan
if ($AuthMode -eq "Device") {
    Connect-MgGraph `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -Scopes $GraphScopes `
        -UseDeviceAuthentication `
        -NoWelcome | Out-Null
} else {
    Connect-MgGraph `
        -TenantId $TenantId `
        -ClientId $ClientId `
        -Scopes $GraphScopes `
        -NoWelcome | Out-Null
}

$mg = Get-MgContext
Write-Host "Graph connected as: $($mg.Account)" -ForegroundColor Green
Write-Host "Graph scopes: $($mg.Scopes -join ', ')" -ForegroundColor Gray

Write-Host "Connecting to Exchange Online ($AuthMode auth)..." -ForegroundColor Cyan
if ($AuthMode -eq "Device") {
    Connect-ExchangeOnline -Organization $TenantDomain -Device -ShowBanner:$false | Out-Null
} else {
    Connect-ExchangeOnline -Organization $TenantDomain -ShowBanner:$false | Out-Null
}
$exo = Get-ConnectionInformation | Select-Object -First 1
Write-Host "Exchange connected as: $($exo.UserPrincipalName)" -ForegroundColor Green

$ip = $null
if ($ConnectPurview) {
    Write-Host "Connecting to Purview Compliance PowerShell..." -ForegroundColor Cyan
    Connect-IPPSSession -Organization $TenantDomain -EnableSearchOnlySession -ShowBanner:$false -WarningAction SilentlyContinue | Out-Null
    $ip = "Connected"
    Write-Host "Purview session connected." -ForegroundColor Green
}

[pscustomobject]@{
    TimestampUtc         = (Get-Date).ToUniversalTime().ToString("o")
    TenantId             = $TenantId
    TenantDomain         = $TenantDomain
    ClientId             = $ClientId
    GraphAccount         = $mg.Account
    GraphScopes          = $mg.Scopes
    ExchangeUserPrincipal = $exo.UserPrincipalName
    PurviewSession       = $ip
} | ConvertTo-Json -Depth 8
