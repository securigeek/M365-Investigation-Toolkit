<#
.SYNOPSIS
User-facing launcher for the self-service Microsoft 365 compromise check.

.DESCRIPTION
Runs the delegated read-only investigation flow in one command. The script
checks prerequisites, installs missing modules after confirmation, opens the
browser for admin sign-in, collects evidence, and writes verdict plus artifacts.
Profile parameters are retained for internal legacy investigator mode only.
#>

param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$TenantDomain,

    [Parameter()]
    [string]$CaseName,

    [Parameter()]
    [int]$DaysBack = 14,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [string]$OutputRoot,

    [Parameter()]
    [string]$ProfilePath,

    [Parameter()]
    [string]$ProfileRoot,

    [Parameter()]
    [string]$Sender,

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [string]$SubjectContains,

    [Parameter()]
    [switch]$SkipPrompt
)

$ErrorActionPreference = "Stop"

$coreScript = Join-Path $PSScriptRoot "src/Invoke-InvestigationCollector.ps1"
if (-not (Test-Path $coreScript)) {
    throw "Core script not found: $coreScript"
}

$params = @{}

if ($PSBoundParameters.ContainsKey("DaysBack")) {
    $params.DaysBack = $DaysBack
}

foreach ($name in @("TenantId", "TenantDomain", "CaseName", "OutputPath", "OutputRoot", "ProfilePath", "ProfileRoot", "Sender", "Domain", "UserPrincipalName", "SubjectContains")) {
    if ($PSBoundParameters.ContainsKey($name)) {
        $params[$name] = $PSBoundParameters[$name]
    }
}
if ($PSBoundParameters.ContainsKey("SkipPrompt")) {
    $params.SkipPrompt = $SkipPrompt
}

& $coreScript @params
