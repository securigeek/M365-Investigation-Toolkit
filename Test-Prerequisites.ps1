#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Test prerequisites for M365 Investigation Toolkit
.DESCRIPTION
    Verifies PowerShell version, required modules, and execution policy
.EXAMPLE
    .\Test-Prerequisites.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║     M365 Investigation Toolkit - Prerequisites Check         ║
╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

$allPassed = $true

# 1. Check PowerShell version
Write-Host "1. Checking PowerShell version..." -NoNewline
$minVersion = [Version]"7.5.0"
$currentVersion = $PSVersionTable.PSVersion
if ($currentVersion -ge $minVersion) {
    Write-Host " ✓ PASS" -ForegroundColor Green
    Write-Host "   Version: $currentVersion" -ForegroundColor Gray
}
else {
    Write-Host " ✗ FAIL" -ForegroundColor Red
    Write-Host "   Required: PowerShell $minVersion or later" -ForegroundColor Red
    Write-Host "   Current: $currentVersion" -ForegroundColor Red
    Write-Host "   Download: https://github.com/PowerShell/PowerShell/releases" -ForegroundColor Yellow
    $allPassed = $false
}

# 2. Check execution policy
Write-Host "`n2. Checking execution policy..." -NoNewline
$execPolicy = Get-ExecutionPolicy
if ($execPolicy -in @("RemoteSigned", "Unrestricted", "Bypass")) {
    Write-Host " ✓ PASS" -ForegroundColor Green
    Write-Host "   Current: $execPolicy" -ForegroundColor Gray
}
else {
    Write-Host " ⚠ WARNING" -ForegroundColor Yellow
    Write-Host "   Current: $execPolicy" -ForegroundColor Yellow
    Write-Host "   Required: RemoteSigned or Unrestricted" -ForegroundColor Yellow
    Write-Host "   Run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Cyan
}

# 3. Check required modules
Write-Host "`n3. Checking required modules..."
$requiredModules = @(
    @{ Name = "ExchangeOnlineManagement"; MinimumVersion = "3.0.0" },
    @{ Name = "Microsoft.Graph.Authentication"; MinimumVersion = "2.0.0" }
)

foreach ($module in $requiredModules) {
    Write-Host "   Checking $($module.Name)..." -NoNewline
    $installed = Get-Module -ListAvailable -Name $module.Name | Sort-Object Version -Descending | Select-Object -First 1
    
    if ($installed) {
        if ($installed.Version -ge $module.MinimumVersion) {
            Write-Host " ✓ $($installed.Version)" -ForegroundColor Green
        }
        else {
            Write-Host " ⚠ v$($installed.Version) (Update recommended)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host " ✗ Not installed" -ForegroundColor Red
        Write-Host "      Install: Install-Module $($module.Name) -Scope CurrentUser" -ForegroundColor Cyan
        $allPassed = $false
    }
}

# 4. Check admin privileges (not required but recommended)
Write-Host "`n4. Checking platform..." -NoNewline
if ($IsMacOS) {
    Write-Host " ✓ macOS" -ForegroundColor Green
}
elseif ($IsLinux) {
    Write-Host " ✓ Linux" -ForegroundColor Green
}
elseif ($IsWindows) {
    Write-Host " ✓ Windows" -ForegroundColor Green
}
else {
    Write-Host " ? Unknown" -ForegroundColor Yellow
}

# 5. Check Node.js (for presentations)
Write-Host "`n5. Checking Node.js (for branded presentations)..." -NoNewline
try {
    $nodeVersion = & node --version 2>$null
    if ($nodeVersion) {
        Write-Host " ✓ $nodeVersion" -ForegroundColor Green
    }
    else {
        Write-Host " ⚠ Not found (optional, needed for PPTX generation)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host " ⚠ Not found (optional, needed for PPTX generation)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "✓ All critical checks passed!" -ForegroundColor Green
    Write-Host "`nYou can now run: .\Run-Investigation-Collector.ps1" -ForegroundColor White
}
else {
    Write-Host "✗ Some checks failed. Please install missing prerequisites." -ForegroundColor Red
}
Write-Host "══════════════════════════════════════════════════════════════`n" -ForegroundColor Cyan
