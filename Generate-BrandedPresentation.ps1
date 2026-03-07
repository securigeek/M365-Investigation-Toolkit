#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Generate a branded executive presentation from investigation results
.DESCRIPTION
    Prompts for company brand (Securigeek or Cydenti) and creates a styled PowerPoint presentation
.EXAMPLE
    .\Generate-BrandedPresentation.ps1 -InvestigationPath "./output/incidents/case-001"
.EXAMPLE
    .\Generate-BrandedPresentation.ps1 -InvestigationPath "./output/incidents/case-001" -Brand "Securigeek"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to investigation output folder")]
    [string]$InvestigationPath,
    
    [Parameter(HelpMessage="Output filename (optional)")]
    [string]$OutputFileName = "",
    
    [Parameter(HelpMessage="Brand name (Securigeek or Cydenti)")]
    [ValidateSet("Securigeek", "Cydenti")]
    [string]$Brand = "",
    
    [Parameter(HelpMessage="Skip brand selection prompt")]
    [switch]$SkipPrompt
)

$ErrorActionPreference = "Stop"

# Source branding module
$brandingPath = Join-Path $PSScriptRoot "src/branding/branding.ps1"
if (-not (Test-Path $brandingPath)) {
    throw "Branding module not found: $brandingPath"
}
. $brandingPath

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║     M365 Investigation - Branded Presentation Generator      ║
╚══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

# Get available brands
$brands = Get-AvailableBrands

# Brand selection
if ($SkipPrompt -and -not [string]::IsNullOrWhiteSpace($Brand)) {
    $selectedBrand = $Brand
    Write-Host "Using specified brand: $selectedBrand" -ForegroundColor Gray
}
elseif ([string]::IsNullOrWhiteSpace($Brand)) {
    Write-Host "Which company is this presentation for?" -ForegroundColor White
    Write-Host ""
    for ($i = 0; $i -lt $brands.Count; $i++) {
        $isDefault = if ($brands[$i] -eq "Securigeek") { " (default)" } else { "" }
        Write-Host "  [$($i+1)] $($brands[$i])$isDefault" -ForegroundColor Gray
    }
    Write-Host ""
    $selection = Read-Host "Enter number (1-$($brands.Count)) or press Enter for Securigeek"
    
    if ([string]::IsNullOrWhiteSpace($selection)) {
        $selectedBrand = "Securigeek"
    }
    else {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $brands.Count) {
            $selectedBrand = $brands[$index]
        }
        else {
            Write-Warning "Invalid selection. Using default: Securigeek"
            $selectedBrand = "Securigeek"
        }
    }
}
else {
    $selectedBrand = $Brand
}

# Set the brand
$script:CurrentBrand = $script:BrandConfigs[$selectedBrand]
$brand = Get-CurrentBrand

Write-Host "`n✓ Selected brand: " -NoNewline -ForegroundColor Green
Write-Host "$selectedBrand" -ForegroundColor White
Write-Host "  Primary: $($brand.PrimaryColor) | Accent: $($brand.AccentColor)" -ForegroundColor DarkGray

# Verify investigation path
if (-not (Test-Path $InvestigationPath)) {
    throw "Investigation path not found: $InvestigationPath"
}

$verdictPath = Join-Path $InvestigationPath "verdict.json"
if (-not (Test-Path $verdictPath)) {
    throw "Investigation verdict not found: $verdictPath`nRun an investigation first using Run-Investigation-Collector.ps1"
}

# Read verdict
$verdict = Get-Content $verdictPath | ConvertFrom-Json
Write-Host "`nInvestigation Summary:" -ForegroundColor Yellow
Write-Host "  Severity: $($verdict.Severity)" -ForegroundColor $(if ($verdict.Severity -eq "High") { "Red" } else { "White" })
Write-Host "  Score: $($verdict.Score)" -ForegroundColor White
Write-Host "  Top Finding: $($verdict.TopFindings)" -ForegroundColor White

# Create output filename
if ([string]::IsNullOrWhiteSpace($OutputFileName)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputFileName = "$selectedBrand-Executive-Summary-$timestamp.pptx"
}

# Create branded presentation directory
$presDir = Join-Path $InvestigationPath "presentation-$($brand.Name.ToLower())"
if (-not (Test-Path $presDir)) {
    New-Item -ItemType Directory -Path $presDir -Force | Out-Null
}

Write-Host "`nGenerating branded slides..." -ForegroundColor Gray

# Generate HTML slides with brand styling
# Slide 1: Title
$slide1 = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: $($brand.PrimaryColor); }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: $($brand.PrimaryColor); font-family: Arial, sans-serif;
  display: flex; flex-direction: column; justify-content: center; align-items: center;
}
.logo-area { position: absolute; top: 20pt; left: 40pt; }
.logo-text { color: #ffffff; font-size: 20pt; font-weight: bold; margin: 0; }
.title-box {
  background: $($brand.AccentColor); padding: 35pt 50pt; border-radius: 12pt; text-align: center;
}
h1 { color: #ffffff; font-size: 32pt; margin: 0 0 15pt 0; }
h2 { color: #f0fdf4; font-size: 18pt; margin: 0 0 15pt 0; font-weight: normal; }
.date-text { color: #a0aec0; font-size: 12pt; margin: 0; }
.severity-badge {
  background: $(if ($verdict.Severity -eq "High") { "#dc2626" } else { $brand.AccentColor }); 
  padding: 12pt 25pt; border-radius: 6pt; margin-top: 25pt;
}
.severity-text { color: #ffffff; font-size: 22pt; font-weight: bold; margin: 0; }
.tagline { position: absolute; bottom: 20pt; color: #94a3b8; font-size: 11pt; font-style: italic; margin: 0; }
</style>
</head>
<body>
<div class="logo-area"><p class="logo-text">$($brand.FullName)</p></div>
<div class="title-box">
  <h1>Rapport d'Investigation</h1>
  <h2>Security Assessment - Executive Summary</h2>
  <p class="date-text">$(Get-Date -Format 'dd MMMM yyyy')</p>
</div>
<div class="severity-badge">
  <p class="severity-text">$($verdict.Severity) RISK DETECTED</p>
</div>
<p class="tagline">$($brand.Tagline)</p>
</body>
</html>
"@
$slide1 | Out-File -FilePath (Join-Path $presDir "slide1.html") -Encoding UTF8

# Slide 2: Summary
$slide2 = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: $($brand.BackgroundColor); }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: $($brand.BackgroundColor); font-family: Arial, sans-serif;
  display: flex; flex-direction: column;
}
.header { background: $($brand.PrimaryColor); padding: 15pt 40pt; }
h1 { color: #ffffff; font-size: 22pt; margin: 0; }
.content { padding: 20pt 40pt 40pt 40pt; flex: 1; }
.metrics-grid { display: flex; gap: 15pt; margin-bottom: 15pt; }
.metric-box {
  flex: 1; background: #ffffff; padding: 15pt; border-radius: 6pt;
  border-left: 4pt solid $($brand.AccentColor); box-shadow: 0 2pt 6pt rgba(0,0,0,0.08);
}
.metric-number { font-size: 28pt; font-weight: bold; color: $($brand.PrimaryColor); margin: 0 0 5pt 0; }
.metric-label { font-size: 10pt; color: $($brand.TextColor); margin: 0; }
.verdict-box {
  background: #ffffff; padding: 15pt; border-radius: 6pt;
  border-left: 4pt solid $(if ($verdict.Severity -eq "High") { "#dc2626" } else { $brand.AccentColor });
}
h3 { color: $($brand.PrimaryColor); font-size: 14pt; margin: 0 0 10pt 0; }
p { color: $($brand.TextColor); font-size: 11pt; margin: 0; line-height: 1.5; }
</style>
</head>
<body>
<div class="header"><h1>Résumé de l'Investigation</h1></div>
<div class="content">
  <div class="metrics-grid">
    <div class="metric-box">
      <p class="metric-number">$($verdict.Score)</p>
      <p class="metric-label">Risk Score</p>
    </div>
    <div class="metric-box">
      <p class="metric-number">$($verdict.Severity)</p>
      <p class="metric-label">Severity Level</p>
    </div>
    <div class="metric-box">
      <p class="metric-number">$($verdict.CollectionGapCount)</p>
      <p class="metric-label">Collection Gaps</p>
    </div>
    <div class="metric-box">
      <p class="metric-number">14</p>
      <p class="metric-label">Modules Analyzed</p>
    </div>
  </div>
  <div class="verdict-box">
    <h3>Verdict</h3>
    <p>$($verdict.TopFindings)</p>
  </div>
</div>
</body>
</html>
"@
$slide2 | Out-File -FilePath (Join-Path $presDir "slide2.html") -Encoding UTF8

# Slide 3: Contact/Closing
$slide3 = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: $($brand.PrimaryColor); }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: $($brand.PrimaryColor); font-family: Arial, sans-serif;
  display: flex; flex-direction: column; justify-content: center; align-items: center;
  text-align: center;
}
.closing-box {
  background: #ffffff; padding: 30pt 50pt; border-radius: 12pt; max-width: 500pt;
}
h1 { color: $($brand.PrimaryColor); font-size: 28pt; margin: 0 0 15pt 0; }
.tagline { color: $($brand.AccentColor); font-size: 16pt; font-style: italic; margin: 0 0 20pt 0; }
.contact-grid { display: flex; gap: 25pt; justify-content: center; margin: 20pt 0; }
.contact-item { text-align: center; }
.contact-label { color: #64748b; font-size: 10pt; margin: 0 0 5pt 0; }
.contact-value { color: $($brand.PrimaryColor); font-size: 12pt; font-weight: bold; margin: 0; }
.labels-box { display: flex; gap: 8pt; justify-content: center; flex-wrap: wrap; margin-top: 20pt; }
.label-badge { background: #f1f5f9; color: #334155; padding: 4pt 10pt; border-radius: 12pt; font-size: 9pt; }
</style>
</head>
<body>
<div class="closing-box">
  <h1>$($brand.FullName)</h1>
  <p class="tagline">$($brand.Tagline)</p>
  <div class="contact-grid">
    <div class="contact-item">
      <p class="contact-label">Téléphone</p>
      <p class="contact-value">$($brand.Phone)</p>
    </div>
    <div class="contact-item">
      <p class="contact-label">Email</p>
      <p class="contact-value">$($brand.Email)</p>
    </div>
  </div>
  <p style="color: #64748b; font-size: 10pt; margin: 0;">$($brand.Address)</p>
  <div class="labels-box">
    <span class="label-badge">France Cybersecurity</span>
    <span class="label-badge">JEI</span>
    <span class="label-badge">BPI France</span>
    <span class="label-badge">ANSSI</span>
  </div>
</div>
</body>
</html>
"@
$slide3 | Out-File -FilePath (Join-Path $presDir "slide3.html") -Encoding UTF8

# Get absolute paths for Node.js
$absPresDir = (Resolve-Path $presDir).Path
$absOutputFile = Join-Path (Resolve-Path $InvestigationPath).Path $OutputFileName

# Create Node.js generator
$generatorJs = @"
const pptxgen = require('pptxgenjs');
const html2pptx = require('$($PSScriptRoot.Replace('\', '\\'))/src/lib/html2pptx.js');
const path = require('path');

async function createPresentation() {
    const pptx = new pptxgen();
    pptx.layout = 'LAYOUT_16x9';
    pptx.author = '$($brand.FullName)';
    pptx.title = "Rapport d'Investigation Cybersécurité";
    pptx.subject = 'Security Assessment';
    pptx.company = '$($brand.FullName)';

    const baseDir = '$($absPresDir.Replace('\', '\\'))';
    const outputFile = '$($absOutputFile.Replace('\', '\\'))';

    console.log('Generating $($brand.FullName) branded presentation...');

    await html2pptx(path.join(baseDir, 'slide1.html'), pptx);
    console.log('✓ Title slide');

    await html2pptx(path.join(baseDir, 'slide2.html'), pptx);
    console.log('✓ Summary slide');

    await html2pptx(path.join(baseDir, 'slide3.html'), pptx);
    console.log('✓ Closing slide');

    await pptx.writeFile({ fileName: outputFile });
    console.log('\\n✅ Presentation created: ' + outputFile);
}

createPresentation().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
"@
$generatorJs | Out-File -FilePath (Join-Path $presDir "generate.js") -Encoding UTF8

# Summary
Write-Host "`n=== Branded Presentation Ready ===" -ForegroundColor Green
Write-Host "Brand: $selectedBrand" -ForegroundColor White
Write-Host "Slides directory: $presDir" -ForegroundColor Gray
Write-Host "Generator: $(Join-Path $presDir "generate.js")" -ForegroundColor Gray
Write-Host "Output will be: $(Join-Path $InvestigationPath $OutputFileName)" -ForegroundColor Gray

Write-Host "`nTo generate the PowerPoint:" -ForegroundColor Yellow
Write-Host "  cd '$presDir'" -ForegroundColor White
Write-Host "  node generate.js" -ForegroundColor White

Write-Host "`n✨ Done!" -ForegroundColor Cyan

# Return object for programmatic use
return @{
    Brand = $selectedBrand
    SlideDirectory = $presDir
    GeneratorScript = Join-Path $presDir "generate.js"
    OutputFile = Join-Path $InvestigationPath $OutputFileName
}
