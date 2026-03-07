<#
.SYNOPSIS
    Branded PowerPoint presentation generator for investigation results
.DESCRIPTION
    Generates executive presentations with Securigeek or Cydenti branding
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InvestigationPath,
    
    [Parameter()]
    [string]$OutputFileName = "Executive-Summary-Branded.pptx",
    
    [Parameter()]
    [string]$Brand = "",  # Will prompt if empty
    
    [Parameter()]
    [switch]$IncludeLogo
)

Set-StrictMode -Version Latest

# Source the branding module
. (Join-Path $PSScriptRoot "branding.ps1")

function New-BrandedExecutivePresentation {
    param(
        [string]$InvestigationPath,
        [string]$OutputFileName,
        [string]$BrandOverride
    )
    
    # Select brand
    if ([string]::IsNullOrWhiteSpace($BrandOverride)) {
        $brandConfig = Select-InvestigationBrand -DefaultBrand "Securigeek"
    }
    else {
        $script:CurrentBrand = $script:BrandConfigs[$BrandOverride]
        $brandConfig = Get-CurrentBrand
    }
    
    Write-Host "`n=== Generating Branded Presentation ===" -ForegroundColor Cyan
    Write-Host "Brand: $($brandConfig.FullName)" -ForegroundColor White
    Write-Host "Output: $OutputFileName" -ForegroundColor Gray
    
    # Read investigation data
    $verdictPath = Join-Path $InvestigationPath "verdict.json"
    $findingsPath = Join-Path $InvestigationPath "findings-summary.json"
    
    if (-not (Test-Path $verdictPath)) {
        throw "Investigation verdict not found: $verdictPath"
    }
    
    $verdict = Get-Content $verdictPath | ConvertFrom-Json
    $findings = if (Test-Path $findingsPath) { 
        Get-Content $findingsPath | ConvertFrom-Json 
    } else { $null }
    
    # Create presentation directory
    $presDir = Join-Path $InvestigationPath "presentation-branded"
    if (-not (Test-Path $presDir)) {
        New-Item -ItemType Directory -Path $presDir -Force | Out-Null
    }
    
    # Export brand config for JS generator
    $brandConfigPath = Join-Path $presDir "brand-config.json"
    Export-BrandConfiguration -OutputPath $brandConfigPath
    
    # Generate branded HTML slides
    Write-Host "`nCreating branded slides..." -ForegroundColor Gray
    
    New-BrandedTitleSlide -OutputPath (Join-Path $presDir "slide1.html") -Verdict $verdict -Brand $brandConfig
    New-BrandedSummarySlide -OutputPath (Join-Path $presDir "slide2.html") -Verdict $verdict -Findings $findings -Brand $brandConfig
    New-BrandedFindingsSlide -OutputPath (Join-Path $presDir "slide3.html") -Verdict $verdict -Findings $findings -Brand $brandConfig
    New-BrandedRecommendationsSlide -OutputPath (Join-Path $presDir "slide4.html") -Brand $brandConfig
    New-BrandedClosingSlide -OutputPath (Join-Path $presDir "slide5.html") -Brand $brandConfig
    
    # Create Node.js generator script
    $generatorScript = New-BrandedPptxGeneratorScript -SlideDir $presDir -OutputFile (Join-Path $InvestigationPath $OutputFileName) -Brand $brandConfig
    $generatorPath = Join-Path $presDir "generate-branded.js"
    $generatorScript | Out-File -FilePath $generatorPath -Encoding UTF8
    
    Write-Host "`n✅ Branded presentation source files created!" -ForegroundColor Green
    Write-Host "Location: $presDir" -ForegroundColor Gray
    Write-Host "`nTo generate the PowerPoint file, run:" -ForegroundColor Yellow
    Write-Host "  cd '$presDir'" -ForegroundColor White
    Write-Host "  node generate-branded.js" -ForegroundColor White
    
    return @{
        Brand = $brandConfig.Name
        SlideDirectory = $presDir
        GeneratorScript = $generatorPath
        OutputFile = Join-Path $InvestigationPath $OutputFileName
    }
}

function New-BrandedTitleSlide {
    param($OutputPath, $Verdict, $Brand)
    
    $severity = $Verdict.Severity
    $severityColor = switch ($severity) {
        "High" { $Brand.RiskColors.High }
        "Medium" { $Brand.RiskColors.Medium }
        "Low" { $Brand.RiskColors.Low }
        default { $Brand.AccentColor }
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: $($Brand.PrimaryColor); }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: $($Brand.PrimaryColor); font-family: $($Brand.BodyFont), Arial, sans-serif;
  display: flex; flex-direction: column; justify-content: center; align-items: center;
}
.logo-area {
  position: absolute; top: 20pt; left: 40pt;
}
.logo-text { color: #ffffff; font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 18pt; font-weight: bold; margin: 0; }
.title-box {
  background: $($Brand.AccentColor); padding: 35pt 50pt; border-radius: 12pt;
  text-align: center;
}
h1 { color: #ffffff; font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 32pt; margin: 0 0 15pt 0; }
h2 { color: #e8f5d6; font-family: $($Brand.BodyFont), Arial, sans-serif; font-size: 18pt; margin: 0 0 20pt 0; font-weight: normal; }
.date-text { color: #a0aec0; font-size: 12pt; margin: 0; }
.severity-badge {
  background: $severityColor; padding: 10pt 25pt; border-radius: 6pt;
  margin-top: 25pt;
}
.severity-text { color: #ffffff; font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 22pt; font-weight: bold; margin: 0; }
.tagline {
  position: absolute; bottom: 20pt;
  color: #a0aec0; font-size: 11pt; font-style: italic; margin: 0;
}
</style>
</head>
<body>
<div class="logo-area">
  <p class="logo-text">$($Brand.FullName)</p>
</div>
<div class="title-box">
  <h1>Rapport d'Investigation</h1>
  <h2>Security Assessment - Executive Summary</h2>
  <p class="date-text">$(Get-Date -Format 'MMMM dd, yyyy')</p>
</div>
<div class="severity-badge">
  <p class="severity-text">$severity RISK DETECTED</p>
</div>
<p class="tagline">$($Brand.Tagline)</p>
</body>
</html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-BrandedSummarySlide {
    param($OutputPath, $Verdict, $Findings, $Brand)
    
    $score = $Verdict.Score
    $findingsCount = if ($Findings) { $Findings.TopDetections.Count } else { 0 }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: $($Brand.BackgroundColor); }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: $($Brand.BackgroundColor); font-family: $($Brand.BodyFont), Arial, sans-serif;
  display: flex; flex-direction: column;
}
.header {
  background: $($Brand.PrimaryColor); padding: 15pt 40pt;
}
h1 { color: #ffffff; font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 22pt; margin: 0; }
.content {
  padding: 20pt 40pt 40pt 40pt; flex: 1;
}
.metrics-grid {
  display: flex; gap: 15pt; margin-bottom: 15pt;
}
.metric-box {
  flex: 1; background: #ffffff; padding: 15pt;
  border-radius: 6pt; border-left: 4pt solid $($Brand.AccentColor);
  box-shadow: 0 2pt 6pt rgba(0,0,0,0.08);
}
.metric-number { font-size: 28pt; font-weight: bold; color: $($Brand.PrimaryColor); margin: 0 0 5pt 0; font-family: $($Brand.HeadingFont), Arial, sans-serif; }
.metric-label { font-size: 10pt; color: $($Brand.TextColor); margin: 0; }
.verdict-box {
  background: #ffffff; padding: 15pt; border-radius: 6pt;
  border-left: 4pt solid $($Brand.RiskColors.High);
}
h3 { color: $($Brand.PrimaryColor); font-size: 14pt; margin: 0 0 10pt 0; font-family: $($Brand.HeadingFont), Arial, sans-serif; }
p { color: $($Brand.TextColor); font-size: 11pt; margin: 0; line-height: 1.5; }
</style>
</head>
<body>
<div class="header">
  <h1>Résumé de l'Investigation</h1>
</div>
<div class="content">
  <div class="metrics-grid">
    <div class="metric-box">
      <p class="metric-number">$score</p>
      <p class="metric-label">Risk Score</p>
    </div>
    <div class="metric-box">
      <p class="metric-number">$($Verdict.Severity)</p>
      <p class="metric-label">Severity Level</p>
    </div>
    <div class="metric-box">
      <p class="metric-number">$findingsCount</p>
      <p class="metric-label">Detections</p>
    </div>
    <div class="metric-box">
      <p class="metric-number">14</p>
      <p class="metric-label">Modules Analyzed</p>
    </div>
  </div>
  <div class="verdict-box">
    <h3>Verdict</h3>
    <p>$($Verdict.TopFindings)</p>
  </div>
</div>
</body>
</html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-BrandedFindingsSlide {
    param($OutputPath, $Verdict, $Findings, $Brand)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: #fef2f2; }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: #fef2f2; font-family: $($Brand.BodyFont), Arial, sans-serif;
  display: flex; flex-direction: column;
}
.header {
  background: $($Brand.RiskColors.High); padding: 15pt 40pt;
}
h1 { color: #ffffff; font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 22pt; margin: 0; }
.content {
  padding: 20pt 40pt 40pt 40pt; flex: 1;
}
.finding-card {
  background: #ffffff; padding: 15pt; border-radius: 6pt;
  margin-bottom: 12pt; border-left: 4pt solid $($Brand.RiskColors.High);
}
h3 { color: $($Brand.RiskColors.High); font-size: 14pt; margin: 0 0 8pt 0; font-family: $($Brand.HeadingFont), Arial, sans-serif; }
p { color: $($Brand.TextColor); font-size: 11pt; margin: 0 0 6pt 0; line-height: 1.4; }
.action-box {
  background: #fee2e2; padding: 12pt; border-radius: 4pt;
  margin-top: 10pt;
}
.action-title { color: #991b1b; font-size: 10pt; font-weight: bold; margin: 0 0 5pt 0; }
.action-text { color: #7f1d1d; font-size: 10pt; margin: 0; }
</style>
</head>
<body>
<div class="header">
  <h1>Principales Découvertes</h1>
</div>
<div class="content">
  <div class="finding-card">
    <h3>Abus de Consentement OAuth</h3>
    <p>Autorisation accordée à <b>Microsoft Graph</b> avec des permissions dangereuses permettant l'accès aux boîtes mail.</p>
    <div class="action-box">
      <p class="action-title">Action Requise:</p>
      <p class="action-text">Révoquer immédiatement le consentement non autorisé et auditer toutes les autorisations OAuth.</p>
    </div>
  </div>
  <div class="finding-card">
    <h3>Règles de Boîte de Réception Suspectes</h3>
    <p>5 règles détectées effectuant du transfert, de la redirection ou de la suppression automatique.</p>
    <div class="action-box">
      <p class="action-title">Action Requise:</p>
      <p class="action-text">Examiner et désactiver les règles non autorisées. Mécanisme de persistance typique des attaques BEC.</p>
    </div>
  </div>
</div>
</body>
</html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-BrandedRecommendationsSlide {
    param($OutputPath, $Brand)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: #eff6ff; }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: #eff6ff; font-family: $($Brand.BodyFont), Arial, sans-serif;
  display: flex; flex-direction: column;
}
.header {
  background: $($Brand.PrimaryColor); padding: 15pt 40pt;
}
h1 { color: #ffffff; font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 22pt; margin: 0; }
.content {
  padding: 20pt 40pt 40pt 40pt; flex: 1;
}
.priorities-grid {
  display: flex; gap: 15pt; margin-bottom: 15pt;
}
.priority-box {
  flex: 1; background: #ffffff; padding: 15pt;
  border-radius: 6pt;
}
.immediate { border-top: 3pt solid $($Brand.RiskColors.High); }
.short-term { border-top: 3pt solid $($Brand.RiskColors.Medium); }
.monitoring { border-top: 3pt solid $($Brand.AccentColor); }
h3 { font-size: 13pt; margin: 0 0 10pt 0; font-family: $($Brand.HeadingFont), Arial, sans-serif; }
.immediate h3 { color: $($Brand.RiskColors.High); }
.short-term h3 { color: $($Brand.RiskColors.Medium); }
.monitoring h3 { color: $($Brand.AccentColor); }
ul { margin: 0; padding-left: 16pt; }
li { color: $($Brand.TextColor); font-size: 10pt; margin-bottom: 5pt; line-height: 1.3; }
.contact-box {
  background: $($Brand.AccentColor); padding: 15pt; border-radius: 6pt;
  text-align: center;
}
h4 { color: #ffffff; font-size: 14pt; margin: 0 0 10pt 0; font-family: $($Brand.HeadingFont), Arial, sans-serif; }
.contact-text { color: #ffffff; font-size: 11pt; margin: 0; }
</style>
</head>
<body>
<div class="header">
  <h1>Recommandations</h1>
</div>
<div class="content">
  <div class="priorities-grid">
    <div class="priority-box immediate">
      <h3>Immédiat (24h)</h3>
      <ul>
        <li>Révoquer le consentement OAuth suspect</li>
        <li>Désactiver les règles de boîte mail</li>
        <li>Investiguer les connexions à risque</li>
      </ul>
    </div>
    <div class="priority-box short-term">
      <h3>Court Terme (7j)</h3>
      <ul>
        <li>Auditer les 32 autorisations OAuth</li>
        <li>Examiner les nouveaux SP</li>
        <li>Valider la configuration domaine</li>
      </ul>
    </div>
    <div class="priority-box monitoring">
      <h3>Surveillance</h3>
      <ul>
        <li>Monitoring continu des connexions</li>
        <li>Vérifications hebdomadaires</li>
        <li>Revues mensuelles OAuth</li>
      </ul>
    </div>
  </div>
  <div class="contact-box">
    <h4>Besoin d'Assistance?</h4>
    <p class="contact-text">$($Brand.Phone) | $($Brand.Email)</p>
  </div>
</div>
</body>
</html>
"@
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-BrandedClosingSlide {
    param($OutputPath, $Brand)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
<style>
html { background: $($Brand.PrimaryColor); }
body {
  width: 720pt; height: 405pt; margin: 0; padding: 0;
  background: $($Brand.PrimaryColor); font-family: $($Brand.BodyFont), Arial, sans-serif;
  display: flex; flex-direction: column; justify-content: center; align-items: center;
  text-align: center;
}
.closing-box {
  background: #ffffff; padding: 30pt 50pt; border-radius: 12pt;
  max-width: 500pt;
}
h1 { color: $($Brand.PrimaryColor); font-family: $($Brand.HeadingFont), Arial, sans-serif; font-size: 28pt; margin: 0 0 15pt 0; }
.tagline { color: $($Brand.AccentColor); font-size: 16pt; font-style: italic; margin: 0 0 20pt 0; }
.contact-grid {
  display: flex; gap: 20pt; justify-content: center; margin: 20pt 0;
}
.contact-item { text-align: center; }
.contact-label { color: #64748b; font-size: 10pt; margin: 0 0 5pt 0; }
.contact-value { color: $($Brand.PrimaryColor); font-size: 12pt; font-weight: bold; margin: 0; }
.labels-box {
  display: flex; gap: 8pt; justify-content: center; flex-wrap: wrap;
  margin-top: 20pt;
}
.label-badge {
  background: $($Brand.BorderColor); color: $($Brand.TextColor);
  padding: 4pt 10pt; border-radius: 12pt; font-size: 9pt;
}
</style>
</head>
<body>
<div class="closing-box">
  <h1>$($Brand.FullName)</h1>
  <p class="tagline">$($Brand.Tagline)</p>
  <div class="contact-grid">
    <div class="contact-item">
      <p class="contact-label">Téléphone</p>
      <p class="contact-value">$($Brand.Phone)</p>
    </div>
    <div class="contact-item">
      <p class="contact-label">Email</p>
      <p class="contact-value">$($Brand.Email)</p>
    </div>
  </div>
  <p style="color: #64748b; font-size: 10pt; margin: 0;">$($Brand.Address)</p>
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
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function New-BrandedPptxGeneratorScript {
    param($SlideDir, $OutputFile, $Brand)
    
    return @"
const pptxgen = require('pptxgenjs');
const html2pptx = require('/Users/addysharma/.agents/skills/powerpoint/scripts/html2pptx.js');
const path = require('path');

async function createBrandedPresentation() {
    const pptx = new pptxgen();
    pptx.layout = 'LAYOUT_16x9';
    pptx.author = '$($Brand.FullName)';
    pptx.title = 'Rapport d\'Investigation Cybersécurité';
    pptx.subject = 'Security Assessment';
    pptx.company = '$($Brand.FullName)';

    const baseDir = '$SlideDir';

    console.log('Generating $($Brand.FullName) branded presentation...');

    // Slide 1: Title
    console.log('Creating title slide...');
    await html2pptx(path.join(baseDir, 'slide1.html'), pptx);

    // Slide 2: Summary
    console.log('Creating summary slide...');
    await html2pptx(path.join(baseDir, 'slide2.html'), pptx);

    // Slide 3: Findings
    console.log('Creating findings slide...');
    await html2pptx(path.join(baseDir, 'slide3.html'), pptx);

    // Slide 4: Recommendations
    console.log('Creating recommendations slide...');
    await html2pptx(path.join(baseDir, 'slide4.html'), pptx);

    // Slide 5: Closing
    console.log('Creating closing slide...');
    await html2pptx(path.join(baseDir, 'slide5.html'), pptx);

    // Save
    await pptx.writeFile({ fileName: '$OutputFile' });
    console.log(`\n✅ Branded presentation created!`);
    console.log(`📄 Output: $OutputFile`);
}

createBrandedPresentation().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
"@
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = New-BrandedExecutivePresentation `
            -InvestigationPath $InvestigationPath `
            -OutputFileName $OutputFileName `
            -BrandOverride $Brand
        
        Write-Host "`n✨ Done! Next steps:" -ForegroundColor Cyan
        Write-Host "1. Review slides in: $($result.SlideDirectory)" -ForegroundColor White
        Write-Host "2. Run: node $($result.GeneratorScript)" -ForegroundColor White
        Write-Host "3. Output will be: $($result.OutputFile)" -ForegroundColor White
    }
    catch {
        Write-Error "Failed to generate presentation: $_"
        exit 1
    }
}
