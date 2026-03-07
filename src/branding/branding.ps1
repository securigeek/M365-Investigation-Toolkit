<#
.SYNOPSIS
    Brand configuration and styling for investigation presentations
.DESCRIPTION
    Manages brand guidelines for Securigeek and Cydenti companies.
    Prompts for company selection and provides brand assets/colors.
#>

Set-StrictMode -Version Latest

# Brand configurations
$script:BrandConfigs = @{
    "Securigeek" = @{
        Name = "Securigeek"
        FullName = "SecuriGeek"
        Tagline = "Simplifiez votre cybersécurité. Protégez votre avenir."
        PrimaryColor = "#2A3444"      # Charcoal Navy
        AccentColor = "#8CC63F"       # Securigeek Green
        BackgroundColor = "#FFFFFF"   # White
        TextColor = "#344155"         # Slate
        BorderColor = "#F1F5F9"       # Light Gray
        HeadingFont = "Lexend"
        BodyFont = "Source Sans 3"
        LogoUrl = "https://securigeek.com/logo/securigeekh.png"
        LogoIconUrl = "https://securigeek.com/logo/securigeek.png"
        Language = "fr-FR"
        Address = "14 Av. de l'Europe, 77144 Montévrain"
        Phone = "01 87 07 94 86"
        Email = "contact@securigeek.com"
        Labels = @("France Cybersecurity Label", "JEI", "BPI France", "ANSSI Visa", "ACN")
        Founded = "2021"
        Services = @("Audit 360°", "Pentest", "SOC Managé 24/7", "Sécurité Cloud", "Audit IAM", "Audit Web & API")
        Tone = "Professional, medium energy - authoritative but approachable"
        RiskColors = @{
            High = "#dc2626"
            Medium = "#f59e0b"
            Low = "#8CC63F"
            Info = "#3b82f6"
        }
    }
    "Cydenti" = @{
        Name = "Cydenti"
        FullName = "Cydenti"
        Tagline = "Identity-First Security"
        PrimaryColor = "#1e3a5f"      # Deep Navy
        AccentColor = "#00d4aa"       # Teal
        BackgroundColor = "#FFFFFF"
        TextColor = "#1f2937"
        BorderColor = "#e5e7eb"
        HeadingFont = "Inter"
        BodyFont = "Inter"
        LogoUrl = ""
        LogoIconUrl = ""
        Language = "en-US"
        Address = ""
        Phone = ""
        Email = ""
        Labels = @()
        Founded = ""
        Services = @()
        Tone = "Professional, technical"
        RiskColors = @{
            High = "#dc2626"
            Medium = "#f59e0b"
            Low = "#00d4aa"
            Info = "#3b82f6"
        }
    }
}

$script:CurrentBrand = $null

function Get-AvailableBrands {
    return @($script:BrandConfigs.Keys | Sort-Object)
}

function Select-InvestigationBrand {
    param(
        [Parameter()]
        [string]$DefaultBrand = "Securigeek"
    )

    $brands = Get-AvailableBrands
    
    Write-Host "`n=== Brand Selection ===" -ForegroundColor Cyan
    Write-Host "Which company is this presentation for?" -ForegroundColor White
    Write-Host ""
    
    for ($i = 0; $i -lt $brands.Count; $i++) {
        $brand = $brands[$i]
        $config = $script:BrandConfigs[$brand]
        $marker = if ($brand -eq $DefaultBrand) { " (default)" } else { "" }
        Write-Host "  [$($i+1)] $brand$marker" -ForegroundColor Gray
        Write-Host "      Tagline: $($config.Tagline)" -ForegroundColor DarkGray
    }
    
    Write-Host ""
    $selection = Read-Host "Enter number (1-$($brands.Count)) or press Enter for [$DefaultBrand]"
    
    if ([string]::IsNullOrWhiteSpace($selection)) {
        $selectedBrand = $DefaultBrand
    }
    else {
        $index = [int]$selection - 1
        if ($index -ge 0 -and $index -lt $brands.Count) {
            $selectedBrand = $brands[$index]
        }
        else {
            Write-Warning "Invalid selection. Using default: $DefaultBrand"
            $selectedBrand = $DefaultBrand
        }
    }
    
    $script:CurrentBrand = $script:BrandConfigs[$selectedBrand]
    
    Write-Host "`n✓ Selected brand: " -NoNewline -ForegroundColor Green
    Write-Host "$selectedBrand" -ForegroundColor White
    Write-Host "  Primary: $($script:CurrentBrand.PrimaryColor)" -ForegroundColor DarkGray
    Write-Host "  Accent:  $($script:CurrentBrand.AccentColor)" -ForegroundColor DarkGray
    
    return $script:CurrentBrand
}

function Get-CurrentBrand {
    if ($null -eq $script:CurrentBrand) {
        $script:CurrentBrand = $script:BrandConfigs["Securigeek"]
    }
    return $script:CurrentBrand
}

function Get-BrandColor {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Primary", "Accent", "Background", "Text", "Border", "High", "Medium", "Low", "Info")]
        [string]$ColorName
    )
    
    $brand = Get-CurrentBrand
    
    switch ($ColorName) {
        "Primary"   { return $brand.PrimaryColor }
        "Accent"    { return $brand.AccentColor }
        "Background" { return $brand.BackgroundColor }
        "Text"      { return $brand.TextColor }
        "Border"    { return $brand.BorderColor }
        "High"      { return $brand.RiskColors.High }
        "Medium"    { return $brand.RiskColors.Medium }
        "Low"       { return $brand.RiskColors.Low }
        "Info"      { return $brand.RiskColors.Info }
        default     { return $brand.PrimaryColor }
    }
}

function Export-BrandConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $brand = Get-CurrentBrand
    $brand | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    return $OutputPath
}
