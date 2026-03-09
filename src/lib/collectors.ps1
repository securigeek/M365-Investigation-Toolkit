Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot "common.ps1")

function New-CollectorArtifactPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    $rawRoot = Resolve-InvestigationPath -Path (Join-Path $OutputPath "raw")
    $normalizedRoot = Resolve-InvestigationPath -Path (Join-Path $OutputPath "normalized")

    return [pscustomobject]@{
        RawPath = Join-Path $rawRoot "$ModuleName.json"
        NormalizedPath = Join-Path $normalizedRoot "$ModuleName.json"
    }
}

function New-CollectorResult {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("success", "partial", "failed", "skipped")]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$RawPath,

        [Parameter(Mandatory = $true)]
        [string]$NormalizedPath,

        [Parameter()]
        [object]$Data,

        [Parameter()]
        [hashtable]$Metrics,

        [Parameter()]
        [string]$ErrorMessage,

        [Parameter()]
        [string[]]$Warnings,

        [Parameter()]
        [string[]]$Gaps
    )

    $resolvedWarnings = @(
        $Warnings |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    )

    $resolvedGaps = @(
        $Gaps |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    )

    return [pscustomobject]@{
        Module = $ModuleName
        Status = $Status
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        RawPath = $RawPath
        NormalizedPath = $NormalizedPath
        Metrics = if ($Metrics) { [pscustomobject]$Metrics } else { [pscustomobject]@{} }
        Error = if ([string]::IsNullOrWhiteSpace($ErrorMessage)) { $null } else { $ErrorMessage }
        Warnings = $resolvedWarnings
        Gaps = $resolvedGaps
        Data = $Data
    }
}

function Publish-CollectorArtifacts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter()]
        [object]$RawData,

        [Parameter()]
        [object]$NormalizedData,

        [Parameter()]
        [hashtable]$Metrics,

        [Parameter()]
        [ValidateSet("success", "partial", "failed", "skipped")]
        [string]$Status = "success",

        [Parameter()]
        [string]$ErrorMessage,

        [Parameter()]
        [string[]]$Warnings,

        [Parameter()]
        [string[]]$Gaps
    )

    $paths = New-CollectorArtifactPaths -OutputPath $OutputPath -ModuleName $ModuleName
    Write-InvestigationJsonFile -Path $paths.RawPath -Data $(if ($null -ne $RawData) { $RawData } else { [pscustomobject]@{} }) | Out-Null
    Write-InvestigationJsonFile -Path $paths.NormalizedPath -Data $(if ($null -ne $NormalizedData) { $NormalizedData } else { [pscustomobject]@{} }) | Out-Null

    return New-CollectorResult `
        -ModuleName $ModuleName `
        -Status $Status `
        -RawPath $paths.RawPath `
        -NormalizedPath $paths.NormalizedPath `
        -Data $NormalizedData `
        -Metrics $Metrics `
        -ErrorMessage $ErrorMessage `
        -Warnings $Warnings `
        -Gaps $Gaps
}

# Function to handle collector errors
function Publish-CollectorError {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [object]$Error
    )
    
    $errorMessage = $Error.Exception.Message
    if (-not $errorMessage) {
        $errorMessage = $Error.ToString()
    }
    
    Write-Host "⚠️ Collector '$ModuleName' failed: $errorMessage" -ForegroundColor Yellow
    
    return Publish-CollectorArtifacts `
        -OutputPath $OutputPath `
        -ModuleName $ModuleName `
        -RawData $null `
        -NormalizedData $null `
        -Metrics @{ Error = $errorMessage } `
        -Status "failed" `
        -ErrorMessage $errorMessage
}

# Function to handle successful collector results
function Publish-CollectorSuccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter()]
        [object]$RawData,
        
        [Parameter()]
        [object]$NormalizedData,
        
        [Parameter()]
        [hashtable]$Metrics,
        
        [Parameter()]
        [string[]]$Warnings
    )
    
    return Publish-CollectorArtifacts `
        -OutputPath $OutputPath `
        -ModuleName $ModuleName `
        -RawData $RawData `
        -NormalizedData $NormalizedData `
        -Metrics $Metrics `
        -Status "success" `
        -Warnings $Warnings
}
