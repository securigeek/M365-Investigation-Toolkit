Set-StrictMode -Version Latest

function Resolve-InvestigationPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (Test-Path $Path) {
        return (Resolve-Path $Path).Path
    }

    $item = New-Item -ItemType Directory -Path $Path -Force
    return $item.FullName
}

function Write-InvestigationJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Data
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        Resolve-InvestigationPath -Path $parent | Out-Null
    }

    $Data | ConvertTo-Json -Depth 100 -WarningAction SilentlyContinue | Set-Content $Path
    return $Path
}

function Read-InvestigationJsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return Get-Content $Path -Raw | ConvertFrom-Json
}
