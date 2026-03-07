Set-StrictMode -Version Latest

function Get-InvestigationRequiredModules {
    return @(
        [pscustomobject]@{ Name = "Microsoft.Graph.Authentication"; MinimumVersion = [version]"2.35.1" },
        [pscustomobject]@{ Name = "Microsoft.Graph.Applications"; MinimumVersion = [version]"2.35.1" },
        [pscustomobject]@{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; MinimumVersion = [version]"2.35.1" },
        [pscustomobject]@{ Name = "Microsoft.Graph.Identity.SignIns"; MinimumVersion = [version]"2.35.1" },
        [pscustomobject]@{ Name = "Microsoft.Graph.Reports"; MinimumVersion = [version]"2.35.1" },
        [pscustomobject]@{ Name = "ExchangeOnlineManagement"; MinimumVersion = [version]"3.9.2" }
    )
}

function Get-InstalledInvestigationModules {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$RequiredModules
    )

    return @(
        $RequiredModules |
            ForEach-Object {
                $installed = Get-Module -ListAvailable -Name $_.Name |
                    Sort-Object Version -Descending |
                    Select-Object -First 1

                if ($installed) {
                    [pscustomobject]@{
                        Name = $installed.Name
                        Version = [version]$installed.Version
                    }
                }
            }
    )
}

function Get-InvestigationBrowserCapability {
    $commandNames = @()
    if ($IsMacOS) {
        $commandNames += "open"
    } elseif ($IsWindows) {
        $commandNames += "Start-Process"
    } else {
        $commandNames += @("xdg-open", "gio")
    }

    foreach ($commandName in $commandNames) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($command) {
            return [pscustomobject]@{
                Supported = $true
                Method = $commandName
            }
        }
    }

    return [pscustomobject]@{
        Supported = $false
        Method = $null
    }
}

function Test-InvestigationPrerequisites {
    param(
        [Parameter(Mandatory = $true)]
        [version]$CurrentPwshVersion,

        [Parameter(Mandatory = $true)]
        [object[]]$RequiredModules,

        [Parameter(Mandatory = $true)]
        [object[]]$InstalledModules,

        [Parameter(Mandatory = $true)]
        [psobject]$BrowserCapability
    )

    $missingModules = @()
    $outdatedModules = @()

    foreach ($required in $RequiredModules) {
        $installed = $InstalledModules | Where-Object { $_.Name -eq $required.Name } | Select-Object -First 1
        if (-not $installed) {
            $missingModules += $required
            continue
        }

        if ([version]$installed.Version -lt [version]$required.MinimumVersion) {
            $outdatedModules += [pscustomobject]@{
                Name = $required.Name
                InstalledVersion = [version]$installed.Version
                MinimumVersion = [version]$required.MinimumVersion
            }
        }
    }

    $minimumPwshVersion = [version]"7.5.0"
    $ready = ($CurrentPwshVersion -ge $minimumPwshVersion) -and
        ($missingModules.Count -eq 0) -and
        ($outdatedModules.Count -eq 0) -and
        $BrowserCapability.Supported

    return [pscustomobject]@{
        Ready = $ready
        MinimumPwshVersion = $minimumPwshVersion
        CurrentPwshVersion = $CurrentPwshVersion
        MissingModules = $missingModules
        OutdatedModules = $outdatedModules
        Browser = $BrowserCapability
    }
}

function Get-InvestigationPrerequisiteStatus {
    $requiredModules = Get-InvestigationRequiredModules
    $installedModules = Get-InstalledInvestigationModules -RequiredModules $requiredModules
    $browserCapability = Get-InvestigationBrowserCapability

    return Test-InvestigationPrerequisites `
        -CurrentPwshVersion ([version]$PSVersionTable.PSVersion) `
        -RequiredModules $requiredModules `
        -InstalledModules $installedModules `
        -BrowserCapability $browserCapability
}

function Install-InvestigationModules {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Modules
    )

    foreach ($module in $Modules) {
        Install-Module -Name $module.Name -MinimumVersion $module.MinimumVersion -Scope CurrentUser -Force -AllowClobber
    }
}
