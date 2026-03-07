Set-StrictMode -Version Latest

function ConvertTo-ForensicPropertyMap {
    param(
        [Parameter()]
        [object[]]$Properties
    )

    $map = @{}

    foreach ($property in @($Properties)) {
        if ($null -eq $property) {
            continue
        }

        $name = $null
        if ($property.PSObject.Properties.Name -contains "Name" -and $property.Name) {
            $name = [string]$property.Name
        } elseif ($property.PSObject.Properties.Name -contains "DisplayName" -and $property.DisplayName) {
            $name = [string]$property.DisplayName
        }

        if (-not $name) {
            continue
        }

        $value = $null
        foreach ($candidate in @("Value", "NewValue", "OldValue")) {
            if ($property.PSObject.Properties.Name -contains $candidate) {
                $value = $property.$candidate
                break
            }
        }

        $map[$name] = $value
    }

    return [pscustomobject]$map
}

function Resolve-ForensicActor {
    param(
        [Parameter()]
        [psobject]$Record
    )

    if ($Record.PSObject.Properties.Name -contains "Actor" -and $Record.Actor) {
        return [string]$Record.Actor
    }
    if ($Record.PSObject.Properties.Name -contains "InitiatedBy" -and $Record.InitiatedBy) {
        if ($Record.InitiatedBy.User -and $Record.InitiatedBy.User.UserPrincipalName) {
            return [string]$Record.InitiatedBy.User.UserPrincipalName
        }
        if ($Record.InitiatedBy.User -and $Record.InitiatedBy.User.DisplayName) {
            return [string]$Record.InitiatedBy.User.DisplayName
        }
        if ($Record.InitiatedBy.App -and $Record.InitiatedBy.App.DisplayName) {
            return [string]$Record.InitiatedBy.App.DisplayName
        }
    }

    return $null
}

function Resolve-ForensicTarget {
    param(
        [Parameter()]
        [object[]]$Targets
    )

    $target = @($Targets | Select-Object -First 1)[0]
    if (-not $target) {
        return [pscustomobject]@{
            Name = $null
            Id = $null
            Type = $null
        }
    }

    return [pscustomobject]@{
        Name = if ($target.PSObject.Properties.Name -contains "DisplayName") { $target.DisplayName } else { $null }
        Id = if ($target.PSObject.Properties.Name -contains "Id") { $target.Id } else { $null }
        Type = if ($target.PSObject.Properties.Name -contains "Type") { $target.Type } else { $null }
    }
}

function Resolve-ForensicAuthenticationProtocol {
    param(
        [Parameter()]
        [object]$Protocol
    )

    if ($null -eq $Protocol -or [string]::IsNullOrWhiteSpace([string]$Protocol)) {
        return "unknown"
    }

    return [string]$Protocol
}

function Get-ForensicTimeBucketKey {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Timestamp,

        [Parameter()]
        [int]$WindowSeconds = 3
    )

    $utc = $Timestamp.ToUniversalTime()
    $epoch = [DateTimeOffset]::FromUnixTimeSeconds(0)
    $bucketStartSeconds = [math]::Floor((([DateTimeOffset]$utc) - $epoch).TotalSeconds / $WindowSeconds) * $WindowSeconds

    return ([DateTimeOffset]::FromUnixTimeSeconds([int64]$bucketStartSeconds)).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
}

function Get-ForensicDormancyDays {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$LastSeen,

        [Parameter()]
        [datetime]$ReferenceTime = (Get-Date).ToUniversalTime()
    )

    return [int][math]::Floor(($ReferenceTime.ToUniversalTime() - $LastSeen.ToUniversalTime()).TotalDays)
}
