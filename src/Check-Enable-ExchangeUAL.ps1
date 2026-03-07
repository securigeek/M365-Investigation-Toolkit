<#
.SYNOPSIS
    Checks and enables Exchange Online Unified Audit Log (UAL) configuration.

.DESCRIPTION
    This script checks the current status of Exchange Online audit logging settings
    and optionally enables the Unified Audit Log if it's disabled.
    
    It performs the following actions:
    - Checks if ExchangeOnlineManagement module is installed and installs if missing
    - Connects to Exchange Online (prompts for credentials if not connected)
    - Checks current status of AdminAuditLogEnabled, UnifiedAuditLogIngestionEnabled, and AuditLogAgeLimit
    - Displays status with color coding (Green=Enabled, Red=Disabled)
    - Prompts user to enable UAL if disabled (unless -AutoEnable is specified)
    - Verifies changes were applied successfully

.PARAMETER AutoEnable
    If specified, automatically enables Unified Audit Log without prompting.
    Useful for automation scenarios.

.PARAMETER Organization
    The organization to connect to (tenant domain or ID). Optional if already connected.

.EXAMPLE
    .\Check-Enable-ExchangeUAL.ps1
    
    Checks UAL status and prompts to enable if disabled.

.EXAMPLE
    .\Check-Enable-ExchangeUAL.ps1 -AutoEnable
    
    Checks UAL status and automatically enables if disabled.

.EXAMPLE
    .\Check-Enable-ExchangeUAL.ps1 -Organization contoso.onmicrosoft.com
    
    Connects to specified tenant and checks UAL status.

.NOTES
    File Name      : Check-Enable-ExchangeUAL.ps1
    Author         : M365 Investigation Team
    Version        : 1.0
    Requires       : PowerShell 5.1 or later, ExchangeOnlineManagement module
    Prerequisites  : Exchange Online admin credentials

.LINK
    https://docs.microsoft.com/en-us/microsoft-365/compliance/turn-audit-log-search-on-or-off
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$AutoEnable,

    [Parameter()]
    [string]$Organization
)

# Initialize error action preference
$ErrorActionPreference = "Stop"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-StatusMessage {
    <#
    .SYNOPSIS
        Writes a formatted status message with color coding.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("Info", "Success", "Warning", "Error", "Verbose")]
        [string]$Type = "Info"
    )

    $colors = @{
        Info    = "White"
        Success = "Green"
        Warning = "Yellow"
        Error   = "Red"
        Verbose = "Gray"
    }

    $prefixes = @{
        Info    = "[*]"
        Success = "[+]"
        Warning = "[!]"
        Error   = "[X]"
        Verbose = "[>]"
    }

    $color = $colors[$Type]
    $prefix = $prefixes[$Type]

    if ($Type -eq "Verbose" -and -not $VerbosePreference) {
        return
    }

    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Test-ExchangeOnlineConnection {
    <#
    .SYNOPSIS
        Checks if already connected to Exchange Online.
    .OUTPUTS
        Boolean indicating connection status.
    #>
    try {
        $context = Get-ConnectionInformation -ErrorAction SilentlyContinue
        return ($null -ne $context -and $context.TenantId)
    }
    catch {
        return $false
    }
}

function Install-ExchangeOnlineModule {
    <#
    .SYNOPSIS
        Checks and installs ExchangeOnlineManagement module if missing.
    #>
    Write-StatusMessage -Message "Checking ExchangeOnlineManagement module..." -Type "Info"

    $moduleName = "ExchangeOnlineManagement"
    $module = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1

    if (-not $module) {
        Write-StatusMessage -Message "ExchangeOnlineManagement module not found. Installing..." -Type "Warning"
        
        try {
            # Check if running as administrator (required for system-wide install)
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            
            if ($isAdmin) {
                Install-Module -Name $moduleName -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
            }
            else {
                Write-StatusMessage -Message "Installing for current user only (run as admin for system-wide install)..." -Type "Verbose"
                Install-Module -Name $moduleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            }
            
            Write-StatusMessage -Message "ExchangeOnlineManagement module installed successfully" -Type "Success"
        }
        catch {
            throw "Failed to install ExchangeOnlineManagement module: $_"
        }
    }
    else {
        Write-StatusMessage -Message "ExchangeOnlineManagement module found (v$($module.Version))" -Type "Success"
        
        # Import the module
        try {
            Import-Module $moduleName -Force -ErrorAction Stop
            Write-StatusMessage -Message "Module imported successfully" -Type "Verbose"
        }
        catch {
            throw "Failed to import ExchangeOnlineManagement module: $_"
        }
    }
}

function Connect-ExchangeOnlineSession {
    <#
    .SYNOPSIS
        Establishes connection to Exchange Online.
    #>
    param([string]$Organization)

    Write-StatusMessage -Message "Checking Exchange Online connection..." -Type "Info"

    if (Test-ExchangeOnlineConnection) {
        $context = Get-ConnectionInformation
        Write-StatusMessage -Message "Already connected to: $($context.TenantDomain)" -Type "Success"
        Write-StatusMessage -Message "User: $($context.UserPrincipalName)" -Type "Verbose"
        return
    }

    Write-StatusMessage -Message "Not connected to Exchange Online. Initiating connection..." -Type "Warning"

    try {
        $connectParams = @{
            ShowBanner = $false
            ErrorAction = "Stop"
        }

        if ($Organization) {
            $connectParams['Organization'] = $Organization
            Write-StatusMessage -Message "Connecting to organization: $Organization" -Type "Info"
        }
        else {
            Write-StatusMessage -Message "Connecting (you will be prompted for credentials)..." -Type "Info"
        }

        Connect-ExchangeOnline @connectParams

        $context = Get-ConnectionInformation
        Write-StatusMessage -Message "Connected to: $($context.TenantDomain)" -Type "Success"
        Write-StatusMessage -Message "User: $($context.UserPrincipalName)" -Type "Verbose"
    }
    catch {
        throw "Failed to connect to Exchange Online: $_"
    }
}

function Get-AuditLogStatus {
    <#
    .SYNOPSIS
        Retrieves current audit log configuration status.
    .OUTPUTS
        PSCustomObject with audit configuration details.
    #>
    Write-StatusMessage -Message "Retrieving current audit log configuration..." -Type "Info"

    try {
        $config = Get-AdminAuditLogConfig -ErrorAction Stop
        
        return [PSCustomObject]@{
            AdminAuditLogEnabled           = $config.AdminAuditLogEnabled
            UnifiedAuditLogIngestionEnabled = $config.UnifiedAuditLogIngestionEnabled
            AuditLogAgeLimit               = $config.AuditLogAgeLimit
            TenantName                     = $config.TenantName
            TestCmdletLoggingEnabled       = $config.TestCmdletLoggingEnabled
        }
    }
    catch {
        throw "Failed to retrieve audit log configuration: $_"
    }
}

function Show-AuditStatus {
    <#
    .SYNOPSIS
        Displays audit log status with color coding.
    #>
    param([PSCustomObject]$Status)

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   Exchange Online Audit Log Status     " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Display Tenant Name
    Write-Host "Tenant: " -NoNewline -ForegroundColor White
    Write-Host $Status.TenantName -ForegroundColor Yellow
    Write-Host ""

    # Display Admin Audit Log Enabled
    Write-Host "Admin Audit Log Enabled:           " -NoNewline
    if ($Status.AdminAuditLogEnabled) {
        Write-Host "Enabled" -ForegroundColor Green
    }
    else {
        Write-Host "Disabled" -ForegroundColor Red
    }

    # Display Unified Audit Log Ingestion Enabled
    Write-Host "Unified Audit Log Ingestion:       " -NoNewline
    if ($Status.UnifiedAuditLogIngestionEnabled) {
        Write-Host "Enabled" -ForegroundColor Green
    }
    else {
        Write-Host "Disabled" -ForegroundColor Red
    }

    # Display Audit Log Age Limit
    Write-Host "Audit Log Age Limit:               " -NoNewline
    Write-Host "$($Status.AuditLogAgeLimit) days" -ForegroundColor Yellow

    # Display Test Cmdlet Logging
    Write-Host "Test Cmdlet Logging Enabled:       " -NoNewline
    if ($Status.TestCmdletLoggingEnabled) {
        Write-Host "Enabled" -ForegroundColor Green
    }
    else {
        Write-Host "Disabled" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Enable-UnifiedAuditLog {
    <#
    .SYNOPSIS
        Enables the Unified Audit Log.
    #>
    Write-StatusMessage -Message "Enabling Unified Audit Log Ingestion..." -Type "Info"

    try {
        # Note: Enabling UAL may take a few minutes to propagate
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
        
        Write-StatusMessage -Message "Unified Audit Log enabled successfully" -Type "Success"
        Write-StatusMessage -Message "Note: It may take 15-60 minutes for the change to fully propagate" -Type "Warning"
        
        return $true
    }
    catch {
        Write-StatusMessage -Message "Failed to enable Unified Audit Log: $_" -Type "Error"
        return $false
    }
}

function Confirm-EnableAuditLog {
    <#
    .SYNOPSIS
        Prompts user to confirm enabling audit log.
    .OUTPUTS
        Boolean indicating user confirmation.
    #>
    if ($AutoEnable) {
        Write-StatusMessage -Message "AutoEnable specified - proceeding without prompt" -Type "Verbose"
        return $true
    }

    Write-Host ""
    $response = Read-Host "Do you want to enable the Unified Audit Log? (Y/N)"
    
    return ($response -eq 'Y' -or $response -eq 'y')
}

function Test-ConfigurationChange {
    <#
    .SYNOPSIS
        Verifies that the configuration change was applied.
    .OUTPUTS
        Boolean indicating verification result.
    #>
    Write-StatusMessage -Message "Verifying configuration change..." -Type "Info"

    try {
        # Wait a moment for the change to propagate
        Start-Sleep -Seconds 2
        
        $newConfig = Get-AdminAuditLogConfig -ErrorAction Stop
        
        if ($newConfig.UnifiedAuditLogIngestionEnabled) {
            Write-StatusMessage -Message "Verification successful - Unified Audit Log is enabled" -Type "Success"
            return $true
        }
        else {
            Write-StatusMessage -Message "Verification failed - Unified Audit Log is still disabled" -Type "Error"
            return $false
        }
    }
    catch {
        Write-StatusMessage -Message "Verification error: $_" -Type "Error"
        return $false
    }
}

# ============================================================================
# Main Script Execution
# ============================================================================

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Exchange Online UAL Check & Enable Tool     " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

try {
    # Step 1: Check/Install Exchange Online Module
    Install-ExchangeOnlineModule

    # Step 2: Connect to Exchange Online
    Connect-ExchangeOnlineSession -Organization $Organization

    # Step 3: Get Current Audit Status
    $auditStatus = Get-AuditLogStatus

    # Step 4: Display Current Status
    Show-AuditStatus -Status $auditStatus

    # Step 5: Check if UAL is enabled and act accordingly
    if ($auditStatus.UnifiedAuditLogIngestionEnabled) {
        Write-StatusMessage -Message "Unified Audit Log is already enabled. No action required." -Type "Success"
    }
    else {
        Write-StatusMessage -Message "Unified Audit Log is currently DISABLED" -Type "Warning"
        
        if (Confirm-EnableAuditLog) {
            # Enable the Unified Audit Log
            $enableResult = Enable-UnifiedAuditLog
            
            if ($enableResult) {
                # Verify the change
                $verified = Test-ConfigurationChange
                
                if ($verified) {
                    Write-Host ""
                    Write-StatusMessage -Message "Configuration completed successfully!" -Type "Success"
                    Write-Host ""
                    Write-Host "Important Notes:" -ForegroundColor Yellow
                    Write-Host "- Unified Audit Log is now enabled" -ForegroundColor White
                    Write-Host "- Audit records will begin capturing immediately" -ForegroundColor White
                    Write-Host "- Full search availability may take 15-60 minutes" -ForegroundColor White
                    Write-Host "- Audit log entries are retained for $($auditStatus.AuditLogAgeLimit) days" -ForegroundColor White
                    Write-Host ""
                }
                else {
                    Write-StatusMessage -Message "Configuration was applied but verification failed. Please check manually." -Type "Warning"
                }
            }
            else {
                throw "Failed to enable Unified Audit Log"
            }
        }
        else {
            Write-StatusMessage -Message "User chose not to enable Unified Audit Log. Exiting." -Type "Info"
        }
    }
}
catch {
    Write-Host ""
    Write-StatusMessage -Message "Script encountered an error: $_" -Type "Error"
    Write-Host ""
    Write-StatusMessage -Message "Stack Trace: $($_.ScriptStackTrace)" -Type "Verbose"
    exit 1
}
finally {
    Write-Host ""
    Write-StatusMessage -Message "Script execution completed" -Type "Info"
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host ""
}

# Return the audit status for programmatic use
if ($auditStatus) {
    return $auditStatus
}
