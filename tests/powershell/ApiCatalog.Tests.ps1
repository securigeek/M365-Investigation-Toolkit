BeforeAll {
    $apiPath = Join-Path $PSScriptRoot "../../scripts/lib/api-capabilities.ps1"
    if (Test-Path $apiPath) {
        . $apiPath
    }
}

Describe "Investigation API catalog" {
    It "defines registry entries with the metadata needed for runtime preflight" {
        $registry = @(Get-InvestigationCollectorRegistry)

        $registry.Count | Should -BeGreaterThan 0
        foreach ($entry in $registry) {
            $entry.Name | Should -Not -BeNullOrEmpty
            $entry.Surface | Should -BeIn @("Exchange", "Graph")
            $entry.PreferredCommand | Should -Not -BeNullOrEmpty
            $entry.PSObject.Properties.Name | Should -Contain "RequiredScopes"
            $entry.AllowBetaFallback | Should -BeOfType [bool]
        }

        ($registry.Name -contains "mailboxAuditPosture") | Should -BeTrue
    }

    It "registers shared forensic evidence modules with explicit surfaces and fallback behavior" {
        $registry = @(Get-InvestigationCollectorRegistry)

        foreach ($moduleName in @(
            "directoryAuditLog",
            "interactiveSignins",
            "nonInteractiveSignins",
            "servicePrincipalSignins",
            "unifiedAuditLog"
        )) {
            $module = $registry | Where-Object { $_.Name -eq $moduleName } | Select-Object -First 1

            $module | Should -Not -BeNullOrEmpty
            $module.Surface | Should -BeIn @("Exchange", "Graph")
            $module.FallbackBehavior | Should -Be "skip"
        }
    }

    It "prefers Get-MessageTraceV2 for message trace pivots" {
        $registry = @(Get-InvestigationCollectorRegistry)
        $module = $registry | Where-Object { $_.Name -eq "messageTracePivot" } | Select-Object -First 1

        $module.PreferredCommand | Should -Be "Get-MessageTraceV2"
    }

    It "marks a module available when the preferred v1 command exists" {
        $definition = [pscustomobject]@{
            Name = "riskySignins"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgAuditLogSignIn"
            AllowBetaFallback = $true
            BetaCommand = "Get-MgBetaAuditLogSignIn"
            RequiredScopes = @("AuditLog.Read.All")
        }

        $commandSupport = @{
            "v1.0:Get-MgAuditLogSignIn" = $true
        }

        $status = Resolve-InvestigationModuleStatus -Definition $definition -CommandSupport $commandSupport

        $status.Status | Should -Be "available"
        $status.Profile | Should -Be "v1.0"
    }

    It "marks a module as beta-fallback when v1 is missing but beta is allowed" {
        $definition = [pscustomobject]@{
            Name = "consentGrants"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgOauth2PermissionGrant"
            AllowBetaFallback = $true
            BetaCommand = "Get-MgBetaOauth2PermissionGrant"
            RequiredScopes = @("Directory.Read.All")
        }

        $commandSupport = @{
            "beta:Get-MgBetaOauth2PermissionGrant" = $true
        }

        $status = Resolve-InvestigationModuleStatus -Definition $definition -CommandSupport $commandSupport

        $status.Status | Should -Be "beta-fallback"
        $status.Profile | Should -Be "beta"
    }

    It "requires Directory.Read.All for delegated permission grant collection" {
        $registry = @(Get-InvestigationCollectorRegistry)
        $module = $registry | Where-Object { $_.Name -eq "consentGrants" } | Select-Object -First 1

        $module.RequiredScopes | Should -Contain "Directory.Read.All"
        $module.RequiredScopes | Should -Not -Contain "DelegatedPermissionGrant.Read.All"
    }

    It "marks a module unavailable when no supported command is present" {
        $definition = [pscustomobject]@{
            Name = "roleAssignments"
            Surface = "Graph"
            PreferredProfile = "v1.0"
            PreferredCommand = "Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance"
            AllowBetaFallback = $false
            BetaCommand = $null
            RequiredScopes = @("RoleManagement.Read.Directory")
        }

        $status = Resolve-InvestigationModuleStatus -Definition $definition -CommandSupport @{}

        $status.Status | Should -Be "unavailable"
    }
}
