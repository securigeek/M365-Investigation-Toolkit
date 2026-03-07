BeforeAll {
    $orchestratorPath = Join-Path $PSScriptRoot "../../scripts/Invoke-InvestigationCollector.ps1"
    if (Test-Path $orchestratorPath) {
        . $orchestratorPath
    }
}

Describe "Investigation launcher" {
    It "creates the case manifest before running collectors" {
        $manifest = New-InvestigationManifest `
            -TenantId "11111111-1111-1111-1111-111111111111" `
            -TenantDomain "contoso.onmicrosoft.com" `
            -CaseName "possible-compromise"

        $manifest.CaseName | Should -Be "possible-compromise"
        $manifest.TenantDomain | Should -Be "contoso.onmicrosoft.com"
    }

    It "treats empty profile parameters as self-service mode instead of legacy mode" {
        $mode = Test-InvestigationLegacyProfileMode -BoundParameters @{
            ProfilePath = $null
            ProfileRoot = $null
        }

        $mode | Should -BeFalse
    }

    It "returns a countable profile collection when one profile exists" {
        $root = Join-Path TestDrive: "profiles"
        $tenantRoot = Join-Path $root "tenants"
        New-Item -ItemType Directory -Path $tenantRoot -Force | Out-Null
        @(
            @{
                TenantId = "11111111-1111-1111-1111-111111111111"
                TenantDomain = "contoso.onmicrosoft.com"
                CustomerName = "Contoso"
            } | ConvertTo-Json
        ) | Set-Content (Join-Path $tenantRoot "tenant.json")

        $profiles = Get-AvailableInvestigationProfiles -RootPath $root

        $profiles.Count | Should -Be 1
    }

    It "uses the default output root when the public flow does not pass one" {
        Mock Ensure-InvestigationPrerequisites {
            [pscustomobject]@{
                Ready = $true
                Browser = [pscustomobject]@{ Supported = $true; Method = "open" }
                CurrentPwshVersion = [version]"7.5.4"
                MinimumPwshVersion = [version]"7.5.0"
            }
        }
        Mock Resolve-InvestigationPath { param($Path) $Path }
        Mock Invoke-SelfServiceCollection {
            param($TenantId, $TenantDomain, $Prerequisites, $CaseName, $DaysBack, $OutputPath, $Pivots)
            [pscustomobject]@{
                OutputPath = $OutputPath
                Report = [pscustomobject]@{
                    Verdict = [pscustomobject]@{
                        Severity = "Low"
                        TopFindings = @()
                    }
                }
                CollectorResults = @()
            }
        }
        Mock Clear-InvestigationConnections {}

        $result = Invoke-InvestigationCollector -CaseName "output-root-check" -SkipPrompt

        $result.OutputPath | Should -Match "output-root-check"
        $result.OutputPath | Should -Match "output/incidents"
    }

    It "defines analyst-friendly prompts with purpose guidance" {
        $prompts = Get-InvestigationPromptDefinitions

        $prompts.CaseName | Should -Match "report title"
        $prompts.Sender | Should -Match "message trace"
        $prompts.Sender | Should -Match "optional"
        $prompts.SubjectContains | Should -Match "subject"
    }

    It "selects only available modules and includes pivot collectors when pivots are provided" {
        $apiCatalog = [pscustomobject]@{
            Modules = @(
                [pscustomobject]@{ Name = "mailboxForwarding"; Status = "available" },
                [pscustomobject]@{ Name = "messageTracePivot"; Status = "available" },
                [pscustomobject]@{ Name = "quarantinePivot"; Status = "unavailable" }
            )
        }

        $plan = Resolve-InvestigationExecutionPlan `
            -ApiCatalog $apiCatalog `
            -Pivots @{ Sender = "bad@contoso.com" }

        $plan.ModuleNames | Should -Contain "mailboxForwarding"
        $plan.ModuleNames | Should -Contain "messageTracePivot"
        $plan.ModuleNames | Should -Not -Contain "quarantinePivot"
    }

    It "includes available forensic evidence modules in the default execution plan" {
        $apiCatalog = [pscustomobject]@{
            Modules = @(
                [pscustomobject]@{ Name = "directoryAuditLog"; Status = "available" },
                [pscustomobject]@{ Name = "interactiveSignins"; Status = "available" },
                [pscustomobject]@{ Name = "nonInteractiveSignins"; Status = "available" },
                [pscustomobject]@{ Name = "servicePrincipalSignins"; Status = "available" },
                [pscustomobject]@{ Name = "unifiedAuditLog"; Status = "unavailable" }
            )
        }

        $plan = Resolve-InvestigationExecutionPlan `
            -ApiCatalog $apiCatalog `
            -Pivots @{}

        $plan.ModuleNames | Should -Contain "directoryAuditLog"
        $plan.ModuleNames | Should -Contain "interactiveSignins"
        $plan.ModuleNames | Should -Contain "nonInteractiveSignins"
        $plan.ModuleNames | Should -Contain "servicePrincipalSignins"
        $plan.ModuleNames | Should -Not -Contain "unifiedAuditLog"
        (@($plan.SkippedModules | Where-Object { $_.Name -eq "unifiedAuditLog" })).Count | Should -Be 1
    }

    It "skips the UAL collector at runtime when audit coverage already verified it off" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "auditCoverage"
                Status = "success"
                Data = [pscustomobject]@{
                    UnifiedAuditLogStatus = "verified-off"
                }
            }
        )

        $decision = Resolve-InvestigationRuntimeSkip -ModuleName "unifiedAuditLog" -CollectorResults $collectorResults

        $decision.ShouldSkip | Should -BeTrue
        $decision.Reason | Should -Be "ual-verified-off"
    }

    It "skips the UAL collector at runtime when audit coverage is ambiguous" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "auditCoverage"
                Status = "partial"
                Data = [pscustomobject]@{
                    UnifiedAuditLogStatus = "ambiguous"
                }
            }
        )

        $decision = Resolve-InvestigationRuntimeSkip -ModuleName "unifiedAuditLog" -CollectorResults $collectorResults

        $decision.ShouldSkip | Should -BeTrue
        $decision.Reason | Should -Be "ual-status-ambiguous"
    }
}
