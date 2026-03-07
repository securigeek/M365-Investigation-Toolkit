BeforeAll {
    $detectionPath = Join-Path $PSScriptRoot "../../scripts/lib/detections.ps1"
    if (Test-Path $detectionPath) {
        . $detectionPath
    }
}

Describe "Investigation detections" {
    It "creates explicit detection records with severity, confidence, and evidence sources" {
        $record = New-DetectionRecord `
            -Name "deviceCodePhishing" `
            -Severity "High" `
            -Confidence "Medium" `
            -Summary "Device code sign-in correlated with CMSI evidence." `
            -EvidenceSources @("interactiveSignins", "unifiedAuditLog") `
            -Entities @("user@contoso.com") `
            -NextSteps @("Review follow-on Graph activity.")

        $record.Name | Should -Be "deviceCodePhishing"
        $record.Severity | Should -Be "High"
        $record.Confidence | Should -Be "Medium"
        $record.EvidenceSources | Should -Contain "interactiveSignins"
    }

    It "returns a detection collection even when no detectors are registered yet" {
        $detections = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ DaysBack = 14 }) -CollectorResults @() -OutputPath $TestDrive)

        $detections.Count | Should -Be 0
    }

    It "flags dangerous OAuth consent grants with high-risk delegated scopes" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "directoryAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            Operation = "Consent to application"
                            Category = "ApplicationManagement"
                            Actor = "user@contoso.com"
                            Target = "Suspicious App"
                            ModifiedProperties = [pscustomobject]@{
                                "ConsentAction.Permissions" = "Mail.ReadWrite Files.ReadWrite.All"
                            }
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "oauth" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        ($hits.Name) | Should -Contain "oauthConsentAbuse"
    }

    It "flags service principal backdoor activity when a credential change is followed by app sign-in activity" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "directoryAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            Operation = "Update service principal"
                            Actor = "admin@contoso.com"
                            Target = "Renamed Automation"
                            TargetId = "spn-1"
                            TargetType = "ServicePrincipal"
                            ModifiedProperties = [pscustomobject]@{
                                "KeyDescription" = "Password credential added"
                            }
                        }
                    )
                }
            },
            [pscustomobject]@{
                Module = "servicePrincipalSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            AppDisplayName = "Different Display Name"
                            ServicePrincipalId = "spn-1"
                            ResultType = 0
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "spn" }) -CollectorResults $collectorResults -OutputPath $TestDrive)
        $record = @($hits | Where-Object { $_.Name -eq "servicePrincipalBackdoor" } | Select-Object -First 1)[0]

        $record | Should -Not -BeNullOrEmpty
        $record.Severity | Should -Be "High"
        $record.Summary | Should -Match "sign-in activity"
    }

    It "flags federated backdoor indicators such as any.sts issuer URIs" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "directoryAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            Operation = "Set domain authentication"
                            Actor = "admin@contoso.com"
                            Target = "contoso.com"
                            ModifiedProperties = [pscustomobject]@{
                                "IssuerUri" = "https://any.sts/issuer"
                            }
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "federation" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        ($hits.Name) | Should -Contain "federatedBackdoor"
    }

    It "ignores empty modified-property bags in federated backdoor analysis" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "directoryAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            Operation = "Hard Delete policy"
                            Actor = "admin@contoso.com"
                            Target = "dummy-policy"
                            ModifiedProperties = [pscustomobject]@{}
                        }
                    )
                }
            }
        )

        {
            $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "federation-empty" }) -CollectorResults $collectorResults -OutputPath $TestDrive)
            $hits.Count | Should -Be 0
        } | Should -Not -Throw
    }

    It "flags device code phishing when device-code sign-in aligns with CMSI login evidence and follow-on activity" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "interactiveSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreatedDateTime = "2026-03-05T10:00:00Z"
                            UserPrincipalName = "user@contoso.com"
                            AuthenticationProtocol = "deviceCode"
                            AppDisplayName = "Microsoft Graph"
                            IPAddress = "203.0.113.10"
                        }
                    )
                }
            },
            [pscustomobject]@{
                Module = "unifiedAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreationDate = "2026-03-05T10:03:00Z"
                            Operation = "UserLoggedIn"
                            UserId = "user@contoso.com"
                            ExtendedProperties = [pscustomobject]@{
                                RequestType = "CMSI"
                            }
                        },
                        [pscustomobject]@{
                            CreationDate = "2026-03-05T10:25:00Z"
                            Operation = "MailItemsAccessed"
                            UserId = "user@contoso.com"
                            ClientInfoString = "REST"
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "device-code" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        $record = @($hits | Where-Object { $_.Name -eq "deviceCodePhishing" } | Select-Object -First 1)[0]

        $record | Should -Not -BeNullOrEmpty
        $record.Severity | Should -Be "High"
    }

    It "does not flag device code phishing when CMSI evidence is outside the correlation window" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "interactiveSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreatedDateTime = "2026-03-05T10:00:00Z"
                            UserPrincipalName = "user@contoso.com"
                            AuthenticationProtocol = "deviceCode"
                            AppDisplayName = "Microsoft Graph"
                            IPAddress = "203.0.113.10"
                        }
                    )
                }
            },
            [pscustomobject]@{
                Module = "unifiedAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreationDate = "2026-03-05T13:00:00Z"
                            Operation = "UserLoggedIn"
                            UserId = "user@contoso.com"
                            ExtendedProperties = [pscustomobject]@{
                                RequestType = "CMSI"
                            }
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "device-code-window" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        @($hits | Where-Object { $_.Name -eq "deviceCodePhishing" }).Count | Should -Be 0
    }

    It "downgrades device code phishing to medium when follow-on activity is absent" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "interactiveSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreatedDateTime = "2026-03-05T10:00:00Z"
                            UserPrincipalName = "user@contoso.com"
                            AuthenticationProtocol = "deviceCode"
                            AppDisplayName = "Microsoft Graph"
                            IPAddress = "203.0.113.10"
                        }
                    )
                }
            },
            [pscustomobject]@{
                Module = "unifiedAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreationDate = "2026-03-05T10:04:00Z"
                            Operation = "UserLoggedIn"
                            UserId = "user@contoso.com"
                            ExtendedProperties = [pscustomobject]@{
                                RequestType = "CMSI"
                            }
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "device-code-medium" }) -CollectorResults $collectorResults -OutputPath $TestDrive)
        $record = @($hits | Where-Object { $_.Name -eq "deviceCodePhishing" } | Select-Object -First 1)[0]

        $record | Should -Not -BeNullOrEmpty
        $record.Severity | Should -Be "Medium"
    }

    It "ignores UserLoggedIn rows with empty extended properties during device-code analysis" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "interactiveSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreatedDateTime = "2026-03-05T10:00:00Z"
                            UserPrincipalName = "user@contoso.com"
                            AuthenticationProtocol = "deviceCode"
                            AppDisplayName = "Microsoft Graph"
                            IPAddress = "203.0.113.10"
                        }
                    )
                }
            },
            [pscustomobject]@{
                Module = "unifiedAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreationDate = "2026-03-05T10:04:00Z"
                            Operation = "UserLoggedIn"
                            UserId = "user@contoso.com"
                            ExtendedProperties = [pscustomobject]@{}
                        }
                    )
                }
            }
        )

        {
            $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "device-code-empty-ual" }) -CollectorResults $collectorResults -OutputPath $TestDrive)
            @($hits | Where-Object { $_.Name -eq "deviceCodePhishing" }).Count | Should -Be 0
        } | Should -Not -Throw
    }

    It "flags dormant-account MFA takeover after security info registration" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "directoryAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            ActivityDateTime = [datetime]"2026-03-05T08:00:00Z"
                            Operation = "User registered all required security info"
                            Actor = "Azure MFA Strong Authentication Service"
                            Target = "user@contoso.com"
                            ModifiedProperties = [pscustomobject]@{
                                "Strong Authentication Phone App Detail" = "iPhone 12"
                            }
                        }
                    )
                }
            },
            [pscustomobject]@{
                Module = "interactiveSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreatedDateTime = [datetime]"2026-02-01T00:00:00Z"
                            UserPrincipalName = "user@contoso.com"
                            ResultType = 0
                        },
                        [pscustomobject]@{
                            CreatedDateTime = [datetime]"2026-03-05T09:00:00Z"
                            UserPrincipalName = "user@contoso.com"
                            ResultType = 0
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "mfa-takeover" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        ($hits.Name) | Should -Contain "dormantAccountMfaTakeover"
    }

    It "flags password spray clusters across many users in a 3-second window" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "interactiveSignins"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            CreatedDateTime = [datetime]"2026-03-05T11:00:00Z"
                            UserPrincipalName = "a@contoso.com"
                            IPAddress = "198.51.100.50"
                            ResultType = 50126
                            AppDisplayName = "Azure Active Directory PowerShell"
                        },
                        [pscustomobject]@{
                            CreatedDateTime = [datetime]"2026-03-05T11:00:01Z"
                            UserPrincipalName = "b@contoso.com"
                            IPAddress = "198.51.100.50"
                            ResultType = 50126
                            AppDisplayName = "Azure Active Directory PowerShell"
                        },
                        [pscustomobject]@{
                            CreatedDateTime = [datetime]"2026-03-05T11:00:02Z"
                            UserPrincipalName = "c@contoso.com"
                            IPAddress = "198.51.100.50"
                            ResultType = 50126
                            AppDisplayName = "Azure Active Directory PowerShell"
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "spray" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        ($hits.Name) | Should -Contain "passwordSpray"
    }

    It "raises BEC severity when forwarding and MailItemsAccessed bursts are both present" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "mailboxForwarding"
                Status = "success"
                Data = [pscustomobject]@{
                    ForwardingHits = @(
                        [pscustomobject]@{ UserPrincipalName = "user@contoso.com"; ForwardingSmtpAddress = "ext@example.com" }
                    )
                }
            },
            [pscustomobject]@{
                Module = "unifiedAuditLog"
                Status = "success"
                Data = [pscustomobject]@{
                    Rows = @(
                        [pscustomobject]@{
                            Operation = "MailItemsAccessed"
                            UserId = "user@contoso.com"
                            ClientInfoString = "REST"
                        },
                        [pscustomobject]@{
                            Operation = "SearchQueryInitiated"
                            UserId = "user@contoso.com"
                            ClientInfoString = "ComplianceCenter"
                        }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "bec" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        ($hits.Name) | Should -Contain "becDataExfiltration"
    }

    It "flags audit defense evasion when audit is disabled or bypassed" {
        $collectorResults = @(
            [pscustomobject]@{
                Module = "auditCoverage"
                Status = "success"
                Data = [pscustomobject]@{
                    CoverageGaps = @("Unified audit log ingestion is disabled.")
                }
            },
            [pscustomobject]@{
                Module = "mailboxAuditPosture"
                Status = "success"
                Data = [pscustomobject]@{
                    AuditDisabledMailboxes = @(
                        [pscustomobject]@{ UserPrincipalName = "user@contoso.com" }
                    )
                }
            }
        )

        $hits = @(Invoke-InvestigationDetectors -Manifest ([pscustomobject]@{ CaseName = "audit" }) -CollectorResults $collectorResults -OutputPath $TestDrive)

        ($hits.Name) | Should -Contain "auditDefenseEvasion"
    }
}
