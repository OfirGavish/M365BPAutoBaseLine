<#
.SYNOPSIS
    Automates deployment of Microsoft Purview compliance and governance baselines.

.DESCRIPTION
    This script configures Microsoft Purview with compliance best practices including:
    - Sensitivity labels for data classification
    - Retention policies for Exchange, SharePoint, OneDrive, Teams
    - Data Loss Prevention (DLP) policies
    - Alert policies for high-risk activities
    - Unified audit log enablement
    - Compliance assessment and recommendations

.PARAMETER OrganizationName
    Name of your organization for labeling and policies

.PARAMETER RetentionPeriodYears
    Default retention period in years (default: 7)

.PARAMETER AdminEmail
    Admin email address for alert notifications (if not provided, will attempt to detect)

.PARAMETER SkipSensitivityLabels
    Skip creation of sensitivity labels (useful if already configured)

.PARAMETER WhatIf
    Run in simulation mode without making actual changes

.EXAMPLE
    .\Deploy-PurviewBaseline.ps1 -OrganizationName "Contoso" -RetentionPeriodYears 5 -AdminEmail "admin@contoso.com"

.EXAMPLE
    .\Deploy-PurviewBaseline.ps1 -OrganizationName "Contoso" -WhatIf
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OrganizationName,
    [int]$RetentionPeriodYears = 7,
    [string]$AdminEmail = "",
    [switch]$SkipSensitivityLabels = $false,
    [switch]$WhatIf = $false
)

# Function to log messages
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(if($Level -eq "ERROR"){"Red"} elseif($Level -eq "WARNING"){"Yellow"} else{"Green"})
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check if required modules are available
    $requiredModules = @(
        "ExchangeOnlineManagement",
        "Microsoft.Graph",
        "PnP.PowerShell"
    )
    
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Log "$module module not found. Installing..." -Level "WARNING"
            Install-Module -Name $module -Force -AllowClobber
        }
    }
    
    Write-Log "Prerequisites check completed."
}

# Function to connect to services
function Connect-ComplianceServices {
    Write-Log "Connecting to compliance services..."
    try {
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would connect to Exchange Online and Security & Compliance Center" -Level "WARNING"
            return
        }
        
        # Connect to Exchange Online for compliance
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Connected to Exchange Online successfully."
        
        # Connect to Security & Compliance Center
        Connect-IPPSSession -ErrorAction Stop
        Write-Log "Connected to Security & Compliance Center successfully."
        
        # Connect to Microsoft Graph
        $scopes = @(
            "InformationProtectionPolicy.Read",
            "InformationProtectionPolicy.ReadWrite",
            "Organization.Read.All"
        )
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log "Connected to Microsoft Graph successfully."
        
        Write-Log "Successfully connected to all compliance services."
    }
    catch {
        Write-Log "Failed to connect to compliance services: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to create sensitivity labels
function New-SensitivityLabels {
    Write-Log "Creating sensitivity labels..."
    
    if ($SkipSensitivityLabels) {
        Write-Log "Skipping sensitivity labels creation (SkipSensitivityLabels parameter specified)" -Level "WARNING"
        return
    }
    
    try {
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would create sensitivity labels for $OrganizationName" -Level "WARNING"
            return
        }
        
        # Define comprehensive sensitivity labels with protection settings
        $labels = @(
            @{
                Name = "$OrganizationName-Public"
                DisplayName = "Public"
                Comment = "Information that can be shared publicly without restriction"
                Priority = 0
                AdvancedSettings = @{
                    "color" = "#0078d4"
                }
            },
            @{
                Name = "$OrganizationName-Internal"
                DisplayName = "Internal Use Only"
                Comment = "Information for internal use within the organization"
                Priority = 1
                AdvancedSettings = @{
                    "color" = "#ffc83d"
                }
            },
            @{
                Name = "$OrganizationName-Confidential"
                DisplayName = "Confidential"
                Comment = "Sensitive business information requiring protection"
                Priority = 2
                AdvancedSettings = @{
                    "color" = "#ff8c00"
                }
            },
            @{
                Name = "$OrganizationName-Highly-Confidential"
                DisplayName = "Highly Confidential"
                Comment = "Highly sensitive information with strict access controls"
                Priority = 3
                AdvancedSettings = @{
                    "color" = "#d13438"
                }
            }
        )
        
        Write-Log "Creating $($labels.Count) sensitivity labels..."
        $createdLabels = @()
        
        foreach ($label in $labels) {
            try {
                $existingLabel = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue
                if (!$existingLabel) {
                    # Create the label
                    $labelParams = @{
                        Name = $label.Name
                        DisplayName = $label.DisplayName
                        Comment = $label.Comment
                        Priority = $label.Priority
                    }
                    
                    # Add advanced settings if specified
                    if ($label.AdvancedSettings) {
                        $labelParams.AdvancedSettings = $label.AdvancedSettings
                    }
                    
                    New-Label @labelParams -ErrorAction Stop
                    $createdLabels += $label.Name
                    Write-Log "✓ Created sensitivity label: $($label.DisplayName)" -Level "SUCCESS"
                } else {
                    Write-Log "• Sensitivity label already exists: $($label.DisplayName)" -Level "INFO"
                    $createdLabels += $label.Name
                }
            }
            catch {
                Write-Log "✗ Failed to create label '$($label.DisplayName)': $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        # Create and publish label policy
        if ($createdLabels.Count -gt 0) {
            try {
                $policyName = "$OrganizationName-Default-Policy"
                $labelPolicy = Get-LabelPolicy -Identity $policyName -ErrorAction SilentlyContinue
                
                if (!$labelPolicy) {
                    Write-Log "Creating sensitivity label policy..."
                    $policyParams = @{
                        Name = $policyName
                        Labels = $createdLabels
                        ExchangeLocation = "All"
                        SharePointLocation = "All" 
                        OneDriveLocation = "All"
                        Comment = "Default sensitivity label policy for $OrganizationName"
                    }
                    
                    New-LabelPolicy @policyParams -ErrorAction Stop
                    Write-Log "✓ Created and published sensitivity label policy: $policyName" -Level "SUCCESS"
                } else {
                    Write-Log "• Sensitivity label policy already exists: $policyName" -Level "INFO"
                }
            }
            catch {
                Write-Log "✗ Failed to create label policy: $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        Write-Log "Sensitivity labels configuration completed." -Level "SUCCESS"
    }
    catch {
        Write-Log "Error creating sensitivity labels: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to create retention policies
function New-RetentionPolicies {
    Write-Log "Creating retention policies..."
    try {
        # Email retention policy
        $emailRetentionPolicy = Get-RetentionCompliancePolicy -Identity "$OrganizationName-Email-Retention" -ErrorAction SilentlyContinue
        if (!$emailRetentionPolicy) {
            New-RetentionCompliancePolicy -Name "$OrganizationName-Email-Retention" -ExchangeLocation All
            New-RetentionComplianceRule -Name "$OrganizationName-Email-Retention-Rule" -Policy "$OrganizationName-Email-Retention" -RetentionDuration (365 * $RetentionPeriodYears) -RetentionComplianceAction Keep
            Write-Log "Created email retention policy ($RetentionPeriodYears years)"
        } else {
            Write-Log "Email retention policy already exists"
        }
        
        # SharePoint retention policy
        $sharepointRetentionPolicy = Get-RetentionCompliancePolicy -Identity "$OrganizationName-SharePoint-Retention" -ErrorAction SilentlyContinue
        if (!$sharepointRetentionPolicy) {
            New-RetentionCompliancePolicy -Name "$OrganizationName-SharePoint-Retention" -SharePointLocation All -OneDriveLocation All
            New-RetentionComplianceRule -Name "$OrganizationName-SharePoint-Retention-Rule" -Policy "$OrganizationName-SharePoint-Retention" -RetentionDuration (365 * $RetentionPeriodYears) -RetentionComplianceAction Keep
            Write-Log "Created SharePoint/OneDrive retention policy ($RetentionPeriodYears years)"
        } else {
            Write-Log "SharePoint/OneDrive retention policy already exists"
        }
        
        # Teams retention policy
        $teamsRetentionPolicy = Get-RetentionCompliancePolicy -Identity "$OrganizationName-Teams-Retention" -ErrorAction SilentlyContinue
        if (!$teamsRetentionPolicy) {
            New-RetentionCompliancePolicy -Name "$OrganizationName-Teams-Retention" -TeamsChannelLocation All -TeamsChatLocation All
            New-RetentionComplianceRule -Name "$OrganizationName-Teams-Retention-Rule" -Policy "$OrganizationName-Teams-Retention" -RetentionDuration (365 * $RetentionPeriodYears) -RetentionComplianceAction Keep
            Write-Log "Created Teams retention policy ($RetentionPeriodYears years)"
        } else {
            Write-Log "Teams retention policy already exists"
        }
    }
    catch {
        Write-Log "Error creating retention policies: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to create DLP policies
function New-DLPPolicies {
    Write-Log "Creating Data Loss Prevention (DLP) policies..."
    try {
        # Credit Card DLP Policy
        $creditCardDLP = Get-DlpCompliancePolicy -Identity "$OrganizationName-Credit-Card-Protection" -ErrorAction SilentlyContinue
        if (!$creditCardDLP) {
            New-DlpCompliancePolicy -Name "$OrganizationName-Credit-Card-Protection" -ExchangeLocation All -SharePointLocation All -OneDriveLocation All -TeamsLocation All
            New-DlpComplianceRule -Name "$OrganizationName-Credit-Card-Rule" -Policy "$OrganizationName-Credit-Card-Protection" -ContentContainsSensitiveInformation @{Name="Credit Card Number"; minCount="1"} -BlockAccess $true -NotifyUser "SiteAdmin, LastModifier" -GenerateIncident $true
            Write-Log "Created Credit Card DLP policy"
        } else {
            Write-Log "Credit Card DLP policy already exists"
        }
        
        # SSN DLP Policy
        $ssnDLP = Get-DlpCompliancePolicy -Identity "$OrganizationName-SSN-Protection" -ErrorAction SilentlyContinue
        if (!$ssnDLP) {
            New-DlpCompliancePolicy -Name "$OrganizationName-SSN-Protection" -ExchangeLocation All -SharePointLocation All -OneDriveLocation All -TeamsLocation All
            New-DlpComplianceRule -Name "$OrganizationName-SSN-Rule" -Policy "$OrganizationName-SSN-Protection" -ContentContainsSensitiveInformation @{Name="U.S. Social Security Number (SSN)"; minCount="1"} -BlockAccess $true -NotifyUser "SiteAdmin, LastModifier" -GenerateIncident $true
            Write-Log "Created SSN DLP policy"
        } else {
            Write-Log "SSN DLP policy already exists"
        }
        
        # General PII DLP Policy
        $piiDLP = Get-DlpCompliancePolicy -Identity "$OrganizationName-PII-Protection" -ErrorAction SilentlyContinue
        if (!$piiDLP) {
            New-DlpCompliancePolicy -Name "$OrganizationName-PII-Protection" -ExchangeLocation All -SharePointLocation All -OneDriveLocation All -TeamsLocation All
            New-DlpComplianceRule -Name "$OrganizationName-PII-Rule" -Policy "$OrganizationName-PII-Protection" -ContentContainsSensitiveInformation @{Name="All Full Names"; minCount="10"},@{Name="U.S. Phone Number"; minCount="10"} -NotifyUser "SiteAdmin, LastModifier" -GenerateIncident $true
            Write-Log "Created PII DLP policy"
        } else {
            Write-Log "PII DLP policy already exists"
        }
    }
    catch {
        Write-Log "Error creating DLP policies: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to create alert policies
function New-AlertPolicies {
    Write-Log "Creating alert policies..."
    try {
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would create alert policies for security monitoring" -Level "WARNING"
            return
        }
        
        # Determine admin email for notifications
        $notificationEmail = $AdminEmail
        if ([string]::IsNullOrEmpty($notificationEmail)) {
            try {
                # Try to get admin email from organization settings
                $orgConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
                if ($orgConfig -and $orgConfig.MicrosoftExchangeRecipientEmailAddresses) {
                    $notificationEmail = $orgConfig.MicrosoftExchangeRecipientEmailAddresses[0]
                    Write-Log "Using detected admin email: $notificationEmail" -Level "INFO"
                } else {
                    $notificationEmail = "admin@$OrganizationName.com"
                    Write-Log "Using default admin email format: $notificationEmail (Please update if different)" -Level "WARNING"
                }
            }
            catch {
                $notificationEmail = "admin@$OrganizationName.com"
                Write-Log "Could not detect admin email. Using default: $notificationEmail" -Level "WARNING"
            }
        }
        
        # Define comprehensive alert policies
        $alertPolicies = @(
            @{
                Name = "$OrganizationName-Mass-File-Deletion"
                DisplayName = "Mass File Deletion Alert"
                Category = "DataLossDetection"
                Operation = "FileDeleted"
                Threshold = 100
                TimeWindow = 60
                Description = "Alert when a user deletes 100+ files within 60 minutes"
            },
            @{
                Name = "$OrganizationName-External-Sharing"
                DisplayName = "Excessive External Sharing Alert" 
                Category = "ThreatManagement"
                Operation = "SharingSet"
                Threshold = 50
                TimeWindow = 60
                Description = "Alert when excessive external sharing occurs"
            },
            @{
                Name = "$OrganizationName-Admin-Activity"
                DisplayName = "Unusual Admin Activity Alert"
                Category = "ThreatManagement" 
                Operation = "UserLoggedIn"
                Threshold = 10
                TimeWindow = 60
                Description = "Alert for unusual admin login patterns"
            },
            @{
                Name = "$OrganizationName-DLP-Violations"
                DisplayName = "DLP Policy Violations Alert"
                Category = "DataLossDetection"
                Operation = "DLPRuleMatch"
                Threshold = 5
                TimeWindow = 60
                Description = "Alert when DLP policy violations exceed threshold"
            },
            @{
                Name = "$OrganizationName-Malware-Detection"
                DisplayName = "Malware Detection Alert"
                Category = "ThreatManagement"
                Operation = "MalwareDetected"
                Threshold = 1
                TimeWindow = 60
                Description = "Alert immediately when malware is detected"
            }
        )
        
        Write-Log "Creating $($alertPolicies.Count) alert policies with notification email: $notificationEmail"
        $createdAlerts = 0
        
        foreach ($alertPolicy in $alertPolicies) {
            try {
                $existingAlert = Get-ProtectionAlert -Identity $alertPolicy.Name -ErrorAction SilentlyContinue
                if (!$existingAlert) {
                    $alertParams = @{
                        Name = $alertPolicy.Name
                        Category = $alertPolicy.Category
                        Operation = $alertPolicy.Operation
                        Threshold = $alertPolicy.Threshold
                        TimeWindow = $alertPolicy.TimeWindow
                        NotifyUser = @($notificationEmail)
                        Comment = $alertPolicy.Description
                    }
                    
                    New-ProtectionAlert @alertParams -ErrorAction Stop
                    $createdAlerts++
                    Write-Log "✓ Created alert policy: $($alertPolicy.DisplayName)" -Level "SUCCESS"
                } else {
                    Write-Log "• Alert policy already exists: $($alertPolicy.DisplayName)" -Level "INFO"
                }
            }
            catch {
                Write-Log "✗ Failed to create alert policy '$($alertPolicy.DisplayName)': $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        Write-Log "Alert policies configuration completed. Created $createdAlerts new policies." -Level "SUCCESS"
        
        if ($createdAlerts -gt 0) {
            Write-Log "IMPORTANT: Verify notification email '$notificationEmail' is correct and accessible." -Level "WARNING"
            Write-Log "Alert policies may take up to 24 hours to become fully active." -Level "INFO"
        }
    }
    catch {
        Write-Log "Error creating alert policies: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to enable unified audit log
function Enable-UnifiedAuditLog {
    Write-Log "Enabling unified audit log..."
    try {
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would enable unified audit log and configure retention" -Level "WARNING"
            return
        }
        
        # Enable unified audit log ingestion
        $auditConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
        if ($auditConfig) {
            if ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $false) {
                Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true -ErrorAction Stop
                Write-Log "✓ Unified audit log ingestion enabled" -Level "SUCCESS"
            } else {
                Write-Log "• Unified audit log ingestion already enabled" -Level "INFO"
            }
            
            # Configure audit log retention if possible
            try {
                # Check current audit log retention settings
                Write-Log "Checking audit log retention configuration..."
                $auditRetentionPolicies = Get-UnifiedAuditLogRetentionPolicy -ErrorAction SilentlyContinue
                
                if ($auditRetentionPolicies) {
                    Write-Log "Found $($auditRetentionPolicies.Count) audit retention policies configured." -Level "INFO"
                } else {
                    Write-Log "No custom audit retention policies found. Using default retention (90 days for most events)." -Level "INFO"
                    Write-Log "Consider configuring custom retention policies for critical events." -Level "WARNING"
                }
            }
            catch {
                Write-Log "Could not check audit retention policies (may require higher license): $($_.Exception.Message)" -Level "WARNING"
            }
        } else {
            Write-Log "Could not retrieve audit configuration" -Level "WARNING"
        }
        
        # Verify audit log is working
        try {
            Write-Log "Verifying audit log functionality..."
            $recentAudits = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) -ResultSize 1 -ErrorAction SilentlyContinue
            if ($recentAudits) {
                Write-Log "✓ Audit log is functioning correctly - recent events found" -Level "SUCCESS"
            } else {
                Write-Log "⚠ No recent audit events found. Audit log may be newly enabled." -Level "WARNING"
                Write-Log "It can take up to 24 hours for audit events to appear after enabling." -Level "INFO"
            }
        }
        catch {
            Write-Log "Could not verify audit log functionality: $($_.Exception.Message)" -Level "WARNING"
        }
        
        Write-Log "Unified audit log configuration completed." -Level "SUCCESS"
    }
    catch {
        Write-Log "Error enabling unified audit log: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to perform compliance assessment
function Invoke-ComplianceAssessment {
    Write-Log "Performing compliance assessment..."
    try {
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would perform comprehensive compliance assessment" -Level "WARNING"
            return
        }
        
        $assessment = @{
            SensitivityLabels = $false
            RetentionPolicies = $false
            DLPPolicies = $false
            AlertPolicies = $false
            AuditLog = $false
            TotalScore = 0
            Recommendations = @()
        }
        
        # Check Sensitivity Labels
        try {
            $labels = Get-Label -ErrorAction SilentlyContinue
            $labelPolicies = Get-LabelPolicy -ErrorAction SilentlyContinue
            
            if ($labels -and $labelPolicies) {
                $assessment.SensitivityLabels = $true
                $assessment.TotalScore += 20
                Write-Log "✓ Sensitivity labels: $($labels.Count) labels, $($labelPolicies.Count) policies" -Level "SUCCESS"
            } else {
                $assessment.Recommendations += "Configure sensitivity labels for data classification"
                Write-Log "✗ Sensitivity labels: Not configured" -Level "WARNING"
            }
        }
        catch {
            $assessment.Recommendations += "Review sensitivity label configuration"
            Write-Log "✗ Could not assess sensitivity labels: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Check Retention Policies
        try {
            $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue
            if ($retentionPolicies -and $retentionPolicies.Count -gt 0) {
                $assessment.RetentionPolicies = $true
                $assessment.TotalScore += 25
                Write-Log "✓ Retention policies: $($retentionPolicies.Count) policies configured" -Level "SUCCESS"
            } else {
                $assessment.Recommendations += "Configure retention policies for data lifecycle management"
                Write-Log "✗ Retention policies: Not configured" -Level "WARNING"
            }
        }
        catch {
            $assessment.Recommendations += "Review retention policy configuration"
            Write-Log "✗ Could not assess retention policies: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Check DLP Policies
        try {
            $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue
            if ($dlpPolicies -and $dlpPolicies.Count -gt 0) {
                $assessment.DLPPolicies = $true
                $assessment.TotalScore += 25
                Write-Log "✓ DLP policies: $($dlpPolicies.Count) policies configured" -Level "SUCCESS"
            } else {
                $assessment.Recommendations += "Configure DLP policies to prevent data loss"
                Write-Log "✗ DLP policies: Not configured" -Level "WARNING"
            }
        }
        catch {
            $assessment.Recommendations += "Review DLP policy configuration"
            Write-Log "✗ Could not assess DLP policies: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Check Alert Policies
        try {
            $alertPolicies = Get-ProtectionAlert -ErrorAction SilentlyContinue
            if ($alertPolicies -and $alertPolicies.Count -gt 0) {
                $assessment.AlertPolicies = $true
                $assessment.TotalScore += 15
                Write-Log "✓ Alert policies: $($alertPolicies.Count) policies configured" -Level "SUCCESS"
            } else {
                $assessment.Recommendations += "Configure alert policies for security monitoring"
                Write-Log "✗ Alert policies: Not configured" -Level "WARNING"
            }
        }
        catch {
            $assessment.Recommendations += "Review alert policy configuration"
            Write-Log "✗ Could not assess alert policies: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Check Audit Log
        try {
            $auditConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
            if ($auditConfig -and $auditConfig.UnifiedAuditLogIngestionEnabled) {
                $assessment.AuditLog = $true
                $assessment.TotalScore += 15
                Write-Log "✓ Unified audit log: Enabled" -Level "SUCCESS"
            } else {
                $assessment.Recommendations += "Enable unified audit log for compliance monitoring"
                Write-Log "✗ Unified audit log: Not enabled" -Level "WARNING"
            }
        }
        catch {
            $assessment.Recommendations += "Review audit log configuration"
            Write-Log "✗ Could not assess audit log: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Generate compliance score and recommendations
        Write-Log "=== COMPLIANCE ASSESSMENT RESULTS ===" -Level "INFO"
        Write-Log "Compliance Score: $($assessment.TotalScore)/100" -Level "INFO"
        
        if ($assessment.TotalScore -ge 80) {
            Write-Log "Compliance Status: EXCELLENT" -Level "SUCCESS"
        } elseif ($assessment.TotalScore -ge 60) {
            Write-Log "Compliance Status: GOOD" -Level "INFO"
        } elseif ($assessment.TotalScore -ge 40) {
            Write-Log "Compliance Status: NEEDS IMPROVEMENT" -Level "WARNING"
        } else {
            Write-Log "Compliance Status: CRITICAL - IMMEDIATE ACTION REQUIRED" -Level "ERROR"
        }
        
        if ($assessment.Recommendations.Count -gt 0) {
            Write-Log "RECOMMENDATIONS:" -Level "WARNING"
            foreach ($recommendation in $assessment.Recommendations) {
                Write-Log "• $recommendation" -Level "WARNING"
            }
        }
        
        return $assessment
    }
    catch {
        Write-Log "Error performing compliance assessment: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Function to disconnect from services
function Disconnect-ComplianceServices {
    Write-Log "Disconnecting from compliance services..."
    try {
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would disconnect from services" -Level "WARNING"
            return
        }
        
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "Disconnected from compliance services."
    }
    catch {
        Write-Log "Error disconnecting from compliance services: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to show comprehensive recommendations
function Show-PurviewRecommendations {
    param([hashtable]$AssessmentResults)
    
    Write-Log "=== MICROSOFT PURVIEW DEPLOYMENT SUMMARY ===" -Level "SUCCESS"
    Write-Log ""
    Write-Log "COMPLETED CONFIGURATIONS:" -Level "INFO"
    if (!$SkipSensitivityLabels) {
        Write-Log "✓ Sensitivity labels and policies deployed" -Level "INFO"
    }
    Write-Log "✓ Retention policies configured for $RetentionPeriodYears years" -Level "INFO"
    Write-Log "✓ Data Loss Prevention (DLP) policies deployed" -Level "INFO"
    Write-Log "✓ Alert policies configured for security monitoring" -Level "INFO"
    Write-Log "✓ Unified audit logging enabled" -Level "INFO"
    Write-Log ""
    
    if ($AssessmentResults) {
        Write-Log "COMPLIANCE SCORE: $($AssessmentResults.TotalScore)/100" -Level "INFO"
        Write-Log ""
    }
    
    Write-Log "CRITICAL NEXT STEPS:" -Level "WARNING"
    Write-Log "1. TEST all DLP policies with pilot users before full enforcement" -Level "WARNING"
    Write-Log "2. TRAIN users on sensitivity labels and data classification" -Level "WARNING"
    Write-Log "3. VERIFY alert notification emails are correct and monitored" -Level "WARNING"
    Write-Log "4. REVIEW retention policies and adjust based on legal requirements" -Level "WARNING"
    Write-Log "5. MONITOR compliance reports and audit logs regularly" -Level "WARNING"
    Write-Log ""
    Write-Log "ADDITIONAL RECOMMENDATIONS:" -Level "INFO"
    Write-Log "• Configure insider risk management policies" -Level "INFO"
    Write-Log "• Set up communication compliance for regulatory requirements" -Level "INFO"
    Write-Log "• Implement eDiscovery workflows for legal holds" -Level "INFO"
    Write-Log "• Enable Advanced eDiscovery for complex investigations" -Level "INFO"
    Write-Log "• Configure information barriers if needed" -Level "INFO"
    Write-Log "• Set up records management for regulatory compliance" -Level "INFO"
    Write-Log "• Regular compliance assessment using Microsoft Compliance Manager" -Level "INFO"
    Write-Log ""
    Write-Log "DOCUMENTATION LINKS:" -Level "INFO"
    Write-Log "• Microsoft Purview: https://docs.microsoft.com/microsoft-365/compliance/" -Level "INFO"
    Write-Log "• Sensitivity Labels: https://docs.microsoft.com/microsoft-365/compliance/sensitivity-labels" -Level "INFO"
    Write-Log "• DLP Policies: https://docs.microsoft.com/microsoft-365/compliance/dlp-learn-about-dlp" -Level "INFO"
    Write-Log "• Retention Policies: https://docs.microsoft.com/microsoft-365/compliance/retention-policies" -Level "INFO"
    Write-Log "============================================================" -Level "SUCCESS"
}

# Main execution
try {
    Write-Log "Starting Microsoft Purview baseline deployment..." -Level "SUCCESS"
    Write-Log "Organization: $OrganizationName | Retention Period: $RetentionPeriodYears years"
    
    if ($WhatIf) {
        Write-Log "🔍 Running in WHAT-IF mode - no changes will be made" -Level "WARNING"
    }
    
    Test-Prerequisites
    Connect-ComplianceServices
    
    # Deploy compliance components
    New-SensitivityLabels
    New-RetentionPolicies  
    New-DLPPolicies
    New-AlertPolicies
    Enable-UnifiedAuditLog
    
    Write-Log "Microsoft Purview baseline deployment completed successfully!" -Level "SUCCESS"
    
    # Perform compliance assessment
    Write-Log ""
    $assessmentResults = Invoke-ComplianceAssessment
    
    # Show comprehensive recommendations
    Show-PurviewRecommendations -AssessmentResults $assessmentResults
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-ComplianceServices
}
