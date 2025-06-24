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

.PARAMETER OrganizationName
    Name of your organization for labeling and policies

.PARAMETER RetentionPeriodYears
    Default retention period in years (default: 7)

.EXAMPLE
    .\Deploy-PurviewBaseline.ps1 -OrganizationName "Contoso" -RetentionPeriodYears 5
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$OrganizationName,
    [int]$RetentionPeriodYears = 7
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
        # Connect to Exchange Online for compliance
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        
        # Connect to Security & Compliance Center
        Connect-IPPSSession -ErrorAction Stop
        
        # Connect to Microsoft Graph
        $scopes = @(
            "InformationProtectionPolicy.Read",
            "InformationProtectionPolicy.ReadWrite"
        )
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        
        Write-Log "Successfully connected to compliance services."
    }
    catch {
        Write-Log "Failed to connect to compliance services: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to create sensitivity labels
function New-SensitivityLabels {
    Write-Log "Creating sensitivity labels..."
    try {
        # Define sensitivity labels
        $labels = @(
            @{
                Name = "$OrganizationName-Public"
                DisplayName = "Public"
                Comment = "Information that can be shared publicly"
                Priority = 0
            },
            @{
                Name = "$OrganizationName-Internal"
                DisplayName = "Internal"
                Comment = "Information for internal use only"
                Priority = 1
            },
            @{
                Name = "$OrganizationName-Confidential"
                DisplayName = "Confidential"
                Comment = "Sensitive information requiring protection"
                Priority = 2
            },
            @{
                Name = "$OrganizationName-Highly-Confidential"
                DisplayName = "Highly Confidential"
                Comment = "Highly sensitive information with strict access controls"
                Priority = 3
            }
        )
        
        foreach ($label in $labels) {
            $existingLabel = Get-Label -Identity $label.Name -ErrorAction SilentlyContinue
            if (!$existingLabel) {
                New-Label @label
                Write-Log "Created sensitivity label: $($label.DisplayName)"
            } else {
                Write-Log "Sensitivity label already exists: $($label.DisplayName)"
            }
        }
        
        # Publish labels
        $labelPolicy = Get-LabelPolicy -Identity "$OrganizationName-Default-Policy" -ErrorAction SilentlyContinue
        if (!$labelPolicy) {
            $labelNames = $labels | ForEach-Object { $_.Name }
            New-LabelPolicy -Name "$OrganizationName-Default-Policy" -Labels $labelNames -ExchangeLocation All -SharePointLocation All -OneDriveLocation All
            Write-Log "Created and published sensitivity label policy"
        } else {
            Write-Log "Sensitivity label policy already exists"
        }
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
        # Mass file deletion alert
        $fileDeleteAlert = Get-ProtectionAlert -Identity "$OrganizationName-Mass-File-Deletion" -ErrorAction SilentlyContinue
        if (!$fileDeleteAlert) {
            New-ProtectionAlert -Name "$OrganizationName-Mass-File-Deletion" -Category DataLossDetection -Operation FileDeleted -Threshold 100 -TimeWindow 60 -NotifyUser @("admin@$OrganizationName.com")
            Write-Log "Created mass file deletion alert policy"
        } else {
            Write-Log "Mass file deletion alert policy already exists"
        }
        
        # External sharing alert
        $externalSharingAlert = Get-ProtectionAlert -Identity "$OrganizationName-External-Sharing" -ErrorAction SilentlyContinue
        if (!$externalSharingAlert) {
            New-ProtectionAlert -Name "$OrganizationName-External-Sharing" -Category ThreatManagement -Operation SharingSet -Threshold 50 -TimeWindow 60 -NotifyUser @("admin@$OrganizationName.com")
            Write-Log "Created external sharing alert policy"
        } else {
            Write-Log "External sharing alert policy already exists"
        }
        
        # Unusual admin activity alert
        $adminActivityAlert = Get-ProtectionAlert -Identity "$OrganizationName-Admin-Activity" -ErrorAction SilentlyContinue
        if (!$adminActivityAlert) {
            New-ProtectionAlert -Name "$OrganizationName-Admin-Activity" -Category ThreatManagement -Operation UserLoggedIn -Threshold 10 -TimeWindow 60 -NotifyUser @("admin@$OrganizationName.com")
            Write-Log "Created admin activity alert policy"
        } else {
            Write-Log "Admin activity alert policy already exists"
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
        $auditConfig = Get-AdminAuditLogConfig
        if ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $false) {
            Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
            Write-Log "Unified audit log enabled"
        } else {
            Write-Log "Unified audit log already enabled"
        }
    }
    catch {
        Write-Log "Error enabling unified audit log: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to disconnect from services
function Disconnect-ComplianceServices {
    Write-Log "Disconnecting from compliance services..."
    try {
        Disconnect-ExchangeOnline -Confirm:$false
        Disconnect-MgGraph
        Write-Log "Disconnected from compliance services."
    }
    catch {
        Write-Log "Error disconnecting from compliance services: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Main execution
try {
    Write-Log "Starting Microsoft Purview baseline deployment..."
    
    Test-Prerequisites
    Connect-ComplianceServices
    
    New-SensitivityLabels
    New-RetentionPolicies
    New-DLPPolicies
    New-AlertPolicies
    Enable-UnifiedAuditLog
    
    Write-Log "Microsoft Purview baseline deployment completed successfully!"
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-ComplianceServices
}
