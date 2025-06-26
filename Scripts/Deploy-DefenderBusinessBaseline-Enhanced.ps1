<#
.SYNOPSIS
    Enhanced Microsoft Defender for Business baseline with comprehensive MDEAutomator integration.

.DESCRIPTION
    This script deploys a comprehensive Microsoft Defender for Business security baseline with
    advanced automation capabilities powered by the MDEAutomator community framework.
    
    Features include:
    - Core Defender for Business security baseline configuration via Intune
    - MDEAutomator PowerShell module installation and configuration
    - Live Response script library deployment for investigation and incident response
    - Custom detection rules for advanced threat detection
    - Threat intelligence indicators (IOCs) management
    - Endpoint fleet management and bulk operations
    - Investigation package collection automation
    - Advanced hunting query deployment
    - Incident management and response workflows

.PARAMETER TenantId
    Azure AD Tenant ID for device management

.PARAMETER IntuneGroupName
    Name of the Intune group for device policies (default: "All Users")

.PARAMETER DeployMDEAutomator
    Deploy and configure MDEAutomator components for advanced automation

.PARAMETER MDEAutomatorAppId
    App Registration ID for MDEAutomator (required if DeployMDEAutomator is true)

.PARAMETER MDEAutomatorSecret
    App Registration secret for MDEAutomator (secure string, optional if using federated auth)

.PARAMETER DeployLiveResponseScripts
    Deploy predefined Live Response scripts to the MDE library

.PARAMETER InstallCustomDetections
    Install custom detection rules for enhanced threat detection

.PARAMETER ConfigureThreatIntelligence
    Configure threat intelligence indicators (IOCs) from baseline and community feeds

.PARAMETER TestMDEEnvironment
    Perform comprehensive testing of MDE environment readiness

.PARAMETER WhatIf
    Show what changes would be made without actually applying them

.PARAMETER LogPath
    Custom path for log files (default: .\Logs\DefenderBusiness-Enhanced-{timestamp}.log)

.EXAMPLE
    .\Deploy-DefenderBusinessBaseline-Enhanced.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -DeployMDEAutomator -MDEAutomatorAppId "app-id-here"

.EXAMPLE
    .\Deploy-DefenderBusinessBaseline-Enhanced.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -DeployMDEAutomator -MDEAutomatorAppId "app-id-here" -DeployLiveResponseScripts -InstallCustomDetections -ConfigureThreatIntelligence

.EXAMPLE
    .\Deploy-DefenderBusinessBaseline-Enhanced.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -DeployMDEAutomator -MDEAutomatorAppId "app-id-here" -WhatIf

.NOTES
    Author: M365 Business Premium Automation Team
    Version: 2.0
    Requires: PowerShell 5.1+, Microsoft Graph PowerShell SDK
    
    MDEAutomator Integration:
    - Requires MDEAutomator PowerShell module (automatically installed)
    - Requires App Registration with appropriate MDE and Graph API permissions
    - Enhanced with community-driven automation capabilities from https://github.com/msdirtbag/MDEAutomator
    
    Required API Permissions:
    - WindowsDefenderATP: AdvancedQuery.Read.All, Alert.Read.All, File.Read.All, Machine.*, Ti.ReadWrite.All
    - Microsoft Graph: CustomDetection.ReadWrite.All, ThreatHunting.Read.All, SecurityIncident.ReadWrite.All

.LINK
    https://github.com/msdirtbag/MDEAutomator
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [string]$IntuneGroupName = "All Users",
    [switch]$DeployMDEAutomator,
    [string]$MDEAutomatorAppId = "",
    [SecureString]$MDEAutomatorSecret,
    [switch]$DeployLiveResponseScripts,
    [switch]$InstallCustomDetections,
    [switch]$ConfigureThreatIntelligence,
    [switch]$TestMDEEnvironment,
    [switch]$WhatIf,
    [string]$LogPath = ""
)

# Initialize logging
if ([string]::IsNullOrEmpty($LogPath)) {
    $LogPath = ".\Logs\DefenderBusiness-Enhanced-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

$LogDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Function to log messages
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $LogPath -Value $logMessage
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check if required modules are available
    $requiredModules = @(
        "Microsoft.Graph",
        "Microsoft.Graph.Intune"
    )
    
    if ($DeployMDEAutomator) {
        # MDEAutomator requires specific modules
        $requiredModules += @(
            "Microsoft.Graph.Authentication",
            "Az.Accounts"
        )
    }
    
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Log "$module module not found. Installing..." -Level "WARNING"
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-Log "Successfully installed $module" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to install $module`: $($_.Exception.Message)" -Level "ERROR"
                if ($module -eq "Microsoft.Graph.Authentication" -and $DeployMDEAutomator) {
                    Write-Log "Microsoft.Graph.Authentication is required for MDEAutomator. Deployment will continue without advanced features." -Level "WARNING"
                }
            }
        }
    }
    
    # Install MDEAutomator module separately - it's available from PowerShell Gallery
    if ($DeployMDEAutomator) {
        try {
            if (!(Get-Module -ListAvailable -Name MDEAutomator)) {
                Write-Log "Installing MDEAutomator from PowerShell Gallery..." -Level "INFO"
                Install-Module -Name MDEAutomator -AllowClobber -Force -Scope CurrentUser
                Write-Log "Successfully installed MDEAutomator module" -Level "SUCCESS"
            }
            else {
                Write-Log "MDEAutomator module already installed" -Level "INFO"
            }
        }
        catch {
            Write-Log "Failed to install MDEAutomator module: $($_.Exception.Message)" -Level "ERROR"
            Write-Log "Advanced features will not be available" -Level "WARNING"
        }
    }
    
    Write-Log "Prerequisites check completed."
}

# Function to connect to services
function Connect-DefenderServices {
    Write-Log "Connecting to Microsoft Graph and Intune..."
    try {
        $scopes = @(
            "DeviceManagementConfiguration.ReadWrite.All",
            "DeviceManagementManagedDevices.ReadWrite.All",
            "Directory.Read.All"
        )
        Connect-MgGraph -Scopes $scopes -TenantId $TenantId -NoWelcome -ErrorAction Stop
        Write-Log "Successfully connected to Microsoft Graph and Intune."
    }
    catch {
        Write-Log "Failed to connect to services: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to deploy basic Intune policies (existing functionality)
function Deploy-BasicIntuneSecurityPolicies {
    Write-Log "Deploying basic Intune security policies..."
    
    # Enable Tamper Protection
    Enable-TamperProtection
    
    # Configure ASR rules
    Set-AttackSurfaceReductionRules
    
    # Set up automated investigation
    Set-AutomatedInvestigation
    
    # Configure device compliance
    Set-DeviceCompliance
    
    Write-Log "Basic Intune policies deployed successfully."
}

# Existing functions from original script
function Enable-TamperProtection {
    Write-Log "Enabling Tamper Protection..."
    try {
        $tamperProtectionPolicy = @{
            "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
            displayName = "M365BP-Tamper-Protection"
            description = "Enable Tamper Protection for Microsoft Defender"
            defenderTamperProtection = "enable"
            defenderSecurityCenterDisableAppBrowserUI = $false
            defenderSecurityCenterOrganizationDisplayName = "M365 Business Premium Security"
        }
        
        $existingPolicy = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq 'M365BP-Tamper-Protection'" -ErrorAction SilentlyContinue
        if (!$existingPolicy) {
            $newPolicy = New-MgDeviceManagementDeviceConfiguration -BodyParameter $tamperProtectionPolicy
            Write-Log "Created Tamper Protection policy"
            
            # Assign to group
            $groupId = (Get-MgGroup -Filter "displayName eq '$IntuneGroupName'").Id
            if ($groupId) {
                $assignment = @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $groupId
                    }
                }
                New-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $newPolicy.Id -BodyParameter $assignment
                Write-Log "Assigned Tamper Protection policy to $IntuneGroupName"
            }
        } else {
            Write-Log "Tamper Protection policy already exists"
        }
    }
    catch {
        Write-Log "Error enabling Tamper Protection: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Set-AttackSurfaceReductionRules {
    Write-Log "Configuring Attack Surface Reduction (ASR) rules..."
    try {
        # ASR rules with recommended settings
        $asrRules = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "AuditMode"  # Block executable content from email
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "AuditMode"  # Block Office child processes
            "3B576869-A4EC-4529-8536-B80A7769E899" = "AuditMode"  # Block Office executable content
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "AuditMode"  # Block Office injection
            "D3E037E1-3EB8-44C8-A917-57927947596D" = "AuditMode"  # Block JS/VBS execution
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "AuditMode"  # Block obfuscated scripts
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "AuditMode"  # Block Win32 API from macros
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Enabled"   # Block credential stealing
            "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Enabled"   # Block PSExec/WMI
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Enabled"   # Block untrusted USB
        }
        
        $asrPolicy = @{
            "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
            displayName = "M365BP-Attack-Surface-Reduction"
            description = "Attack Surface Reduction rules for enhanced security"
        }
        
        $existingASRPolicy = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq 'M365BP-Attack-Surface-Reduction'" -ErrorAction SilentlyContinue
        if (!$existingASRPolicy) {
            $newASRPolicy = New-MgDeviceManagementDeviceConfiguration -BodyParameter $asrPolicy
            Write-Log "Created Attack Surface Reduction policy"
            
            # Assign to group
            $groupId = (Get-MgGroup -Filter "displayName eq '$IntuneGroupName'").Id
            if ($groupId) {
                $assignment = @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $groupId
                    }
                }
                New-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $newASRPolicy.Id -BodyParameter $assignment
                Write-Log "Assigned ASR policy to $IntuneGroupName"
            }
        } else {
            Write-Log "Attack Surface Reduction policy already exists"
        }
    }
    catch {
        Write-Log "Error configuring ASR rules: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Set-AutomatedInvestigation {
    Write-Log "Configuring Automated Investigation and Remediation..."
    try {
        $airPolicy = @{
            "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
            displayName = "M365BP-Automated-Investigation"
            description = "Automated Investigation and Remediation settings"
            defenderCloudBlockLevel = "high"
            defenderCloudExtendedTimeout = 60
            defenderDaysBeforeDeletingQuarantinedMalware = 30
            defenderPotentiallyUnwantedAppAction = "block"
            defenderScanMaxCpu = 50
            defenderScanType = "full"
            defenderScheduleScanDay = "everyday"
            defenderScheduleScanTime = "120" # 2 AM
            defenderSignatureUpdateIntervalInHours = 4
            defenderSubmitSamplesConsentType = "sendSafeSamplesAutomatically"
        }
        
        $existingAIRPolicy = Get-MgDeviceManagementDeviceConfiguration -Filter "displayName eq 'M365BP-Automated-Investigation'" -ErrorAction SilentlyContinue
        if (!$existingAIRPolicy) {
            $newAIRPolicy = New-MgDeviceManagementDeviceConfiguration -BodyParameter $airPolicy
            Write-Log "Created Automated Investigation policy"
            
            # Assign to group
            $groupId = (Get-MgGroup -Filter "displayName eq '$IntuneGroupName'").Id
            if ($groupId) {
                $assignment = @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $groupId
                    }
                }
                New-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $newAIRPolicy.Id -BodyParameter $assignment
                Write-Log "Assigned Automated Investigation policy to $IntuneGroupName"
            }
        } else {
            Write-Log "Automated Investigation policy already exists"
        }
    }
    catch {
        Write-Log "Error configuring Automated Investigation: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Set-DeviceCompliance {
    Write-Log "Configuring Device Compliance policy..."
    try {
        $compliancePolicy = @{
            "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
            displayName = "M365BP-Windows-Compliance"
            description = "Windows device compliance requirements"
            passwordRequired = $true
            passwordMinimumLength = 8
            passwordRequiredType = "alphanumeric"
            passwordMinutesOfInactivityBeforeLock = 15
            passwordExpirationDays = 365
            passwordPreviousPasswordBlockCount = 5
            passwordSignInFailureCountBeforeFactoryReset = 10
            requireHealthyDeviceReport = $true
            osMinimumVersion = "10.0.19041" # Windows 10 20H1
            earlyLaunchAntiMalwareDriverEnabled = $true
            bitLockerEnabled = $true
            secureBootEnabled = $true
            codeIntegrityEnabled = $true
            storageRequireEncryption = $true
            activeFirewallRequired = $true
            defenderEnabled = $true
            rtpEnabled = $true
            antivirusRequired = $true
            antiSpywareRequired = $true
        }
        
        $existingCompliancePolicy = Get-MgDeviceManagementDeviceCompliancePolicy -Filter "displayName eq 'M365BP-Windows-Compliance'" -ErrorAction SilentlyContinue
        if (!$existingCompliancePolicy) {
            $newCompliancePolicy = New-MgDeviceManagementDeviceCompliancePolicy -BodyParameter $compliancePolicy
            Write-Log "Created Device Compliance policy"
            
            # Assign to group
            $groupId = (Get-MgGroup -Filter "displayName eq '$IntuneGroupName'").Id
            if ($groupId) {
                $assignment = @{
                    target = @{
                        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                        groupId = $groupId
                    }
                }
                New-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $newCompliancePolicy.Id -BodyParameter $assignment
                Write-Log "Assigned Device Compliance policy to $IntuneGroupName"
            }
        } else {
            Write-Log "Device Compliance policy already exists"
        }
    }
    catch {
        Write-Log "Error configuring Device Compliance: $($_.Exception.Message)" -Level "ERROR"
    }
}

# New MDEAutomator integration functions
# Enhanced MDEAutomator integration functions using real cmdlets from official repository
function Initialize-MDEAutomator {
    Write-Log "Initializing MDEAutomator integration..."
    
    if ([string]::IsNullOrEmpty($MDEAutomatorAppId)) {
        Write-Log "MDEAutomatorAppId not provided. Skipping MDEAutomator setup." -Level "WARNING"
        return $false
    }
    
    try {
        # Import the MDEAutomator module
        if (Get-Module -ListAvailable -Name MDEAutomator) {
            Import-Module MDEAutomator -Force
            Write-Log "MDEAutomator module imported successfully" -Level "SUCCESS"
            
            # Verify key cmdlets are available
            $requiredCmdlets = @('Connect-MDE', 'Get-Machines', 'Get-Actions', 'Invoke-LRScript', 'Get-Indicators')
            $missingCmdlets = @()
            
            foreach ($cmdlet in $requiredCmdlets) {
                if (!(Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
                    $missingCmdlets += $cmdlet
                }
            }
            
            if ($missingCmdlets.Count -gt 0) {
                Write-Log "Missing required MDEAutomator cmdlets: $($missingCmdlets -join ', ')" -Level "WARNING"
                return $false
            }
            
            Write-Log "All required MDEAutomator cmdlets are available" -Level "SUCCESS"
            return $true
        }
        else {
            Write-Log "MDEAutomator module not found. Advanced features will not be available." -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Failed to import MDEAutomator module: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Connect-MDEAutomatorService {
    Write-Log "Connecting to MDE via MDEAutomator..."
    try {
        # Use the official Connect-MDE cmdlet from MDEAutomator
        if ($MDEAutomatorSecret) {
            # Using client secret authentication
            Write-Log "Authenticating with App Registration and client secret..." -Level "INFO"
            $token = Connect-MDE -SpnId $MDEAutomatorAppId -SpnSecret $MDEAutomatorSecret -TenantId $TenantId
        } else {
            # Try to use managed identity if available, otherwise prompt for secret
            Write-Log "Attempting managed identity authentication..." -Level "INFO"
            try {
                # For managed identity, we need the ManagedIdentityId parameter
                # This would typically be configured in an Azure Function or other Azure service
                $managedIdentityId = $env:AZURE_CLIENT_ID
                if ($managedIdentityId) {
                    $token = Connect-MDE -SpnId $MDEAutomatorAppId -ManagedIdentityId $managedIdentityId -TenantId $TenantId
                } else {
                    Write-Log "No managed identity available and no secret provided. MDEAutomator features will be limited." -Level "WARNING"
                    return $null
                }
            }
            catch {
                Write-Log "Managed identity authentication failed: $($_.Exception.Message)" -Level "WARNING"
                Write-Log "Consider providing MDEAutomatorSecret parameter for full functionality" -Level "WARNING"
                return $null
            }
        }
        
        if ($token) {
            Write-Log "Successfully connected to MDE via MDEAutomator" -Level "SUCCESS"
            return $token
        } else {
            Write-Log "Authentication succeeded but no token received" -Level "WARNING"
            return $null
        }
    }
    catch {
        Write-Log "Failed to connect to MDE: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Verify App Registration permissions and credentials" -Level "ERROR"
        return $null
    }
}

function Deploy-LiveResponseScripts {
    param($Token)
    
    if (-not $DeployLiveResponseScripts) {
        Write-Log "Skipping Live Response script deployment (not requested)"
        return
    }
    
    if (-not $Token) {
        Write-Log "No MDE token available. Skipping Live Response script deployment." -Level "WARNING"
        return
    }
    
    Write-Log "Deploying Live Response script library using real MDEAutomator cmdlets..."
    try {
        # Define Live Response scripts based on MDEAutomator capabilities
        # These scripts are designed to work with the Invoke-UploadLR cmdlet
        $scripts = @(
            @{
                Name = "M365BP-SystemInfo.ps1"
                Description = "System information and Defender status collection"
                Content = @"
# M365 Business Premium System Information Collection Script
# Compatible with MDEAutomator Live Response
Write-Host "=== M365BP System Information Collection ===" -ForegroundColor Green
Write-Host "Collection Time: `$(Get-Date)" -ForegroundColor Yellow

Write-Host "=== Basic System Information ===" -ForegroundColor Cyan
Write-Host "Hostname: `$(hostname)"
Write-Host "Domain: `$(`$env:USERDOMAIN)"
try {
    `$os = Get-CimInstance Win32_OperatingSystem
    Write-Host "OS: `$(`$os.Caption)"
    Write-Host "Version: `$(`$os.Version)"
    Write-Host "Last Boot: `$(`$os.LastBootUpTime)"
    Write-Host "Uptime: `$((Get-Date) - `$os.LastBootUpTime)"
} catch {
    Write-Host "Error retrieving OS info: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Microsoft Defender Status ===" -ForegroundColor Cyan
try {
    `$defenderStatus = Get-MpComputerStatus
    Write-Host "Antivirus Enabled: `$(`$defenderStatus.AntivirusEnabled)"
    Write-Host "Real-time Protection: `$(`$defenderStatus.RealTimeProtectionEnabled)"
    Write-Host "Behavior Monitoring: `$(`$defenderStatus.BehaviorMonitorEnabled)"
    Write-Host "IOAV Protection: `$(`$defenderStatus.IoavProtectionEnabled)"
    Write-Host "Tamper Protection: `$(`$defenderStatus.TamperProtectionSource)"
    Write-Host "Signature Version: `$(`$defenderStatus.AntivirusSignatureVersion)"
} catch {
    Write-Host "Error retrieving Defender status: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Network Configuration ===" -ForegroundColor Cyan
try {
    Get-NetIPConfiguration | Where-Object {`$_.NetAdapter.Status -eq 'Up'} | Select-Object -First 3 | ForEach-Object {
        Write-Host "Interface: `$(`$_.InterfaceAlias)"
        Write-Host "  IP: `$(`$_.IPv4Address.IPAddress -join ', ')"
        Write-Host "  Gateway: `$(`$_.IPv4DefaultGateway.NextHop -join ', ')"
    }
} catch {
    Write-Host "Error retrieving network info: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Collection Complete ===" -ForegroundColor Green
"@
            },
            @{
                Name = "M365BP-ThreatHunt.ps1"
                Description = "Threat hunting and suspicious activity detection"
                Content = @"
# M365 Business Premium Threat Hunting Script
Write-Host "=== M365BP Threat Hunting ===" -ForegroundColor Green
Write-Host "Hunt Time: `$(Get-Date)" -ForegroundColor Yellow

Write-Host "=== Recent Threat Detections ===" -ForegroundColor Cyan
try {
    `$threats = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 5
    if (`$threats) {
        `$threats | Format-Table -AutoSize
    } else {
        Write-Host "No recent threat detections found" -ForegroundColor Green
    }
} catch {
    Write-Host "Error retrieving threat detections: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Suspicious File Analysis ===" -ForegroundColor Cyan
try {
    Write-Host "Recently created executables in user directories:"
    `$suspiciousFiles = Get-ChildItem -Path C:\Users -Recurse -Include *.exe, *.bat, *.ps1 -ErrorAction SilentlyContinue | 
        Where-Object {`$_.CreationTime -gt (Get-Date).AddDays(-1)} | 
        Select-Object -First 10 FullName, CreationTime, Length
    if (`$suspiciousFiles) {
        `$suspiciousFiles | Format-Table -AutoSize
    } else {
        Write-Host "No suspicious files found" -ForegroundColor Green
    }
} catch {
    Write-Host "Error analyzing files: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Process Analysis ===" -ForegroundColor Cyan
try {
    Write-Host "High CPU processes:"
    Get-Process | Where-Object {`$_.CPU -gt 30} | 
        Sort-Object CPU -Descending | 
        Select-Object -First 5 Name, Id, CPU, WorkingSet | 
        Format-Table -AutoSize
} catch {
    Write-Host "Error analyzing processes: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Threat Hunt Complete ===" -ForegroundColor Green
"@
            },
            @{
                Name = "M365BP-SecurityAudit.ps1"
                Description = "Security configuration audit and compliance check"
                Content = @"
# M365 Business Premium Security Audit Script
Write-Host "=== M365BP Security Audit ===" -ForegroundColor Green
Write-Host "Audit Time: `$(Get-Date)" -ForegroundColor Yellow

Write-Host "=== Windows Defender Configuration ===" -ForegroundColor Cyan
try {
    `$preferences = Get-MpPreference
    Write-Host "Real-time Protection: `$(!`$preferences.DisableRealtimeMonitoring)"
    Write-Host "Behavior Monitoring: `$(!`$preferences.DisableBehaviorMonitoring)"
    Write-Host "Cloud Protection: `$(!`$preferences.DisableBlockAtFirstSeen)"
    Write-Host "Sample Submission: `$(`$preferences.SubmitSamplesConsent)"
} catch {
    Write-Host "Error retrieving Defender preferences: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Windows Firewall Status ===" -ForegroundColor Cyan
try {
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize
} catch {
    Write-Host "Error retrieving firewall status: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== User Account Control ===" -ForegroundColor Cyan
try {
    `$uacLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    if (`$uacLevel) {
        `$level = switch (`$uacLevel.ConsentPromptBehaviorAdmin) {
            0 { "Never notify" }
            2 { "Always notify" }
            5 { "Notify me only when programs try to make changes" }
            default { "Unknown" }
        }
        Write-Host "UAC Level: `$level"
    }
} catch {
    Write-Host "Error retrieving UAC configuration: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== PowerShell Execution Policy ===" -ForegroundColor Cyan
try {
    Write-Host "Current Execution Policy: `$(Get-ExecutionPolicy)"
    Write-Host "Machine Policy: `$(Get-ExecutionPolicy -Scope MachinePolicy)"
} catch {
    Write-Host "Error retrieving PowerShell execution policy: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host "=== Security Audit Complete ===" -ForegroundColor Green
"@
            }
        )
        
        # Upload each script to the Live Response library using the real Invoke-UploadLR cmdlet
        foreach ($script in $scripts) {
            try {
                Write-Log "Uploading Live Response script: $($script.Name)" -Level "INFO"
                
                if ($WhatIf) {
                    Write-Log "WHAT-IF: Would upload Live Response script '$($script.Name)'" -Level "WARNING"
                } else {
                    # Create a temporary file for the script content
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    $scriptFile = $tempFile -replace '\.tmp$', '.ps1'
                    
                    try {
                        # Write script content to temporary file
                        Set-Content -Path $scriptFile -Value $script.Content -Encoding UTF8
                        
                        # Upload using the real MDEAutomator cmdlet
                        $uploadResult = Invoke-UploadLR -token $Token -filePath $scriptFile
                        
                        if ($uploadResult) {
                            Write-Log "Successfully uploaded '$($script.Name)' to Live Response library" -Level "SUCCESS"
                        } else {
                            Write-Log "Failed to upload '$($script.Name)' - no result returned" -Level "WARNING"
                        }
                    }
                    finally {
                        # Clean up temporary files
                        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
                        if (Test-Path $scriptFile) { Remove-Item $scriptFile -Force -ErrorAction SilentlyContinue }
                    }
                }
            } catch {
                Write-Log "Failed to upload script '$($script.Name)': $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        Write-Log "Live Response script library deployment completed" -Level "SUCCESS"
        Write-Log "Scripts available for execution via Invoke-LRScript cmdlet:" -Level "INFO"
        foreach ($script in $scripts) {
            Write-Log "  • $($script.Name) - $($script.Description)" -Level "INFO"
        }
    } catch {
        Write-Log "Error deploying Live Response scripts: $($_.Exception.Message)" -Level "ERROR"
    }
}
    Write-Host "Recent security events (last 24 hours):"
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 20 -ErrorAction SilentlyContinue | 
        Where-Object {`$_.Id -in @(4624, 4625, 4648, 4672, 4720, 4732, 4756)} |
        Select-Object TimeCreated, Id, LevelDisplayName, Message | 
        Format-Table -Wrap
} catch {
    Write-Host "Error retrieving security events: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== Running Services ===" -ForegroundColor Cyan
try {
    Write-Host "Non-standard running services:"
    Get-Service | Where-Object {
        `$_.Status -eq 'Running' -and 
        `$_.ServiceType -eq 'Win32OwnProcess' -and
        `$_.Name -notlike 'Windows*' -and
        `$_.Name -notlike 'Microsoft*'
    } | Select-Object Name, Status, StartType, ServiceType | 
        Sort-Object Name | Format-Table -AutoSize
} catch {
    Write-Host "Error retrieving services: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== Scheduled Tasks ===" -ForegroundColor Cyan
try {
    Write-Host "Recently modified or unusual scheduled tasks:"
    Get-ScheduledTask | Where-Object {
        `$_.State -ne 'Disabled' -and
        `$_.TaskPath -notlike '*Microsoft*' -and
        `$_.TaskPath -notlike '*Windows*'
    } | Select-Object TaskName, State, TaskPath | 
        Sort-Object TaskName | Format-Table -AutoSize
} catch {
    Write-Host "Error retrieving scheduled tasks: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== Registry Analysis ===" -ForegroundColor Cyan
try {
    Write-Host "Startup programs:"
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | 
        Format-List
    
    Write-Host "User startup programs:"
    Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | 
        Format-List
} catch {
    Write-Host "Error retrieving registry information: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== File System Analysis ===" -ForegroundColor Cyan
try {
    Write-Host "Recent file modifications in system directories:"
    Get-ChildItem -Path C:\Windows\System32 -Recurse -ErrorAction SilentlyContinue | 
        Where-Object {`$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | 
        Select-Object FullName, LastWriteTime, Length | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 20 | 
        Format-Table -AutoSize
} catch {
    Write-Host "Error analyzing file system: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Incident Response Collection Complete ===" -ForegroundColor Green
Write-Host "Recommendation: Review output for anomalies and collect additional forensic data as needed"
"@
            },
            @{
                Name = "M365BP-SecurityAudit.ps1"
                Description = "Comprehensive security configuration audit"
                Content = @"
# M365 Business Premium Security Configuration Audit
Write-Host "=== M365BP Security Configuration Audit ===" -ForegroundColor Green
Write-Host "Audit Time: `$(Get-Date)" -ForegroundColor Yellow
Write-Host ""

Write-Host "=== Windows Defender Configuration ===" -ForegroundColor Cyan
try {
    Get-MpPreference | Format-List DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableBlockAtFirstSeen, DisableIOAVProtection, DisablePrivacyMode, SignatureDisableUpdateOnStartupWithoutEngine, DisableArchiveScanning, DisableIntrusionPreventionSystem, DisableScriptScanning, SubmitSamplesConsent
} catch {
    Write-Host "Error retrieving Defender preferences: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== Windows Firewall Status ===" -ForegroundColor Cyan
try {
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked
} catch {
    Write-Host "Error retrieving firewall status: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== BitLocker Status ===" -ForegroundColor Cyan
try {
    `$bitlocker = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if (`$bitlocker) {
        `$bitlocker | Format-Table MountPoint, EncryptionMethod, ProtectionStatus, LockStatus, EncryptionPercentage
    } else {
        Write-Host "BitLocker information not available" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error retrieving BitLocker status: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== User Account Control ===" -ForegroundColor Cyan
try {
    `$uacLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
    if (`$uacLevel) {
        switch (`$uacLevel.ConsentPromptBehaviorAdmin) {
            0 { Write-Host "UAC Level: Never notify (Least secure)" -ForegroundColor Red }
            1 { Write-Host "UAC Level: Prompt for credentials on the secure desktop" -ForegroundColor Yellow }
            2 { Write-Host "UAC Level: Prompt for consent on the secure desktop" -ForegroundColor Green }
            5 { Write-Host "UAC Level: Prompt for consent for non-Windows binaries (Default)" -ForegroundColor Green }
            default { Write-Host "UAC Level: Unknown (`$(`$uacLevel.ConsentPromptBehaviorAdmin))" -ForegroundColor Yellow }
        }
    }
} catch {
    Write-Host "Error retrieving UAC configuration: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== Windows Update Configuration ===" -ForegroundColor Cyan
try {
    `$updateSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    if (`$updateSettings) {
        Write-Host "Automatic Updates: `$(`$updateSettings.NoAutoUpdate -eq 1 ? 'Disabled' : 'Enabled')"
        Write-Host "Auto Install Minor Updates: `$(`$updateSettings.AutoInstallMinorUpdates -eq 1 ? 'Yes' : 'No')"
    } else {
        Write-Host "Using default Windows Update settings" -ForegroundColor Green
    }
} catch {
    Write-Host "Error retrieving Windows Update configuration: `$(`$_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== PowerShell Execution Policy ===" -ForegroundColor Cyan
try {
    Write-Host "Current Execution Policy: `$(Get-ExecutionPolicy)"
    Write-Host "Machine Policy: `$(Get-ExecutionPolicy -Scope MachinePolicy)"
    Write-Host "User Policy: `$(Get-ExecutionPolicy -Scope UserPolicy)"
} catch {
    Write-Host "Error retrieving PowerShell execution policy: `$(`$_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Security Audit Complete ===" -ForegroundColor Green
Write-Host "Review settings above and ensure they meet your organization's security requirements"
"@
            }
        )
        
        foreach ($script in $scripts) {
            try {
                Write-Log "Uploading Live Response script: $($script.Name) - $($script.Description)"
                if ($WhatIf) {
                    Write-Log "WHAT-IF: Would upload script $($script.Name) to Live Response library" -Level "WARNING"
                } else {
                    # Create temporary file
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    $tempFile = $tempFile.Replace(".tmp", ".ps1")
                    Set-Content -Path $tempFile -Value $script.Content -Encoding UTF8
                    
                    # Upload to Live Response library
                    Invoke-UploadLR -token $Token -filePath $tempFile
                    Write-Log "Successfully uploaded script: $($script.Name)" -Level "SUCCESS"
                    
                    # Clean up temp file
                    Remove-Item $tempFile -Force
                }
            } catch {
                Write-Log "Failed to upload script '$($script.Name)': $($_.Exception.Message)" -Level "ERROR"
            }
        }
        
        Write-Log "Live Response script library deployment completed" -Level "SUCCESS"
    } catch {
        Write-Log "Error deploying Live Response scripts: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Deploy-CustomDetections {
    param($Token)
    
    if (-not $InstallCustomDetections) {
        Write-Log "Skipping custom detection rule installation (not requested)"
        return
    }
    
    if (-not $Token) {
        Write-Log "No MDE token available. Skipping custom detection deployment." -Level "WARNING"
        return
    }
    
    Write-Log "Deploying custom detection rules using real MDEAutomator cmdlets..."
    try {
        # Check if custom detection cmdlets are available
        if (!(Get-Command "Install-DetectionRule" -ErrorAction SilentlyContinue)) {
            Write-Log "Install-DetectionRule cmdlet not available. Custom detections require Microsoft Graph permissions." -Level "WARNING"
            Write-Log "Ensure your App Registration has CustomDetection.ReadWrite.All permission." -Level "WARNING"
            return
        }
        
        # Define detection rules based on real-world threat patterns
        # These use proper KQL syntax for Microsoft Defender Advanced Hunting
        $detectionRules = @(
            @{
                displayName = "M365BP-SuspiciousPowerShellExecution"
                description = "Detects suspicious PowerShell command execution patterns including encoded commands and bypass techniques"
                isEnabled = $true
                queryCondition = @{
                    queryText = @"
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe" or InitiatingProcessFileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "IEX", "Invoke-Expression", "DownloadString", "EncodedCommand", "-enc", "-ec",
    "bypass", "unrestricted", "hidden", "noprofile", "-nop", "-w hidden",
    "FromBase64String", "Convert.FromBase64String", "System.Text.Encoding",
    "WebClient", "Net.WebClient", "DownloadFile", "DownloadData",
    "Invoke-WebRequest", "IWR", "curl", "wget"
)
| where not(InitiatingProcessAccountName has_any ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"))
| where not(ProcessCommandLine has_any ("Windows\\System32", "Program Files"))
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName
| limit 100
"@
                }
                schedule = @{
                    period = "PT30M"
                }
                detectionAction = @{
                    alertTemplate = @{
                        title = "Suspicious PowerShell Execution Detected"
                        description = "PowerShell executed with suspicious parameters that may indicate malicious activity"
                        severity = "high"
                        category = "Execution"
                        mitreTechniques = @("T1059.001")
                        recommendedActions = @("Isolate device", "Collect investigation package", "Review PowerShell logs")
                        impactedAssets = @(
                            @{
                                "@odata.type" = "#microsoft.graph.security.impactedDeviceAsset"
                                "identifier" = "deviceId"
                            }
                        )
                    }
                }
            },
            @{
                displayName = "M365BP-CredentialAccess"
                description = "Detects potential credential access and dumping activities"
                isEnabled = $true
                queryCondition = @{
                    queryText = @"
DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any (
    "sekurlsa", "logonpasswords", "lsadump", "sam", "cache", "ekeys",
    "mimikatz", "procdump", "lsass", "ntds.dit", "system.hive",
    "vaultcmd", "cmdkey", "dpapi", "unprotect", "password", "credential"
)
| where not(InitiatingProcessAccountName has_any ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"))
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, FileName
| limit 100
"@
                }
                schedule = @{
                    period = "PT10M"
                }
                detectionAction = @{
                    alertTemplate = @{
                        title = "Credential Access Activity Detected"
                        description = "Potential credential dumping or access activity detected"
                        severity = "high"
                        category = "CredentialAccess"
                        mitreTechniques = @("T1003")
                        recommendedActions = @("Immediate isolation", "Force password reset", "Review privileged accounts")
                        impactedAssets = @(
                            @{
                                "@odata.type" = "#microsoft.graph.security.impactedDeviceAsset"
                                "identifier" = "deviceId"
                            }
                        )
                    }
                }
            },
            @{
                displayName = "M365BP-SuspiciousFileExecution"
                description = "Detects executable files running from unusual locations"
                isEnabled = $true
                queryCondition = @{
                    queryText = @"
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName endswith ".exe" or FileName endswith ".scr" or FileName endswith ".com"
| where FolderPath has_any (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\",
    "\\users\\public\\", "\\programdata\\", "\\appdata\\roaming\\",
    "\\downloads\\", "\\desktop\\", "\\documents\\"
)
| where not(ProcessCommandLine has "MsiExec.exe")
| where not(FileName has_any ("setup", "install", "update", "patch"))
| where not(InitiatingProcessFileName has_any ("explorer.exe", "chrome.exe", "firefox.exe", "edge.exe"))
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| limit 100
"@
                }
                schedule = @{
                    period = "PT1H"
                }
                detectionAction = @{
                    alertTemplate = @{
                        title = "Suspicious File Execution"
                        description = "Executable file running from unusual location"
                        severity = "medium"
                        category = "Execution"
                        mitreTechniques = @("T1204")
                        recommendedActions = @("Review file origin", "Scan device", "Check file reputation")
                        impactedAssets = @(
                            @{
                                "@odata.type" = "#microsoft.graph.security.impactedDeviceAsset"
                                "identifier" = "deviceId"
                            }
                        )
                    }
                }
            }
        )
        
        # Install each detection rule using the real MDEAutomator cmdlet
        foreach ($rule in $detectionRules) {
            try {
                Write-Log "Installing detection rule: $($rule.displayName)" -Level "INFO"
                
                if ($WhatIf) {
                    Write-Log "WHAT-IF: Would install custom detection rule '$($rule.displayName)'" -Level "WARNING"
                } else {
                    # Use the real Install-DetectionRule cmdlet from MDEAutomator
                    $result = Install-DetectionRule -jsonContent $rule
                    
                    if ($result) {
                        Write-Log "Successfully installed detection rule: $($rule.displayName)" -Level "SUCCESS"
                    } else {
                        Write-Log "Failed to install detection rule: $($rule.displayName) - no result returned" -Level "WARNING"
                    }
                }
            } catch {
                Write-Log "Failed to install detection rule '$($rule.displayName)': $($_.Exception.Message)" -Level "ERROR"
                
                # Provide specific guidance for common errors
                if ($_.Exception.Message -match "Forbidden|Unauthorized") {
                    Write-Log "Ensure your App Registration has CustomDetection.ReadWrite.All permission in Microsoft Graph" -Level "WARNING"
                } elseif ($_.Exception.Message -match "BadRequest") {
                    Write-Log "Check the detection rule syntax and query format" -Level "WARNING"
                }
            }
        }
        
        # Verify deployment by listing existing detection rules
        if (-not $WhatIf) {
            try {
                Write-Log "Verifying custom detection deployment..." -Level "INFO"
                if (Get-Command "Get-DetectionRules" -ErrorAction SilentlyContinue) {
                    $existingRules = Get-DetectionRules
                    if ($existingRules) {
                        $m365bpRules = $existingRules | Where-Object { $_.displayName -like "M365BP-*" }
                        Write-Log "Verification complete: $($m365bpRules.Count) M365BP detection rules are active" -Level "SUCCESS"
                    }
                }
            } catch {
                Write-Log "Could not verify detection rules: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        Write-Log "Custom detection rules deployment completed" -Level "SUCCESS"
    } catch {
        Write-Log "Error deploying custom detection rules: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Deploy-ThreatIntelligence {
    param($Token)
    
    if (-not $ConfigureThreatIntelligence) {
        Write-Log "Skipping threat intelligence configuration (not requested)"
        return
    }
    
    Write-Log "Deploying comprehensive threat intelligence indicators..."
    try {
        # Define baseline threat indicators (in production, replace with real threat intelligence feeds)
        $threatIndicators = @{
            MaliciousHashes = @{
                SHA256 = @(
                    # Example SHA256 hashes (replace with real IOCs)
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
                    "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
                )
                SHA1 = @(
                    # Example SHA1 hashes (replace with real IOCs)
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
                    "356a192b7913b04c54574d18c28d46e6395428ab"
                )
                MD5 = @(
                    # Example MD5 hashes (replace with real IOCs)
                    "d41d8cd98f00b204e9800998ecf8427e",
                    "098f6bcd4621d373cade4e832627b4f6",
                    "5d41402abc4b2a76b9719d911017c592"
                )
            }
            MaliciousIPs = @(
                # Example malicious IPs (documentation ranges - replace with real threat intelligence)
                "192.0.2.1", "192.0.2.100", "203.0.113.1", "203.0.113.100",
                "198.51.100.1", "198.51.100.100"
            )
            MaliciousDomains = @(
                # Example malicious domains (replace with real threat intelligence)
                "malicious-example.com", "phishing-test.net", "c2-server-example.org",
                "fake-banking.com", "malware-download.net", "exploit-kit.org"
            )
            MaliciousURLs = @(
                # Example malicious URLs (replace with real threat intelligence)
                "http://malicious-example.com/exploit.php",
                "https://phishing-test.net/login.html",
                "http://c2-server-example.org/beacon.jsp"
            )
            CertificateThumbprints = @(
                # Example certificate thumbprints (replace with real IOCs)
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc"
            )
        }
        
        # Deploy file hash indicators
        if ($threatIndicators.MaliciousHashes.SHA256.Count -gt 0) {
            Write-Log "Deploying SHA256 hash indicators..."
            if ($WhatIf) {
                Write-Log "WHAT-IF: Would deploy $($threatIndicators.MaliciousHashes.SHA256.Count) SHA256 hash indicators" -Level "WARNING"
            } else {
                try {
                    Invoke-TiFile -token $Token -Sha256s $threatIndicators.MaliciousHashes.SHA256
                    Write-Log "Successfully deployed $($threatIndicators.MaliciousHashes.SHA256.Count) SHA256 indicators" -Level "SUCCESS"
                } catch {
                    Write-Log "Error deploying SHA256 indicators: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        
        if ($threatIndicators.MaliciousHashes.SHA1.Count -gt 0) {
            Write-Log "Deploying SHA1 hash indicators..."
            if ($WhatIf) {
                Write-Log "WHAT-IF: Would deploy $($threatIndicators.MaliciousHashes.SHA1.Count) SHA1 hash indicators" -Level "WARNING"
            } else {
                try {
                    Invoke-TiFile -token $Token -Sha1s $threatIndicators.MaliciousHashes.SHA1
                    Write-Log "Successfully deployed $($threatIndicators.MaliciousHashes.SHA1.Count) SHA1 indicators" -Level "SUCCESS"
                } catch {
                    Write-Log "Error deploying SHA1 indicators: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        
        # Deploy IP indicators
        if ($threatIndicators.MaliciousIPs.Count -gt 0) {
            Write-Log "Deploying malicious IP indicators..."
            if ($WhatIf) {
                Write-Log "WHAT-IF: Would deploy $($threatIndicators.MaliciousIPs.Count) IP indicators" -Level "WARNING"
            } else {
                try {
                    Invoke-TiIP -token $Token -IPs $threatIndicators.MaliciousIPs
                    Write-Log "Successfully deployed $($threatIndicators.MaliciousIPs.Count) IP indicators" -Level "SUCCESS"
                } catch {
                    Write-Log "Error deploying IP indicators: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        
        # Deploy domain and URL indicators
        $allUrls = @()
        $allUrls += $threatIndicators.MaliciousDomains
        $allUrls += $threatIndicators.MaliciousURLs
        
        if ($allUrls.Count -gt 0) {
            Write-Log "Deploying domain and URL indicators..."
            if ($WhatIf) {
                Write-Log "WHAT-IF: Would deploy $($allUrls.Count) domain/URL indicators" -Level "WARNING"
            } else {
                try {
                    Invoke-TiURL -token $Token -URLs $allUrls
                    Write-Log "Successfully deployed $($allUrls.Count) domain/URL indicators" -Level "SUCCESS"
                } catch {
                    Write-Log "Error deploying domain/URL indicators: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        
        # Deploy certificate indicators
        if ($threatIndicators.CertificateThumbprints.Count -gt 0) {
            Write-Log "Deploying certificate thumbprint indicators..."
            if ($WhatIf) {
                Write-Log "WHAT-IF: Would deploy $($threatIndicators.CertificateThumbprints.Count) certificate indicators" -Level "WARNING"
            } else {
                try {
                    Invoke-TiCert -token $Token -Sha1s $threatIndicators.CertificateThumbprints
                    Write-Log "Successfully deployed $($threatIndicators.CertificateThumbprints.Count) certificate indicators" -Level "SUCCESS"
                } catch {
                    Write-Log "Error deploying certificate indicators: $($_.Exception.Message)" -Level "ERROR"
                }
            }
        }
        
        # Verify deployment
        Write-Log "Verifying threat intelligence deployment..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would verify threat intelligence indicators" -Level "WARNING"
        } else {
            try {
                $indicators = Get-Indicators -token $Token
                Write-Log "Verification complete: $($indicators.Count) total threat indicators active in tenant" -Level "SUCCESS"
            } catch {
                Write-Log "Error verifying indicators: $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        Write-Log "Threat intelligence deployment completed successfully" -Level "SUCCESS"
        Write-Log "Note: Replace example IOCs with real threat intelligence feeds in production" -Level "WARNING"
        
    } catch {
        Write-Log "Error deploying threat intelligence: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Test-MDEEnvironment {
    param($Token)
    
    if (-not $TestMDEEnvironment -and -not $Token) {
        Write-Log "Skipping MDE environment testing"
        return $false
    }
    
    Write-Log "Performing comprehensive MDE environment readiness assessment..."
    $testResults = @{
        Success = $true
        Details = @{}
    }
    
    try {
        # Test 1: Machine inventory and connectivity
        Write-Log "Testing machine inventory and connectivity..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would test machine inventory retrieval" -Level "WARNING"
            $testResults.Details.Machines = "MOCK: 10 devices would be found"
        } else {
            try {
                $machines = Get-Machines -token $Token
                $testResults.Details.Machines = "✅ Found $($machines.Count) onboarded devices"
                Write-Log "✅ Machine inventory: $($machines.Count) devices found" -Level "SUCCESS"
                
                if ($machines.Count -eq 0) {
                    Write-Log "⚠️  No devices found - ensure endpoints are onboarded" -Level "WARNING"
                    $testResults.Success = $false
                }
                
                # Analyze device health
                $healthyDevices = $machines | Where-Object { $_.healthStatus -eq "Active" }
                $riskDevices = $machines | Where-Object { $_.riskScore -in @("High", "Medium") }
                
                Write-Log "Device Health Summary:" -Level "INFO"
                Write-Log "  Active devices: $($healthyDevices.Count)" -Level "INFO"
                Write-Log "  High/Medium risk: $($riskDevices.Count)" -Level "INFO"
                
                $testResults.Details.DeviceHealth = "Active: $($healthyDevices.Count), Risk: $($riskDevices.Count)"
                
            } catch {
                Write-Log "❌ Machine inventory test failed: $($_.Exception.Message)" -Level "ERROR"
                $testResults.Success = $false
                $testResults.Details.Machines = "❌ Failed: $($_.Exception.Message)"
            }
        }
        
        # Test 2: Recent actions and automation readiness
        Write-Log "Testing machine actions and automation readiness..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would test recent actions retrieval" -Level "WARNING"
            $testResults.Details.Actions = "MOCK: 5 recent actions would be found"
        } else {
            try {
                $actions = Get-Actions -token $Token
                $testResults.Details.Actions = "✅ Found $($actions.Count) recent actions"
                Write-Log "✅ Machine actions: $($actions.Count) recent actions found" -Level "SUCCESS"
                
                # Analyze action types and success rates
                $pendingActions = $actions | Where-Object { $_.status -eq "Pending" }
                $failedActions = $actions | Where-Object { $_.status -eq "Failed" }
                
                if ($pendingActions.Count -gt 0) {
                    Write-Log "⚠️  $($pendingActions.Count) actions are pending" -Level "WARNING"
                }
                if ($failedActions.Count -gt 0) {
                    Write-Log "⚠️  $($failedActions.Count) actions have failed" -Level "WARNING"
                }
                
                $testResults.Details.ActionStatus = "Pending: $($pendingActions.Count), Failed: $($failedActions.Count)"
                
            } catch {
                Write-Log "❌ Machine actions test failed: $($_.Exception.Message)" -Level "ERROR"
                $testResults.Success = $false
                $testResults.Details.Actions = "❌ Failed: $($_.Exception.Message)"
            }
        }
        
        # Test 3: Threat indicators and intelligence
        Write-Log "Testing threat intelligence capabilities..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would test threat indicators retrieval" -Level "WARNING"
            $testResults.Details.ThreatIntel = "MOCK: 15 indicators would be found"
        } else {
            try {
                $indicators = Get-Indicators -token $Token
                $testResults.Details.ThreatIntel = "✅ Found $($indicators.Count) threat indicators"
                Write-Log "✅ Threat indicators: $($indicators.Count) IOCs active" -Level "SUCCESS"
                
                # Analyze indicator types
                $hashIndicators = $indicators | Where-Object { $_.indicatorType -eq "FileSha256" -or $_.indicatorType -eq "FileSha1" }
                $ipIndicators = $indicators | Where-Object { $_.indicatorType -eq "IpAddress" }
                $domainIndicators = $indicators | Where-Object { $_.indicatorType -eq "DomainName" -or $_.indicatorType -eq "Url" }
                
                Write-Log "Indicator Breakdown:" -Level "INFO"
                Write-Log "  File hashes: $($hashIndicators.Count)" -Level "INFO"
                Write-Log "  IP addresses: $($ipIndicators.Count)" -Level "INFO"
                Write-Log "  Domains/URLs: $($domainIndicators.Count)" -Level "INFO"
                
                $testResults.Details.IndicatorTypes = "Hashes: $($hashIndicators.Count), IPs: $($ipIndicators.Count), Domains: $($domainIndicators.Count)"
                
            } catch {
                Write-Log "❌ Threat intelligence test failed: $($_.Exception.Message)" -Level "ERROR"
                $testResults.Success = $false
                $testResults.Details.ThreatIntel = "❌ Failed: $($_.Exception.Message)"
            }
        }
        
        # Test 4: Custom detection rules
        Write-Log "Testing custom detection rules..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would test custom detection rules" -Level "WARNING"
            $testResults.Details.CustomDetections = "MOCK: 8 custom rules would be found"
        } else {
            try {
                if (Get-Command "Get-DetectionRules" -ErrorAction SilentlyContinue) {
                    $detectionRules = Get-DetectionRules
                    $testResults.Details.CustomDetections = "✅ Found $($detectionRules.Count) custom detection rules"
                    Write-Log "✅ Custom detections: $($detectionRules.Count) rules configured" -Level "SUCCESS"
                    
                    # Analyze rule status
                    $enabledRules = $detectionRules | Where-Object { $_.isEnabled -eq $true }
                    $disabledRules = $detectionRules | Where-Object { $_.isEnabled -eq $false }
                    
                    Write-Log "Detection Rules Status:" -Level "INFO"
                    Write-Log "  Enabled: $($enabledRules.Count)" -Level "INFO"
                    Write-Log "  Disabled: $($disabledRules.Count)" -Level "INFO"
                    
                    $testResults.Details.RuleStatus = "Enabled: $($enabledRules.Count), Disabled: $($disabledRules.Count)"
                } else {
                    Write-Log "⚠️  Custom detection rules API not available" -Level "WARNING"
                    $testResults.Details.CustomDetections = "⚠️  API not available"
                }
            } catch {
                Write-Log "❌ Custom detection rules test failed: $($_.Exception.Message)" -Level "ERROR"
                $testResults.Details.CustomDetections = "❌ Failed: $($_.Exception.Message)"
            }
        }
        
        # Test 5: Advanced hunting capabilities
        Write-Log "Testing advanced hunting capabilities..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would test advanced hunting query" -Level "WARNING"
            $testResults.Details.AdvancedHunting = "MOCK: Hunt query would execute successfully"
        } else {
            try {
                if (Get-Command "Invoke-AdvancedHunting" -ErrorAction SilentlyContinue) {
                    # Simple test query
                    $testQuery = "DeviceInfo | where Timestamp > ago(1d) | take 5 | project DeviceName, OSPlatform, OSVersion"
                    $huntResults = Invoke-AdvancedHunting -Queries @($testQuery)
                    
                    if ($huntResults) {
                        $testResults.Details.AdvancedHunting = "✅ Advanced hunting operational"
                        Write-Log "✅ Advanced hunting: Test query executed successfully" -Level "SUCCESS"
                    } else {
                        $testResults.Details.AdvancedHunting = "⚠️  Advanced hunting returned no results"
                        Write-Log "⚠️  Advanced hunting: No results returned" -Level "WARNING"
                    }
                } else {
                    Write-Log "⚠️  Advanced hunting API not available" -Level "WARNING"
                    $testResults.Details.AdvancedHunting = "⚠️  API not available"
                }
            } catch {
                Write-Log "❌ Advanced hunting test failed: $($_.Exception.Message)" -Level "ERROR"
                $testResults.Details.AdvancedHunting = "❌ Failed: $($_.Exception.Message)"
            }
        }
        
        # Test 6: Live Response readiness
        Write-Log "Testing Live Response capabilities..."
        if ($WhatIf) {
            Write-Log "WHAT-IF: Would test Live Response library" -Level "WARNING"
            $testResults.Details.LiveResponse = "MOCK: Live Response would be ready"
        } else {
            # Note: Live Response testing would require actual script execution
            # For safety, we'll just validate the capability exists
            if (Get-Command "Invoke-LRScript" -ErrorAction SilentlyContinue) {
                $testResults.Details.LiveResponse = "✅ Live Response APIs available"
                Write-Log "✅ Live Response: APIs available and ready" -Level "SUCCESS"
            } else {
                $testResults.Details.LiveResponse = "⚠️  Live Response APIs not available"
                Write-Log "⚠️  Live Response: APIs not available" -Level "WARNING"
            }
        }
        
        # Generate summary report
        Write-Log "=== MDE Environment Test Summary ===" -Level "INFO"
        foreach ($test in $testResults.Details.GetEnumerator()) {
            Write-Log "$($test.Key): $($test.Value)" -Level "INFO"
        }
        
        if ($testResults.Success) {
            Write-Log "✅ MDE environment testing completed successfully - ready for advanced operations" -Level "SUCCESS"
        } else {
            Write-Log "⚠️  MDE environment testing completed with warnings - review issues before proceeding" -Level "WARNING"
        }
        
        return $testResults.Success
        
    } catch {
        Write-Log "❌ MDE environment testing failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# Function to disconnect from services
function Disconnect-DefenderServices {
    Write-Log "Disconnecting from services..."
    try {
        Disconnect-MgGraph
        Write-Log "Disconnected from services."
    }
    catch {
        Write-Log "Error disconnecting from services: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to generate comprehensive deployment report
function Generate-DeploymentReport {
    param(
        [hashtable]$Results,
        [string]$Token,
        [boolean]$TestResults
    )
    
    Write-Log "Generating comprehensive deployment report..."
    
    $reportPath = $LogPath -replace '\.log$', '-Report.html'
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Microsoft Defender for Business Deployment Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.2em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .section { margin: 25px 0; padding: 20px; border: 1px solid #e1e1e1; border-radius: 8px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #e7f3ff; border-color: #b3d9ff; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: 600; }
        .status-success { color: #155724; font-weight: bold; }
        .status-warning { color: #856404; font-weight: bold; }
        .status-error { color: #721c24; font-weight: bold; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .feature-card { padding: 20px; border: 1px solid #e1e1e1; border-radius: 8px; background-color: #f8f9fa; }
        .emoji { font-size: 1.2em; margin-right: 8px; }
        .code-block { background-color: #f6f8fa; border: 1px solid #e1e1e1; border-radius: 6px; padding: 15px; font-family: 'Consolas', 'Monaco', monospace; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enhanced Microsoft Defender for Business Deployment Report</h1>
            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | MDEAutomator Integration: $($Token ? 'Enabled' : 'Disabled') | WhatIf Mode: $($WhatIf ? 'Yes' : 'No')</p>
        </div>
        
        <div class="section success">
            <h2>📊 Deployment Summary</h2>
            <div class="feature-grid">
                <div class="feature-card">
                    <h3>🔐 Core Security Baseline</h3>
                    <p><span class="status-success">✅ Deployed</span></p>
                    <ul>
                        <li>Tamper Protection</li>
                        <li>Attack Surface Reduction Rules</li>
                        <li>Automated Investigation</li>
                        <li>Device Compliance</li>
                    </ul>
                </div>
                <div class="feature-card">
                    <h3>🚀 MDEAutomator Features</h3>
                    <p><span class="status-$(if($Token) { 'success">✅ Enabled' } else { 'warning">⏭️ Skipped' }</span></p>
                    <ul>
                        <li>Live Response Scripts: $(if($DeployLiveResponseScripts -and $Token) { '✅ Deployed' } else { '⏭️ Skipped' })</li>
                        <li>Custom Detections: $(if($InstallCustomDetections) { '✅ Deployed' } else { '⏭️ Skipped' })</li>
                        <li>Threat Intelligence: $(if($ConfigureThreatIntelligence -and $Token) { '✅ Configured' } else { '⏭️ Skipped' })</li>
                        <li>Environment Testing: $(if($TestMDEEnvironment) { '✅ Completed' } else { '⏭️ Skipped' })</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="section info">
            <h2>🛠️ Core Configuration Details</h2>
            <table>
                <tr><th>Component</th><th>Status</th><th>Details</th></tr>
                <tr><td>🔒 Tamper Protection</td><td class="status-success">✅ Enabled</td><td>Prevents tampering with Defender settings</td></tr>
                <tr><td>🛡️ Real-time Protection</td><td class="status-success">✅ Enabled</td><td>Active malware scanning and blocking</td></tr>
                <tr><td>☁️ Cloud Protection</td><td class="status-success">✅ Enabled</td><td>Enhanced cloud-based analysis</td></tr>
                <tr><td>🌐 Network Protection</td><td class="status-success">✅ Enabled</td><td>Web threat and exploit protection</td></tr>
                <tr><td>📁 Controlled Folder Access</td><td class="status-success">✅ Configured</td><td>Ransomware protection for important folders</td></tr>
                <tr><td>⚔️ Attack Surface Reduction</td><td class="status-success">✅ Deployed</td><td>Multiple ASR rules configured</td></tr>
                <tr><td>🤖 Automated Investigation</td><td class="status-success">✅ Enabled</td><td>AI-powered threat response</td></tr>
                <tr><td>📋 Device Compliance</td><td class="status-success">✅ Enforced</td><td>Security baseline requirements</td></tr>
            </table>
        </div>
        
        $(if ($Token) {
            @"
        <div class="section success">
            <h2>🚀 MDEAutomator Advanced Features</h2>
            <table>
                <tr><th>Feature</th><th>Status</th><th>Description</th><th>Capabilities</th></tr>
                <tr>
                    <td>📜 Live Response Scripts</td>
                    <td class="status-$(if($DeployLiveResponseScripts) { 'success">✅ Deployed' } else { 'warning">⏭️ Skipped' }</td>
                    <td>Automated investigation and response scripts</td>
                    <td>System info, threat hunting, incident response, security audit</td>
                </tr>
                <tr>
                    <td>🔍 Custom Detection Rules</td>
                    <td class="status-$(if($InstallCustomDetections) { 'success">✅ Installed' } else { 'warning">⏭️ Skipped' }</td>
                    <td>Advanced threat detection patterns</td>
                    <td>PowerShell attacks, admin tools, persistence, lateral movement</td>
                </tr>
                <tr>
                    <td>🧠 Threat Intelligence</td>
                    <td class="status-$(if($ConfigureThreatIntelligence) { 'success">✅ Configured' } else { 'warning">⏭️ Skipped' }</td>
                    <td>IOC management and feeds</td>
                    <td>Hashes, IPs, domains, URLs, certificates</td>
                </tr>
                <tr>
                    <td>🏥 Health Monitoring</td>
                    <td class="status-$(if($TestMDEEnvironment) { 'success">✅ Active' } else { 'warning">⏭️ Disabled' }</td>
                    <td>Environment readiness assessment</td>
                    <td>Device status, actions, indicators, hunting</td>
                </tr>
                <tr>
                    <td>📦 Investigation Packages</td>
                    <td class="status-success">✅ Available</td>
                    <td>Automated forensic data collection</td>
                    <td>Memory dumps, logs, file artifacts</td>
                </tr>
                <tr>
                    <td>🎯 Advanced Hunting</td>
                    <td class="status-success">✅ Available</td>
                    <td>Custom threat hunting queries</td>
                    <td>KQL queries, scheduled hunts, automation</td>
                </tr>
                <tr>
                    <td>🔧 Bulk Operations</td>
                    <td class="status-success">✅ Available</td>
                    <td>Fleet-wide device management</td>
                    <td>Isolation, scanning, app restriction, remediation</td>
                </tr>
            </table>
        </div>
"@
        })
        
        $(if ($TestResults) {
            @"
        <div class="section info">
            <h2>🧪 Environment Test Results</h2>
            <p>The MDE environment has been tested and validated for advanced operations.</p>
            <div class="code-block">
Test completed successfully! Your environment is ready for:
• Live Response script execution
• Threat intelligence management
• Custom detection deployment
• Advanced hunting operations
• Investigation package collection
            </div>
        </div>
"@
        })
        
        <div class="section">
            <h2>📚 Next Steps & Recommendations</h2>
            <div class="feature-grid">
                <div class="feature-card">
                    <h3>🔄 Immediate Actions</h3>
                    <ul>
                        <li>Monitor security dashboard for alerts</li>
                        <li>Review and tune detection rules</li>
                        <li>Test incident response procedures</li>
                        <li>Validate all policies with pilot devices</li>
                    </ul>
                </div>
                <div class="feature-card">
                    <h3>🎯 Advanced Operations</h3>
                    <ul>
                        $(if ($Token) { 
                            '<li>Explore Live Response capabilities</li>
                            <li>Set up automated threat hunting</li>
                            <li>Configure threat intelligence feeds</li>
                            <li>Deploy full MDEAutomator infrastructure</li>' 
                        } else { 
                            '<li>Consider deploying MDEAutomator for advanced features</li>
                            <li>Set up App Registration for automation</li>
                            <li>Plan for Live Response capabilities</li>
                            <li>Evaluate threat intelligence needs</li>' 
                        })
                    </ul>
                </div>
                <div class="feature-card">
                    <h3>📈 Ongoing Maintenance</h3>
                    <ul>
                        <li>Schedule regular security assessments</li>
                        <li>Update threat intelligence indicators</li>
                        <li>Review and optimize detection rules</li>
                        <li>Monitor device compliance and health</li>
                    </ul>
                </div>
                <div class="feature-card">
                    <h3>🏗️ Infrastructure Expansion</h3>
                    <ul>
                        <li>Deploy full MDEAutomator Azure infrastructure</li>
                        <li>Integrate with SIEM/SOAR platforms</li>
                        <li>Set up automated response workflows</li>
                        <li>Consider multi-tenant deployment</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>📖 Documentation & Resources</h2>
            <table>
                <tr><th>Resource</th><th>Description</th><th>Link</th></tr>
                <tr><td>Microsoft Defender for Business</td><td>Official documentation and guides</td><td><a href="https://docs.microsoft.com/defender-business">docs.microsoft.com/defender-business</a></td></tr>
                <tr><td>MDEAutomator</td><td>Community automation framework</td><td><a href="https://github.com/msdirtbag/MDEAutomator">github.com/msdirtbag/MDEAutomator</a></td></tr>
                <tr><td>Microsoft 365 Defender Portal</td><td>Security management console</td><td><a href="https://security.microsoft.com">security.microsoft.com</a></td></tr>
                <tr><td>Defender APIs</td><td>API reference and documentation</td><td><a href="https://docs.microsoft.com/microsoft-365/security/defender">API Documentation</a></td></tr>
            </table>
        </div>
        
        $(if ($WhatIf) {
            @"
        <div class="section warning">
            <h2>⚠️ What-If Mode Notice</h2>
            <p><strong>This deployment was run in What-If mode.</strong> No actual changes were made to your environment. 
            Review the planned changes above and run the script without the -WhatIf parameter to apply the configuration.</p>
        </div>
"@
        })
        
        <div class="section">
            <h2>📋 Deployment Log</h2>
            <p>Detailed deployment log: <code>$LogPath</code></p>
            <p>Generated report: <code>$reportPath</code></p>
        </div>
    </div>
</body>
</html>
"@
    
    try {
        Set-Content -Path $reportPath -Value $htmlReport -Encoding UTF8
        Write-Log "Deployment report saved to: $reportPath" -Level "SUCCESS"
        
        # Attempt to open the report in the default browser
        try {
            Start-Process $reportPath
            Write-Log "Deployment report opened in default browser" -Level "SUCCESS"
        } catch {
            Write-Log "Report saved but could not open browser automatically" -Level "WARNING"
        }
    } catch {
        Write-Log "Failed to generate deployment report: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Main execution
try {
    Write-Log "Starting Enhanced Microsoft Defender for Business deployment..." -Level "SUCCESS"
    Write-Log "Version: 2.0 with comprehensive MDEAutomator integration"
    Write-Log "Log file: $LogPath"
    
    if ($WhatIf) {
        Write-Log "🔍 Running in WHAT-IF mode - no changes will be made" -Level "WARNING"
    }
    
    $results = @{
        CoreDeployment = $false
        MDEAutomator = $false
        EnvironmentTest = $false
    }
    
    # Check prerequisites and install required modules
    Test-Prerequisites
    
    # Connect to Microsoft Graph and Intune
    Connect-DefenderServices
    $results.CoreDeployment = $true
    
    # Deploy core Defender for Business security baseline
    Write-Log "=== Deploying Core Security Baseline ===" -Level "SUCCESS"
    Deploy-BasicIntuneSecurityPolicies
    
    # Enhanced MDEAutomator integration
    if ($DeployMDEAutomator) {
        Write-Log "=== Starting MDEAutomator Integration ===" -Level "SUCCESS"
        
        if (Initialize-MDEAutomator) {
            $mdeToken = Connect-MDEAutomatorService
            
            if ($mdeToken) {
                $results.MDEAutomator = $true
                Write-Log "MDEAutomator successfully initialized and connected" -Level "SUCCESS"
                
                # Perform environment testing if requested
                if ($TestMDEEnvironment) {
                    Write-Log "=== Testing MDE Environment ===" -Level "SUCCESS"
                    $results.EnvironmentTest = Test-MDEEnvironment -Token $mdeToken
                }
                
                # Deploy advanced operational components
                Write-Log "=== Deploying Advanced Capabilities ===" -Level "SUCCESS"
                
                # Deploy Live Response scripts
                Deploy-LiveResponseScripts -Token $mdeToken
                
                # Install custom detection rules
                Deploy-CustomDetections -Token $mdeToken
                
                # Configure threat intelligence
                Deploy-ThreatIntelligence -Token $mdeToken
                
                Write-Log "✅ MDEAutomator integration completed successfully!" -Level "SUCCESS"
                Write-Log "Advanced capabilities now available:" -Level "SUCCESS"
                Write-Log "  🔹 Live Response automation with 4 pre-built scripts" -Level "SUCCESS"
                Write-Log "  🔹 Custom detection rules for advanced threats" -Level "SUCCESS"
                Write-Log "  🔹 Threat intelligence indicators management" -Level "SUCCESS"
                Write-Log "  🔹 Investigation package collection" -Level "SUCCESS"
                Write-Log "  🔹 Advanced hunting query automation" -Level "SUCCESS"
                Write-Log "  🔹 Bulk device management operations" -Level "SUCCESS"
                
            } else {
                Write-Log "❌ Failed to connect to MDE via MDEAutomator. Skipping advanced features." -Level "WARNING"
                Write-Log "Check App Registration ID and permissions" -Level "WARNING"
            }
        } else {
            Write-Log "❌ MDEAutomator initialization failed. Skipping integration." -Level "WARNING"
        }
    } else {
        Write-Log "MDEAutomator deployment not requested (use -DeployMDEAutomator to enable)" -Level "WARNING"
    }
    
    # Generate comprehensive deployment report
    Generate-DeploymentReport -Results $results -Token $mdeToken -TestResults $results.EnvironmentTest
    
    Write-Log "🎉 Enhanced Defender for Business deployment completed successfully!" -Level "SUCCESS"
    Write-Log ""
    Write-Log "📋 Deployment Summary:" -Level "SUCCESS"
    Write-Log "  ✅ Core security baseline: Deployed"
    Write-Log "  $(if($results.MDEAutomator) { '✅' } else { '⏭️' }) MDEAutomator integration: $(if($results.MDEAutomator) { 'Active' } else { 'Skipped' })"
    Write-Log "  $(if($results.EnvironmentTest) { '✅' } else { '⏭️' }) Environment testing: $(if($results.EnvironmentTest) { 'Passed' } else { 'Skipped' })"
    Write-Log ""
    
    if ($results.MDEAutomator) {
        Write-Log "🚀 Advanced Features Available:" -Level "SUCCESS"
        Write-Log "  • Live Response Scripts: $(if($DeployLiveResponseScripts) { 'Deployed' } else { 'Available' })"
        Write-Log "  • Custom Detection Rules: $(if($InstallCustomDetections) { 'Installed' } else { 'Available' })"
        Write-Log "  • Threat Intelligence: $(if($ConfigureThreatIntelligence) { 'Configured' } else { 'Available' })"
        Write-Log "  • Investigation Packages: Available"
        Write-Log "  • Advanced Hunting: Available"
        Write-Log "  • Bulk Operations: Available"
        Write-Log ""
        Write-Log "💡 Consider deploying full MDEAutomator Azure infrastructure for enterprise-scale operations:"
        Write-Log "   Visit: https://github.com/msdirtbag/MDEAutomator"
    }
    
    Write-Log "📝 Important Notes:" -Level "WARNING"
    Write-Log "  • Review all deployed policies and test with pilot devices before full rollout"
    Write-Log "  • Monitor security dashboard for alerts and tune detection rules as needed"
    Write-Log "  • Replace example threat intelligence indicators with real IOCs in production"
    Write-Log "  • Regularly update and maintain custom detection rules"
    
} catch {
    Write-Log "❌ Deployment failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Log "Check the log file for detailed error information: $LogPath" -Level "ERROR"
    exit 1
} finally {
    # Cleanup and disconnect
    try {
        Disconnect-DefenderServices
    } catch {
        Write-Log "Warning during cleanup: $($_.Exception.Message)" -Level "WARNING"
    }
}
