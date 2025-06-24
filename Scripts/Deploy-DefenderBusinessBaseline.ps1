<#
.SYNOPSIS
    Automates deployment of Defender for Business (Endpoint) security baselines.

.DESCRIPTION
    This script configures Defender for Business with security best practices including:
    - Tamper Protection enablement
    - Attack Surface Reduction (ASR) rules via Intune
    - Automated investigation and remediation
    - Vulnerability management settings
    - Device onboarding and compliance

.PARAMETER TenantId
    Azure AD Tenant ID for device management

.PARAMETER IntuneGroupName
    Name of the Intune group for device policies (default: "All Users")

.EXAMPLE
    .\Deploy-DefenderBusinessBaseline.ps1 -TenantId "12345678-1234-1234-1234-123456789012"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    [string]$IntuneGroupName = "All Users"
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
        "Microsoft.Graph",
        "Microsoft.Graph.Intune"
    )
    
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Log "$module module not found. Installing..." -Level "WARNING"
            Install-Module -Name $module -Force -AllowClobber
        }
    }
    
    Write-Log "Prerequisites check completed."
}

# Function to connect to Microsoft Graph and Intune
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

# Function to enable Tamper Protection
function Enable-TamperProtection {
    Write-Log "Enabling Tamper Protection..."
    try {
        # Create Endpoint Protection policy for Tamper Protection
        $tamperProtectionPolicy = @{
            "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
            displayName = "M365BP-Tamper-Protection"
            description = "Enable Tamper Protection for Microsoft Defender"
            defenderTamperProtection = "enable"
            defenderSecurityCenterDisableAppBrowserUI = $false
            defenderSecurityCenterDisableFamilyUI = $false
            defenderSecurityCenterDisableHealthUI = $false
            defenderSecurityCenterDisableNetworkUI = $false
            defenderSecurityCenterDisableVirusUI = $false
            defenderSecurityCenterOrganizationDisplayName = "M365 Business Premium Security"
            defenderSecurityCenterHelpEmail = "security@company.com"
            defenderSecurityCenterHelpPhone = "555-0123"
            defenderSecurityCenterHelpURL = "https://company.com/security"
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

# Function to configure Attack Surface Reduction rules
function Set-AttackSurfaceReductionRules {
    Write-Log "Configuring Attack Surface Reduction (ASR) rules..."
    try {
        # Define ASR rules with recommended settings
        $asrRules = @{
            # Block executable content from email client and webmail
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "AuditMode"
            # Block all Office applications from creating child processes
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "AuditMode"
            # Block Office applications from creating executable content
            "3B576869-A4EC-4529-8536-B80A7769E899" = "AuditMode"
            # Block Office applications from injecting code into other processes
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "AuditMode"
            # Block JavaScript or VBScript from launching downloaded executable content
            "D3E037E1-3EB8-44C8-A917-57927947596D" = "AuditMode"
            # Block execution of potentially obfuscated scripts
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "AuditMode"
            # Block Win32 API calls from Office macros
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "AuditMode"
            # Block credential stealing from the Windows local security authority subsystem
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Enabled"
            # Block process creations originating from PSExec and WMI commands
            "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Enabled"
            # Block untrusted and unsigned processes that run from USB
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Enabled"
        }
        
        $asrPolicy = @{
            "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
            displayName = "M365BP-Attack-Surface-Reduction"
            description = "Attack Surface Reduction rules for enhanced security"
            defenderAttackSurfaceReductionOnlyExclusions = @()
        }
        
        # Add ASR rules to policy
        foreach ($ruleId in $asrRules.Keys) {
            $asrPolicy["defenderAttackSurfaceType$ruleId"] = $asrRules[$ruleId]
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

# Function to configure Automated Investigation and Remediation
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
            defenderDetectedMalwareActions = @{
                lowSeverity = "quarantine"
                moderateSeverity = "quarantine"
                highSeverity = "quarantine"
                severeSeverity = "quarantine"
            }
            defenderFileExtensionsToExclude = @()
            defenderFilesAndFoldersToExclude = @()
            defenderProcessesToExclude = @()
            defenderPotentiallyUnwantedAppAction = "block"
            defenderScanMaxCpu = 50
            defenderScanType = "full"
            defenderScheduleScanDay = "everyday"
            defenderScheduleScanTime = "120" # 2 AM
            defenderSignatureUpdateIntervalInHours = 4
            defenderSubmitSamplesConsentType = "sendSafeSamplesAutomatically"
            defenderSystemScanSchedule = "userDefined"
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

# Function to configure Device Compliance policy
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
            passwordRequiredToUnlockFromIdle = $true
            requireHealthyDeviceReport = $true
            osMinimumVersion = "10.0.19041" # Windows 10 20H1
            osMaximumVersion = $null
            mobileOsMinimumVersion = $null
            mobileOsMaximumVersion = $null
            earlyLaunchAntiMalwareDriverEnabled = $true
            bitLockerEnabled = $true
            secureBootEnabled = $true
            codeIntegrityEnabled = $true
            storageRequireEncryption = $true
            activeFirewallRequired = $true
            defenderEnabled = $true
            defenderVersion = $null
            signatureOutOfDate = $false
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

# Main execution
try {
    Write-Log "Starting Defender for Business baseline deployment..."
    
    Test-Prerequisites
    Connect-DefenderServices
    
    Enable-TamperProtection
    Set-AttackSurfaceReductionRules
    Set-AutomatedInvestigation
    Set-DeviceCompliance
    
    Write-Log "Defender for Business baseline deployment completed successfully!"
    Write-Log "Note: Device onboarding and additional vulnerability management settings may require manual configuration in the Microsoft 365 Defender portal."
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-DefenderServices
}
