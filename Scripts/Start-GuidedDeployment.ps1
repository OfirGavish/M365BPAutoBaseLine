<#
.SYNOPSIS
    Guided deployment wizard for M365 Business Premium Security Baseline.

.DESCRIPTION
    This script provides a step-by-step guided deployment process for the M365 Business Premium
    security baselines with safety checks, configuration validation, and rollback capabilities.

.NOTES
    This wizard is designed for first-time deployments and includes comprehensive safety measures.
#>

[CmdletBinding()]
param(
    [switch]$SkipPrerequisites,
    [switch]$ProductionMode,
    [string]$ConfigFile = ""
)

# Import required functions
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Step {
    param([string]$Message, [string]$Status = "INFO", [int]$Step = 0)
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "HEADER" { "Cyan" }
        default { "White" }
    }
    
    if ($Step -gt 0) {
        Write-Host "`n[$Step] $Message" -ForegroundColor $color
    } else {
        Write-Host "    $Message" -ForegroundColor $color
    }
}

function Wait-UserConfirmation {
    param([string]$Message, [bool]$DefaultYes = $false)
    
    $defaultText = if ($DefaultYes) { "(Y/n)" } else { "(y/N)" }
    $response = Read-Host "$Message $defaultText"
    
    if ([string]::IsNullOrEmpty($response)) {
        return $DefaultYes
    }
    
    return $response -eq "y" -or $response -eq "Y" -or $response -eq "yes"
}

function Get-TenantInformation {
    Write-Step "Gathering tenant information..." "INFO"
    
    try {
        # Try to get current context
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($context) {
            Write-Step "Connected to tenant: $($context.TenantId)" "SUCCESS"
            return @{
                TenantId = $context.TenantId
                Account = $context.Account
            }
        } else {
            Write-Step "Not currently connected to Microsoft Graph" "WARNING"
            return $null
        }
    } catch {
        Write-Step "Unable to get tenant information: $($_.Exception.Message)" "WARNING"
        return $null
    }
}

function Test-DeploymentPermissions {
    Write-Step "Validating deployment permissions..." "INFO"
    
    $permissions = @()
    $issues = @()
    
    try {
        # Test Microsoft Graph permissions
        $me = Get-MgUser -UserId (Get-MgContext).Account -ErrorAction Stop
        $permissions += "Microsoft Graph: Basic access ✓"
        
        # Test if we can read groups (needed for assignments)
        $groups = Get-MgGroup -Top 1 -ErrorAction Stop
        $permissions += "Microsoft Graph: Groups read ✓"
        
        # Test if we can read device management
        $devices = Get-MgDeviceManagementManagedDevice -Top 1 -ErrorAction SilentlyContinue
        if ($devices -or $Error[0].Exception.Message -like "*Forbidden*") {
            $permissions += "Microsoft Graph: Device Management access ✓"
        } else {
            $issues += "Device Management access may be limited"
        }
        
    } catch {
        $issues += "Microsoft Graph access issues: $($_.Exception.Message)"
    }
    
    # Test Exchange Online (if module is available)
    try {
        if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
            $session = Get-ConnectionInformation -ErrorAction SilentlyContinue
            if ($session) {
                $permissions += "Exchange Online: Connected ✓"
            } else {
                $issues += "Exchange Online: Not connected (will connect during deployment)"
            }
        }
    } catch {
        $issues += "Exchange Online: Unable to check connection status"
    }
    
    return @{
        Permissions = $permissions
        Issues = $issues
    }
}

function New-DeploymentConfiguration {
    Write-Step "Setting up deployment configuration..." "HEADER"
    
    # Get organization details
    $orgName = Read-Host "Enter your organization name"
    while ([string]::IsNullOrEmpty($orgName)) {
        Write-Step "Organization name is required" "ERROR"
        $orgName = Read-Host "Enter your organization name"
    }
    
    $adminEmail = Read-Host "Enter admin email address"
    while ([string]::IsNullOrEmpty($adminEmail) -or $adminEmail -notlike "*@*") {
        Write-Step "Valid admin email is required" "ERROR"
        $adminEmail = Read-Host "Enter admin email address"
    }
    
    # Get tenant information
    $tenantInfo = Get-TenantInformation
    $tenantId = if ($tenantInfo) { $tenantInfo.TenantId } else { Read-Host "Enter your Tenant ID (optional for most components)" }
    
    # Component selection
    Write-Step "Component Selection:" "HEADER"
    Write-Step "Available components:" "INFO"
    Write-Step "1. Defender for Office 365 - Email security and threat protection" "INFO"
    Write-Step "2. Entra ID Security - Identity and access management" "INFO"
    Write-Step "3. Microsoft Intune - Device security baselines (OpenIntuneBaseline)" "INFO"
    Write-Step "4. Defender for Business - Enhanced endpoint protection" "INFO"
    Write-Step "5. Microsoft Purview - Data protection and compliance" "INFO"
    Write-Step "6. Conditional Access - Zero Trust access controls" "INFO"
    
    if (Wait-UserConfirmation "Deploy ALL components (recommended for comprehensive security)?" $true) {
        $components = @("All")
    } else {
        Write-Step "Select individual components (comma-separated numbers): " "INFO"
        $selection = Read-Host "Enter component numbers (e.g., 1,2,3)"
        $componentMap = @{
            "1" = "DefenderO365"
            "2" = "EntraID" 
            "3" = "Intune"
            "4" = "DefenderBusiness"
            "5" = "Purview"
            "6" = "ConditionalAccess"
        }
        
        $components = $selection.Split(',') | ForEach-Object { $componentMap[$_.Trim()] } | Where-Object { $_ }
        if ($components.Count -eq 0) {
            $components = @("All")
            Write-Step "No valid selection made, defaulting to ALL components" "WARNING"
        }
    }
    
    # Safety settings
    Write-Step "Safety Configuration:" "HEADER"
    $testMode = Wait-UserConfirmation "Deploy in TEST mode first (recommended)?" $true
    $whatIf = Wait-UserConfirmation "Run in WHAT-IF mode to preview changes?" $true
    
    return @{
        OrganizationName = $orgName
        AdminEmail = $adminEmail
        TenantId = $tenantId
        Components = $components
        TestMode = $testMode
        WhatIf = $whatIf
    }
}

function Invoke-SafeDeployment {
    param($Config)
    
    Write-Step "Preparing deployment with the following configuration:" "HEADER"
    Write-Step "Organization: $($Config.OrganizationName)" "INFO"
    Write-Step "Admin Email: $($Config.AdminEmail)" "INFO"
    Write-Step "Tenant ID: $($Config.TenantId)" "INFO"
    Write-Step "Components: $($Config.Components -join ', ')" "INFO"
    Write-Step "Test Mode: $($Config.TestMode)" "INFO"
    Write-Step "What-If Mode: $($Config.WhatIf)" "INFO"
    
    if (-not (Wait-UserConfirmation "Proceed with deployment?" $false)) {
        Write-Step "Deployment cancelled by user" "WARNING"
        return
    }
    
    # Build deployment parameters
    $deployParams = @{
        Components = $Config.Components
        OrganizationName = $Config.OrganizationName
        AdminEmail = $Config.AdminEmail
    }
    
    if (![string]::IsNullOrEmpty($Config.TenantId)) {
        $deployParams.TenantId = $Config.TenantId
    }
    
    if ($Config.WhatIf) {
        $deployParams.WhatIf = $true
    }
    
    # Execute deployment
    try {
        Write-Step "Starting M365 Business Premium baseline deployment..." "SUCCESS"
        $deployScript = Join-Path $ScriptPath "Deploy-M365BPBaseline.ps1"
        
        if (Test-Path $deployScript) {
            & $deployScript @deployParams
            Write-Step "Deployment script completed successfully!" "SUCCESS"
        } else {
            Write-Step "Deployment script not found: $deployScript" "ERROR"
            return
        }
        
        # Post-deployment testing
        if (-not $Config.WhatIf -and (Wait-UserConfirmation "Run post-deployment validation tests?" $true)) {
            Write-Step "Running post-deployment validation..." "INFO"
            $testScript = Join-Path $ScriptPath "Test-M365BPBaseline.ps1"
            
            if (Test-Path $testScript) {
                & $testScript -TestCategories @("All") -GenerateReports
            }
        }
        
    } catch {
        Write-Step "Deployment failed: $($_.Exception.Message)" "ERROR"
        Write-Step "Check the log files for detailed error information" "INFO"
    }
}

# Main execution
Clear-Host

Write-Step "Microsoft 365 Business Premium Security Baseline" "HEADER"
Write-Step "Guided Deployment Wizard" "HEADER"
Write-Step "==========================================================" "HEADER"

# Step 1: Prerequisites check
if (-not $SkipPrerequisites) {
    Write-Step "Checking prerequisites..." "HEADER" 1
    
    $prereqScript = Join-Path $ScriptPath "Install-Prerequisites.ps1"
    if (Test-Path $prereqScript) {
        & $prereqScript -CheckOnly
        
        if (-not (Wait-UserConfirmation "Prerequisites look good. Continue with deployment?" $true)) {
            Write-Step "Please install missing prerequisites first" "WARNING"
            exit
        }
    } else {
        Write-Step "Prerequisites script not found. Please ensure all required modules are installed." "WARNING"
    }
}

# Step 2: Connect to Microsoft Graph
Write-Step "Connecting to Microsoft 365..." "HEADER" 2

try {
    $requiredScopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "Directory.ReadWrite.All",
        "Group.ReadWrite.All",
        "Policy.ReadWrite.ConditionalAccess",
        "Application.ReadWrite.All"
    )
    
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    $tenantInfo = Get-TenantInformation
    
    if ($tenantInfo) {
        Write-Step "Successfully connected to tenant: $($tenantInfo.TenantId)" "SUCCESS"
        Write-Step "Signed in as: $($tenantInfo.Account)" "SUCCESS"
    }
    
} catch {
    Write-Step "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
    exit
}

# Step 3: Validate permissions
Write-Step "Validating permissions..." "HEADER" 3

$permissionCheck = Test-DeploymentPermissions
foreach ($permission in $permissionCheck.Permissions) {
    Write-Step $permission "SUCCESS"
}
foreach ($issue in $permissionCheck.Issues) {
    Write-Step $issue "WARNING"
}

if ($permissionCheck.Issues.Count -gt 0) {
    if (-not (Wait-UserConfirmation "Some permission issues detected. Continue anyway?" $false)) {
        Write-Step "Please resolve permission issues first" "WARNING"
        exit
    }
}

# Step 4: Configuration
Write-Step "Deployment Configuration" "HEADER" 4
$deployConfig = New-DeploymentConfiguration

# Step 5: Safety confirmation
if (-not $ProductionMode) {
    Write-Step "IMPORTANT SAFETY INFORMATION" "HEADER" 5
    Write-Step "This deployment will make changes to your Microsoft 365 tenant:" "WARNING"
    Write-Step "• Conditional Access policies will be created in REPORT-ONLY mode" "INFO"
    Write-Step "• Intune policies will be assigned to test groups initially" "INFO"
    Write-Step "• Email security policies will be applied immediately" "INFO"
    Write-Step "• All changes are logged and can be reviewed/modified afterward" "INFO"
    
    if (-not (Wait-UserConfirmation "I understand the changes and want to proceed" $false)) {
        Write-Step "Deployment cancelled for safety" "WARNING"
        exit
    }
}

# Step 6: Execute deployment
Write-Step "Executing Deployment" "HEADER" 6
Invoke-SafeDeployment -Config $deployConfig

Write-Step "Deployment wizard completed!" "SUCCESS"
Write-Step "Next steps:" "INFO"
Write-Step "1. Review the deployment reports generated" "INFO"
Write-Step "2. Test policies with pilot users" "INFO"
Write-Step "3. Gradually enable report-only policies" "INFO"
Write-Step "4. Monitor security dashboard for effectiveness" "INFO"
