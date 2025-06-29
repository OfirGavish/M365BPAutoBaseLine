<#
.SYNOPSIS
    Master deployment script for Microsoft 365 Business Premium security baselines.

.DESCRIPTION
    This script orchestrates the deployment of all M365 Business Premium security baselines:
    - Defender for Office 365
    - Entra ID (Azure AD) security controls
    - Microsoft Purview compliance
    - Enhanced Defender for Business (Endpoint) with MDEAutomator integration
    - Microsoft Intune device security baselines (OpenIntuneBaseline)
    - Conditional Access policies (deployed in report-only mode for safety)
    - Tenant-wide hardening

.PARAMETER Components
    Array of components to deploy. Options: "DefenderO365", "EntraID", "Purview", "DefenderBusiness", "Intune", "ConditionalAccess", "All"

.PARAMETER OrganizationName
    Name of your organization (required for Purview)

.PARAMETER TenantId
    Azure AD Tenant ID (required for Defender for Business)

.PARAMETER AdminEmail
    Admin email for notifications and reviews

.PARAMETER ConfigFile
    Path to configuration file with custom settings (optional)

.PARAMETER DeployAdvancedMDEFeatures
    Deploy advanced MDE features including Live Response scripts, custom detections, and threat intelligence (default: true)

.EXAMPLE
    .\Deploy-M365BPBaseline.ps1 -Components @("All") -OrganizationName "Contoso" -TenantId "12345678-1234-1234-1234-123456789012" -AdminEmail "admin@contoso.com"

.EXAMPLE
    .\Deploy-M365BPBaseline.ps1 -Components @("DefenderO365", "EntraID") -OrganizationName "Contoso" -AdminEmail "admin@contoso.com"
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("DefenderO365", "EntraID", "Purview", "DefenderBusiness", "ConditionalAccess", "Intune", "All")]
    [string[]]$Components,
    
    [Parameter(Mandatory=$true)]
    [string]$OrganizationName,
    
    [string]$TenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$AdminEmail,
    
    [string]$ConfigFile = "",
    
    [switch]$WhatIf = $false,
    
    [switch]$RunPostDeploymentTests = $true,
    
    [switch]$GenerateTestReports = $true,
    
    [switch]$DeployAdvancedMDEFeatures = $true
)

# Global variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$LogFile = Join-Path $ScriptPath "M365BP-Deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$TranscriptFile = Join-Path $ScriptPath "M365BP-FullTranscript-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Start transcript for complete session logging
Start-Transcript -Path $TranscriptFile -Append

# Function to log messages with consolidated logging
function Write-Log {
    param(
        [string]$Message, 
        [string]$Level = "INFO",
        [switch]$NoConsole,
        [string]$Component = "MAIN"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Component] [$Level] $Message"
    
    # Write to consolidated log file
    Add-Content -Path $LogFile -Value $logEntry
    
    # Write to console unless suppressed
    if (!$NoConsole) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            "INFO" { "Cyan" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

# Function to display banner
function Show-Banner {
    $banner = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                Microsoft 365 Business Premium Security Baseline             ║
║                           Automated Deployment Tool                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Log "Starting M365 Business Premium baseline deployment for: $OrganizationName"
    Write-Log "Components to deploy: $($Components -join ', ')"
    Write-Log "Log file: $LogFile"
}

# Function to validate prerequisites and load modules safely
function Test-Prerequisites {
    Write-Log "Validating prerequisites..."
    
    # Check if modules are already loaded to prevent conflicts
    $loadedModules = Get-Module | Select-Object -ExpandProperty Name
    
    $requiredModules = @(
        @{Name = "ExchangeOnlineManagement"; Components = @("DefenderO365", "All")},
        @{Name = "Microsoft.Graph.Authentication"; Components = @("EntraID", "DefenderBusiness", "Intune", "ConditionalAccess", "All")},
        @{Name = "Microsoft.Graph.DeviceManagement"; Components = @("DefenderBusiness", "Intune", "All")},
        @{Name = "Microsoft.Graph.Identity.SignIns"; Components = @("EntraID", "ConditionalAccess", "All")},
        @{Name = "Microsoft.Graph.Groups"; Components = @("EntraID", "DefenderBusiness", "Intune", "All")},
        @{Name = "PnP.PowerShell"; Components = @("Purview", "All")}
    )
    
    $missingModules = @()
    $needsModules = @()
    
    # Determine which modules we need based on selected components
    foreach ($moduleInfo in $requiredModules) {
        $needsModule = $false
        foreach ($component in $Components) {
            if ($moduleInfo.Components -contains $component) {
                $needsModule = $true
                break
            }
        }
        
        if ($needsModule) {
            $needsModules += $moduleInfo.Name
            if (!(Get-Module -ListAvailable -Name $moduleInfo.Name)) {
                $missingModules += $moduleInfo.Name
            }
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing required modules: $($missingModules -join ', ')" -Level "ERROR"
        throw "Please install missing modules using Install-Prerequisites.ps1"
    }
    
    # Import required modules if not already loaded (prevents conflicts)
    foreach ($moduleName in $needsModules) {
        if ($loadedModules -notcontains $moduleName) {
            try {
                Write-Log "Loading module: $moduleName"
                Import-Module $moduleName -Force -ErrorAction Stop
                Write-Log "Successfully loaded: $moduleName" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to load module $moduleName : $($_.Exception.Message)" -Level "ERROR"
                throw "Module loading failed: $moduleName"
            }
        } else {
            Write-Log "Module already loaded: $moduleName"
        }
    }
    
    # Validate required parameters based on components
    if (($Components -contains "DefenderBusiness" -or $Components -contains "All") -and [string]::IsNullOrEmpty($TenantId)) {
        throw "TenantId is required when deploying Defender for Business component"
    }
    
    Write-Log "Prerequisites validation completed" -Level "SUCCESS"
}

# Function to load configuration
function Get-Configuration {
    $config = @{
        RetentionPeriodYears = 7
        PolicyPreset = "Standard"
        EnableSecurityDefaults = $false
        ServiceAccounts = @()
        IntuneGroupName = "All Users"
        DeployAdvancedFeatures = $DeployAdvancedMDEFeatures  # Use parameter to control advanced features
        AllowedCountries = @("US", "CA", "GB", "AU", "DE", "FR", "NL", "BE", "LU")
        BreakGlassAccounts = @()
        # Intune-specific configuration
        IncludeMacOS = $false
        IncludeBYOD = $false
        IntuneBaselineVersion = "Latest"
        IntuneImportMethod = "IntuneManagement"
    }
    
    if (![string]::IsNullOrEmpty($ConfigFile) -and (Test-Path $ConfigFile)) {
        Write-Log "Loading configuration from: $ConfigFile"
        $customConfig = Get-Content $ConfigFile | ConvertFrom-Json
        foreach ($property in $customConfig.PSObject.Properties) {
            $config[$property.Name] = $property.Value
        }
        Write-Log "Configuration loaded successfully"
    } else {
        Write-Log "Using default configuration"
    }
    
    return $config
}

# Function to deploy Defender for Office 365
function Deploy-DefenderO365 {
    param($Config)
    
    Write-Log "=== Deploying Defender for Office 365 Baseline ===" -Level "INFO"
    
    try {
        $scriptPath = Join-Path $ScriptPath "Deploy-DefenderO365Baseline.ps1"
        if (Test-Path $scriptPath) {
            $params = @{
                ServiceAccounts = $Config.ServiceAccounts
                PolicyPreset = $Config.PolicyPreset
            }
            
            # Add WhatIf parameter if specified
            if ($WhatIf) {
                $params.Add("WhatIf", $true)
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Deploy-DefenderO365Baseline.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                & $scriptPath @params
            }
            Write-Log "Defender for Office 365 deployment completed" -Level "SUCCESS"
        } else {
            Write-Log "Defender for Office 365 script not found: $scriptPath" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error deploying Defender for Office 365: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to deploy Entra ID baseline
function Deploy-EntraID {
    param($Config)
    
    Write-Log "=== Deploying Entra ID Security Baseline ===" -Level "INFO"
    
    try {
        $scriptPath = Join-Path $ScriptPath "Deploy-EntraIDBaseline.ps1"
        if (Test-Path $scriptPath) {
            $params = @{
                EnableSecurityDefaults = $Config.EnableSecurityDefaults
                AdminConsentReviewers = @($AdminEmail)
            }
            
            # Skip Conditional Access policies if ConditionalAccess component is also being deployed
            if ($Components -contains "ConditionalAccess") {
                $params.SkipConditionalAccessPolicies = $true
                Write-Log "ConditionalAccess component detected - Entra ID will skip basic Conditional Access policies" -Level "INFO"
            }
            
            # Add WhatIf parameter if specified
            if ($WhatIf) {
                $params.Add("WhatIf", $true)
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Deploy-EntraIDBaseline.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                & $scriptPath @params
            }
            Write-Log "Entra ID deployment completed" -Level "SUCCESS"
            
            # Only show Conditional Access warnings if we actually deployed them
            if (-not ($Components -contains "ConditionalAccess")) {
                Write-Log "IMPORTANT: Conditional Access policies were created in REPORT-ONLY mode to prevent lockout." -Level "WARNING"
                Write-Log "Review the policy reports before enabling them to ensure proper functionality." -Level "WARNING"
            }
        } else {
            Write-Log "Entra ID script not found: $scriptPath" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error deploying Entra ID baseline: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to deploy Purview baseline
function Deploy-Purview {
    param($Config)
    
    Write-Log "=== Deploying Microsoft Purview Baseline ===" -Level "INFO"
    
    try {
        $scriptPath = Join-Path $ScriptPath "Deploy-PurviewBaseline.ps1"
        if (Test-Path $scriptPath) {
            $params = @{
                OrganizationName = $OrganizationName
                RetentionPeriodYears = $Config.RetentionPeriodYears
            }
            
            # Add WhatIf parameter if specified
            if ($WhatIf) {
                $params.Add("WhatIf", $true)
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Deploy-PurviewBaseline.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                & $scriptPath @params
            }
            Write-Log "Microsoft Purview deployment completed" -Level "SUCCESS"
        } else {
            Write-Log "Purview script not found: $scriptPath" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error deploying Purview baseline: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to deploy Defender for Business
function Deploy-DefenderBusiness {
    param($Config, $ConflictResolution)
    
    Write-Log "=== Deploying Enhanced Defender for Business Baseline ===" -Level "INFO"
    
    try {
        $scriptPath = Join-Path $ScriptPath "Deploy-DefenderBusinessBaseline-Enhanced.ps1"
        if (Test-Path $scriptPath) {
            $params = @{
                TenantId = $TenantId
                IntuneGroupName = $Config.IntuneGroupName
            }
            
            # Add enhanced parameters for comprehensive deployment
            if ($Config.DeployAdvancedFeatures) {
                $params.DeployMDEAutomator = $true
                $params.DeployLiveResponseScripts = $true
                $params.InstallCustomDetections = $true
                $params.ConfigureThreatIntelligence = $true
                $params.TestMDEEnvironment = $true
            }
            
            # Apply conflict resolution settings if available
            if ($ConflictResolution) {
                Write-Log "Applying conflict resolution to DefenderBusiness deployment" -Level "INFO"
                if ($ConflictResolution.DefenderBusiness.DisableASR) {
                    $params.DisableASR = $true
                    Write-Log "DefenderBusiness: ASR rules disabled due to conflict resolution"
                }
                if ($ConflictResolution.DefenderBusiness.DisableCompliance) {
                    $params.DisableCompliance = $true
                    Write-Log "DefenderBusiness: Compliance policies disabled due to conflict resolution"
                }
                if ($ConflictResolution.DefenderBusiness.DisableTamperProtection) {
                    $params.DisableTamperProtection = $true
                    Write-Log "DefenderBusiness: Tamper protection disabled due to conflict resolution"
                }
                if ($ConflictResolution.DefenderBusiness.DisableEndpointProtection) {
                    $params.DisableEndpointProtection = $true
                    Write-Log "DefenderBusiness: Endpoint protection disabled due to conflict resolution"
                }
            }
            
            # Add WhatIf parameter if specified
            if ($WhatIf) {
                $params.Add("WhatIf", $true)
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Deploy-DefenderBusinessBaseline-Enhanced.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                & $scriptPath @params
            }
            Write-Log "Enhanced Defender for Business deployment completed" -Level "SUCCESS"
            Write-Log "Advanced features available: Live Response, Custom Detections, Threat Intelligence" -Level "SUCCESS"
        } else {
            Write-Log "Enhanced Defender for Business script not found: $scriptPath" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error deploying Enhanced Defender for Business baseline: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to deploy Conditional Access baseline
function Deploy-ConditionalAccess {
    param($Config)
    
    Write-Log "=== Deploying Conditional Access Baseline ===" -Level "INFO"
    
    try {
        $scriptPath = Join-Path $ScriptPath "Deploy-ConditionalAccessBaseline.ps1"
        if (Test-Path $scriptPath) {
            $params = @{
                TenantId = $TenantId
                ReportMode = $true  # Start with report-only mode for safety
                AllowedCountries = $Config.AllowedCountries
                BreakGlassAccounts = $Config.BreakGlassAccounts
            }
            
            # Add WhatIf parameter if specified
            if ($WhatIf) {
                $params.Add("WhatIf", $true)
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Deploy-ConditionalAccessBaseline.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                & $scriptPath @params
            }
            Write-Log "Conditional Access baseline deployment completed" -Level "SUCCESS"
            Write-Log "IMPORTANT: Conditional Access policies deployed in REPORT-ONLY mode. Review and enable manually." -Level "WARNING"
        } else {
            Write-Log "Conditional Access baseline script not found: $scriptPath" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error deploying Conditional Access baseline: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to deploy Intune baseline
function Deploy-Intune {
    param($Config, $ConflictResolution)
    
    Write-Log "=== Deploying Microsoft Intune Security Baseline (OpenIntuneBaseline) ===" -Level "INFO"
    
    try {
        $scriptPath = Join-Path $ScriptPath "Deploy-IntuneBaseline.ps1"
        if (Test-Path $scriptPath) {
            $params = @{
                Platforms = @("Windows", "Windows365")  # Default platforms for M365BP
                IntuneGroupName = $Config.IntuneGroupName
                PolicyPrefix = "M365BP-OIB"
                DownloadBaseline = $true
                TestMode = $true  # Start in test mode for safety
            }
            
            # Add platform selection based on organization needs
            if ($Config.IncludeMacOS) {
                $params.Platforms += "macOS"
            }
            if ($Config.IncludeBYOD) {
                $params.Platforms += "BYOD"
            }
            
            # Apply conflict resolution settings if available
            if ($ConflictResolution) {
                Write-Log "Applying conflict resolution to Intune deployment" -Level "INFO"
                $excludePolicies = @()
                
                if ($ConflictResolution.Intune.ExcludePolicies -contains "ASR") {
                    $params.ExcludeASR = $true
                    $excludePolicies += "ASR"
                    Write-Log "Intune: ASR policies excluded due to conflict resolution (handled by DefenderBusiness)"
                }
                if ($ConflictResolution.Intune.ExcludePolicies -contains "TamperProtection") {
                    $params.ExcludeTamperProtection = $true
                    $excludePolicies += "TamperProtection"
                    Write-Log "Intune: Tamper Protection excluded due to conflict resolution (handled by DefenderBusiness)"
                }
                if ($ConflictResolution.Intune.ModifyCompliance) {
                    $params.ModifyCompliance = $true
                    Write-Log "Intune: Compliance policies will be coordinated with DefenderBusiness"
                }
                
                # Add to ExcludePolicies parameter if needed
                if ($excludePolicies.Count -gt 0) {
                    $params.ExcludePolicies = $excludePolicies
                }
            }
            
            # Add WhatIf parameter if specified
            if ($WhatIf) {
                $params.Add("WhatIf", $true)
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Deploy-IntuneBaseline.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                & $scriptPath @params
            }
            Write-Log "Microsoft Intune baseline deployment completed" -Level "SUCCESS"
            Write-Log "OpenIntuneBaseline policies deployed based on CIS, NCSC, and Microsoft security frameworks" -Level "SUCCESS"
            Write-Log "IMPORTANT: Policies deployed in TEST mode. Review assignments before full rollout." -Level "WARNING"
        } else {
            Write-Log "Intune baseline script not found: $scriptPath" -Level "ERROR"
        }
    }
    catch {
        Write-Log "Error deploying Intune baseline: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to generate deployment report
function New-DeploymentReport {
    Write-Log "=== Generating Deployment Report ===" -Level "INFO"
    
    $reportPath = Join-Path $ScriptPath "M365BP-Deployment-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Business Premium Deployment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0078d4; }
        h2 { color: #106ebe; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Microsoft 365 Business Premium Security Baseline Deployment Report</h1>
    <p><strong>Organization:</strong> $OrganizationName</p>
    <p><strong>Deployment Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p><strong>Components Deployed:</strong> $($Components -join ', ')</p>
    
    <h2>Deployment Summary</h2>
    <table>
        <tr><th>Component</th><th>Status</th><th>Notes</th></tr>
"@

    foreach ($component in $Components) {
        if ($component -eq "All") { continue }
        $status = "Completed"
        $notes = "Baseline configuration applied"
        
        # Add specific notes for enhanced features
        if ($component -eq "DefenderBusiness" -and $DeployAdvancedMDEFeatures) {
            $notes = "Enhanced baseline with Live Response, Custom Detections, and Threat Intelligence"
        }
        elseif ($component -eq "EntraID") {
            $notes = "Policies deployed in REPORT-ONLY mode for safety"
        }
        elseif ($component -eq "ConditionalAccess") {
            $notes = "All policies deployed in REPORT-ONLY mode"
        }
        
        $htmlReport += "        <tr><td>$component</td><td class='success'>$status</td><td>$notes</td></tr>`n"
    }

    $htmlReport += @"
    </table>
    
    <h2>Next Steps</h2>
    <ul>
        <li><strong>Review Conditional Access policies:</strong> All policies were deployed in REPORT-ONLY mode for safety</li>
        <li><strong>Monitor policy reports:</strong> Check Azure AD sign-in logs to see policy impact</li>
        <li><strong>Enable policies:</strong> Use the Enable-ConditionalAccessPolicies.ps1 script to safely enable policies</li>
        <li><strong>Test enhanced MDE features:</strong> $(if($DeployAdvancedMDEFeatures) { 'Live Response scripts, custom detections, and threat intelligence are now available' } else { 'Consider re-running with -DeployAdvancedMDEFeatures to enable advanced capabilities' })</li>
        <li><strong>Test with pilot users:</strong> Enable policies gradually for pilot groups first</li>
        <li>Review all policies in the respective admin centers</li>
        <li>Monitor security dashboard for alerts and tune detection rules as needed</li>
        <li>Schedule regular policy reviews and updates</li>
        <li>Train users on new security features</li>
    </ul>
    
    <h2>Important Safety Information</h2>
    <div style="background-color: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px;">
        <h3>⚠️ Admin Device Compliance Policy</h3>
        <p>The <strong>M365BP-Admin-Require-Compliant-Device</strong> policy was created in REPORT-ONLY mode to prevent admin lockout.</p>
        <p><strong>Before enabling this policy:</strong></p>
        <ul>
            <li>Ensure your admin device is compliant with Intune policies</li>
            <li>Have a break-glass account available</li>
            <li>Test with a non-critical admin account first</li>
        </ul>
        <p>Use the <code>Enable-ConditionalAccessPolicies.ps1</code> script to safely enable policies after testing.</p>
    </div>
    
    <h2>Log File</h2>
    <p>Detailed deployment logs can be found at: <code>$LogFile</code></p>
</body>
</html>
"@

    Set-Content -Path $reportPath -Value $htmlReport
    Write-Log "Deployment report generated: $reportPath" -Level "SUCCESS"
    
    return $reportPath
}

# Function to run post-deployment validation tests
function Invoke-PostDeploymentValidation {
    param($Config)
    
    Write-Log "=== Running Post-Deployment Validation Tests ===" -Level "INFO"
    
    try {
        $testScriptPath = Join-Path $ScriptPath "Test-M365BPBaseline.ps1"
        if (Test-Path $testScriptPath) {
            # Map deployed components to test categories
            $testCategories = @()
            foreach ($component in $Components) {
                switch ($component) {
                    "DefenderO365" { $testCategories += "DefenderO365" }
                    "EntraID" { $testCategories += "EntraID" }
                    "Purview" { $testCategories += "Purview" }
                    "DefenderBusiness" { $testCategories += "DefenderBusiness" }
                    "ConditionalAccess" { $testCategories += "ConditionalAccess" }
                }
            }
            
            # Always include EIDSCA tests for comprehensive validation
            $testCategories += "EIDSCA"
            
            $params = @{
                TenantId = $TenantId
                TestCategories = $testCategories
                GenerateReports = $GenerateTestReports
                IncludeWhatIfTests = $true
                NotificationEmail = $AdminEmail
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would execute Test-M365BPBaseline.ps1 with parameters: $($params | ConvertTo-Json)"
            } else {
                Write-Log "Executing validation tests for deployed components..."
                & $testScriptPath @params
            }
            
            Write-Log "Post-deployment validation completed" -Level "SUCCESS"
        } else {
            Write-Log "Post-deployment test script not found: $testScriptPath" -Level "WARNING"
        }
    }
    catch {
        Write-Log "Error running post-deployment validation: $($_.Exception.Message)" -Level "ERROR"
        # Don't throw here - we don't want testing failures to fail the entire deployment
    }
}

# Function to establish service connections
function Connect-Services {
    param([string[]]$RequiredServices)
    
    Write-Log "Establishing service connections..." -Component "CONNECT"
    
    foreach ($service in $RequiredServices) {
        Write-Log "Connecting to $service..." -Component "CONNECT"
        
        switch ($service) {
            "ExchangeOnline" {
                try {
                    if (!(Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
                        Write-Log "Connecting to Exchange Online..." -Component "CONNECT"
                        Connect-ExchangeOnline -ShowProgress $false -ShowBanner:$false
                        Write-Log "Successfully connected to Exchange Online" -Level "SUCCESS" -Component "CONNECT"
                    } else {
                        Write-Log "Already connected to Exchange Online" -Component "CONNECT"
                    }
                }
                catch {
                    Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level "ERROR" -Component "CONNECT"
                    throw "Exchange Online connection failed"
                }
            }
            
            "MicrosoftGraph" {
                try {
                    $context = Get-MgContext -ErrorAction SilentlyContinue
                    if (!$context) {
                        Write-Log "Connecting to Microsoft Graph..." -Component "CONNECT"
                        $scopes = @(
                            "DeviceManagementConfiguration.ReadWrite.All",
                            "DeviceManagementManagedDevices.ReadWrite.All",
                            "Directory.ReadWrite.All",
                            "Group.ReadWrite.All",
                            "Policy.ReadWrite.ConditionalAccess",
                            "Application.ReadWrite.All"
                        )
                        Connect-MgGraph -Scopes $scopes -NoWelcome
                        Write-Log "Successfully connected to Microsoft Graph" -Level "SUCCESS" -Component "CONNECT"
                    } else {
                        Write-Log "Already connected to Microsoft Graph (Tenant: $($context.TenantId))" -Component "CONNECT"
                    }
                }
                catch {
                    Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR" -Component "CONNECT"
                    throw "Microsoft Graph connection failed"
                }
            }
            
            "SharePoint" {
                try {
                    Write-Log "Connecting to SharePoint Online..." -Component "CONNECT"
                    # SharePoint connection will be handled by PnP PowerShell in the Purview script
                    Write-Log "SharePoint connection will be established by component script" -Component "CONNECT"
                }
                catch {
                    Write-Log "Failed to connect to SharePoint: $($_.Exception.Message)" -Level "ERROR" -Component "CONNECT"
                    throw "SharePoint connection failed"
                }
            }
        }
    }
    
    Write-Log "Service connections established successfully" -Level "SUCCESS" -Component "CONNECT"
}

# Function to disconnect from services
function Disconnect-Services {
    Write-Log "Disconnecting from services..." -Component "DISCONNECT"
    
    try {
        if (Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            Disconnect-ExchangeOnline -Confirm:$false
            Write-Log "Disconnected from Exchange Online" -Component "DISCONNECT"
        }
    }
    catch {
        Write-Log "Note: Exchange Online disconnect: $($_.Exception.Message)" -Level "WARNING" -Component "DISCONNECT"
    }
    
    try {
        if (Get-MgContext -ErrorAction SilentlyContinue) {
            Disconnect-MgGraph
            Write-Log "Disconnected from Microsoft Graph" -Component "DISCONNECT"
        }
    }
    catch {
        Write-Log "Note: Microsoft Graph disconnect: $($_.Exception.Message)" -Level "WARNING" -Component "DISCONNECT"
    }
    
    Write-Log "Service disconnection completed" -Component "DISCONNECT"
}

# Function to load conflict resolution configuration
function Get-ConflictResolutionConfig {
    Write-Log "Checking for conflict resolution configuration..."
    
    # Look for the most recent conflict resolution file
    $configFiles = Get-ChildItem -Path $ScriptPath -Filter "M365BP-ConflictResolution-*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    
    if ($configFiles.Count -eq 0) {
        Write-Log "No conflict resolution configuration found. Deploying without conflict resolution." -Level "WARNING"
        return $null
    }
    
    $latestConfig = $configFiles[0]
    Write-Log "Loading conflict resolution configuration: $($latestConfig.Name)"
    
    try {
        $configContent = Get-Content -Path $latestConfig.FullName -Raw | ConvertFrom-Json
        Write-Log "Conflict resolution configuration loaded successfully" -Level "SUCCESS"
        Write-Log "DefenderBusiness flags: DisableASR=$($configContent.ResolutionPlan.DefenderBusiness.DisableASR), DisableTamperProtection=$($configContent.ResolutionPlan.DefenderBusiness.DisableTamperProtection)"
        Write-Log "Intune exclusions: $($configContent.ResolutionPlan.Intune.ExcludePolicies -join ', ')"
        return $configContent.ResolutionPlan
    }
    catch {
        Write-Log "Error loading conflict resolution configuration: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

# Main execution
try {
    Show-Banner
    
    # Validate prerequisites and load modules
    Test-Prerequisites
    
    # Load configuration
    $config = Get-Configuration
    Write-Log "Using configuration: $($config | ConvertTo-Json -Depth 2)" -Component "CONFIG"
    
    # Load conflict resolution configuration if available
    $conflictResolution = Get-ConflictResolutionConfig
    if ($conflictResolution) {
        Write-Log "Conflict resolution configuration loaded - coordinated deployment enabled" -Level "SUCCESS" -Component "CONFIG"
    } else {
        Write-Log "No conflict resolution configuration - deploying with default settings" -Level "INFO" -Component "CONFIG"
    }
    
    # Expand "All" components
    if ($Components -contains "All") {
        $Components = @("DefenderO365", "EntraID", "Purview", "DefenderBusiness", "ConditionalAccess", "Intune")
    }
    
    # Determine required service connections based on components
    $requiredServices = @()
    if ($Components -contains "DefenderO365") { $requiredServices += "ExchangeOnline" }
    if ($Components -contains "EntraID" -or $Components -contains "DefenderBusiness" -or $Components -contains "Intune" -or $Components -contains "ConditionalAccess") { 
        $requiredServices += "MicrosoftGraph" 
    }
    if ($Components -contains "Purview") { $requiredServices += "SharePoint" }
    
    # Establish service connections
    if (!$WhatIf -and $requiredServices.Count -gt 0) {
        Connect-Services -RequiredServices ($requiredServices | Select-Object -Unique)
    }
    
    Write-Log "Starting deployment process..." -Component "DEPLOY"
    
    # Deploy each component
    foreach ($component in $Components) {
        Write-Log "=== Starting $component deployment ===" -Level "INFO" -Component $component.ToUpper()
        
        try {
            switch ($component) {
                "DefenderO365" { Deploy-DefenderO365 -Config $config }
                "EntraID" { Deploy-EntraID -Config $config }
                "Purview" { Deploy-Purview -Config $config }
                "DefenderBusiness" { Deploy-DefenderBusiness -Config $config -ConflictResolution $conflictResolution }
                "ConditionalAccess" { Deploy-ConditionalAccess -Config $config }
                "Intune" { Deploy-Intune -Config $config -ConflictResolution $conflictResolution }
            }
            Write-Log "=== $component deployment completed successfully ===" -Level "SUCCESS" -Component $component.ToUpper()
        }
        catch {
            Write-Log "=== $component deployment FAILED: $($_.Exception.Message) ===" -Level "ERROR" -Component $component.ToUpper()
            throw "Component deployment failed: $component"
        }
    }
    
    # Run post-deployment validation tests
    if ($RunPostDeploymentTests -and -not $WhatIf) {
        Write-Log "=== Starting post-deployment validation ===" -Level "INFO" -Component "VALIDATE"
        Invoke-PostDeploymentValidation -Config $config
    }
    
    # Generate report
    $reportPath = New-DeploymentReport
    
    Write-Log "=== DEPLOYMENT COMPLETED SUCCESSFULLY ===" -Level "SUCCESS" -Component "COMPLETE"
    Write-Log "Report generated: $reportPath" -Level "SUCCESS" -Component "COMPLETE"
    Write-Log "Log file: $LogFile" -Level "SUCCESS" -Component "COMPLETE"
    Write-Log "Full transcript file: $TranscriptFile" -Level "SUCCESS" -Component "COMPLETE"
    
    # Open report if not in WhatIf mode
    if (!$WhatIf -and (Test-Path $reportPath)) {
        Start-Process $reportPath
    }
}
catch {
    Write-Log "DEPLOYMENT FAILED: $($_.Exception.Message)" -Level "ERROR" -Component "MAIN"
    Write-Log "Check the log file for detailed error information: $LogFile" -Level "ERROR" -Component "MAIN"
    Write-Log "Check the full transcript for complete output: $TranscriptFile" -Level "ERROR" -Component "MAIN"
    exit 1
}
finally {
    # Disconnect from services
    if (!$WhatIf) {
        Disconnect-Services
    }
    
    # Stop transcript
    try { Stop-Transcript } catch { }
}
