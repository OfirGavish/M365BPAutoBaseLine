<#
.SYNOPSIS
    Master deployment script for Microsoft 365 Business Premium security baselines.

.DESCRIPTION
    This script orchestrates the deployment of all M365 Business Premium security baselines:
    - Defender for Office 365
    - Entra ID (Azure AD) security controls
    - Microsoft Purview compliance
    - Enhanced Defender for Business (Endpoint) with MDEAutomator integration
    - Conditional Access policies (deployed in report-only mode for safety)
    - Tenant-wide hardening

.PARAMETER Components
    Array of components to deploy. Options: "DefenderO365", "EntraID", "Purview", "DefenderBusiness", "All"

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
    [ValidateSet("DefenderO365", "EntraID", "Purview", "DefenderBusiness", "ConditionalAccess", "All")]
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

# Function to log messages
function Write-Log {
    param(
        [string]$Message, 
        [string]$Level = "INFO",
        [switch]$NoConsole
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry
    
    # Write to console unless suppressed
    if (!$NoConsole) {
        $color = switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
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

# Function to validate prerequisites
function Test-Prerequisites {
    Write-Log "Validating prerequisites..."
    
    $requiredModules = @(
        "ExchangeOnlineManagement",
        "Microsoft.Graph",
        "Microsoft.Graph.Intune"
    )
    
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing required modules: $($missingModules -join ', ')" -Level "WARNING"
        if (!$WhatIf) {
            Write-Log "Installing missing modules..."
            foreach ($module in $missingModules) {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-Log "Installed module: $module"
            }
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
    param($Config)
    
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

# Main execution
try {
    # Start transcript to capture all output
    Start-Transcript -Path $TranscriptFile -Append
    
    Show-Banner
    
    # Validate prerequisites
    Test-Prerequisites
    
    # Load configuration
    $config = Get-Configuration
      # Expand "All" components
    if ($Components -contains "All") {
        $Components = @("DefenderO365", "EntraID", "Purview", "DefenderBusiness", "ConditionalAccess")
    }
    
    Write-Log "Starting deployment process..."    # Deploy each component
    foreach ($component in $Components) {
        switch ($component) {
            "DefenderO365" { Deploy-DefenderO365 -Config $config }
            "EntraID" { Deploy-EntraID -Config $config }
            "Purview" { Deploy-Purview -Config $config }
            "DefenderBusiness" { Deploy-DefenderBusiness -Config $config }
            "ConditionalAccess" { Deploy-ConditionalAccess -Config $config }
        }
    }
    
    # Run post-deployment validation tests
    if ($RunPostDeploymentTests -and -not $WhatIf) {
        Invoke-PostDeploymentValidation -Config $config
    }
    
    # Generate report
    $reportPath = New-DeploymentReport
    
    Write-Log "=== Deployment Completed Successfully ===" -Level "SUCCESS"
    Write-Log "Report generated: $reportPath" -Level "SUCCESS"
    Write-Log "Log file: $LogFile" -Level "SUCCESS"
    Write-Log "Full transcript file: $TranscriptFile" -Level "SUCCESS"
    
    # Open report if not in WhatIf mode
    if (!$WhatIf -and (Test-Path $reportPath)) {
        Start-Process $reportPath
    }
}
catch {
    Write-Log "Deployment failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Check the log file for detailed error information: $LogFile" -Level "ERROR"
    Write-Log "Check the full transcript for complete output: $TranscriptFile" -Level "ERROR"
    exit 1
}
finally {
    # Stop transcript
    Stop-Transcript
}
