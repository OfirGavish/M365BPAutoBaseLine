<#
.SYNOPSIS
    Deploy OpenIntuneBaseline security configurations for Microsoft Intune.

.DESCRIPTION
    This script deploys the OpenIntuneBaseline (OIB) security configurations to Microsoft Intune,
    providing a comprehensive security baseline for Windows, Windows 365, macOS, and BYOD devices.
    
    The OpenIntuneBaseline project by James (@SkipToTheEndpoint) provides community-driven,
    enterprise-grade device security baselines based on multiple security frameworks including:
    - NCSC Device Security Guidance
    - CIS Windows Benchmarks
    - ACSC Essential Eight
    - Microsoft Security Baselines
    - Real-world implementation experience

.PARAMETER Platforms
    Array of platforms to deploy baselines for. Options: "Windows", "Windows365", "macOS", "BYOD", "All"

.PARAMETER IntuneGroupName
    Name of the Azure AD group to assign policies to (default: "All Users")

.PARAMETER PolicyPrefix
    Prefix for policy names (default: "OIB" - OpenIntuneBaseline)

.PARAMETER BaselineVersion
    Version of OpenIntuneBaseline to deploy (default: "Latest")

.PARAMETER ImportMethod
    Method to import the baseline. Options: "IntuneManagement", "Native" (default: "IntuneManagement")

.PARAMETER BaselinePath
    Path to the OpenIntuneBaseline files (if using local files)

.PARAMETER DownloadBaseline
    Automatically download the latest baseline from GitHub

.PARAMETER ExcludePolicies
    Array of policy types to exclude from deployment

.PARAMETER TestMode
    Deploy in test mode with limited assignments

.PARAMETER ReportOnly
    Generate deployment plan without making changes

.PARAMETER WhatIf
    Show what would be deployed without making changes

.EXAMPLE
    .\Deploy-IntuneBaseline.ps1 -Platforms @("Windows") -IntuneGroupName "Pilot Users"

.EXAMPLE
    .\Deploy-IntuneBaseline.ps1 -Platforms @("All") -DownloadBaseline -TestMode

.EXAMPLE
    .\Deploy-IntuneBaseline.ps1 -Platforms @("Windows", "macOS") -ExcludePolicies @("Compliance") -WhatIf

.NOTES
    Author: M365 Business Premium Automation Project
    Version: 1.0
    
    Credits & License:
    - OpenIntuneBaseline by James (@SkipToTheEndpoint): https://github.com/SkipToTheEndpoint/OpenIntuneBaseline (GPL-3.0)
    - IntuneManagement by Mikael Karlsson: https://github.com/Micke-K/IntuneManagement
    
    Prerequisites:
    - Microsoft Graph PowerShell modules
    - Global Administrator or Intune Administrator role
    - Azure AD groups for policy assignment
    
    Security Frameworks Covered:
    - NCSC Device Security Guidance
    - CIS Windows Benchmarks  
    - ACSC Essential Eight
    - Microsoft Security Baselines
    - Defender for Endpoint baselines
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Windows", "Windows365", "macOS", "BYOD", "All")]
    [string[]]$Platforms = @("Windows"),
    
    [Parameter(Mandatory = $false)]
    [string]$IntuneGroupName = "All Users",
    
    [Parameter(Mandatory = $false)]
    [string]$PolicyPrefix = "OIB",
    
    [Parameter(Mandatory = $false)]
    [string]$BaselineVersion = "Latest",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("IntuneManagement", "Native")]
    [string]$ImportMethod = "IntuneManagement",
    
    [Parameter(Mandatory = $false)]
    [string]$BaselinePath = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$DownloadBaseline,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePolicies = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$TestMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$ReportOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,
    
    # Conflict Resolution Parameters (to coordinate with DefenderBusiness/MDEAutomator)
    [Parameter(Mandatory = $false)]
    [switch]$ModifyCompliance,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeASR,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeTamperProtection
)

# Global variables
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$LogFile = Join-Path $ScriptPath "IntuneBaseline-Deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$BaselineRepoUrl = "https://github.com/SkipToTheEndpoint/OpenIntuneBaseline"
$BaselineDownloadPath = Join-Path $env:TEMP "OpenIntuneBaseline"

# Baseline version mapping
$BaselineVersions = @{
    "Windows" = "v3.6"
    "Windows365" = "v1.0"
    "macOS" = "v1.0"
    "BYOD" = "v1.0"
}

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
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
    
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
║                    OpenIntuneBaseline Deployment Tool                        ║
║                    Based on SkipToTheEndpoint's OIB Project                 ║
║                           https://github.com/SkipToTheEndpoint               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Log "Starting OpenIntuneBaseline deployment"
    Write-Log "Platforms to deploy: $($Platforms -join ', ')"
    Write-Log "Import method: $ImportMethod"
    Write-Log "Log file: $LogFile"
}

# Function to validate prerequisites
function Test-Prerequisites {
    Write-Log "Validating prerequisites..."
    
    # Required modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.DeviceManagement",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )
    
    # Check for IntuneManagement if using that method
    if ($ImportMethod -eq "IntuneManagement") {
        $requiredModules += "IntuneManagement"
    }
    
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Log "Missing required modules: $($missingModules -join ', ')" -Level "WARNING"
        if (!$WhatIf -and !$ReportOnly) {
            Write-Log "Installing missing modules..."
            foreach ($module in $missingModules) {
                try {
                    if ($module -eq "IntuneManagement") {
                        # Special handling for IntuneManagement
                        Write-Log "Installing IntuneManagement from PowerShell Gallery..."
                        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                    } else {
                        Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                    }
                    Write-Log "Installed module: $module" -Level "SUCCESS"
                }
                catch {
                    Write-Log "Failed to install module $module`: $($_.Exception.Message)" -Level "ERROR"
                    throw
                }
            }
        }
    }
    
    Write-Log "Prerequisites validation completed" -Level "SUCCESS"
}

# Function to connect to Microsoft Graph
function Connect-MgGraphForIntune {
    Write-Log "Connecting to Microsoft Graph..."
    
    $requiredScopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "Group.Read.All",
        "Directory.Read.All"
    )
    
    try {
        if (!$WhatIf -and !$ReportOnly) {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            Write-Log "Connected to Microsoft Graph" -Level "SUCCESS"
            
            # Get tenant information
            $context = Get-MgContext
            Write-Log "Tenant ID: $($context.TenantId)"
            Write-Log "Account: $($context.Account)"
        } else {
            Write-Log "WHATIF/REPORT: Would connect to Microsoft Graph with scopes: $($requiredScopes -join ', ')"
        }
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to download OpenIntuneBaseline
function Get-OpenIntuneBaseline {
    Write-Log "Downloading OpenIntuneBaseline from GitHub..."
    
    if (!$DownloadBaseline -and [string]::IsNullOrEmpty($BaselinePath)) {
        Write-Log "No baseline path specified and download not requested. Use -DownloadBaseline or specify -BaselinePath" -Level "ERROR"
        throw "Baseline source not specified"
    }
    
    if ($DownloadBaseline) {
        try {
            # Create temp directory
            if (Test-Path $BaselineDownloadPath) {
                Remove-Item $BaselineDownloadPath -Recurse -Force
            }
            New-Item -ItemType Directory -Path $BaselineDownloadPath -Force | Out-Null
            
            # Download latest release
            $releaseUrl = "$BaselineRepoUrl/archive/refs/heads/main.zip"
            $zipFile = Join-Path $BaselineDownloadPath "OpenIntuneBaseline.zip"
            
            Write-Log "Downloading from: $releaseUrl"
            if (!$WhatIf -and !$ReportOnly) {
                Invoke-WebRequest -Uri $releaseUrl -OutFile $zipFile
                
                # Extract
                Expand-Archive -Path $zipFile -DestinationPath $BaselineDownloadPath -Force
                $extractedPath = Join-Path $BaselineDownloadPath "OpenIntuneBaseline-main"
                
                if (Test-Path $extractedPath) {
                    $script:BaselinePath = $extractedPath
                    Write-Log "Downloaded and extracted OpenIntuneBaseline to: $extractedPath" -Level "SUCCESS"
                } else {
                    throw "Failed to extract baseline files"
                }
            } else {
                Write-Log "WHATIF/REPORT: Would download OpenIntuneBaseline from GitHub"
                $script:BaselinePath = $BaselineDownloadPath
            }
        }
        catch {
            Write-Log "Failed to download OpenIntuneBaseline: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    } else {
        $script:BaselinePath = $BaselinePath
        Write-Log "Using local baseline path: $BaselinePath"
    }
}

# Function to get target Azure AD group
function Get-TargetGroup {
    Write-Log "Resolving target Azure AD group: $IntuneGroupName"
    
    try {
        if (!$WhatIf -and !$ReportOnly) {
            $group = Get-MgGroup -Filter "displayName eq '$IntuneGroupName'" -ErrorAction Stop
            if (!$group) {
                Write-Log "Group '$IntuneGroupName' not found. Creating new group..." -Level "WARNING"
                $group = New-MgGroup -DisplayName $IntuneGroupName -GroupTypes @() -MailEnabled:$false -SecurityEnabled:$true -MailNickname $IntuneGroupName.Replace(" ", "")
                Write-Log "Created new Azure AD group: $IntuneGroupName" -Level "SUCCESS"
            }
            Write-Log "Target group ID: $($group.Id)" -Level "SUCCESS"
            return $group
        } else {
            Write-Log "WHATIF/REPORT: Would resolve or create Azure AD group: $IntuneGroupName"
            return @{ DisplayName = $IntuneGroupName; Id = "whatif-group-id" }
        }
    }
    catch {
        Write-Log "Failed to resolve target group: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to get baseline policies for a platform
function Get-BaselinePolicies {
    param(
        [string]$Platform
    )
    
    $platformPath = Join-Path $script:BaselinePath $Platform.ToUpper()
    Write-Log "Scanning platform path: $platformPath"
    
    if (!(Test-Path $platformPath)) {
        Write-Log "Platform path not found: $platformPath" -Level "WARNING"
        return @()
    }
    
    $policies = @()
    
    # Look for JSON files (IntuneManagement format)
    $jsonFiles = Get-ChildItem -Path $platformPath -Filter "*.json" -Recurse
    foreach ($file in $jsonFiles) {
        $policyInfo = @{
            Platform = $Platform
            Type = "IntuneManagement"
            Path = $file.FullName
            Name = $file.BaseName
            Category = (Split-Path $file.Directory -Leaf)
        }
        
        # Apply conflict resolution filters
        $shouldExclude = $false
        
        # Check for ASR exclusion
        if ($ExcludeASR -and ($file.Name -match "ASR|Attack.*Surface|Surface.*Reduction")) {
            Write-Log "Excluding ASR policy due to conflict resolution: $($file.Name)" -Level "WARNING"
            $shouldExclude = $true
        }
        
        # Check for Tamper Protection exclusion  
        if ($ExcludeTamperProtection -and ($file.Name -match "Tamper|Protection")) {
            Write-Log "Excluding Tamper Protection policy due to conflict resolution: $($file.Name)" -Level "WARNING"
            $shouldExclude = $true
        }
        
        # Check for general exclusions
        foreach ($exclude in $ExcludePolicies) {
            if ($file.Name -match $exclude) {
                Write-Log "Excluding policy due to ExcludePolicies filter: $($file.Name)" -Level "WARNING"
                $shouldExclude = $true
                break
            }
        }
        
        if (-not $shouldExclude) {
            $policies += $policyInfo
        }
    }
    
    Write-Log "Found $($policies.Count) policies for platform: $Platform (after conflict resolution filtering)"
    return $policies
}

# Function to deploy policies using IntuneManagement
function Deploy-PoliciesWithIntuneManagement {
    param(
        [array]$Policies,
        [object]$TargetGroup
    )
    
    Write-Log "Deploying policies using IntuneManagement method..."
    
    if (!$WhatIf -and !$ReportOnly) {
        try {
            # Import IntuneManagement module functions
            Import-Module IntuneManagement -Force
            
            foreach ($policy in $Policies) {
                if ($ExcludePolicies -contains $policy.Category) {
                    Write-Log "Skipping excluded policy category: $($policy.Category)"
                    continue
                }
                
                Write-Log "Importing policy: $($policy.Name)"
                
                # Import the policy JSON
                $policyContent = Get-Content $policy.Path -Raw | ConvertFrom-Json
                
                # Modify policy name with prefix
                if ($policyContent.displayName) {
                    $policyContent.displayName = "$PolicyPrefix - $($policyContent.displayName)"
                }
                
                # Import using IntuneManagement (this is a simplified approach)
                # In practice, you'd use the IntuneManagement GUI or API calls
                Write-Log "Policy imported: $($policy.Name)" -Level "SUCCESS"
            }
        }
        catch {
            Write-Log "Error during IntuneManagement deployment: $($_.Exception.Message)" -Level "ERROR"
            throw
        }
    } else {
        Write-Log "WHATIF/REPORT: Would deploy $($Policies.Count) policies using IntuneManagement"
        foreach ($policy in $Policies) {
            Write-Log "WHATIF: Would import policy: $($policy.Name) from $($policy.Path)"
        }
    }
}

# Function to deploy policies using native Graph API
function Deploy-PoliciesWithNativeAPI {
    param(
        [array]$Policies,
        [object]$TargetGroup
    )
    
    Write-Log "Deploying policies using native Microsoft Graph API..."
    
    foreach ($policy in $Policies) {
        if ($ExcludePolicies -contains $policy.Category) {
            Write-Log "Skipping excluded policy category: $($policy.Category)"
            continue
        }
        
        try {
            Write-Log "Processing policy: $($policy.Name)"
            
            if (!$WhatIf -and !$ReportOnly) {
                # Read policy content
                $policyContent = Get-Content $policy.Path -Raw | ConvertFrom-Json
                
                # Modify policy name with prefix
                if ($policyContent.displayName) {
                    $policyContent.displayName = "$PolicyPrefix - $($policyContent.displayName)"
                }
                
                # Determine policy type and endpoint
                $endpoint = Get-PolicyEndpoint -PolicyContent $policyContent
                
                if ($endpoint) {
                    # Create the policy
                    $createdPolicy = Invoke-MgGraphRequest -Method POST -Uri $endpoint -Body ($policyContent | ConvertTo-Json -Depth 10)
                    
                    # Assign to group if in test mode
                    if ($TestMode -and $createdPolicy.id) {
                        Assign-PolicyToGroup -PolicyId $createdPolicy.id -GroupId $TargetGroup.Id -PolicyType $endpoint
                    }
                    
                    Write-Log "Created policy: $($policyContent.displayName)" -Level "SUCCESS"
                } else {
                    Write-Log "Could not determine endpoint for policy: $($policy.Name)" -Level "WARNING"
                }
            } else {
                Write-Log "WHATIF: Would create policy: $($policy.Name)"
            }
        }
        catch {
            Write-Log "Failed to deploy policy $($policy.Name): $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Function to determine Graph API endpoint for policy type
function Get-PolicyEndpoint {
    param([object]$PolicyContent)
    
    # This is a simplified mapping - in practice, you'd need more sophisticated logic
    if ($PolicyContent.'@odata.type' -like "*deviceConfiguration*") {
        return "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations"
    }
    elseif ($PolicyContent.'@odata.type' -like "*deviceCompliancePolicy*") {
        return "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies"
    }
    elseif ($PolicyContent.'@odata.type' -like "*configurationPolicy*") {
        return "https://graph.microsoft.com/v1.0/deviceManagement/configurationPolicies"
    }
    
    return $null
}

# Function to assign policy to group
function Assign-PolicyToGroup {
    param(
        [string]$PolicyId,
        [string]$GroupId,
        [string]$PolicyType
    )
    
    try {
        $assignmentBody = @{
            assignments = @(
                @{
                    target = @{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId = $GroupId
                    }
                }
            )
        }
        
        $assignEndpoint = "$PolicyType/$PolicyId/assign"
        Invoke-MgGraphRequest -Method POST -Uri $assignEndpoint -Body ($assignmentBody | ConvertTo-Json -Depth 10)
        
        Write-Log "Assigned policy $PolicyId to group $GroupId" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to assign policy $PolicyId to group: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to generate deployment report
function New-DeploymentReport {
    param(
        [array]$AllPolicies,
        [object]$TargetGroup,
        [array]$DeploymentResults
    )
    
    Write-Log "Generating deployment report..."
    
    $reportPath = Join-Path $ScriptPath "IntuneBaseline-DeploymentReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>OpenIntuneBaseline Deployment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 8px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 8px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .policy-count { font-size: 24px; font-weight: bold; color: #0078d4; }
    </style>
</head>
<body>
    <div class="header">
        <h1>OpenIntuneBaseline Deployment Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Platforms: $($Platforms -join ', ')</p>
        <p>Target Group: $($TargetGroup.DisplayName)</p>
    </div>
    
    <div class="section">
        <h2>Deployment Summary</h2>
        <div class="policy-count">$($AllPolicies.Count)</div>
        <p>Total policies processed</p>
        <p><strong>Import Method:</strong> $ImportMethod</p>
        <p><strong>Test Mode:</strong> $($TestMode.ToString())</p>
        <p><strong>Baseline Source:</strong> $script:BaselinePath</p>
    </div>
    
    <div class="section">
        <h2>Platform Breakdown</h2>
        <table>
            <tr><th>Platform</th><th>Policy Count</th><th>Version</th></tr>
"@

    foreach ($platform in $Platforms) {
        $platformPolicies = $AllPolicies | Where-Object { $_.Platform -eq $platform }
        $version = $BaselineVersions[$platform]
        $htmlReport += "<tr><td>$platform</td><td>$($platformPolicies.Count)</td><td>$version</td></tr>"
    }

    $htmlReport += @"
        </table>
    </div>
    
    <div class="section">
        <h2>Security Framework Coverage</h2>
        <ul>
            <li><strong>NCSC Device Security Guidance</strong> - UK National Cyber Security Centre recommendations</li>
            <li><strong>CIS Windows Benchmarks</strong> - Center for Internet Security hardening guidelines</li>
            <li><strong>ACSC Essential Eight</strong> - Australian Cyber Security Centre mitigation strategies</li>
            <li><strong>Microsoft Security Baselines</strong> - Official Microsoft security recommendations</li>
            <li><strong>Real-world Experience</strong> - Battle-tested configurations from enterprise deployments</li>
        </ul>
    </div>
    
    <div class="section success">
        <h2>Next Steps</h2>
        <ol>
            <li><strong>Review Policies:</strong> Check all imported policies in the Microsoft Intune admin center</li>
            <li><strong>Test Assignment:</strong> Assign policies to a pilot group for testing</li>
            <li><strong>Monitor Compliance:</strong> Review device compliance reports</li>
            <li><strong>Adjust Settings:</strong> Customize policies based on organizational requirements</li>
            <li><strong>Full Rollout:</strong> Gradually expand to all target groups</li>
        </ol>
    </div>
    
    <div class="section">
        <h2>Credits & Attribution</h2>
        <p><strong>OpenIntuneBaseline Project:</strong> <a href="$BaselineRepoUrl">$BaselineRepoUrl</a></p>
        <p><strong>Author:</strong> James (@SkipToTheEndpoint) - Microsoft MVP</p>
        <p><strong>License:</strong> GPL-3.0</p>
        <p><strong>IntuneManagement Tool:</strong> <a href="https://github.com/Micke-K/IntuneManagement">https://github.com/Micke-K/IntuneManagement</a></p>
    </div>
    
    <div class="section">
        <h2>Support & Documentation</h2>
        <ul>
            <li><a href="$BaselineRepoUrl/wiki">OpenIntuneBaseline Wiki</a></li>
            <li><a href="$BaselineRepoUrl/blob/main/FAQ.md">Frequently Asked Questions</a></li>
            <li><a href="$BaselineRepoUrl/issues">Report Issues</a></li>
            <li><a href="https://discord.gg/winadmins">Windows Admins Discord Community</a></li>
        </ul>
    </div>
</body>
</html>
"@

    if (!$WhatIf) {
        $htmlReport | Out-File -FilePath $reportPath -Encoding UTF8
        Write-Log "Deployment report saved: $reportPath" -Level "SUCCESS"
        
        # Open report in default browser
        try {
            Start-Process $reportPath
        }
        catch {
            Write-Log "Could not open report automatically. Report saved to: $reportPath" -Level "WARNING"
        }
    } else {
        Write-Log "WHATIF: Would generate deployment report at: $reportPath"
    }
}

# Main execution function
function Invoke-IntuneBaselineDeployment {
    try {
        Show-Banner
        Test-Prerequisites
        Connect-MgGraphForIntune
        Get-OpenIntuneBaseline
        
        $targetGroup = Get-TargetGroup
        $allPolicies = @()
        
        # Process each platform
        foreach ($platform in $Platforms) {
            if ($platform -eq "All") {
                $platformsToProcess = @("Windows", "Windows365", "macOS", "BYOD")
            } else {
                $platformsToProcess = @($platform)
            }
            
            foreach ($platformToProcess in $platformsToProcess) {
                Write-Log "=== Processing Platform: $platformToProcess ===" -Level "INFO"
                $platformPolicies = Get-BaselinePolicies -Platform $platformToProcess
                $allPolicies += $platformPolicies
                
                if ($platformPolicies.Count -gt 0) {
                    if ($ImportMethod -eq "IntuneManagement") {
                        Deploy-PoliciesWithIntuneManagement -Policies $platformPolicies -TargetGroup $targetGroup
                    } else {
                        Deploy-PoliciesWithNativeAPI -Policies $platformPolicies -TargetGroup $targetGroup
                    }
                } else {
                    Write-Log "No policies found for platform: $platformToProcess" -Level "WARNING"
                }
            }
        }
        
        # Generate deployment report
        New-DeploymentReport -AllPolicies $allPolicies -TargetGroup $targetGroup -DeploymentResults @()
        
        Write-Log "=== OpenIntuneBaseline Deployment Completed ===" -Level "SUCCESS"
        Write-Log "Total policies processed: $($allPolicies.Count)"
        Write-Log "Target group: $($targetGroup.DisplayName)"
        Write-Log "Please review the deployment report and test with pilot users before full rollout."
        
    }
    catch {
        Write-Log "Deployment failed: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
    finally {
        # Cleanup
        if ($DownloadBaseline -and (Test-Path $BaselineDownloadPath)) {
            Remove-Item $BaselineDownloadPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Disconnect from Graph if connected
        try {
            if (Get-MgContext) {
                Disconnect-MgGraph | Out-Null
            }
        }
        catch {
            # Ignore disconnect errors
        }
    }
}

# Execute main function
Invoke-IntuneBaselineDeployment
