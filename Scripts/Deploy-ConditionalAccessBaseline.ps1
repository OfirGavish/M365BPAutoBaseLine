#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Deploys a comprehensive Conditional Access baseline for Microsoft 365 Business Premium environments.

.DESCRIPTION
    This script automates the deployment of a robust Conditional Access baseline based on the community
    ConditionalAccessBaseline project by j0eyv. It implements persona-based policies covering:
    - Global protection (all users)
    - Admin-specific controls
    - Internal user policies
    - Guest user restrictions
    
    The script includes comprehensive automation for creating required groups, named locations,
    and deploying policies with proper dependency management and validation.

.PARAMETER TenantId
    The Azure AD tenant ID where policies will be deployed.

.PARAMETER ConfigurationPath
    Path to the Conditional Access baseline configuration files. Defaults to a Config subfolder.

.PARAMETER WhatIf
    Shows what changes would be made without actually applying them.

.PARAMETER ReportMode
    Deploys all policies in report-only mode for testing and validation.

.PARAMETER AllowedCountries
    Array of allowed country codes for geographic restrictions. Defaults to common business locations.

.PARAMETER BreakGlassAccounts
    Array of break-glass account UPNs to exclude from all policies.

.PARAMETER InternalGroupName
    Name of the group containing internal users. Defaults to creating a dynamic group.

.PARAMETER AdminGroupName
    Name of the group containing admin users. Defaults to creating a dynamic group.

.PARAMETER LogPath
    Path for deployment logs and reports.

.PARAMETER SkipPrerequisites
    Skip prerequisite validation and module checks.

.EXAMPLE
    .\Deploy-ConditionalAccessBaseline.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -WhatIf

.EXAMPLE
    .\Deploy-ConditionalAccessBaseline.ps1 -ReportMode -AllowedCountries @("US", "CA", "GB") -BreakGlassAccounts @("breakglass@contoso.com")

.NOTES
    Author: M365 Business Premium Automation Project
    Version: 1.0
    Based on: ConditionalAccessBaseline by j0eyv (https://github.com/j0eyv/ConditionalAccessBaseline)
    
    Prerequisites:
    - Global Administrator or Conditional Access Administrator role
    - Microsoft Graph PowerShell modules
    - Azure AD Premium P1/P2 licensing for advanced features
    - Entra ID identity protection (for risk-based policies)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationPath = (Join-Path $PSScriptRoot "..\Config\ConditionalAccess"),
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory = $false)]
    [switch]$ReportMode,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AllowedCountries = @("US", "CA", "GB", "AU", "DE", "FR", "NL", "BE", "LU"),
    
    [Parameter(Mandatory = $false)]
    [string[]]$BreakGlassAccounts = @(),
    
    [Parameter(Mandatory = $false)]
    [string]$InternalGroupName = "CA-Internals-DynamicGroup",
    
    [Parameter(Mandatory = $false)]
    [string]$AdminGroupName = "CA-Admins-DynamicGroup",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path $PSScriptRoot "..\Logs"),
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipPrerequisites
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "ConditionalAccess_Deployment_$timestamp.log"
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force }

function Write-LogMessage {
    param([string]$Message, [string]$Level = "INFO")
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(if($Level -eq "ERROR"){"Red"} elseif($Level -eq "WARNING"){"Yellow"} else{"Green"})
    Add-Content -Path $logFile -Value $logEntry
}

function Test-Prerequisites {
    Write-LogMessage "Checking prerequisites..."
    
    # Check required modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.SignIns", 
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-LogMessage "Required module '$module' not found. Installing..." "WARNING"
            Install-Module -Name $module -Force -AllowClobber
        }
    }
    
    # Check Graph connection
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-LogMessage "Not connected to Microsoft Graph. Connecting..." "WARNING"
            $scopes = @(
                "Policy.ReadWrite.ConditionalAccess",
                "Group.ReadWrite.All",
                "Directory.ReadWrite.All",
                "Application.Read.All"
            )
            Connect-MgGraph -Scopes $scopes -TenantId $TenantId
        }
    }
    catch {
        Write-LogMessage "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
        throw
    }
    
    Write-LogMessage "Prerequisites validated successfully."
}

function Get-CAPersonaGroups {
    Write-LogMessage "Setting up persona-based groups..."
    
    $groups = @{}
    
    # Break Glass Accounts Group
    $breakGlassGroupName = "CA-BreakGlassAccounts - Exclude"
    $breakGlassGroup = Get-MgGroup -Filter "displayName eq '$breakGlassGroupName'" -ErrorAction SilentlyContinue
    
    if (-not $breakGlassGroup) {
        Write-LogMessage "Creating break glass accounts exclusion group..."
        $breakGlassGroup = New-MgGroup -DisplayName $breakGlassGroupName -MailEnabled:$false -SecurityEnabled:$true -MailNickname "CA-BreakGlass-Exclude"
    }
    
    # Add break glass accounts to group
    if ($BreakGlassAccounts.Count -gt 0) {
        foreach ($account in $BreakGlassAccounts) {
            try {
                $user = Get-MgUser -Filter "userPrincipalName eq '$account'" -ErrorAction SilentlyContinue
                if ($user) {
                    New-MgGroupMember -GroupId $breakGlassGroup.Id -DirectoryObjectId $user.Id -ErrorAction SilentlyContinue
                    Write-LogMessage "Added break glass account '$account' to exclusion group."
                }
            }
            catch {
                Write-LogMessage "Failed to add break glass account '$account': $($_.Exception.Message)" "WARNING"
            }
        }
    }
    
    $groups["BreakGlass"] = $breakGlassGroup.Id
    
    # Internal Users Dynamic Group
    $internalGroup = Get-MgGroup -Filter "displayName eq '$InternalGroupName'" -ErrorAction SilentlyContinue
    
    if (-not $internalGroup) {
        Write-LogMessage "Creating internal users dynamic group..."
        $membershipRule = "(user.userType -eq ""Member"") and (user.accountEnabled -eq true)"
        $internalGroup = New-MgGroup -DisplayName $InternalGroupName -MailEnabled:$false -SecurityEnabled:$true -MailNickname "CA-Internals" -GroupTypes @("DynamicMembership") -MembershipRule $membershipRule -MembershipRuleProcessingState "On"
    }
    
    $groups["Internals"] = $internalGroup.Id
    
    # Admin Users Dynamic Group  
    $adminGroup = Get-MgGroup -Filter "displayName eq '$AdminGroupName'" -ErrorAction SilentlyContinue
    
    if (-not $adminGroup) {
        Write-LogMessage "Creating admin users dynamic group..."
        $adminRoles = @(
            "Global Administrator", "Privileged Role Administrator", "Security Administrator",
            "Conditional Access Administrator", "Exchange Administrator", "SharePoint Administrator",
            "Intune Administrator", "User Administrator", "Helpdesk Administrator"
        )
        $membershipRule = "user.assignedRoles -any (role.displayName -in ['" + ($adminRoles -join "','") + "'])"
        $adminGroup = New-MgGroup -DisplayName $AdminGroupName -MailEnabled:$false -SecurityEnabled:$true -MailNickname "CA-Admins" -GroupTypes @("DynamicMembership") -MembershipRule $membershipRule -MembershipRuleProcessingState "On"
    }
    
    $groups["Admins"] = $adminGroup.Id
    
    # Guest Users (Built-in)
    $groups["Guests"] = "All Guest Users" # Special identifier for guest users condition
    
    Write-LogMessage "Persona groups configured successfully."
    return $groups
}

function Set-CANamedLocations {
    Write-LogMessage "Configuring named locations..."
    
    # Allowed Countries Named Location
    $allowedCountriesLocation = "ALLOWED COUNTRIES"
    $existingLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq '$allowedCountriesLocation'" -ErrorAction SilentlyContinue
    
    if ($existingLocation) {
        Write-LogMessage "Updating existing 'ALLOWED COUNTRIES' named location..."
        Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId $existingLocation.Id -CountriesAndRegions $AllowedCountries
    }
    else {
        Write-LogMessage "Creating 'ALLOWED COUNTRIES' named location..."
        $locationParams = @{
            "@odata.type" = "#microsoft.graph.countryNamedLocation"
            DisplayName = $allowedCountriesLocation
            CountriesAndRegions = $AllowedCountries
            IncludeUnknownCountriesAndRegions = $false
        }
        New-MgIdentityConditionalAccessNamedLocation -BodyParameter $locationParams
    }
    
    Write-LogMessage "Named locations configured successfully."
}

function New-CAPolicy {
    param(
        [string]$PolicyName,
        [hashtable]$PolicyDefinition,
        [hashtable]$PersonaGroups,
        [bool]$ReportOnlyMode = $false
    )
    
    Write-LogMessage "Processing policy: $PolicyName"
    
    # Check if policy already exists
    $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$PolicyName'" -ErrorAction SilentlyContinue
    
    if ($existingPolicy) {
        Write-LogMessage "Policy '$PolicyName' already exists. Skipping..." "WARNING"
        return $existingPolicy
    }
    
    # Set policy state
    $state = if ($ReportOnlyMode) { "enabledForReportingButNotEnforced" } else { "disabled" }
    
    # Build policy object based on baseline definitions
    $policyParams = @{
        DisplayName = $PolicyName
        State = $state
        Conditions = @{}
        GrantControls = @{}
        SessionControls = @{}
    }
    
    # Configure policy based on type and persona
    if ($PolicyName -like "*Global*") {
        $policyParams.Conditions.Users = @{
            IncludeUsers = @("All")
            ExcludeGroups = @($PersonaGroups["BreakGlass"])
        }
    }
    elseif ($PolicyName -like "*Admins*") {
        $policyParams.Conditions.Users = @{
            IncludeGroups = @($PersonaGroups["Admins"])
            ExcludeGroups = @($PersonaGroups["BreakGlass"])
        }
    }
    elseif ($PolicyName -like "*Internals*") {
        $policyParams.Conditions.Users = @{
            IncludeGroups = @($PersonaGroups["Internals"])
            ExcludeGroups = @($PersonaGroups["BreakGlass"])
        }
    }
    elseif ($PolicyName -like "*Guest*") {
        $policyParams.Conditions.Users = @{
            IncludeUsers = @("GuestsOrExternalUsers")
            ExcludeGroups = @($PersonaGroups["BreakGlass"])
        }
    }
    
    # Apply common policy configurations based on type
    if ($PolicyName -like "*MFA*") {
        $policyParams.GrantControls = @{
            Operator = "OR"
            BuiltInControls = @("mfa")
        }
        $policyParams.Conditions.Applications = @{
            IncludeApplications = @("All")
        }
    }
    elseif ($PolicyName -like "*BLOCK*") {
        $policyParams.GrantControls = @{
            Operator = "OR"
            BuiltInControls = @("block")
        }
    }
    elseif ($PolicyName -like "*CompliantorAADHJ*") {
        $policyParams.GrantControls = @{
            Operator = "OR"
            BuiltInControls = @("compliantDevice", "domainJoinedDevice")
        }
    }
    
    # Special configurations for specific policy types
    if ($PolicyName -like "*CountryWhitelist*") {
        $allowedLocation = Get-MgIdentityConditionalAccessNamedLocation -Filter "displayName eq 'ALLOWED COUNTRIES'"
        if ($allowedLocation) {
            $policyParams.Conditions.Locations = @{
                IncludeLocations = @("All")
                ExcludeLocations = @($allowedLocation.Id)
            }
        }
    }
    
    if ($PolicyName -like "*LegacyAuthentication*") {
        $policyParams.Conditions.ClientAppTypes = @("exchangeActiveSync", "other")
    }
    
    if ($PolicyName -like "*SigninFrequency*") {
        $policyParams.SessionControls.SignInFrequency = @{
            Value = 12
            Type = "hours"
            IsEnabled = $true
        }
    }
    
    if ($PolicyName -like "*PersistentBrowser*") {
        $policyParams.SessionControls.PersistentBrowser = @{
            Mode = "never"
            IsEnabled = $true
        }
    }
    
    try {
        if ($WhatIf) {
            Write-LogMessage "WHAT-IF: Would create policy '$PolicyName' with state '$state'"
            return $null
        }
        
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams
        Write-LogMessage "Successfully created policy: $PolicyName"
        return $newPolicy
    }
    catch {
        Write-LogMessage "Failed to create policy '$PolicyName': $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Deploy-CABaseline {
    Write-LogMessage "Starting Conditional Access baseline deployment..."
    
    # Get persona groups
    $personaGroups = Get-CAPersonaGroups
    
    # Set up named locations
    Set-CANamedLocations
    
    # Define baseline policies
    $baselinePolicies = @{
        # Global Policies
        "CA000-Global-IdentityProtection-AnyApp-AnyPlatform-MFA" = @{ Type = "MFA"; Priority = 1 }
        "CA001-Global-AttackSurfaceReduction-AnyApp-AnyPlatform-BLOCK-CountryWhitelist" = @{ Type = "GeoBlock"; Priority = 2 }
        "CA002-Global-IdentityProtection-AnyApp-AnyPlatform-Block-LegacyAuthentication" = @{ Type = "LegacyBlock"; Priority = 3 }
        "CA003-Global-BaseProtection-RegisterOrJoin-AnyPlatform-MFA" = @{ Type = "DeviceRegistration"; Priority = 4 }
        "CA004-Global-IdentityProtection-AnyApp-AnyPlatform-AuthenticationFlows" = @{ Type = "AuthFlows"; Priority = 5 }
        "CA005-Global-DataProtection-Office365-AnyPlatform-Unmanaged-AppEnforcedRestrictions-BlockDownload" = @{ Type = "DataProtection"; Priority = 6 }
        "CA006-Global-DataProtection-Office365-iOSenAndroid-RequireAppProtection" = @{ Type = "AppProtection"; Priority = 7 }
        
        # Admin Policies
        "CA100-Admins-IdentityProtection-AdminPortals-AnyPlatform-MFA" = @{ Type = "AdminMFA"; Priority = 8 }
        "CA101-Admins-IdentityProtection-AnyApp-AnyPlatform-MFA" = @{ Type = "AdminMFA"; Priority = 9 }
        "CA102-Admins-IdentityProtection-AllApps-AnyPlatform-SigninFrequency" = @{ Type = "AdminSigninFreq"; Priority = 10 }
        "CA103-Admins-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser" = @{ Type = "AdminSession"; Priority = 11 }
        "CA104-Admins-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation" = @{ Type = "AdminCAE"; Priority = 12 }
        "CA105-Admins-IdentityProtection-AnyApp-AnyPlatform-PhishingResistantMFA" = @{ Type = "AdminPhishingMFA"; Priority = 13 }
        
        # Internal User Policies
        "CA200-Internals-IdentityProtection-AnyApp-AnyPlatform-MFA" = @{ Type = "InternalMFA"; Priority = 14 }
        "CA201-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskUser" = @{ Type = "RiskBlock"; Priority = 15 }
        "CA202-Internals-IdentityProtection-AllApps-WindowsMacOS-SigninFrequency-UnmanagedDevices" = @{ Type = "InternalSigninFreq"; Priority = 16 }
        "CA205-Internals-BaseProtection-AnyApp-Windows-CompliantorAADHJ" = @{ Type = "DeviceCompliance"; Priority = 17 }
        "CA206-Internals-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser" = @{ Type = "InternalSession"; Priority = 18 }
        "CA208-Internals-BaseProtection-AnyApp-MacOS-Compliant" = @{ Type = "MacCompliance"; Priority = 19 }
        "CA209-Internals-IdentityProtection-AllApps-AnyPlatform-ContinuousAccessEvaluation" = @{ Type = "InternalCAE"; Priority = 20 }
        "CA210-Internals-IdentityProtection-AnyApp-AnyPlatform-BLOCK-HighRiskSignIn" = @{ Type = "SigninRiskBlock"; Priority = 21 }
        
        # Guest User Policies
        "CA400-GuestUsers-IdentityProtection-AnyApp-AnyPlatform-MFA" = @{ Type = "GuestMFA"; Priority = 22 }
        "CA401-GuestUsers-AttackSurfaceReduction-AllApps-AnyPlatform-BlockNonGuestAppAccess" = @{ Type = "GuestAppBlock"; Priority = 23 }
        "CA402-GuestUsers-IdentityProtection-AllApps-AnyPlatform-SigninFrequency" = @{ Type = "GuestSigninFreq"; Priority = 24 }
        "CA403-Guests-IdentityProtection-AllApps-AnyPlatform-PersistentBrowser" = @{ Type = "GuestSession"; Priority = 25 }
    }
    
    # Deploy policies in priority order
    $deploymentResults = @()
    $sortedPolicies = $baselinePolicies.GetEnumerator() | Sort-Object { $_.Value.Priority }
    
    foreach ($policy in $sortedPolicies) {
        $policyName = $policy.Key
        $policyConfig = $policy.Value
        
        $result = New-CAPolicy -PolicyName $policyName -PolicyDefinition $policyConfig -PersonaGroups $personaGroups -ReportOnlyMode:$ReportMode
        
        $deploymentResults += @{
            PolicyName = $policyName
            Status = if ($result) { "Success" } else { "Failed" }
            PolicyId = if ($result) { $result.Id } else { "N/A" }
        }
        
        Start-Sleep -Seconds 2  # Rate limiting
    }
    
    return $deploymentResults
}

function Write-DeploymentReport {
    param([array]$Results)
    
    $reportPath = Join-Path $LogPath "ConditionalAccess_DeploymentReport_$timestamp.html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Conditional Access Baseline Deployment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        .success { color: #28a745; font-weight: bold; }
        .failed { color: #dc3545; font-weight: bold; }
        .footer { margin-top: 30px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Conditional Access Baseline Deployment Report</h1>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    </div>
    
    <div class="summary">
        <h2>Deployment Summary</h2>
        <p><strong>Total Policies:</strong> $($Results.Count)</p>
        <p><strong>Successful:</strong> $($Results | Where-Object {$_.Status -eq "Success"} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Failed:</strong> $($Results | Where-Object {$_.Status -eq "Failed"} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Mode:</strong> $(if($ReportMode){"Report-Only"}elseif($WhatIf){"What-If"}else{"Disabled"})</p>
    </div>
    
    <h2>Policy Deployment Results</h2>
    <table>
        <tr>
            <th>Policy Name</th>
            <th>Status</th>
            <th>Policy ID</th>
        </tr>
"@
    
    foreach ($result in $Results) {
        $statusClass = if ($result.Status -eq "Success") { "success" } else { "failed" }
        $html += @"
        <tr>
            <td>$($result.PolicyName)</td>
            <td class="$statusClass">$($result.Status)</td>
            <td>$($result.PolicyId)</td>
        </tr>
"@
    }
    
    $html += @"
    </table>
    
    <div class="footer">
        <p>This report was generated by the M365 Business Premium Conditional Access Baseline deployment script.</p>
        <p>Based on the ConditionalAccessBaseline project by j0eyv: <a href="https://github.com/j0eyv/ConditionalAccessBaseline">https://github.com/j0eyv/ConditionalAccessBaseline</a></p>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-LogMessage "Deployment report saved to: $reportPath"
    return $reportPath
}

# Main execution
try {
    Write-LogMessage "=== Conditional Access Baseline Deployment Started ==="
    Write-LogMessage "Tenant: $TenantId"
    Write-LogMessage "Mode: $(if($WhatIf){"What-If"}elseif($ReportMode){"Report-Only"}else{"Live Deployment"})"
    
    if (-not $SkipPrerequisites) {
        Test-Prerequisites
    }
    
    $deploymentResults = Deploy-CABaseline
    $reportPath = Write-DeploymentReport -Results $deploymentResults
    
    Write-LogMessage "=== Deployment Completed ==="
    Write-LogMessage "Report available at: $reportPath"
    
    if (-not $WhatIf) {
        Write-LogMessage "IMPORTANT: Policies are deployed in DISABLED state. Enable them manually after validation." "WARNING"
        Write-LogMessage "Consider enabling policies one by one, starting with report-only mode." "WARNING"
    }
}
catch {
    Write-LogMessage "Deployment failed: $($_.Exception.Message)" "ERROR"
    throw
}
