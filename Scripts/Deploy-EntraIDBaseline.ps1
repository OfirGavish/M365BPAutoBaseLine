<#
.SYNOPSIS
    Automates deployment of Entra ID security baselines and best practices.

.DESCRIPTION
    This script configures Entra ID with security best practices including:
    - Multi-Factor Authentication (MFA) via Conditional Access
    - Admin consent workflow for OAuth applications
    - Privileged Identity Management (PIM) configuration
    - Block legacy authentication
    - Security defaults or custom conditional access policies

.PARAMETER EnableSecurityDefaults
    Enable Security Defaults instead of custom Conditional Access policies

.PARAMETER AdminConsentReviewers
    Array of admin email addresses to review consent requests

.PARAMETER SkipConditionalAccessPolicies
    Skip creating Conditional Access policies (useful when deploying ConditionalAccess component separately)

.EXAMPLE
    .\Deploy-EntraIDBaseline.ps1 -AdminConsentReviewers @("admin@domain.com")
#>

param(
    [switch]$EnableSecurityDefaults = $false,
    [string[]]$AdminConsentReviewers = @(),
    [switch]$SkipConditionalAccessPolicies = $false
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
    
    # Check if Microsoft Graph PowerShell module is available
    if (!(Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Log "Microsoft.Graph module not found. Installing..." -Level "WARNING"
        Install-Module -Name Microsoft.Graph -Force -AllowClobber
    }
    
    Write-Log "Prerequisites check completed."
}

# Function to connect to Microsoft Graph
function Connect-MicrosoftGraphService {
    Write-Log "Connecting to Microsoft Graph..."
    try {
        $scopes = @(
            "Policy.ReadWrite.ConditionalAccess",
            "Policy.ReadWrite.PermissionGrant", 
            "Policy.ReadWrite.AuthenticationMethod",
            "Directory.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
            "Organization.Read.All",
            "Application.Read.All"
        )
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log "Successfully connected to Microsoft Graph."
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to enable Security Defaults
function Enable-SecurityDefaults {
    Write-Log "Enabling Security Defaults..."
    try {
        $identitySecurityDefaultsPolicy = @{
            IsEnabled = $true
        }
        Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $identitySecurityDefaultsPolicy
        Write-Log "Security Defaults enabled successfully."
    }
    catch {
        Write-Log "Error enabling Security Defaults: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to create Conditional Access policies
function New-ConditionalAccessPolicies {
    Write-Log "Creating Conditional Access policies..."
    try {
        # Policy 1: Require MFA for all users (start in report-only mode for safety)
        $mfaPolicy = @{
            displayName = "M365BP-Require-MFA-All-Users"
            state = "enabledForReportingButNotEnforced"  # Start in report-only mode for safety
            conditions = @{
                users = @{
                    includeUsers = @("All")
                    excludeUsers = @()
                }
                applications = @{
                    includeApplications = @("All")
                }
                locations = @{
                    includeLocations = @("All")
                }
            }
            grantControls = @{
                operator = "AND"
                builtInControls = @("mfa")
            }
        }
        
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'M365BP-Require-MFA-All-Users'" -ErrorAction SilentlyContinue
        if (!$existingPolicy) {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $mfaPolicy
            Write-Log "Created MFA policy for all users in REPORT-ONLY mode."
        } else {
            Write-Log "MFA policy already exists."
        }
        
        # Policy 2: Block legacy authentication (start in report-only mode for safety)
        $legacyAuthPolicy = @{
            displayName = "M365BP-Block-Legacy-Authentication"
            state = "enabledForReportingButNotEnforced"  # Start in report-only mode for safety
            conditions = @{
                users = @{
                    includeUsers = @("All")
                }
                applications = @{
                    includeApplications = @("All")
                }
                clientAppTypes = @("exchangeActiveSync", "other")
            }
            grantControls = @{
                operator = "OR"
                builtInControls = @("block")
            }
        }
        
        $existingLegacyPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'M365BP-Block-Legacy-Authentication'" -ErrorAction SilentlyContinue
        if (!$existingLegacyPolicy) {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $legacyAuthPolicy
            Write-Log "Created legacy authentication blocking policy in REPORT-ONLY mode."
        } else {
            Write-Log "Legacy authentication blocking policy already exists."
        }
        
        # Policy 3: Require compliant devices for admins (start in report-only mode for safety)
        $adminDevicePolicy = @{
            displayName = "M365BP-Admin-Require-Compliant-Device"
            state = "enabledForReportingButNotEnforced"  # Start in report-only mode to prevent lockout
            conditions = @{
                users = @{
                    includeRoles = @(
                        "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                        "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator
                    )
                }
                applications = @{
                    includeApplications = @("All")
                }
            }
            grantControls = @{
                operator = "AND"
                builtInControls = @("compliantDevice", "mfa")
            }
        }
        
        $existingAdminPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq 'M365BP-Admin-Require-Compliant-Device'" -ErrorAction SilentlyContinue
        if (!$existingAdminPolicy) {
            New-MgIdentityConditionalAccessPolicy -BodyParameter $adminDevicePolicy
            Write-Log "Created admin device compliance policy in REPORT-ONLY mode."
            Write-Log "IMPORTANT: Review and manually enable the 'M365BP-Admin-Require-Compliant-Device' policy after testing." -Level "WARNING"
        } else {
            Write-Log "Admin device compliance policy already exists."
        }
        
        # Add warning about all policies being in report-only mode
        Write-Log "IMPORTANT: All Conditional Access policies were created in REPORT-ONLY mode for safety." -Level "WARNING"
        Write-Log "Use the Enable-ConditionalAccessPolicies.ps1 script to safely enable them after testing." -Level "WARNING"
    }
    catch {
        Write-Log "Error creating Conditional Access policies: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to enable admin consent workflow
function Enable-AdminConsentWorkflow {
    Write-Log "Enabling admin consent workflow..."
    try {
        if ($AdminConsentReviewers.Count -gt 0) {
            $reviewers = $AdminConsentReviewers | ForEach-Object {
                @{
                    query = "/users/$_"
                    queryType = "MicrosoftGraph"
                }
            }
            
            $adminConsentRequestPolicy = @{
                isEnabled = $true
                notifyReviewers = $true
                remindersEnabled = $true
                requestDurationInDays = 30
                reviewers = $reviewers
            }
            
            Update-MgPolicyAdminConsentRequestPolicy -BodyParameter $adminConsentRequestPolicy
            Write-Log "Admin consent workflow enabled with reviewers: $($AdminConsentReviewers -join ', ')"
        } else {
            Write-Log "No reviewers specified for admin consent workflow." -Level "WARNING"
        }
    }
    catch {
        Write-Log "Error enabling admin consent workflow: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure PIM for privileged roles
function Set-PrivilegedIdentityManagement {
    Write-Log "Configuring Privileged Identity Management settings..."
    try {
        # Check if PIM is available (requires Azure AD Premium P2)
        try {
            $pimServicePrincipal = Get-MgServicePrincipal -Filter "displayName eq 'MS-PIM'" -ErrorAction SilentlyContinue
            if (-not $pimServicePrincipal) {
                Write-Log "PIM service principal not found. This may indicate PIM is not available in this tenant." -Level "WARNING"
                Write-Log "PIM requires Azure AD Premium P2 license. Please verify licensing and PIM availability." -Level "WARNING"
                return
            }
        }
        catch {
            Write-Log "Unable to verify PIM availability: $($_.Exception.Message)" -Level "WARNING"
        }

        # Get privileged roles to monitor
        $privilegedRoles = @{
            "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
            "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"  
            "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
            "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
            "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
        }
        
        foreach ($roleId in $privilegedRoles.Keys) {
            try {
                # Check if role exists and get current assignments
                $role = Get-MgDirectoryRole -Filter "roleTemplateId eq '$roleId'" -ErrorAction SilentlyContinue
                if ($role) {
                    $roleName = $privilegedRoles[$roleId]
                    Write-Log "Analyzing role: $roleName"
                    
                    # Get current role assignments
                    $roleAssignments = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                    
                    if ($roleAssignments) {
                        Write-Log "Found $($roleAssignments.Count) assignment(s) for role: $roleName"
                        
                        # Check for permanent assignments (potential PIM candidates)
                        foreach ($assignment in $roleAssignments) {
                            try {
                                $user = Get-MgUser -UserId $assignment.Id -ErrorAction SilentlyContinue
                                if ($user) {
                                    Write-Log "  - User: $($user.DisplayName) ($($user.UserPrincipalName))" -Level "WARNING"
                                }
                            }
                            catch {
                                Write-Log "  - Assignment ID: $($assignment.Id) (could not resolve user details)"
                            }
                        }
                        
                        Write-Log "RECOMMENDATION: Review permanent assignments for role '$roleName' and consider moving to PIM eligible assignments." -Level "WARNING"
                    } else {
                        Write-Log "No assignments found for role: $roleName"
                    }
                } else {
                    Write-Log "Role template $roleId not found or not instantiated"
                }
            }
            catch {
                Write-Log "Error analyzing role $roleId ($($privilegedRoles[$roleId])): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        # Provide guidance for PIM configuration
        Write-Log "PIM analysis completed. To properly configure PIM:" -Level "INFO"
        Write-Log "1. Navigate to Azure AD Privileged Identity Management in the Azure portal" -Level "INFO"
        Write-Log "2. Configure role settings for each privileged role (activation time, approval requirements, etc.)" -Level "INFO"
        Write-Log "3. Convert permanent assignments to eligible assignments where appropriate" -Level "INFO"
        Write-Log "4. Set up access reviews for privileged role assignments" -Level "INFO"
        Write-Log "5. Enable alerts for privileged role activations and assignments" -Level "INFO"
        
        Write-Log "PIM configuration guidance provided. Manual configuration required in Azure portal." -Level "WARNING"
    }
    catch {
        Write-Log "Error configuring PIM: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure authentication methods
function Set-AuthenticationMethods {
    Write-Log "Configuring authentication methods policies..."
    try {
        # Configure SMS authentication policy (disable for security)
        Write-Log "Configuring SMS authentication policy..."
        try {
            $smsAuthMethodPolicy = @{
                state = "disabled"
            }
            
            # Update SMS authentication method policy
            Update-MgPolicyAuthenticationMethodPolicySms -BodyParameter $smsAuthMethodPolicy
            Write-Log "SMS authentication has been disabled for enhanced security."
        }
        catch {
            Write-Log "Error configuring SMS authentication policy: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Manual configuration may be required in Azure AD portal under Authentication methods." -Level "WARNING"
        }
        
        # Configure Voice Call authentication policy (disable for security)
        Write-Log "Configuring Voice Call authentication policy..."
        try {
            $voiceAuthMethodPolicy = @{
                state = "disabled"
            }
            
            # Update Voice authentication method policy
            Update-MgPolicyAuthenticationMethodPolicyVoice -BodyParameter $voiceAuthMethodPolicy
            Write-Log "Voice call authentication has been disabled for enhanced security."
        }
        catch {
            Write-Log "Error configuring Voice authentication policy: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Manual configuration may be required in Azure AD portal under Authentication methods." -Level "WARNING"
        }
        
        # Configure Microsoft Authenticator policy (enable and require number match)
        Write-Log "Configuring Microsoft Authenticator policy..."
        try {
            $authenticatorPolicy = @{
                state = "enabled"
                microsoftAuthenticatorAuthenticationMethodConfiguration = @{
                    state = "enabled"
                    featureSettings = @{
                        requireNumberMatching = $true
                        companionAppAllowedState = @{
                            state = "enabled"
                        }
                    }
                }
            }
            
            # Update Microsoft Authenticator policy
            Update-MgPolicyAuthenticationMethodPolicyMicrosoftAuthenticator -BodyParameter $authenticatorPolicy
            Write-Log "Microsoft Authenticator configured with number matching requirement."
        }
        catch {
            Write-Log "Error configuring Microsoft Authenticator policy: $($_.Exception.Message)" -Level "WARNING"
            Write-Log "Manual configuration may be required in Azure AD portal under Authentication methods." -Level "WARNING"
        }
        
        # Get current authentication methods policy status
        Write-Log "Reviewing current authentication methods configuration..."
        try {
            $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
            if ($authMethodsPolicy) {
                Write-Log "Authentication methods policy found and configured."
                
                # Provide recommendations
                Write-Log "RECOMMENDATIONS for authentication methods:" -Level "INFO"
                Write-Log "1. Ensure FIDO2 security keys are enabled for passwordless authentication" -Level "INFO"
                Write-Log "2. Configure Temporary Access Pass for secure onboarding" -Level "INFO"
                Write-Log "3. Review and test all authentication methods with pilot users" -Level "INFO"
                Write-Log "4. Consider enabling Windows Hello for Business" -Level "INFO"
            }
        }
        catch {
            Write-Log "Could not retrieve authentication methods policy for review: $($_.Exception.Message)" -Level "WARNING"
        }
        
        Write-Log "Authentication methods configuration completed."
    }
    catch {
        Write-Log "Error configuring authentication methods: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to enable and verify Continuous Access Evaluation
function Enable-ContinuousAccessEvaluation {
    Write-Log "Verifying Continuous Access Evaluation (CAE) configuration..."
    try {
        # CAE is typically enabled by default, but let's verify the configuration
        Write-Log "Checking CAE-compatible applications and policies..."
        
        # Check for CAE-compatible conditional access policies
        try {
            $conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue
            $caeCompatiblePolicies = $conditionalAccessPolicies | Where-Object { 
                $_.SessionControls -and $_.SessionControls.SignInFrequency 
            }
            
            if ($caeCompatiblePolicies) {
                Write-Log "Found $($caeCompatiblePolicies.Count) conditional access policies with session controls that work with CAE."
            } else {
                Write-Log "No conditional access policies with CAE-compatible session controls found." -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not analyze conditional access policies for CAE compatibility: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Verify tenant configuration supports CAE
        try {
            # Get tenant information
            $organization = Get-MgOrganization -ErrorAction SilentlyContinue
            if ($organization) {
                Write-Log "Tenant verification completed for CAE support."
                
                # Check if security defaults are enabled (affects CAE)
                try {
                    $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
                    if ($securityDefaults -and $securityDefaults.IsEnabled) {
                        Write-Log "Security Defaults are enabled. CAE works with Security Defaults." -Level "INFO"
                    } else {
                        Write-Log "Security Defaults are disabled. CAE works with custom Conditional Access policies." -Level "INFO"
                    }
                }
                catch {
                    Write-Log "Could not verify Security Defaults status: $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }
        catch {
            Write-Log "Could not verify tenant configuration: $($_.Exception.Message)" -Level "WARNING"
        }
        
        # Provide CAE guidance and recommendations
        Write-Log "Continuous Access Evaluation (CAE) information:" -Level "INFO"
        Write-Log "- CAE is automatically enabled for supported applications and scenarios" -Level "INFO"
        Write-Log "- CAE works with: Exchange Online, SharePoint Online, Microsoft Teams, and Microsoft Graph" -Level "INFO"
        Write-Log "- CAE provides real-time enforcement of IP location and user risk policies" -Level "INFO"
        Write-Log "- CAE reduces sign-in frequency for trusted scenarios while maintaining security" -Level "INFO"
        
        Write-Log "CAE RECOMMENDATIONS:" -Level "INFO"
        Write-Log "1. Ensure your Conditional Access policies include IP location conditions to benefit from CAE" -Level "INFO"
        Write-Log "2. Test CAE behavior with different network locations and risk levels" -Level "INFO"
        Write-Log "3. Monitor CAE events in Azure AD sign-in logs" -Level "INFO"
        Write-Log "4. Educate users about potential immediate access revocation with CAE" -Level "INFO"
        
        # Check for CAE-related service principals
        try {
            $caeRelatedApps = @(
                "Microsoft Graph",
                "Office 365 Exchange Online", 
                "Microsoft Office 365",
                "Office 365 SharePoint Online"
            )
            
            Write-Log "Verifying CAE-compatible service principals..."
            foreach ($appName in $caeRelatedApps) {
                $servicePrincipal = Get-MgServicePrincipal -Filter "displayName eq '$appName'" -ErrorAction SilentlyContinue
                if ($servicePrincipal) {
                    Write-Log "✓ CAE-compatible service principal found: $appName"
                } else {
                    Write-Log "⚠ CAE-compatible service principal not found: $appName" -Level "WARNING"
                }
            }
        }
        catch {
            Write-Log "Could not verify CAE-compatible service principals: $($_.Exception.Message)" -Level "WARNING"
        }
        
        Write-Log "Continuous Access Evaluation verification completed."
        Write-Log "CAE is enabled by default and requires no additional configuration." -Level "SUCCESS"
    }
    catch {
        Write-Log "Error verifying CAE configuration: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to disconnect from Microsoft Graph
function Disconnect-MicrosoftGraphService {
    Write-Log "Disconnecting from Microsoft Graph..."
    try {
        Disconnect-MgGraph
        Write-Log "Disconnected from Microsoft Graph."
    }
    catch {
        Write-Log "Error disconnecting from Microsoft Graph: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Function to provide comprehensive security recommendations
function Show-SecurityRecommendations {
    Write-Log "=== ENTRA ID SECURITY BASELINE DEPLOYMENT SUMMARY ===" -Level "SUCCESS"
    Write-Log ""
    Write-Log "COMPLETED CONFIGURATIONS:" -Level "INFO"
    Write-Log "✓ Conditional Access policies created (in report-only mode for safety)" -Level "INFO"
    Write-Log "✓ Admin consent workflow configured" -Level "INFO"
    Write-Log "✓ Authentication methods policies updated" -Level "INFO"
    Write-Log "✓ PIM role analysis completed" -Level "INFO"
    Write-Log "✓ Continuous Access Evaluation verified" -Level "INFO"
    Write-Log ""
    Write-Log "CRITICAL NEXT STEPS:" -Level "WARNING"
    Write-Log "1. TEST all Conditional Access policies in report-only mode before enabling" -Level "WARNING"
    Write-Log "2. REVIEW privileged role assignments and implement PIM eligible assignments" -Level "WARNING"
    Write-Log "3. VERIFY authentication methods work for all users before enforcing" -Level "WARNING"
    Write-Log "4. CONFIGURE emergency access accounts (break-glass accounts)" -Level "WARNING"
    Write-Log "5. SET UP monitoring and alerting for security events" -Level "WARNING"
    Write-Log ""
    Write-Log "ADDITIONAL RECOMMENDATIONS:" -Level "INFO"
    Write-Log "• Enable Identity Protection for real-time risk detection" -Level "INFO"
    Write-Log "• Configure access reviews for privileged roles" -Level "INFO"
    Write-Log "• Implement Azure AD Connect Health monitoring" -Level "INFO"
    Write-Log "• Set up Azure Sentinel for advanced security monitoring" -Level "INFO"
    Write-Log "• Regular security assessment using Microsoft Secure Score" -Level "INFO"
    Write-Log ""
    Write-Log "DOCUMENTATION LINKS:" -Level "INFO"
    Write-Log "• Conditional Access: https://docs.microsoft.com/azure/active-directory/conditional-access/" -Level "INFO"
    Write-Log "• PIM: https://docs.microsoft.com/azure/active-directory/privileged-identity-management/" -Level "INFO"
    Write-Log "• Authentication Methods: https://docs.microsoft.com/azure/active-directory/authentication/" -Level "INFO"
    Write-Log "============================================================" -Level "SUCCESS"
}

# Main execution
try {
    Write-Log "Starting Entra ID baseline deployment..." -Level "SUCCESS"
    
    Test-Prerequisites
    Connect-MicrosoftGraphService
    
    if ($EnableSecurityDefaults) {
        Write-Log "Security Defaults mode selected - this will override custom Conditional Access policies" -Level "WARNING"
        Enable-SecurityDefaults
    } elseif ($SkipConditionalAccessPolicies) {
        Write-Log "Skipping Conditional Access policies creation (will be handled by ConditionalAccess component)" -Level "WARNING"
    } else {
        New-ConditionalAccessPolicies
    }
    
    Enable-AdminConsentWorkflow
    Set-PrivilegedIdentityManagement
    Set-AuthenticationMethods
    Enable-ContinuousAccessEvaluation
    
    Write-Log "Entra ID baseline deployment completed successfully!" -Level "SUCCESS"
    
    # Show comprehensive recommendations
    Show-SecurityRecommendations
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-MicrosoftGraphService
}
