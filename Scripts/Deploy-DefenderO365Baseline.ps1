<#
.SYNOPSIS
    Automates deployment of Defender for Office 365 baselines and best practices with comprehensive compliance assessment.

.DESCRIPTION
    This script configures Defender for Office 365 with security best practices including:
    - DKIM enforcement for all domains with validation
    - Safe Links and Safe Attachments with enhanced settings
    - Anti-phishing policies with advanced protection
    - Policy presets (Standard/Strict) configuration
    - Service account exclusions for operational needs
    - Comprehensive compliance assessment and scoring
    - HTML report generation with recommendations
    - Email authentication (SPF/DMARC) verification
    - WhatIf mode for safe testing

.PARAMETER ServiceAccounts
    Array of service account email addresses to exclude from strict policies.
    These accounts will be exempt from anti-phishing rules to prevent operational disruption.

.PARAMETER PolicyPreset
    Choose between "Standard" or "Strict" policy preset (default: Standard).
    - Standard: Balanced security with minimal user impact
    - Strict: Maximum security with potential for more user friction

.PARAMETER AdminEmail
    Administrator email address for policy notifications and redirects.
    If not specified, the script will attempt to auto-detect from current connection.

.PARAMETER OutputPath
    Path for the HTML compliance report (default: .\M365BP-DefenderO365-Report.html).
    The report includes detailed assessment, recommendations, and configuration details.

.PARAMETER WhatIf
    Run in simulation mode without making any changes.
    Shows what would be configured without actually implementing changes.

.PARAMETER SkipDKIM
    Skip DKIM configuration. Use when DKIM is managed externally or not required.

.PARAMETER SkipSafeLinks
    Skip Safe Links configuration. Use when Safe Links is managed by other policies.

.PARAMETER SkipSafeAttachments
    Skip Safe Attachments configuration. Use when Safe Attachments is managed by other policies.

.PARAMETER SkipAntiPhishing
    Skip Anti-Phishing configuration. Use when anti-phishing is managed by other policies.

.EXAMPLE
    .\Deploy-DefenderO365Baseline.ps1
    Deploys standard Defender for Office 365 baseline with auto-detection.

.EXAMPLE
    .\Deploy-DefenderO365Baseline.ps1 -PolicyPreset "Strict" -AdminEmail "admin@company.com"
    Deploys strict security policies with specified admin email for notifications.

.EXAMPLE
    .\Deploy-DefenderO365Baseline.ps1 -ServiceAccounts @("service1@company.com", "service2@company.com") -WhatIf
    Simulates deployment with service account exclusions without making changes.

.EXAMPLE
    .\Deploy-DefenderO365Baseline.ps1 -SkipDKIM -SkipSafeLinks -OutputPath "C:\Reports\DefenderO365.html"
    Deploys only Safe Attachments and Anti-Phishing with custom report location.

.NOTES
    Author: Microsoft 365 Business Premium Baseline Script
    Version: 2.0
    Requires: ExchangeOnlineManagement PowerShell module
    Requires: Exchange Online Administrator or Security Administrator role
    
    This script provides comprehensive Defender for Office 365 configuration with:
    - Production-ready error handling and logging
    - Compliance scoring and assessment
    - Detailed HTML reporting with recommendations
    - WhatIf mode for safe testing
    - Granular control over individual components
    
.LINK
    https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/
#>

param(
    [string[]]$ServiceAccounts = @(),
    [ValidateSet("Standard", "Strict")]
    [string]$PolicyPreset = "Standard",
    [string]$AdminEmail = "",
    [string]$OutputPath = ".\M365BP-DefenderO365-Report.html",
    [switch]$WhatIf,
    [switch]$SkipDKIM,
    [switch]$SkipSafeLinks,
    [switch]$SkipSafeAttachments,
    [switch]$SkipAntiPhishing
)

# Function to log messages
# Global variables for tracking
$script:ComplianceResults = @()
$script:Recommendations = @()
$script:PolicyResults = @{
    DKIM = @()
    SafeLinks = @()
    SafeAttachments = @()
    AntiPhishing = @()
}
$script:DeploymentStartTime = Get-Date
$script:LogFile = "M365BP-DefenderO365-Deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Function to log messages with fixed log file
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [DefenderO365] [$Level] $Message"
    
    # Write to console with color
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
    
    # Write to consistent log file (don't create new file each time!)
    Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

# Function to verify Exchange Online connection
function Test-ExchangeOnlineConnection {
    try {
        $connection = Get-ConnectionInformation -ErrorAction Stop
        if ($connection) {
            Write-Log "Exchange Online connection verified: $($connection.TenantID)" -Level "SUCCESS"
            return $true
        }
    }
    catch {
        Write-Log "Exchange Online connection failed: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    return $false
}

# Function to verify policy creation/update
function Test-PolicyExists {
    param(
        [string]$PolicyName,
        [string]$PolicyType
    )
    
    try {
        switch ($PolicyType) {
            "SafeLinks" {
                $policy = Get-SafeLinksPolicy -Identity $PolicyName -ErrorAction SilentlyContinue
                return $null -ne $policy
            }
            "SafeAttachments" {
                $policy = Get-SafeAttachmentsPolicy -Identity $PolicyName -ErrorAction SilentlyContinue
                return $null -ne $policy
            }
            "AntiPhishing" {
                $policy = Get-AntiPhishPolicy -Identity $PolicyName -ErrorAction SilentlyContinue
                return $null -ne $policy
            }
            default {
                return $false
            }
        }
    }
    catch {
        Write-Log "Error checking policy $PolicyName : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}
    SafeLinks = @()
    SafeAttachments = @()
    AntiPhishing = @()
    PresetPolicies = @()
}

# Function to check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check if Exchange Online module is available
    if (!(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Log "ExchangeOnlineManagement module not found. Installing..." -Level "WARNING"
        Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
    }
    
    Write-Log "Prerequisites check completed."
}

# Function to connect to Exchange Online
function Connect-ExchangeOnlineService {
    Write-Log "Connecting to Exchange Online..."
    try {
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Write-Log "Successfully connected to Exchange Online."
    }
    catch {
        Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

# Function to enable DKIM for all domains
function Enable-DKIMForAllDomains {
    if ($SkipDKIM) {
        Write-Log "Skipping DKIM configuration as requested" -Level "WARNING"
        return
    }
    
    Write-Log "Enabling DKIM for all accepted domains..."
    try {
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            $domainName = $domain.DomainName
            Write-Log "Processing domain: $domainName"
            
            $dkimConfig = Get-DkimSigningConfig -Identity $domainName -ErrorAction SilentlyContinue
            if ($dkimConfig) {
                $currentStatus = $dkimConfig.Enabled
                $result = @{
                    Domain = $domainName
                    CurrentStatus = $currentStatus
                    Action = ""
                    Success = $false
                    Error = ""
                }
                
                if (!$currentStatus) {
                    if ($WhatIf) {
                        Write-Log "WHATIF: Would enable DKIM for $domainName" -Level "WARNING"
                        $result.Action = "Would Enable"
                        $result.Success = $true
                    } else {
                        try {
                            Set-DkimSigningConfig -Identity $domainName -Enabled $true
                            Write-Log "DKIM enabled for $domainName" -Level "SUCCESS"
                            $result.Action = "Enabled"
                            $result.Success = $true
                        }
                        catch {
                            Write-Log "Failed to enable DKIM for $domainName`: $($_.Exception.Message)" -Level "ERROR"
                            $result.Error = $_.Exception.Message
                        }
                    }
                } else {
                    Write-Log "DKIM already enabled for $domainName" -Level "SUCCESS"
                    $result.Action = "Already Enabled"
                    $result.Success = $true
                }
                
                $script:PolicyResults.DKIM += $result
            } else {
                Write-Log "DKIM configuration not found for $domainName" -Level "WARNING"
                $script:PolicyResults.DKIM += @{
                    Domain = $domainName
                    CurrentStatus = "Not Available"
                    Action = "Configuration Missing"
                    Success = $false
                    Error = "DKIM configuration not available"
                }
            }
        }
        
        # Add compliance result
        $enabledDomains = ($script:PolicyResults.DKIM | Where-Object { $_.Success -and $_.CurrentStatus }).Count
        $totalDomains = $domains.Count
        $complianceScore = if ($totalDomains -gt 0) { [math]::Round(($enabledDomains / $totalDomains) * 100, 2) } else { 0 }
        
        $script:ComplianceResults += @{
            Category = "DKIM Authentication"
            Status = if ($complianceScore -eq 100) { "Compliant" } elseif ($complianceScore -ge 75) { "Partially Compliant" } else { "Non-Compliant" }
            Score = $complianceScore
            Details = "$enabledDomains of $totalDomains domains have DKIM enabled"
            Recommendation = if ($complianceScore -lt 100) { "Enable DKIM for all accepted domains to improve email authentication" } else { "DKIM is properly configured for all domains" }
        }
    }
    catch {
        Write-Log "Error enabling DKIM: $($_.Exception.Message)" -Level "ERROR"
        $script:ComplianceResults += @{
            Category = "DKIM Authentication"
            Status = "Error"
            Score = 0
            Details = "Failed to configure DKIM: $($_.Exception.Message)"
            Recommendation = "Review DKIM configuration requirements and permissions"
        }
    }
}

# Function to check SPF and DMARC records
function Test-EmailAuthentication {
    Write-Log "Checking SPF and DMARC records for all domains..."
    $authResults = @()
    
    try {
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            $domainName = $domain.DomainName
            $domainResult = @{
                Domain = $domainName
                SPFRecord = ""
                SPFStatus = "Not Configured"
                DMARCRecord = ""
                DMARCStatus = "Not Configured"
                DMARCPolicy = ""
            }
            
            # Check SPF record
            try {
                $spfRecord = Resolve-DnsName -Name $domainName -Type TXT -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Strings -like "v=spf1*" }
                if ($spfRecord) {
                    $spfString = $spfRecord.Strings -join ""
                    $domainResult.SPFRecord = $spfString
                    $domainResult.SPFStatus = "Configured"
                    Write-Log "$domainName - SPF: $spfString" -Level "SUCCESS"
                    
                    # Check for common SPF issues
                    if ($spfString -notlike "*include:spf.protection.outlook.com*") {
                        Write-Log "$domainName - SPF: Missing Office 365 include" -Level "WARNING"
                        $script:Recommendations += "Add 'include:spf.protection.outlook.com' to SPF record for $domainName"
                    }
                } else {
                    Write-Log "$domainName - SPF: Not configured" -Level "WARNING"
                    $script:Recommendations += "Configure SPF record for $domainName to prevent email spoofing"
                }
            }
            catch {
                Write-Log "$domainName - SPF: Unable to resolve - $($_.Exception.Message)" -Level "WARNING"
                $domainResult.SPFStatus = "Resolution Error"
            }
            
            # Check DMARC record
            try {
                $dmarcRecord = Resolve-DnsName -Name "_dmarc.$domainName" -Type TXT -ErrorAction SilentlyContinue
                if ($dmarcRecord) {
                    $dmarcString = $dmarcRecord.Strings -join ""
                    $domainResult.DMARCRecord = $dmarcString
                    $domainResult.DMARCStatus = "Configured"
                    
                    # Extract DMARC policy
                    if ($dmarcString -match "p=(\w+)") {
                        $domainResult.DMARCPolicy = $Matches[1]
                    }
                    
                    Write-Log "$domainName - DMARC: $dmarcString" -Level "SUCCESS"
                    
                    # Check DMARC policy strength
                    if ($domainResult.DMARCPolicy -eq "none") {
                        Write-Log "$domainName - DMARC: Policy is set to 'none' - consider strengthening" -Level "WARNING"
                        $script:Recommendations += "Consider strengthening DMARC policy for $domainName from 'none' to 'quarantine' or 'reject'"
                    }
                } else {
                    Write-Log "$domainName - DMARC: Not configured" -Level "WARNING"
                    $script:Recommendations += "Configure DMARC record for $domainName to improve email authentication"
                }
            }
            catch {
                Write-Log "$domainName - DMARC: Unable to resolve - $($_.Exception.Message)" -Level "WARNING"
                $domainResult.DMARCStatus = "Resolution Error"
            }
            
            $authResults += $domainResult
        }
        
        # Calculate compliance score
        $spfConfigured = ($authResults | Where-Object { $_.SPFStatus -eq "Configured" }).Count
        $dmarcConfigured = ($authResults | Where-Object { $_.DMARCStatus -eq "Configured" }).Count
        $totalDomains = $authResults.Count
        
        $spfScore = if ($totalDomains -gt 0) { [math]::Round(($spfConfigured / $totalDomains) * 100, 2) } else { 0 }
        $dmarcScore = if ($totalDomains -gt 0) { [math]::Round(($dmarcConfigured / $totalDomains) * 100, 2) } else { 0 }
        $overallScore = [math]::Round(($spfScore + $dmarcScore) / 2, 2)
        
        $script:ComplianceResults += @{
            Category = "Email Authentication (SPF/DMARC)"
            Status = if ($overallScore -eq 100) { "Compliant" } elseif ($overallScore -ge 75) { "Partially Compliant" } else { "Non-Compliant" }
            Score = $overallScore
            Details = "SPF: $spfConfigured/$totalDomains domains configured ($spfScore%). DMARC: $dmarcConfigured/$totalDomains domains configured ($dmarcScore%)"
            Recommendation = "Ensure all domains have proper SPF and DMARC records configured for email authentication"
        }
        
        return $authResults
    }
    catch {
        Write-Log "Error checking email authentication: $($_.Exception.Message)" -Level "ERROR"
        $script:ComplianceResults += @{
            Category = "Email Authentication (SPF/DMARC)"
            Status = "Error"
            Score = 0
            Details = "Failed to check email authentication: $($_.Exception.Message)"
            Recommendation = "Review DNS resolution and domain configuration"
        }
        return @()
    }
}

# Function to configure Safe Links and Safe Attachments
function Set-SafeLinksAndAttachments {
    if ($SkipSafeLinks -and $SkipSafeAttachments) {
        Write-Log "Skipping Safe Links and Safe Attachments configuration as requested" -Level "WARNING"
        return
    }
    
    # Configure Safe Links
    if (!$SkipSafeLinks) {
        Write-Log "Configuring Safe Links..."
        try {
            $safeLinksPolicy = Get-SafeLinksPolicy -Identity "M365BP-SafeLinks-Policy" -ErrorAction SilentlyContinue
            $result = @{
                PolicyName = "M365BP-SafeLinks-Policy"
                Type = "Safe Links Policy"
                Action = ""
                Success = $false
                Error = ""
                Configuration = @{}
            }
            
            $safeLinksConfig = @{
                EnableSafeLinksForTeams = $true
                ScanUrls = $true
                EnableForInternalSenders = $true
                DeliverMessageAfterScan = $true
                DisableUrlRewrite = $false
                EnableOrganizationBranding = $true
            }
            
            if (!$safeLinksPolicy) {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would create Safe Links policy with enhanced settings" -Level "WARNING"
                    $result.Action = "Would Create"
                    $result.Success = $true
                } else {
                    try {
                        # Verify Exchange Online connection first
                        if (!(Test-ExchangeOnlineConnection)) {
                            throw "Exchange Online connection required but not available"
                        }
                        
                        Write-Log "Creating Safe Links policy..." -Level "INFO"
                        New-SafeLinksPolicy -Name "M365BP-SafeLinks-Policy" @safeLinksConfig -ErrorAction Stop
                        
                        # Verify policy was actually created
                        Start-Sleep -Seconds 2  # Give time for policy to be created
                        if (Test-PolicyExists -PolicyName "M365BP-SafeLinks-Policy" -PolicyType "SafeLinks") {
                            Write-Log "Successfully created and verified Safe Links policy with enhanced settings" -Level "SUCCESS"
                            $result.Action = "Created"
                            $result.Success = $true
                        } else {
                            throw "Policy creation appeared successful but policy not found in verification"
                        }
                    }
                    catch {
                        Write-Log "Failed to create Safe Links policy: $($_.Exception.Message)" -Level "ERROR"
                        $result.Error = $_.Exception.Message
                        $result.Success = $false
                    }
                }
            } else {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would update Safe Links policy with enhanced settings" -Level "WARNING"
                    $result.Action = "Would Update"
                    $result.Success = $true
                } else {
                    try {
                        Set-SafeLinksPolicy -Identity "M365BP-SafeLinks-Policy" @safeLinksConfig
                        Write-Log "Updated Safe Links policy with enhanced settings" -Level "SUCCESS"
                        $result.Action = "Updated"
                        $result.Success = $true
                    }
                    catch {
                        Write-Log "Failed to update Safe Links policy: $($_.Exception.Message)" -Level "ERROR"
                        $result.Error = $_.Exception.Message
                    }
                }
            }
            
            $result.Configuration = $safeLinksConfig
            $script:PolicyResults.SafeLinks += $result
            
            # Create Safe Links rule
            $safeLinksRule = Get-SafeLinksRule -Identity "M365BP-SafeLinks-Rule" -ErrorAction SilentlyContinue
            if (!$safeLinksRule) {
                $ruleResult = @{
                    PolicyName = "M365BP-SafeLinks-Rule"
                    Type = "Safe Links Rule"
                    Action = ""
                    Success = $false
                    Error = ""
                }
                
                if ($WhatIf) {
                    Write-Log "WHATIF: Would create Safe Links rule for all domains" -Level "WARNING"
                    $ruleResult.Action = "Would Create"
                    $ruleResult.Success = $true
                } else {
                    try {
                        $domains = (Get-AcceptedDomain).DomainName
                        New-SafeLinksRule -Name "M365BP-SafeLinks-Rule" -SafeLinksPolicy "M365BP-SafeLinks-Policy" -RecipientDomainIs $domains
                        Write-Log "Created Safe Links rule for all domains" -Level "SUCCESS"
                        $ruleResult.Action = "Created"
                        $ruleResult.Success = $true
                    }
                    catch {
                        Write-Log "Failed to create Safe Links rule: $($_.Exception.Message)" -Level "ERROR"
                        $ruleResult.Error = $_.Exception.Message
                    }
                }
                
                $script:PolicyResults.SafeLinks += $ruleResult
            }
        }
        catch {
            Write-Log "Error configuring Safe Links: $($_.Exception.Message)" -Level "ERROR"
            $script:PolicyResults.SafeLinks += @{
                PolicyName = "M365BP-SafeLinks-Policy"
                Type = "Safe Links Policy"
                Action = "Error"
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Configure Safe Attachments
    if (!$SkipSafeAttachments) {
        Write-Log "Configuring Safe Attachments..."
        try {
            $safeAttachmentsPolicy = Get-SafeAttachmentPolicy -Identity "M365BP-SafeAttachments-Policy" -ErrorAction SilentlyContinue
            $result = @{
                PolicyName = "M365BP-SafeAttachments-Policy"
                Type = "Safe Attachments Policy"
                Action = ""
                Success = $false
                Error = ""
                Configuration = @{}
            }
            
            $safeAttachmentsConfig = @{
                Enable = $true
                Action = "Block"
                EnableOrganizationBranding = $true
                Redirect = $false
            }
            
            # Add redirect email if admin email is provided
            if ($AdminEmail) {
                $safeAttachmentsConfig.Redirect = $true
                $safeAttachmentsConfig.RedirectAddress = $AdminEmail
            }
            
            if (!$safeAttachmentsPolicy) {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would create Safe Attachments policy with block action" -Level "WARNING"
                    $result.Action = "Would Create"
                    $result.Success = $true
                } else {
                    try {
                        New-SafeAttachmentPolicy -Name "M365BP-SafeAttachments-Policy" @safeAttachmentsConfig
                        Write-Log "Created Safe Attachments policy with block action" -Level "SUCCESS"
                        $result.Action = "Created"
                        $result.Success = $true
                    }
                    catch {
                        Write-Log "Failed to create Safe Attachments policy: $($_.Exception.Message)" -Level "ERROR"
                        $result.Error = $_.Exception.Message
                    }
                }
            } else {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would update Safe Attachments policy with block action" -Level "WARNING"
                    $result.Action = "Would Update"
                    $result.Success = $true
                } else {
                    try {
                        Set-SafeAttachmentPolicy -Identity "M365BP-SafeAttachments-Policy" @safeAttachmentsConfig
                        Write-Log "Updated Safe Attachments policy with block action" -Level "SUCCESS"
                        $result.Action = "Updated"
                        $result.Success = $true
                    }
                    catch {
                        Write-Log "Failed to update Safe Attachments policy: $($_.Exception.Message)" -Level "ERROR"
                        $result.Error = $_.Exception.Message
                    }
                }
            }
            
            $result.Configuration = $safeAttachmentsConfig
            $script:PolicyResults.SafeAttachments += $result
            
            # Create Safe Attachments rule
            $safeAttachmentsRule = Get-SafeAttachmentRule -Identity "M365BP-SafeAttachments-Rule" -ErrorAction SilentlyContinue
            if (!$safeAttachmentsRule) {
                $ruleResult = @{
                    PolicyName = "M365BP-SafeAttachments-Rule"
                    Type = "Safe Attachments Rule"
                    Action = ""
                    Success = $false
                    Error = ""
                }
                
                if ($WhatIf) {
                    Write-Log "WHATIF: Would create Safe Attachments rule for all domains" -Level "WARNING"
                    $ruleResult.Action = "Would Create"
                    $ruleResult.Success = $true
                } else {
                    try {
                        $domains = (Get-AcceptedDomain).DomainName
                        New-SafeAttachmentRule -Name "M365BP-SafeAttachments-Rule" -SafeAttachmentPolicy "M365BP-SafeAttachments-Policy" -RecipientDomainIs $domains
                        Write-Log "Created Safe Attachments rule for all domains" -Level "SUCCESS"
                        $ruleResult.Action = "Created"
                        $ruleResult.Success = $true
                    }
                    catch {
                        Write-Log "Failed to create Safe Attachments rule: $($_.Exception.Message)" -Level "ERROR"
                        $ruleResult.Error = $_.Exception.Message
                    }
                }
                
                $script:PolicyResults.SafeAttachments += $ruleResult
            }
        }
        catch {
            Write-Log "Error configuring Safe Attachments: $($_.Exception.Message)" -Level "ERROR"
            $script:PolicyResults.SafeAttachments += @{
                PolicyName = "M365BP-SafeAttachments-Policy"
                Type = "Safe Attachments Policy"
                Action = "Error"
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Add compliance results
    $safeLinksSuccess = ($script:PolicyResults.SafeLinks | Where-Object { $_.Success }).Count
    $safeAttachmentsSuccess = ($script:PolicyResults.SafeAttachments | Where-Object { $_.Success }).Count
    $totalPolicies = $script:PolicyResults.SafeLinks.Count + $script:PolicyResults.SafeAttachments.Count
    $successCount = $safeLinksSuccess + $safeAttachmentsSuccess
    
    if ($totalPolicies -gt 0) {
        $complianceScore = [math]::Round(($successCount / $totalPolicies) * 100, 2)
        $script:ComplianceResults += @{
            Category = "Safe Links and Attachments"
            Status = if ($complianceScore -eq 100) { "Compliant" } elseif ($complianceScore -ge 75) { "Partially Compliant" } else { "Non-Compliant" }
            Score = $complianceScore
            Details = "Successfully configured $successCount of $totalPolicies Safe Links/Attachments policies"
            Recommendation = if ($complianceScore -lt 100) { "Review and fix failed Safe Links/Attachments policy configurations" } else { "Safe Links and Attachments are properly configured" }
        }
    }
}

# Function to configure Anti-Phishing policies
function Set-AntiPhishingPolicies {
    if ($SkipAntiPhishing) {
        Write-Log "Skipping Anti-Phishing configuration as requested" -Level "WARNING"
        return
    }
    
    Write-Log "Configuring Anti-Phishing policies..."
    try {
        $antiPhishPolicy = Get-AntiPhishPolicy -Identity "M365BP-AntiPhish-Policy" -ErrorAction SilentlyContinue
        $result = @{
            PolicyName = "M365BP-AntiPhish-Policy"
            Type = "Anti-Phishing Policy"
            Action = ""
            Success = $false
            Error = ""
            Configuration = @{}
        }
        
        # Enhanced anti-phishing configuration
        $antiPhishConfig = @{
            EnableTargetedUserProtection = $true
            EnableTargetedDomainsProtection = $true
            EnableMailboxIntelligence = $true
            EnableMailboxIntelligenceProtection = $true
            EnableSpoofIntelligence = $true
            EnableUnauthenticatedSender = $true
            EnableViaTag = $true
            EnableSimilarUsersSafetyTips = $true
            EnableSimilarDomainsSafetyTips = $true
            EnableUnusualCharactersSafetyTips = $true
        }
        
        # Add targeted users protection if admin email is provided
        if ($AdminEmail) {
            $antiPhishConfig.TargetedUsersToProtect = $AdminEmail
        }
        
        if (!$antiPhishPolicy) {
            if ($WhatIf) {
                Write-Log "WHATIF: Would create Anti-Phishing policy with enhanced protection" -Level "WARNING"
                $result.Action = "Would Create"
                $result.Success = $true
            } else {
                try {
                    New-AntiPhishPolicy -Name "M365BP-AntiPhish-Policy" @antiPhishConfig
                    Write-Log "Created Anti-Phishing policy with enhanced protection" -Level "SUCCESS"
                    $result.Action = "Created"
                    $result.Success = $true
                }
                catch {
                    Write-Log "Failed to create Anti-Phishing policy: $($_.Exception.Message)" -Level "ERROR"
                    $result.Error = $_.Exception.Message
                }
            }
        } else {
            if ($WhatIf) {
                Write-Log "WHATIF: Would update Anti-Phishing policy with enhanced protection" -Level "WARNING"
                $result.Action = "Would Update"
                $result.Success = $true
            } else {
                try {
                    Set-AntiPhishPolicy -Identity "M365BP-AntiPhish-Policy" @antiPhishConfig
                    Write-Log "Updated Anti-Phishing policy with enhanced protection" -Level "SUCCESS"
                    $result.Action = "Updated"
                    $result.Success = $true
                }
                catch {
                    Write-Log "Failed to update Anti-Phishing policy: $($_.Exception.Message)" -Level "ERROR"
                    $result.Error = $_.Exception.Message
                }
            }
        }
        
        $result.Configuration = $antiPhishConfig
        $script:PolicyResults.AntiPhishing += $result
        
        # Create Anti-Phishing rule
        $antiPhishRule = Get-AntiPhishRule -Identity "M365BP-AntiPhish-Rule" -ErrorAction SilentlyContinue
        if (!$antiPhishRule) {
            $ruleResult = @{
                PolicyName = "M365BP-AntiPhish-Rule"
                Type = "Anti-Phishing Rule"
                Action = ""
                Success = $false
                Error = ""
            }
            
            if ($WhatIf) {
                Write-Log "WHATIF: Would create Anti-Phishing rule for all domains" -Level "WARNING"
                $ruleResult.Action = "Would Create"
                $ruleResult.Success = $true
            } else {
                try {
                    $domains = (Get-AcceptedDomain).DomainName
                    $ruleParams = @{
                        Name = "M365BP-AntiPhish-Rule"
                        AntiPhishPolicy = "M365BP-AntiPhish-Policy"
                        RecipientDomainIs = $domains
                    }
                    
                    # Add service account exclusions if provided
                    if ($ServiceAccounts.Count -gt 0) {
                        $ruleParams.ExceptIfSentTo = $ServiceAccounts
                        Write-Log "Excluding $($ServiceAccounts.Count) service accounts from Anti-Phishing policy"
                    }
                    
                    New-AntiPhishRule @ruleParams
                    Write-Log "Created Anti-Phishing rule for all domains" -Level "SUCCESS"
                    $ruleResult.Action = "Created"
                    $ruleResult.Success = $true
                }
                catch {
                    Write-Log "Failed to create Anti-Phishing rule: $($_.Exception.Message)" -Level "ERROR"
                    $ruleResult.Error = $_.Exception.Message
                }
            }
            
            $script:PolicyResults.AntiPhishing += $ruleResult
        }
        
        # Add compliance result
        $successCount = ($script:PolicyResults.AntiPhishing | Where-Object { $_.Success }).Count
        $totalPolicies = $script:PolicyResults.AntiPhishing.Count
        
        if ($totalPolicies -gt 0) {
            $complianceScore = [math]::Round(($successCount / $totalPolicies) * 100, 2)
            $script:ComplianceResults += @{
                Category = "Anti-Phishing Protection"
                Status = if ($complianceScore -eq 100) { "Compliant" } elseif ($complianceScore -ge 75) { "Partially Compliant" } else { "Non-Compliant" }
                Score = $complianceScore
                Details = "Successfully configured $successCount of $totalPolicies Anti-Phishing policies"
                Recommendation = if ($complianceScore -lt 100) { "Review and fix failed Anti-Phishing policy configurations" } else { "Anti-Phishing protection is properly configured" }
            }
        }
    }
    catch {
        Write-Log "Error configuring Anti-Phishing policies: $($_.Exception.Message)" -Level "ERROR"
        $script:PolicyResults.AntiPhishing += @{
            PolicyName = "M365BP-AntiPhish-Policy"
            Type = "Anti-Phishing Policy"
            Action = "Error"
            Success = $false
            Error = $_.Exception.Message
        }
        
        $script:ComplianceResults += @{
            Category = "Anti-Phishing Protection"
            Status = "Error"
            Score = 0
            Details = "Failed to configure Anti-Phishing: $($_.Exception.Message)"
            Recommendation = "Review Anti-Phishing configuration requirements and permissions"
        }
    }
}

# Function to apply preset security policies
function Set-PresetSecurityPolicies {
    Write-Log "Applying $PolicyPreset preset security policies..."
    try {
        $result = @{
            PolicyName = "Preset Security Policies"
            Type = "ATP Tenant Settings"
            Action = ""
            Success = $false
            Error = ""
            Configuration = @{}
        }
        
        # Configure ATP settings based on preset
        $atpConfig = @{
            EnableATPForSPOTeamsODB = $true
            EnableSafeDocs = $true
        }
        
        if ($PolicyPreset -eq "Strict") {
            $atpConfig.AllowSafeDocsOpen = $false
            Write-Log "Applying Strict preset: Safe Documents will not allow users to click through protection"
        } else {
            Write-Log "Applying Standard preset: Safe Documents with standard settings"
        }
        
        if ($WhatIf) {
            Write-Log "WHATIF: Would apply $PolicyPreset preset security policies" -Level "WARNING"
            $result.Action = "Would Apply $PolicyPreset"
            $result.Success = $true
        } else {
            try {
                Set-AtpPolicyForO365 @atpConfig
                Write-Log "Applied $PolicyPreset preset policies successfully" -Level "SUCCESS"
                $result.Action = "Applied $PolicyPreset"
                $result.Success = $true
            }
            catch {
                Write-Log "Failed to apply preset policies: $($_.Exception.Message)" -Level "ERROR"
                $result.Error = $_.Exception.Message
            }
        }
        
        $result.Configuration = $atpConfig
        $script:PolicyResults.PresetPolicies += $result
        
        # Add compliance result
        $script:ComplianceResults += @{
            Category = "ATP Preset Security Policies"
            Status = if ($result.Success) { "Compliant" } else { "Non-Compliant" }
            Score = if ($result.Success) { 100 } else { 0 }
            Details = if ($result.Success) { "$PolicyPreset preset policies applied successfully" } else { "Failed to apply preset policies: $($result.Error)" }
            Recommendation = if ($result.Success) { "Consider upgrading to Strict preset for enhanced security" } else { "Review ATP configuration requirements and permissions" }
        }
    }
    catch {
        Write-Log "Error applying preset security policies: $($_.Exception.Message)" -Level "ERROR"
        $script:PolicyResults.PresetPolicies += @{
            PolicyName = "Preset Security Policies"
            Type = "ATP Tenant Settings"
            Action = "Error"
            Success = $false
            Error = $_.Exception.Message
        }
        
        $script:ComplianceResults += @{
            Category = "ATP Preset Security Policies"
            Status = "Error"
            Score = 0
            Details = "Failed to apply preset policies: $($_.Exception.Message)"
            Recommendation = "Review ATP configuration requirements and permissions"
        }
    }
}

# Function to generate comprehensive compliance assessment
function Get-ComplianceAssessment {
    Write-Log "Generating compliance assessment..."
    
    $totalScore = 0
    $maxScore = 0
    $compliantCategories = 0
    $totalCategories = $script:ComplianceResults.Count
    
    foreach ($result in $script:ComplianceResults) {
        $totalScore += $result.Score
        $maxScore += 100
        if ($result.Status -eq "Compliant") {
            $compliantCategories++
        }
    }
    
    $overallScore = if ($maxScore -gt 0) { [math]::Round($totalScore / $maxScore * 100, 2) } else { 0 }
    $compliancePercentage = if ($totalCategories -gt 0) { [math]::Round($compliantCategories / $totalCategories * 100, 2) } else { 0 }
    
    $assessment = @{
        OverallScore = $overallScore
        CompliancePercentage = $compliancePercentage
        CompliantCategories = $compliantCategories
        TotalCategories = $totalCategories
        Status = if ($overallScore -ge 90) { "Excellent" } 
                elseif ($overallScore -ge 75) { "Good" } 
                elseif ($overallScore -ge 60) { "Fair" } 
                else { "Needs Improvement" }
        Categories = $script:ComplianceResults
        Recommendations = $script:Recommendations
    }
    
    return $assessment
}

# Function to generate detailed HTML report
function New-DefenderO365Report {
    param([hashtable]$Assessment, [array]$AuthResults)
    
    Write-Log "Generating comprehensive HTML report..."
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $statusColor = switch ($Assessment.Status) {
        "Excellent" { "#28a745" }
        "Good" { "#17a2b8" }
        "Fair" { "#ffc107" }
        default { "#dc3545" }
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft 365 Defender for Office 365 Baseline Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 30px; text-align: center; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header p { margin: 10px 0 0 0; font-size: 1.1em; opacity: 0.9; }
        .content { padding: 30px; }
        .score-section { background: linear-gradient(135deg, #f8f9fa, #e9ecef); border-radius: 10px; padding: 25px; margin-bottom: 30px; text-align: center; }
        .score-circle { width: 120px; height: 120px; border-radius: 50%; margin: 0 auto 20px; display: flex; align-items: center; justify-content: center; font-size: 2em; font-weight: bold; color: white; background: $statusColor; }
        .score-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .score-item { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .score-item h4 { margin: 0 0 10px 0; color: #0078d4; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; margin-bottom: 20px; }
        .compliance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .compliance-card { background: #f8f9fa; border-left: 4px solid #0078d4; padding: 20px; border-radius: 0 8px 8px 0; }
        .compliance-card.compliant { border-left-color: #28a745; }
        .compliance-card.partial { border-left-color: #ffc107; }
        .compliance-card.non-compliant { border-left-color: #dc3545; }
        .compliance-card.error { border-left-color: #6c757d; }
        .compliance-card h3 { margin: 0 0 10px 0; font-size: 1.2em; }
        .status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.9em; font-weight: bold; color: white; }
        .status-compliant { background-color: #28a745; }
        .status-partial { background-color: #ffc107; }
        .status-non-compliant { background-color: #dc3545; }
        .status-error { background-color: #6c757d; }
        .table-container { overflow-x: auto; margin: 20px 0; }
        .styled-table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .styled-table th { background: #0078d4; color: white; padding: 15px; text-align: left; font-weight: 600; }
        .styled-table td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        .styled-table tbody tr:hover { background-color: #f8f9fa; }
        .success { color: #28a745; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .error { color: #dc3545; font-weight: bold; }
        .recommendations { background: #e7f3ff; border: 1px solid #b3d9ff; border-radius: 8px; padding: 20px; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .recommendations li { margin-bottom: 8px; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #6c757d; border-top: 1px solid #dee2e6; }
        .policy-details { background: white; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin: 10px 0; }
        .policy-details h4 { margin: 0 0 10px 0; color: #0078d4; }
        .config-item { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid #f0f0f0; }
        .config-item:last-child { border-bottom: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Microsoft 365 Defender for Office 365</h1>
            <p>Security Baseline Deployment Report</p>
            <p>Generated on $reportDate</p>
        </div>
        
        <div class="content">
            <div class="score-section">
                <div class="score-circle">$($Assessment.OverallScore)%</div>
                <h2>Overall Security Score: $($Assessment.Status)</h2>
                <div class="score-details">
                    <div class="score-item">
                        <h4>Compliance Percentage</h4>
                        <p>$($Assessment.CompliancePercentage)% ($($Assessment.CompliantCategories)/$($Assessment.TotalCategories) categories)</p>
                    </div>
                    <div class="score-item">
                        <h4>Policy Preset</h4>
                        <p>$PolicyPreset Protection Level</p>
                    </div>
                    <div class="score-item">
                        <h4>Service Accounts</h4>
                        <p>$($ServiceAccounts.Count) accounts excluded</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Compliance Assessment by Category</h2>
                <div class="compliance-grid">
"@
    
    foreach ($category in $Assessment.Categories) {
        $statusClass = switch ($category.Status) {
            "Compliant" { "compliant" }
            "Partially Compliant" { "partial" }
            "Non-Compliant" { "non-compliant" }
            default { "error" }
        }
        
        $statusBadgeClass = switch ($category.Status) {
            "Compliant" { "status-compliant" }
            "Partially Compliant" { "status-partial" }
            "Non-Compliant" { "status-non-compliant" }
            default { "status-error" }
        }
        
        $html += @"
                    <div class="compliance-card $statusClass">
                        <h3>$($category.Category)</h3>
                        <span class="status-badge $statusBadgeClass">$($category.Status)</span>
                        <p><strong>Score:</strong> $($category.Score)%</p>
                        <p><strong>Details:</strong> $($category.Details)</p>
                        <p><strong>Recommendation:</strong> $($category.Recommendation)</p>
                    </div>
"@
    }
    
    $html += @"
                </div>
            </div>
"@
    
    # Add DKIM Results
    if ($script:PolicyResults.DKIM.Count -gt 0) {
        $html += @"
            <div class="section">
                <h2>DKIM Configuration Results</h2>
                <div class="table-container">
                    <table class="styled-table">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Current Status</th>
                                <th>Action Taken</th>
                                <th>Result</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($dkim in $script:PolicyResults.DKIM) {
            $resultClass = if ($dkim.Success) { "success" } else { "error" }
            $html += @"
                            <tr>
                                <td>$($dkim.Domain)</td>
                                <td>$($dkim.CurrentStatus)</td>
                                <td>$($dkim.Action)</td>
                                <td class="$resultClass">$(if ($dkim.Success) { "Success" } else { "Failed" })</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
    }
    
    # Add Email Authentication Results
    if ($AuthResults.Count -gt 0) {
        $html += @"
            <div class="section">
                <h2>Email Authentication (SPF/DMARC) Status</h2>
                <div class="table-container">
                    <table class="styled-table">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>SPF Status</th>
                                <th>DMARC Status</th>
                                <th>DMARC Policy</th>
                            </tr>
                        </thead>
                        <tbody>
"@
        foreach ($auth in $AuthResults) {
            $spfClass = if ($auth.SPFStatus -eq "Configured") { "success" } else { "warning" }
            $dmarcClass = if ($auth.DMARCStatus -eq "Configured") { "success" } else { "warning" }
            $html += @"
                            <tr>
                                <td>$($auth.Domain)</td>
                                <td class="$spfClass">$($auth.SPFStatus)</td>
                                <td class="$dmarcClass">$($auth.DMARCStatus)</td>
                                <td>$($auth.DMARCPolicy)</td>
                            </tr>
"@
        }
        $html += @"
                        </tbody>
                    </table>
                </div>
            </div>
"@
    }
    
    # Add Policy Configuration Details
    $allPolicies = @()
    $allPolicies += $script:PolicyResults.SafeLinks
    $allPolicies += $script:PolicyResults.SafeAttachments
    $allPolicies += $script:PolicyResults.AntiPhishing
    $allPolicies += $script:PolicyResults.PresetPolicies
    
    if ($allPolicies.Count -gt 0) {
        $html += @"
            <div class="section">
                <h2>Policy Configuration Details</h2>
"@
        foreach ($policy in $allPolicies) {
            $resultClass = if ($policy.Success) { "success" } else { "error" }
            $html += @"
                <div class="policy-details">
                    <h4>$($policy.PolicyName) ($($policy.Type))</h4>
                    <div class="config-item">
                        <span><strong>Action:</strong></span>
                        <span class="$resultClass">$($policy.Action)</span>
                    </div>
"@
            if ($policy.Configuration) {
                foreach ($config in $policy.Configuration.GetEnumerator()) {
                    $html += @"
                    <div class="config-item">
                        <span>$($config.Key):</span>
                        <span>$($config.Value)</span>
                    </div>
"@
                }
            }
            if ($policy.Error) {
                $html += @"
                    <div class="config-item">
                        <span><strong>Error:</strong></span>
                        <span class="error">$($policy.Error)</span>
                    </div>
"@
            }
            $html += @"
                </div>
"@
        }
        $html += @"
            </div>
"@
    }
    
    # Add Recommendations
    if ($Assessment.Recommendations.Count -gt 0) {
        $html += @"
            <div class="section">
                <h2>Security Recommendations</h2>
                <div class="recommendations">
                    <ul>
"@
        foreach ($recommendation in $Assessment.Recommendations) {
            $html += "<li>$recommendation</li>"
        }
        $html += @"
                    </ul>
                </div>
            </div>
"@
    }
    
    $html += @"
            <div class="section">
                <h2>Next Steps</h2>
                <div class="recommendations">
                    <ul>
                        <li><strong>Review Non-Compliant Items:</strong> Address any failed configurations or policies marked as non-compliant</li>
                        <li><strong>Monitor Security Events:</strong> Regularly review Defender for Office 365 reports and alerts</li>
                        <li><strong>Update Policies:</strong> Periodically review and update security policies based on organizational changes</li>
                        <li><strong>User Training:</strong> Ensure users are trained on recognizing phishing and malicious attachments</li>
                        <li><strong>Consider Strict Policies:</strong> Evaluate upgrading to Strict preset policies for enhanced security</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>This report was generated by the Microsoft 365 Business Premium Defender for Office 365 Baseline Script</p>
            <p>For support and updates, contact your IT administrator</p>
        </div>
    </div>
</body>
</html>
"@
    
    try {
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Log "HTML report generated: $OutputPath" -Level "SUCCESS"
    }
    catch {
        Write-Log "Failed to generate HTML report: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to disconnect from Exchange Online
function Disconnect-ExchangeOnlineService {
    Write-Log "Disconnecting from Exchange Online..."
    try {
        Disconnect-ExchangeOnline -Confirm:$false
        Write-Log "Disconnected from Exchange Online."
    }
    catch {
        Write-Log "Error disconnecting from Exchange Online: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Main execution
try {
    Write-Log "Starting Defender for Office 365 baseline deployment..."
    Write-Log "Configuration: PolicyPreset=$PolicyPreset, WhatIf=$WhatIf, ServiceAccounts=$($ServiceAccounts.Count)"
    
    # Auto-detect admin email if not provided
    if (-not $AdminEmail) {
        try {
            $currentUser = Get-ConnectionInformation -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($currentUser -and $currentUser.UserPrincipalName) {
                $AdminEmail = $currentUser.UserPrincipalName
                Write-Log "Auto-detected admin email: $AdminEmail"
            }
        }
        catch {
            Write-Log "Could not auto-detect admin email. Some features may be limited." -Level "WARNING"
        }
    }
    
    Test-Prerequisites
    Connect-ExchangeOnlineService
    
    # Execute configuration functions
    Enable-DKIMForAllDomains
    $authResults = Test-EmailAuthentication
    Set-SafeLinksAndAttachments
    Set-AntiPhishingPolicies
    Set-PresetSecurityPolicies
    
    # Generate comprehensive assessment and report
    $assessment = Get-ComplianceAssessment
    New-DefenderO365Report -Assessment $assessment -AuthResults $authResults
    
    # Display summary
    Write-Log "=== DEPLOYMENT SUMMARY ===" -Level "SUCCESS"
    Write-Log "Overall Security Score: $($assessment.OverallScore)% ($($assessment.Status))" -Level "SUCCESS"
    Write-Log "Compliant Categories: $($assessment.CompliantCategories)/$($assessment.TotalCategories)" -Level "SUCCESS"
    Write-Log "Total Recommendations: $($assessment.Recommendations.Count)" -Level "SUCCESS"
    Write-Log "Report Generated: $OutputPath" -Level "SUCCESS"
    
    if ($WhatIf) {
        Write-Log "WhatIf mode: No changes were made to your environment" -Level "WARNING"
    }
    
    Write-Log "Defender for Office 365 baseline deployment completed successfully!" -Level "SUCCESS"
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-ExchangeOnlineService
}
