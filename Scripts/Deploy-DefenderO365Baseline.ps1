<#
.SYNOPSIS
    Automates deployment of Defender for Office 365 baselines and best practices.

.DESCRIPTION
    This script configures Defender for Office 365 with security best practices including:
    - DKIM enforcement for all domains
    - Safe Links and Safe Attachments
    - Anti-phishing policies
    - Policy presets (Standard/Strict)
    - Service account exclusions

.PARAMETER ServiceAccounts
    Array of service account email addresses to exclude from strict policies

.PARAMETER PolicyPreset
    Choose between "Standard" or "Strict" policy preset (default: Standard)

.EXAMPLE
    .\Deploy-DefenderO365Baseline.ps1 -ServiceAccounts @("service@domain.com") -PolicyPreset "Standard"
#>

param(
    [string[]]$ServiceAccounts = @(),
    [ValidateSet("Standard", "Strict")]
    [string]$PolicyPreset = "Standard"
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
    Write-Log "Enabling DKIM for all accepted domains..."
    try {
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            $domainName = $domain.DomainName
            Write-Log "Processing domain: $domainName"
            
            $dkimConfig = Get-DkimSigningConfig -Identity $domainName -ErrorAction SilentlyContinue
            if ($dkimConfig) {
                if (!$dkimConfig.Enabled) {
                    Set-DkimSigningConfig -Identity $domainName -Enabled $true
                    Write-Log "DKIM enabled for $domainName"
                } else {
                    Write-Log "DKIM already enabled for $domainName"
                }
            }
        }
    }
    catch {
        Write-Log "Error enabling DKIM: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to check SPF and DMARC records
function Test-EmailAuthentication {
    Write-Log "Checking SPF and DMARC records for all domains..."
    try {
        $domains = Get-AcceptedDomain
        foreach ($domain in $domains) {
            $domainName = $domain.DomainName
            
            # Check SPF record
            try {
                $spfRecord = Resolve-DnsName -Name $domainName -Type TXT -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Strings -like "v=spf1*" }
                if ($spfRecord) {
                    Write-Log "$domainName - SPF: $($spfRecord.Strings)"
                } else {
                    Write-Log "$domainName - SPF: Not configured" -Level "WARNING"
                }
            }
            catch {
                Write-Log "$domainName - SPF: Unable to resolve" -Level "WARNING"
            }
            
            # Check DMARC record
            try {
                $dmarcRecord = Resolve-DnsName -Name "_dmarc.$domainName" -Type TXT -ErrorAction SilentlyContinue
                if ($dmarcRecord) {
                    Write-Log "$domainName - DMARC: $($dmarcRecord.Strings)"
                } else {
                    Write-Log "$domainName - DMARC: Not configured" -Level "WARNING"
                }
            }
            catch {
                Write-Log "$domainName - DMARC: Unable to resolve" -Level "WARNING"
            }
        }
    }
    catch {
        Write-Log "Error checking email authentication: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure Safe Links and Safe Attachments
function Set-SafeLinksAndAttachments {
    Write-Log "Configuring Safe Links and Safe Attachments..."
    try {
        # Get or create Safe Links policy
        $safeLinksPolicy = Get-SafeLinksPolicy -Identity "M365BP-SafeLinks-Policy" -ErrorAction SilentlyContinue
        if (!$safeLinksPolicy) {
            New-SafeLinksPolicy -Name "M365BP-SafeLinks-Policy" -EnableSafeLinksForTeams $true -ScanUrls $true -EnableForInternalSenders $true
            Write-Log "Created Safe Links policy"
        } else {
            Set-SafeLinksPolicy -Identity "M365BP-SafeLinks-Policy" -EnableSafeLinksForTeams $true -ScanUrls $true -EnableForInternalSenders $true
            Write-Log "Updated Safe Links policy"
        }
        
        # Create Safe Links rule
        $safeLinksRule = Get-SafeLinksRule -Identity "M365BP-SafeLinks-Rule" -ErrorAction SilentlyContinue
        if (!$safeLinksRule) {
            New-SafeLinksRule -Name "M365BP-SafeLinks-Rule" -SafeLinksPolicy "M365BP-SafeLinks-Policy" -RecipientDomainIs (Get-AcceptedDomain).DomainName
            Write-Log "Created Safe Links rule"
        }
        
        # Get or create Safe Attachments policy
        $safeAttachmentsPolicy = Get-SafeAttachmentPolicy -Identity "M365BP-SafeAttachments-Policy" -ErrorAction SilentlyContinue
        if (!$safeAttachmentsPolicy) {
            New-SafeAttachmentPolicy -Name "M365BP-SafeAttachments-Policy" -Enable $true -Action Block -EnableOrganizationBranding $true
            Write-Log "Created Safe Attachments policy"
        } else {
            Set-SafeAttachmentPolicy -Identity "M365BP-SafeAttachments-Policy" -Enable $true -Action Block -EnableOrganizationBranding $true
            Write-Log "Updated Safe Attachments policy"
        }
        
        # Create Safe Attachments rule
        $safeAttachmentsRule = Get-SafeAttachmentRule -Identity "M365BP-SafeAttachments-Rule" -ErrorAction SilentlyContinue
        if (!$safeAttachmentsRule) {
            New-SafeAttachmentRule -Name "M365BP-SafeAttachments-Rule" -SafeAttachmentPolicy "M365BP-SafeAttachments-Policy" -RecipientDomainIs (Get-AcceptedDomain).DomainName
            Write-Log "Created Safe Attachments rule"
        }
    }
    catch {
        Write-Log "Error configuring Safe Links and Attachments: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to configure Anti-Phishing policies
function Set-AntiPhishingPolicies {
    Write-Log "Configuring Anti-Phishing policies..."
    try {
        # Get or create Anti-Phishing policy
        $antiPhishPolicy = Get-AntiPhishPolicy -Identity "M365BP-AntiPhish-Policy" -ErrorAction SilentlyContinue
        if (!$antiPhishPolicy) {
            New-AntiPhishPolicy -Name "M365BP-AntiPhish-Policy" -EnableTargetedUserProtection $true -EnableTargetedDomainsProtection $true -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true -EnableSpoofIntelligence $true
            Write-Log "Created Anti-Phishing policy"
        } else {
            Set-AntiPhishPolicy -Identity "M365BP-AntiPhish-Policy" -EnableTargetedUserProtection $true -EnableTargetedDomainsProtection $true -EnableMailboxIntelligence $true -EnableMailboxIntelligenceProtection $true -EnableSpoofIntelligence $true
            Write-Log "Updated Anti-Phishing policy"
        }
        
        # Create Anti-Phishing rule
        $antiPhishRule = Get-AntiPhishRule -Identity "M365BP-AntiPhish-Rule" -ErrorAction SilentlyContinue
        if (!$antiPhishRule) {
            New-AntiPhishRule -Name "M365BP-AntiPhish-Rule" -AntiPhishPolicy "M365BP-AntiPhish-Policy" -RecipientDomainIs (Get-AcceptedDomain).DomainName -ExceptIfSentTo $ServiceAccounts
            Write-Log "Created Anti-Phishing rule"
        }
    }
    catch {
        Write-Log "Error configuring Anti-Phishing policies: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Function to apply preset security policies
function Set-PresetSecurityPolicies {
    Write-Log "Applying $PolicyPreset preset security policies..."
    try {
        # Enable preset security policies
        if ($PolicyPreset -eq "Standard") {
            Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true
            Write-Log "Applied Standard preset policies"
        } elseif ($PolicyPreset -eq "Strict") {
            Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -AllowSafeDocsOpen $false
            Write-Log "Applied Strict preset policies"
        }
    }
    catch {
        Write-Log "Error applying preset security policies: $($_.Exception.Message)" -Level "ERROR"
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
    
    Test-Prerequisites
    Connect-ExchangeOnlineService
    
    Enable-DKIMForAllDomains
    Test-EmailAuthentication
    Set-SafeLinksAndAttachments
    Set-AntiPhishingPolicies
    Set-PresetSecurityPolicies
    
    Write-Log "Defender for Office 365 baseline deployment completed successfully!"
}
catch {
    Write-Log "Script execution failed: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
finally {
    Disconnect-ExchangeOnlineService
}
