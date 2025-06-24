<#
.SYNOPSIS
    Enables Conditional Access policies that were deployed in report-only mode.

.DESCRIPTION
    This script helps safely enable Conditional Access policies that were initially
    deployed in report-only mode. It provides options to enable policies individually
    or in groups, with safety checks and validation.

.PARAMETER PolicyNames
    Array of policy names to enable. If not specified, shows all report-only policies.

.PARAMETER AllPolicies
    Switch to enable all M365BP policies that are currently in report-only mode.

.PARAMETER WhatIf
    Shows what policies would be enabled without actually changing them.

.EXAMPLE
    .\Enable-ConditionalAccessPolicies.ps1 -WhatIf
    Shows all policies that would be enabled

.EXAMPLE
    .\Enable-ConditionalAccessPolicies.ps1 -PolicyNames @("M365BP-Admin-Require-Compliant-Device")
    Enables only the admin device compliance policy

.EXAMPLE
    .\Enable-ConditionalAccessPolicies.ps1 -AllPolicies
    Enables all M365BP policies currently in report-only mode
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$PolicyNames = @(),
    
    [Parameter(Mandatory = $false)]
    [switch]$AllPolicies,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Import required modules
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns"
)

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Warning "Required module '$module' not found. Please install it first."
        exit 1
    }
    Import-Module $module -Force
}

# Function to log messages
function Write-Log {
    param(
        [string]$Message, 
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Connect to Microsoft Graph
try {
    Write-Log "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess" -NoWelcome
    Write-Log "Successfully connected to Microsoft Graph" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

try {
    # Get all M365BP policies in report-only mode
    $reportOnlyPolicies = Get-MgIdentityConditionalAccessPolicy | Where-Object {
        $_.DisplayName -like "M365BP-*" -and $_.State -eq "enabledForReportingButNotEnforced"
    }
    
    if ($reportOnlyPolicies.Count -eq 0) {
        Write-Log "No M365BP policies found in report-only mode." -Level "WARNING"
        return
    }
    
    Write-Log "Found $($reportOnlyPolicies.Count) M365BP policies in report-only mode:"
    foreach ($policy in $reportOnlyPolicies) {
        Write-Log "  - $($policy.DisplayName)"
    }
    
    # Determine which policies to enable
    $policiesToEnable = @()
    
    if ($AllPolicies) {
        $policiesToEnable = $reportOnlyPolicies
        Write-Log "All M365BP policies will be enabled."
    }
    elseif ($PolicyNames.Count -gt 0) {
        foreach ($policyName in $PolicyNames) {
            $policy = $reportOnlyPolicies | Where-Object { $_.DisplayName -eq $policyName }
            if ($policy) {
                $policiesToEnable += $policy
            }
            else {
                Write-Log "Policy '$policyName' not found or not in report-only mode." -Level "WARNING"
            }
        }
    }
    else {
        Write-Log "No policies specified to enable. Use -AllPolicies or -PolicyNames parameter."
        Write-Log "Available policies in report-only mode:"
        foreach ($policy in $reportOnlyPolicies) {
            Write-Log "  - $($policy.DisplayName)"
        }
        return
    }
    
    # Safety warning for admin policies
    $adminPolicies = $policiesToEnable | Where-Object { $_.DisplayName -like "*Admin*" }
    if ($adminPolicies.Count -gt 0) {
        Write-Log "WARNING: You are about to enable admin-related policies!" -Level "WARNING"
        Write-Log "Make sure you have:" -Level "WARNING"
        Write-Log "  1. A compliant device for your admin account" -Level "WARNING"
        Write-Log "  2. MFA properly configured" -Level "WARNING"
        Write-Log "  3. A break-glass account available" -Level "WARNING"
        
        if (!$WhatIf) {
            $confirmation = Read-Host "Are you sure you want to proceed? (yes/no)"
            if ($confirmation -ne "yes") {
                Write-Log "Operation cancelled by user." -Level "WARNING"
                return
            }
        }
    }
    
    # Enable policies
    foreach ($policy in $policiesToEnable) {
        try {
            if ($WhatIf) {
                Write-Log "WHATIF: Would enable policy '$($policy.DisplayName)'"
            }
            else {
                Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -State "enabled"
                Write-Log "Enabled policy: $($policy.DisplayName)" -Level "SUCCESS"
            }
        }
        catch {
            Write-Log "Failed to enable policy '$($policy.DisplayName)': $($_.Exception.Message)" -Level "ERROR"
        }
    }
    
    if (!$WhatIf) {
        Write-Log "Policy enablement completed!" -Level "SUCCESS"
        Write-Log "Monitor the policies in the Azure portal to ensure they work as expected."
    }
}
catch {
    Write-Log "Error during policy enablement: $($_.Exception.Message)" -Level "ERROR"
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph
        Write-Log "Disconnected from Microsoft Graph"
    }
    catch {
        # Ignore disconnect errors
    }
}
