<#
.SYNOPSIS
    Policy Conflict Detection and Resolution for M365 Business Premium Automation

.DESCRIPTION
    This script detects and resolves conflicts between different security baseline components
    that may create overlapping or conflicting policies in Microsoft Intune.
    
    Components that may have conflicts:
    - DefenderBusiness (MDEAutomator): Creates ASR rules, compliance policies, endpoint protection
    - Intune (OpenIntuneBaseline): Creates comprehensive device security baselines including ASR
    - EntraID: May create some device-related conditional access policies
    
.NOTES
    This is a utility script to prevent policy conflicts during deployment.
#>

param(
    [Parameter(Mandatory=$true)]
    [string[]]$ComponentsToCheck,
    
    [switch]$ResolveConflicts,
    [switch]$ReportOnly
)

# Define policy mappings and potential conflicts
$PolicyConflicts = @{
    "ASR_Rules" = @{
        DefenderBusiness = @{
            PolicyName = "M365BP-Attack-Surface-Reduction"
            ConfigurationType = "DeviceConfiguration"
            Scope = "EndpointProtection"
        }
        Intune = @{
            PolicyName = "*OIB*Attack Surface Reduction*"
            ConfigurationType = "SettingsCatalog"
            Scope = "DeviceConfiguration"
        }
        ConflictLevel = "HIGH"
        Resolution = "Keep DefenderBusiness ASR rules (MDEAutomator optimized), disable OpenIntuneBaseline ASR"
        PreferredSource = "DefenderBusiness"
    }
    
    "Device_Compliance" = @{
        DefenderBusiness = @{
            PolicyName = "M365BP-Windows-Compliance"
            ConfigurationType = "DeviceCompliancePolicy"
            Scope = "Compliance"
        }
        Intune = @{
            PolicyName = "*OIB*Compliance*"
            ConfigurationType = "DeviceCompliancePolicy" 
            Scope = "Compliance"
        }
        ConflictLevel = "HIGH"
        Resolution = "Combine both: Use OpenIntuneBaseline base compliance + DefenderBusiness security enhancements"
        PreferredSource = "Combined"
    }
    
    "Tamper_Protection" = @{
        DefenderBusiness = @{
            PolicyName = "M365BP-Tamper-Protection"
            ConfigurationType = "DeviceConfiguration"
            Scope = "EndpointProtection"
        }
        Intune = @{
            PolicyName = "*OIB*Tamper Protection*"
            ConfigurationType = "SettingsCatalog"
            Scope = "DeviceConfiguration"
        }
        ConflictLevel = "MEDIUM"
        Resolution = "Keep DefenderBusiness tamper protection (MDEAutomator optimized), disable OpenIntuneBaseline tamper protection"
        PreferredSource = "DefenderBusiness"
    }
    
    "Endpoint_Protection" = @{
        DefenderBusiness = @{
            PolicyName = "M365BP-Automated-Investigation"
            ConfigurationType = "DeviceConfiguration"
            Scope = "EndpointProtection"
        }
        Intune = @{
            PolicyName = "*OIB*Endpoint Protection*"
            ConfigurationType = "SettingsCatalog"
            Scope = "DeviceConfiguration"
        }
        ConflictLevel = "MEDIUM"
        Resolution = "Use both but ensure no overlapping settings"
    }
}

function Write-ConflictLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [CONFLICT-CHECK] [$Level] $Message"
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "CONFLICT" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Test-PolicyConflicts {
    param([string[]]$Components)
    
    Write-ConflictLog "Checking for policy conflicts between components: $($Components -join ', ')"
    
    $conflicts = @()
    
    foreach ($conflictArea in $PolicyConflicts.Keys) {
        $conflictDef = $PolicyConflicts[$conflictArea]
        
        # Check if multiple components are trying to configure the same thing
        $activeComponents = @()
        foreach ($component in $Components) {
            if ($conflictDef.ContainsKey($component)) {
                $activeComponents += $component
            }
        }
        
        if ($activeComponents.Count -gt 1) {
            $conflicts += @{
                Area = $conflictArea
                Components = $activeComponents
                Level = $conflictDef.ConflictLevel
                Resolution = $conflictDef.Resolution
                Details = $conflictDef
            }
            
            Write-ConflictLog "CONFLICT DETECTED: $conflictArea - Components: $($activeComponents -join ', ') - Level: $($conflictDef.ConflictLevel)" -Level "CONFLICT"
        }
    }
    
    return $conflicts
}

function Resolve-PolicyConflicts {
    param([array]$Conflicts)
    
    Write-ConflictLog "Resolving $($Conflicts.Count) policy conflicts with user preferences..."
    
    $resolutionPlan = @{
        DefenderBusiness = @{
            DisableASR = $false
            DisableCompliance = $false  
            DisableTamperProtection = $false
            DisableEndpointProtection = $false
            ModifyCompliance = $false  # New: modify instead of disable
        }
        Intune = @{
            EnableComprehensiveBaseline = $true
            ExcludePolicies = @()
            ModifyCompliance = $false  # New: modify instead of disable
        }
    }
    
    foreach ($conflict in $Conflicts) {
        Write-ConflictLog "Resolving conflict: $($conflict.Area)"
        $preferredSource = $conflict.Details.PreferredSource
        
        switch ($conflict.Area) {
            "ASR_Rules" {
                if ($preferredSource -eq "DefenderBusiness") {
                    Write-ConflictLog "Resolution: Keep DefenderBusiness ASR rules (MDEAutomator optimized), exclude ASR from OpenIntuneBaseline"
                    $resolutionPlan.Intune.ExcludePolicies += "ASR"
                    $resolutionPlan.DefenderBusiness.DisableASR = $false
                } else {
                    Write-ConflictLog "Resolution: Keep OpenIntuneBaseline ASR rules, disable DefenderBusiness ASR"
                    $resolutionPlan.DefenderBusiness.DisableASR = $true
                }
            }
            
            "Device_Compliance" {
                if ($preferredSource -eq "Combined") {
                    Write-ConflictLog "Resolution: Combine both compliance policies - OpenIntuneBaseline base + DefenderBusiness enhancements"
                    $resolutionPlan.DefenderBusiness.ModifyCompliance = $true
                    $resolutionPlan.Intune.ModifyCompliance = $true
                    # Both will deploy but with coordination
                } else {
                    Write-ConflictLog "Resolution: Using single compliance source: $preferredSource"
                    if ($preferredSource -eq "DefenderBusiness") {
                        $resolutionPlan.Intune.ExcludePolicies += "Compliance"
                    } else {
                        $resolutionPlan.DefenderBusiness.DisableCompliance = $true
                    }
                }
            }
            
            "Tamper_Protection" {
                if ($preferredSource -eq "DefenderBusiness") {
                    Write-ConflictLog "Resolution: Keep DefenderBusiness tamper protection (MDEAutomator optimized), exclude from OpenIntuneBaseline"
                    $resolutionPlan.Intune.ExcludePolicies += "TamperProtection"
                    $resolutionPlan.DefenderBusiness.DisableTamperProtection = $false
                } else {
                    Write-ConflictLog "Resolution: Keep OpenIntuneBaseline tamper protection, disable DefenderBusiness tamper protection"
                    $resolutionPlan.DefenderBusiness.DisableTamperProtection = $true
                }
            }
            
            "Endpoint_Protection" {
                Write-ConflictLog "Resolution: Using both with careful coordination" -Level "WARNING"
                # Both can coexist with different settings
            }
        }
    }
    
    return $resolutionPlan
}

function Export-ConflictResolutionConfig {
    param([object]$ResolutionPlan)
    
    $configPath = "M365BP-ConflictResolution-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    
    $config = @{
        Timestamp = Get-Date
        ResolutionPlan = $ResolutionPlan
        Instructions = @{
            DefenderBusiness = "Apply these flags to Deploy-DefenderBusinessBaseline-Enhanced.ps1"
            Intune = "Apply these settings to Deploy-IntuneBaseline.ps1"
        }
    }
    
    $config | ConvertTo-Json -Depth 5 | Out-File $configPath
    Write-ConflictLog "Conflict resolution configuration saved to: $configPath" -Level "SUCCESS"
    
    return $configPath
}

# Main execution
Write-ConflictLog "Policy Conflict Detection and Resolution Tool" -Level "SUCCESS"
Write-ConflictLog "Checking components: $($ComponentsToCheck -join ', ')"

# Detect conflicts
$detectedConflicts = Test-PolicyConflicts -Components $ComponentsToCheck

if ($detectedConflicts.Count -eq 0) {
    Write-ConflictLog "No policy conflicts detected between selected components" -Level "SUCCESS"
} else {
    Write-ConflictLog "Found $($detectedConflicts.Count) policy conflicts that need resolution" -Level "WARNING"
    
    foreach ($conflict in $detectedConflicts) {
        Write-ConflictLog ""
        Write-ConflictLog "CONFLICT: $($conflict.Area)" -Level "CONFLICT"
        Write-ConflictLog "  Components: $($conflict.Components -join ', ')" -Level "CONFLICT"
        Write-ConflictLog "  Severity: $($conflict.Level)" -Level "CONFLICT" 
        Write-ConflictLog "  Recommended Resolution: $($conflict.Resolution)" -Level "CONFLICT"
    }
    
    if ($ResolveConflicts) {
        Write-ConflictLog ""
        Write-ConflictLog "Generating conflict resolution plan..." -Level "SUCCESS"
        
        $resolutionPlan = Resolve-PolicyConflicts -Conflicts $detectedConflicts
        $configFile = Export-ConflictResolutionConfig -ResolutionPlan $resolutionPlan
        
        Write-ConflictLog ""
        Write-ConflictLog "CONFLICT RESOLUTION SUMMARY:" -Level "SUCCESS"
        Write-ConflictLog "DefenderBusiness modifications needed:" -Level "SUCCESS"
        if ($resolutionPlan.DefenderBusiness.DisableASR) { 
            Write-ConflictLog "  - Disable ASR rule creation" -Level "SUCCESS" 
        } else {
            Write-ConflictLog "  - Keep ASR rules (MDEAutomator optimized)" -Level "SUCCESS"
        }
        if ($resolutionPlan.DefenderBusiness.DisableCompliance) { 
            Write-ConflictLog "  - Disable compliance policy creation" -Level "SUCCESS" 
        } elseif ($resolutionPlan.DefenderBusiness.ModifyCompliance) {
            Write-ConflictLog "  - Modify compliance policies for coordination with OpenIntuneBaseline" -Level "SUCCESS"
        } else {
            Write-ConflictLog "  - Keep compliance policies" -Level "SUCCESS"
        }
        if ($resolutionPlan.DefenderBusiness.DisableTamperProtection) { 
            Write-ConflictLog "  - Disable tamper protection policy creation" -Level "SUCCESS" 
        } else {
            Write-ConflictLog "  - Keep tamper protection (MDEAutomator optimized)" -Level "SUCCESS"
        }
        
        Write-ConflictLog "Intune (OpenIntuneBaseline) modifications:" -Level "SUCCESS"
        if ($resolutionPlan.Intune.ExcludePolicies.Count -gt 0) {
            Write-ConflictLog "  - Exclude conflicting policies: $($resolutionPlan.Intune.ExcludePolicies -join ', ')" -Level "SUCCESS"
        }
        if ($resolutionPlan.Intune.ModifyCompliance) {
            Write-ConflictLog "  - Modify compliance policies for coordination with DefenderBusiness" -Level "SUCCESS"
        }
        Write-ConflictLog "  - Deploy comprehensive baseline (with exclusions)" -Level "SUCCESS"
        
        Write-ConflictLog ""
        Write-ConflictLog "Next steps:" -Level "SUCCESS"
        Write-ConflictLog "1. Review the generated config file: $configFile"
        Write-ConflictLog "2. Update deployment scripts with the recommended flags"
        Write-ConflictLog "3. Deploy components in this order: Intune first, then DefenderBusiness"
    }
}
