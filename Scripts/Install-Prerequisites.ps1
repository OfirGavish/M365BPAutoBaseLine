#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install all required PowerShell modules for M365BP AutoBaseline deployment.

.DESCRIPTION
    This script installs all necessary PowerShell modules and verifies permissions
    required for deploying the M365 Business Premium security baselines.

.NOTES
    Run this script as Administrator to ensure proper module installation.
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$CheckOnly
)

# Required modules for the deployment
$requiredModules = @(
    @{ Name = "ExchangeOnlineManagement"; MinVersion = "3.0.0"; Purpose = "Defender for Office 365 and Exchange configuration" },
    @{ Name = "Microsoft.Graph"; MinVersion = "2.0.0"; Purpose = "Core Microsoft Graph API access" },
    @{ Name = "Microsoft.Graph.Authentication"; MinVersion = "2.0.0"; Purpose = "Graph authentication" },
    @{ Name = "Microsoft.Graph.DeviceManagement"; MinVersion = "2.0.0"; Purpose = "Intune device management" },
    @{ Name = "Microsoft.Graph.Identity.SignIns"; MinVersion = "2.0.0"; Purpose = "Conditional Access policies" },
    @{ Name = "Microsoft.Graph.Groups"; MinVersion = "2.0.0"; Purpose = "Azure AD group management" },
    @{ Name = "PnP.PowerShell"; MinVersion = "1.12.0"; Purpose = "SharePoint and Teams configuration" },
    @{ Name = "Maester"; MinVersion = "0.5.0"; Purpose = "Security validation and testing" },
    @{ Name = "Pester"; MinVersion = "5.0.0"; Purpose = "PowerShell testing framework" }
)

# Optional but recommended modules
$optionalModules = @(
    @{ Name = "IntuneManagement"; Purpose = "Enhanced Intune policy management (for OpenIntuneBaseline)" }
)

function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    Write-Host "[$Status] $Message" -ForegroundColor $color
}

function Test-ModuleInstallation {
    param([array]$Modules, [string]$Type = "Required")
    
    Write-Status "Checking $Type modules..." "INFO"
    $results = @()
    
    foreach ($module in $Modules) {
        $installed = Get-Module -ListAvailable -Name $module.Name | Sort-Object Version -Descending | Select-Object -First 1
        
        if ($installed) {
            if ($module.MinVersion -and $installed.Version -lt [version]$module.MinVersion) {
                $status = "OUTDATED"
                $message = "$($module.Name) v$($installed.Version) (requires v$($module.MinVersion))"
            } else {
                $status = "OK"
                $message = "$($module.Name) v$($installed.Version)"
            }
        } else {
            $status = "MISSING"
            $message = "$($module.Name) - Not installed"
        }
        
        $results += @{
            Name = $module.Name
            Status = $status
            Message = $message
            Purpose = $module.Purpose
            MinVersion = $module.MinVersion
            InstalledVersion = $installed.Version
        }
        
        $statusColor = switch ($status) {
            "OK" { "SUCCESS" }
            "OUTDATED" { "WARNING" }
            "MISSING" { "ERROR" }
        }
        Write-Status $message $statusColor
    }
    
    return $results
}

function Install-RequiredModules {
    param([array]$ModuleResults)
    
    $toInstall = $ModuleResults | Where-Object { $_.Status -in @("MISSING", "OUTDATED") }
    
    if ($toInstall.Count -eq 0) {
        Write-Status "All required modules are up to date!" "SUCCESS"
        return
    }
    
    Write-Status "Installing/updating $($toInstall.Count) modules..." "INFO"
    
    foreach ($module in $toInstall) {
        try {
            Write-Status "Installing $($module.Name)..." "INFO"
            
            $installParams = @{
                Name = $module.Name
                Scope = "CurrentUser"
                Force = $Force
                AllowClobber = $true
                ErrorAction = "Stop"
            }
            
            if ($module.MinVersion) {
                $installParams.MinimumVersion = $module.MinVersion
            }
            
            Install-Module @installParams -ErrorAction Stop
            Write-Status "Successfully installed $($module.Name)" "SUCCESS"
            
        } catch {
            Write-Status "Failed to install $($module.Name): $($_.Exception.Message)" "ERROR"
            Write-Status "Continuing with remaining modules..." "INFO"
            continue
        }
    }
}

function Test-AdminPermissions {
    Write-Status "Checking administrative requirements..." "INFO"
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if ($isAdmin) {
        Write-Status "Running with Administrator privileges ✓" "SUCCESS"
    } else {
        Write-Status "NOT running with Administrator privileges - some modules may fail to install" "WARNING"
    }
    
    # Check execution policy
    $executionPolicy = Get-ExecutionPolicy
    if ($executionPolicy -in @("Restricted", "AllSigned")) {
        Write-Status "Execution Policy: $executionPolicy - may prevent script execution" "WARNING"
        Write-Status "Consider running: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" "INFO"
    } else {
        Write-Status "Execution Policy: $executionPolicy ✓" "SUCCESS"
    }
}

# Main execution
Write-Status "M365 Business Premium AutoBaseline - Prerequisites Check" "INFO"
Write-Status "================================================================" "INFO"

# Check admin permissions
Test-AdminPermissions

# Check required modules
$requiredResults = Test-ModuleInstallation -Modules $requiredModules -Type "Required"

# Check optional modules
Write-Status "`nChecking optional modules..." "INFO"
$optionalResults = Test-ModuleInstallation -Modules $optionalModules -Type "Optional"

# Summary
Write-Status "`n================================================================" "INFO"
$missingRequired = ($requiredResults | Where-Object { $_.Status -eq "MISSING" }).Count
$outdatedRequired = ($requiredResults | Where-Object { $_.Status -eq "OUTDATED" }).Count
$okRequired = ($requiredResults | Where-Object { $_.Status -eq "OK" }).Count

Write-Status "Required Modules Summary:" "INFO"
Write-Status "  ✓ Up to date: $okRequired" "SUCCESS"
if ($outdatedRequired -gt 0) { Write-Status "  ⚠ Outdated: $outdatedRequired" "WARNING" }
if ($missingRequired -gt 0) { Write-Status "  ✗ Missing: $missingRequired" "ERROR" }

if ($CheckOnly) {
    Write-Status "`nCheck-only mode complete. Use -Force to install missing modules." "INFO"
    return
}

# Install missing/outdated modules
if ($missingRequired -gt 0 -or $outdatedRequired -gt 0) {
    Write-Status "`nInstalling missing and outdated modules..." "INFO"
    Install-RequiredModules -ModuleResults $requiredResults
    
    # Offer to install optional modules
    $missingOptional = ($optionalResults | Where-Object { $_.Status -eq "MISSING" }).Count
    if ($missingOptional -gt 0) {
        $response = Read-Host "`nInstall optional modules? (y/N)"
        if ($response -eq "y" -or $response -eq "Y") {
            Install-RequiredModules -ModuleResults $optionalResults
        }
    }
} else {
    Write-Status "`nAll required modules are already installed and up to date!" "SUCCESS"
}

Write-Status "`n================================================================" "INFO"
Write-Status "Prerequisites check complete!" "SUCCESS"
Write-Status "Next steps:" "INFO"
Write-Status "1. Ensure you have Global Administrator or Security Administrator role" "INFO"
Write-Status "2. Review and customize Config\M365BP-Config-Template.yaml" "INFO"
Write-Status "3. Run Deploy-M365BPBaseline.ps1 with -WhatIf first to preview changes" "INFO"
