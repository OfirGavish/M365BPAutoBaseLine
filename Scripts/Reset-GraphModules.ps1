<#
.SYNOPSIS
    Helper script to clean up and reload Microsoft Graph modules properly

.DESCRIPTION
    This script handles the complex module loading issues we've been experiencing
    by completely cleaning up all Graph modules and reinstalling/reimporting them cleanly.
#>

param(
    [switch]$Force
)

Write-Host "=== Microsoft Graph Module Reset Utility ===" -ForegroundColor Cyan

# Step 1: Disconnect from any existing Graph sessions
Write-Host "Disconnecting from any existing Graph sessions..." -ForegroundColor Yellow
try {
    if (Get-MgContext -ErrorAction SilentlyContinue) {
        Disconnect-MgGraph
        Write-Host "✅ Disconnected from Microsoft Graph" -ForegroundColor Green
    }
} catch {
    Write-Host "Note: Graph disconnect issue (normal): $($_.Exception.Message)" -ForegroundColor Gray
}

# Step 2: Remove all loaded Graph modules
Write-Host "Removing all loaded Graph modules..." -ForegroundColor Yellow
$graphModules = Get-Module Microsoft.Graph* -ErrorAction SilentlyContinue
if ($graphModules) {
    Write-Host "Found $($graphModules.Count) loaded Graph modules to remove" -ForegroundColor Yellow
    $graphModules | Remove-Module -Force -ErrorAction SilentlyContinue
    Write-Host "✅ Removed all Graph modules from current session" -ForegroundColor Green
} else {
    Write-Host "No Graph modules currently loaded" -ForegroundColor Gray
}

# Step 3: Check installed versions
Write-Host "Checking installed Graph module versions..." -ForegroundColor Yellow
$installedModules = Get-Module Microsoft.Graph* -ListAvailable | Group-Object Name
foreach ($moduleGroup in $installedModules) {
    $versions = $moduleGroup.Group | Select-Object Version -Unique | Sort-Object Version -Descending
    Write-Host "  $($moduleGroup.Name): $($versions.Count) versions installed" -ForegroundColor Gray
    foreach ($version in $versions) {
        Write-Host "    - $($version.Version)" -ForegroundColor Gray
    }
}

# Step 4: Install/Update required modules
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.DeviceManagement",
    "Microsoft.Graph.Groups"
)

Write-Host "Installing/updating required Graph modules..." -ForegroundColor Yellow
foreach ($module in $requiredModules) {
    try {
        Write-Host "Processing $module..." -ForegroundColor Cyan
        
        if ($Force) {
            # Force reinstall
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Write-Host "✅ Force reinstalled $module" -ForegroundColor Green
        } else {
            # Check if we need to install/update
            $installed = Get-Module -Name $module -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
            if (!$installed) {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "✅ Installed $module" -ForegroundColor Green
            } else {
                Write-Host "✅ $module already installed (v$($installed.Version))" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "❌ Failed to install $module`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Module Reset Complete ===" -ForegroundColor Green
Write-Host "You can now run your deployment scripts." -ForegroundColor Green
Write-Host ""
Write-Host "If you still experience issues, try:" -ForegroundColor Yellow
Write-Host "1. Close this PowerShell session completely" -ForegroundColor Yellow
Write-Host "2. Open a new PowerShell session as Administrator" -ForegroundColor Yellow
Write-Host "3. Run: .\Reset-GraphModules.ps1 -Force" -ForegroundColor Yellow
Write-Host "4. Then run your deployment script" -ForegroundColor Yellow
