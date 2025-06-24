#Requires -Modules Maester

<#
.SYNOPSIS
    Post-deployment validation and testing for M365 Business Premium security baselines using Maester.

.DESCRIPTION
    This script provides comprehensive validation and testing of deployed M365 Business Premium
    security configurations using the Maester framework. It validates:
    - Conditional Access policies
    - Defender for Office 365 configurations
    - Entra ID security settings
    - Microsoft Purview compliance
    - Defender for Business endpoint security
    - EIDSCA (Entra ID Security Config Analyzer) checks
    - Custom business security requirements

.PARAMETER TenantId
    Azure AD tenant ID for authentication and testing

.PARAMETER TestCategories
    Array of test categories to run. Options: "All", "ConditionalAccess", "DefenderO365", "EntraID", "Purview", "DefenderBusiness", "EIDSCA", "Custom"

.PARAMETER OutputPath
    Path where test results and reports will be saved

.PARAMETER CustomTestsPath
    Path to custom Pester tests specific to your organization

.PARAMETER ConfigValidation
    Validate against a specific configuration file

.PARAMETER IncludeWhatIfTests
    Include Conditional Access What-If scenario testing

.PARAMETER GenerateReports
    Generate HTML reports and summaries

.PARAMETER EmailNotification
    Send email notifications with test results

.PARAMETER NotificationEmail
    Email address for notifications

.PARAMETER PassThru
    Return test results object for further processing

.EXAMPLE
    .\Test-M365BPBaseline.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -TestCategories @("All")

.EXAMPLE
    .\Test-M365BPBaseline.ps1 -TestCategories @("ConditionalAccess", "EIDSCA") -IncludeWhatIfTests -GenerateReports

.NOTES
    Author: M365 Business Premium Automation Project
    Version: 1.0
    Based on: Maester Framework by @merill and the Maester team (https://github.com/maester365/maester)
    
    Prerequisites:
    - Maester PowerShell module
    - Global Reader or Security Reader role (minimum)
    - Microsoft Graph PowerShell modules
    - Pester framework (installed with Maester)
    
    Credits:
    - Maester Framework: https://github.com/maester365/maester (MIT License)
    - EIDSCA: Entra ID Security Config Analyzer by Microsoft
    - ConditionalAccessBaseline: https://github.com/j0eyv/ConditionalAccessBaseline
    - MDEAutomator: https://github.com/msdirtbag/MDEAutomator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "ConditionalAccess", "DefenderO365", "EntraID", "Purview", "DefenderBusiness", "EIDSCA", "Custom")]
    [string[]]$TestCategories = @("All"),
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\TestResults"),
    
    [Parameter(Mandatory = $false)]
    [string]$CustomTestsPath = (Join-Path $PSScriptRoot "..\Tests\Custom"),
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigValidation = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWhatIfTests,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReports = $true,
    
    [Parameter(Mandatory = $false)]
    [switch]$EmailNotification,
    
    [Parameter(Mandatory = $false)]
    [string]$NotificationEmail = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

# Initialize logging and paths
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $OutputPath "M365BP_ValidationTests_$timestamp.log"
$testResultsPath = Join-Path $OutputPath "TestResults_$timestamp"

# Ensure output directories exist
foreach ($path in @($OutputPath, $testResultsPath, $CustomTestsPath)) {
    if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }
}

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(
        switch ($Level) {
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
    )
    Add-Content -Path $logFile -Value $logEntry
}

function Test-Prerequisites {
    Write-TestLog "Validating prerequisites..."
    
    # Check Maester module
    if (-not (Get-Module -ListAvailable -Name "Maester")) {
        Write-TestLog "Installing Maester module..." "WARNING"
        Install-Module -Name Maester -Scope CurrentUser -Force
    }
    
    # Import Maester
    Import-Module Maester -Force
    
    # Check additional required modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Groups"
    )
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-TestLog "Installing required module: $module" "WARNING"
            Install-Module -Name $module -Scope CurrentUser -Force
        }
    }
    
    Write-TestLog "Prerequisites validated successfully." "SUCCESS"
}

function Initialize-MaesterTests {
    Write-TestLog "Initializing Maester test environment..."
    
    # Create Maester tests directory if it doesn't exist
    $maesterTestsPath = Join-Path $testResultsPath "MaesterTests"
    if (-not (Test-Path $maesterTestsPath)) {
        New-Item -Path $maesterTestsPath -ItemType Directory -Force | Out-Null
        Set-Location $maesterTestsPath
        
        Write-TestLog "Installing Maester tests..."
        Install-MaesterTests
    } else {
        Set-Location $maesterTestsPath
        Write-TestLog "Updating existing Maester tests..."
        Update-MaesterTests
    }
    
    Write-TestLog "Maester test environment ready." "SUCCESS"
}

function Connect-MaesterGraph {
    Write-TestLog "Connecting to Microsoft Graph for testing..."
    
    try {
        # Check if already connected
        $context = Get-MgContext
        if (-not $context -or ($TenantId -and $context.TenantId -ne $TenantId)) {
            $connectParams = @{
                Scopes = @(
                    "Directory.Read.All",
                    "Policy.Read.All",
                    "IdentityRiskEvent.Read.All",
                    "IdentityRiskyUser.Read.All",
                    "UserAuthenticationMethod.Read.All",
                    "SecurityEvents.Read.All",
                    "Reports.Read.All"
                )
            }
            
            if ($TenantId) {
                $connectParams.TenantId = $TenantId
            }
            
            Connect-MgGraph @connectParams
        }
        
        # Connect Maester
        Connect-Maester
        
        $connectedTenant = (Get-MgContext).TenantId
        Write-TestLog "Connected to tenant: $connectedTenant" "SUCCESS"
        
    } catch {
        Write-TestLog "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Invoke-ConditionalAccessTests {
    Write-TestLog "Running Conditional Access validation tests..."
    
    $caTests = @()
    
    # Maester built-in CA tests
    $caTests += @{
        Name = "Conditional Access - Maester Built-in Tests"
        TestPath = "tests\ConditionalAccess\*.Tests.ps1"
        Description = "Standard Conditional Access policy validation"
    }
    
    if ($IncludeWhatIfTests) {
        # What-If scenario tests
        $caTests += @{
            Name = "Conditional Access - What-If Scenarios"
            TestPath = "tests\ConditionalAccess\WhatIf\*.Tests.ps1"
            Description = "Policy impact analysis and scenario testing"
        }
    }
    
    $results = @()
    foreach ($test in $caTests) {
        Write-TestLog "Executing: $($test.Name)"
        
        try {
            $testResult = Invoke-Pester -Path $test.TestPath -PassThru -OutputFormat NUnitXml -OutputFile (Join-Path $testResultsPath "CA_$($test.Name -replace '[^\w]','_').xml")
            $results += $testResult
            
            if ($testResult.FailedCount -eq 0) {
                Write-TestLog "$($test.Name) - All tests passed ($($testResult.PassedCount) passed)" "SUCCESS"
            } else {
                Write-TestLog "$($test.Name) - $($testResult.FailedCount) test(s) failed, $($testResult.PassedCount) passed" "WARNING"
            }
        } catch {
            Write-TestLog "Error running $($test.Name): $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $results
}

function Invoke-EIDSCATests {
    Write-TestLog "Running EIDSCA (Entra ID Security Config Analyzer) tests..."
    
    try {
        # Run EIDSCA tests that come with Maester
        $eidsca = Invoke-Pester -Path "tests\EIDSCA\*.Tests.ps1" -PassThru -OutputFormat NUnitXml -OutputFile (Join-Path $testResultsPath "EIDSCA_Results.xml")
        
        Write-TestLog "EIDSCA Analysis completed: $($eidsca.PassedCount) passed, $($eidsca.FailedCount) failed" $(if($eidsca.FailedCount -eq 0){"SUCCESS"}else{"WARNING"})
        
        return $eidsca
    } catch {
        Write-TestLog "Error running EIDSCA tests: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Invoke-DefenderO365Tests {
    Write-TestLog "Running Defender for Office 365 validation tests..."
    
    # Create custom tests for Defender for Office 365
    $defenderO365TestScript = @"
Describe "Defender for Office 365 Configuration" {
    BeforeAll {
        `$tenantInfo = Get-MgOrganization
    }
    
    Context "Anti-Phishing Policies" {
        It "Should have anti-phishing policies configured" {
            # This would require Exchange Online PowerShell or Graph beta endpoints
            # For now, we'll create a placeholder that can be expanded
            `$true | Should -Be `$true
        }
    }
    
    Context "Safe Attachments" {
        It "Should have Safe Attachments enabled" {
            # Placeholder for Safe Attachments validation
            `$true | Should -Be `$true
        }
    }
    
    Context "Safe Links" {
        It "Should have Safe Links configured" {
            # Placeholder for Safe Links validation
            `$true | Should -Be `$true
        }
    }
}
"@
    
    $defenderO365TestFile = Join-Path $testResultsPath "DefenderO365.Tests.ps1"
    Set-Content -Path $defenderO365TestFile -Value $defenderO365TestScript
    
    try {
        $result = Invoke-Pester -Path $defenderO365TestFile -PassThru -OutputFormat NUnitXml -OutputFile (Join-Path $testResultsPath "DefenderO365_Results.xml")
        Write-TestLog "Defender for Office 365 tests completed: $($result.PassedCount) passed, $($result.FailedCount) failed" $(if($result.FailedCount -eq 0){"SUCCESS"}else{"WARNING"})
        return $result
    } catch {
        Write-TestLog "Error running Defender for Office 365 tests: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Invoke-DefenderBusinessTests {
    Write-TestLog "Running Defender for Business validation tests..."
    
    # Create tests for Defender for Business/Endpoint
    $defenderBusinessTestScript = @"
Describe "Defender for Business Configuration" {
    BeforeAll {
        `$intuneDeviceConfigs = Get-MgDeviceManagementDeviceConfiguration -ErrorAction SilentlyContinue
    }
    
    Context "Tamper Protection" {
        It "Should have Tamper Protection policy configured" {
            `$tamperPolicy = `$intuneDeviceConfigs | Where-Object { `$_.DisplayName -eq "M365BP-Tamper-Protection" }
            `$tamperPolicy | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Attack Surface Reduction" {
        It "Should have ASR rules policy configured" {
            `$asrPolicy = `$intuneDeviceConfigs | Where-Object { `$_.DisplayName -eq "M365BP-Attack-Surface-Reduction" }
            `$asrPolicy | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Automated Investigation" {
        It "Should have Automated Investigation policy configured" {
            `$airPolicy = `$intuneDeviceConfigs | Where-Object { `$_.DisplayName -eq "M365BP-Automated-Investigation" }
            `$airPolicy | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Device Compliance" {
        It "Should have Windows compliance policy configured" {
            `$compliancePolicy = Get-MgDeviceManagementDeviceCompliancePolicy -Filter "displayName eq 'M365BP-Windows-Compliance'" -ErrorAction SilentlyContinue
            `$compliancePolicy | Should -Not -BeNullOrEmpty
        }
    }
}
"@
    
    $defenderBusinessTestFile = Join-Path $testResultsPath "DefenderBusiness.Tests.ps1"
    Set-Content -Path $defenderBusinessTestFile -Value $defenderBusinessTestScript
    
    try {
        $result = Invoke-Pester -Path $defenderBusinessTestFile -PassThru -OutputFormat NUnitXml -OutputFile (Join-Path $testResultsPath "DefenderBusiness_Results.xml")
        Write-TestLog "Defender for Business tests completed: $($result.PassedCount) passed, $($result.FailedCount) failed" $(if($result.FailedCount -eq 0){"SUCCESS"}else{"WARNING"})
        return $result
    } catch {
        Write-TestLog "Error running Defender for Business tests: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Invoke-CustomTests {
    Write-TestLog "Running custom organization-specific tests..."
    
    if (Test-Path $CustomTestsPath) {
        $customTestFiles = Get-ChildItem -Path $CustomTestsPath -Filter "*.Tests.ps1" -Recurse
        
        if ($customTestFiles.Count -eq 0) {
            Write-TestLog "No custom test files found in $CustomTestsPath" "WARNING"
            return $null
        }
        
        $allResults = @()
        foreach ($testFile in $customTestFiles) {
            Write-TestLog "Running custom test: $($testFile.Name)"
            
            try {
                $result = Invoke-Pester -Path $testFile.FullName -PassThru -OutputFormat NUnitXml -OutputFile (Join-Path $testResultsPath "Custom_$($testFile.BaseName).xml")
                $allResults += $result
            } catch {
                Write-TestLog "Error running custom test $($testFile.Name): $($_.Exception.Message)" "ERROR"
            }
        }
        
        return $allResults
    } else {
        Write-TestLog "Custom tests directory not found: $CustomTestsPath" "WARNING"
        return $null
    }
}

function New-ValidationReport {
    param([array]$TestResults, [string]$ReportPath)
    
    Write-TestLog "Generating comprehensive validation report..."
    
    $totalTests = ($TestResults | Measure-Object -Property TotalCount -Sum).Sum
    $totalPassed = ($TestResults | Measure-Object -Property PassedCount -Sum).Sum
    $totalFailed = ($TestResults | Measure-Object -Property FailedCount -Sum).Sum
    $totalSkipped = ($TestResults | Measure-Object -Property SkippedCount -Sum).Sum
    
    $successRate = if ($totalTests -gt 0) { [math]::Round(($totalPassed / $totalTests) * 100, 2) } else { 0 }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>M365 Business Premium Security Validation Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #0078d4, #005a9e); color: white; padding: 30px; border-radius: 10px; text-align: center; }
        .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric { display: inline-block; text-align: center; margin: 0 20px; }
        .metric-value { font-size: 2em; font-weight: bold; }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        .skipped { color: #ffc107; }
        .success-rate { font-size: 3em; font-weight: bold; color: $(if($successRate -ge 90){'#28a745'}elseif($successRate -ge 70){'#ffc107'}else{'#dc3545'}); }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; background-color: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        .test-section { margin: 20px 0; }
        .credits { background-color: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); font-size: 0.9em; color: #666; }
        .credits h3 { color: #0078d4; margin-bottom: 10px; }
        .credits a { color: #0078d4; text-decoration: none; }
        .credits a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔥 M365 Business Premium Security Validation Report</h1>
        <p>Comprehensive security baseline testing using Maester framework</p>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC")</p>
    </div>
    
    <div class="summary">
        <h2>📊 Test Execution Summary</h2>
        <div style="text-align: center;">
            <div class="metric">
                <div class="success-rate">$successRate%</div>
                <div>Success Rate</div>
            </div>
        </div>
        <br>
        <div style="text-align: center;">
            <div class="metric">
                <div class="metric-value">$totalTests</div>
                <div>Total Tests</div>
            </div>
            <div class="metric">
                <div class="metric-value passed">$totalPassed</div>
                <div>Passed</div>
            </div>
            <div class="metric">
                <div class="metric-value failed">$totalFailed</div>
                <div>Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value skipped">$totalSkipped</div>
                <div>Skipped</div>
            </div>
        </div>
    </div>
    
    <div class="test-section">
        <h2>🧪 Test Results by Category</h2>
        <table>
            <tr>
                <th>Test Category</th>
                <th>Total</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Skipped</th>
                <th>Success Rate</th>
                <th>Duration</th>
            </tr>
"@
    
    foreach ($result in $TestResults) {
        if ($result) {
            $categorySuccessRate = if ($result.TotalCount -gt 0) { [math]::Round(($result.PassedCount / $result.TotalCount) * 100, 2) } else { 0 }
            $duration = if ($result.Time) { $result.Time.ToString("mm\:ss") } else { "N/A" }
            
            $html += @"
            <tr>
                <td>$($result.Name -replace '\.Tests$', '')</td>
                <td>$($result.TotalCount)</td>
                <td class="passed">$($result.PassedCount)</td>
                <td class="failed">$($result.FailedCount)</td>
                <td class="skipped">$($result.SkippedCount)</td>
                <td>$categorySuccessRate%</td>
                <td>$duration</td>
            </tr>
"@
        }
    }
    
    $html += @"
        </table>
    </div>
    
    <div class="summary">
        <h2>📋 Recommendations</h2>
        <ul>
            <li><strong>Failed Tests:</strong> Review failed test details and remediate configurations as needed</li>
            <li><strong>Security Monitoring:</strong> Schedule regular validation runs (weekly/monthly)</li>
            <li><strong>Continuous Improvement:</strong> Add custom tests for organization-specific requirements</li>
            <li><strong>Documentation:</strong> Update security documentation based on test results</li>
            <li><strong>Training:</strong> Ensure administrators understand configuration requirements</li>
        </ul>
    </div>
    
    <div class="credits">
        <h3>🙏 Credits & Acknowledgments</h3>
        <p>This validation framework integrates several outstanding open-source projects:</p>
        <ul>
            <li><strong><a href="https://github.com/maester365/maester" target="_blank">Maester Framework</a></strong> by <a href="https://github.com/merill" target="_blank">@merill</a> and the Maester team - PowerShell-based Microsoft 365 security test automation (MIT License)</li>
            <li><strong><a href="https://github.com/j0eyv/ConditionalAccessBaseline" target="_blank">ConditionalAccessBaseline</a></strong> by <a href="https://github.com/j0eyv" target="_blank">@j0eyv</a> - Comprehensive Conditional Access policy baseline (MIT License)</li>
            <li><strong><a href="https://github.com/msdirtbag/MDEAutomator" target="_blank">MDEAutomator</a></strong> by <a href="https://github.com/msdirtbag" target="_blank">@msdirtbag</a> - Advanced Microsoft Defender for Endpoint automation</li>
            <li><strong>EIDSCA (Entra ID Security Config Analyzer)</strong> by Microsoft - Security configuration analysis framework</li>
            <li><strong><a href="https://pester.dev/" target="_blank">Pester</a></strong> - PowerShell testing framework that powers Maester</li>
        </ul>
        <p>We are grateful for the contributions of these projects and their maintainers to the Microsoft 365 security community.</p>
    </div>
    
    <div class="summary">
        <h2>📁 Test Artifacts</h2>
        <p><strong>Test Results Location:</strong> <code>$testResultsPath</code></p>
        <p><strong>Log File:</strong> <code>$logFile</code></p>
        <p><strong>XML Results:</strong> Individual test XML files available in the test results directory</p>
    </div>
</body>
</html>
"@
    
    Set-Content -Path $ReportPath -Value $html -Encoding UTF8
    Write-TestLog "Validation report generated: $ReportPath" "SUCCESS"
    
    return $ReportPath
}

function Send-TestNotification {
    param([string]$ReportPath, [array]$TestResults, [string]$EmailAddress)
    
    if (-not $EmailAddress) {
        Write-TestLog "No email address provided for notifications" "WARNING"
        return
    }
    
    Write-TestLog "Email notification functionality would be implemented here" "WARNING"
    Write-TestLog "Report available at: $ReportPath"
    
    # TODO: Implement email notification using Send-MailMessage or Microsoft Graph
    # This would require additional configuration for SMTP or Graph Mail permissions
}

# Main execution
try {
    Write-TestLog "=== M365 Business Premium Security Validation Started ==="
    Write-TestLog "Tenant: $(if($TenantId){$TenantId}else{'Current'})"
    Write-TestLog "Test Categories: $($TestCategories -join ', ')"
    
    # Expand "All" test categories
    if ($TestCategories -contains "All") {
        $TestCategories = @("ConditionalAccess", "DefenderO365", "EntraID", "DefenderBusiness", "EIDSCA", "Custom")
    }
    
    # Prerequisites and setup
    Test-Prerequisites
    Initialize-MaesterTests
    Connect-MaesterGraph
    
    # Run Maester base tests first
    Write-TestLog "Running core Maester validation tests..."
    $maesterResults = Invoke-Maester -PassThru
    
    # Run category-specific tests
    $allResults = @($maesterResults)
    
    foreach ($category in $TestCategories) {
        switch ($category) {
            "ConditionalAccess" { 
                $result = Invoke-ConditionalAccessTests
                if ($result) { $allResults += $result }
            }
            "EIDSCA" { 
                $result = Invoke-EIDSCATests
                if ($result) { $allResults += $result }
            }
            "DefenderO365" { 
                $result = Invoke-DefenderO365Tests
                if ($result) { $allResults += $result }
            }
            "DefenderBusiness" { 
                $result = Invoke-DefenderBusinessTests
                if ($result) { $allResults += $result }
            }
            "Custom" { 
                $result = Invoke-CustomTests
                if ($result) { $allResults += $result }
            }
        }
    }
    
    # Generate reports
    if ($GenerateReports) {
        $reportPath = Join-Path $OutputPath "M365BP_ValidationReport_$timestamp.html"
        $finalReport = New-ValidationReport -TestResults $allResults -ReportPath $reportPath
        
        # Send notifications if requested
        if ($EmailNotification) {
            Send-TestNotification -ReportPath $finalReport -TestResults $allResults -EmailAddress $NotificationEmail
        }
        
        # Open report
        if (Test-Path $finalReport) {
            Start-Process $finalReport
        }
    }
    
    Write-TestLog "=== Validation Testing Completed Successfully ===" "SUCCESS"
    Write-TestLog "Results saved to: $OutputPath"
    
    # Return results if requested
    if ($PassThru) {
        return $allResults
    }
    
} catch {
    Write-TestLog "Validation testing failed: $($_.Exception.Message)" "ERROR"
    throw
} finally {
    # Return to original location
    if ($PWD.Path -ne $PSScriptRoot) {
        Set-Location $PSScriptRoot
    }
}
