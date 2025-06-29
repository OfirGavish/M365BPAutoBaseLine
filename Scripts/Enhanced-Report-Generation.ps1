# Enhanced Report Generation Functions for M365BP Deploy-DefenderBusinessBaseline-Enhanced.ps1
# This file contains the improved reporting mechanism with proper verification

function Generate-DeploymentReport {
    param(
        [hashtable]$Results,
        [string]$Token,
        [boolean]$TestResults
    )
    
    Write-Log "Generating comprehensive deployment report with verification details..."
    
    $reportPath = $LogPath -replace '\.log$', '-Report.html'
    
    # Build comprehensive status analysis
    $coreStatus = Analyze-CorePolicyStatus
    $mdeStatus = Analyze-MDEAutomatorStatus
    $asyncStatus = Analyze-AsyncOperationStatus
    
    # Build status values for HTML
    $mdeIntegrationStatus = if ($Token) { 'Enabled' } else { 'Disabled' }
    $whatIfStatus = if ($WhatIf) { 'Yes' } else { 'No' }
    $tokenStatusClass = if ($Token) { 'success' } else { 'warning' }
    $tokenStatusText = if ($Token) { '✅ Enabled' } else { '⏭️ Skipped' }
    
    # Create HTML content with comprehensive verification details
    $htmlContent = @()
    
    # HTML Header
    $htmlContent += @'
<!DOCTYPE html>
<html>
<head>
    <title>Enhanced Microsoft Defender for Business Deployment Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2.2em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .section { margin: 25px 0; padding: 20px; border: 1px solid #e1e1e1; border-radius: 8px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #e7f3ff; border-color: #b3d9ff; }
        .verification-success { background-color: #d1e7dd; border-left: 4px solid #0f5132; }
        .verification-warning { background-color: #fff3cd; border-left: 4px solid #664d03; }
        .verification-error { background-color: #f8d7da; border-left: 4px solid #842029; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: 600; }
        .status-success { color: #155724; font-weight: bold; }
        .status-warning { color: #856404; font-weight: bold; }
        .status-error { color: #721c24; font-weight: bold; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .feature-card { padding: 20px; border: 1px solid #e1e1e1; border-radius: 8px; background-color: #f8f9fa; }
        .code-block { background-color: #f6f8fa; border: 1px solid #e1e1e1; border-radius: 6px; padding: 15px; font-family: 'Consolas', 'Monaco', monospace; overflow-x: auto; font-size: 0.9em; }
        .expandable { cursor: pointer; user-select: none; }
        .expandable:hover { background-color: #f0f0f0; }
        .details { display: none; margin-top: 10px; padding: 10px; background-color: #f8f9fa; border-radius: 4px; }
        .summary-stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; border-radius: 8px; background-color: #f8f9fa; }
        .stat-number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .async-operations { margin-top: 20px; }
        .operation-item { margin: 10px 0; padding: 10px; border-left: 4px solid #0078d4; background-color: #f8f9fa; }
    </style>
    <script>
        function toggleDetails(elementId) {
            var details = document.getElementById(elementId);
            if (details.style.display === 'none' || details.style.display === '') {
                details.style.display = 'block';
            } else {
                details.style.display = 'none';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enhanced Microsoft Defender for Business Deployment Report</h1>
'@
    
    # Add dynamic header content
    $htmlContent += "            <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | MDEAutomator Integration: $mdeIntegrationStatus | WhatIf Mode: $whatIfStatus</p>"
    $htmlContent += @'
        </div>
        
        <div class="section info">
            <h2>📊 Executive Summary</h2>
            <div class="summary-stats">
'@
    
    # Add executive summary statistics
    $htmlContent += @"
                <div class="stat-box">
                    <div class="stat-number" style="color: #28a745;">$($coreStatus.SuccessCount)</div>
                    <div>Core Policies<br>Verified</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #ffc107;">$($coreStatus.WarningCount)</div>
                    <div>Core Policies<br>Warnings</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #dc3545;">$($coreStatus.ErrorCount)</div>
                    <div>Core Policies<br>Failed</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" style="color: #17a2b8;">$($mdeStatus.TotalOperations)</div>
                    <div>MDE Operations<br>Attempted</div>
                </div>
"@
    
    $htmlContent += @'
            </div>
        </div>
        
        <div class="section success">
            <h2>🔐 Core Security Baseline Detailed Status</h2>
'@
    
    # Add detailed core policy status
    foreach ($policyName in $global:DeploymentResults.CorePolicies.Keys) {
        $policy = $global:DeploymentResults.CorePolicies[$policyName]
        $statusClass = switch ($policy.Status) {
            {$_ -like "*Verified"} { "verification-success" }
            {$_ -like "*Unverified" -or $_ -eq "WhatIf"} { "verification-warning" }
            {$_ -eq "Failed" -or $_ -like "*Error"} { "verification-error" }
            default { "verification-warning" }
        }
        
        $htmlContent += @"
            <div class="$statusClass" style="margin: 10px 0; padding: 15px; border-radius: 5px;">
                <div class="expandable" onclick="toggleDetails('$policyName-details')">
                    <strong>$policyName</strong>: $($policy.Status) - $($policy.Message) <span>▼</span>
                </div>
                <div id="$policyName-details" class="details">
"@
        
        if ($policy.PolicyId) {
            $htmlContent += "<p><strong>Policy ID:</strong> $($policy.PolicyId)</p>"
        }
        if ($policy.VerificationDetails) {
            $htmlContent += "<p><strong>Verification Details:</strong></p>"
            $htmlContent += "<div class='code-block'>$($policy.VerificationDetails | ConvertTo-Json -Depth 3 | Out-String)</div>"
        }
        if ($policy.FullError) {
            $htmlContent += "<p><strong>Error Details:</strong></p>"
            $htmlContent += "<div class='code-block'>$($policy.FullError)</div>"
        }
        
        $htmlContent += @"
                </div>
            </div>
"@
    }
    
    # Add MDEAutomator section if applicable
    if ($Token -or $global:DeploymentResults.MDEAutomator.Keys.Count -gt 1) {
        $htmlContent += @'
        
        <div class="section info">
            <h2>🚀 MDEAutomator Integration Detailed Status</h2>
'@
        
        # Live Response Scripts
        if ($global:DeploymentResults.MDEAutomator.LiveResponseScripts.Keys.Count -gt 0) {
            $htmlContent += "<h3>📜 Live Response Scripts</h3>"
            
            foreach ($scriptName in $global:DeploymentResults.MDEAutomator.LiveResponseScripts.Keys) {
                if ($scriptName -eq "Status") { continue }  # Skip summary status
                
                $script = $global:DeploymentResults.MDEAutomator.LiveResponseScripts[$scriptName]
                $statusClass = switch ($script.Status) {
                    {$_ -like "*Verified"} { "verification-success" }
                    {$_ -like "*NotVerifiable" -or $_ -eq "WhatIf"} { "verification-warning" }
                    {$_ -like "*Failed" -or $_ -eq "Error"} { "verification-error" }
                    default { "verification-warning" }
                }
                
                $htmlContent += @"
                <div class="$statusClass" style="margin: 10px 0; padding: 15px; border-radius: 5px;">
                    <div class="expandable" onclick="toggleDetails('$scriptName-details')">
                        <strong>$scriptName</strong>: $($script.Status) - $($script.Message) <span>▼</span>
                    </div>
                    <div id="$scriptName-details" class="details">
                        <p><strong>Description:</strong> $($script.Description)</p>
"@
                
                if ($script.OperationId) {
                    $htmlContent += "<p><strong>Operation ID:</strong> $($script.OperationId)</p>"
                }
                if ($script.UploadResult) {
                    $htmlContent += "<p><strong>Upload Result:</strong></p>"
                    $htmlContent += "<div class='code-block'>$($script.UploadResult | ConvertTo-Json -Depth 2 | Out-String)</div>"
                }
                if ($script.VerificationDetails) {
                    $htmlContent += "<p><strong>Verification Details:</strong></p>"
                    $htmlContent += "<div class='code-block'>$($script.VerificationDetails | ConvertTo-Json -Depth 2 | Out-String)</div>"
                }
                if ($script.FullError) {
                    $htmlContent += "<p><strong>Error Details:</strong></p>"
                    $htmlContent += "<div class='code-block'>$($script.FullError)</div>"
                }
                
                $htmlContent += @"
                    </div>
                </div>
"@
            }
        }
        
        $htmlContent += "</div>"
    }
    
    # Add async operations section
    if ($global:DeploymentResults.AsyncOperations.Keys.Count -gt 0) {
        $htmlContent += @'
        
        <div class="section info">
            <h2>⏱️ Asynchronous Operations Tracking</h2>
            <div class="async-operations">
'@
        
        foreach ($opId in $global:DeploymentResults.AsyncOperations.Keys) {
            $operation = $global:DeploymentResults.AsyncOperations[$opId]
            $statusClass = switch ($operation.Status) {
                "Completed" { "verification-success" }
                "InProgress" { "verification-warning" }
                "Failed" { "verification-error" }
                default { "verification-warning" }
            }
            
            $htmlContent += @"
                <div class="operation-item $statusClass">
                    <div class="expandable" onclick="toggleDetails('$opId-details')">
                        <strong>$($operation.Description)</strong> - Status: $($operation.Status) <span>▼</span>
                    </div>
                    <div id="$opId-details" class="details">
                        <p><strong>Resource Type:</strong> $($operation.ResourceType)</p>
                        <p><strong>Started:</strong> $($operation.StartTime)</p>
                        <p><strong>Last Checked:</strong> $($operation.LastChecked)</p>
"@
            
            if ($operation.Data) {
                $htmlContent += "<p><strong>Operation Data:</strong></p>"
                $htmlContent += "<div class='code-block'>$($operation.Data | ConvertTo-Json -Depth 3 | Out-String)</div>"
            }
            
            $htmlContent += @"
                    </div>
                </div>
"@
        }
        
        $htmlContent += @'
            </div>
        </div>
'@
    }
    
    # Add recommendations and next steps
    $htmlContent += @'
        
        <div class="section warning">
            <h2>📝 Recommendations and Next Steps</h2>
            <ul>
'@
    
    # Add dynamic recommendations based on results
    if ($coreStatus.ErrorCount -gt 0) {
        $htmlContent += "<li><strong>🔴 Critical:</strong> $($coreStatus.ErrorCount) core policies failed to deploy. Review error details above and retry deployment.</li>"
    }
    if ($coreStatus.WarningCount -gt 0) {
        $htmlContent += "<li><strong>🟡 Warning:</strong> $($coreStatus.WarningCount) core policies require attention. Verify configurations manually.</li>"
    }
    if ($mdeStatus.FailedOperations -gt 0) {
        $htmlContent += "<li><strong>🔴 Critical:</strong> $($mdeStatus.FailedOperations) MDEAutomator operations failed. Check credentials and permissions.</li>"
    }
    if ($asyncStatus.InProgressCount -gt 0) {
        $htmlContent += "<li><strong>ℹ️ Info:</strong> $($asyncStatus.InProgressCount) operations still in progress. Monitor status and re-run verification if needed.</li>"
    }
    
    $htmlContent += @'
                <li>Review all deployed policies and test with pilot devices before full rollout</li>
                <li>Monitor security dashboard for alerts and tune detection rules as needed</li>
                <li>Replace example threat intelligence indicators with real IOCs in production</li>
                <li>Regularly update and maintain custom detection rules</li>
                <li>Schedule periodic re-verification of all deployed components</li>
            </ul>
        </div>
        
        <div class="section info">
            <h2>🔗 Additional Resources</h2>
            <ul>
                <li><a href="https://github.com/msdirtbag/MDEAutomator">MDEAutomator GitHub Repository</a></li>
                <li><a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/">Microsoft Defender for Endpoint Documentation</a></li>
                <li><a href="https://docs.microsoft.com/en-us/mem/intune/">Microsoft Intune Documentation</a></li>
            </ul>
        </div>
        
        <div class="section" style="background-color: #f8f9fa; border: 1px solid #dee2e6;">
            <h2>📋 Report Generation Details</h2>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Log File:</strong> $LogPath</p>
            <p><strong>Script Version:</strong> 2.0 Enhanced</p>
            <p><strong>Verification Enabled:</strong> Yes</p>
            <p><strong>Async Tracking Enabled:</strong> Yes</p>
        </div>
    </div>
</body>
</html>
'@
    
    # Write HTML content to file
    try {
        $htmlContent | Out-File -FilePath $reportPath -Encoding UTF8 -Force
        Write-Log "✅ Comprehensive deployment report generated: $reportPath" -Level "SUCCESS"
    }
    catch {
        Write-Log "❌ Failed to generate HTML report: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Helper functions for report analysis
function Analyze-CorePolicyStatus {
    $successCount = 0
    $warningCount = 0
    $errorCount = 0
    
    foreach ($policy in $global:DeploymentResults.CorePolicies.Values) {
        switch ($policy.Status) {
            {$_ -like "*Verified"} { $successCount++ }
            {$_ -like "*Unverified" -or $_ -eq "WhatIf"} { $warningCount++ }
            {$_ -eq "Failed" -or $_ -like "*Error"} { $errorCount++ }
            default { $warningCount++ }
        }
    }
    
    return @{
        SuccessCount = $successCount
        WarningCount = $warningCount
        ErrorCount = $errorCount
        Total = $successCount + $warningCount + $errorCount
    }
}

function Analyze-MDEAutomatorStatus {
    $totalOperations = 0
    $successfulOperations = 0
    $failedOperations = 0
    
    # Analyze Live Response Scripts
    foreach ($script in $global:DeploymentResults.MDEAutomator.LiveResponseScripts.Values) {
        if ($script -is [hashtable] -and $script.Status) {
            $totalOperations++
            if ($script.Status -like "*Verified") {
                $successfulOperations++
            } elseif ($script.Status -like "*Failed" -or $script.Status -eq "Error") {
                $failedOperations++
            }
        }
    }
    
    # Add other MDEAutomator operations when implemented
    foreach ($detection in $global:DeploymentResults.MDEAutomator.CustomDetections.Values) {
        if ($detection -is [hashtable] -and $detection.Status) {
            $totalOperations++
            if ($detection.Status -like "*Verified") {
                $successfulOperations++
            } elseif ($detection.Status -like "*Failed" -or $detection.Status -eq "Error") {
                $failedOperations++
            }
        }
    }
    
    return @{
        TotalOperations = $totalOperations
        SuccessfulOperations = $successfulOperations
        FailedOperations = $failedOperations
    }
}

function Analyze-AsyncOperationStatus {
    $inProgressCount = 0
    $completedCount = 0
    $failedCount = 0
    
    foreach ($operation in $global:DeploymentResults.AsyncOperations.Values) {
        switch ($operation.Status) {
            "InProgress" { $inProgressCount++ }
            "Completed" { $completedCount++ }
            "Failed" { $failedCount++ }
        }
    }
    
    return @{
        InProgressCount = $inProgressCount
        CompletedCount = $completedCount
        FailedCount = $failedCount
        Total = $inProgressCount + $completedCount + $failedCount
    }
}
