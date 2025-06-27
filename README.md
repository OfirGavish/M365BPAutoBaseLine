# Microsoft 365 Business Premium Security Baseline - README

## Overview

This repository contains automated PowerShell scripts to deploy security baselines and best practices for Microsoft 365 Business Premium subscriptions. The solution provides comprehensive security configurations across all major M365 security components.

## Components Covered

### 1. Defender for Office 365
- Email authentication (SPF, DKIM, DMARC)
- Safe Links and Safe Attachments
- Anti-phishing policies
- Policy presets (Standard/Strict)
- Service account exclusions

### 2. Entra ID (Azure AD) Security
- Multi-Factor Authentication via Conditional Access
- Admin consent workflow for OAuth applications
- Legacy authentication blocking
- Device compliance requirements for admins
- Privileged Identity Management configuration

### 3. Microsoft Purview Compliance
- Sensitivity labels for data classification
- Retention policies (Exchange, SharePoint, OneDrive, Teams)
- Data Loss Prevention (DLP) policies
- Alert policies for high-risk activities
- Unified audit log enablement

### 4. Defender for Business (Endpoint+XDR)
- Tamper Protection enablement
- Attack Surface Reduction (ASR) rules
- Automated investigation and remediation
- Device compliance policies
- Endpoint security configurations

### 5. Microsoft Intune Security Baselines (OpenIntuneBaseline)
- Comprehensive device security configurations for Windows, Windows 365, macOS, and BYOD
- CIS Windows Benchmarks implementation
- NCSC Device Security Guidance compliance
- ACSC Essential Eight mitigation strategies
- Microsoft Security Baselines integration
- Real-world tested enterprise configurations
- Community-driven security policies

## Prerequisites

### Required PowerShell Modules
```powershell
Install-Module -Name ExchangeOnlineManagement -Force
Install-Module -Name Microsoft.Graph -Force
Install-Module -Name Microsoft.Graph.Intune -Force
Install-Module -Name PnP.PowerShell -Force
Install-Module -Name IntuneManagement -Force  # For OpenIntuneBaseline deployment
```

### Required Permissions
- Global Administrator or Security Administrator role
- Appropriate API permissions for Microsoft Graph
- Exchange Online administrative access
- Intune administrative access (for device policies)

## Quick Start

### 1. Clone or Download Repository
```powershell
git clone https://github.com/your-org/M365BPAutoBaseLine.git
cd M365BPAutoBaseLine
```

### 2. Deploy All Components
```powershell
.\Scripts\Deploy-M365BPBaseline.ps1 `
    -Components @("All") `
    -OrganizationName "YourCompany" `
    -TenantId "your-tenant-id" `
    -AdminEmail "admin@yourcompany.com"
```

### 3. Deploy Specific Components
```powershell
.\Scripts\Deploy-M365BPBaseline.ps1 `
    -Components @("DefenderO365", "EntraID", "Intune") `
    -OrganizationName "YourCompany" `
    -AdminEmail "admin@yourcompany.com"
```

## Individual Component Deployment

### Defender for Office 365
```powershell
.\Scripts\Deploy-DefenderO365Baseline.ps1 `
    -ServiceAccounts @("service@domain.com") `
    -PolicyPreset "Standard"
```

### Entra ID Security
```powershell
.\Scripts\Deploy-EntraIDBaseline.ps1 `
    -AdminConsentReviewers @("admin@domain.com") `
    -EnableSecurityDefaults:$false
```

### Microsoft Purview
```powershell
.\Scripts\Deploy-PurviewBaseline.ps1 `
    -OrganizationName "YourCompany" `
    -RetentionPeriodYears 7
```

### Defender for Business
```powershell
.\Scripts\Deploy-DefenderBusinessBaseline.ps1 `
    -TenantId "your-tenant-id" `
    -IntuneGroupName "All Users"
```

### Microsoft Intune (OpenIntuneBaseline)
```powershell
.\Scripts\Deploy-IntuneBaseline.ps1 `
    -Platforms @("Windows", "Windows365") `
    -IntuneGroupName "Pilot Users" `
    -DownloadBaseline
```

```powershell
# Deploy for all supported platforms including macOS and BYOD
.\Scripts\Deploy-IntuneBaseline.ps1 `
    -Platforms @("All") `
    -IntuneGroupName "All Users" `
    -TestMode `
    -DownloadBaseline
```

## Microsoft Intune Security Baselines (OpenIntuneBaseline Integration)

### About OpenIntuneBaseline
The **OpenIntuneBaseline (OIB)** project by James (@SkipToTheEndpoint), a Microsoft MVP, provides community-driven, enterprise-grade security baselines for Microsoft Intune. This integration brings industry-leading device security configurations to your M365 Business Premium deployment.

### Security Framework Coverage
The OpenIntuneBaseline implements multiple security frameworks:
- **NCSC Device Security Guidance** - UK National Cyber Security Centre recommendations
- **CIS Windows Benchmarks** - Center for Internet Security hardening guidelines
- **ACSC Essential Eight** - Australian Cyber Security Centre mitigation strategies
- **Microsoft Security Baselines** - Official Microsoft security recommendations
- **Real-world Experience** - Battle-tested configurations from enterprise deployments

### Supported Platforms
- **Windows 10/11** - Comprehensive device security (v3.6)
- **Windows 365** - Cloud PC specific configurations (v1.0)
- **macOS** - Apple device security baselines (v1.0)
- **BYOD (Bring Your Own Device)** - Personal device management (v1.0)

### Key Security Areas Covered
- **Device Configuration** - System hardening and security settings
- **Compliance Policies** - Device health and security requirements  
- **Endpoint Security** - Advanced threat protection settings
- **Application Control** - Software installation and execution policies
- **Data Protection** - Encryption and information protection
- **Network Security** - Wi-Fi, VPN, and network access controls
- **User Experience** - Balanced security with productivity

### Deployment Methods
1. **IntuneManagement Tool** (Recommended)
   - Imports entire baseline with full policy management
   - Preserves policy relationships and dependencies
   - Enables bulk operations and maintenance

2. **Native Intune Import**
   - Uses built-in Intune import/export functionality
   - Limited to Settings Catalog policies only
   - Suitable for environments with restricted tool usage

### Policy Naming Convention
All imported policies follow the OpenIntuneBaseline naming convention:
```
[Platform] - OIB - [Category] - [Type] - [Description] - [Version]

Examples:
- Win - OIB - Device Security - D - Login and Lock Screen - v3.6
- Win365 - OIB - Device Security - D - Resource Redirection - v1.0
- MacOS - OIB - Microsoft Edge - D - Security - v1.0
```

Where:
- **Platform**: Win, Win365, MacOS, BYOD
- **OIB**: OpenIntuneBaseline identifier
- **Category**: Device Security, Application Control, etc.
- **Type**: D (Device), U (User)
- **Description**: Specific functionality area
- **Version**: Baseline version number

### Safety Features
- **Test Mode Deployment** - Policies deployed to pilot groups initially
- **Gradual Rollout** - Controlled expansion from pilot to production
- **Policy Validation** - Automated testing of policy effectiveness
- **Compliance Monitoring** - Continuous assessment of device health
- **Rollback Capability** - Quick policy reversal if issues arise

### Integration Benefits
- **Accelerated Deployment** - Skip months of policy development
- **Industry Best Practices** - Leverage community expertise
- **Regular Updates** - Automatic access to latest security improvements
- **Comprehensive Coverage** - Address all major security areas
- **Production-Ready** - Tested in real enterprise environments
- **Documentation** - Detailed policy explanations and rationale

## Configuration

### Using Configuration Files
Create a custom configuration file based on the template:

```powershell
cp .\Config\M365BP-Config-Template.yaml .\Config\MyCompany-Config.yaml
# Edit MyCompany-Config.yaml with your settings

.\Scripts\Deploy-M365BPBaseline.ps1 `
    -Components @("All") `
    -OrganizationName "MyCompany" `
    -TenantId "your-tenant-id" `
    -AdminEmail "admin@mycompany.com" `
    -ConfigFile ".\Config\MyCompany-Config.yaml"
```

### What-If Mode
Test the deployment without making changes:

```powershell
.\Scripts\Deploy-M365BPBaseline.ps1 `
    -Components @("All") `
    -OrganizationName "YourCompany" `
    -TenantId "your-tenant-id" `
    -AdminEmail "admin@yourcompany.com" `
    -WhatIf
```

## File Structure

```
M365BPAutoBaseLine/
├── Scripts/
│   ├── Deploy-M365BPBaseline.ps1          # Master deployment script
│   ├── Deploy-DefenderO365Baseline.ps1    # Defender for Office 365
│   ├── Deploy-EntraIDBaseline.ps1         # Entra ID security
│   ├── Deploy-PurviewBaseline.ps1         # Microsoft Purview
│   ├── Deploy-DefenderBusinessBaseline.ps1 # Defender for Business
│   └── Deploy-IntuneBaseline.ps1          # Microsoft Intune
├── Config/
│   └── M365BP-Config-Template.yaml        # Configuration template
├── Docs/
│   └── detailed-guides/                   # Detailed documentation
├── ProjectOverview.md                     # Project overview and resources
└── README.md                             # This file
```

## Logging and Reporting

### Log Files
- All scripts generate detailed log files with timestamps
- Logs are stored in the Scripts directory
- Format: `M365BP-Deployment-YYYYMMDD-HHMMSS.log`

### HTML Reports
- Comprehensive deployment reports are generated automatically
- Reports include deployment status, configurations applied, and next steps
- Reports automatically open in your default browser after successful deployment

## Post-Deployment Steps

### 1. Review and Validate
- Review all created policies in their respective admin centers
- **Intune Admin Center**: Validate OpenIntuneBaseline policies and assignments
- Validate policy assignments and exclusions
- Test with pilot users before full rollout

### 2. DNS Configuration (Manual)
For Defender for Office 365, manually configure:
- SPF records: `v=spf1 include:spf.protection.outlook.com -all`
- DMARC records: `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`
- DKIM signing will be enabled automatically

### 3. Monitor and Adjust
- Monitor security alerts and incidents
- Review policy effectiveness regularly
- Adjust configurations based on organizational needs
- Schedule periodic baseline reviews

### 4. Intune-Specific Steps
- **Validate OpenIntuneBaseline Policies**: Check all OIB policies are correctly imported in Intune admin center
- **Monitor Device Compliance**: Review device compliance reports to ensure policies are being applied
- **Test Policy Assignment**: Verify policies are assigned to correct Azure AD groups
- **Check Device Enrollment**: Ensure devices are enrolling and receiving policies properly
- **Review Security Baselines**: Validate that CIS, NCSC, and Microsoft baseline requirements are met
- **Pilot Testing**: Gradually expand from pilot groups to full deployment
- **Policy Conflicts**: Resolve any conflicts between different policy types
- **User Impact Assessment**: Monitor user experience and helpdesk tickets for policy-related issues

## Post-Deployment Validation & Testing

### Automated Testing with Maester
The solution includes comprehensive post-deployment validation using the **Maester framework** - a PowerShell-based test automation framework specifically designed for Microsoft 365 security configuration monitoring.

### Run Complete Validation Suite
```powershell
.\Scripts\Test-M365BPBaseline.ps1 `
    -TenantId "your-tenant-id" `
    -TestCategories @("All") `
    -GenerateReports
```

### Category-Specific Testing
```powershell
# Test only Conditional Access and EIDSCA
.\Scripts\Test-M365BPBaseline.ps1 `
    -TestCategories @("ConditionalAccess", "EIDSCA", "Intune") `
    -IncludeWhatIfTests `
    -GenerateReports
```

### Testing Categories Available
- **ConditionalAccess**: Validates all CA policies and includes What-If scenario testing
- **DefenderO365**: Verifies Defender for Office 365 configurations
- **EntraID**: Tests Entra ID security settings and configurations
- **DefenderBusiness**: Validates Defender for Business/Endpoint policies
- **Intune**: Validates Microsoft Intune device security baselines and OpenIntuneBaseline policies
- **EIDSCA**: Runs Entra ID Security Config Analyzer (40+ security checks)
- **Custom**: Executes organization-specific custom tests

### Test Reports & Monitoring
- **Interactive HTML Reports**: Comprehensive test results with drill-down capabilities
- **XML Output**: Machine-readable results for CI/CD integration
- **Success Metrics**: Overall security posture scoring
- **Remediation Guidance**: Direct links to admin portals for fixes
- **Email Notifications**: Automated alerting for test failures

### Continuous Monitoring
```powershell
# Schedule daily validation
.\Scripts\Test-M365BPBaseline.ps1 `
    -TestCategories @("EIDSCA", "ConditionalAccess", "Intune") `
    -EmailNotification `
    -NotificationEmail "security@yourcompany.com"
```

## Troubleshooting

### Common Issues

#### Module Installation Errors
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
```

#### Permission Errors
- Ensure you have Global Administrator or Security Administrator role
- Check that your account has the necessary API permissions
- Some features may require additional licensing (e.g., PIM requires Azure AD P2)

#### Connection Issues
- Verify network connectivity to Microsoft 365 services
- Check for corporate proxy or firewall restrictions
- Ensure modern authentication is enabled

### Getting Help
- Review the generated log files for detailed error information
- Check the official Microsoft documentation links in ProjectOverview.md
- Consult the community resources listed in the project overview

## Security Considerations

### Least Privilege
- Scripts request only the minimum required permissions
- Consider using dedicated admin accounts for deployment
- Review and approve all policy changes before deployment

### Testing
- Always test in a non-production environment first
- Use What-If mode to preview changes
- Deploy to pilot groups before organization-wide rollout

### Compliance
- Ensure compliance with your organization's security policies
- Review retention and DLP policies for regulatory requirements
- Document all security configurations for audit purposes

## Contributing

### Feedback and Improvements
- Submit issues for bugs or feature requests
- Contribute improvements via pull requests
- Share configuration templates for specific industries or use cases

### Development
- Follow PowerShell best practices
- Include comprehensive error handling and logging
- Test thoroughly before submitting changes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits & Acknowledgments

This project integrates and builds upon several outstanding open-source projects from the Microsoft 365 security community:

### Core Testing Framework
- **[Maester](https://github.com/maester365/maester)** by [@merill](https://github.com/merill) and the Maester team - PowerShell-based Microsoft 365 security test automation framework (MIT License)
- **[EIDSCA](https://github.com/Cloud-Architekt/EIDSCA)** - Entra ID Security Config Analyzer for comprehensive identity security validation

### Security Baselines & Policies
- **[ConditionalAccessBaseline](https://github.com/j0eyv/ConditionalAccessBaseline)** by [@j0eyv](https://github.com/j0eyv) - Enterprise-grade Conditional Access policy baseline based on Microsoft's Zero Trust framework (MIT License)

### Advanced Endpoint Security
- **[MDEAutomator](https://github.com/msdirtbag/MDEAutomator)** by [@msdirtbag](https://github.com/msdirtbag) - Advanced Microsoft Defender for Endpoint automation and orchestration platform
- **[OpenIntuneBaseline](https://github.com/SkipToTheEndpoint/OpenIntuneBaseline)** by [@SkipToTheEndpoint](https://github.com/SkipToTheEndpoint) - Community-driven baseline to accelerate Intune adoption and learning (GPL-3.0 License)

### Underlying Technologies
- **[Pester](https://pester.dev/)** - PowerShell testing framework that powers Maester
- **[Microsoft Graph PowerShell SDK](https://github.com/microsoftgraph/msgraph-sdk-powershell)** - Microsoft Graph API integration
- **[IntuneManagement](https://github.com/Micke-K/IntuneManagement)** by [@Micke-K](https://github.com/Micke-K) - Comprehensive Intune management tool for bulk operations

We are deeply grateful for the contributions of these projects and their maintainers to the Microsoft 365 security community. This automation solution would not be possible without their dedication to open-source security tooling.

### License & Attribution
This project is released under the MIT License. All integrated components retain their original licenses and attributions. Please refer to individual component repositories for specific licensing terms.

## Version History

- v1.0: Initial release with core baseline configurations
- Future versions will include additional security features and improvements

---

For detailed documentation on each component, see the individual script files and the ProjectOverview.md file.
