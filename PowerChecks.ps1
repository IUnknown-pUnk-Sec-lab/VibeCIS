# Security-Focused Build Review Script - PowerShell Edition
# Comprehensive security assessment for Windows builds
# Version: 1.0

param(
    [string]$OutputFile = "",
    [ValidateSet("JSON", "CSV", "HTML")]
    [string]$Format = "JSON",
    [switch]$ShowAll,
    [string[]]$Severity = @()
)

# Global results storage
$Script:Results = @()
$Script:Summary = @{
    Critical = 0
    High = 0
    Medium = 0
    Low = 0
    Info = 0
}

# Color codes for output
$Script:Colors = @{
    Critical = 'Red'
    High = 'DarkRed'
    Medium = 'Yellow'
    Low = 'Cyan'
    Info = 'Gray'
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Title,
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        [string]$Severity,
        [string]$Description,
        [string]$Evidence = "",
        [string]$Recommendation = ""
    )
    
    $finding = [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Severity = $Severity
        Description = $Description
        Evidence = $Evidence
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    }
    
    $Script:Results += $finding
    $Script:Summary[$Severity]++
}

function Test-SystemInfo {
    Write-Host "[*] Gathering System Information..." -ForegroundColor Cyan
    
    try {
        $sysInfo = Get-ComputerInfo -ErrorAction SilentlyContinue
        if ($sysInfo) {
            $info = "OS: $($sysInfo.OsName)`nVersion: $($sysInfo.OsVersion)`nBuild: $($sysInfo.OsBuildNumber)"
            Add-Finding -Category "System Info" -Title "Windows System Information" -Severity "INFO" `
                -Description "Basic system information gathered" -Evidence $info
        }
    } catch {
        Write-Warning "Could not gather full system info: $_"
    }
    
    # Get hotfixes
    try {
        $hotfixes = Get-HotFix | Select-Object -First 20 | Out-String
        Add-Finding -Category "System Info" -Title "Recent Windows Updates" -Severity "INFO" `
            -Description "Recently installed Windows updates" -Evidence $hotfixes
    } catch {
        Write-Warning "Could not retrieve hotfix information: $_"
    }
}

function Test-UserAccounts {
    Write-Host "[*] Checking User Accounts and Groups..." -ForegroundColor Cyan
    
    # Check for accounts with passwords that don't expire
    try {
        $nonExpiringPasswords = Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true }
        if ($nonExpiringPasswords) {
            $evidence = $nonExpiringPasswords | Select-Object Name, Enabled, PasswordNeverExpires | Out-String
            Add-Finding -Category "User Accounts" -Title "Accounts with Non-Expiring Passwords" -Severity "HIGH" `
                -Description "Found $($nonExpiringPasswords.Count) accounts with passwords set to never expire" `
                -Evidence $evidence `
                -Recommendation "Set password expiration policies: Set-LocalUser -Name 'username' -PasswordNeverExpires `$false"
        }
    } catch {
        Write-Warning "Could not check password expiration: $_"
    }
    
    # Check local administrators
    try {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
        $adminCount = ($admins | Measure-Object).Count
        $evidence = $admins | Select-Object Name, ObjectClass | Out-String
        
        if ($adminCount -gt 2) {
            Add-Finding -Category "User Accounts" -Title "Multiple Local Administrators" -Severity "MEDIUM" `
                -Description "Found $adminCount members in local Administrators group" `
                -Evidence $evidence `
                -Recommendation "Review and minimize local administrator membership"
        } else {
            Add-Finding -Category "User Accounts" -Title "Local Administrator Count" -Severity "INFO" `
                -Description "Local Administrators group has $adminCount members" -Evidence $evidence
        }
    } catch {
        Write-Warning "Could not enumerate administrators: $_"
    }
    
    # Check guest account
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            Add-Finding -Category "User Accounts" -Title "Guest Account Enabled" -Severity "HIGH" `
                -Description "Guest account is enabled" `
                -Evidence ($guest | Out-String) `
                -Recommendation "Disable the Guest account: Disable-LocalUser -Name 'Guest'"
        }
    } catch {
        # Guest account may not exist on some systems
    }
    
    # Check for accounts without password requirement
    try {
        $noPasswordRequired = Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }
        if ($noPasswordRequired) {
            $evidence = $noPasswordRequired | Select-Object Name, PasswordRequired | Out-String
            Add-Finding -Category "User Accounts" -Title "Accounts Without Password Requirement" -Severity "CRITICAL" `
                -Description "Found $($noPasswordRequired.Count) accounts that don't require passwords" `
                -Evidence $evidence `
                -Recommendation "Enable password requirements for all accounts"
        }
    } catch {
        Write-Warning "Could not check password requirements: $_"
    }
}

function Test-NetworkServices {
    Write-Host "[*] Checking Network Services..." -ForegroundColor Cyan
    
    # Check listening ports
    try {
        $listeningPorts = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess, State
        $riskyPorts = $listeningPorts | Where-Object { $_.LocalPort -in @(21, 23, 135, 139, 445, 3389) }
        
        if ($riskyPorts) {
            $evidence = $riskyPorts | Out-String
            Add-Finding -Category "Network Services" -Title "Potentially Risky Open Ports" -Severity "HIGH" `
                -Description "Found $($riskyPorts.Count) potentially risky ports listening" `
                -Evidence $evidence `
                -Recommendation "Review necessity of these services and restrict access"
        }
        
        $portSummary = $listeningPorts | Select-Object -First 30 | Out-String
        Add-Finding -Category "Network Services" -Title "Listening TCP Ports" -Severity "INFO" `
            -Description "Currently listening TCP ports" -Evidence $portSummary
    } catch {
        Write-Warning "Could not enumerate network connections: $_"
    }
    
    # Check Windows Firewall
    try {
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled
        $disabledProfiles = $firewallProfiles | Where-Object { $_.Enabled -eq $false }
        
        if ($disabledProfiles) {
            $evidence = $firewallProfiles | Out-String
            Add-Finding -Category "Network Services" -Title "Firewall Disabled" -Severity "CRITICAL" `
                -Description "Windows Firewall is disabled on one or more profiles" `
                -Evidence $evidence `
                -Recommendation "Enable Windows Firewall on all profiles: Set-NetFirewallProfile -All -Enabled True"
        } else {
            Add-Finding -Category "Network Services" -Title "Windows Firewall Status" -Severity "INFO" `
                -Description "Windows Firewall is enabled on all profiles" -Evidence ($firewallProfiles | Out-String)
        }
    } catch {
        Write-Warning "Could not check firewall status: $_"
    }
    
    # Check for SMBv1
    try {
        $smbConfig = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
        if ($smbConfig.EnableSMB1Protocol -eq $true) {
            Add-Finding -Category "Network Services" -Title "SMBv1 Enabled" -Severity "HIGH" `
                -Description "SMBv1 protocol is enabled (vulnerable to EternalBlue and other attacks)" `
                -Evidence ($smbConfig | Out-String) `
                -Recommendation "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
        }
    } catch {
        Write-Warning "Could not check SMB configuration: $_"
    }
    
    # Check RDP settings
    try {
        $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdpEnabled -eq 0) {
            Add-Finding -Category "Network Services" -Title "RDP Enabled" -Severity "MEDIUM" `
                -Description "Remote Desktop Protocol is enabled" `
                -Evidence "fDenyTSConnections = 0" `
                -Recommendation "Review RDP necessity, enable NLA, and restrict access via firewall"
        }
    } catch {
        Write-Warning "Could not check RDP status: $_"
    }
}

function Test-SecuritySoftware {
    Write-Host "[*] Checking Security Software..." -ForegroundColor Cyan
    
    # Check Windows Defender status
    try {
        $defenderStatus = Get-MpComputerStatus
        
        $disabledProtections = @()
        if (-not $defenderStatus.AntivirusEnabled) { $disabledProtections += "Antivirus" }
        if (-not $defenderStatus.RealTimeProtectionEnabled) { $disabledProtections += "Real-Time Protection" }
        if (-not $defenderStatus.IoavProtectionEnabled) { $disabledProtections += "IOAV Protection" }
        if (-not $defenderStatus.AntispywareEnabled) { $disabledProtections += "Antispyware" }
        
        if ($disabledProtections.Count -gt 0) {
            Add-Finding -Category "Security Software" -Title "Windows Defender Protection Disabled" -Severity "CRITICAL" `
                -Description "One or more Windows Defender protections are disabled: $($disabledProtections -join ', ')" `
                -Evidence ($defenderStatus | Out-String) `
                -Recommendation "Enable all Windows Defender protections"
        } else {
            Add-Finding -Category "Security Software" -Title "Windows Defender Status" -Severity "INFO" `
                -Description "Windows Defender protections are enabled" -Evidence ($defenderStatus | Select-Object Antivirus*, RealTime* | Out-String)
        }
        
        # Check definition age
        $sigAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
        if ($sigAge.Days -gt 7) {
            Add-Finding -Category "Security Software" -Title "Outdated Defender Definitions" -Severity "HIGH" `
                -Description "Windows Defender definitions are $($sigAge.Days) days old" `
                -Evidence "Last Updated: $($defenderStatus.AntivirusSignatureLastUpdated)" `
                -Recommendation "Update Windows Defender definitions: Update-MpSignature"
        }
    } catch {
        Write-Warning "Could not check Windows Defender status: $_"
    }
    
    # Check BitLocker status
    try {
        $bitlockerVolumes = Get-BitLockerVolume
        $unprotected = $bitlockerVolumes | Where-Object { $_.ProtectionStatus -eq 'Off' }
        
        if ($unprotected) {
            $evidence = $bitlockerVolumes | Select-Object MountPoint, ProtectionStatus, EncryptionPercentage | Out-String
            Add-Finding -Category "Security Software" -Title "BitLocker Not Enabled" -Severity "MEDIUM" `
                -Description "BitLocker drive encryption is not enabled on $($unprotected.Count) volume(s)" `
                -Evidence $evidence `
                -Recommendation "Enable BitLocker encryption for sensitive data protection"
        } else {
            Add-Finding -Category "Security Software" -Title "BitLocker Status" -Severity "INFO" `
                -Description "BitLocker is enabled on all volumes" `
                -Evidence ($bitlockerVolumes | Select-Object MountPoint, ProtectionStatus | Out-String)
        }
    } catch {
        Write-Warning "Could not check BitLocker status: $_"
    }
}

function Test-InstalledSoftware {
    Write-Host "[*] Checking Installed Software..." -ForegroundColor Cyan
    
    # Get installed applications
    try {
        $software32 = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher | Where-Object { $_.DisplayName }
        
        $software64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher | Where-Object { $_.DisplayName }
        
        $allSoftware = $software32 + $software64 | Sort-Object DisplayName -Unique
        
        Add-Finding -Category "Installed Software" -Title "Installed Applications" -Severity "INFO" `
            -Description "Found $($allSoftware.Count) installed applications" `
            -Evidence ($allSoftware | Select-Object -First 30 | Out-String)
        
        # Check for risky remote access software
        $riskySoftware = @('TeamViewer', 'AnyDesk', 'VNC', 'LogMeIn', 'GoToMyPC', 'Chrome Remote Desktop')
        foreach ($software in $riskySoftware) {
            $found = $allSoftware | Where-Object { $_.DisplayName -like "*$software*" }
            if ($found) {
                Add-Finding -Category "Installed Software" -Title "Remote Access Software: $software" -Severity "MEDIUM" `
                    -Description "Remote access software $software is installed" `
                    -Evidence ($found | Out-String) `
                    -Recommendation "Review necessity and ensure proper access controls"
            }
        }
    } catch {
        Write-Warning "Could not enumerate installed software: $_"
    }
}

function Test-AuditLogging {
    Write-Host "[*] Checking Audit and Logging..." -ForegroundColor Cyan
    
    # Check audit policies
    try {
        $auditPol = auditpol /get /category:* | Out-String
        
        if ($auditPol -match "No Auditing" -or $auditPol -notmatch "Success and Failure") {
            Add-Finding -Category "Audit & Logging" -Title "Insufficient Audit Policies" -Severity "HIGH" `
                -Description "Audit policies may not be configured to log security events" `
                -Evidence $auditPol.Substring(0, [Math]::Min(2000, $auditPol.Length)) `
                -Recommendation "Configure comprehensive audit policies via Group Policy or auditpol"
        } else {
            Add-Finding -Category "Audit & Logging" -Title "Audit Policies" -Severity "INFO" `
                -Description "Audit policies are configured" `
                -Evidence $auditPol.Substring(0, [Math]::Min(1500, $auditPol.Length))
        }
    } catch {
        Write-Warning "Could not check audit policies: $_"
    }
    
    # Check security event log
    try {
        $securityLog = Get-EventLog -LogName Security -Newest 1 -ErrorAction SilentlyContinue
        if ($securityLog) {
            Add-Finding -Category "Audit & Logging" -Title "Security Event Log Active" -Severity "INFO" `
                -Description "Security event log is receiving events" `
                -Evidence "Last Event: $($securityLog.TimeGenerated)"
        }
    } catch {
        Add-Finding -Category "Audit & Logging" -Title "Security Event Log Issue" -Severity "HIGH" `
            -Description "Unable to retrieve security event log entries" `
            -Recommendation "Verify security event log is enabled and receiving events"
    }
}

function Test-SystemHardening {
    Write-Host "[*] Checking System Hardening..." -ForegroundColor Cyan
    
    # Check UAC settings
    try {
        $uacSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if ($uacSettings.EnableLUA -eq 0) {
            Add-Finding -Category "System Hardening" -Title "UAC Disabled" -Severity "CRITICAL" `
                -Description "User Account Control (UAC) is disabled" `
                -Evidence "EnableLUA = 0" `
                -Recommendation "Enable UAC for elevation prompts"
        } else {
            Add-Finding -Category "System Hardening" -Title "UAC Status" -Severity "INFO" `
                -Description "UAC is enabled" -Evidence "EnableLUA = $($uacSettings.EnableLUA)"
        }
    } catch {
        Write-Warning "Could not check UAC status: $_"
    }
    
    # Check LSA protection
    try {
        $lsaProtection = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
        if ($lsaProtection -ne 1) {
            Add-Finding -Category "System Hardening" -Title "LSA Protection Not Enabled" -Severity "HIGH" `
                -Description "LSA Protection (RunAsPPL) is not enabled" `
                -Evidence "RunAsPPL = $lsaProtection" `
                -Recommendation "Enable LSA Protection to prevent credential dumping attacks"
        } else {
            Add-Finding -Category "System Hardening" -Title "LSA Protection Enabled" -Severity "INFO" `
                -Description "LSA Protection is enabled" -Evidence "RunAsPPL = 1"
        }
    } catch {
        Write-Warning "Could not check LSA protection: $_"
    }
    
    # Check Credential Guard
    try {
        $cgStatus = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\DeviceGuard' -ErrorAction SilentlyContinue
        if (-not $cgStatus -or -not $cgStatus.EnableVirtualizationBasedSecurity) {
            Add-Finding -Category "System Hardening" -Title "Credential Guard Not Configured" -Severity "MEDIUM" `
                -Description "Credential Guard (VBS) is not configured" `
                -Recommendation "Consider enabling Credential Guard on supported systems"
        } else {
            Add-Finding -Category "System Hardening" -Title "Credential Guard Status" -Severity "INFO" `
                -Description "Credential Guard is configured" -Evidence ($cgStatus | Out-String)
        }
    } catch {
        Write-Warning "Could not check Credential Guard: $_"
    }
}

function Test-SecurityPosture {
    Write-Host "[*] Checking Security Posture (Reconnaissance)..." -ForegroundColor Cyan
    
    # Check Windows Defender exclusions
    try {
        $exclusions = Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess
        $exclusionCount = 0
        if ($exclusions.ExclusionPath) { $exclusionCount += $exclusions.ExclusionPath.Count }
        if ($exclusions.ExclusionExtension) { $exclusionCount += $exclusions.ExclusionExtension.Count }
        if ($exclusions.ExclusionProcess) { $exclusionCount += $exclusions.ExclusionProcess.Count }
        
        if ($exclusionCount -gt 5) {
            Add-Finding -Category "Security Posture" -Title "Multiple AV Exclusions Configured" -Severity "MEDIUM" `
                -Description "Found $exclusionCount antivirus exclusions configured" `
                -Evidence ($exclusions | Out-String) `
                -Recommendation "Review AV exclusions - excessive exclusions reduce protection and could be abused"
        }
    } catch {
        Write-Warning "Could not check AV exclusions: $_"
    }
    
    # Check PowerShell execution policy
    try {
        $execPolicies = Get-ExecutionPolicy -List
        $permissive = $execPolicies | Where-Object { $_.ExecutionPolicy -in @('Unrestricted', 'Bypass') }
        
        if ($permissive) {
            Add-Finding -Category "Security Posture" -Title "Permissive PowerShell Execution Policy" -Severity "MEDIUM" `
                -Description "PowerShell execution policy allows unrestricted script execution" `
                -Evidence ($execPolicies | Out-String) `
                -Recommendation "Set execution policy to RemoteSigned or AllSigned"
        }
    } catch {
        Write-Warning "Could not check PowerShell execution policy: $_"
    }
    
    # Check PowerShell logging
    try {
        $scriptBlockLogging = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
        if (-not $scriptBlockLogging -or $scriptBlockLogging.EnableScriptBlockLogging -ne 1) {
            Add-Finding -Category "Security Posture" -Title "PowerShell Script Block Logging Disabled" -Severity "HIGH" `
                -Description "PowerShell script block logging is not enabled" `
                -Recommendation "Enable PowerShell script block logging for visibility into PowerShell activity"
        }
        
        $transcription = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
        if (-not $transcription -or $transcription.EnableTranscripting -ne 1) {
            Add-Finding -Category "Security Posture" -Title "PowerShell Transcription Disabled" -Severity "MEDIUM" `
                -Description "PowerShell transcription logging is not enabled" `
                -Recommendation "Enable PowerShell transcription for complete PowerShell session logging"
        }
    } catch {
        Write-Warning "Could not check PowerShell logging: $_"
    }
    
    # Check WinRM
    try {
        $winrm = Get-Service WinRM
        if ($winrm.Status -eq 'Running') {
            Add-Finding -Category "Security Posture" -Title "WinRM Service Running" -Severity "MEDIUM" `
                -Description "Windows Remote Management service is running" `
                -Evidence ($winrm | Out-String) `
                -Recommendation "If WinRM is not required, disable it. If required, ensure proper authentication and network restrictions"
        }
    } catch {
        Write-Warning "Could not check WinRM status: $_"
    }
    
    # Check for saved credentials
    try {
        $savedCreds = cmdkey /list | Out-String
        if ($savedCreds -match "Target:") {
            $credCount = ([regex]::Matches($savedCreds, "Target:")).Count
            Add-Finding -Category "Security Posture" -Title "Saved Credentials Present" -Severity "HIGH" `
                -Description "Found $credCount saved credentials in credential manager" `
                -Evidence $savedCreds.Substring(0, [Math]::Min(1000, $savedCreds.Length)) `
                -Recommendation "Review saved credentials - these can be extracted by attackers with local access"
        }
    } catch {
        Write-Warning "Could not check saved credentials: $_"
    }
    
    # Check file shares
    try {
        $shares = Get-SmbShare
        $nonDefault = $shares | Where-Object { $_.Name -notin @('ADMIN$', 'C$', 'IPC$', 'print$') }
        
        if ($nonDefault) {
            $evidence = $nonDefault | Select-Object Name, Path, Description | Out-String
            Add-Finding -Category "Security Posture" -Title "Non-Default Shares Present" -Severity "MEDIUM" `
                -Description "Found $($nonDefault.Count) non-default file shares" `
                -Evidence $evidence `
                -Recommendation "Review share permissions and necessity of exposed shares"
        }
    } catch {
        Write-Warning "Could not enumerate file shares: $_"
    }
    
    # Check LLMNR
    try {
        $llmnr = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue
        if (-not $llmnr -or $llmnr.EnableMulticast -ne 0) {
            Add-Finding -Category "Security Posture" -Title "LLMNR Enabled" -Severity "HIGH" `
                -Description "LLMNR (Link-Local Multicast Name Resolution) is enabled" `
                -Recommendation "Disable LLMNR to prevent name resolution poisoning attacks (Responder, NTLM relay)"
        }
    } catch {
        Write-Warning "Could not check LLMNR status: $_"
    }
    
    # Check SMB signing
    try {
        $smbSigning = Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
        if ($smbSigning.RequireSecuritySignature -eq $false) {
            Add-Finding -Category "Security Posture" -Title "SMB Signing Not Required" -Severity "HIGH" `
                -Description "SMB signing is not required" `
                -Evidence ($smbSigning | Out-String) `
                -Recommendation "Enable required SMB signing to prevent relay attacks: Set-SmbServerConfiguration -RequireSecuritySignature `$true"
        }
    } catch {
        Write-Warning "Could not check SMB signing: $_"
    }
    
    # Check for AutoAdminLogon
    try {
        $autoLogon = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue).AutoAdminLogon
        if ($autoLogon -eq "1") {
            Add-Finding -Category "Security Posture" -Title "Auto Admin Logon Enabled" -Severity "CRITICAL" `
                -Description "Automatic administrator login is enabled" `
                -Evidence "AutoAdminLogon = 1" `
                -Recommendation "Disable AutoAdminLogon - credentials may be stored in clear text in registry"
        }
    } catch {
        Write-Warning "Could not check AutoAdminLogon: $_"
    }
    
    # Check AlwaysInstallElevated
    try {
        $hklm = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $hkcu = (Get-ItemProperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated
        
        if ($hklm -eq 1 -and $hkcu -eq 1) {
            Add-Finding -Category "Security Posture" -Title "AlwaysInstallElevated Enabled" -Severity "CRITICAL" `
                -Description "AlwaysInstallElevated is enabled in both HKLM and HKCU" `
                -Evidence "HKLM: $hklm, HKCU: $hkcu" `
                -Recommendation "Disable AlwaysInstallElevated - allows privilege escalation via MSI installers"
        }
    } catch {
        Write-Warning "Could not check AlwaysInstallElevated: $_"
    }
    
    # Check AppLocker
    try {
        $appLocker = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if (-not $appLocker -or -not $appLocker.RuleCollections) {
            Add-Finding -Category "Security Posture" -Title "No AppLocker Policies" -Severity "MEDIUM" `
                -Description "AppLocker application control policies are not configured" `
                -Recommendation "Consider implementing AppLocker to control which applications can run"
        } else {
            Add-Finding -Category "Security Posture" -Title "AppLocker Enabled" -Severity "INFO" `
                -Description "AppLocker application control is configured" `
                -Evidence ($appLocker.RuleCollections | Out-String).Substring(0, 1000)
        }
    } catch {
        Write-Warning "Could not check AppLocker: $_"
    }
    
    # Check for unquoted service paths
    try {
        $services = Get-WmiObject -Class Win32_Service | 
            Where-Object { 
                $_.PathName -notmatch '^\".+\"' -and 
                $_.PathName -match '.+\s.+' -and 
                $_.StartMode -ne 'Disabled' 
            }
        
        if ($services) {
            $evidence = $services | Select-Object Name, PathName, StartMode | Format-List | Out-String
            Add-Finding -Category "Security Posture" -Title "Unquoted Service Paths" -Severity "HIGH" `
                -Description "Found $($services.Count) services with unquoted paths containing spaces" `
                -Evidence $evidence.Substring(0, [Math]::Min(2000, $evidence.Length)) `
                -Recommendation "Quote service paths to prevent privilege escalation via path hijacking"
        }
    } catch {
        Write-Warning "Could not check service paths: $_"
    }
}

function Test-ScheduledTasks {
    Write-Host "[*] Checking Scheduled Tasks..." -ForegroundColor Cyan
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }
        Add-Finding -Category "Scheduled Tasks" -Title "Active Scheduled Tasks" -Severity "INFO" `
            -Description "Found $($tasks.Count) active scheduled tasks" `
            -Evidence ($tasks | Select-Object TaskName, TaskPath, State -First 30 | Out-String)
        
        # Check for non-Microsoft tasks
        $nonMSTasks = $tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
        if ($nonMSTasks) {
            $evidence = $nonMSTasks | Select-Object TaskName, TaskPath | Format-List | Out-String
            Add-Finding -Category "Scheduled Tasks" -Title "Non-Microsoft Scheduled Tasks" -Severity "MEDIUM" `
                -Description "Found $($nonMSTasks.Count) active scheduled tasks not in Microsoft paths - review required" `
                -Evidence $evidence.Substring(0, [Math]::Min(2000, $evidence.Length)) `
                -Recommendation "Review non-Microsoft scheduled tasks for legitimacy"
        }
    } catch {
        Write-Warning "Could not enumerate scheduled tasks: $_"
    }
}

function Export-Results {
    param(
        [string]$OutputFile,
        [string]$Format
    )
    
    if (-not $OutputFile) {
        return
    }
    
    $report = [PSCustomObject]@{
        Summary = [PSCustomObject]@{
            ScanDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            Hostname = $env:COMPUTERNAME
            TotalFindings = $Script:Results.Count
            Critical = $Script:Summary.Critical
            High = $Script:Summary.High
            Medium = $Script:Summary.Medium
            Low = $Script:Summary.Low
            Informational = $Script:Summary.Info
        }
        Findings = $Script:Results
    }
    
    switch ($Format.ToUpper()) {
        "JSON" {
            $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
        }
        "CSV" {
            $Script:Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        }
        "HTML" {
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Build Review Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .CRITICAL { background-color: #ff0000; color: white; font-weight: bold; }
        .HIGH { background-color: #ff6600; color: white; }
        .MEDIUM { background-color: #ffcc00; }
        .LOW { background-color: #66ccff; }
        .INFO { background-color: #cccccc; }
        .summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Security Build Review Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Scan Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Hostname:</strong> $env:COMPUTERNAME</p>
        <p><strong>Total Findings:</strong> $($Script:Results.Count)</p>
        <p><strong>Critical:</strong> $($Script:Summary.Critical) | 
           <strong>High:</strong> $($Script:Summary.High) | 
           <strong>Medium:</strong> $($Script:Summary.Medium) | 
           <strong>Low:</strong> $($Script:Summary.Low) | 
           <strong>Info:</strong> $($Script:Summary.Info)</p>
    </div>
    <table>
        <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Title</th>
            <th>Description</th>
            <th>Recommendation</th>
        </tr>
"@
            foreach ($finding in $Script:Results | Sort-Object @{Expression={
                switch ($_.Severity) {
                    'CRITICAL' { 0 }
                    'HIGH' { 1 }
                    'MEDIUM' { 2 }
                    'LOW' { 3 }
                    'INFO' { 4 }
                }
            }}) {
                $html += @"
        <tr>
            <td class="$($finding.Severity)">$($finding.Severity)</td>
            <td>$($finding.Category)</td>
            <td>$($finding.Title)</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($finding.Description))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($finding.Recommendation))</td>
        </tr>
"@
            }
            $html += @"
    </table>
</body>
</html>
"@
            $html | Out-File -FilePath $OutputFile -Encoding UTF8
        }
    }
    
    Write-Host "`n[+] Report saved to: $OutputFile" -ForegroundColor Green
}

function Show-Summary {
    $total = $Script:Results.Count
    
    Write-Host "`n" -NoNewline
    Write-Host ("="*70) -ForegroundColor White
    Write-Host "SECURITY ASSESSMENT SUMMARY" -ForegroundColor White
    Write-Host ("="*70) -ForegroundColor White
    Write-Host "Total Findings:    $total"
    Write-Host "CRITICAL:          $($Script:Summary.Critical)" -ForegroundColor Red
    Write-Host "HIGH:              $($Script:Summary.High)" -ForegroundColor DarkRed
    Write-Host "MEDIUM:            $($Script:Summary.Medium)" -ForegroundColor Yellow
    Write-Host "LOW:               $($Script:Summary.Low)" -ForegroundColor Cyan
    Write-Host "INFORMATIONAL:     $($Script:Summary.Info)" -ForegroundColor Gray
    Write-Host ("="*70) -ForegroundColor White
    Write-Host ""
}

function Show-DetailedFindings {
    param(
        [string[]]$SeverityFilter
    )
    
    if (-not $SeverityFilter -or $SeverityFilter.Count -eq 0) {
        $SeverityFilter = @('CRITICAL', 'HIGH', 'MEDIUM')
    }
    
    foreach ($sev in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')) {
        if ($sev -notin $SeverityFilter) {
            continue
        }
        
        $findings = $Script:Results | Where-Object { $_.Severity -eq $sev }
        if ($findings.Count -eq 0) {
            continue
        }
        
        $color = $Script:Colors[$sev]
        
        Write-Host "`n" -NoNewline
        Write-Host ("="*70) -ForegroundColor $color
        Write-Host "$sev FINDINGS ($($findings.Count))" -ForegroundColor $color
        Write-Host ("="*70) -ForegroundColor $color
        Write-Host ""
        
        foreach ($finding in $findings) {
            Write-Host "[$sev] " -ForegroundColor $color -NoNewline
            Write-Host "[$($finding.Category)] " -ForegroundColor White -NoNewline
            Write-Host $finding.Title
            Write-Host "  ├─ $($finding.Description)"
            
            if ($finding.Evidence -and $finding.Evidence.Length -gt 0) {
                $evidencePreview = $finding.Evidence.Substring(0, [Math]::Min(200, $finding.Evidence.Length))
                if ($finding.Evidence.Length -gt 200) { $evidencePreview += "..." }
                Write-Host "  ├─ Evidence: $evidencePreview"
            }
            
            if ($finding.Recommendation) {
                Write-Host "  └─ " -NoNewline
                Write-Host "Recommendation: " -ForegroundColor White -NoNewline
                Write-Host $finding.Recommendation
            }
            
            Write-Host ""
        }
    }
}

# Main execution
function Main {
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Warning "Not running as Administrator. Some checks may be incomplete."
        Write-Host ""
    }
    
    Write-Host ""
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host "Security-Focused Build Review - PowerShell Edition" -ForegroundColor Cyan
    Write-Host "System: $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host ("="*70) -ForegroundColor Cyan
    Write-Host ""
    
    # Run all checks
    Test-SystemInfo
    Test-UserAccounts
    Test-NetworkServices
    Test-SecuritySoftware
    Test-InstalledSoftware
    Test-AuditLogging
    Test-SystemHardening
    Test-SecurityPosture
    Test-ScheduledTasks
    
    # Export results if requested
    if ($OutputFile) {
        Export-Results -OutputFile $OutputFile -Format $Format
    }
    
    # Show summary
    Show-Summary
    
    # Show detailed findings
    $severityFilter = $Severity
    if ($ShowAll) {
        $severityFilter = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
    }
    
    Show-DetailedFindings -SeverityFilter $severityFilter
}

# Run the script
Main
