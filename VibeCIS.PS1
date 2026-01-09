<#
.SYNOPSIS
    CIS Benchmark Assessment Script for Windows Server
.DESCRIPTION
    Tests common CIS benchmark controls for Windows Server hardening
.NOTES
    Run as Administrator for accurate results
#>

# Requires elevation
#Requires -RunAsAdministrator

Write-Host "=== CIS Benchmark Assessment for Windows Server ===" -ForegroundColor Cyan
Write-Host "Starting assessment at $(Get-Date)" -ForegroundColor Green
Write-Host ""

$results = @()

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue,
        [string]$Description
    )
    
    try {
        $actualValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        $compliant = ($actualValue -eq $ExpectedValue)
        
        return [PSCustomObject]@{
            Check = $Description
            Expected = $ExpectedValue
            Actual = $actualValue
            Compliant = $compliant
            Status = if($compliant) { "PASS" } else { "FAIL" }
        }
    }
    catch {
        return [PSCustomObject]@{
            Check = $Description
            Expected = $ExpectedValue
            Actual = "Not Found"
            Compliant = $false
            Status = "FAIL"
        }
    }
}

# Account Policies - Password Policy
Write-Host "[*] Checking Account Policies..." -ForegroundColor Yellow

# Password complexity
$secpol = seceditOutput = secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
$secpolContent = Get-Content "$env:TEMP\secpol.cfg"

$passwordComplexity = ($secpolContent | Select-String "PasswordComplexity").ToString().Split("=")[1].Trim()
$results += [PSCustomObject]@{
    Check = "Password must meet complexity requirements"
    Expected = "1 (Enabled)"
    Actual = $passwordComplexity
    Compliant = ($passwordComplexity -eq "1")
    Status = if($passwordComplexity -eq "1") { "PASS" } else { "FAIL" }
}

$minPasswordLength = ($secpolContent | Select-String "MinimumPasswordLength").ToString().Split("=")[1].Trim()
$results += [PSCustomObject]@{
    Check = "Minimum password length"
    Expected = "14 or greater"
    Actual = $minPasswordLength
    Compliant = ([int]$minPasswordLength -ge 14)
    Status = if([int]$minPasswordLength -ge 14) { "PASS" } else { "FAIL" }
}

$maxPasswordAge = ($secpolContent | Select-String "MaximumPasswordAge").ToString().Split("=")[1].Trim()
$results += [PSCustomObject]@{
    Check = "Maximum password age"
    Expected = "365 or less"
    Actual = "$maxPasswordAge days"
    Compliant = ([int]$maxPasswordAge -le 365 -and [int]$maxPasswordAge -gt 0)
    Status = if([int]$maxPasswordAge -le 365 -and [int]$maxPasswordAge -gt 0) { "PASS" } else { "FAIL" }
}

# Account Lockout Policy
$lockoutThreshold = ($secpolContent | Select-String "LockoutBadCount").ToString().Split("=")[1].Trim()
$results += [PSCustomObject]@{
    Check = "Account lockout threshold"
    Expected = "10 or fewer (but not 0)"
    Actual = $lockoutThreshold
    Compliant = ([int]$lockoutThreshold -le 10 -and [int]$lockoutThreshold -gt 0)
    Status = if([int]$lockoutThreshold -le 10 -and [int]$lockoutThreshold -gt 0) { "PASS" } else { "FAIL" }
}

Remove-Item "$env:TEMP\secpol.cfg" -Force

# Security Options
Write-Host "[*] Checking Security Options..." -ForegroundColor Yellow

$results += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ExpectedValue 1 `
    -Description "Accounts: Limit local account use of blank passwords"

$results += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ExpectedValue 1 `
    -Description "Network security: Do not store LAN Manager hash"

$results += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ExpectedValue 1 `
    -Description "Microsoft network server: Digitally sign communications (always)"

$results += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ExpectedValue 1 `
    -Description "Network access: Do not allow anonymous enumeration of SAM accounts"

$results += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ExpectedValue 1 `
    -Description "User Account Control: Run all administrators in Admin Approval Mode"

$results += Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 2 `
    -Description "User Account Control: Behavior of the elevation prompt for administrators"

# Windows Firewall
Write-Host "[*] Checking Windows Firewall..." -ForegroundColor Yellow

$firewallProfiles = @("Domain", "Public", "Private")
foreach ($profile in $firewallProfiles) {
    $fwState = (Get-NetFirewallProfile -Name $profile).Enabled
    $results += [PSCustomObject]@{
        Check = "Windows Firewall: $profile Profile - State"
        Expected = "True (Enabled)"
        Actual = $fwState
        Compliant = $fwState
        Status = if($fwState) { "PASS" } else { "FAIL" }
    }
}

# Audit Policies
Write-Host "[*] Checking Audit Policies..." -ForegroundColor Yellow

$auditChecks = @{
    "Credential Validation" = "Success and Failure"
    "Logon" = "Success and Failure"
    "Account Lockout" = "Failure"
    "Security Group Management" = "Success"
    "User Account Management" = "Success and Failure"
}

foreach ($category in $auditChecks.Keys) {
    $auditSetting = auditpol /get /subcategory:"$category" | Select-String -Pattern "Success|Failure"
    $results += [PSCustomObject]@{
        Check = "Audit Policy: $category"
        Expected = $auditChecks[$category]
        Actual = $auditSetting.ToString().Trim()
        Compliant = $auditSetting -match $auditChecks[$category].Replace(" and ", ".*")
        Status = if($auditSetting -match $auditChecks[$category].Replace(" and ", ".*")) { "PASS" } else { "FAIL" }
    }
}

# Services
Write-Host "[*] Checking Service Configurations..." -ForegroundColor Yellow

$dangerousServices = @{
    "RemoteRegistry" = "Disabled"
    "TlntSvr" = "Disabled"  # Telnet
    "SSDPSRV" = "Disabled"  # SSDP Discovery
}

foreach ($service in $dangerousServices.Keys) {
    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($svc) {
        $results += [PSCustomObject]@{
            Check = "Service: $service"
            Expected = $dangerousServices[$service]
            Actual = $svc.StartType
            Compliant = ($svc.StartType -eq $dangerousServices[$service])
            Status = if($svc.StartType -eq $dangerousServices[$service]) { "PASS" } else { "FAIL" }
        }
    }
}

# SMB Settings
Write-Host "[*] Checking SMB Configuration..." -ForegroundColor Yellow

$results += Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ExpectedValue 0 `
    -Description "SMBv1 Protocol Disabled"

# Display Results
Write-Host ""
Write-Host "=== Assessment Results ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

# Summary
$totalChecks = $results.Count
$passed = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$failed = $totalChecks - $passed
$compliancePercent = [math]::Round(($passed / $totalChecks) * 100, 2)

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "Total Checks: $totalChecks" -ForegroundColor White
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host "Compliance: $compliancePercent%" -ForegroundColor $(if($compliancePercent -ge 80) { "Green" } else { "Red" })
