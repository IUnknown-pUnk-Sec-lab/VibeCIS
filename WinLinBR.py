#!/usr/bin/env python3
"""
Security-Focused Build Review Script
Comprehensive security assessment for Windows and Linux builds

Author: Security Assessment Tool
Version: 1.0
"""

import subprocess
import os
import re
import json
import argparse
import platform
import socket
from datetime import datetime
from pathlib import Path


class BuildReviewScanner:
    """Security-focused build review scanner"""
    
    def __init__(self, output_format='json'):
        self.output_format = output_format
        self.results = []
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.hostname = socket.gethostname()
        self.os_version = platform.platform()
        
        self.critical = 0
        self.high = 0
        self.medium = 0
        self.low = 0
        self.info = 0
        
    def run_command(self, cmd, shell=True, powershell=False):
        """Execute system command and return output"""
        try:
            if powershell and self.is_windows:
                cmd = f'powershell.exe -NoProfile -Command "{cmd}"'
            
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return "", str(e), -1
    
    def add_finding(self, category, title, severity, description, evidence="", recommendation=""):
        """Add security finding"""
        finding = {
            'category': category,
            'title': title,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(finding)
        
        if severity == 'CRITICAL':
            self.critical += 1
        elif severity == 'HIGH':
            self.high += 1
        elif severity == 'MEDIUM':
            self.medium += 1
        elif severity == 'LOW':
            self.low += 1
        else:
            self.info += 1
    
    def check_system_info(self):
        """Gather system information"""
        print("[*] Gathering System Information...")
        
        if self.is_windows:
            stdout, _, _ = self.run_command("systeminfo", powershell=False)
            self.add_finding("System Info", "Windows System Information", "INFO",
                           "Basic system information gathered", stdout[:1000])
            
            # Get hotfixes
            stdout, _, _ = self.run_command("Get-HotFix | Format-Table -AutoSize", powershell=True)
            self.add_finding("System Info", "Installed Hotfixes", "INFO",
                           "List of installed Windows updates", stdout[:2000])
        
        elif self.is_linux:
            stdout, _, _ = self.run_command("uname -a")
            self.add_finding("System Info", "Linux System Information", "INFO",
                           "Basic system information", stdout)
            
            stdout, _, _ = self.run_command("cat /etc/os-release")
            self.add_finding("System Info", "OS Release Information", "INFO",
                           "Distribution information", stdout)
    
    def check_user_accounts(self):
        """Check for security issues with user accounts"""
        print("[*] Checking User Accounts and Groups...")
        
        if self.is_windows:
            # Check for accounts with passwords that don't expire
            stdout, _, _ = self.run_command(
                "Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true} | Select-Object Name,Enabled,PasswordNeverExpires",
                powershell=True
            )
            if stdout and "Name" in stdout:
                lines = [l for l in stdout.split('\n') if l.strip() and 'Name' not in l and '---' not in l]
                if lines:
                    self.add_finding("User Accounts", "Accounts with Non-Expiring Passwords", "HIGH",
                                   "Found accounts with passwords set to never expire",
                                   stdout,
                                   "Set password expiration policies for all accounts")
            
            # Check local administrators
            stdout, _, _ = self.run_command(
                "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass",
                powershell=True
            )
            admin_count = len([l for l in stdout.split('\n') if l.strip() and 'Name' not in l and '---' not in l])
            if admin_count > 2:
                self.add_finding("User Accounts", "Multiple Local Administrators", "MEDIUM",
                                f"Found {admin_count} members in local Administrators group",
                                stdout,
                                "Review and minimize local administrator membership")
            else:
                self.add_finding("User Accounts", "Local Administrator Count", "INFO",
                               f"Local Administrators group has {admin_count} members", stdout)
            
            # Check guest account
            stdout, _, _ = self.run_command(
                "Get-LocalUser -Name 'Guest' | Select-Object Name,Enabled",
                powershell=True
            )
            if "True" in stdout:
                self.add_finding("User Accounts", "Guest Account Enabled", "HIGH",
                               "Guest account is enabled",
                               stdout,
                               "Disable the Guest account: Disable-LocalUser -Name 'Guest'")
            
            # Check for blank passwords
            stdout, _, _ = self.run_command(
                "Get-LocalUser | Where-Object {$_.PasswordRequired -eq $false} | Select-Object Name,PasswordRequired",
                powershell=True
            )
            if stdout and len(stdout.split('\n')) > 3:
                self.add_finding("User Accounts", "Accounts Without Password Requirement", "CRITICAL",
                               "Found accounts that don't require passwords",
                               stdout,
                               "Enable password requirements for all accounts")
        
        elif self.is_linux:
            # Check for UID 0 accounts
            stdout, _, _ = self.run_command("awk -F: '($3 == 0) {print $1}' /etc/passwd")
            uid0_accounts = [a for a in stdout.split('\n') if a.strip()]
            if len(uid0_accounts) > 1:
                self.add_finding("User Accounts", "Multiple UID 0 Accounts", "CRITICAL",
                               f"Found {len(uid0_accounts)} accounts with UID 0: {', '.join(uid0_accounts)}",
                               stdout,
                               "Remove or change UID for non-root accounts with UID 0")
            
            # Check for empty passwords
            stdout, _, _ = self.run_command("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
            if stdout:
                self.add_finding("User Accounts", "Accounts with Empty Passwords", "CRITICAL",
                               f"Found accounts with empty passwords: {stdout}",
                               stdout,
                               "Lock or set passwords for these accounts immediately")
            
            # Check password aging
            stdout, _, _ = self.run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")
            if stdout:
                parts = stdout.split()
                if len(parts) >= 2:
                    days = parts[-1]
                    try:
                        days_int = int(days)
                        if days_int > 90:
                            self.add_finding("User Accounts", "Password Expiration Too Long", "MEDIUM",
                                           f"Password expiration set to {days} days (recommended: 90 or less)",
                                           stdout,
                                           "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs")
                        else:
                            self.add_finding("User Accounts", "Password Expiration Policy", "INFO",
                                           f"Password expiration is set to {days} days", stdout)
                    except ValueError:
                        self.add_finding("User Accounts", "Password Expiration Policy", "INFO",
                                       f"Password expiration setting: {days}", stdout)
            
            # Check for users with login shells
            stdout, _, _ = self.run_command("awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) {print $1}' /etc/passwd")
            user_count = len([u for u in stdout.split('\n') if u.strip()])
            self.add_finding("User Accounts", "Users with Login Shells", "INFO",
                           f"Found {user_count} users with login shells", stdout)
    
    def check_network_services(self):
        """Check network services and open ports"""
        print("[*] Checking Network Services...")
        
        if self.is_windows:
            # Check listening ports
            stdout, _, _ = self.run_command(
                "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -AutoSize",
                powershell=True
            )
            
            risky_ports = []
            for line in stdout.split('\n'):
                if any(port in line for port in ['21', '23', '135', '139', '445', '3389']):
                    risky_ports.append(line.strip())
            
            if risky_ports:
                self.add_finding("Network Services", "Potentially Risky Open Ports", "HIGH",
                               "Found potentially risky ports open",
                               '\n'.join(risky_ports),
                               "Review necessity of these services and restrict access")
            
            self.add_finding("Network Services", "Listening TCP Ports", "INFO",
                           "All listening TCP ports", stdout[:2000])
            
            # Check Windows Firewall
            stdout, _, _ = self.run_command(
                "Get-NetFirewallProfile | Select-Object Name,Enabled",
                powershell=True
            )
            if "False" in stdout:
                self.add_finding("Network Services", "Firewall Disabled", "CRITICAL",
                               "Windows Firewall is disabled on one or more profiles",
                               stdout,
                               "Enable Windows Firewall on all profiles")
            
            # Check for SMBv1
            stdout, _, _ = self.run_command(
                "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
                powershell=True
            )
            if "True" in stdout:
                self.add_finding("Network Services", "SMBv1 Enabled", "HIGH",
                               "SMBv1 protocol is enabled (vulnerable to EternalBlue)",
                               stdout,
                               "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false")
            
            # Check RDP settings
            stdout, _, rc = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections'",
                powershell=True
            )
            if "fDenyTSConnections" in stdout and ": 0" in stdout:
                self.add_finding("Network Services", "RDP Enabled", "MEDIUM",
                               "Remote Desktop Protocol is enabled",
                               stdout,
                               "Review RDP necessity, enable NLA, and restrict access via firewall")
        
        elif self.is_linux:
            # Check listening ports - only flag if actually found
            stdout, _, rc = self.run_command("ss -tlnp")
            if rc != 0:
                stdout, _, _ = self.run_command("netstat -tlnp")
            
            # Only report risky ports if we have valid output
            if stdout and rc == 0:
                risky_ports = []
                for line in stdout.split('\n'):
                    # Check for specific risky ports
                    if ':21 ' in line or ':21\t' in line:  # FTP
                        risky_ports.append(f"FTP (21): {line.strip()}")
                    elif ':23 ' in line or ':23\t' in line:  # Telnet
                        risky_ports.append(f"Telnet (23): {line.strip()}")
                    elif ':69 ' in line or ':69\t' in line:  # TFTP
                        risky_ports.append(f"TFTP (69): {line.strip()}")
                    elif ':111 ' in line or ':111\t' in line:  # RPC
                        risky_ports.append(f"RPC (111): {line.strip()}")
                    elif ':512 ' in line or ':512\t' in line:  # rexec
                        risky_ports.append(f"rexec (512): {line.strip()}")
                    elif ':513 ' in line or ':513\t' in line:  # rlogin
                        risky_ports.append(f"rlogin (513): {line.strip()}")
                    elif ':514 ' in line or ':514\t' in line:  # rsh
                        risky_ports.append(f"rsh (514): {line.strip()}")
                
                if risky_ports:
                    self.add_finding("Network Services", "Potentially Risky Open Ports", "HIGH",
                                   f"Found {len(risky_ports)} potentially risky ports listening",
                                   '\n'.join(risky_ports),
                                   "Review necessity of these services and restrict access")
                
                self.add_finding("Network Services", "Listening TCP Ports", "INFO",
                               "All listening TCP ports", stdout[:2000])
            
            # Check for unnecessary services - only report if actually running
            dangerous_services = ['telnet', 'rsh', 'rlogin', 'vsftpd', 'xinetd', 'rsh-server', 'rlogin-server', 'telnet-server']
            for service in dangerous_services:
                # First check if service unit exists
                check_stdout, _, check_rc = self.run_command(f"systemctl list-unit-files {service}.service 2>/dev/null")
                
                # Only proceed if service unit exists
                if check_rc == 0 and service in check_stdout:
                    stdout, _, rc = self.run_command(f"systemctl is-active {service}")
                    if rc == 0 and "active" in stdout:
                        self.add_finding("Network Services", f"Insecure Service Running: {service}", "HIGH",
                                       f"Insecure service {service} is running",
                                       stdout,
                                       f"Stop and disable {service}: systemctl stop {service} && systemctl disable {service}")
            
            # Check SSH configuration
            if os.path.exists("/etc/ssh/sshd_config"):
                try:
                    with open("/etc/ssh/sshd_config", 'r') as f:
                        ssh_config = f.read()
                    
                    issues = []
                    
                    # Check for explicitly enabled bad settings (not commented out)
                    config_lines = [line.strip() for line in ssh_config.split('\n') 
                                   if line.strip() and not line.strip().startswith('#')]
                    
                    for line in config_lines:
                        if line.startswith('PermitRootLogin') and 'yes' in line.lower():
                            issues.append("Root login via SSH is explicitly permitted")
                        elif line.startswith('PermitEmptyPasswords') and 'yes' in line.lower():
                            issues.append("Empty passwords are explicitly permitted")
                    
                    # Check if password auth is the only method
                    has_pubkey = any('PubkeyAuthentication yes' in line for line in config_lines)
                    has_password = any('PasswordAuthentication yes' in line for line in config_lines)
                    
                    if has_password and not has_pubkey:
                        issues.append("Only password authentication enabled (pubkey auth not found)")
                    
                    if issues:
                        self.add_finding("Network Services", "SSH Configuration Issues", "HIGH",
                                       '\n'.join(issues),
                                       '\n'.join(issues),
                                       "Harden SSH configuration: disable root login, use key-based auth, disable empty passwords")
                    else:
                        self.add_finding("Network Services", "SSH Configuration", "INFO",
                                       "SSH configuration appears properly hardened", "")
                except Exception as e:
                    self.add_finding("Network Services", "SSH Configuration Check Failed", "LOW",
                                   f"Could not read SSH configuration: {str(e)}", "", "")
    
    def check_security_software(self):
        """Check antivirus and security software"""
        print("[*] Checking Security Software...")
        
        if self.is_windows:
            # Check Windows Defender status
            stdout, _, _ = self.run_command(
                "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,AntispywareEnabled",
                powershell=True
            )
            
            if "False" in stdout:
                self.add_finding("Security Software", "Windows Defender Protection Disabled", "CRITICAL",
                               "One or more Windows Defender protections are disabled",
                               stdout,
                               "Enable all Windows Defender protections")
            else:
                self.add_finding("Security Software", "Windows Defender Status", "INFO",
                               "Windows Defender protection status", stdout)
            
            # Check for definition updates
            stdout, _, _ = self.run_command(
                "Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated,AntispywareSignatureLastUpdated",
                powershell=True
            )
            self.add_finding("Security Software", "Windows Defender Definitions", "INFO",
                           "Antivirus definition update status", stdout)
            
            # Check BitLocker status
            stdout, _, _ = self.run_command(
                "Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,EncryptionPercentage",
                powershell=True
            )
            if "Off" in stdout or "ProtectionStatus" not in stdout:
                self.add_finding("Security Software", "BitLocker Not Enabled", "MEDIUM",
                               "BitLocker drive encryption is not enabled",
                               stdout,
                               "Enable BitLocker encryption for sensitive data protection")
            else:
                self.add_finding("Security Software", "BitLocker Status", "INFO",
                               "BitLocker encryption status", stdout)
        
        elif self.is_linux:
            # Check for SELinux/AppArmor
            stdout, _, rc = self.run_command("getenforce")
            if rc == 0:
                if "Enforcing" in stdout:
                    self.add_finding("Security Software", "SELinux Status", "INFO",
                                   "SELinux is in enforcing mode", stdout)
                else:
                    self.add_finding("Security Software", "SELinux Not Enforcing", "HIGH",
                                   f"SELinux is in {stdout} mode",
                                   stdout,
                                   "Enable SELinux enforcing mode for mandatory access control")
            else:
                stdout, _, rc = self.run_command("systemctl is-active apparmor")
                if "active" in stdout:
                    self.add_finding("Security Software", "AppArmor Status", "INFO",
                                   "AppArmor is active", stdout)
                else:
                    self.add_finding("Security Software", "No MAC System Active", "HIGH",
                                   "Neither SELinux nor AppArmor is active",
                                   "",
                                   "Enable SELinux or AppArmor for mandatory access control")
            
            # Check for antivirus
            av_present = False
            for av in ['clamav', 'rkhunter', 'chkrootkit']:
                stdout, _, rc = self.run_command(f"which {av}")
                if rc == 0:
                    av_present = True
                    self.add_finding("Security Software", f"{av} Installed", "INFO",
                                   f"{av} is installed", stdout)
            
            if not av_present:
                self.add_finding("Security Software", "No Antivirus Detected", "MEDIUM",
                               "No common antivirus software detected",
                               "",
                               "Consider installing ClamAV or similar antivirus solution")
    
    def check_installed_software(self):
        """Check for vulnerable or unauthorized software"""
        print("[*] Checking Installed Software...")
        
        if self.is_windows:
            # Check installed applications
            stdout, _, _ = self.run_command(
                "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize",
                powershell=True
            )
            self.add_finding("Installed Software", "Installed Applications (32-bit)", "INFO",
                           "List of installed 32-bit applications", stdout[:3000])
            
            stdout, _, _ = self.run_command(
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize",
                powershell=True
            )
            self.add_finding("Installed Software", "Installed Applications (64-bit)", "INFO",
                           "List of installed 64-bit applications", stdout[:3000])
            
            # Check for risky software
            risky_software = ['TeamViewer', 'AnyDesk', 'VNC', 'LogMeIn', 'GoToMyPC', 'Chrome Remote Desktop']
            for software in risky_software:
                stdout, _, _ = self.run_command(
                    f"Get-ItemProperty HKLM:\\Software\\*\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {{$_.DisplayName -like '*{software}*'}} | Select-Object DisplayName",
                    powershell=True
                )
                if stdout and software.lower() in stdout.lower():
                    self.add_finding("Installed Software", f"Remote Access Software: {software}", "MEDIUM",
                                   f"Remote access software {software} is installed",
                                   stdout,
                                   "Review necessity and ensure proper access controls")
        
        elif self.is_linux:
            # List installed packages
            stdout, _, rc = self.run_command("rpm -qa")
            if rc != 0:
                stdout, _, _ = self.run_command("dpkg -l")
            
            package_count = len([p for p in stdout.split('\n') if p.strip()])
            self.add_finding("Installed Software", "Installed Packages", "INFO",
                           f"Total packages installed: {package_count}", stdout[:3000])
            
            # Check for development tools in production
            dev_tools = ['gcc', 'g++', 'make', 'gdb']
            found_dev_tools = []
            for tool in dev_tools:
                stdout, _, rc = self.run_command(f"which {tool}")
                if rc == 0:
                    found_dev_tools.append(tool)
            
            if found_dev_tools:
                self.add_finding("Installed Software", "Development Tools Present", "LOW",
                               f"Development tools found: {', '.join(found_dev_tools)}",
                               "",
                               "Remove development tools from production systems to reduce attack surface")
    
    def check_audit_logging(self):
        """Check audit and logging configuration"""
        print("[*] Checking Audit and Logging...")
        
        if self.is_windows:
            # Check audit policies
            stdout, _, _ = self.run_command("auditpol /get /category:*", powershell=False)
            
            if "No Auditing" in stdout or "Failure" not in stdout:
                self.add_finding("Audit & Logging", "Insufficient Audit Policies", "HIGH",
                               "Audit policies may not be configured to log security events",
                               stdout[:2000],
                               "Configure comprehensive audit policies via Group Policy or auditpol")
            else:
                self.add_finding("Audit & Logging", "Audit Policies", "INFO",
                               "Current audit policy configuration", stdout[:2000])
            
            # Check event log configuration
            stdout, _, _ = self.run_command(
                "Get-EventLog -LogName Security -Newest 1 | Select-Object TimeGenerated",
                powershell=True
            )
            if stdout:
                self.add_finding("Audit & Logging", "Security Event Log Active", "INFO",
                               "Security event log is receiving events", stdout)
            else:
                self.add_finding("Audit & Logging", "Security Event Log Issue", "HIGH",
                               "Unable to retrieve security event log entries",
                               "",
                               "Verify security event log is enabled and receiving events")
        
        elif self.is_linux:
            # Check auditd
            stdout, _, rc = self.run_command("systemctl is-active auditd")
            if "active" not in stdout:
                self.add_finding("Audit & Logging", "auditd Not Running", "HIGH",
                               "Linux audit daemon (auditd) is not running",
                               stdout,
                               "Enable and start auditd: systemctl enable auditd && systemctl start auditd")
            else:
                self.add_finding("Audit & Logging", "auditd Status", "INFO",
                               "Linux audit daemon is active", stdout)
            
            # Check for audit rules
            stdout, _, _ = self.run_command("auditctl -l")
            rule_count = len([r for r in stdout.split('\n') if r.strip() and not r.startswith('No rules')])
            if rule_count < 10:
                self.add_finding("Audit & Logging", "Few Audit Rules Configured", "MEDIUM",
                               f"Only {rule_count} audit rules configured",
                               stdout[:1000],
                               "Configure comprehensive audit rules for security monitoring")
            else:
                self.add_finding("Audit & Logging", "Audit Rules", "INFO",
                               f"{rule_count} audit rules configured", stdout[:1000])
            
            # Check rsyslog
            stdout, _, rc = self.run_command("systemctl is-active rsyslog")
            if "active" not in stdout:
                self.add_finding("Audit & Logging", "rsyslog Not Running", "MEDIUM",
                               "System logging daemon (rsyslog) is not running",
                               stdout,
                               "Enable and start rsyslog: systemctl enable rsyslog && systemctl start rsyslog")
    
    def check_system_hardening(self):
        """Check system hardening settings"""
        print("[*] Checking System Hardening...")
        
        if self.is_windows:
            # Check UAC settings
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA,ConsentPromptBehaviorAdmin",
                powershell=True
            )
            if "EnableLUA" in stdout and ": 0" in stdout:
                self.add_finding("System Hardening", "UAC Disabled", "CRITICAL",
                               "User Account Control (UAC) is disabled",
                               stdout,
                               "Enable UAC for elevation prompts")
            
            # Check Windows Update settings
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue",
                powershell=True
            )
            self.add_finding("System Hardening", "Windows Update Configuration", "INFO",
                           "Windows Update policy configuration", stdout)
            
            # Check LSA protection
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue",
                powershell=True
            )
            if "RunAsPPL" not in stdout or ": 0" in stdout:
                self.add_finding("System Hardening", "LSA Protection Not Enabled", "HIGH",
                               "LSA Protection (RunAsPPL) is not enabled",
                               stdout,
                               "Enable LSA Protection to prevent credential dumping attacks")
            
            # Check Credential Guard
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\DeviceGuard' -ErrorAction SilentlyContinue",
                powershell=True
            )
            if "EnableVirtualizationBasedSecurity" not in stdout:
                self.add_finding("System Hardening", "Credential Guard Not Configured", "MEDIUM",
                               "Credential Guard (VBS) is not configured",
                               "",
                               "Consider enabling Credential Guard on supported systems")
        
        elif self.is_linux:
            # Check kernel parameters
            hardening_params = {
                'kernel.randomize_va_space': '2',
                'kernel.dmesg_restrict': '1',
                'kernel.kptr_restrict': '2',
                'net.ipv4.conf.all.send_redirects': '0',
                'net.ipv4.conf.default.send_redirects': '0',
                'net.ipv4.conf.all.accept_source_route': '0',
                'net.ipv4.conf.default.accept_source_route': '0',
                'net.ipv4.conf.all.accept_redirects': '0',
                'net.ipv4.conf.default.accept_redirects': '0',
                'net.ipv4.tcp_syncookies': '1',
                'net.ipv4.icmp_echo_ignore_broadcasts': '1',
                'fs.suid_dumpable': '0'
            }
            
            issues = []
            checked_params = []
            
            for param, expected in hardening_params.items():
                stdout, _, rc = self.run_command(f"sysctl {param} 2>/dev/null")
                if rc == 0 and stdout:
                    checked_params.append(param)
                    actual_value = stdout.split('=')[-1].strip() if '=' in stdout else ""
                    if actual_value != expected:
                        issues.append(f"{param} = {actual_value} (expected: {expected})")
            
            if issues:
                self.add_finding("System Hardening", "Kernel Parameters Not Hardened", "MEDIUM",
                               f"Found {len(issues)} kernel parameters not set to secure values",
                               '\n'.join(issues[:10]),  # Limit output
                               "Configure secure kernel parameters in /etc/sysctl.conf or /etc/sysctl.d/")
            elif checked_params:
                self.add_finding("System Hardening", "Kernel Hardening", "INFO",
                               f"Checked {len(checked_params)} kernel hardening parameters - all properly configured", "")
            
            # Check for compiler restrictions
            stdout, _, _ = self.run_command("ls -la /usr/bin/gcc /usr/bin/cc 2>/dev/null")
            if stdout:
                perms = stdout.split('\n')[0].split()[0] if stdout.split('\n') else ""
                if 'x' in perms[7:]:  # World executable
                    self.add_finding("System Hardening", "Compiler Accessible to All Users", "LOW",
                                   "Compiler binaries are executable by all users",
                                   stdout,
                                   "Restrict compiler access on production systems")
    
    def check_security_posture(self):
        """Check security posture from pentest perspective - reconnaissance only"""
        print("[*] Checking Security Posture (Reconnaissance)...")
        
        if self.is_windows:
            # Check Windows Defender exclusions
            stdout, _, _ = self.run_command(
                "Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess",
                powershell=True
            )
            if stdout and len(stdout) > 100:
                exclusion_count = len([l for l in stdout.split('\n') if l.strip() and ':' in l])
                if exclusion_count > 5:
                    self.add_finding("Security Posture", "Multiple AV Exclusions Configured", "MEDIUM",
                                   f"Found {exclusion_count} antivirus exclusions configured",
                                   stdout[:1500],
                                   "Review AV exclusions - excessive exclusions reduce protection and could be abused")
            
            # Check PowerShell execution policy
            stdout, _, _ = self.run_command("Get-ExecutionPolicy -List", powershell=True)
            if "Unrestricted" in stdout or "Bypass" in stdout:
                self.add_finding("Security Posture", "Permissive PowerShell Execution Policy", "MEDIUM",
                               "PowerShell execution policy allows unrestricted script execution",
                               stdout,
                               "Set execution policy to RemoteSigned or AllSigned")
            
            # Check for PowerShell logging
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue",
                powershell=True
            )
            if not stdout or "EnableScriptBlockLogging" not in stdout:
                self.add_finding("Security Posture", "PowerShell Script Block Logging Disabled", "HIGH",
                               "PowerShell script block logging is not enabled",
                               "",
                               "Enable PowerShell script block logging for visibility into PowerShell activity")
            
            # Check PowerShell transcription
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription' -ErrorAction SilentlyContinue",
                powershell=True
            )
            if not stdout or "EnableTranscripting" not in stdout:
                self.add_finding("Security Posture", "PowerShell Transcription Disabled", "MEDIUM",
                               "PowerShell transcription logging is not enabled",
                               "",
                               "Enable PowerShell transcription for complete PowerShell session logging")
            
            # Check AMSI providers
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\*' -ErrorAction SilentlyContinue",
                powershell=True
            )
            if stdout:
                self.add_finding("Security Posture", "AMSI Providers", "INFO",
                               "AMSI (Antimalware Scan Interface) providers registered", stdout[:500])
            
            # Check WMIC availability
            stdout, _, rc = self.run_command("where wmic", powershell=False)
            if rc == 0:
                self.add_finding("Security Posture", "WMIC Available", "INFO",
                               "WMIC is available (commonly used for reconnaissance and lateral movement)", stdout)
            
            # Check Windows Remote Management
            stdout, _, _ = self.run_command(
                "Get-Service WinRM | Select-Object Status,StartType",
                powershell=True
            )
            if "Running" in stdout:
                self.add_finding("Security Posture", "WinRM Service Running", "MEDIUM",
                               "Windows Remote Management service is running",
                               stdout,
                               "If WinRM is not required, disable it. If required, ensure proper authentication and network restrictions")
            
            # Check for saved credentials
            stdout, _, _ = self.run_command("cmdkey /list", powershell=False)
            if stdout and "Target:" in stdout:
                cred_count = stdout.count("Target:")
                self.add_finding("Security Posture", "Saved Credentials Present", "HIGH",
                               f"Found {cred_count} saved credentials in credential manager",
                               stdout[:1000],
                               "Review saved credentials - these can be extracted by attackers with local access")
            
            # Check for interesting file shares
            stdout, _, _ = self.run_command("net share", powershell=False)
            shares = [l for l in stdout.split('\n') if l.strip() and not l.startswith('-') and 'Share name' not in l]
            non_default = [s for s in shares if not any(x in s for x in ['C$', 'ADMIN$', 'IPC$', 'print$'])]
            if non_default:
                self.add_finding("Security Posture", "Non-Default Shares Present", "MEDIUM",
                               f"Found {len(non_default)} non-default file shares",
                               '\n'.join(non_default[:10]),
                               "Review share permissions and necessity of exposed shares")
            
            # Check share permissions
            stdout, _, _ = self.run_command(
                "Get-SmbShare | Select-Object Name,Path,Description | Format-Table -AutoSize",
                powershell=True
            )
            self.add_finding("Security Posture", "SMB Share Enumeration", "INFO",
                           "Current SMB shares configuration", stdout[:1500])
            
            # Check LLMNR/NetBIOS
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue",
                powershell=True
            )
            if "EnableMulticast" not in stdout or ": 0" not in stdout:
                self.add_finding("Security Posture", "LLMNR Enabled", "HIGH",
                               "LLMNR (Link-Local Multicast Name Resolution) is enabled",
                               "",
                               "Disable LLMNR to prevent name resolution poisoning attacks (Responder, NTLM relay)")
            
            # Check SMB signing
            stdout, _, _ = self.run_command(
                "Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSecuritySignature",
                powershell=True
            )
            if "False" in stdout:
                self.add_finding("Security Posture", "SMB Signing Not Required", "HIGH",
                               "SMB signing is not required",
                               stdout,
                               "Enable required SMB signing to prevent relay attacks")
            
            # Check WPAD
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name AutoDetect -ErrorAction SilentlyContinue",
                powershell=True
            )
            if "AutoDetect" in stdout and ": 1" in stdout:
                self.add_finding("Security Posture", "WPAD Enabled", "MEDIUM",
                               "Web Proxy Auto-Discovery (WPAD) is enabled",
                               stdout,
                               "Disable WPAD to prevent WPAD spoofing attacks")
            
            # Check for AutoAdminLogon
            stdout, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name AutoAdminLogon -ErrorAction SilentlyContinue",
                powershell=True
            )
            if "AutoAdminLogon" in stdout and ": 1" in stdout:
                self.add_finding("Security Posture", "Auto Admin Logon Enabled", "CRITICAL",
                               "Automatic administrator login is enabled",
                               stdout,
                               "Disable AutoAdminLogon - credentials may be stored in clear text in registry")
            
            # Check for AlwaysInstallElevated
            stdout1, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue",
                powershell=True
            )
            stdout2, _, _ = self.run_command(
                "Get-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue",
                powershell=True
            )
            if "AlwaysInstallElevated" in stdout1 and "AlwaysInstallElevated" in stdout2:
                self.add_finding("Security Posture", "AlwaysInstallElevated Enabled", "CRITICAL",
                               "AlwaysInstallElevated is enabled in both HKLM and HKCU",
                               f"HKLM: {stdout1}\nHKCU: {stdout2}",
                               "Disable AlwaysInstallElevated - allows privilege escalation via MSI installers")
            
            # Check AppLocker policies
            stdout, _, _ = self.run_command(
                "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RuleCollections",
                powershell=True
            )
            if not stdout or len(stdout) < 50:
                self.add_finding("Security Posture", "No AppLocker Policies", "MEDIUM",
                               "AppLocker application control policies are not configured",
                               "",
                               "Consider implementing AppLocker to control which applications can run")
            else:
                self.add_finding("Security Posture", "AppLocker Enabled", "INFO",
                               "AppLocker application control is configured", stdout[:1000])
            
            # Check for unquoted service paths
            stdout, _, _ = self.run_command(
                "Get-WmiObject -Class Win32_Service | Where-Object {$_.PathName -notmatch '^\".+\"' -and $_.PathName -match '.+\\s.+' -and $_.StartMode -ne 'Disabled'} | Select-Object Name,PathName,StartMode | Format-List",
                powershell=True
            )
            if stdout and "PathName" in stdout:
                self.add_finding("Security Posture", "Unquoted Service Paths", "HIGH",
                               "Found services with unquoted paths containing spaces",
                               stdout[:2000],
                               "Quote service paths to prevent privilege escalation via path hijacking")
            
            # Check running processes for interesting targets
            stdout, _, _ = self.run_command(
                "Get-Process | Where-Object {$_.ProcessName -match 'lsass|winlogon|csrss'} | Select-Object ProcessName,Id | Format-Table",
                powershell=True
            )
            if stdout:
                self.add_finding("Security Posture", "Sensitive Processes Running", "INFO",
                               "Sensitive system processes (potential credential dump targets)", stdout)
        
        elif self.is_linux:
            # Check for writable system paths in PATH
            stdout, _, _ = self.run_command("echo $PATH")
            if stdout:
                paths = stdout.split(':')
                writable_paths = []
                for path in paths:
                    check_stdout, _, rc = self.run_command(f"test -w {path} && echo 'writable' 2>/dev/null")
                    if rc == 0 and 'writable' in check_stdout:
                        writable_paths.append(path)
                
                if writable_paths:
                    self.add_finding("Security Posture", "Writable Paths in $PATH", "HIGH",
                                   f"Found {len(writable_paths)} writable directories in PATH",
                                   '\n'.join(writable_paths),
                                   "Remove write permissions from system PATH directories to prevent binary hijacking")
            
            # Check for SUID/SGID binaries
            stdout, _, _ = self.run_command(
                "find / -type f \\( -perm -4000 -o -perm -2000 \\) -ls 2>/dev/null | head -50"
            )
            suid_count = len([l for l in stdout.split('\n') if l.strip()])
            if suid_count > 0:
                self.add_finding("Security Posture", "SUID/SGID Binaries", "MEDIUM",
                               f"Found {suid_count} SUID/SGID binaries (potential privilege escalation vectors)",
                               stdout[:2000],
                               "Review SUID/SGID binaries and remove unnecessary privileges")
            
            # Check for world-writable files in system directories
            stdout, _, _ = self.run_command(
                "find /etc /usr /bin /sbin -type f -perm -002 2>/dev/null | head -20"
            )
            if stdout:
                self.add_finding("Security Posture", "World-Writable System Files", "CRITICAL",
                               "Found world-writable files in system directories",
                               stdout,
                               "Remove world-write permissions from system files immediately")
            
            # Check for world-writable directories
            stdout, _, _ = self.run_command(
                "find / -type d -perm -002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null | head -20"
            )
            if stdout:
                writable_dirs = [d for d in stdout.split('\n') if d.strip()]
                if writable_dirs:
                    self.add_finding("Security Posture", "World-Writable Directories", "MEDIUM",
                                   f"Found {len(writable_dirs)} world-writable directories outside standard temp locations",
                                   '\n'.join(writable_dirs[:10]),
                                   "Review and restrict permissions on world-writable directories")
            
            # Check for files with no owner
            stdout, _, _ = self.run_command(
                "find / -nouser -o -nogroup 2>/dev/null | head -20"
            )
            if stdout:
                self.add_finding("Security Posture", "Files Without Owner", "LOW",
                               "Found files without valid user/group ownership",
                               stdout,
                               "Assign proper ownership or remove orphaned files")
            
            # Check sudo configuration
            stdout, _, rc = self.run_command("sudo -l 2>/dev/null")
            if rc == 0 and stdout:
                if "NOPASSWD" in stdout:
                    self.add_finding("Security Posture", "Passwordless Sudo Configured", "HIGH",
                                   "User can run commands with sudo without password",
                                   stdout[:1000],
                                   "Review sudo configuration - passwordless sudo increases privilege escalation risk")
                elif "(ALL)" in stdout or "(ALL : ALL)" in stdout:
                    self.add_finding("Security Posture", "Broad Sudo Privileges", "MEDIUM",
                                   "User has broad sudo privileges",
                                   stdout[:1000],
                                   "Restrict sudo access to only required commands")
            
            # Check sudoers file for dangerous configs
            if os.path.exists("/etc/sudoers"):
                try:
                    stdout, _, _ = self.run_command("cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | grep -v '^$'")
                    if "!authenticate" in stdout or "NOPASSWD" in stdout:
                        self.add_finding("Security Posture", "Risky Sudoers Configuration", "HIGH",
                                       "Sudoers file contains passwordless or unauthenticated entries",
                                       stdout[:1500],
                                       "Review and restrict sudoers configuration")
                except:
                    pass
            
            # Check for readable sensitive files
            sensitive_files = [
                '/etc/shadow',
                '/etc/gshadow',
                '/root/.ssh/id_rsa',
                '/root/.ssh/id_dsa',
                '/root/.bash_history',
                '/home/*/.ssh/id_rsa',
                '/home/*/.bash_history'
            ]
            
            readable_sensitive = []
            for filepath in sensitive_files:
                stdout, _, rc = self.run_command(f"test -r {filepath} && echo 'readable' 2>/dev/null")
                if rc == 0 and 'readable' in stdout:
                    readable_sensitive.append(filepath)
            
            if readable_sensitive:
                self.add_finding("Security Posture", "Readable Sensitive Files", "CRITICAL",
                               f"Found {len(readable_sensitive)} sensitive files readable by current user",
                               '\n'.join(readable_sensitive[:10]),
                               "Restrict permissions on sensitive files")
            
            # Check for SSH keys
            stdout, _, _ = self.run_command("find /home /root -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null")
            if stdout:
                key_count = len([k for k in stdout.split('\n') if k.strip()])
                self.add_finding("Security Posture", "SSH Private Keys Found", "INFO",
                               f"Found {key_count} SSH private keys on system",
                               stdout[:1000],
                               "Ensure SSH keys are properly protected and not world-readable")
            
            # Check for credentials in environment variables
            stdout, _, _ = self.run_command("env | grep -i 'pass\\|pwd\\|secret\\|key\\|token' | head -10")
            if stdout:
                self.add_finding("Security Posture", "Potential Credentials in Environment", "MEDIUM",
                               "Found environment variables that may contain credentials",
                               stdout,
                               "Avoid storing credentials in environment variables")
            
            # Check for interesting capabilities
            stdout, _, _ = self.run_command("getcap -r / 2>/dev/null | head -20")
            if stdout:
                self.add_finding("Security Posture", "Files with Capabilities", "MEDIUM",
                               "Found files with Linux capabilities set",
                               stdout,
                               "Review files with capabilities - some can be abused for privilege escalation")
            
            # Check for Docker socket access
            stdout, _, rc = self.run_command("test -w /var/run/docker.sock && echo 'writable' 2>/dev/null")
            if rc == 0 and 'writable' in stdout:
                self.add_finding("Security Posture", "Docker Socket Writable", "CRITICAL",
                               "Current user has write access to Docker socket",
                               "/var/run/docker.sock is writable",
                               "Docker socket access provides root-equivalent privileges")
            
            # Check for interesting groups
            stdout, _, _ = self.run_command("id")
            if stdout:
                risky_groups = ['docker', 'lxd', 'disk', 'video', 'sudo', 'wheel', 'adm']
                user_groups = stdout.lower()
                found_risky = [g for g in risky_groups if g in user_groups]
                
                if found_risky:
                    self.add_finding("Security Posture", "User in Privileged Groups", "HIGH",
                                   f"User is member of privileged groups: {', '.join(found_risky)}",
                                   stdout,
                                   "Membership in these groups may provide privilege escalation paths")
            
            # Check for NFS exports
            if os.path.exists("/etc/exports"):
                stdout, _, _ = self.run_command("cat /etc/exports | grep -v '^#' | grep -v '^$'")
                if stdout:
                    if "no_root_squash" in stdout:
                        self.add_finding("Security Posture", "NFS no_root_squash Configured", "CRITICAL",
                                       "NFS exports configured with no_root_squash",
                                       stdout,
                                       "Remove no_root_squash from NFS exports - allows root access from clients")
                    else:
                        self.add_finding("Security Posture", "NFS Exports Configured", "MEDIUM",
                                       "NFS exports are configured",
                                       stdout[:1000],
                                       "Review NFS export permissions and client restrictions")
            
            # Check for kernel modules that can be loaded
            stdout, _, _ = self.run_command("lsmod | head -20")
            self.add_finding("Security Posture", "Loaded Kernel Modules", "INFO",
                           "Currently loaded kernel modules", stdout)
            
            # Check for core dumps enabled
            stdout, _, _ = self.run_command("ulimit -c")
            if stdout and stdout.strip() != "0":
                self.add_finding("Security Posture", "Core Dumps Enabled", "MEDIUM",
                               f"Core dumps are enabled (limit: {stdout})",
                               stdout,
                               "Disable core dumps to prevent information disclosure")
            
            # Check for .rhosts or .netrc files
            stdout, _, _ = self.run_command("find /home /root -name '.rhosts' -o -name '.netrc' 2>/dev/null")
            if stdout:
                self.add_finding("Security Posture", "Legacy Authentication Files Found", "HIGH",
                               "Found .rhosts or .netrc files (legacy insecure authentication)",
                               stdout,
                               "Remove .rhosts and .netrc files - these use insecure authentication")
            
            # Check tmux/screen sessions
            stdout, _, _ = self.run_command("ls /tmp/tmux-* /var/run/screen 2>/dev/null")
            if stdout:
                self.add_finding("Security Posture", "Tmux/Screen Sessions Detected", "LOW",
                               "Active tmux or screen sessions detected",
                               stdout,
                               "Other users' tmux/screen sessions may contain sensitive information")
        """Check scheduled tasks and cron jobs"""
        print("[*] Checking Scheduled Tasks...")
        
        if self.is_windows:
            # Get scheduled tasks
            stdout, _, _ = self.run_command(
                "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName,TaskPath,State | Format-Table -AutoSize",
                powershell=True
            )
            
            task_count = len([l for l in stdout.split('\n') if l.strip() and 'TaskName' not in l and '---' not in l])
            self.add_finding("Scheduled Tasks", "Active Scheduled Tasks", "INFO",
                           f"Found {task_count} active scheduled tasks", stdout[:3000])
            
            # Check for suspicious task paths
            stdout, _, _ = self.run_command(
                "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*' -and $_.State -ne 'Disabled'} | Select-Object TaskName,TaskPath,Actions | Format-List",
                powershell=True
            )
            if stdout and len(stdout) > 100:
                self.add_finding("Scheduled Tasks", "Non-Microsoft Scheduled Tasks", "MEDIUM",
                               "Found active scheduled tasks not in Microsoft paths - review required",
                               stdout[:2000],
                               "Review non-Microsoft scheduled tasks for legitimacy")
        
        elif self.is_linux:
            # Check crontabs
            stdout, _, _ = self.run_command("crontab -l 2>/dev/null")
            if stdout and not "no crontab" in stdout.lower():
                self.add_finding("Scheduled Tasks", "Root Crontab", "INFO",
                               "Root user has crontab entries", stdout[:1000])
            
            # Check system-wide cron
            stdout, _, _ = self.run_command("ls -la /etc/cron.*/* 2>/dev/null | head -50")
            self.add_finding("Scheduled Tasks", "System Cron Jobs", "INFO",
                           "System-wide cron jobs", stdout[:2000])
            
            # Check at jobs
            stdout, _, _ = self.run_command("atq")
            if stdout:
                self.add_finding("Scheduled Tasks", "Pending at Jobs", "INFO",
                               "Pending at jobs", stdout)
    
    def run_all_checks(self):
        """Run all security checks"""
        print("\n" + "="*70)
        print(f"Security-Focused Build Review")
        print(f"System: {self.hostname}")
        print(f"OS: {self.os_version}")
        print("="*70 + "\n")
        
        self.check_system_info()
        self.check_user_accounts()
        self.check_network_services()
        self.check_security_software()
        self.check_installed_software()
        self.check_audit_logging()
        self.check_system_hardening()
        self.check_security_posture()
        self.check_scheduled_tasks()
    
    def generate_report(self, output_file=None):
        """Generate security assessment report"""
        total = len(self.results)
        
        summary = {
            'scan_date': datetime.now().isoformat(),
            'hostname': self.hostname,
            'os': self.os_version,
            'total_findings': total,
            'critical': self.critical,
            'high': self.high,
            'medium': self.medium,
            'low': self.low,
            'informational': self.info
        }
        
        report = {
            'summary': summary,
            'findings': self.results
        }
        
        if output_file:
            if self.output_format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
            elif self.output_format == 'csv':
                import csv
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['category', 'title', 'severity', 'description', 'evidence', 'recommendation'])
                    writer.writeheader()
                    writer.writerows(self.results)
            
            print(f"\n[+] Report saved to: {output_file}")
        
        return report
    
    def print_summary(self):
        """Print executive summary"""
        total = self.critical + self.high + self.medium + self.low + self.info
        
        print("\n" + "="*70)
        print("SECURITY ASSESSMENT SUMMARY")
        print("="*70)
        print(f"Total Findings:    {total}")
        print(f"CRITICAL:          {self.critical}")
        print(f"HIGH:              {self.high}")
        print(f"MEDIUM:            {self.medium}")
        print(f"LOW:               {self.low}")
        print(f"INFORMATIONAL:     {self.info}")
        print("="*70 + "\n")
    
    def print_detailed_findings(self, severity_filter=None):
        """Print detailed findings"""
        # Color codes
        RED = '\033[91m'
        ORANGE = '\033[93m'
        YELLOW = '\033[33m'
        BLUE = '\033[94m'
        GREY = '\033[90m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        
        severity_colors = {
            'CRITICAL': RED,
            'HIGH': ORANGE,
            'MEDIUM': YELLOW,
            'LOW': BLUE,
            'INFO': GREY
        }
        
        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity_filter and severity not in severity_filter:
                continue
            
            findings = [f for f in self.results if f['severity'] == severity]
            if not findings:
                continue
            
            color = severity_colors.get(severity, RESET)
            print(f"\n{color}{BOLD}{'='*70}")
            print(f"{severity} FINDINGS ({len(findings)})")
            print(f"{'='*70}{RESET}\n")
            
            for finding in findings:
                print(f"{color}[{severity}]{RESET} {BOLD}[{finding['category']}]{RESET} {finding['title']}")
                print(f"  ├─ {finding['description']}")
                
                if finding['evidence']:
                    evidence_preview = finding['evidence'][:200] + "..." if len(finding['evidence']) > 200 else finding['evidence']
                    print(f"  ├─ Evidence: {evidence_preview}")
                
                if finding['recommendation']:
                    print(f"  └─ {BOLD}Recommendation:{RESET} {finding['recommendation']}")
                
                print()


def main():
    parser = argparse.ArgumentParser(
        description='Security-Focused Build Review Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run full security scan
  python3 build_review.py --show-all
  
  # Show only critical and high findings
  python3 build_review.py --severity CRITICAL HIGH
  
  # Save report to file
  python3 build_review.py -o security_report.json --show-all
  
  # Windows: Run as Administrator
  # Linux: Run with sudo for complete checks
        '''
    )
    
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--show-all', action='store_true',
                       help='Show all findings including informational')
    parser.add_argument('--severity', nargs='+', 
                       choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                       help='Show only specified severity levels')
    
    args = parser.parse_args()
    
    # Check privileges
    if os.name == 'nt':
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("[!] Warning: Not running as Administrator. Some checks may be incomplete.")
    else:
        if os.geteuid() != 0:
            print("[!] Warning: Not running as root. Some checks may be incomplete.")
    
    print()
    
    scanner = BuildReviewScanner(output_format=args.format)
    scanner.run_all_checks()
    scanner.generate_report(args.output)
    scanner.print_summary()
    
    # Determine what to show
    severity_filter = args.severity if args.severity else None
    if args.show_all:
        severity_filter = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    elif not severity_filter:
        severity_filter = ['CRITICAL', 'HIGH', 'MEDIUM']
    
    scanner.print_detailed_findings(severity_filter)


if __name__ == '__main__':
    main()
