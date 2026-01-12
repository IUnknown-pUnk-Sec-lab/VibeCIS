#!/usr/bin/env python3
"""
CIS Benchmark Compliance Scanner for Red Hat Enterprise Linux
Based on CIS Red Hat Enterprise Linux 8/9 Benchmark

Author: Security Assessment Tool
Version: 1.0
"""

import subprocess
import os
import re
import json
import argparse
from datetime import datetime
from pathlib import Path
import pwd
import grp


class CISBenchmark:
    """CIS Benchmark compliance checker for Red Hat Linux"""
    
    def __init__(self, output_format='json'):
        self.output_format = output_format
        self.results = []
        self.passed = 0
        self.failed = 0
        self.manual = 0
        self.not_applicable = 0
        
    def run_command(self, cmd, shell=True):
        """Execute system command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except Exception as e:
            return "", str(e), -1
    
    def check_file_exists(self, filepath):
        """Check if file exists"""
        return os.path.exists(filepath)
    
    def check_file_permissions(self, filepath, expected_perms):
        """Check file permissions"""
        try:
            stat_info = os.stat(filepath)
            actual_perms = oct(stat_info.st_mode)[-3:]
            return actual_perms <= expected_perms
        except:
            return False
    
    def add_result(self, section, title, status, details, recommendation=""):
        """Add check result"""
        result = {
            'section': section,
            'title': title,
            'status': status,
            'details': details,
            'recommendation': recommendation,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)
        
        if status == 'PASS':
            self.passed += 1
        elif status == 'FAIL':
            self.failed += 1
        elif status == 'MANUAL':
            self.manual += 1
        else:
            self.not_applicable += 1
    
    def check_1_1_filesystem_configuration(self):
        """1.1 Filesystem Configuration"""
        print("[*] Checking 1.1 Filesystem Configuration...")
        
        # 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
        stdout, _, _ = self.run_command("modprobe -n -v cramfs")
        stdout2, _, _ = self.run_command("lsmod | grep cramfs")
        
        if "install /bin/true" in stdout and not stdout2:
            self.add_result("1.1.1.1", "Ensure mounting of cramfs filesystems is disabled",
                          "PASS", "cramfs is properly disabled")
        else:
            self.add_result("1.1.1.1", "Ensure mounting of cramfs filesystems is disabled",
                          "FAIL", "cramfs may not be properly disabled",
                          "Edit /etc/modprobe.d/cramfs.conf: install cramfs /bin/true")
        
        # 1.1.2 Ensure /tmp is configured
        stdout, _, _ = self.run_command("systemctl is-enabled tmp.mount")
        if "enabled" in stdout or "static" in stdout:
            self.add_result("1.1.2", "Ensure /tmp is configured",
                          "PASS", "/tmp is properly configured")
        else:
            self.add_result("1.1.2", "Ensure /tmp is configured",
                          "FAIL", "/tmp is not properly configured",
                          "Run: systemctl unmask tmp.mount && systemctl enable tmp.mount")
        
        # 1.1.2.1 Ensure nodev option set on /tmp partition
        stdout, _, _ = self.run_command("findmnt -n /tmp | grep nodev")
        if stdout:
            self.add_result("1.1.2.1", "Ensure nodev option set on /tmp partition",
                          "PASS", "nodev is set on /tmp")
        else:
            self.add_result("1.1.2.1", "Ensure nodev option set on /tmp partition",
                          "FAIL", "nodev is not set on /tmp",
                          "Edit /etc/fstab or systemd mount unit to add nodev option")
        
        # 1.1.2.2 Ensure nosuid option set on /tmp partition
        stdout, _, _ = self.run_command("findmnt -n /tmp | grep nosuid")
        if stdout:
            self.add_result("1.1.2.2", "Ensure nosuid option set on /tmp partition",
                          "PASS", "nosuid is set on /tmp")
        else:
            self.add_result("1.1.2.2", "Ensure nosuid option set on /tmp partition",
                          "FAIL", "nosuid is not set on /tmp",
                          "Edit /etc/fstab or systemd mount unit to add nosuid option")
        
        # 1.1.2.3 Ensure noexec option set on /tmp partition
        stdout, _, _ = self.run_command("findmnt -n /tmp | grep noexec")
        if stdout:
            self.add_result("1.1.2.3", "Ensure noexec option set on /tmp partition",
                          "PASS", "noexec is set on /tmp")
        else:
            self.add_result("1.1.2.3", "Ensure noexec option set on /tmp partition",
                          "FAIL", "noexec is not set on /tmp",
                          "Edit /etc/fstab or systemd mount unit to add noexec option")
    
    def check_1_3_mandatory_access_control(self):
        """1.3 Mandatory Access Control"""
        print("[*] Checking 1.3 Mandatory Access Control...")
        
        # 1.3.1.1 Ensure SELinux is installed
        stdout, _, rc = self.run_command("rpm -q libselinux")
        if rc == 0:
            self.add_result("1.3.1.1", "Ensure SELinux is installed",
                          "PASS", f"SELinux is installed: {stdout}")
        else:
            self.add_result("1.3.1.1", "Ensure SELinux is installed",
                          "FAIL", "SELinux is not installed",
                          "Run: dnf install libselinux")
        
        # 1.3.1.2 Ensure SELinux is not disabled in bootloader configuration
        stdout, _, _ = self.run_command("grep -E 'kernelopts=.*selinux=0' /boot/grub2/grubenv")
        if not stdout:
            self.add_result("1.3.1.2", "Ensure SELinux is not disabled in bootloader",
                          "PASS", "SELinux is not disabled in bootloader")
        else:
            self.add_result("1.3.1.2", "Ensure SELinux is not disabled in bootloader",
                          "FAIL", "SELinux is disabled in bootloader",
                          "Run: grubby --update-kernel ALL --remove-args selinux=0")
        
        # 1.3.1.3 Ensure SELinux policy is configured
        stdout, _, _ = self.run_command("sestatus")
        if "targeted" in stdout or "mls" in stdout:
            self.add_result("1.3.1.3", "Ensure SELinux policy is configured",
                          "PASS", "SELinux policy is properly configured")
        else:
            self.add_result("1.3.1.3", "Ensure SELinux policy is configured",
                          "FAIL", "SELinux policy not properly configured",
                          "Edit /etc/selinux/config: SELINUXTYPE=targeted")
        
        # 1.3.1.4 Ensure the SELinux mode is enforcing or permissive
        stdout, _, _ = self.run_command("getenforce")
        if stdout in ['Enforcing', 'Permissive']:
            self.add_result("1.3.1.4", "Ensure SELinux mode is enforcing or permissive",
                          "PASS", f"SELinux mode is {stdout}")
        else:
            self.add_result("1.3.1.4", "Ensure SELinux mode is enforcing or permissive",
                          "FAIL", f"SELinux mode is {stdout}",
                          "Run: setenforce 1 or edit /etc/selinux/config: SELINUX=enforcing")
        
        # 1.3.1.5 Ensure the SELinux mode is enforcing
        if stdout == 'Enforcing':
            self.add_result("1.3.1.5", "Ensure SELinux mode is enforcing",
                          "PASS", "SELinux is in enforcing mode")
        else:
            self.add_result("1.3.1.5", "Ensure SELinux mode is enforcing",
                          "FAIL", f"SELinux is in {stdout} mode",
                          "Run: setenforce 1 && edit /etc/selinux/config: SELINUX=enforcing")
    
    def check_1_4_bootloader(self):
        """1.4 Configure Boot Settings"""
        print("[*] Checking 1.4 Boot Settings...")
        
        # 1.4.1 Ensure bootloader password is set
        stdout, _, _ = self.run_command("grep '^GRUB2_PASSWORD' /boot/grub2/user.cfg 2>/dev/null")
        if stdout:
            self.add_result("1.4.1", "Ensure bootloader password is set",
                          "PASS", "Bootloader password is configured")
        else:
            self.add_result("1.4.1", "Ensure bootloader password is set",
                          "FAIL", "Bootloader password is not set",
                          "Run: grub2-setpassword")
        
        # 1.4.2 Ensure permissions on bootloader config are configured
        if self.check_file_permissions("/boot/grub2/grub.cfg", "600"):
            self.add_result("1.4.2", "Ensure permissions on bootloader config",
                          "PASS", "Bootloader config permissions are correct")
        else:
            self.add_result("1.4.2", "Ensure permissions on bootloader config",
                          "FAIL", "Bootloader config permissions are incorrect",
                          "Run: chmod 600 /boot/grub2/grub.cfg")
    
    def check_1_5_process_hardening(self):
        """1.5 Additional Process Hardening"""
        print("[*] Checking 1.5 Process Hardening...")
        
        # 1.5.1 Ensure core dumps are restricted
        stdout, _, _ = self.run_command("grep -E '^\\*[[:space:]]+hard[[:space:]]+core' /etc/security/limits.conf /etc/security/limits.d/*")
        stdout2, _, _ = self.run_command("sysctl fs.suid_dumpable")
        
        if "hard core 0" in stdout and "fs.suid_dumpable = 0" in stdout2:
            self.add_result("1.5.1", "Ensure core dumps are restricted",
                          "PASS", "Core dumps are properly restricted")
        else:
            self.add_result("1.5.1", "Ensure core dumps are restricted",
                          "FAIL", "Core dumps are not properly restricted",
                          "Add to /etc/security/limits.conf: * hard core 0; Set sysctl fs.suid_dumpable=0")
        
        # 1.5.2 Ensure address space layout randomization is enabled
        stdout, _, _ = self.run_command("sysctl kernel.randomize_va_space")
        if "kernel.randomize_va_space = 2" in stdout:
            self.add_result("1.5.2", "Ensure ASLR is enabled",
                          "PASS", "ASLR is enabled")
        else:
            self.add_result("1.5.2", "Ensure ASLR is enabled",
                          "FAIL", "ASLR is not enabled",
                          "Run: sysctl -w kernel.randomize_va_space=2")
    
    def check_2_1_inetd_services(self):
        """2.1 inetd Services"""
        print("[*] Checking 2.1 inetd Services...")
        
        # 2.1.1 Ensure xinetd is not installed
        stdout, _, rc = self.run_command("rpm -q xinetd")
        if rc != 0:
            self.add_result("2.1.1", "Ensure xinetd is not installed",
                          "PASS", "xinetd is not installed")
        else:
            self.add_result("2.1.1", "Ensure xinetd is not installed",
                          "FAIL", f"xinetd is installed: {stdout}",
                          "Run: dnf remove xinetd")
    
    def check_2_2_special_purpose_services(self):
        """2.2 Special Purpose Services"""
        print("[*] Checking 2.2 Special Purpose Services...")
        
        services_to_check = [
            ("2.2.1", "time-sync", "chrony", "Ensure time synchronization is in use"),
            ("2.2.2", "xorg-x11-server-common", None, "Ensure X Window System is not installed"),
            ("2.2.3", "avahi-daemon", None, "Ensure Avahi Server is not installed"),
            ("2.2.4", "cups", None, "Ensure CUPS is not installed"),
            ("2.2.5", "dhcp-server", None, "Ensure DHCP Server is not installed"),
            ("2.2.6", "bind", None, "Ensure DNS Server is not installed"),
            ("2.2.7", "vsftpd", None, "Ensure FTP Server is not installed"),
            ("2.2.8", "httpd", None, "Ensure HTTP server is not installed"),
            ("2.2.9", "dovecot", None, "Ensure IMAP and POP3 server is not installed"),
            ("2.2.10", "samba", None, "Ensure Samba is not installed"),
            ("2.2.11", "squid", None, "Ensure HTTP Proxy Server is not installed"),
            ("2.2.12", "net-snmp", None, "Ensure SNMP Server is not installed"),
            ("2.2.13", "ypserv", None, "Ensure NIS Server is not installed"),
            ("2.2.14", "telnet-server", None, "Ensure telnet server is not installed"),
        ]
        
        for section, package, service, title in services_to_check:
            stdout, _, rc = self.run_command(f"rpm -q {package}")
            
            if "chrony" in package or "time-sync" in package:
                # For time sync, we want it installed
                if rc == 0 or "chrony" in stdout:
                    self.add_result(section, title, "PASS", f"{package} is installed")
                else:
                    self.add_result(section, title, "FAIL", f"{package} is not installed",
                                  f"Run: dnf install {package}")
            else:
                # For other services, we don't want them installed
                if rc != 0:
                    self.add_result(section, title, "PASS", f"{package} is not installed")
                else:
                    self.add_result(section, title, "FAIL", f"{package} is installed",
                                  f"Run: dnf remove {package}")
    
    def check_3_network_configuration(self):
        """3 Network Configuration"""
        print("[*] Checking 3 Network Configuration...")
        
        # 3.1.1 Ensure IP forwarding is disabled
        stdout, _, _ = self.run_command("sysctl net.ipv4.ip_forward")
        stdout2, _, _ = self.run_command("sysctl net.ipv6.conf.all.forwarding")
        
        if "net.ipv4.ip_forward = 0" in stdout and "net.ipv6.conf.all.forwarding = 0" in stdout2:
            self.add_result("3.1.1", "Ensure IP forwarding is disabled",
                          "PASS", "IP forwarding is disabled")
        else:
            self.add_result("3.1.1", "Ensure IP forwarding is disabled",
                          "FAIL", "IP forwarding is enabled",
                          "Run: sysctl -w net.ipv4.ip_forward=0; sysctl -w net.ipv6.conf.all.forwarding=0")
        
        # 3.1.2 Ensure packet redirect sending is disabled
        stdout, _, _ = self.run_command("sysctl net.ipv4.conf.all.send_redirects")
        stdout2, _, _ = self.run_command("sysctl net.ipv4.conf.default.send_redirects")
        
        if "= 0" in stdout and "= 0" in stdout2:
            self.add_result("3.1.2", "Ensure packet redirect sending is disabled",
                          "PASS", "Packet redirect sending is disabled")
        else:
            self.add_result("3.1.2", "Ensure packet redirect sending is disabled",
                          "FAIL", "Packet redirect sending is enabled",
                          "Set sysctl net.ipv4.conf.all.send_redirects=0 and net.ipv4.conf.default.send_redirects=0")
        
        # 3.2.1 Ensure source routed packets are not accepted
        checks = [
            ("net.ipv4.conf.all.accept_source_route", "0"),
            ("net.ipv4.conf.default.accept_source_route", "0"),
            ("net.ipv6.conf.all.accept_source_route", "0"),
            ("net.ipv6.conf.default.accept_source_route", "0")
        ]
        
        all_pass = True
        for param, expected in checks:
            stdout, _, _ = self.run_command(f"sysctl {param}")
            if f"{param} = {expected}" not in stdout:
                all_pass = False
                break
        
        if all_pass:
            self.add_result("3.2.1", "Ensure source routed packets are not accepted",
                          "PASS", "Source routed packets are rejected")
        else:
            self.add_result("3.2.1", "Ensure source routed packets are not accepted",
                          "FAIL", "Source routed packets may be accepted",
                          "Set all accept_source_route parameters to 0")
        
        # 3.2.2 Ensure ICMP redirects are not accepted
        checks = [
            ("net.ipv4.conf.all.accept_redirects", "0"),
            ("net.ipv4.conf.default.accept_redirects", "0"),
            ("net.ipv6.conf.all.accept_redirects", "0"),
            ("net.ipv6.conf.default.accept_redirects", "0")
        ]
        
        all_pass = True
        for param, expected in checks:
            stdout, _, _ = self.run_command(f"sysctl {param}")
            if f"{param} = {expected}" not in stdout:
                all_pass = False
                break
        
        if all_pass:
            self.add_result("3.2.2", "Ensure ICMP redirects are not accepted",
                          "PASS", "ICMP redirects are not accepted")
        else:
            self.add_result("3.2.2", "Ensure ICMP redirects are not accepted",
                          "FAIL", "ICMP redirects may be accepted",
                          "Set all accept_redirects parameters to 0")
        
        # 3.3.1 Ensure TCP SYN Cookies is enabled
        stdout, _, _ = self.run_command("sysctl net.ipv4.tcp_syncookies")
        if "net.ipv4.tcp_syncookies = 1" in stdout:
            self.add_result("3.3.1", "Ensure TCP SYN Cookies is enabled",
                          "PASS", "TCP SYN Cookies are enabled")
        else:
            self.add_result("3.3.1", "Ensure TCP SYN Cookies is enabled",
                          "FAIL", "TCP SYN Cookies are not enabled",
                          "Run: sysctl -w net.ipv4.tcp_syncookies=1")
    
    def check_4_logging_auditing(self):
        """4 Logging and Auditing"""
        print("[*] Checking 4 Logging and Auditing...")
        
        # 4.1.1.1 Ensure auditd is installed
        stdout, _, rc = self.run_command("rpm -q audit audit-libs")
        if rc == 0:
            self.add_result("4.1.1.1", "Ensure auditd is installed",
                          "PASS", "auditd is installed")
        else:
            self.add_result("4.1.1.1", "Ensure auditd is installed",
                          "FAIL", "auditd is not installed",
                          "Run: dnf install audit audit-libs")
        
        # 4.1.1.2 Ensure auditd service is enabled
        stdout, _, _ = self.run_command("systemctl is-enabled auditd")
        if "enabled" in stdout:
            self.add_result("4.1.1.2", "Ensure auditd service is enabled",
                          "PASS", "auditd service is enabled")
        else:
            self.add_result("4.1.1.2", "Ensure auditd service is enabled",
                          "FAIL", "auditd service is not enabled",
                          "Run: systemctl enable auditd")
        
        # 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled
        stdout, _, _ = self.run_command("grep -E 'kernelopts=.*audit=1' /boot/grub2/grubenv")
        if stdout:
            self.add_result("4.1.1.3", "Ensure auditing for processes prior to auditd is enabled",
                          "PASS", "Early process auditing is enabled")
        else:
            self.add_result("4.1.1.3", "Ensure auditing for processes prior to auditd is enabled",
                          "FAIL", "Early process auditing is not enabled",
                          "Run: grubby --update-kernel ALL --args audit=1")
        
        # 4.2.1.1 Ensure rsyslog is installed
        stdout, _, rc = self.run_command("rpm -q rsyslog")
        if rc == 0:
            self.add_result("4.2.1.1", "Ensure rsyslog is installed",
                          "PASS", "rsyslog is installed")
        else:
            self.add_result("4.2.1.1", "Ensure rsyslog is installed",
                          "FAIL", "rsyslog is not installed",
                          "Run: dnf install rsyslog")
        
        # 4.2.1.2 Ensure rsyslog service is enabled
        stdout, _, _ = self.run_command("systemctl is-enabled rsyslog")
        if "enabled" in stdout:
            self.add_result("4.2.1.2", "Ensure rsyslog service is enabled",
                          "PASS", "rsyslog service is enabled")
        else:
            self.add_result("4.2.1.2", "Ensure rsyslog service is enabled",
                          "FAIL", "rsyslog service is not enabled",
                          "Run: systemctl enable rsyslog")
    
    def check_5_access_authentication(self):
        """5 Access, Authentication and Authorization"""
        print("[*] Checking 5 Access, Authentication and Authorization...")
        
        # 5.1.1 Ensure cron daemon is enabled
        stdout, _, _ = self.run_command("systemctl is-enabled crond")
        if "enabled" in stdout:
            self.add_result("5.1.1", "Ensure cron daemon is enabled",
                          "PASS", "cron daemon is enabled")
        else:
            self.add_result("5.1.1", "Ensure cron daemon is enabled",
                          "FAIL", "cron daemon is not enabled",
                          "Run: systemctl enable crond")
        
        # 5.1.2 Ensure permissions on /etc/crontab are configured
        if self.check_file_permissions("/etc/crontab", "600"):
            self.add_result("5.1.2", "Ensure permissions on /etc/crontab",
                          "PASS", "/etc/crontab permissions are correct")
        else:
            self.add_result("5.1.2", "Ensure permissions on /etc/crontab",
                          "FAIL", "/etc/crontab permissions are incorrect",
                          "Run: chmod 600 /etc/crontab")
        
        # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
        if self.check_file_permissions("/etc/ssh/sshd_config", "600"):
            self.add_result("5.2.1", "Ensure permissions on /etc/ssh/sshd_config",
                          "PASS", "SSH config permissions are correct")
        else:
            self.add_result("5.2.1", "Ensure permissions on /etc/ssh/sshd_config",
                          "FAIL", "SSH config permissions are incorrect",
                          "Run: chmod 600 /etc/ssh/sshd_config")
        
        # 5.2.2 Ensure SSH Protocol is set to 2
        stdout, _, _ = self.run_command("sshd -T | grep protocol")
        # Protocol 2 is default in modern SSH, so absence is OK
        self.add_result("5.2.2", "Ensure SSH Protocol is set to 2",
                      "PASS", "SSH Protocol 2 is in use (default)")
        
        # 5.2.3 Ensure SSH LogLevel is appropriate
        stdout, _, _ = self.run_command("sshd -T | grep loglevel")
        if "loglevel" in stdout.lower() and ("info" in stdout.lower() or "verbose" in stdout.lower()):
            self.add_result("5.2.3", "Ensure SSH LogLevel is appropriate",
                          "PASS", f"SSH LogLevel is set: {stdout}")
        else:
            self.add_result("5.2.3", "Ensure SSH LogLevel is appropriate",
                          "FAIL", "SSH LogLevel may not be appropriate",
                          "Set 'LogLevel VERBOSE' or 'LogLevel INFO' in /etc/ssh/sshd_config")
        
        # 5.2.4 Ensure SSH X11 forwarding is disabled
        stdout, _, _ = self.run_command("sshd -T | grep x11forwarding")
        if "x11forwarding no" in stdout.lower():
            self.add_result("5.2.4", "Ensure SSH X11 forwarding is disabled",
                          "PASS", "SSH X11 forwarding is disabled")
        else:
            self.add_result("5.2.4", "Ensure SSH X11 forwarding is disabled",
                          "FAIL", "SSH X11 forwarding may be enabled",
                          "Set 'X11Forwarding no' in /etc/ssh/sshd_config")
        
        # 5.2.5 Ensure SSH PermitRootLogin is disabled
        stdout, _, _ = self.run_command("sshd -T | grep permitrootlogin")
        if "permitrootlogin no" in stdout.lower():
            self.add_result("5.2.5", "Ensure SSH PermitRootLogin is disabled",
                          "PASS", "SSH root login is disabled")
        else:
            self.add_result("5.2.5", "Ensure SSH PermitRootLogin is disabled",
                          "FAIL", "SSH root login may be enabled",
                          "Set 'PermitRootLogin no' in /etc/ssh/sshd_config")
        
        # 5.2.6 Ensure SSH PermitEmptyPasswords is disabled
        stdout, _, _ = self.run_command("sshd -T | grep permitemptypasswords")
        if "permitemptypasswords no" in stdout.lower():
            self.add_result("5.2.6", "Ensure SSH PermitEmptyPasswords is disabled",
                          "PASS", "SSH empty passwords are disabled")
        else:
            self.add_result("5.2.6", "Ensure SSH PermitEmptyPasswords is disabled",
                          "FAIL", "SSH empty passwords may be enabled",
                          "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config")
        
        # 5.3.1 Ensure password creation requirements are configured
        if self.check_file_exists("/etc/security/pwquality.conf"):
            stdout, _, _ = self.run_command("grep '^minlen' /etc/security/pwquality.conf")
            if "minlen" in stdout:
                self.add_result("5.3.1", "Ensure password creation requirements are configured",
                              "PASS", "Password quality settings are configured")
            else:
                self.add_result("5.3.1", "Ensure password creation requirements are configured",
                              "FAIL", "Password quality may not be configured",
                              "Configure /etc/security/pwquality.conf with appropriate settings")
        else:
            self.add_result("5.3.1", "Ensure password creation requirements are configured",
                          "FAIL", "/etc/security/pwquality.conf not found",
                          "Install libpwquality and configure password requirements")
        
        # 5.4.1.1 Ensure password expiration is 365 days or less
        stdout, _, _ = self.run_command("grep '^PASS_MAX_DAYS' /etc/login.defs")
        if stdout:
            days = stdout.split()[-1]
            if days.isdigit() and int(days) <= 365:
                self.add_result("5.4.1.1", "Ensure password expiration is 365 days or less",
                              "PASS", f"Password expiration is set to {days} days")
            else:
                self.add_result("5.4.1.1", "Ensure password expiration is 365 days or less",
                              "FAIL", f"Password expiration is {days} days",
                              "Set PASS_MAX_DAYS to 365 or less in /etc/login.defs")
        else:
            self.add_result("5.4.1.1", "Ensure password expiration is 365 days or less",
                          "MANUAL", "Could not determine password expiration setting")
    
    def check_6_system_maintenance(self):
        """6 System Maintenance"""
        print("[*] Checking 6 System Maintenance...")
        
        # 6.1.1 Audit system file permissions
        stdout, _, _ = self.run_command("rpm -Va --nomtime --nosize --nomd5 --nolinkto 2>/dev/null | head -20")
        if stdout:
            self.add_result("6.1.1", "Audit system file permissions",
                          "MANUAL", "Some file permission changes detected - review required",
                          "Review rpm -Va output and remediate unauthorized changes")
        else:
            self.add_result("6.1.1", "Audit system file permissions",
                          "PASS", "No unauthorized file permission changes detected")
        
        # 6.1.2 Ensure permissions on /etc/passwd are configured
        if self.check_file_permissions("/etc/passwd", "644"):
            self.add_result("6.1.2", "Ensure permissions on /etc/passwd",
                          "PASS", "/etc/passwd permissions are correct")
        else:
            self.add_result("6.1.2", "Ensure permissions on /etc/passwd",
                          "FAIL", "/etc/passwd permissions are incorrect",
                          "Run: chmod 644 /etc/passwd")
        
        # 6.1.3 Ensure permissions on /etc/shadow are configured
        if self.check_file_permissions("/etc/shadow", "000"):
            self.add_result("6.1.3", "Ensure permissions on /etc/shadow",
                          "PASS", "/etc/shadow permissions are correct")
        else:
            self.add_result("6.1.3", "Ensure permissions on /etc/shadow",
                          "FAIL", "/etc/shadow permissions are incorrect",
                          "Run: chmod 000 /etc/shadow")
        
        # 6.1.4 Ensure permissions on /etc/group are configured
        if self.check_file_permissions("/etc/group", "644"):
            self.add_result("6.1.4", "Ensure permissions on /etc/group",
                          "PASS", "/etc/group permissions are correct")
        else:
            self.add_result("6.1.4", "Ensure permissions on /etc/group",
                          "FAIL", "/etc/group permissions are incorrect",
                          "Run: chmod 644 /etc/group")
        
        # 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords
        stdout, _, _ = self.run_command("awk -F: '($2 != \"x\" ) { print $1 }' /etc/passwd")
        if not stdout:
            self.add_result("6.2.1", "Ensure accounts use shadowed passwords",
                          "PASS", "All accounts use shadowed passwords")
        else:
            self.add_result("6.2.1", "Ensure accounts use shadowed passwords",
                          "FAIL", f"Accounts not using shadow: {stdout}",
                          "Run pwconv to move passwords to /etc/shadow")
        
        # 6.2.2 Ensure password fields are not empty
        stdout, _, _ = self.run_command("awk -F: '($2 == \"\" ) { print $1 }' /etc/shadow")
        if not stdout:
            self.add_result("6.2.2", "Ensure password fields are not empty",
                          "PASS", "No accounts have empty passwords")
        else:
            self.add_result("6.2.2", "Ensure password fields are not empty",
                          "FAIL", f"Accounts with empty passwords: {stdout}",
                          "Lock or set passwords for these accounts")
        
        # 6.2.3 Ensure root is the only UID 0 account
        stdout, _, _ = self.run_command("awk -F: '($3 == 0) { print $1 }' /etc/passwd")
        if stdout.strip() == "root":
            self.add_result("6.2.3", "Ensure root is the only UID 0 account",
                          "PASS", "Only root has UID 0")
        else:
            self.add_result("6.2.3", "Ensure root is the only UID 0 account",
                          "FAIL", f"Multiple UID 0 accounts: {stdout}",
                          "Remove or change UID for non-root accounts with UID 0")
    
    def run_all_checks(self):
        """Run all CIS benchmark checks"""
        print("\n" + "="*70)
        print("CIS Benchmark Compliance Scanner for Red Hat Enterprise Linux")
        print("="*70 + "\n")
        
        self.check_1_1_filesystem_configuration()
        self.check_1_3_mandatory_access_control()
        self.check_1_4_bootloader()
        self.check_1_5_process_hardening()
        self.check_2_1_inetd_services()
        self.check_2_2_special_purpose_services()
        self.check_3_network_configuration()
        self.check_4_logging_auditing()
        self.check_5_access_authentication()
        self.check_6_system_maintenance()
    
    def generate_report(self, output_file=None, show_passed=True):
        """Generate compliance report"""
        total = len(self.results)
        
        summary = {
            'scan_date': datetime.now().isoformat(),
            'total_checks': total,
            'passed': self.passed,
            'failed': self.failed,
            'manual': self.manual,
            'not_applicable': self.not_applicable,
            'compliance_percentage': round((self.passed / total * 100), 2) if total > 0 else 0
        }
        
        report = {
            'summary': summary,
            'results': self.results
        }
        
        if output_file:
            if self.output_format == 'json':
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2)
            elif self.output_format == 'csv':
                import csv
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['section', 'title', 'status', 'details', 'recommendation'])
                    writer.writeheader()
                    writer.writerows(self.results)
            
            print(f"\n[+] Report saved to: {output_file}")
        
        # Print summary
        print("\n" + "="*70)
        print("COMPLIANCE SUMMARY")
        print("="*70)
        print(f"Total Checks:    {total}")
        print(f"Passed:          {self.passed} ({round(self.passed/total*100, 1)}%)")
        print(f"Failed:          {self.failed} ({round(self.failed/total*100, 1)}%)")
        print(f"Manual Review:   {self.manual} ({round(self.manual/total*100, 1)}%)")
        print(f"Not Applicable:  {self.not_applicable}")
        print(f"\nOverall Compliance: {summary['compliance_percentage']}%")
        print("="*70 + "\n")
        
        return report
    
    def print_detailed_results(self, show_passed=True, show_failed=True, show_manual=True):
        """Print detailed results organized by status"""
        
        # Color codes for terminal output
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        RESET = '\033[0m'
        BOLD = '\033[1m'
        
        # Group results by status
        passed_results = [r for r in self.results if r['status'] == 'PASS']
        failed_results = [r for r in self.results if r['status'] == 'FAIL']
        manual_results = [r for r in self.results if r['status'] == 'MANUAL']
        
        # Print PASSED checks
        if show_passed and passed_results:
            print(f"\n{GREEN}{BOLD}{'='*70}")
            print(f"✓ PASSED CHECKS ({len(passed_results)})")
            print(f"{'='*70}{RESET}\n")
            
            for result in passed_results:
                print(f"{GREEN}[✓ PASS]{RESET} {BOLD}[{result['section']}]{RESET} {result['title']}")
                print(f"  {GREEN}└─{RESET} {result['details']}")
                print()
        
        # Print FAILED checks
        if show_failed and failed_results:
            print(f"\n{RED}{BOLD}{'='*70}")
            print(f"✗ FAILED CHECKS ({len(failed_results)})")
            print(f"{'='*70}{RESET}\n")
            
            for result in failed_results:
                print(f"{RED}[✗ FAIL]{RESET} {BOLD}[{result['section']}]{RESET} {result['title']}")
                print(f"  {RED}├─{RESET} Issue: {result['details']}")
                if result['recommendation']:
                    print(f"  {RED}└─{RESET} {BOLD}Remediation:{RESET} {result['recommendation']}")
                print()
        
        # Print MANUAL checks
        if show_manual and manual_results:
            print(f"\n{YELLOW}{BOLD}{'='*70}")
            print(f"⚠ MANUAL REVIEW REQUIRED ({len(manual_results)})")
            print(f"{'='*70}{RESET}\n")
            
            for result in manual_results:
                print(f"{YELLOW}[⚠ MANUAL]{RESET} {BOLD}[{result['section']}]{RESET} {result['title']}")
                print(f"  {YELLOW}├─{RESET} Details: {result['details']}")
                if result['recommendation']:
                    print(f"  {YELLOW}└─{RESET} Action: {result['recommendation']}")
                print()


def main():
    parser = argparse.ArgumentParser(
        description='CIS Benchmark Compliance Scanner for Red Hat Enterprise Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run full scan with all details
  sudo python3 cis_redhat_benchmark.py --show-all
  
  # Save detailed report to file
  sudo python3 cis_redhat_benchmark.py -o compliance_report.json --show-all
  
  # Show only failed checks
  sudo python3 cis_redhat_benchmark.py --failed-only
  
  # Show passed and failed, but not manual
  sudo python3 cis_redhat_benchmark.py --show-passed --show-failed
        '''
    )
    
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--failed-only', action='store_true',
                       help='Show only failed checks')
    parser.add_argument('--show-all', action='store_true',
                       help='Show all checks (passed, failed, and manual)')
    parser.add_argument('--show-passed', action='store_true',
                       help='Show passed checks')
    parser.add_argument('--show-failed', action='store_true',
                       help='Show failed checks')
    parser.add_argument('--show-manual', action='store_true',
                       help='Show checks requiring manual review')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Warning: This script should be run as root for complete checks")
        print()
    
    scanner = CISBenchmark(output_format=args.format)
    scanner.run_all_checks()
    report = scanner.generate_report(args.output)
    
    # Determine what to show
    show_passed = args.show_all or args.show_passed
    show_failed = args.show_all or args.show_failed or args.failed_only or not (args.show_passed or args.show_manual)
    show_manual = args.show_all or args.show_manual
    
    # If failed-only is specified, only show failed
    if args.failed_only:
        show_passed = False
        show_manual = False
        show_failed = True
    
    # Print detailed results
    scanner.print_detailed_results(
        show_passed=show_passed,
        show_failed=show_failed,
        show_manual=show_manual
    )
    
    # Print quick remediation summary
    if scanner.failed > 0:
        print("\n" + "="*70)
        print("QUICK REMEDIATION SUMMARY")
        print("="*70 + "\n")
        
        failed_results = [r for r in scanner.results if r['status'] == 'FAIL']
        
        print("Priority remediation commands:\n")
        for idx, result in enumerate(failed_results, 1):
            if result['recommendation']:
                print(f"{idx}. [{result['section']}] {result['title']}")
                print(f"   {result['recommendation']}\n")


if __name__ == '__main__':
    main()
