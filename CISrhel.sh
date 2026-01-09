#!/bin/bash

#########################################################
# CIS Benchmark Assessment Script for RHEL
# Requires root privileges
#########################################################

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
PASSED=0
FAILED=0

echo -e "${CYAN}=== CIS Benchmark Assessment for RHEL ===${NC}"
echo -e "${GREEN}Starting assessment at $(date)${NC}"
echo ""

# Function to test and display results
test_check() {
    local description="$1"
    local test_result=$2
    
    ((TOTAL++))
    
    if [ $test_result -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $description"
        ((PASSED++))
    else
        echo -e "${RED}[FAIL]${NC} $description"
        ((FAILED++))
    fi
}

#########################################################
# 1. Initial Setup
#########################################################
echo -e "${YELLOW}[*] Checking Initial Setup...${NC}"

# 1.1.1 Ensure mounting of filesystems is disabled
echo -e "\n${CYAN}--- Filesystem Configurations ---${NC}"

for fs in cramfs freevxfs jffs2 hfs hfsplus udf; do
    if lsmod | grep -q "^$fs "; then
        test_check "Filesystem $fs should be disabled" 1
    else
        test_check "Filesystem $fs is disabled" 0
    fi
done

# 1.3.1 Ensure AIDE is installed
if rpm -q aide &>/dev/null; then
    test_check "AIDE is installed" 0
else
    test_check "AIDE is installed" 1
fi

# 1.4.1 Ensure bootloader password is set
if grep -q "^password" /boot/grub2/grub.cfg 2>/dev/null || grep -q "^password" /boot/efi/EFI/redhat/grub.cfg 2>/dev/null; then
    test_check "GRUB bootloader password is set" 0
else
    test_check "GRUB bootloader password is set" 1
fi

# 1.5.1 Ensure core dumps are restricted
echo -e "\n${CYAN}--- Core Dump Restrictions ---${NC}"

if grep -q "hard core 0" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    test_check "Core dumps are restricted in limits.conf" 0
else
    test_check "Core dumps are restricted in limits.conf" 1
fi

if sysctl fs.suid_dumpable 2>/dev/null | grep -q "fs.suid_dumpable = 0"; then
    test_check "fs.suid_dumpable is set to 0" 0
else
    test_check "fs.suid_dumpable is set to 0" 1
fi

# 1.5.3 Ensure address space layout randomization is enabled
if sysctl kernel.randomize_va_space 2>/dev/null | grep -q "kernel.randomize_va_space = 2"; then
    test_check "ASLR is enabled" 0
else
    test_check "ASLR is enabled" 1
fi

#########################################################
# 2. Services
#########################################################
echo -e "\n${YELLOW}[*] Checking Services Configuration...${NC}"

# Check if various services are disabled
services_to_disable=(
    "autofs"
    "avahi-daemon"
    "cups"
    "dhcpd"
    "slapd"
    "nfs"
    "rpcbind"
    "named"
    "vsftpd"
    "httpd"
    "dovecot"
    "smb"
    "squid"
    "snmpd"
    "telnet.socket"
)

for service in "${services_to_disable[@]}"; do
    if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
        test_check "Service $service should be disabled" 1
    else
        test_check "Service $service is disabled/not installed" 0
    fi
done

#########################################################
# 3. Network Configuration
#########################################################
echo -e "\n${YELLOW}[*] Checking Network Configuration...${NC}"

# 3.1 Network Parameters (Host Only)
network_params=(
    "net.ipv4.ip_forward:0"
    "net.ipv4.conf.all.send_redirects:0"
    "net.ipv4.conf.default.send_redirects:0"
    "net.ipv4.conf.all.accept_source_route:0"
    "net.ipv4.conf.default.accept_source_route:0"
    "net.ipv4.conf.all.accept_redirects:0"
    "net.ipv4.conf.default.accept_redirects:0"
    "net.ipv4.conf.all.secure_redirects:0"
    "net.ipv4.conf.default.secure_redirects:0"
    "net.ipv4.conf.all.log_martians:1"
    "net.ipv4.conf.default.log_martians:1"
    "net.ipv4.icmp_echo_ignore_broadcasts:1"
    "net.ipv4.icmp_ignore_bogus_error_responses:1"
    "net.ipv4.conf.all.rp_filter:1"
    "net.ipv4.conf.default.rp_filter:1"
    "net.ipv4.tcp_syncookies:1"
)

for param in "${network_params[@]}"; do
    key="${param%%:*}"
    expected="${param##*:}"
    actual=$(sysctl "$key" 2>/dev/null | awk '{print $3}')
    
    if [ "$actual" = "$expected" ]; then
        test_check "Kernel parameter $key = $expected" 0
    else
        test_check "Kernel parameter $key = $expected (actual: $actual)" 1
    fi
done

# 3.4 Ensure firewalld is enabled
if systemctl is-enabled firewalld 2>/dev/null | grep -q "enabled"; then
    test_check "Firewalld is enabled" 0
else
    test_check "Firewalld is enabled" 1
fi

if systemctl is-active firewalld 2>/dev/null | grep -q "active"; then
    test_check "Firewalld is running" 0
else
    test_check "Firewalld is running" 1
fi

#########################################################
# 4. Logging and Auditing
#########################################################
echo -e "\n${YELLOW}[*] Checking Logging and Auditing...${NC}"

# 4.1.1 Ensure auditd is installed
if rpm -q audit audit-libs &>/dev/null; then
    test_check "auditd packages are installed" 0
else
    test_check "auditd packages are installed" 1
fi

# 4.1.2 Ensure auditd is enabled
if systemctl is-enabled auditd 2>/dev/null | grep -q "enabled"; then
    test_check "auditd service is enabled" 0
else
    test_check "auditd service is enabled" 1
fi

# Check audit rules exist
if [ -f /etc/audit/rules.d/audit.rules ] || [ -f /etc/audit/audit.rules ]; then
    test_check "Audit rules file exists" 0
else
    test_check "Audit rules file exists" 1
fi

# 4.2.1 Ensure rsyslog is installed
if rpm -q rsyslog &>/dev/null; then
    test_check "rsyslog is installed" 0
else
    test_check "rsyslog is installed" 1
fi

# 4.2.2 Ensure rsyslog is enabled
if systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled"; then
    test_check "rsyslog service is enabled" 0
else
    test_check "rsyslog service is enabled" 1
fi

#########################################################
# 5. Access, Authentication and Authorization
#########################################################
echo -e "\n${YELLOW}[*] Checking Access Control...${NC}"

# 5.1 Configure cron
if stat -L -c "%a" /etc/crontab 2>/dev/null | grep -q "600\|400\|200\|000"; then
    test_check "/etc/crontab permissions are 600 or more restrictive" 0
else
    test_check "/etc/crontab permissions are 600 or more restrictive" 1
fi

# 5.2 SSH Server Configuration
echo -e "\n${CYAN}--- SSH Configuration ---${NC}"

sshd_checks=(
    "Protocol:2"
    "LogLevel:INFO"
    "X11Forwarding:no"
    "MaxAuthTries:4"
    "IgnoreRhosts:yes"
    "HostbasedAuthentication:no"
    "PermitRootLogin:no"
    "PermitEmptyPasswords:no"
    "PermitUserEnvironment:no"
    "ClientAliveInterval:300"
    "ClientAliveCountMax:0"
)

for check in "${sshd_checks[@]}"; do
    param="${check%%:*}"
    expected="${check##*:}"
    
    actual=$(sshd -T 2>/dev/null | grep -i "^$param" | awk '{print $2}')
    
    if [ "$actual" = "$expected" ]; then
        test_check "SSH $param is set to $expected" 0
    else
        test_check "SSH $param is set to $expected (actual: $actual)" 1
    fi
done

# 5.3 Configure PAM
echo -e "\n${CYAN}--- PAM Configuration ---${NC}"

# Check password quality requirements
if grep -q "pam_pwquality.so" /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    test_check "pam_pwquality.so is configured" 0
else
    test_check "pam_pwquality.so is configured" 1
fi

# Check faillock
if grep -q "pam_faillock.so" /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    test_check "pam_faillock.so is configured" 0
else
    test_check "pam_faillock.so is configured" 1
fi

# 5.4 User Accounts and Environment
echo -e "\n${CYAN}--- User Account Settings ---${NC}"

# Check password aging
pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ "$pass_max_days" -le 365 ] && [ "$pass_max_days" -gt 0 ] 2>/dev/null; then
    test_check "PASS_MAX_DAYS is 365 or less" 0
else
    test_check "PASS_MAX_DAYS is 365 or less (actual: $pass_max_days)" 1
fi

pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ "$pass_min_days" -ge 1 ] 2>/dev/null; then
    test_check "PASS_MIN_DAYS is 1 or more" 0
else
    test_check "PASS_MIN_DAYS is 1 or more (actual: $pass_min_days)" 1
fi

pass_warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
if [ "$pass_warn_age" -ge 7 ] 2>/dev/null; then
    test_check "PASS_WARN_AGE is 7 or more" 0
else
    test_check "PASS_WARN_AGE is 7 or more (actual: $pass_warn_age)" 1
fi

# Check for accounts with empty passwords
empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
if [ "$empty_pass" -eq 0 ]; then
    test_check "No accounts have empty passwords" 0
else
    test_check "No accounts have empty passwords (found: $empty_pass)" 1
fi

# Check UID 0 accounts
uid_zero=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null | grep -v "^root$" | wc -l)
if [ "$uid_zero" -eq 0 ]; then
    test_check "Only root account has UID 0" 0
else
    test_check "Only root account has UID 0 (found: $uid_zero others)" 1
fi

# 5.5 Ensure root login is restricted to system console
if [ -f /etc/securetty ]; then
    test_check "/etc/securetty exists (root login restriction)" 0
else
    test_check "/etc/securetty exists (root login restriction)" 1
fi

# Check for sudo configuration
if grep -q "Defaults use_pty" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    test_check "sudo use_pty is enabled" 0
else
    test_check "sudo use_pty is enabled" 1
fi

if grep -q "Defaults logfile=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    test_check "sudo logfile is configured" 0
else
    test_check "sudo logfile is configured" 1
fi

#########################################################
# 6. System Maintenance
#########################################################
echo -e "\n${YELLOW}[*] Checking System Maintenance...${NC}"

# 6.1 System File Permissions
echo -e "\n${CYAN}--- File Permissions ---${NC}"

file_perms=(
    "/etc/passwd:644"
    "/etc/shadow:000"
    "/etc/group:644"
    "/etc/gshadow:000"
    "/etc/passwd-:600"
    "/etc/shadow-:000"
    "/etc/group-:600"
    "/etc/gshadow-:000"
)

for check in "${file_perms[@]}"; do
    file="${check%%:*}"
    expected="${check##*:}"
    
    if [ -f "$file" ]; then
        actual=$(stat -L -c "%a" "$file" 2>/dev/null)
        if [ "$actual" -le "$expected" ] 2>/dev/null; then
            test_check "$file permissions are $expected or more restrictive" 0
        else
            test_check "$file permissions are $expected or more restrictive (actual: $actual)" 1
        fi
    else
        test_check "$file exists" 1
    fi
done

# Check for world-writable files
echo -e "\n${CYAN}--- Checking for World-Writable Files (sample) ---${NC}"
ww_count=$(df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null | head -10 | wc -l)
if [ "$ww_count" -eq 0 ]; then
    test_check "No world-writable files found (sample check)" 0
else
    test_check "World-writable files found: $ww_count (sample check)" 1
fi

# Check for unowned files
echo -e "\n${CYAN}--- Checking for Unowned Files (sample) ---${NC}"
unowned=$(df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null | head -10 | wc -l)
if [ "$unowned" -eq 0 ]; then
    test_check "No unowned files found (sample check)" 0
else
    test_check "Unowned files found: $unowned (sample check)" 1
fi

#########################################################
# Summary
#########################################################
echo ""
echo -e "${CYAN}=== Summary ===${NC}"
echo -e "${CYAN}Total Checks: $TOTAL${NC}"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

compliance=$(awk "BEGIN {printf \"%.2f\", ($PASSED/$TOTAL)*100}")
echo -e "${CYAN}Compliance: $compliance%${NC}"

echo ""
echo -e "${GREEN}Assessment completed at $(date)${NC}"
