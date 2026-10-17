#!/usr/bin/env bash
# ==============================================================================
# Linux File Permission Analyzer (LfPA) - Vulnerability Sandbox Setup
# Course: 25CS2104E - Operating Systems and Systems Programming (OSSP)
# Rule #7 Compliance: Creates a completely isolated, safe sandbox environment
# ==============================================================================

set -e

SANDBOX_DIR="${1:-./demo_sandbox}"

echo -e "\033[1;34m[*] Initializing Vulnerable Test Sandbox at '${SANDBOX_DIR}'...\033[0m"

# 1. Clean previous sandbox if present
rm -rf "${SANDBOX_DIR}"
mkdir -p "${SANDBOX_DIR}"

# 2. Subdirectories
mkdir -p "${SANDBOX_DIR}/scripts"
mkdir -p "${SANDBOX_DIR}/bin"
mkdir -p "${SANDBOX_DIR}/shared/insecure_tmp"
mkdir -p "${SANDBOX_DIR}/shared/secure_tmp"
mkdir -p "${SANDBOX_DIR}/credentials"
mkdir -p "${SANDBOX_DIR}/backups"
mkdir -p "${SANDBOX_DIR}/safe"
mkdir -p "${SANDBOX_DIR}/links"

# 3. Create SEC-001: World-Writable Executable Script (0777)
cat << 'EOF' > "${SANDBOX_DIR}/scripts/world_writable_script.sh"
#!/bin/bash
echo "Vulnerable system automation task"
EOF
chmod 777 "${SANDBOX_DIR}/scripts/world_writable_script.sh"

# 4. Create SEC-002: SUID Executable Binary (04755)
# Compile a minimal binary stub
cat << 'EOF' > "${SANDBOX_DIR}/bin/suid_stub.c"
#include <stdio.h>
int main(void) {
    printf("SUID binary execution stub.\n");
    return 0;
}
EOF
if command -v gcc >/dev/null 2>&1; then
    gcc -O2 "${SANDBOX_DIR}/bin/suid_stub.c" -o "${SANDBOX_DIR}/bin/fake_suid_binary"
    chmod 4755 "${SANDBOX_DIR}/bin/fake_suid_binary"
    rm -f "${SANDBOX_DIR}/bin/suid_stub.c"
else
    # Fallback to touch if gcc not in path
    touch "${SANDBOX_DIR}/bin/fake_suid_binary"
    chmod 4755 "${SANDBOX_DIR}/bin/fake_suid_binary"
fi

# 5. Create SEC-003: SGID Binary (02755)
cp "${SANDBOX_DIR}/bin/fake_suid_binary" "${SANDBOX_DIR}/bin/fake_sgid_binary" 2>/dev/null || touch "${SANDBOX_DIR}/bin/fake_sgid_binary"
chmod 2755 "${SANDBOX_DIR}/bin/fake_sgid_binary"

# 6. Create SEC-004: World-Writable Directory MISSING Sticky Bit (0777)
chmod 777 "${SANDBOX_DIR}/shared/insecure_tmp"

# 7. Create Compliant Reference: World-Writable Directory WITH Sticky Bit (01777)
chmod 1777 "${SANDBOX_DIR}/shared/secure_tmp"

# 8. Create SEC-005: Sensitive Private SSH Key with loose permissions (0644)
cat << 'EOF' > "${SANDBOX_DIR}/credentials/id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvulnerableDemokeyForTestingOperatingSystemsCourse==
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 644 "${SANDBOX_DIR}/credentials/id_rsa"

# 9. Create SEC-005 / SEC-001: Exposed .env file with secrets (0666)
cat << 'EOF' > "${SANDBOX_DIR}/credentials/.env"
DB_HOST=127.0.0.1
DB_USER=root
DB_PASSWORD=SuperSecretPassword2026!
AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE
EOF
chmod 666 "${SANDBOX_DIR}/credentials/.env"

# 10. Create SEC-008: World-Readable SQL Backup (0644)
cat << 'EOF' > "${SANDBOX_DIR}/backups/dump_2026.sql"
-- Production Database Dump
CREATE TABLE users (id INT, email VARCHAR(255), pass_hash VARCHAR(255));
INSERT INTO users VALUES (1, 'admin@university.edu', '$2y$10$demoHash');
EOF
chmod 644 "${SANDBOX_DIR}/backups/dump_2026.sql"

# 11. Create Symlink (To verify lstat does not traverse circular or external links)
ln -sf "../credentials/.env" "${SANDBOX_DIR}/links/symlink_to_env"

# 12. Create Compliant Baseline Files (Should NOT trigger alerts)
echo "Standard system documentation" > "${SANDBOX_DIR}/safe/readme.txt"
chmod 644 "${SANDBOX_DIR}/safe/readme.txt"

cat << 'EOF' > "${SANDBOX_DIR}/safe/safe_script.sh"
#!/bin/sh
echo "Safely permitted script"
EOF
chmod 755 "${SANDBOX_DIR}/safe/safe_script.sh"

echo -e "\033[1;32m[✓] Sandbox environment successfully created at '${SANDBOX_DIR}'!\033[0m"
echo -e "Generated Test Scenarios:"
echo -e "  - SEC-001: ${SANDBOX_DIR}/scripts/world_writable_script.sh (0777)"
echo -e "  - SEC-002: ${SANDBOX_DIR}/bin/fake_suid_binary (04755)"
echo -e "  - SEC-003: ${SANDBOX_DIR}/bin/fake_sgid_binary (02755)"
echo -e "  - SEC-004: ${SANDBOX_DIR}/shared/insecure_tmp (0777 - Missing Sticky Bit)"
echo -e "  - SEC-005: ${SANDBOX_DIR}/credentials/id_rsa (0644 - Private key exposed)"
echo -e "  - SEC-005: ${SANDBOX_DIR}/credentials/.env (0666 - World-writable secrets)"
echo -e "  - SEC-008: ${SANDBOX_DIR}/backups/dump_2026.sql (0644 - World-readable SQL dump)"
echo -e "  - SYMLNK : ${SANDBOX_DIR}/links/symlink_to_env (lstat test)"
echo -e "  - SAFE   : ${SANDBOX_DIR}/safe/readme.txt (0644 - Clean baseline)"
