/**
 * @file rules_engine.c
 * @brief Security Heuristics and Bitmask Mathematical Evaluation Engine
 * @course 25CS2104E - Operating Systems and Systems Programming (OSSP)
 * @author Team Member 3 (Bitmask Math & Security Rules Module)
 * 
 * Course Outcome Alignment:
 * - Inode Metadata & Permission Bitmasks (S_IRWXU, S_IRWXG, S_IRWXO, S_ISUID, S_ISGID, S_ISVTX)
 * - Security vulnerability classification & risk scoring
 * - Automated calculation of recommended secure permissions
 */

#include "analyzer.h"

/* List of sensitive credential filenames and substrings */
static const char *SENSITIVE_PATTERNS[] = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".pem",
    ".key",
    ".env",
    "credentials.json",
    "wp-config.php",
    "database.yml",
    "database.conf",
    "db.conf",
    "secrets.txt",
    "shadow",
    "master.key",
    "jwt_secret",
    NULL
};

/* List of backup and dump extensions prone to info leakage */
static const char *BACKUP_EXTENSIONS[] = {
    ".bak",
    ".backup",
    ".dump",
    ".sql",
    ".old",
    ".swp",
    NULL
};

/**
 * @brief Checks if a filename matches known sensitive credential patterns.
 */
bool is_sensitive_credential_file(const char *path) {
    if (!path) return false;
    
    /* Extract filename basename */
    const char *slash = strrchr(path, '/');
    const char *filename = slash ? slash + 1 : path;

    for (int i = 0; SENSITIVE_PATTERNS[i] != NULL; ++i) {
        if (strstr(filename, SENSITIVE_PATTERNS[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Checks if a filename matches backup or dump patterns.
 */
static bool is_backup_or_dump_file(const char *path) {
    if (!path) return false;
    for (int i = 0; BACKUP_EXTENSIONS[i] != NULL; ++i) {
        size_t path_len = strlen(path);
        size_t ext_len = strlen(BACKUP_EXTENSIONS[i]);
        if (path_len >= ext_len) {
            if (strcasecmp(path + (path_len - ext_len), BACKUP_EXTENSIONS[i]) == 0) {
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief Converts a SeverityLevel enum to an ASCII string.
 */
const char* severity_to_string(SeverityLevel sev) {
    switch (sev) {
        case SEV_CRITICAL: return "CRITICAL";
        case SEV_HIGH:     return "HIGH";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_LOW:      return "LOW";
        case SEV_INFO:     return "INFO";
        default:           return "UNKNOWN";
    }
}

/**
 * @brief Converts a SeverityLevel enum to a colored ANSI terminal badge.
 */
const char* severity_to_badge(SeverityLevel sev) {
    switch (sev) {
        case SEV_CRITICAL: return CLR_BG_RED " CRITICAL " CLR_RESET;
        case SEV_HIGH:     return CLR_RED    "[HIGH]    " CLR_RESET;
        case SEV_MEDIUM:   return CLR_YELLOW "[MEDIUM]  " CLR_RESET;
        case SEV_LOW:      return CLR_CYAN   "[LOW]     " CLR_RESET;
        case SEV_INFO:     return CLR_BLUE   "[INFO]    " CLR_RESET;
        default:           return "[UNKNOWN] ";
    }
}

/**
 * @brief Returns human-readable name of finding type.
 */
const char* finding_type_to_string(FindingType type) {
    switch (type) {
        case FINDING_WORLD_WRITABLE_ROOT:   return "World-Writable Sensitive/Root File";
        case FINDING_SUID_ROOT:             return "SUID Bit on Root Executable";
        case FINDING_SGID_BINARY:           return "SGID Bit on Binary Executable";
        case FINDING_STICKY_MISSING:        return "Missing Sticky Bit on World-Writable Directory";
        case FINDING_SENSITIVE_EXPOSURE:    return "Exposed Sensitive Credentials/Key";
        case FINDING_ORPHANED_INODE:        return "Orphaned Inode (Unmapped UID/GID)";
        case FINDING_WORLD_WRITABLE_FILE:   return "World-Writable General File";
        case FINDING_SUSPICIOUS_EXECUTABLE: return "Suspicious Executable in World Area";
        default:                            return "Clean / No Finding";
    }
}

/**
 * @brief Evaluates inode metadata against security rules using bitmask mathematics.
 * 
 * Bitmask Operations Implemented:
 * 1. World-Writable: `st->st_mode & S_IWOTH` (00002 octal)
 * 2. World-Readable: `st->st_mode & S_IROTH` (00004 octal)
 * 3. SUID Bit:       `st->st_mode & S_ISUID` (04000 octal)
 * 4. SGID Bit:       `st->st_mode & S_ISGID` (02000 octal)
 * 5. Sticky Bit:     `st->st_mode & S_ISVTX` (01000 octal)
 * 
 * @param path File system path being inspected.
 * @param st Pointer to struct stat populated by lstat().
 * @param out_record Output record filled if a vulnerability is detected.
 * @return true if an audit finding was identified, false if safe.
 */
bool evaluate_inode_security(const char *path, const struct stat *st, AuditRecord *out_record) {
    if (!path || !st || !out_record) return false;

    mode_t mode = st->st_mode;
    mode_t perms = mode & 07777;
    bool is_dir = S_ISDIR(mode);
    bool is_reg = S_ISREG(mode);
    bool is_exec = (mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;

    /* Base Record Metadata */
    memset(out_record, 0, sizeof(AuditRecord));
    strncpy(out_record->path, path, sizeof(out_record->path) - 1);
    out_record->raw_mode = mode;
    out_record->uid = st->st_uid;
    out_record->gid = st->st_gid;
    out_record->inode_num = st->st_ino;
    out_record->size_bytes = st->st_size;
    out_record->mtime = st->st_mtime;
    out_record->is_fixed = false;
    out_record->fix_status[0] = '\0';
    format_mode_to_string(mode, out_record->perm_str);
    resolve_identity(st->st_uid, st->st_gid, out_record->owner_name, out_record->group_name);

    /* --------------------------------------------------------------------- */
    /* RULE SEC-002: SUID Bit on Executable Binary (CRITICAL / HIGH)         */
    /* Binary condition: (mode & 04000) != 0 && is_reg && is_exec            */
    /* --------------------------------------------------------------------- */
    if (is_reg && IS_SUID(mode) && is_exec) {
        out_record->finding_type = FINDING_SUID_ROOT;
        strncpy(out_record->rule_id, "SEC-002", sizeof(out_record->rule_id) - 1);
        if (st->st_uid == 0) {
            out_record->severity = SEV_CRITICAL;
            snprintf(out_record->description, sizeof(out_record->description),
                     "SUID bit (04000) on root executable enables unprivileged execution as root (privilege escalation).");
        } else {
            out_record->severity = SEV_HIGH;
            snprintf(out_record->description, sizeof(out_record->description),
                     "SUID bit (04000) on binary allows execution with privileges of %s (UID %d).",
                     out_record->owner_name, (int)st->st_uid);
        }
        /* Safe remediation: Strip SUID bit: perms & ~S_ISUID */
        out_record->recommended_mode = perms & ~(mode_t)S_ISUID;
        return true;
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-005: Sensitive Credential or Key File Exposure (HIGH/CRIT)   */
    /* Binary condition: Sensitive file matching name pattern AND             */
    /*                   group/others have read or write access              */
    /* --------------------------------------------------------------------- */
    if (is_reg && is_sensitive_credential_file(path)) {
        if ((mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) != 0) {
            out_record->finding_type = FINDING_SENSITIVE_EXPOSURE;
            out_record->severity = (mode & (S_IROTH | S_IWOTH)) ? SEV_CRITICAL : SEV_HIGH;
            strncpy(out_record->rule_id, "SEC-005", sizeof(out_record->rule_id) - 1);
            snprintf(out_record->description, sizeof(out_record->description),
                     "Sensitive secret or private key is accessible to group/world (current: 0%04o, required: 0600).",
                     (unsigned int)perms);
            /* Recommended mode: Strict owner-only read/write (0600) */
            out_record->recommended_mode = (S_IRUSR | S_IWUSR);
            return true;
        }
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-004: World-Writable Directory Missing Sticky Bit (HIGH)      */
    /* Binary condition: S_ISDIR(mode) && (mode & 0002) && !(mode & 01000)   */
    /* --------------------------------------------------------------------- */
    if (is_dir && IS_WORLD_WRITABLE(mode) && !IS_STICKY(mode)) {
        out_record->finding_type = FINDING_STICKY_MISSING;
        out_record->severity = SEV_HIGH;
        strncpy(out_record->rule_id, "SEC-004", sizeof(out_record->rule_id) - 1);
        snprintf(out_record->description, sizeof(out_record->description),
                 "World-writable directory lacks Sticky Bit (01000). Any user can delete or rename other users' files.");
        /* Recommended fix: Add Sticky Bit: perms | S_ISVTX (e.g. 01777) */
        out_record->recommended_mode = perms | S_ISVTX;
        return true;
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-003: SGID Bit on Binary Executable (HIGH)                    */
    /* Binary condition: (mode & 02000) != 0 && is_reg && is_exec            */
    /* --------------------------------------------------------------------- */
    if (is_reg && IS_SGID(mode) && is_exec) {
        out_record->finding_type = FINDING_SGID_BINARY;
        out_record->severity = SEV_HIGH;
        strncpy(out_record->rule_id, "SEC-003", sizeof(out_record->rule_id) - 1);
        snprintf(out_record->description, sizeof(out_record->description),
                 "SGID bit (02000) on executable allows process to run with group privileges of %s (GID %d).",
                 out_record->group_name, (int)st->st_gid);
        /* Recommended fix: Strip SGID bit */
        out_record->recommended_mode = perms & ~(mode_t)S_ISGID;
        return true;
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-001: World-Writable Executable Script or System File (CRIT)  */
    /* Binary condition: is_reg && (mode & 0002) && (is_exec || uid == 0)    */
    /* --------------------------------------------------------------------- */
    if (is_reg && IS_WORLD_WRITABLE(mode) && (is_exec || st->st_uid == 0)) {
        out_record->finding_type = FINDING_WORLD_WRITABLE_ROOT;
        out_record->severity = SEV_CRITICAL;
        strncpy(out_record->rule_id, "SEC-001", sizeof(out_record->rule_id) - 1);
        snprintf(out_record->description, sizeof(out_record->description),
                 "World-writable executable/root file allows arbitrary code injection by any local user.");
        /* Recommended fix: Strip world write and group write */
        out_record->recommended_mode = is_exec ? (perms & ~(mode_t)(S_IWGRP | S_IWOTH)) : 0644;
        return true;
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-006: Orphaned Inode with Unmapped UID or GID (MEDIUM)        */
    /* Condition: getpwuid(uid) == NULL || getgrgid(gid) == NULL             */
    /* --------------------------------------------------------------------- */
    if (strcmp(out_record->owner_name, "UNKNOWN") == 0 || strcmp(out_record->group_name, "UNKNOWN") == 0) {
        out_record->finding_type = FINDING_ORPHANED_INODE;
        out_record->severity = SEV_MEDIUM;
        strncpy(out_record->rule_id, "SEC-006", sizeof(out_record->rule_id) - 1);
        snprintf(out_record->description, sizeof(out_record->description),
                 "Orphaned inode owned by nonexistent UID %d / GID %d. Re-created users could claim ownership.",
                 (int)st->st_uid, (int)st->st_gid);
        out_record->recommended_mode = (perms & 07700); /* Restrict until chown */
        return true;
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-007: General World-Writable Regular File (MEDIUM)            */
    /* Binary condition: is_reg && (mode & 0002)                             */
    /* --------------------------------------------------------------------- */
    if (is_reg && IS_WORLD_WRITABLE(mode)) {
        out_record->finding_type = FINDING_WORLD_WRITABLE_FILE;
        out_record->severity = SEV_MEDIUM;
        strncpy(out_record->rule_id, "SEC-007", sizeof(out_record->rule_id) - 1);
        snprintf(out_record->description, sizeof(out_record->description),
                 "World-writable regular file can be modified or truncated by any local user.");
        /* Recommended fix: Strip S_IWOTH */
        out_record->recommended_mode = perms & ~(mode_t)S_IWOTH;
        return true;
    }

    /* --------------------------------------------------------------------- */
    /* RULE SEC-008: World-Readable Database Backup / Log Leak (LOW)         */
    /* Binary condition: Backup extension && (mode & 0004)                   */
    /* --------------------------------------------------------------------- */
    if (is_reg && is_backup_or_dump_file(path) && IS_WORLD_READABLE(mode)) {
        out_record->finding_type = FINDING_SENSITIVE_EXPOSURE;
        out_record->severity = SEV_LOW;
        strncpy(out_record->rule_id, "SEC-008", sizeof(out_record->rule_id) - 1);
        snprintf(out_record->description, sizeof(out_record->description),
                 "Database backup, SQL dump, or log file is world-readable (information disclosure risk).");
        /* Recommended fix: Strip world read/write */
        out_record->recommended_mode = perms & ~(mode_t)(S_IROTH | S_IWOTH);
        return true;
    }

    return false;
}
