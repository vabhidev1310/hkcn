/**
 * @file analyzer.h
 * @brief Core Header for Linux File Permission Analyzer (LfPA)
 * @course 25CS2104E - Operating Systems and Systems Programming (OSSP)
 * 
 * Course Outcome (CO) Mapping:
 * - CO1: POSIX System Calls (lstat, open, write, close, chmod, errno, perror)
 * - CO2: Process Control (fork, waitpid, chmod for child-isolated auto-remediation)
 * - CO3: Signals & IPC (sigaction for graceful SIGINT Ctrl+C interception)
 * - CO4: Dynamic Memory Management (heap-allocated AuditRecord database via malloc/realloc/free)
 * - CO5: Virtual File System & Inode Metadata (opendir, readdir, lstat, getpwuid, getgrgid)
 * - CO6: Concurrency & Synchronization (pthread_mutex_t protected database access)
 */

#ifndef ANALYZER_H
#define ANALYZER_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>

/* ========================================================================= */
/*                          MACROS & CONSTANTS                               */
/* ========================================================================= */

#define LfPA_VERSION "1.2.0"
#define LfPA_BANNER_LINE "================================================================================"

/* ANSI Terminal Color Escape Codes */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_WHITE   "\033[1;37m"
#define CLR_BG_RED  "\033[41;1;37m"

/* Path and String Limits */
#define MAX_PATH_LEN    1024
#define MAX_NAME_LEN    64
#define MAX_DESC_LEN    256
#define MAX_STATUS_LEN  128
#define INITIAL_DB_CAP  32

/* Bitmask Helper Macros (Octal POSIX masks) */
#define IS_WORLD_WRITABLE(m)  (((m) & S_IWOTH) != 0)
#define IS_WORLD_READABLE(m)  (((m) & S_IROTH) != 0)
#define IS_GROUP_WRITABLE(m)  (((m) & S_IWGRP) != 0)
#define IS_SUID(m)            (((m) & S_ISUID) != 0)
#define IS_SGID(m)            (((m) & S_ISGID) != 0)
#define IS_STICKY(m)          (((m) & S_ISVTX) != 0)

/* ========================================================================= */
/*                          ENUMERATED TYPES                                 */
/* ========================================================================= */

/**
 * @brief Severity level classification for security findings.
 */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} SeverityLevel;

/**
 * @brief Security violation category taxonomy.
 */
typedef enum {
    FINDING_NONE = 0,
    FINDING_WORLD_WRITABLE_FILE,    /**< General file writable by any local user */
    FINDING_WORLD_WRITABLE_ROOT,    /**< Root or sensitive config writable by others */
    FINDING_SUID_ROOT,              /**< SUID bit set on root-owned binary */
    FINDING_SGID_BINARY,            /**< SGID bit set on binary */
    FINDING_STICKY_MISSING,         /**< World-writable directory missing Sticky Bit (+t) */
    FINDING_SENSITIVE_EXPOSURE,     /**< Exposed credentials, private keys, or .env */
    FINDING_ORPHANED_INODE,         /**< Inode owned by unmapped UID or GID */
    FINDING_SUSPICIOUS_EXECUTABLE   /**< Executable found in temp or world-writable area */
} FindingType;

/**
 * @brief Supported report export formats.
 */
typedef enum {
    FORMAT_TEXT = 0,
    FORMAT_JSON,
    FORMAT_HTML
} OutputFormat;

/* ========================================================================= */
/*                          CORE DATA STRUCTURES                             */
/* ========================================================================= */

/**
 * @brief Individual security audit finding record.
 * Stores VFS inode metadata, security rule evaluation, and remediation state.
 */
typedef struct {
    char path[MAX_PATH_LEN];
    mode_t raw_mode;                /**< Raw octal mode (st_mode) */
    char perm_str[11];              /**< Formatted permissions e.g. "-rwxrwxrwx" */
    uid_t uid;                      /**< Owner UID */
    gid_t gid;                      /**< Group GID */
    char owner_name[MAX_NAME_LEN];  /**< Resolved via getpwuid() */
    char group_name[MAX_NAME_LEN];  /**< Resolved via getgrgid() */
    ino_t inode_num;                /**< Inode number from struct stat */
    off_t size_bytes;               /**< File size in bytes */
    time_t mtime;                   /**< Last modification timestamp */
    FindingType finding_type;       /**< Category of vulnerability */
    SeverityLevel severity;         /**< Severity rating */
    char rule_id[16];               /**< E.g., "SEC-001" */
    char description[MAX_DESC_LEN]; /**< Human-readable explanation */
    mode_t recommended_mode;        /**< Safe suggested mode, e.g. 0644 */
    bool is_fixed;                  /**< True if auto-remediated */
    char fix_status[MAX_STATUS_LEN];/**< Remediation diagnostic message */
} AuditRecord;

/**
 * @brief In-memory database of audit findings (CO4: Dynamic Memory, CO6: Concurrency).
 */
typedef struct {
    AuditRecord *records;           /**< Dynamically resized array (malloc/realloc/free) */
    size_t count;                   /**< Current number of findings stored */
    size_t capacity;                /**< Allocated capacity */
    pthread_mutex_t lock;           /**< Thread-safe mutex lock (CO6) */
    
    /* Telemetry Counters */
    uint64_t total_files_scanned;
    uint64_t total_dirs_scanned;
    uint64_t total_symlinks_skipped;
    uint64_t critical_count;
    uint64_t high_count;
    uint64_t medium_count;
    uint64_t low_count;
    uint64_t info_count;
    uint64_t fixed_count;
    double scan_duration_ms;
} AuditDB;

/**
 * @brief Runtime configuration arguments passed from CLI.
 */
typedef struct {
    char target_path[MAX_PATH_LEN];
    bool recursive;
    bool auto_fix;
    bool dry_run;
    bool verbose;
    OutputFormat format;
    char report_file[MAX_PATH_LEN];
    int num_threads;
    SeverityLevel min_severity;
} ScanConfig;

/* Global interrupt flag for signal handling (CO3) */
extern volatile sig_atomic_t g_stop_requested;

/* ========================================================================= */
/*                          FUNCTION PROTOTYPES                              */
/* ========================================================================= */

/* --- Module 1: CLI & Signal Management (Member 1 - CO3) --- */
void setup_signal_handlers(void);
void handle_sigint(int sig);
void print_banner(void);
void print_help(const char *prog_name);
void print_version(void);
int parse_arguments(int argc, char *argv[], ScanConfig *config);

/* --- Module 2: VFS Scanner & Dynamic Memory (Member 2 - CO4, CO5, CO6) --- */
int audit_db_init(AuditDB *db, size_t initial_cap);
int audit_db_add(AuditDB *db, const AuditRecord *rec);
void audit_db_free(AuditDB *db);
int scan_file_or_dir(const char *path, const ScanConfig *config, AuditDB *db);
int scan_directory_recursive(const char *dir_path, const ScanConfig *config, AuditDB *db);
void resolve_identity(uid_t uid, gid_t gid, char *out_user, char *out_group);
void format_mode_to_string(mode_t mode, char *out_str);

/* --- Module 3: Security Rules Engine (Member 3 - Bitmask Math) --- */
bool evaluate_inode_security(const char *path, const struct stat *st, AuditRecord *out_record);
bool is_sensitive_credential_file(const char *path);
const char* severity_to_string(SeverityLevel sev);
const char* severity_to_badge(SeverityLevel sev);
const char* finding_type_to_string(FindingType type);

/* --- Module 4: Reporter & Process Fixer (Member 4 - CO1, CO2, CO6) --- */
bool is_safe_path(const char *path);
int remediate_vulnerabilities(AuditDB *db, const ScanConfig *config);
int remediate_single_record(AuditRecord *record, bool dry_run);
void display_terminal_report(const AuditDB *db, const ScanConfig *config);
int export_json_report(const char *filename, const AuditDB *db, const ScanConfig *config);
int export_html_report(const char *filename, const AuditDB *db, const ScanConfig *config);

#endif /* ANALYZER_H */
