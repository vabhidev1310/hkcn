/**
 * @file reporter_fixer.c
 * @brief Reporting Engine and Process-Isolated Auto-Remediation System
 * @course 25CS2104E - Operating Systems and Systems Programming (OSSP)
 * @author Team Member 4 (Low-Level POSIX I/O, Fork/Waitpid Remediation & Safety Guardrail)
 * 
 * Course Outcome Alignment:
 * - CO1: POSIX System Calls (open, write, close, chmod, errno, perror)
 * - CO2: Process Control (fork, waitpid, process isolation for safe chmod execution)
 * - Rule #7 Compliance: Safety guardrail (is_safe_path) strictly protecting root/system directories
 */

#include "analyzer.h"

/* System directories protected by Rule #7 Safety Guardrail */
static const char *PROTECTED_SYSTEM_DIRS[] = {
    "/etc",
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib64",
    "/proc",
    "/sys",
    "/dev",
    "/var",
    "/boot",
    "/root",
    NULL
};

/* ========================================================================= */
/*               RULE #7 SAFETY GUARDRAIL ENGINE                             */
/* ========================================================================= */

/**
 * @brief Evaluates whether a target path is safe for automatic remediation.
 * Prevents disruption or accidental bricking of the host operating system.
 * 
 * @param path The filesystem path to be tested.
 * @return true if safe to modify; false if path is inside protected system roots.
 */
bool is_safe_path(const char *path) {
    if (!path || strlen(path) == 0) return false;

    /* Disallow root directory itself */
    if (strcmp(path, "/") == 0) return false;

    /* Resolve canonical path to defeat traversal evasion (e.g., /tmp/../etc) */
    char resolved[MAX_PATH_LEN];
    if (realpath(path, resolved) == NULL) {
        /* If file does not exist yet or cannot be resolved, check raw path string */
        strncpy(resolved, path, sizeof(resolved) - 1);
        resolved[sizeof(resolved) - 1] = '\0';
    }

    /* Check against blacklist of protected operating system hierarchies */
    for (int i = 0; PROTECTED_SYSTEM_DIRS[i] != NULL; ++i) {
        size_t sys_len = strlen(PROTECTED_SYSTEM_DIRS[i]);
        if (strncmp(resolved, PROTECTED_SYSTEM_DIRS[i], sys_len) == 0) {
            /* Exact match or subdirectory match (e.g., /etc/passwd or /bin/sh) */
            if (resolved[sys_len] == '\0' || resolved[sys_len] == '/') {
                return false;
            }
        }
    }

    return true;
}

/* ========================================================================= */
/*               PROCESS CONTROL & AUTO-REMEDIATION (CO1 & CO2)              */
/* ========================================================================= */

/**
 * @brief Remediates a single audit finding within an isolated child process.
 * 
 * Process Control Workflow (CO2):
 * 1. Parent checks is_safe_path() guardrail.
 * 2. Parent calls fork() to create an isolated child address space.
 * 3. Child executes chmod() system call (CO1) with recommended mode.
 * 4. Child exits with status code 0 on success, or 1 on failure.
 * 5. Parent invokes waitpid() to monitor completion and handle child exit status.
 * 
 * @param record Pointer to AuditRecord finding.
 * @param dry_run If true, simulate remediation without altering filesystem.
 * @return 0 on success, -1 on failure or guardrail rejection.
 */
int remediate_single_record(AuditRecord *record, bool dry_run) {
    if (!record) return -1;

    /* Step 1: Rule #7 Safety Guardrail verification */
    if (!is_safe_path(record->path)) {
        snprintf(record->fix_status, sizeof(record->fix_status),
                 "[GUARDRAIL BLOCKED] System path is protected from auto-remediation");
        record->is_fixed = false;
        return -1;
    }

    /* Step 2: Handle Dry Run Simulation */
    if (dry_run) {
        snprintf(record->fix_status, sizeof(record->fix_status),
                 "[DRY-RUN] Would chmod %04o -> %04o",
                 (unsigned int)(record->raw_mode & 07777),
                 (unsigned int)record->recommended_mode);
        record->is_fixed = false;
        return 0;
    }

    /* Ensure stdio buffers are flushed before fork so child does not duplicate buffers */
    fflush(stdout);
    fflush(stderr);

    /* Step 3: Spawn isolated worker child process via fork() (CO2) */
    pid_t pid = fork();
    if (pid < 0) {
        perror("remediate_single_record: fork failed");
        snprintf(record->fix_status, sizeof(record->fix_status),
                 "[FORK ERROR] %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* ------------------------------------------------------------- */
        /* Child Process Context: Isolated from parent memory space      */
        /* System Call: chmod() (CO1)                                    */
        /* ------------------------------------------------------------- */
        mode_t target_mode = record->recommended_mode & 07777;
        if (chmod(record->path, target_mode) != 0) {
            perror("child chmod");
            _exit(EXIT_FAILURE);
        }
        _exit(EXIT_SUCCESS);
    } else {
        /* ------------------------------------------------------------- */
        /* Parent Process Context: Monitor child via waitpid() (CO2)     */
        /* ------------------------------------------------------------- */
        int status = 0;
        pid_t wait_res = waitpid(pid, &status, 0);
        if (wait_res == -1) {
            perror("remediate_single_record: waitpid failed");
            snprintf(record->fix_status, sizeof(record->fix_status),
                     "[WAITPID ERROR] %s", strerror(errno));
            return -1;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            record->is_fixed = true;
            snprintf(record->fix_status, sizeof(record->fix_status),
                     "SUCCESS: Fixed to %04o by child (PID %d)",
                     (unsigned int)record->recommended_mode, pid);
            return 0;
        } else {
            record->is_fixed = false;
            snprintf(record->fix_status, sizeof(record->fix_status),
                     "FAILED: Child process exited with status %d",
                     WIFEXITED(status) ? WEXITSTATUS(status) : -1);
            return -1;
        }
    }
}

/**
 * @brief Iterates through database findings and triggers auto-remediation.
 */
int remediate_vulnerabilities(AuditDB *db, const ScanConfig *config) {
    if (!db || !config) return -1;
    
    printf("\n%s[AUTO-REMEDIATION ENGINE RUNNING]%s\n", CLR_CYAN, CLR_RESET);
    printf("Evaluating %zu audit findings for safe remediation...\n\n", db->count);

    for (size_t i = 0; i < db->count; ++i) {
        AuditRecord *rec = &db->records[i];
        if (remediate_single_record(rec, config->dry_run) == 0 && rec->is_fixed) {
            pthread_mutex_lock(&db->lock);
            db->fixed_count++;
            pthread_mutex_unlock(&db->lock);
        }
    }

    return 0;
}

/* ========================================================================= */
/*               TERMINAL ANSI REPORT GENERATION                             */
/* ========================================================================= */

/**
 * @brief Prints rich ANSI formatted report to stdout.
 */
void display_terminal_report(const AuditDB *db, const ScanConfig *config) {
    if (!db || !config) return;

    printf("\n%s\n", LfPA_BANNER_LINE);
    printf("%s   LINUX FILE PERMISSION ANALYZER - SECURITY AUDIT SUMMARY REPORT%s\n", CLR_BOLD, CLR_RESET);
    printf("%s\n", LfPA_BANNER_LINE);
    printf(" Target Directory : %s%s%s\n", CLR_CYAN, config->target_path, CLR_RESET);
    printf(" Files Inspected  : %lu\n", (unsigned long)db->total_files_scanned);
    printf(" Dirs Inspected   : %lu\n", (unsigned long)db->total_dirs_scanned);
    printf(" Symlinks Skipped : %lu (lstat preserved)\n", (unsigned long)db->total_symlinks_skipped);
    printf(" Total Findings   : %zu\n", db->count);
    printf(" Scan Duration    : %.2f ms\n", db->scan_duration_ms);
    printf("%s\n", LfPA_BANNER_LINE);

    printf("\n%s SEVERITY BREAKDOWN:%s\n", CLR_BOLD, CLR_RESET);
    printf("   CRITICAL : %s%lu%s\n", CLR_RED, (unsigned long)db->critical_count, CLR_RESET);
    printf("   HIGH     : %s%lu%s\n", CLR_YELLOW, (unsigned long)db->high_count, CLR_RESET);
    printf("   MEDIUM   : %s%lu%s\n", CLR_CYAN, (unsigned long)db->medium_count, CLR_RESET);
    printf("   LOW      : %s%lu%s\n", CLR_BLUE, (unsigned long)db->low_count, CLR_RESET);
    if (config->auto_fix) {
        printf("   REMEDIATED : %s%lu%s\n", CLR_GREEN, (unsigned long)db->fixed_count, CLR_RESET);
    }

    if (db->count == 0) {
        printf("\n%s[+] AUDIT RESULT: No insecure permissions detected. System matches baseline.%s\n\n",
               CLR_GREEN, CLR_RESET);
        return;
    }

    printf("\n%s DETAILED FINDINGS TABLE:%s\n", CLR_BOLD, CLR_RESET);
    printf("%-10s %-8s %-11s %-14s %-6s %-32s %s\n",
           "SEVERITY", "RULE ID", "MODE", "OWNER:GROUP", "INODE", "TARGET PATH", "FINDING & STATUS");
    printf("------------------------------------------------------------------------------------------------------------\n");

    for (size_t i = 0; i < db->count; ++i) {
        const AuditRecord *r = &db->records[i];
        char owner_grp[140];
        snprintf(owner_grp, sizeof(owner_grp), "%.63s:%.63s", r->owner_name, r->group_name);

        /* Truncate path if too long for tabular alignment */
        char short_path[36];
        if (strlen(r->path) > 31) {
            snprintf(short_path, sizeof(short_path), "...%.28s", r->path + (strlen(r->path) - 28));
        } else {
            snprintf(short_path, sizeof(short_path), "%.31s", r->path);
        }

        printf("%s %-8s %-11s %-14s %-6lu %-32s %s\n",
               severity_to_badge(r->severity),
               r->rule_id,
               r->perm_str,
               owner_grp,
               (unsigned long)r->inode_num,
               short_path,
               r->description);

        if (r->fix_status[0] != '\0') {
            printf("           %s└─ Remediation:%s %s\n",
                   CLR_DIM, CLR_RESET, r->fix_status);
        }
    }
    printf("------------------------------------------------------------------------------------------------------------\n\n");
}

/* ========================================================================= */
/*               LOW-LEVEL POSIX SYSCALL I/O (CO1)                           */
/* ========================================================================= */

/**
 * @brief Helper to write all bytes to a file descriptor using write() syscall.
 */
static ssize_t write_all_fd(int fd, const char *buf, size_t count) {
    size_t total_written = 0;
    while (total_written < count) {
        ssize_t res = write(fd, buf + total_written, count - total_written);
        if (res < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total_written += res;
    }
    return total_written;
}

/**
 * @brief Exports audit findings to structured JSON format via POSIX system calls.
 * Uses open(), write(), and close() system calls (CO1).
 */
int export_json_report(const char *filename, const AuditDB *db, const ScanConfig *config) {
    if (!filename || !db || !config) return -1;

    /* POSIX open() system call with O_WRONLY | O_CREAT | O_TRUNC (CO1) */
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("export_json_report: open failed");
        return -1;
    }

    char buf[4096];
    int len = snprintf(buf, sizeof(buf),
        "{\n"
        "  \"generator\": \"Linux File Permission Analyzer v%s\",\n"
        "  \"course\": \"25CS2104E - OSSP\",\n"
        "  \"target_path\": \"%s\",\n"
        "  \"timestamp\": %ld,\n"
        "  \"summary\": {\n"
        "    \"total_files_scanned\": %lu,\n"
        "    \"total_dirs_scanned\": %lu,\n"
        "    \"symlinks_skipped\": %lu,\n"
        "    \"total_findings\": %zu,\n"
        "    \"critical\": %lu,\n"
        "    \"high\": %lu,\n"
        "    \"medium\": %lu,\n"
        "    \"low\": %lu,\n"
        "    \"fixed\": %lu,\n"
        "    \"duration_ms\": %.2f\n"
        "  },\n"
        "  \"findings\": [\n",
        LfPA_VERSION,
        config->target_path,
        (long)time(NULL),
        (unsigned long)db->total_files_scanned,
        (unsigned long)db->total_dirs_scanned,
        (unsigned long)db->total_symlinks_skipped,
        db->count,
        (unsigned long)db->critical_count,
        (unsigned long)db->high_count,
        (unsigned long)db->medium_count,
        (unsigned long)db->low_count,
        (unsigned long)db->fixed_count,
        db->scan_duration_ms
    );
    write_all_fd(fd, buf, len);

    for (size_t i = 0; i < db->count; ++i) {
        const AuditRecord *r = &db->records[i];
        len = snprintf(buf, sizeof(buf),
            "    {\n"
            "      \"rule_id\": \"%s\",\n"
            "      \"severity\": \"%s\",\n"
            "      \"path\": \"%s\",\n"
            "      \"mode_octal\": \"0%04o\",\n"
            "      \"permissions\": \"%s\",\n"
            "      \"uid\": %d,\n"
            "      \"gid\": %d,\n"
            "      \"owner\": \"%s\",\n"
            "      \"group\": \"%s\",\n"
            "      \"inode\": %lu,\n"
            "      \"size_bytes\": %ld,\n"
            "      \"description\": \"%s\",\n"
            "      \"recommended_mode\": \"0%04o\",\n"
            "      \"is_fixed\": %s,\n"
            "      \"fix_status\": \"%s\"\n"
            "    }%s\n",
            r->rule_id,
            severity_to_string(r->severity),
            r->path,
            (unsigned int)(r->raw_mode & 07777),
            r->perm_str,
            (int)r->uid,
            (int)r->gid,
            r->owner_name,
            r->group_name,
            (unsigned long)r->inode_num,
            (long)r->size_bytes,
            r->description,
            (unsigned int)r->recommended_mode,
            r->is_fixed ? "true" : "false",
            r->fix_status,
            (i + 1 < db->count) ? "," : ""
        );
        write_all_fd(fd, buf, len);
    }

    len = snprintf(buf, sizeof(buf), "  ]\n}\n");
    write_all_fd(fd, buf, len);

    /* POSIX close() system call */
    close(fd);
    printf("%s[+] JSON Audit Report saved to:%s %s\n", CLR_GREEN, CLR_RESET, filename);
    return 0;
}

/**
 * @brief Exports interactive HTML web report using POSIX open/write/close syscalls.
 */
int export_html_report(const char *filename, const AuditDB *db, const ScanConfig *config) {
    if (!filename || !db || !config) return -1;

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("export_html_report: open failed");
        return -1;
    }

    char buf[4096];
    int len = snprintf(buf, sizeof(buf),
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "  <title>Linux File Permission Analyzer - Report</title>\n"
        "  <style>\n"
        "    :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --border: #334155; --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #3b82f6; --success: #10b981; }\n"
        "    * { box-sizing: border-box; margin: 0; padding: 0; }\n"
        "    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }\n"
        "    .container { max-width: 1200px; margin: 0 auto; }\n"
        "    header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; display: flex; justify-content: space-between; align-items: center; }\n"
        "    h1 { font-size: 1.8rem; font-weight: 700; color: #38bdf8; }\n"
        "    .subtitle { color: var(--muted); font-size: 0.9rem; margin-top: 0.25rem; }\n"
        "    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }\n"
        "    .kpi-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; text-align: center; }\n"
        "    .kpi-val { font-size: 2rem; font-weight: 700; margin-top: 0.5rem; }\n"
        "    .val-crit { color: var(--crit); }\n"
        "    .val-high { color: var(--high); }\n"
        "    .val-med { color: var(--med); }\n"
        "    .val-fixed { color: var(--success); }\n"
        "    table { width: 100%%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; margin-top: 1rem; font-size: 0.88rem; }\n"
        "    th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); }\n"
        "    th { background: #111827; color: var(--muted); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }\n"
        "    tr:hover { background: rgba(255,255,255,0.02); }\n"
        "    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }\n"
        "    .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--crit); border: 1px solid var(--crit); }\n"
        "    .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }\n"
        "    .badge-MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--med); border: 1px solid var(--med); }\n"
        "    .badge-LOW { background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }\n"
        "    code { font-family: 'Courier New', Courier, monospace; background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #a5f3fc; }\n"
        "  </style>\n"
        "</head>\n"
        "<body>\n"
        "<div class=\"container\">\n"
        "  <header>\n"
        "    <div>\n"
        "      <h1>Linux File Permission Analyzer</h1>\n"
        "      <div class=\"subtitle\">Course 25CS2104E - Operating Systems & Systems Programming | Report Export</div>\n"
        "    </div>\n"
        "    <div style=\"text-align: right; color: var(--muted); font-size: 0.85rem;\">\n"
        "      Target: <code>%s</code><br>Scanned: %lu files in %.2f ms\n"
        "    </div>\n"
        "  </header>\n"
        "  <div class=\"kpi-grid\">\n"
        "    <div class=\"kpi-card\"><div>Total Findings</div><div class=\"kpi-val\">%zu</div></div>\n"
        "    <div class=\"kpi-card\"><div>Critical Risk</div><div class=\"kpi-val val-crit\">%lu</div></div>\n"
        "    <div class=\"kpi-card\"><div>High Risk</div><div class=\"kpi-val val-high\">%lu</div></div>\n"
        "    <div class=\"kpi-card\"><div>Medium Risk</div><div class=\"kpi-val val-med\">%lu</div></div>\n"
        "    <div class=\"kpi-card\"><div>Remediated</div><div class=\"kpi-val val-fixed\">%lu</div></div>\n"
        "  </div>\n"
        "  <table>\n"
        "    <thead>\n"
        "      <tr>\n"
        "        <th>Severity</th>\n"
        "        <th>Rule</th>\n"
        "        <th>Mode</th>\n"
        "        <th>Owner</th>\n"
        "        <th>Path</th>\n"
        "        <th>Description</th>\n"
        "        <th>Remediation Status</th>\n"
        "      </tr>\n"
        "    </thead>\n"
        "    <tbody>\n",
        config->target_path,
        (unsigned long)db->total_files_scanned,
        db->scan_duration_ms,
        db->count,
        (unsigned long)db->critical_count,
        (unsigned long)db->high_count,
        (unsigned long)db->medium_count,
        (unsigned long)db->fixed_count
    );
    write_all_fd(fd, buf, len);

    for (size_t i = 0; i < db->count; ++i) {
        const AuditRecord *r = &db->records[i];
        len = snprintf(buf, sizeof(buf),
            "      <tr>\n"
            "        <td><span class=\"badge badge-%s\">%s</span></td>\n"
            "        <td><code>%s</code></td>\n"
            "        <td><code>%s (0%04o)</code></td>\n"
            "        <td>%s:%s</td>\n"
            "        <td><code>%s</code></td>\n"
            "        <td>%s</td>\n"
            "        <td>%s</td>\n"
            "      </tr>\n",
            severity_to_string(r->severity),
            severity_to_string(r->severity),
            r->rule_id,
            r->perm_str,
            (unsigned int)(r->raw_mode & 07777),
            r->owner_name,
            r->group_name,
            r->path,
            r->description,
            (r->fix_status[0] != '\0') ? r->fix_status : "No fix requested"
        );
        write_all_fd(fd, buf, len);
    }

    len = snprintf(buf, sizeof(buf),
        "    </tbody>\n"
        "  </table>\n"
        "</div>\n"
        "</body>\n"
        "</html>\n"
    );
    write_all_fd(fd, buf, len);

    close(fd);
    printf("%s[+] HTML Web Dashboard saved to:%s %s\n", CLR_GREEN, CLR_RESET, filename);
    return 0;
}
