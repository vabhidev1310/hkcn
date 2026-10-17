/**
 * @file scanner.c
 * @brief VFS Traversal, Inode Inspection, and Dynamic Memory Management
 * @course 25CS2104E - Operating Systems and Systems Programming (OSSP)
 * @author Team Member 2 (VFS Traversal, Inode Analysis, Dynamic Memory & Concurrency)
 * 
 * Course Outcome Alignment:
 * - CO4: Dynamic Memory Allocation (malloc, realloc, free for AuditDB)
 * - CO5: Virtual File System & Inode Metadata (opendir, readdir, closedir, lstat, getpwuid, getgrgid)
 * - CO6: Thread-safe Synchronization via pthread_mutex_t
 */

#include "analyzer.h"

/* ========================================================================= */
/*               DYNAMIC MEMORY MANAGEMENT (CO4 & CO6)                       */
/* ========================================================================= */

/**
 * @brief Initializes the dynamic findings database on the heap.
 * @param db Pointer to AuditDB structure.
 * @param initial_cap Initial capacity for records array.
 * @return 0 on success, -1 on allocation failure.
 */
int audit_db_init(AuditDB *db, size_t initial_cap) {
    if (!db) return -1;
    memset(db, 0, sizeof(AuditDB));
    
    if (initial_cap == 0) initial_cap = INITIAL_DB_CAP;
    
    db->records = (AuditRecord *)malloc(initial_cap * sizeof(AuditRecord));
    if (!db->records) {
        perror("audit_db_init: malloc failed");
        return -1;
    }
    
    db->capacity = initial_cap;
    db->count = 0;
    
    /* Initialize POSIX Mutex for Concurrency Protection (CO6) */
    if (pthread_mutex_init(&db->lock, NULL) != 0) {
        perror("audit_db_init: pthread_mutex_init failed");
        free(db->records);
        db->records = NULL;
        return -1;
    }
    
    return 0;
}

/**
 * @brief Appends an audit finding to the database with dynamic array growth.
 * Implements amortized O(1) geometric doubling strategy.
 * Thread-safe via POSIX mutex synchronization (CO6).
 * 
 * @param db Pointer to AuditDB.
 * @param rec Pointer to record to insert.
 * @return 0 on success, -1 on failure.
 */
int audit_db_add(AuditDB *db, const AuditRecord *rec) {
    if (!db || !rec) return -1;

    /* Acquire synchronization lock */
    pthread_mutex_lock(&db->lock);

    /* Geometric capacity doubling when limit reached */
    if (db->count >= db->capacity) {
        size_t new_cap = db->capacity * 2;
        AuditRecord *expanded = (AuditRecord *)realloc(db->records, new_cap * sizeof(AuditRecord));
        if (!expanded) {
            perror("audit_db_add: realloc failed");
            pthread_mutex_unlock(&db->lock);
            return -1;
        }
        db->records = expanded;
        db->capacity = new_cap;
    }

    /* Copy record into heap memory */
    memcpy(&db->records[db->count], rec, sizeof(AuditRecord));
    db->count++;

    /* Update live telemetry counters */
    switch (rec->severity) {
        case SEV_CRITICAL: db->critical_count++; break;
        case SEV_HIGH:     db->high_count++;     break;
        case SEV_MEDIUM:   db->medium_count++;   break;
        case SEV_LOW:      db->low_count++;      break;
        case SEV_INFO:     db->info_count++;     break;
        default: break;
    }

    /* Release synchronization lock */
    pthread_mutex_unlock(&db->lock);
    return 0;
}

/**
 * @brief Deallocates all dynamic heap memory and destroys synchronization mutex.
 * Guarantees zero memory leaks under Valgrind analysis.
 */
void audit_db_free(AuditDB *db) {
    if (!db) return;
    pthread_mutex_lock(&db->lock);
    if (db->records) {
        free(db->records);
        db->records = NULL;
    }
    db->count = 0;
    db->capacity = 0;
    pthread_mutex_unlock(&db->lock);
    pthread_mutex_destroy(&db->lock);
}

/* ========================================================================= */
/*               VFS & INODE METADATA RESOLUTION (CO5)                       */
/* ========================================================================= */

/**
 * @brief Resolves numerical UID and GID to human-readable names.
 * Flags unmapped IDs as "UNKNOWN" for orphaned inode detection.
 */
void resolve_identity(uid_t uid, gid_t gid, char *out_user, char *out_group) {
    struct passwd *pw = getpwuid(uid);
    if (pw && pw->pw_name) {
        strncpy(out_user, pw->pw_name, MAX_NAME_LEN - 1);
        out_user[MAX_NAME_LEN - 1] = '\0';
    } else {
        snprintf(out_user, MAX_NAME_LEN, "UNKNOWN(%u)", (unsigned int)uid);
    }

    struct group *gr = getgrgid(gid);
    if (gr && gr->gr_name) {
        strncpy(out_group, gr->gr_name, MAX_NAME_LEN - 1);
        out_group[MAX_NAME_LEN - 1] = '\0';
    } else {
        snprintf(out_group, MAX_NAME_LEN, "UNKNOWN(%u)", (unsigned int)gid);
    }
}

/**
 * @brief Converts POSIX mode_t bitmask into standard 10-character permission string.
 * Accurately represents SUID (s/S), SGID (s/S), and Sticky Bit (t/T).
 */
void format_mode_to_string(mode_t mode, char *out_str) {
    if (!out_str) return;

    /* Inode type */
    if (S_ISDIR(mode))       out_str[0] = 'd';
    else if (S_ISLNK(mode))  out_str[0] = 'l';
    else if (S_ISCHR(mode))  out_str[0] = 'c';
    else if (S_ISBLK(mode))  out_str[0] = 'b';
    else if (S_ISFIFO(mode)) out_str[0] = 'p';
    else if (S_ISSOCK(mode)) out_str[0] = 's';
    else                     out_str[0] = '-';

    /* User Permissions */
    out_str[1] = (mode & S_IRUSR) ? 'r' : '-';
    out_str[2] = (mode & S_IWUSR) ? 'w' : '-';
    if (mode & S_ISUID) {
        out_str[3] = (mode & S_IXUSR) ? 's' : 'S';
    } else {
        out_str[3] = (mode & S_IXUSR) ? 'x' : '-';
    }

    /* Group Permissions */
    out_str[4] = (mode & S_IRGRP) ? 'r' : '-';
    out_str[5] = (mode & S_IWGRP) ? 'w' : '-';
    if (mode & S_ISGID) {
        out_str[6] = (mode & S_IXGRP) ? 's' : 'S';
    } else {
        out_str[6] = (mode & S_IXGRP) ? 'x' : '-';
    }

    /* Others Permissions */
    out_str[7] = (mode & S_IROTH) ? 'r' : '-';
    out_str[8] = (mode & S_IWOTH) ? 'w' : '-';
    if (mode & S_ISVTX) {
        out_str[9] = (mode & S_IXOTH) ? 't' : 'T';
    } else {
        out_str[9] = (mode & S_IXOTH) ? 'x' : '-';
    }

    out_str[10] = '\0';
}

/* ========================================================================= */
/*               RECURSIVE DIRECTORY TRAVERSAL (CO5)                         */
/* ========================================================================= */

/**
 * @brief Inspects a single file or directory inode using lstat().
 * Ensures symbolic links are NOT dereferenced, preventing circular traversal.
 */
int scan_file_or_dir(const char *path, const ScanConfig *config, AuditDB *db) {
    if (!path || !config || !db) return -1;
    
    /* Check for SIGINT interruption (CO3) */
    if (g_stop_requested) return 0;

    struct stat st;
    /* POSIX lstat does NOT follow symbolic links */
    if (lstat(path, &st) != 0) {
        if (config->verbose) {
            fprintf(stderr, "%s[WARN]%s Cannot lstat '%s': %s\n",
                    CLR_YELLOW, CLR_RESET, path, strerror(errno));
        }
        return -1;
    }

    /* Track Symlinks without dereferencing */
    if (S_ISLNK(st.st_mode)) {
        pthread_mutex_lock(&db->lock);
        db->total_symlinks_skipped++;
        pthread_mutex_unlock(&db->lock);
        if (config->verbose) {
            printf("%s[INFO]%s Skipped symlink (no dereference): %s\n",
                   CLR_CYAN, CLR_RESET, path);
        }
        return 0;
    }

    /* Update telemetry counts */
    pthread_mutex_lock(&db->lock);
    if (S_ISDIR(st.st_mode)) {
        db->total_dirs_scanned++;
    } else {
        db->total_files_scanned++;
    }
    pthread_mutex_unlock(&db->lock);

    /* Evaluate inode against security rules engine */
    AuditRecord record;
    if (evaluate_inode_security(path, &st, &record)) {
        if (record.severity >= config->min_severity) {
            audit_db_add(db, &record);
            if (config->verbose) {
                printf("%s Found [%s] %s on %s\n",
                       severity_to_badge(record.severity),
                       record.rule_id,
                       finding_type_to_string(record.finding_type),
                       path);
            }
        }
    }

    /* If directory and recursion is enabled, traverse descendants */
    if (S_ISDIR(st.st_mode) && config->recursive) {
        return scan_directory_recursive(path, config, db);
    }

    return 0;
}

/**
 * @brief Recursively traverses a directory hierarchy using opendir/readdir/closedir.
 */
int scan_directory_recursive(const char *dir_path, const ScanConfig *config, AuditDB *db) {
    if (!dir_path || !config || !db) return -1;
    if (g_stop_requested) return 0;

    DIR *dir = opendir(dir_path);
    if (!dir) {
        if (config->verbose) {
            fprintf(stderr, "%s[WARN]%s opendir failed on '%s': %s\n",
                    CLR_YELLOW, CLR_RESET, dir_path, strerror(errno));
        }
        return -1;
    }

    struct dirent *entry;
    char child_path[MAX_PATH_LEN];

    /* Iterate through directory entries */
    while ((entry = readdir(dir)) != NULL) {
        if (g_stop_requested) break;

        /* Skip '.' and '..' entries */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        /* Safely assemble child path */
        int len = snprintf(child_path, sizeof(child_path), "%s/%s", dir_path, entry->d_name);
        if (len < 0 || len >= (int)sizeof(child_path)) {
            fprintf(stderr, "%s[WARN]%s Path truncated for entry '%s'\n",
                    CLR_YELLOW, CLR_RESET, entry->d_name);
            continue;
        }

        /* Inspect child entry */
        scan_file_or_dir(child_path, config, db);
    }

    closedir(dir);
    return 0;
}
