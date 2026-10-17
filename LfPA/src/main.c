/**
 * @file main.c
 * @brief Entrypoint, CLI Parser, Signal Handling, and Workflow Controller
 * @course 25CS2104E - Operating Systems and Systems Programming (OSSP)
 * @author Team Member 1 (CLI, Signal Handling & Workflow Orchestration)
 * 
 * Course Outcome Alignment:
 * - CO3: Signals & IPC (POSIX sigaction for graceful SIGINT Ctrl+C interception)
 * - CO1: POSIX System Calls & Error Checking
 * - Workflow orchestration across Scanner, Rules Engine, and Reporter/Fixer
 */

#include "analyzer.h"
#include <getopt.h>

/* Global interrupt flag (CO3) */
volatile sig_atomic_t g_stop_requested = 0;

/**
 * @brief POSIX Signal Handler for SIGINT (Ctrl+C).
 * Guarantees async-signal-safety by avoiding stdio and using write() syscall.
 */
void handle_sigint(int sig) {
    (void)sig;
    g_stop_requested = 1;
    const char msg[] = "\n\033[1;33m[!] SIGINT (Ctrl+C) caught. Gracefully flushing gathered audit records...\033[0m\n";
    /* Safe write() system call inside signal context */
    ssize_t ret = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ret;
}

/**
 * @brief Configures POSIX sigaction handler for SIGINT (CO3).
 */
void setup_signal_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        perror("setup_signal_handlers: sigaction failed");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Prints ASCII Art Banner and Academic Header.
 */
void print_banner(void) {
    printf("%s", CLR_CYAN);
    printf("  _     _                   ______ _ _        ___              _                     \n");
    printf(" | |   (_)_ __  _   ___  __|  ____(_) | ___  / _ \\ _ __   __ _| |_   _ _______ _ __ \n");
    printf(" | |   | | '_ \\| | | \\ \\/ /| |__   _| |/ _ \\/ /_\\ \\ '_ \\ / _` | | | | |_  / _ \\ '__|\n");
    printf(" | |___| | | | | |_| |>  < |  __| | | |  __/  _  | | | | (_| | | |_| |/ /  __/ |   \n");
    printf(" |_____|_|_| |_|\\__,_/_/\\_\\|_|    |_|_|\\___/_/ \\_|_| |_|\\__,_|_|\\__, /___\\___|_|   \n");
    printf("                                                                 |___/              \n");
    printf("%s", CLR_RESET);
    printf("%s Linux File Permission Analyzer (LfPA) v%s%s\n", CLR_BOLD, LfPA_VERSION, CLR_RESET);
    printf(" Course: %s25CS2104E - Operating Systems and Systems Programming (OSSP)%s\n", CLR_YELLOW, CLR_RESET);
    printf(" Compliant with Syllabus Outcomes: CO1, CO2, CO3, CO4, CO5, CO6\n");
    printf("%s\n\n", LfPA_BANNER_LINE);
}

/**
 * @brief Prints CLI usage instructions.
 */
void print_help(const char *prog_name) {
    print_banner();
    printf("USAGE:\n");
    printf("  %s [OPTIONS]\n\n", prog_name);
    printf("OPTIONS:\n");
    printf("  -p, --path <dir>         Target directory or file to audit (Default: '.')\n");
    printf("  -r, --recursive          Enable recursive directory traversal (Default: enabled)\n");
    printf("  -n, --no-recursive       Disable recursive traversal (audit single level)\n");
    printf("  -f, --fix                Auto-remediate insecure permissions using child processes (CO2)\n");
    printf("  -d, --dry-run            Simulate remediation actions without modifying filesystem\n");
    printf("  -o, --output <file>      Export findings report to file (.html, .json, or .txt)\n");
    printf("      --format <fmt>       Specify export format: 'text', 'json', or 'html'\n");
    printf("  -s, --min-severity <lvl> Filter minimum severity: info, low, medium, high, critical\n");
    printf("  -v, --verbose            Display real-time traversal and inode metadata\n");
    printf("  -h, --help               Display this help and exit\n");
    printf("  -V, --version            Display version information\n\n");
    printf("SAFETY GUARDRAIL (Rule #7):\n");
    printf("  The '--fix' option automatically refuses to modify protected system directories\n");
    printf("  (/etc, /bin, /sbin, /usr, /lib, /sys, /proc, /dev) to prevent host disruption.\n\n");
    printf("EXAMPLES:\n");
    printf("  %s -p ./demo_sandbox\n", prog_name);
    printf("  %s -p ./demo_sandbox -o report.html\n", prog_name);
    printf("  %s -p ./demo_sandbox --fix --dry-run\n", prog_name);
    printf("  %s -p ./demo_sandbox --fix -o report.json\n\n", prog_name);
}

/**
 * @brief Prints version and syllabus outcome details.
 */
void print_version(void) {
    printf("Linux File Permission Analyzer (LfPA) v%s\n", LfPA_VERSION);
    printf("Course: 25CS2104E - Operating Systems and Systems Programming (OSSP)\n");
    printf("Architectural Mapping:\n");
    printf("  - CO1: POSIX Syscalls (lstat, open, write, close, chmod, errno)\n");
    printf("  - CO2: Process Control (fork, waitpid, isolated child remediation)\n");
    printf("  - CO3: Signals & IPC (sigaction SIGINT graceful scan interruption)\n");
    printf("  - CO4: Dynamic Memory (malloc, realloc geometric growth, zero-leak free)\n");
    printf("  - CO5: Virtual File System (opendir, readdir, lstat, getpwuid, getgrgid)\n");
    printf("  - CO6: Synchronization (pthread_mutex_t protected findings store)\n");
}

/**
 * @brief Parses command-line arguments into ScanConfig.
 */
int parse_arguments(int argc, char *argv[], ScanConfig *config) {
    /* Set Defaults */
    memset(config, 0, sizeof(ScanConfig));
    strncpy(config->target_path, ".", sizeof(config->target_path) - 1);
    config->recursive = true;
    config->auto_fix = false;
    config->dry_run = false;
    config->verbose = false;
    config->format = FORMAT_TEXT;
    config->report_file[0] = '\0';
    config->num_threads = 1;
    config->min_severity = SEV_INFO;

    static struct option long_options[] = {
        {"path",         required_argument, 0, 'p'},
        {"recursive",    no_argument,       0, 'r'},
        {"no-recursive", no_argument,       0, 'n'},
        {"fix",          no_argument,       0, 'f'},
        {"dry-run",      no_argument,       0, 'd'},
        {"output",       required_argument, 0, 'o'},
        {"format",       required_argument, 0, 1001},
        {"min-severity", required_argument, 0, 's'},
        {"verbose",      no_argument,       0, 'v'},
        {"help",         no_argument,       0, 'h'},
        {"version",      no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:rnfdo:s:vhV", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                strncpy(config->target_path, optarg, sizeof(config->target_path) - 1);
                break;
            case 'r':
                config->recursive = true;
                break;
            case 'n':
                config->recursive = false;
                break;
            case 'f':
                config->auto_fix = true;
                break;
            case 'd':
                config->dry_run = true;
                break;
            case 'o':
                strncpy(config->report_file, optarg, sizeof(config->report_file) - 1);
                /* Auto-detect format from extension if not explicitly set */
                if (strstr(optarg, ".html") != NULL || strstr(optarg, ".htm") != NULL) {
                    config->format = FORMAT_HTML;
                } else if (strstr(optarg, ".json") != NULL) {
                    config->format = FORMAT_JSON;
                }
                break;
            case 1001: /* --format */
                if (strcasecmp(optarg, "json") == 0) {
                    config->format = FORMAT_JSON;
                } else if (strcasecmp(optarg, "html") == 0) {
                    config->format = FORMAT_HTML;
                } else {
                    config->format = FORMAT_TEXT;
                }
                break;
            case 's':
                if (strcasecmp(optarg, "critical") == 0 || strcasecmp(optarg, "crit") == 0) {
                    config->min_severity = SEV_CRITICAL;
                } else if (strcasecmp(optarg, "high") == 0) {
                    config->min_severity = SEV_HIGH;
                } else if (strcasecmp(optarg, "medium") == 0 || strcasecmp(optarg, "med") == 0) {
                    config->min_severity = SEV_MEDIUM;
                } else if (strcasecmp(optarg, "low") == 0) {
                    config->min_severity = SEV_LOW;
                } else {
                    config->min_severity = SEV_INFO;
                }
                break;
            case 'v':
                config->verbose = true;
                break;
            case 'h':
                print_help(argv[0]);
                exit(EXIT_SUCCESS);
            case 'V':
                print_version();
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return -1;
        }
    }

    return 0;
}

/* ========================================================================= */
/*                          MAIN WORKFLOW ENTRYPOINT                         */
/* ========================================================================= */

int main(int argc, char *argv[]) {
    ScanConfig config;
    if (parse_arguments(argc, argv, &config) != 0) {
        return EXIT_FAILURE;
    }

    /* Print header banner */
    print_banner();

    /* Tier 1 Safety Guardrail (Rule #7): Refuse --fix on protected system roots */
    if (config.auto_fix && !is_safe_path(config.target_path)) {
        fprintf(stderr, "%s[GUARDRAIL REFUSAL] Target path '%s' is an operating system protected hierarchy.\n"
                        "System path is protected from auto-remediation by Rule #7 Safety Guardrail to prevent host disruption.%s\n\n",
                CLR_RED, config.target_path, CLR_RESET);
        return EXIT_FAILURE;
    }

    /* Step 1: Install POSIX SIGINT signal handler (CO3) */
    setup_signal_handlers();

    /* Step 2: Initialize Heap-allocated findings database (CO4 & CO6) */
    AuditDB db;
    if (audit_db_init(&db, INITIAL_DB_CAP) != 0) {
        fprintf(stderr, "%s[FATAL] Failed to initialize audit database.%s\n", CLR_RED, CLR_RESET);
        return EXIT_FAILURE;
    }

    printf("%s[*] Target Path         :%s %s\n", CLR_CYAN, CLR_RESET, config.target_path);
    printf("%s[*] Recursive Traversal :%s %s\n", CLR_CYAN, CLR_RESET, config.recursive ? "Enabled" : "Disabled");
    printf("%s[*] Auto-Remediation    :%s %s%s\n", CLR_CYAN, CLR_RESET,
           config.auto_fix ? (config.dry_run ? "Simulation (Dry-Run)" : "Enabled (Child-Process fork/chmod)") : "Disabled",
           config.auto_fix && !config.dry_run ? " [Rule #7 Guardrail Active]" : "");
    printf("%s[*] Traversal Engine    :%s POSIX lstat() + opendir()/readdir() [No Symlink Dereference]\n\n", CLR_CYAN, CLR_RESET);

    /* Step 3: High-resolution benchmark timing */
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    /* Step 4: Execute VFS Inode Traversal (CO5) */
    printf("Scanning filesystem hierarchy... (Press Ctrl+C to interrupt gracefully)\n");
    scan_file_or_dir(config.target_path, &config, &db);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    db.scan_duration_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1000000.0;

    if (g_stop_requested) {
        printf("\n%s[!] Scan interrupted by user signal. Reporting %zu findings gathered so far.%s\n",
               CLR_YELLOW, db.count, CLR_RESET);
    } else {
        printf("%s[+] Scan completed successfully in %.2f ms.%s\n", CLR_GREEN, db.scan_duration_ms, CLR_RESET);
    }

    /* Step 5: Execute Process Control Auto-Remediation if requested (CO2) */
    if (config.auto_fix && db.count > 0) {
        remediate_vulnerabilities(&db, &config);
    }

    /* Step 6: Render Terminal Report */
    display_terminal_report(&db, &config);

    /* Step 7: Export to File via Low-Level Syscalls (CO1) if specified */
    if (config.report_file[0] != '\0') {
        if (config.format == FORMAT_HTML) {
            export_html_report(config.report_file, &db, &config);
        } else if (config.format == FORMAT_JSON) {
            export_json_report(config.report_file, &db, &config);
        } else {
            /* Text export */
            printf("[*] Text export to file not implemented directly; redirect terminal output or use .html/.json\n");
        }
    }

    /* Step 8: Clean up all dynamically allocated memory (CO4) */
    audit_db_free(&db);

    return EXIT_SUCCESS;
}
