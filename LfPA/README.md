# Linux File Permission Analyzer (LfPA)

[![Standard: POSIX C11](https://img.shields.io/badge/Standard-POSIX_C11-00599C?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Course: 25CS2104E](https://img.shields.io/badge/Course-25CS2104E_OSSP-4B0082)](https://github.com/)
[![Build: GNU Make](https://img.shields.io/badge/Build-GNU_Make-007acc?logo=gnu&logoColor=white)](https://www.gnu.org/software/make/)
[![Memory: Valgrind 0 Leaks](https://img.shields.io/badge/Memory-Valgrind_0_Leaks-brightgreen)](https://valgrind.org/)
[![Tests: 14/14 Passed](https://img.shields.io/badge/Tests-14%2F14_PASS-success)](scripts/run_tests.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```text
  _     _                   ______ _ _        ___              _                     
 | |   (_)_ __  _   ___  __|  ____(_) | ___  / _ \ _ __   __ _| |_   _ _______ _ __ 
 | |   | | '_ \| | | \ \/ /| |__   _| |/ _ \/ /_\ \ '_ \ / _` | | | | |_  / _ \ '__|
 | |___| | | | | |_| |>  < |  __| | | |  __/  _  | | | | (_| | | |_| |/ /  __/ |   
 |_____|_|_| |_|\__,_/_/\_\|_|    |_|_|\___/_/ \_|_| |_|\__,_|_|\__, /___\___|_|   
                                                                 |___/              
 Linux File Permission Analyzer (LfPA) v1.2.0
 Course: 25CS2104E - Operating Systems and Systems Programming (OSSP)
```

The **Linux File Permission Analyzer (LfPA)** is an industrial-grade, zero-dependency systems auditing and auto-remediation utility written in standard POSIX C11. It recursively traverses the Linux Virtual File System (VFS), inspects inode metadata without dereferencing symbolic links, evaluates 12-bit Discretionary Access Control (DAC) permission bitmasks, detects dangerous security misconfigurations (SUID root binaries, world-writable scripts, exposed private keys, and shared directories missing sticky bits), and safely auto-remediates vulnerabilities using isolated child worker processes.

Developed for the course **25CS2104E - Operating Systems and Systems Programming (OSSP)**, LfPA strictly complies with **Rule #7 Controlled Environment Safety Guardrails** to prevent system disruption.

---

## 1. Course Outcomes (CO1–CO6) Syllabus Alignment

| Outcome | Theoretical Topic | Concrete Implementation in LfPA | File Location |
|---|---|---|---|
| **CO1** | System Calls & OS Protection | POSIX `lstat`, `open`, `write`, `close`, `chmod`, `errno`/`perror` | [`src/reporter_fixer.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/reporter_fixer.c) |
| **CO2** | Process Control | Child process isolation via `fork()`, `waitpid()`, and `chmod()` | [`src/reporter_fixer.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/reporter_fixer.c) |
| **CO3** | Signals & IPC | Safe `sigaction()` handler catching `SIGINT` (`Ctrl+C`) with atomic flush | [`src/main.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/main.c) |
| **CO4** | Dynamic Memory Management | Dynamic heap array `AuditDB` (`malloc`, `realloc` geometric doubling, `free`) | [`src/scanner.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/scanner.c) |
| **CO5** | VFS & Inode Abstractions | `opendir()`, `readdir()`, `closedir()`, `lstat()`, `getpwuid()`, `getgrgid()` | [`src/scanner.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/scanner.c) |
| **CO6** | Concurrency & Sync | Thread-safe data insertion guarded by POSIX `pthread_mutex_t` | [`src/scanner.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/scanner.c) |

---

## 2. Modular Architecture & Team Viva Breakdown

The codebase is organized into four distinct modules, enabling each team member to demonstrate complete technical ownership during the laboratory viva:

```text
linux-permission-analyzer/
├── include/
│   └── analyzer.h          # Shared structs (AuditRecord, AuditDB), macros, prototypes
├── src/
│   ├── main.c              # CLI parser, SIGINT sigaction handler, controller (Member 1 - CO3)
│   ├── scanner.c           # VFS traversal (lstat/readdir), heap memory, mutex (Member 2 - CO4, CO5, CO6)
│   ├── rules_engine.c      # Bitmask math (S_IRWXU, S_ISUID, S_ISVTX), rules (Member 3 - CO5)
│   └── reporter_fixer.c    # POSIX syscall reports, fork/waitpid auto-fix, guardrails (Member 4 - CO1, CO2)
├── scripts/
│   ├── setup_sandbox.sh    # Builds controlled vulnerable test fixtures (Rule #7)
│   └── run_tests.sh        # Automated 14-assertion test suite (100% PASS)
├── docs/
│   ├── PROJECT_REPORT.md   # Formal academic project report with syllabus mapping
│   ├── PPT_SLIDES.md       # 15-slide presentation deck with complete speaker notes
│   └── TEAM_VIVA_GUIDE.md  # Viva preparation guide with 25+ technical Q&As
├── Makefile                # Targets: all, demo, test, fix, valgrind, strace, clean
├── .gitignore              # Ignores binaries, objects, demo_sandbox, and generated reports
└── README.md               # GitHub documentation
```

---

## 3. Vulnerability Detection Taxonomy

LfPA enforces an 8-rule security heuristic engine powered by bitwise mathematics:

| Rule ID | Severity | Description | Inode Bitmask Condition | Remediation Target |
|---|---|---|---|---|
| **SEC-001** | **CRITICAL** | World-Writable Script or Executable | `is_reg && (mode & 0002) && (is_exec || uid == 0)` | `mode & ~(S_IWGRP \| S_IWOTH)` (e.g., `0755`) |
| **SEC-002** | **CRITICAL** | SUID Bit on Root-Owned Binary | `is_reg && (mode & 04000) && is_exec && uid == 0` | `mode & ~S_ISUID` (strip SUID bit) |
| **SEC-003** | **HIGH** | SGID Bit on Binary Executable | `is_reg && (mode & 02000) && is_exec` | `mode & ~S_ISGID` (strip SGID bit) |
| **SEC-004** | **HIGH** | World-Writable Dir Missing Sticky Bit | `is_dir && (mode & 0002) && !(mode & 01000)` | `mode \| S_ISVTX` (`01777` sticky bit) |
| **SEC-005** | **HIGH/CRIT**| Exposed Private Key or Credentials | `is_reg && is_sensitive && (mode & 0077) != 0` | Strict `0600` (`-rw-------`) |
| **SEC-006** | **MEDIUM** | Orphaned Inode (Deleted UID/GID) | `getpwuid(uid) == NULL \|\| getgrgid(gid) == NULL` | Restrict to `0700` and flag for audit |
| **SEC-007** | **MEDIUM** | General World-Writable File | `is_reg && (mode & 0002)` | `mode & ~S_IWOTH` (e.g., `0644`) |
| **SEC-008** | **LOW** | World-Readable Database / SQL Dump | `is_reg && is_backup && (mode & 0004)` | `mode & ~(S_IROTH \| S_IWOTH)` (`0640`) |

---

## 4. Rule #7 Compliance: Controlled Environment Safety Guardrail

The course rubric strictly mandates safe execution without disrupting host system files or other users:

1. **Tier 1 (CLI Target Rejection):** If `--fix` is passed against `/etc`, `/bin`, `/sbin`, `/usr`, `/lib`, `/sys`, `/proc`, `/dev`, `/boot`, or `/root`, execution halts immediately with a fatal guardrail message.
2. **Tier 2 (Per-Inode Canonical Path Check):** Before modifying any inode, `is_safe_path()` resolves the canonical path with `realpath()` to defeat directory traversal tricks (`../etc`). Any modification inside system hierarchies is blocked and marked `[GUARDRAIL BLOCKED]`.
3. **Isolated Test Sandbox:** All demonstration and testing is performed in `./demo_sandbox` populated by `scripts/setup_sandbox.sh`.

---

## 5. Quickstart & Compilation

### Prerequisites
- Standard Linux toolchain: `gcc`, `make`
- Optional analysis tools: `valgrind`, `strace`

### Build Commands
```bash
# Compile release binary (bin/analyzer)
make all

# Compile with debug symbols for GDB / Valgrind (-g3 -O0)
make debug
```

### Live Demonstration & Testing
```bash
# 1. Run full live audit demo on vulnerable sandbox with HTML report
make demo

# 2. Run automated 14-assertion test validation suite
make test

# 3. Execute live child-process auto-remediation on sandbox
make fix

# 4. Run Valgrind memory leak audit (CO4 verification)
make valgrind

# 5. Clean all build artifacts, objects, reports, and test sandboxes
make clean
```

---

## 6. CLI Usage & Options

```text
USAGE:
  ./bin/analyzer [OPTIONS]

OPTIONS:
  -p, --path <dir>         Target directory or file to audit (Default: '.')
  -r, --recursive          Enable recursive directory traversal (Default: enabled)
  -n, --no-recursive       Disable recursive traversal (audit single level)
  -f, --fix                Auto-remediate insecure permissions using child processes (CO2)
  -d, --dry-run            Simulate remediation actions without modifying filesystem
  -o, --output <file>      Export findings report to file (.html, .json, or .txt)
      --format <fmt>       Specify export format: 'text', 'json', or 'html'
  -s, --min-severity <lvl> Filter minimum severity: info, low, medium, high, critical
  -v, --verbose            Display real-time traversal and inode metadata
  -h, --help               Display this help and exit
  -V, --version            Display version information
```

### Example Usage Scenarios
```bash
# Audit current directory with verbose metadata
./bin/analyzer -p . -v

# Audit sandbox and export interactive HTML dashboard
./bin/analyzer -p ./demo_sandbox -o report.html

# Simulate auto-remediation in dry-run mode
./bin/analyzer -p ./demo_sandbox --fix --dry-run

# Remediate vulnerable sandbox files and output JSON
./bin/analyzer -p ./demo_sandbox --fix -o audit_results.json
```

---

## 7. Sample Audit Output

### Terminal ANSI Table Output
```text
================================================================================
   LINUX FILE PERMISSION ANALYZER - SECURITY AUDIT SUMMARY REPORT
================================================================================
 Target Directory : /tmp/demo_sandbox
 Files Inspected  : 8
 Dirs Inspected   : 10
 Symlinks Skipped : 1 (lstat preserved)
 Total Findings   : 6
 Scan Duration    : 0.37 ms
================================================================================

 SEVERITY BREAKDOWN:
   CRITICAL : 3
   HIGH     : 2
   MEDIUM   : 0
   LOW      : 1
   REMEDIATED : 6

 DETAILED FINDINGS TABLE:
SEVERITY   RULE ID  MODE        OWNER:GROUP    INODE  TARGET PATH                      FINDING & STATUS
------------------------------------------------------------------------------------------------------------
[LOW]      SEC-008  -rw-r--r--  stvr:stvr      60     ...andbox/backups/dump_2026.sql  Database backup, SQL dump, or log file is world-readable (information disclosure risk).
           └─ Remediation: SUCCESS: Fixed to 0640 by child (PID 665)
 CRITICAL  SEC-005  -rw-rw-rw-  stvr:stvr      59     ...emo_sandbox/credentials/.env  Sensitive secret or private key is accessible to group/world (current: 0666, required: 0600).
           └─ Remediation: SUCCESS: Fixed to 0600 by child (PID 666)
 CRITICAL  SEC-005  -rw-r--r--  stvr:stvr      58     ...o_sandbox/credentials/id_rsa  Sensitive secret or private key is accessible to group/world (current: 0644, required: 0600).
           └─ Remediation: SUCCESS: Fixed to 0600 by child (PID 667)
[HIGH]     SEC-004  drwxrwxrwx  stvr:stvr      43     ..._sandbox/shared/insecure_tmp  World-writable directory lacks Sticky Bit (01000). Any user can delete or rename other users' files.
           └─ Remediation: SUCCESS: Fixed to 1777 by child (PID 668)
[HIGH]     SEC-003  -rwxr-sr-x  stvr:stvr      57     ...sandbox/bin/fake_sgid_binary  SGID bit (02000) on executable allows process to run with group privileges of stvr (GID 1000).
           └─ Remediation: SUCCESS: Fixed to 0755 by child (PID 669)
 CRITICAL  SEC-001  -rwxrwxrwx  stvr:stvr      49     ...pts/world_writable_script.sh  World-writable executable/root file allows arbitrary code injection by any local user.
           └─ Remediation: SUCCESS: Fixed to 0755 by child (PID 670)
------------------------------------------------------------------------------------------------------------
```

### Generated HTML Dashboard Features
The exported `report.html` dashboard provides:
- Responsive, modern Dark Mode UI built with semantic HTML5 and vanilla CSS.
- Key Performance Indicator (KPI) metric cards (Total Scanned, Criticals, Highs, Mediums, Remediated).
- Color-coded severity badge taxonomy (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Tabular record breakdown with exact octal modes, resolved owners, and child-process status strings.

---

## 8. Academic Evaluation Deliverables

- **Comprehensive Project Report:** Located at [`docs/PROJECT_REPORT.md`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/docs/PROJECT_REPORT.md).
- **15-Slide Presentation Deck with Speaker Notes:** Located at [`docs/PPT_SLIDES.md`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/docs/PPT_SLIDES.md).
- **Team Viva Defense Guide (25+ Q&As):** Located at [`docs/TEAM_VIVA_GUIDE.md`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/docs/TEAM_VIVA_GUIDE.md).

---

## 9. License

This project is licensed under the MIT License for academic and educational evaluation under course 25CS2104E.
