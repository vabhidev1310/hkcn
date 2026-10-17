# Presentation Slide Deck: Linux File Permission Analyzer (LfPA)

**Course Code:** 25CS2104E - Operating Systems and Systems Programming (OSSP)  
**Topic:** Recursive Inode Security Analysis, Bitmask Mathematics, and Process-Isolated Auto-Remediation  
**Format:** 15-Slide Academic Viva & Project Presentation Deck with Speaker Notes  

---

## Slide 1: Title & Team Credentials

### Visual Layout
- Centered university title header with course code: `25CS2104E - OSSP`.
- Project Title: **Linux File Permission Analyzer (LfPA)**.
- Subtitle: *A POSIX-Compliant Inode Security Audit & Multi-Process Remediation Engine*.
- 4-Column Team Member Card layout with assigned syllabus modules.

### Content Bullets
- **Course:** 25CS2104E - Operating Systems and Systems Programming (OSSP)
- **Project Title:** Linux File Permission Analyzer (LfPA)
- **Toolchain:** Standard Unix Toolchain (`gcc`, `make`, `valgrind`, `strace`, `gdb`)
- **Team Composition & Viva Ownership:**
  - **Member 1:** CLI Parser, Workflow Orchestration & Asynchronous Signals (`sigaction`) [CO3]
  - **Member 2:** VFS Traversal (`lstat`/`readdir`), Dynamic Memory (`malloc`/`realloc`), Concurrency (`pthread_mutex_t`) [CO4, CO5, CO6]
  - **Member 3:** Permission Bitmask Mathematics, SUID/SGID/Sticky Inode Rules Engine [CO5]
  - **Member 4:** Low-Level POSIX Syscall I/O (`open`/`write`), Fork/Waitpid Remediation & Rule #7 Guardrail [CO1, CO2]

> **Speaker Notes (Member 1):**  
> "Good morning, respected evaluators. Today, our team presents the Linux File Permission Analyzer—a systems-level security auditing utility written in POSIX C11. Over the next fifteen slides, we will demonstrate how low-level systems programming concepts—from VFS inode traversal and bitmask mathematics to child process isolation and asynchronous signal handling—directly address modern Linux security vulnerabilities while rigorously demonstrating Course Outcomes CO1 through CO6."

---

## Slide 2: Problem Statement & Security Threat Landscape

### Visual Layout
- Split screen: On the left, a diagram of Linux Discretionary Access Control (DAC); on the right, the top local privilege escalation (LPE) vulnerability vectors.

```text
       [Unprivileged User]
               │
               ▼
┌───────────────────────────────┐
│ World-Writable Root Executable │ ──► Arbitrary Code Execution
└───────────────────────────────┘
┌───────────────────────────────┐
│ Unmonitored SUID Root Binary  │ ──► Root Shell Spawning (euid = 0)
└───────────────────────────────┘
┌───────────────────────────────┐
│ Missing Sticky Bit on /tmp    │ ──► Unlink/Rename Race Condition
└───────────────────────────────┘
┌───────────────────────────────┐
│ Exposed Cryptographic Keys    │ ──► Horizontal Credential Theft
└───────────────────────────────┘
```

### Content Bullets
- **The DAC Challenge:** Linux relies on 12-bit permission masks. A single misconfigured bit allows unprivileged accounts to compromise the entire system.
- **Critical Vulnerability Vectors:**
  1. *World-Writable Scripts:* Any local user can inject malicious shell commands.
  2. *SUID Root Binaries:* Programs executing with elevated `euid=0` are targets for privilege escalation.
  3. *Unprotected Shared Dirs:* Without the Sticky Bit, users can delete each other's files.
  4. *Sensitive Credentials:* SSH private keys and `.env` files with world-readable bits.
- **The Solution:** A deterministic, fast, zero-dependency C analyzer that audits and safely remediates these risks without disrupting system stability.

> **Speaker Notes (Member 1):**  
> "In Unix environments, Discretionary Access Control hinges on permission bits. While system administrators focus on network perimeters, local misconfigurations—such as world-writable cron scripts, lingering SUID binaries, or shared directories lacking the sticky bit—provide trivial paths for attackers to escalate privileges. Our project provides an automated, mathematically rigorous auditing tool to find and safely remediate these vulnerabilities."

---

## Slide 3: Syllabus Alignment Matrix (Course Outcomes CO1–CO6)

### Visual Layout
- Structured 6-row matrix connecting each Course Outcome to specific C code components.

### Content Table
| Course Outcome | OS Topic | LfPA Implementation |
|---|---|---|
| **CO1** | System Calls & OS Protection | POSIX `lstat`, `open`, `write`, `close`, `chmod`, `errno`/`perror` |
| **CO2** | Process Control | Child process isolation via `fork()`, `waitpid()`, and `chmod()` |
| **CO3** | Signals & IPC | Safe `sigaction()` handler catching `SIGINT` (`Ctrl+C`) |
| **CO4** | Dynamic Memory | Heap-allocated `AuditDB` using `malloc()`, `realloc()`, and `free()` |
| **CO5** | VFS & Inode Abstractions | `opendir()`, `readdir()`, `closedir()`, `lstat()`, `getpwuid()`, `getgrgid()` |
| **CO6** | Concurrency & Sync | Thread-safe data insertion using `pthread_mutex_t` |

> **Speaker Notes (Member 1):**  
> "Our codebase is not just a security scanner; it is structured specifically to satisfy the 25CS2104E curriculum. Every module directly maps to a distinct course outcome: low-level syscalls in CO1, process control in CO2, asynchronous signal safety in CO3, dynamic memory in CO4, Virtual File System traversal in CO5, and thread synchronization in CO6."

---

## Slide 4: Modular Architecture & Team Ownership

### Visual Layout
- Architecture diagram showing the 4 modules and the 4 member viva responsibilities.

```text
 ┌────────────────────────────────────────────────────────┐
 │                      main.c                            │
 │  CLI Parser, Signal Interception, Timing (Member 1)   │
 └──────────────────────────┬─────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
 ┌───────────────────────┐       ┌───────────────────────┐
 │       scanner.c       │       │    rules_engine.c     │
 │ VFS Traversal, Inodes │       │ Bitmask Mathematics,  │
 │ Dynamic Memory, Mutex │       │ Security Heuristics   │
 │      (Member 2)       │       │      (Member 3)       │
 └──────────┬────────────┘       └───────────┬───────────┘
            │                                │
            └───────────────┬────────────────┘
                            ▼
 ┌────────────────────────────────────────────────────────┐
 │                  reporter_fixer.c                      │
 │ Low-level POSIX I/O, Fork/Waitpid Auto-Fix (Member 4) │
 └────────────────────────────────────────────────────────┘
```

### Content Bullets
- **Decoupled Architecture:** High cohesion, low coupling across 4 separate `.c` files.
- **Shared Data Contracts:** Defined in `include/analyzer.h` with clear types (`AuditRecord`, `AuditDB`).
- **Individual Viva Accountability:** Each team member has complete ownership of their respective component during evaluation.

> **Speaker Notes (Member 1):**  
> "To facilitate fair and transparent viva evaluation, we divided our repository into four modular layers. I own `main.c`, orchestrating the CLI and signal handling. Member 2 owns `scanner.c`, managing VFS traversal and heap memory. Member 3 owns `rules_engine.c`, handling permission bitmask math. Member 4 owns `reporter_fixer.c`, handling low-level file exports and process-isolated remediation."

---

## Slide 5: Virtual File System & Inode Metadata (CO5)

### Visual Layout
- Diagram contrasting `stat()` (which dereferences links) with `lstat()` (which reads link inodes directly).

```text
           [Path Input: /path/to/symlink]
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
   stat() Syscall                  lstat() Syscall
Follows symlink pointer           Reads link inode directly
Prone to circular loops           Safe against circular loops
Cannot audit link itself          Preserves symlink integrity
```

### Content Bullets
- **VFS Traversal Mechanics:**
  - `opendir()` and `readdir()` stream directory entries (`struct dirent`).
  - Automatic filtering of `.` (current) and `..` (parent) to avoid recursion traps.
- **The `lstat()` Guarantee:**
  - Does NOT follow symbolic links (`S_ISLNK(st.st_mode)`).
  - Skips external symlinks to neutralize symlink race conditions and denial-of-service loops.
- **Identity Resolution:**
  - Inodes only store numerical `st_uid` and `st_gid`.
  - Resolved via `getpwuid()` and `getgrgid()`.
  - Missing entries are flagged as **Orphaned Inodes** (Rule SEC-006).

> **Speaker Notes (Member 2):**  
> "As the author of `scanner.c`, I focused on Virtual File System traversal. We use `lstat()` rather than `stat()` because `stat()` follows symlinks. If an attacker creates a circular symlink structure, `stat()` will enter an infinite recursion loop and crash the program. `lstat()` inspects the link inode itself. Furthermore, we extract raw UID and GID and resolve them against the system password and group databases. If a UID cannot be resolved, we flag it as an orphaned inode."

---

## Slide 6: Permission Bitmask Mathematics (CO5)

### Visual Layout
- Bitfield breakdown of the 16-bit POSIX `mode_t` structure and octal bitwise masking operations.

```text
 Mode: 0 4 7 5 5 (Octal)
 Binary: [0000] [100] [111] [101] [101]
                 ▲     ▲     ▲     ▲
                 │     │     │     └─ Others: r-x (5)
                 │     │     └─────── Group:  r-x (5)
                 │     └───────────── User:   rwx (7)
                 └─────────────────── SUID Bit Active!
```

### Content Bullets
- **Bitwise Evaluation Equations:**
  - World-Writable Test: `(mode & S_IWOTH) != 0` (Octal `0002`)
  - SUID Bit Test: `(mode & S_ISUID) != 0` (Octal `04000`)
  - SGID Bit Test: `(mode & S_ISGID) != 0` (Octal `02000`)
  - Sticky Bit Test: `(mode & S_ISVTX) != 0` (Octal `01000`)
- **Mathematical Sanitization (Remediation):**
  - Stripping SUID: `sanitized = mode & ~S_ISUID`
  - Adding Sticky Bit: `sanitized = mode | S_ISVTX`
  - Restricting Secrets: `sanitized = (S_IRUSR | S_IWUSR)` (`0600`)

> **Speaker Notes (Member 3):**  
> "I developed `rules_engine.c`. In Linux, file modes are not strings—they are 16-bit integers. We use bitwise operators (`&`, `|`, `~`) to inspect and manipulate permissions. For example, to detect world-writable files, we perform a bitwise AND with `S_IWOTH` (`0002` octal). To fix an SUID binary, we compute `mode & ~S_ISUID`, which strips the 12th bit while leaving all other user, group, and other permissions completely intact."

---

## Slide 7: Security Rules Engine & Heuristics

### Visual Layout
- A taxonomy card displaying all 8 security rules implemented in LfPA.

### Content Table
| Rule ID | Severity | Violation Condition | Threat Vector | Recommended Fix |
|---|---|---|---|---|
| **SEC-001** | CRITICAL | World-writable executable/root script | Arbitrary code injection | `mode & ~(S_IWGRP \| S_IWOTH)` |
| **SEC-002** | CRITICAL | SUID bit on root executable | Root privilege escalation | `mode & ~S_ISUID` |
| **SEC-003** | HIGH | SGID bit on executable binary | Group privilege escalation | `mode & ~S_ISGID` |
| **SEC-004** | HIGH | World-writable dir missing Sticky Bit | Unauthorized file deletion | `mode \| S_ISVTX` (`01777`) |
| **SEC-005** | HIGH/CRIT | Loose permissions on `.env` / `id_rsa` | Cryptographic secret theft | `0600` (`-rw-------`) |
| **SEC-006** | MEDIUM | Orphaned inode (unmapped UID/GID) | Account recycling takeover | Restrict to `0700` / audit |
| **SEC-007** | MEDIUM | General world-writable regular file | Data tampering / truncation | `mode & ~S_IWOTH` |
| **SEC-008** | LOW | World-readable backup/SQL dump | Information disclosure | `mode & ~S_IROTH` |

> **Speaker Notes (Member 3):**  
> "Our rules engine covers eight distinct vulnerability patterns. Notice SEC-004: if a shared world-writable directory lacks the Sticky Bit (`01000`), any local user can delete files created by other users! Our engine classifies this as HIGH risk and calculates the exact octal addition (`| S_ISVTX`) needed to secure it."

---

## Slide 8: Process Control & Isolated Child Remediation (CO2)

### Visual Layout
- Sequence diagram illustrating parent-child process lifecycle during auto-remediation.

```text
 Parent Process                     Child Process
 (Scanner/Fixer)                    (Isolated Worker)
       │                                   │
       ├─── 1. fork() ────────────────────►│
       │                                   ├── 2. chmod(path, safe_mode)
       │                                   ├── 3. _exit(0)
       ├─── 4. waitpid(pid, &status) ◄─────┘
       │
       └─── 5. Update Record State (SUCCESS)
```

### Content Bullets
- **Why Child Isolation Matters (CO2):**
  - Executing `chmod()` directly in the parent process risks crashes or hangs on remote/stalled filesystems.
  - Process isolation ensures that child failures do not compromise the parent's memory space.
- **The Stdio Buffer Hazard:**
  - Before `fork()`, we call `fflush(stdout)` and `fflush(stderr)`.
  - Child processes terminate with `_exit()` rather than `exit()` to avoid duplicating parent buffered output.
- **Parent Synchronization:**
  - Parent invokes `waitpid(pid, &status, 0)` and parses `WIFEXITED(status)` and `WEXITSTATUS(status)`.

> **Speaker Notes (Member 4):**  
> "As author of `reporter_fixer.c`, I implemented the auto-remediation engine. Rather than mutating filesystem permissions in the main scanning process, we call `fork()` to spawn an isolated child worker. The child applies the `chmod()` system call and terminates via `_exit()`. The parent waits using `waitpid()`. This ensures that even if a filesystem hangs or fails, the parent scanning engine remains completely stable."

---

## Slide 9: Asynchronous Signal Interception (CO3)

### Visual Layout
- State diagram of signal delivery and safe report flushing.

```text
 Scanning Deep Hierarchy... [Inode #14029]
              │
    [User presses Ctrl+C]
              │
              ▼
    Kernel sends SIGINT
              │
              ▼
 ┌────────────────────────────────────────────────┐
 │           sigaction Handler                    │
 │ 1. g_stop_requested = 1;                       │
 │ 2. write(STDERR_FILENO, msg, len); (Safe I/O)  │
 └──────────────────────┬─────────────────────────┘
                        │
                        ▼
 Traversal loop checks g_stop_requested and exits
                        │
                        ▼
 Partial Findings Flushed to Report (Zero Data Loss!)
```

### Content Bullets
- **The Signal Handling Challenge:**
  - Standard functions like `printf()` and `malloc()` are **not async-signal-safe** and can deadlock if interrupted.
- **POSIX `sigaction` Configuration:**
  - Global volatile flag: `volatile sig_atomic_t g_stop_requested = 0;`
  - Intercepts `SIGINT` cleanly using POSIX `sigaction()`.
  - Diagnostic notification uses low-level `write()` syscall.
- **Graceful Scan Abort:**
  - Traversal loops check the flag and cleanly break out of recursion.
  - All findings accumulated up to the moment of interruption are safely reported.

> **Speaker Notes (Member 1):**  
> "When scanning massive directory trees, users may need to interrupt the process using Ctrl+C. Traditional programs terminate immediately, losing all audit findings. We configured a POSIX `sigaction` handler that catches `SIGINT`, writes a signal-safe message to stderr using `write()`, and sets a volatile flag. The scanner gracefully exits its recursion loop and immediately flushes the gathered records into the report."

---

## Slide 10: Dynamic Memory Management (CO4) & Concurrency (CO6)

### Visual Layout
- Diagram of dynamic array memory layout showing capacity doubling and mutex synchronization.

```text
 Initial Capacity: [Rec 0] [Rec 1] ... [Rec 31]  (32 records)
                          │ (Capacity Reached)
                          ▼ realloc(new_cap = 64)
 Expanded Array:   [Rec 0] [Rec 1] ... [Rec 63]  (64 records)

 ──► All insertions locked via pthread_mutex_lock(&db->lock) ◄──
```

### Content Bullets
- **Dynamic Array Mechanics (CO4):**
  - Initial heap allocation via `malloc(32 * sizeof(AuditRecord))`.
  - Geometric expansion strategy: capacity doubles ($N \rightarrow 2N$) on saturation for amortized $O(1)$ insertions.
  - Complete deallocation via `audit_db_free()`.
- **Thread Synchronization (CO6):**
  - Insertion and telemetry counter updates protected by `pthread_mutex_t`.
  - Guarantees thread safety under concurrent scanning workers.
- **Zero-Leak Validation:**
  - Verified under `valgrind --leak-check=full`. Zero bytes leaked.

> **Speaker Notes (Member 2):**  
> "In `scanner.c`, findings are stored on the heap. We avoid fixed-size buffers by using an amortized O(1) geometric doubling strategy with `realloc()`. To ensure thread safety (CO6), all insertions into the database are wrapped in `pthread_mutex_lock()` and `unlock()`. Finally, `audit_db_free()` frees all allocated heap memory, verified via Valgrind with zero leaks."

---

## Slide 11: Rule #7 Safety Guardrails Architecture

### Visual Layout
- Visual flow of the two-tier safety guardrail preventing modifications to critical system paths.

```text
 Remediation Request (--fix)
              │
              ▼
 [Tier 1: CLI Target Validation]
 Is target in /etc, /bin, /usr, /lib, /sys?
         ├── YES ──► [TERMINATE WITH ERROR (Refuse)]
         └── NO
              │
              ▼
 [Tier 2: Per-Inode Realpath Check]
 Is resolved canonical path in protected system list?
         ├── YES ──► [BLOCK RECORD WITH GUARDRAIL STATUS]
         └── NO  ──► [PERMIT CHILD PROCESS REMEDIATION]
```

### Content Bullets
- **Course Rubric Rule #7 Requirement:**
  - Execution must occur strictly in a controlled environment without disrupting system processes or other users.
- **Two-Tier Defense:**
  - *Tier 1:* Immediate refusal if `--fix` is passed against `/etc`, `/bin`, `/sbin`, `/usr`, `/lib`, `/sys`, `/proc`, `/dev`, `/boot`, or `/root`.
  - *Tier 2:* Canonical path evaluation using `realpath()` to defeat symlink path traversal bypasses.
- **Sandbox Environment:**
  - `scripts/setup_sandbox.sh` builds an isolated `./demo_sandbox` containing all test fixtures safely.

> **Speaker Notes (Member 4):**  
> "A core requirement of our university course is Rule #7: safety in a controlled environment. We implemented a two-tier guardrail. First, if a user attempts to run `--fix` on system roots like `/etc` or `/bin`, the CLI rejects the command immediately. Second, during traversal, we resolve canonical paths with `realpath()` to ensure no file inside a system directory is ever modified."

---

## Slide 12: Low-Level POSIX Syscall Reporting (CO1)

### Visual Layout
- Architecture of report emission using POSIX syscalls versus standard C library buffering.

```text
 Memory Database (AuditDB)
              │
     [POSIX Low-Level I/O]
              │
              ├── open(file, O_WRONLY | O_CREAT | O_TRUNC, 0644)
              ├── write_all_fd() loop (EINTR safe)
              └── close(fd)
              │
   ┌──────────┴──────────┐
   ▼                     ▼
JSON Report          HTML5 Dashboard
(Machine-Readable)   (Modern Responsive Web UI)
```

### Content Bullets
- **Direct Kernel I/O (CO1):**
  - Uses `open()`, `write()`, and `close()` directly, demonstrating low-level systems programming.
  - Implements atomic `write_all_fd()` loops handling `EINTR` signal interrupts.
- **Export Artifacts:**
  - *ANSI Terminal Table:* Color-coded severity badges and summary statistics.
  - *HTML5 Dashboard:* Responsive dark-mode UI with KPI cards and status tracking.
  - *JSON Output:* Structured machine-readable schema for SIEM integration.

> **Speaker Notes (Member 4):**  
> "For reporting, rather than relying on high-level `fprintf()`, we utilize low-level POSIX system calls: `open()`, `write()`, and `close()`. Our `write_all_fd()` helper handles partial writes and signal interruptions (`EINTR`). We export to ANSI terminal tables, machine-readable JSON, and interactive HTML dashboards."

---

## Slide 13: Live Demonstration & Sandbox Fixtures

### Visual Layout
- Screenshots and fixture layout of `./demo_sandbox`.

```text
 demo_sandbox/
 ├── scripts/world_writable_script.sh  (0777)  ──► SEC-001 (CRITICAL)
 ├── bin/fake_suid_binary              (04755) ──► SEC-002 (CRITICAL/HIGH)
 ├── bin/fake_sgid_binary              (02755) ──► SEC-003 (HIGH)
 ├── shared/insecure_tmp/              (0777)  ──► SEC-004 (HIGH)
 ├── credentials/id_rsa                (0644)  ──► SEC-005 (CRITICAL)
 ├── credentials/.env                  (0666)  ──► SEC-005 (CRITICAL)
 ├── backups/dump_2026.sql             (0644)  ──► SEC-008 (LOW)
 ├── links/symlink_to_env              (symlink)─► Preserved via lstat
 └── safe/readme.txt                   (0644)  ──► Clean Baseline (0 alerts)
```

### Content Bullets
- **Quickstart Demo Target:**
  ```bash
  make demo
  ```
  - Automatically compiles the binary.
  - Sets up the vulnerable `./demo_sandbox`.
  - Executes audit and generates `report.html`.
- **Auto-Remediation Target:**
  ```bash
  make fix
  ```
  - Safely hardens all findings to safe permission modes.

> **Speaker Notes (Member 1):**  
> "Evaluators can verify our entire project with a single command: `make demo`. This sets up our vulnerable sandbox, compiles the C binary, audits all files, and outputs an interactive HTML report. Running `make fix` immediately demonstrates child-process remediation in real time."

---

## Slide 14: Automated Validation & Empirical Test Results

### Visual Layout
- Terminal summary box of the test suite showing 14 passed assertions.

```text
======================================================================
   LINUX FILE PERMISSION ANALYZER - AUTOMATED TEST SUITE (CO1-CO6)   
======================================================================
  TOTAL TESTS RUN : 14
  PASSED          : 14 (100%)
  FAILED          : 0 (0%)
======================================================================
[✓] ALL TEST SUITE ASSERTIONS PASSED WITH 100% SUCCESS!
```

### Content Bullets
- **Test Scenarios Verified:**
  - Compilation under `-Wall -Wextra -Wpedantic` with **zero warnings**.
  - SUID and SGID bitmask detection.
  - Sticky bit absence on world-writable directories.
  - Sensitive credential exposure detection.
  - Rule #7 Safety Guardrail refusal against `/etc`.
  - Dry-run simulation mode.
  - Live child-process auto-remediation.
  - HTML and JSON report integrity.
- **Valgrind Analysis:** Zero leaks, zero memory errors.

> **Speaker Notes (Member 2):**  
> "Our automated test script runs fourteen distinct assertions verifying compilation, bitmask heuristics, safety guardrails, dry-run simulation, and live child-process remediation. All fourteen assertions pass with 100% success, and Valgrind confirms zero memory leaks."

---

## Slide 15: Conclusion & Technical Takeaways

### Visual Layout
- Summary card highlighting project strengths, syllabus takeaways, and future vision.

### Content Bullets
- **Project Achievements:**
  - 100% compliant with 25CS2104E syllabus (CO1 through CO6).
  - Robust systems programming in pure C11 without third-party dependencies.
  - Defense-in-depth safety guardrails strictly complying with Rule #7.
  - Multi-process auto-remediation engine with process isolation.
- **Technical Takeaways:**
  - Mastery of POSIX system call interface (`lstat`, `open`, `write`, `chmod`).
  - Deep appreciation of Virtual File System inode internals and bitmask mathematics.
  - Hands-on implementation of process control (`fork`/`waitpid`) and asynchronous signal handling (`sigaction`).

> **Speaker Notes (Member 1):**  
> "In conclusion, the Linux File Permission Analyzer demonstrates that low-level systems programming provides the foundational backbone for operating system security. Through this project, our team gained practical experience with POSIX system calls, process lifecycles, signal safety, and heap memory management. We thank the faculty and are now ready for your questions."
