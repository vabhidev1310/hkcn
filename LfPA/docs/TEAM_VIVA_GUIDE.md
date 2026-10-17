# Team Viva & Technical Defense Guide: Linux File Permission Analyzer (LfPA)

**Course Code:** 25CS2104E - Operating Systems and Systems Programming (OSSP)  
**Academic Year:** 2025–2026  
**Document Purpose:** Comprehensive preparation guide, module ownership breakdown, and technical Q&A for laboratory viva evaluation.

---

## Team Division & Viva Ownership Matrix

| Member | Primary Role | Codebase Responsibility | Primary Course Outcomes |
|---|---|---|---|
| **Member 1** | Systems Architect & CLI Orchestrator | [`src/main.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/main.c), `Makefile`, Signals | **CO3** (Signals & IPC), Workflow |
| **Member 2** | VFS & Memory Systems Engineer | [`src/scanner.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/scanner.c), `include/analyzer.h` | **CO4** (Dynamic Memory), **CO5** (VFS/Inodes), **CO6** (Pthreads) |
| **Member 3** | Security Heuristics & Bitmask Analyst | [`src/rules_engine.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/rules_engine.c) | **CO5** (Inode Metadata & Bitmasks) |
| **Member 4** | Process Control & Remediation Engineer | [`src/reporter_fixer.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/reporter_fixer.c), Sandboxing | **CO1** (POSIX Syscalls), **CO2** (Process Control & Safety) |

---

## Member 1: CLI, Signal Handling & Workflow Orchestration (CO3)

### Core Modules Owned
- [`src/main.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/main.c): `parse_arguments()`, `setup_signal_handlers()`, `handle_sigint()`, `main()`
- [`Makefile`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/Makefile): Targets (`all`, `demo`, `test`, `fix`, `valgrind`, `strace`, `clean`)

### Key Concept: Asynchronous Signal Interception (`sigaction`)
In POSIX systems, `signal()` has ambiguous semantics across different Unix flavors (BSD vs SysV). We use `sigaction()` to install a reliable handler for `SIGINT` (`Ctrl+C`). Because standard I/O functions like `printf()` or `malloc()` are **not reentrant** and maintain locks that can cause deadlocks if interrupted, the signal handler must only perform async-signal-safe actions.

```c
void handle_sigint(int sig) {
    (void)sig;
    g_stop_requested = 1;
    const char msg[] = "\n[!] SIGINT (Ctrl+C) caught. Gracefully flushing gathered audit records...\n";
    ssize_t ret = write(STDERR_FILENO, msg, sizeof(msg) - 1); // Async-signal-safe!
    (void)ret;
}
```

### Viva Examination Q&A for Member 1

#### Q1.1: Why did you use `sigaction()` instead of `signal()`?
> **Answer:**  
> "`signal()` is deprecated in modern POSIX systems programming because its behavior varies across Unix standards. In System V, the handler resets to `SIG_DFL` after triggering, introducing race conditions. In BSD, interrupted system calls are automatically restarted (`SA_RESTART`). With `sigaction()`, we have deterministic control over the signal mask (`sa_mask`), flags (`sa_flags`), and delivery guarantees."

#### Q1.2: What makes a function "async-signal-safe", and why couldn't you use `printf()` inside `handle_sigint()`?
> **Answer:**  
> "A function is async-signal-safe if it can be called safely from within a signal handler without causing data corruption or deadlocks. `printf()` uses internal static buffers and mutex locks on `stdout`. If a thread is interrupted by `SIGINT` while holding the `stdout` lock, calling `printf()` inside the signal handler will attempt to acquire the same lock, resulting in an immediate and unrecoverable deadlock. Therefore, we use the low-level `write()` system call, which is guaranteed to be reentrant by POSIX."

#### Q1.3: How does your tool preserve audit records when interrupted with Ctrl+C?
> **Answer:**  
> "Instead of terminating abruptly with `exit()`, our signal handler sets a global flag `volatile sig_atomic_t g_stop_requested = 1`. In `scanner.c`, the recursive traversal loop checks this flag before scanning each directory entry. Upon seeing `g_stop_requested == 1`, traversal terminates early and unwinds the call stack back to `main()`. Execution then proceeds to report generation, ensuring that all findings accumulated up to that point are saved to terminal, HTML, and JSON reports with zero data loss."

#### Q1.4: Why is the global flag declared as `volatile sig_atomic_t`?
> **Answer:**  
> "`sig_atomic_t` is an integer type that can be read and written in a single atomic instruction without being interrupted in the middle of a CPU cycle. The `volatile` qualifier informs the compiler that the variable can be modified asynchronously outside the normal program flow, preventing the compiler optimizer from caching it in a CPU register and causing an infinite loop in the scanner."

---

## Member 2: VFS Traversal, Dynamic Memory & Concurrency (CO4, CO5, CO6)

### Core Modules Owned
- [`src/scanner.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/scanner.c): `audit_db_init()`, `audit_db_add()`, `audit_db_free()`, `scan_file_or_dir()`, `scan_directory_recursive()`, `resolve_identity()`
- [`include/analyzer.h`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/include/analyzer.h): Struct definitions (`AuditRecord`, `AuditDB`)

### Key Concept: Virtual File System (VFS) & Dynamic Heap Array
The Virtual File System provides a unified abstraction over underlying storage filesystems. `lstat()` accesses the inode directly without following symlinks. The `AuditDB` structure manages findings on the heap using geometric capacity doubling to achieve amortized $O(1)$ insertions.

```c
int audit_db_add(AuditDB *db, const AuditRecord *rec) {
    pthread_mutex_lock(&db->lock); // CO6: Concurrency Protection
    if (db->count >= db->capacity) {
        size_t new_cap = db->capacity * 2; // CO4: Geometric Doubling
        AuditRecord *expanded = (AuditRecord *)realloc(db->records, new_cap * sizeof(AuditRecord));
        if (!expanded) { pthread_mutex_unlock(&db->lock); return -1; }
        db->records = expanded;
        db->capacity = new_cap;
    }
    memcpy(&db->records[db->count++], rec, sizeof(AuditRecord));
    pthread_mutex_unlock(&db->lock);
    return 0;
}
```

### Viva Examination Q&A for Member 2

#### Q2.1: Why did you choose `lstat()` over `stat()`?
> **Answer:**  
> "`stat()` follows symbolic links to their target inode. If a user creates a symbolic link that points to itself or forms a circular link (`A -> B -> A`), `stat()` causes recursive traversal to get stuck or exhaust file descriptors. Furthermore, `stat()` masks the permissions of the symlink itself. `lstat()` returns metadata about the symlink inode directly. When we detect `S_ISLNK(st.st_mode)`, we increment `symlinks_skipped` and avoid following it, preventing symlink race conditions."

#### Q2.2: How does your dynamic array handle memory expansion without memory leaks?
> **Answer:**  
> "We allocate an initial buffer of 32 `AuditRecord` structures via `malloc()`. When the array fills, we compute `new_cap = capacity * 2` and call `realloc()`. We assign the result to a temporary pointer `expanded` before assigning it to `db->records`. This is critical: if `realloc()` fails, it returns `NULL` without freeing the original buffer; assigning directly to `db->records` would leak the existing data. Once scanning completes, `audit_db_free()` frees `db->records` and destroys the mutex, achieving zero leaks under Valgrind."

#### Q2.3: How does the system resolve numerical UIDs and GIDs into names?
> **Answer:**  
> "Linux inodes store owner and group information as raw numerical integers (`st_uid` and `st_gid`). We query the system database using `getpwuid()` (which reads `/etc/passwd`) and `getgrgid()` (which reads `/etc/group`). If either function returns `NULL`, it indicates that the file is owned by a deleted or unmapped account. We mark the identity as `UNKNOWN(uid)`, which our rules engine identifies as an orphaned inode."

#### Q2.4: Where is `pthread_mutex_t` used and why is it necessary?
> **Answer:**  
> "The mutex `db->lock` protects the critical section inside `audit_db_add()` and the global telemetry counters. In multi-threaded scan modes or when concurrent worker threads insert findings into `AuditDB`, multiple threads modifying `db->count` or reallocating `db->records` simultaneously would trigger data races and heap corruption. Mutex synchronization guarantees serialized access."

---

## Member 3: Bitmask Mathematics & Security Heuristics (CO5)

### Core Modules Owned
- [`src/rules_engine.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/rules_engine.c): `evaluate_inode_security()`, `is_sensitive_credential_file()`, `format_mode_to_string()`

### Key Concept: Bitmask Bitwise Logic & Special Inode Flags
Linux stores permissions in the lower 12 bits of `st_mode`: 3 special bits (SUID, SGID, Sticky) followed by 9 standard rwx bits.

```c
#define IS_WORLD_WRITABLE(m)  (((m) & S_IWOTH) != 0) // Bitmask 00002
#define IS_SUID(m)            (((m) & S_ISUID) != 0) // Bitmask 04000
#define IS_SGID(m)            (((m) & S_ISGID) != 0) // Bitmask 02000
#define IS_STICKY(m)          (((m) & S_ISVTX) != 0) // Bitmask 01000
```

### Viva Examination Q&A for Member 3

#### Q3.1: Explain the difference between SUID, SGID, and the Sticky Bit.
> **Answer:**  
> - **SUID (Set User ID, `04000`):** When set on an executable, the process runs with the privileges of the file owner rather than the executing user (e.g., `/usr/bin/passwd` runs as root).
> - **SGID (Set Group ID, `02000`):** On an executable, the process runs with the privileges of the file's group. On a directory, newly created files inherit the directory's group rather than the creator's primary group.
> - **Sticky Bit (Restricted Deletion, `01000`):** On a directory (like `/tmp`), users can create files, but only the file owner, directory owner, or root can delete or rename those files."

#### Q3.2: Why is a world-writable directory missing the Sticky Bit a severe security vulnerability?
> **Answer:**  
> "In Unix, permission to delete or rename a file is controlled by the write permission on the *parent directory*, not the permissions of the file itself! If a shared directory has mode `0777` without the Sticky Bit (`S_ISVTX`), any unprivileged user can delete another user's files or replace them with malicious symlinks. By setting the Sticky Bit (`01777`), the kernel enforces the restricted deletion flag."

#### Q3.3: How do you mathematically calculate the recommended permission mode for a world-writable file?
> **Answer:**  
> "To strip world-write (`S_IWOTH`) and group-write (`S_IWGRP`) while preserving all other bits, we use bitwise AND with the bitwise NOT of those flags:
> $$\text{recommended} = \text{perms} \ \& \ \sim(\text{S\_IWGRP} \lor \text{S\_IWOTH})$$
> For example, if a file has mode `0777`, `~(0020 | 0002) = ~0022 = 07755`. Then `0777 & 07755 = 0755`."

#### Q3.4: What is an Orphaned Inode and why is it dangerous?
> **Answer:**  
> "An orphaned inode is a file whose `st_uid` does not exist in `/etc/passwd`—usually because a user account was deleted without purging their files. If an administrator later creates a new user, and the operating system assigns the recycled UID, that new user automatically inherits full ownership and control over those orphaned files."

---

## Member 4: POSIX Syscall Reporting, Process Auto-Fix & Safety (CO1, CO2)

### Core Modules Owned
- [`src/reporter_fixer.c`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/src/reporter_fixer.c): `remediate_single_record()`, `is_safe_path()`, `export_html_report()`, `export_json_report()`
- [`scripts/setup_sandbox.sh`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/scripts/setup_sandbox.sh), [`scripts/run_tests.sh`](file:///c:/Users/Acer/OneDrive/Desktop/LfPA/scripts/run_tests.sh)

### Key Concept: Child Process Isolation & Rule #7 Safety Guardrail
Auto-remediation utilizes `fork()` to execute `chmod()` within an isolated child process, while `is_safe_path()` uses `realpath()` to prevent modification of system directories.

```c
int remediate_single_record(AuditRecord *record, bool dry_run) {
    if (!is_safe_path(record->path)) return -1; // Rule #7 Guardrail
    if (dry_run) return 0;

    fflush(stdout); // Prevent stdio buffer duplication
    pid_t pid = fork(); // CO2: Child Isolation
    if (pid == 0) {
        mode_t target_mode = record->recommended_mode & 07777;
        if (chmod(record->path, target_mode) != 0) _exit(EXIT_FAILURE);
        _exit(EXIT_SUCCESS);
    }
    int status;
    waitpid(pid, &status, 0); // Parent Synchronization
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) record->is_fixed = true;
    return 0;
}
```

### Viva Examination Q&A for Member 4

#### Q4.1: Why execute `chmod()` in a child process via `fork()` rather than directly in the parent?
> **Answer:**  
> "Process isolation is a core systems programming principle. If we execute `chmod()` on a remote NFS share or virtual filesystem that is hanging, calling it directly in the parent blocks the entire audit application. By offloading `chmod()` to a child process spawned via `fork()`, the parent can use `waitpid()` with timeouts or signal monitoring. If the child hangs or crashes, the parent catches the exit status and logs the error without aborting the audit."

#### Q4.2: Why must you call `fflush(stdout)` before calling `fork()`?
> **Answer:**  
> "`fork()` creates an exact duplicate of the parent process's address space, including the C standard library's user-space stdio buffers. If `stdout` contains unflushed output, that buffer is copied into the child process. When the child terminates, its exit handlers flush the duplicated buffer, resulting in duplicate lines appearing on the console. Calling `fflush(stdout)` before `fork()` empties the buffer so the child inherits a clean buffer."

#### Q4.3: Why does the child process use `_exit()` instead of `exit()`?
> **Answer:**  
> "`exit()` performs clean-up actions registered via `atexit()`, flushes all open stdio streams, and unlinks temporary files created by `tmpfile()`. In a child process created via `fork()`, executing these clean-up handlers can interfere with the parent's state or flush parent streams twice. `_exit()` is a direct POSIX system call that terminates the process immediately at the kernel level without triggering user-space clean-up routines."

#### Q4.4: How does your tool comply with Rule #7 (Controlled Environment Safety Guardrail)?
> **Answer:**  
> "Rule #7 strictly prohibits disrupting host system files or other users. We implement two tiers of defense:
> 1. In `main.c`, if a user attempts `--fix` on root or system paths (`/etc`, `/bin`, `/usr`, `/lib`, `/sys`, `/proc`, `/dev`, `/boot`, `/root`), the program immediately terminates with an error code before scanning.
> 2. In `remediate_single_record()`, `is_safe_path()` resolves the canonical path using `realpath()` to defeat directory traversal tricks (`../etc`). Any target inside a system root is blocked and flagged as `[GUARDRAIL BLOCKED]`."

---

## Cross-Cutting Systems Programming Viva Questions

#### Q5.1: What is the difference between User Space and Kernel Space in Linux?
> **Answer:**  
> "Modern CPUs enforce hardware protection rings (Ring 0 for Kernel, Ring 3 for User). User-space applications run in Ring 3 with restricted instruction sets and virtualized memory. System calls (`open`, `read`, `fork`, `chmod`) transition execution from User Space to Kernel Space via software interrupts or `syscall` instructions. The kernel verifies permissions, executes the requested privileged operation, and returns the result to user space."

#### Q5.2: What is the difference between a File Descriptor and a `FILE*` pointer?
> **Answer:**  
> "A File Descriptor is an integer index into the process's kernel-managed File Descriptor Table pointing to an open file description (`struct file`). It is used by low-level POSIX system calls (`open`, `read`, `write`, `close`). A `FILE*` is a C standard library user-space structure that wraps a file descriptor and adds user-space buffering, formatting (`fprintf`), and stream management."

#### Q5.3: What is Copy-on-Write (COW) during `fork()`?
> **Answer:**  
> "In early Unix, `fork()` physically copied all parent memory pages into the child, which was slow. Modern Linux uses Copy-on-Write: the kernel duplicates the parent's page tables and marks all pages as read-only. As long as both processes only read memory, they share the exact same physical pages. Only when either process writes to a page does the CPU trigger a page fault, prompting the kernel to allocate a new physical frame and copy that specific page."

#### Q5.4: What is the difference between an Inode and a Directory Entry (`dentry`)?
> **Answer:**  
> "An Inode (`struct inode`) stores all file metadata (permissions, owner, timestamps, file size, data block pointers) but does **not** store the file name. A Directory Entry (`dentry`) is a mapping between a human-readable file name and an inode number (`d_name` $\rightarrow$ `d_ino`). In Linux, directories are simply files whose data blocks contain lists of directory entries."
