# ==============================================================================
# Linux File Permission Analyzer (LfPA) - Makefile
# Course: 25CS2104E - Operating Systems and Systems Programming (OSSP)
# ==============================================================================

CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude -pthread
LDFLAGS  ?= -pthread

SRC_DIR  := src
INC_DIR  := include
OBJ_DIR  := obj
BIN_DIR  := bin

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET   := $(BIN_DIR)/analyzer

# Default target
.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "\033[1;32m[LD]\033[0m Linking binary $@"
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@echo "\033[1;34m[CC]\033[0m Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	@mkdir -p $@

# Debug build with symbols for GDB/Valgrind
.PHONY: debug
debug: CFLAGS += -g3 -O0 -DDEBUG
debug: clean all

# Build demo sandbox and run live audit
.PHONY: demo
demo: all
	@bash scripts/setup_sandbox.sh
	@echo "\033[1;35m[*] Running Live Security Audit Demonstration...\033[0m"
	$(TARGET) -p ./demo_sandbox -o report.html
	@echo "\033[1;32m[✓] Demo complete. Interactive HTML dashboard generated at report.html\033[0m"

# Execute automated test suite
.PHONY: test
test: all
	@bash scripts/run_tests.sh

# Run auto-remediation on sandbox
.PHONY: fix
fix: all
	@bash scripts/setup_sandbox.sh
	@echo "\033[1;35m[*] Executing Auto-Remediation on Sandbox...\033[0m"
	$(TARGET) -p ./demo_sandbox --fix -o remediated_report.html

# Run memory leak analysis via Valgrind (CO4)
.PHONY: valgrind
valgrind: debug
	@bash scripts/setup_sandbox.sh
	@echo "\033[1;35m[*] Running Dynamic Memory Analysis with Valgrind...\033[0m"
	valgrind --leak-check=full \
	         --show-leak-kinds=all \
	         --track-origins=yes \
	         --verbose \
	         $(TARGET) -p ./demo_sandbox

# Run system call tracing via strace (CO1)
.PHONY: strace
strace: all
	@bash scripts/setup_sandbox.sh
	@echo "\033[1;35m[*] Tracing POSIX System Calls with strace (CO1)...\033[0m"
	strace -c $(TARGET) -p ./demo_sandbox

# Clean build artifacts, object files, binaries, and generated sandbox
.PHONY: clean
clean:
	@echo "\033[1;31m[CLEAN]\033[0m Removing build artifacts and test reports"
	@rm -rf $(OBJ_DIR) $(BIN_DIR) demo_sandbox report.html report.json remediated_report.html report_test.html report_test.json

# Help menu
.PHONY: help
help:
	@echo "Linux File Permission Analyzer (LfPA) - Build System"
	@echo "Available Make Targets:"
	@echo "  make all       - Compile release binary ($(TARGET))"
	@echo "  make debug     - Compile with debug symbols (-g3 -O0)"
	@echo "  make demo      - Setup sandbox and run live scan with HTML report"
	@echo "  make test      - Run automated 8-point test validation suite"
	@echo "  make fix       - Run auto-remediation on vulnerable sandbox"
	@echo "  make valgrind  - Run Valgrind heap memory leak analysis"
	@echo "  make strace    - Run strace system call frequency profile"
	@echo "  make clean     - Clean binaries, objects, and test sandbox"
