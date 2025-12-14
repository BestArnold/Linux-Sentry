# ============================================================================
# Makefile for linux_sentry - eBPF Security Monitoring Tool
# ============================================================================
# This Makefile compiles:
#   1. Embedded libbpf static library
#   2. BPF kernel program
#   3. User-space monitoring application
# ============================================================================

# Compiler and Flags
CLANG ?= clang
CFLAGS ?= -g -O2 -Wall
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/')

# Directory Structure
BUILD_DIR := build                          # Output directory for build artifacts
BPF_SRC_DIR := src/bpf                    # BPF kernel program source
USER_SRC_DIR := src/user                  # User-space application source
LIBBPF_SRC := src/libbpf/src              # libbpf library source
LIBBPF_DEST := $(BUILD_DIR)/libbpf        # Compiled libbpf destination

# Output Files
BPF_OBJ := $(BUILD_DIR)/linux_sentry.bpf.o   # Compiled eBPF object
USER_BIN := $(BUILD_DIR)/linux_sentry        # Final executable
LIBBPF_OBJ := $(LIBBPF_DEST)/libbpf.a        # Static libbpf library

# Include Paths
INCLUDES := -I$(LIBBPF_DEST) -I$(USER_SRC_DIR)

.PHONY: all clean vmlinux

# ============================================================================
# Build Targets
# ============================================================================

# Default target: Build both user application and BPF object
all: $(USER_BIN) $(BPF_OBJ)

# Generate vmlinux.h header from kernel BTF information
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_SRC_DIR)/vmlinux.h

# ============================================================================
# Step 1: Build embedded libbpf static library
# ============================================================================
$(LIBBPF_OBJ):
	mkdir -p $(LIBBPF_DEST)
	@echo "Compiling embedded libbpf..."
	$(MAKE) -C $(LIBBPF_SRC) OUTPUT=$(abspath $(LIBBPF_DEST))/ DESTDIR=$(abspath $(LIBBPF_DEST)) OBJDIR=$(abspath $(LIBBPF_DEST)) all install_headers

# ============================================================================
# Step 2: Compile eBPF kernel program
# ============================================================================
$(BPF_OBJ): $(BPF_SRC_DIR)/linux_sentry.bpf.c $(LIBBPF_OBJ)
	mkdir -p $(BUILD_DIR)
	@echo "Compiling BPF object..."
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I $(BPF_SRC_DIR) \
		-I $(LIBBPF_DEST) \
		-c $(BPF_SRC_DIR)/linux_sentry.bpf.c -o $(BPF_OBJ)

# ============================================================================
# Step 3: Compile user-space application
# ============================================================================
$(USER_BIN): $(USER_SRC_DIR)/main.c $(LIBBPF_OBJ) $(BPF_OBJ)
	@echo "Compiling User application..."
	$(CC) $(CFLAGS) $(USER_SRC_DIR)/main.c -o $(USER_BIN) \
		$(INCLUDES) \
		$(LIBBPF_OBJ) -lelf -lz

# ============================================================================
# Cleanup
# ============================================================================
clean:
	rm -rf $(BUILD_DIR)