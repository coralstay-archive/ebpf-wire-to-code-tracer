# SPDX-License-Identifier: GPL-2.0
# ==============================================================================
# Makefile — Kernel-Style BPF & Skeleton Build Harness
# Modeled after tools/testing/selftests/bpf/Makefile
# Target Architecture: aarch64 (Rocky Linux 9.8 5.14.0-687.10.1.el9_8.0.1.aarch64)
# ==============================================================================

CC ?= clang
CXX ?= clang++
BPFTOOL ?= /usr/sbin/bpftool

# Use LLVM Clang with BPF backend support if available (e.g. Homebrew LLVM on macOS or distro clang on Linux)
CLANG_BPF := $(shell if [ -x "/opt/homebrew/opt/llvm/bin/clang" ]; then echo "/opt/homebrew/opt/llvm/bin/clang"; else which clang; fi)

ARCH ?= arm64
TARGET_ARCH ?= -D__TARGET_ARCH_$(ARCH)

ROOT_DIR := $(shell pwd)
REF_BTF_DIR := $(ROOT_DIR)/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers

BPF_CFLAGS := -target bpf $(TARGET_ARCH) -DKRAY_BPF_CORE -O2 -g \
              -I$(ROOT_DIR) -I$(REF_BTF_DIR) -Wall -Werror

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    DYLIB_EXT := dylib
    SHLIB_FLAGS := -dynamiclib
else
    DYLIB_EXT := so
    SHLIB_FLAGS := -shared
endif

.PHONY: all clean bpf skeleton test vmtest vmtest-load help

all: bpf mock-binaries sim-lib

bpf: tracer_kernel_bpf.o

tracer_kernel_bpf.o: tracer_kernel.c kray_bpf_core_compat.h
	$(CLANG_BPF) $(BPF_CFLAGS) -c $< -o $@
	@echo "Compiled BPF Object: $@"

skeleton: tracer_kernel_bpf.o
	@if [ -x "$(BPFTOOL)" ]; then \
		$(BPFTOOL) gen skeleton $< > tracer_kernel.skel.h && \
		echo "Generated BPF Skeleton: tracer_kernel.skel.h"; \
	else \
		echo "Notice: bpftool not installed locally on macOS host. Run 'make vmtest-skeleton' to generate on target Rocky 9.8 VM."; \
	fi

mock-binaries: libcrypto_mock.so mock_server

libcrypto_mock.so: libcrypto_mock.cpp
	$(CXX) -std=c++17 -g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -shared $< -o $@
	strip -x $@

mock_server: mock_server.cpp
	$(CXX) -std=c++17 -g -O0 -fno-inline -fno-omit-frame-pointer -pthread $< -ldl -o $@

sim-lib: libtracer_kernel_sim.$(DYLIB_EXT)

libtracer_kernel_sim.$(DYLIB_EXT): kernel_sim_harness.c tracer_kernel.c mock_bpf_runtime.h
	$(CC) -std=gnu11 -O2 -fPIC $(SHLIB_FLAGS) $< -o $@

test: all
	python3 test_verification_suite.py -v

vmtest:
	./vmtest.sh

vmtest-load:
	./vmtest.sh -l

vmtest-skeleton:
	ssh ebpf-tracer-v2.0.0 bash -c "'cd /home/rocky/ebpf-wire-to-code-tracer-v2.0.0 && clang -target bpf -D__TARGET_ARCH_arm64 -DKRAY_BPF_CORE -O2 -g -I. -Ireferences/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers -c tracer_kernel.c -o tracer_kernel_bpf.o && bpftool gen skeleton tracer_kernel_bpf.o > tracer_kernel.skel.h && head -n 30 tracer_kernel.skel.h'"

vmtest-progs:
	ssh ebpf-tracer-v2.0.0 bash -c "'cd /home/rocky/ebpf-wire-to-code-tracer-v2.0.0 && gcc -O2 -g test_progs.c -lbpf -lelf -lz -o test_progs && sudo ./test_progs'"

clean:
	rm -f tracer_kernel_bpf.o tracer_kernel.skel.h
	rm -f libcrypto_mock.so mock_server
	rm -f libtracer_kernel_sim.dylib libtracer_kernel_sim.so
	rm -rf *.dSYM .pytest_cache __pycache__
