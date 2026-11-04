# SPDX-License-Identifier: GPL-2.0
# ==============================================================================
# Makefile — Kernel-Style BPF & Skeleton Build Harness
# Modeled after tools/testing/selftests/bpf/Makefile
# Target Architecture: aarch64 (Rocky Linux 9.8 5.14.0-687.10.1.el9_8.0.1.aarch64)
# ==============================================================================

CC ?= clang
CXX ?= clang++
BPFTOOL ?= /usr/sbin/bpftool

# 원격 테스트 VM: ssh 호스트 별칭과 VM 안의 작업 디렉터리(원격 홈 기준 상대 경로)
VM_HOST ?= ebpf-vm
VM_DIR ?= ebpf-wire-to-code-tracer

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
	./krayctl run-all

vmtest-load:
	./krayctl claims

vmtest-skeleton:
	./krayctl build

vmtest-progs:
	./krayctl selftest

vmtest-trace:
	./krayctl trace

vmtest-daemon:
	./krayctl trace

install:
	./krayctl install

uninstall:
	./krayctl uninstall

clean:
	rm -f tracer_kernel_bpf.o tracer_kernel.skel.h
	rm -f libcrypto_mock.so mock_server
	rm -f libtracer_kernel_sim.dylib libtracer_kernel_sim.so
	rm -f test_progs tracer_daemon progs/*.skel.h progs/*.o
	rm -rf *.dSYM .pytest_cache __pycache__
