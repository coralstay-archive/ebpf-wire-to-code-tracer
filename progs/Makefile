# SPDX-License-Identifier: GPL-2.0
# ==============================================================================
# progs/Makefile — Micro-BPF Modules & Skeletons Build
# Modeled after tools/testing/selftests/bpf/Makefile
# Target Architecture: aarch64 (Rocky Linux 9.8 5.14.0-687.10.1.el9_8.0.1.aarch64)
# ==============================================================================

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH ?= arm64
TARGET_ARCH ?= -D__TARGET_ARCH_$(ARCH)

ROOT_DIR := ..
REF_BTF_DIR := $(ROOT_DIR)/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers

BPF_CFLAGS := -target bpf $(TARGET_ARCH) -DKRAY_BPF_CORE -O2 -g \
              -I$(ROOT_DIR) -I$(REF_BTF_DIR) -Wall

SRCS := tracer_l2_xdp.bpf.c tracer_l3_ip.bpf.c tracer_l4_tcp.bpf.c tracer_l5_syscall.bpf.c tracer_l6_sched.bpf.c tracer_l7_uprobe.bpf.c
OBJS := $(SRCS:.bpf.c=.bpf.o)
SKELS := $(SRCS:.bpf.c=.skel.h)

.PHONY: all clean skeletons

all: $(OBJS) $(SKELS)

skeletons: $(SKELS)

%.bpf.o: %.bpf.c kray_common.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	@if command -v $(BPFTOOL) >/dev/null 2>&1; then \
		$(BPFTOOL) gen skeleton $< > $@ && echo "Generated skeleton: $@"; \
	fi

clean:
	rm -f *.bpf.o *.skel.h
