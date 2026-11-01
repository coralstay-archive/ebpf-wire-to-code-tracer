#!/usr/bin/env bash
# ==============================================================================
# vmtest.sh — Upstream-Inspired Kernel VM Test Runner
# Modeled after tools/testing/selftests/bpf/vmtest.sh
# Targets: Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)
# ==============================================================================
set -euo pipefail

TARGET_HOST="ebpf-tracer-v2.0.0"
REMOTE_DIR="/home/rocky/ebpf-wire-to-code-tracer-v2.0.0"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TEST_TARGET=""
MODE="all"
VERBOSE=0

usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -t, --test <name>    Run specific test suite (e.g., ADV-TEST-12, TEST-01)"
    echo "  -l, --load-only      Run only live BPF Verifier loading test (bpftool prog loadall)"
    echo "  -s, --sync-only      Only synchronize workspace to target VM without running tests"
    echo "  -v, --verbose        Enable verbose test output"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Target VM: Rocky Linux 9.8 ($TARGET_HOST -> $REMOTE_DIR)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--test)
            TEST_TARGET="$2"
            MODE="test"
            shift 2
            ;;
        -l|--load-only)
            MODE="load"
            shift
            ;;
        -s|--sync-only)
            MODE="sync"
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

echo "================================================================================"
echo " [vmtest.sh] Syncing local workspace to Target VM: $TARGET_HOST"
echo "================================================================================"
rsync -avz --delete \
    --exclude '.git' \
    --exclude 'references' \
    --exclude '*.dSYM' \
    --exclude '__pycache__' \
    --exclude '.pytest_cache' \
    --exclude '*.so' \
    --exclude '*.dylib' \
    --exclude 'mock_server' \
    "$LOCAL_DIR/" "$TARGET_HOST:$REMOTE_DIR/"

if [ "$MODE" = "sync" ]; then
    echo "Sync complete."
    exit 0
fi

echo "================================================================================"
echo " [vmtest.sh] Executing in Target Rocky Linux 9.8 Guest Kernel"
echo "================================================================================"

if [ "$MODE" = "load" ]; then
    ssh "$TARGET_HOST" bash -c "'
        set -euo pipefail
        cd \"$REMOTE_DIR\"
        echo \"[Target Guest] Compiling tracer_kernel.c with Clang BPF CO-RE...\"
        clang -target bpf -D__TARGET_ARCH_arm64 -DKRAY_BPF_CORE -O2 -g \
            -I. -Ireferences/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers \
            -c tracer_kernel.c -o /tmp/tracer_kernel_bpf.o
        PIN_DIR=\"/sys/fs/bpf/kray_verify_test\"
        sudo rm -rf \"\$PIN_DIR\"
        sudo mkdir -p \"\$PIN_DIR\"
        echo \"[Target Guest] Loading and pinning all eBPF programs via bpftool prog loadall...\"
        sudo /usr/sbin/bpftool prog loadall /tmp/tracer_kernel_bpf.o \"\$PIN_DIR\"
        PIN_COUNT=\$(sudo ls -1 \"\$PIN_DIR\" | wc -l)
        echo \"[Target Guest] Successfully loaded and pinned \$PIN_COUNT eBPF programs into kernel!\"
        sudo rm -rf \"\$PIN_DIR\"
    '"
elif [ "$MODE" = "test" ]; then
    ssh "$TARGET_HOST" bash -c "'
        set -euo pipefail
        cd \"$REMOTE_DIR\"
        echo \"[Target Guest] Running test target: $TEST_TARGET\"
        python3 test_verification_suite.py -v | grep -E \"$TEST_TARGET|Summary:\"
    '"
else
    ssh "$TARGET_HOST" bash -c "'
        set -euo pipefail
        cd \"$REMOTE_DIR\"
        ./test_harness.sh
    '"
fi

echo "================================================================================"
echo " [vmtest.sh] Target VM Execution Finished Successfully!"
echo "================================================================================"
