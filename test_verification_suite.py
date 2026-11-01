#!/usr/bin/env python3
"""
eBPF-WireToCode-Tracer — 12 Mandatory End-to-End Verification Suite (TDD Red-to-Green)
Strictly validates TEST-01 through TEST-12 and all 45 Pre-Implementation Design Audit Invariants
specified in PROMPT_SPEC.md against Rocky Linux 9.8 (5.14.0-687.10.1.el9_8.0.1.aarch64) references.
"""

import ctypes
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import pytest
except ImportError:
    pytest = None

ROOT_DIR = Path(__file__).resolve().parent
REF_BASE_DIR = (
    ROOT_DIR / "references"
    if (ROOT_DIR / "references").exists()
    else Path("/Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references")
)
KERNEL_C_PATH = ROOT_DIR / "tracer_kernel.c"
AGENT_PY_PATH = ROOT_DIR / "tracer_agent.py"
MOCK_SERVER_CPP_PATH = ROOT_DIR / "mock_server.cpp"
LIBCRYPTO_CPP_PATH = ROOT_DIR / "libcrypto_mock.cpp"
MOCK_SERVER_BIN = ROOT_DIR / "mock_server"
LIBCRYPTO_SO = ROOT_DIR / "libcrypto_mock.so"


def _ensure_mock_binaries_built() -> None:
    """Compile libcrypto_mock.so (stripped with strip -x) and mock_server if not already built."""
    assert LIBCRYPTO_CPP_PATH.exists(), f"Missing {LIBCRYPTO_CPP_PATH}"
    assert MOCK_SERVER_CPP_PATH.exists(), f"Missing {MOCK_SERVER_CPP_PATH}"

    if not LIBCRYPTO_SO.exists():
        subprocess.run(
            [
                "clang++",
                "-std=c++17",
                "-g",
                "-O0",
                "-fno-inline",
                "-fno-omit-frame-pointer",
                "-fPIC",
                "-shared",
                str(LIBCRYPTO_CPP_PATH),
                "-o",
                str(LIBCRYPTO_SO),
            ],
            cwd=str(ROOT_DIR),
            check=True,
        )
        subprocess.run(["strip", "-x", str(LIBCRYPTO_SO)], cwd=str(ROOT_DIR), check=True)

    if not MOCK_SERVER_BIN.exists():
        subprocess.run(
            [
                "clang++",
                "-std=c++17",
                "-g",
                "-O0",
                "-fno-inline",
                "-fno-omit-frame-pointer",
                "-pthread",
                str(MOCK_SERVER_CPP_PATH),
                "-ldl",
                "-o",
                str(MOCK_SERVER_BIN),
            ],
            cwd=str(ROOT_DIR),
            check=True,
        )


def _import_tracer_agent():
    """Dynamically import tracer_agent.py from workspace root."""
    assert AGENT_PY_PATH.exists(), f"Missing {AGENT_PY_PATH}"
    if str(ROOT_DIR) not in sys.path:
        sys.path.insert(0, str(ROOT_DIR))
    import importlib

    import tracer_agent

    return importlib.reload(tracer_agent)


# ==============================================================================
# TEST-01: C <-> Python 64B kray_event_t & 16B kray_runtime_cfg_t ABI Match
# ==============================================================================
def test_01_abi_struct_layout_and_offsets(tmp_path: Path):
    """
    TEST-01: Compile a real C++ binary extracting struct kray_event_t (64B) and
    struct kray_runtime_cfg_t (16B) from tracer_kernel.c and assert 100% exact
    sizeof and offsetof match against Python ctypes structures in tracer_agent.py.
    """
    assert KERNEL_C_PATH.exists(), "tracer_kernel.c must exist"
    tracer_agent = _import_tracer_agent()

    kernel_src = KERNEL_C_PATH.read_text(encoding="utf-8")
    ev_match = re.search(
        r"struct\s+__attribute__\(\(packed\)\)\s+kray_event_t\s*\{.*?\};",
        kernel_src,
        re.DOTALL,
    )
    cfg_match = re.search(
        r"struct\s+__attribute__\(\(packed\)\)\s+kray_runtime_cfg_t\s*\{.*?\};",
        kernel_src,
        re.DOTALL,
    )
    fkey_match = re.search(
        r"struct\s+flow_key_t\s*\{.*?\};",
        kernel_src,
        re.DOTALL,
    )
    assert ev_match is not None, "struct __attribute__((packed)) kray_event_t not found in tracer_kernel.c"
    assert cfg_match is not None, "struct __attribute__((packed)) kray_runtime_cfg_t not found in tracer_kernel.c"
    assert fkey_match is not None, "struct flow_key_t not found in tracer_kernel.c"

    probe_cpp = tmp_path / "abi_probe.cpp"
    probe_bin = tmp_path / "abi_probe"
    probe_cpp.write_text(
        rf"""
#include <cstddef>
#include <cstdint>
#include <cstdio>

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

{cfg_match.group(0)}
{ev_match.group(0)}
{fkey_match.group(0)}

int main() {{
    printf("{{\"event_sizeof\": %zu, \"cfg_sizeof\": %zu, \"flow_key_sizeof\": %zu, ",
           sizeof(kray_event_t), sizeof(kray_runtime_cfg_t), sizeof(flow_key_t));
    printf("\"event_offsets\": {{");
    printf("\"req_id\": %zu, ", offsetof(kray_event_t, req_id));
    printf("\"ip\": %zu, ", offsetof(kray_event_t, ip));
    printf("\"timestamp\": %zu, ", offsetof(kray_event_t, timestamp));
    printf("\"duration_ns\": %zu, ", offsetof(kray_event_t, duration_ns));
    printf("\"pid\": %zu, ", offsetof(kray_event_t, pid));
    printf("\"tid\": %zu, ", offsetof(kray_event_t, tid));
    printf("\"parent_tid\": %zu, ", offsetof(kray_event_t, parent_tid));
    printf("\"src_ip\": %zu, ", offsetof(kray_event_t, src_ip));
    printf("\"dst_ip\": %zu, ", offsetof(kray_event_t, dst_ip));
    printf("\"src_port\": %zu, ", offsetof(kray_event_t, src_port));
    printf("\"dst_port\": %zu, ", offsetof(kray_event_t, dst_port));
    printf("\"layer_type\": %zu, ", offsetof(kray_event_t, layer_type));
    printf("\"is_return\": %zu, ", offsetof(kray_event_t, is_return));
    printf("\"call_depth\": %zu, ", offsetof(kray_event_t, call_depth));
    printf("\"flags\": %zu, ", offsetof(kray_event_t, flags));
    printf("\"drop_count\": %zu", offsetof(kray_event_t, drop_count));
    printf("}}, \"cfg_offsets\": {{");
    printf("\"target_pid\": %zu, ", offsetof(kray_runtime_cfg_t, target_pid));
    printf("\"target_port\": %zu, ", offsetof(kray_runtime_cfg_t, target_port));
    printf("\"capture_enabled\": %zu, ", offsetof(kray_runtime_cfg_t, capture_enabled));
    printf("\"filter_flags\": %zu, ", offsetof(kray_runtime_cfg_t, filter_flags));
    printf("\"config_epoch\": %zu", offsetof(kray_runtime_cfg_t, config_epoch));
    printf("}}}}\n");
    return 0;
}}
""",
        encoding="utf-8",
    )

    subprocess.run(["clang++", "-std=c++17", str(probe_cpp), "-o", str(probe_bin)], check=True)
    out = subprocess.check_output([str(probe_bin)], text=True)
    c_abi = json.loads(out)

    assert c_abi["event_sizeof"] == 64
    assert c_abi["cfg_sizeof"] == 16
    assert c_abi["flow_key_sizeof"] == 16, "struct flow_key_t must be explicitly padded to 16B for BPF Verifier"
    assert ctypes.sizeof(tracer_agent.KrayEvent) == 64
    assert ctypes.sizeof(tracer_agent.KrayRuntimeCfg) == 16

    py_event_offsets = {
        field_name: getattr(tracer_agent.KrayEvent, field_name).offset
        for field_name, _ in tracer_agent.KrayEvent._fields_
    }
    py_cfg_offsets = {
        field_name: getattr(tracer_agent.KrayRuntimeCfg, field_name).offset
        for field_name, _ in tracer_agent.KrayRuntimeCfg._fields_
    }

    assert c_abi["event_offsets"] == py_event_offsets
    assert c_abi["cfg_offsets"] == py_cfg_offsets


# ==============================================================================
# TEST-02: eBPF C Kernel Code, Rocky 9.8 aarch64 Symbols & 45 Audit Invariants
# ==============================================================================
def test_02_ebpf_kernel_c_rocky98_symbols_and_core_safety():
    """
    TEST-02: Verify tracer_kernel.c strictly complies with Rocky Linux 9.8
    (5.14.0-687.10.1.el9_8.0.1.aarch64) kernel source symbols, BTF CO-RE guards,
    Verifier bounds checks, and the 45 Pre-Implementation Design Audit fixes.
    """
    assert KERNEL_C_PATH.exists(), "tracer_kernel.c must exist"
    src = KERNEL_C_PATH.read_text(encoding="utf-8")

    # 1. Architecture & CO-RE guards
    assert "__TARGET_ARCH_arm64" in src
    assert "KRAY_BPF_CORE" in src
    assert "vmlinux.h" in src
    assert "runtime_config_map" in src

    # 2. Verified Rocky 9.8 kernel symbols & hook signatures
    required_hooks_and_symbols = [
        "xdp_ingress_filter",
        "netif_receive_skb",
        "kprobe__ip_rcv",
        "kprobe__tcp_v4_rcv",
        "tcp_retransmit_skb",
        "kfree_skb",
        "kprobe__tcp_recvmsg",
        "kretprobe__tcp_recvmsg",
        "sys_enter_read",
        "skb_copy_datagram_iovec",
        "kretprobe__skb_copy_datagram_iter",
        "kprobe__handle_mm_fault",
        "sys_enter_futex",
        "sys_exit_futex",
        "sched_process_fork",
        "sched_waking",
        "sched_wakeup",
        "sched_switch",
        "block_rq_insert",
        "block_rq_issue",
        "block_rq_complete",
        "trace_uprobe_entry",
        "trace_uprobe_return",
        "sys_enter_write",
        "sys_exit_write",
        "kprobe__tcp_sendmsg",
        "kretprobe__tcp_sendmsg",
        "kprobe____tcp_transmit_skb",
        "kprobe__ip_output",
        "net_dev_queue",
        "net_dev_xmit",
        # Multi-protocol hooks
        "kprobe__tcp_v6_rcv",
        "kprobe__udp_rcv",
        "kprobe__udp_recvmsg",
        "kretprobe__udp_recvmsg",
        "kprobe__udp_sendmsg",
        "kprobe__ipv6_rcv",
        "kprobe__ip6_output",
        "kprobe__icmp_rcv",
        "kprobe__arp_rcv",
        "kprobe__unix_stream_recvmsg",
        "kprobe__unix_stream_sendmsg",
    ]
    for sym in required_hooks_and_symbols:
        assert sym in src, f"Required Rocky 9.8 hook/symbol '{sym}' missing from tracer_kernel.c"

    # Ensure no forbidden non-existent/inlined/x86-only hook definitions exist
    assert "kprobe__tcp_transmit_skb(" not in src, "tcp_transmit_skb is compiler-inlined; must use kprobe____tcp_transmit_skb"
    assert "TRACEPOINT_PROBE(exceptions, page_fault_user)" not in src, "page_fault_user is x86-only; must use kprobe__handle_mm_fault on aarch64"

    # 3. Required BPF maps (6 LRU_HASH + PERCPU_ARRAY zero_ctx_map + RINGBUF + drop_cnt_map)
    required_maps = [
        "ingress_flow_map",
        "active_ctx_map",
        "zero_ctx_map",
        "pending_handoff_map",
        "egress_flow_map",
        "skb_egress_map",
        "inflight_bio_map",
        "BPF_RINGBUF_OUTPUT(events",
        "drop_cnt_map",
    ]
    for m in required_maps:
        assert m in src, f"Required BPF map '{m}' missing from tracer_kernel.c"

    # 4. XDP Verifier safety: data_end bounds check & NO bpf_get_current_pid_tgid() inside XDP
    xdp_fn_match = re.search(
        r"int\s+xdp_ingress_filter\s*\([^)]*\)\s*\{(.*?)\n\}",
        src,
        re.DOTALL,
    )
    assert xdp_fn_match is not None, "xdp_ingress_filter function body not found"
    xdp_body = xdp_fn_match.group(1)
    assert "data_end" in xdp_body, "XDP hook must check data_end bounds"
    assert "bpf_get_current_pid_tgid" not in xdp_body, "XDP hook must NEVER call bpf_get_current_pid_tgid()"

    # 5. Concrete Audit Invariants check across all hooks
    assert "bpf_probe_read_kernel" in src, "Kprobe SKB reads must use bpf_probe_read_kernel"
    assert "fn_entry_ip" in src, "uretprobe must restore saved fn_entry_ip[depth] to avoid [uprobes] trampoline IP"
    assert "nr_sector" in src, "block_rq_complete must compute bytes from args->nr_sector * 512"
    assert "in_target_sendmsg" in src, "kretprobe__tcp_sendmsg must guard context deletion via in_target_sendmsg"
    assert "PT_REGS_PARM3(ctx)" in src, "kprobe__ip_output / kprobe__ip6_output must read skb from PT_REGS_PARM3(ctx)"
    assert "(u8 *)(arp + 1) + 6" in src and "(u8 *)(arp + 1) + 16" in src, "kprobe__arp_rcv must read ar_sip/ar_tip at +6/+16 past struct arphdr"
    assert "u6_addr32" in src, "IPv6 hooks must XOR-fold in6_u.u6_addr32[0..3]"
    assert "active_msg_name" in src, "udp_recvmsg must stash msg->msg_name into active_msg_name for kretprobe__udp_recvmsg"
    assert "usk->peer" in src, "AF_UNIX hooks must normalize flow key using unix_sock->peer"
    assert "args->rx_sk" in src, "tracepoint:skb:kfree_skb must include Stage 2 args->rx_sk lookup"
    assert "nctx->off_cpu_enter_ts = 0;" in src and "nctx->wakeup_ts        = 0;" in src, "sched_switch must reset off_cpu_enter_ts and wakeup_ts after emission"


# ==============================================================================
# TEST-03: 6-Layer Correlation & Multi-Request Isolation
# ==============================================================================
def test_03_six_layer_correlation_and_multi_request_isolation():
    """
    TEST-03: Inject interleaved 6-layer event streams for two concurrent requests
    (req_id #1 and req_id #2) and verify deterministic isolation and canonical ordering
    (Layer 1 -> 2 -> 3 -> 4 -> 5 -> 6).
    """
    tracer_agent = _import_tracer_agent()
    correlator = tracer_agent.RequestCorrelator(grace_window_ms=50.0)

    req1 = 0x9F82A101
    req2 = 0x9F82A202
    base_ts = 1_000_000_000

    # Interleaved events across req1 and req2
    interleaved_events = [
        # L1 Ingress NIC
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 10_000, duration_ns=40_000, layer_type=1, call_depth=2, src_port=54321, dst_port=8080),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 15_000, duration_ns=42_000, layer_type=1, call_depth=2, src_port=54322, dst_port=8080),
        # L2 Kernel Net (L3 IP + L4 TCP)
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 50_000, duration_ns=38_000, layer_type=2, call_depth=3, src_port=54321, dst_port=8080),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 55_000, duration_ns=39_000, layer_type=2, call_depth=3, src_port=54322, dst_port=8080),
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 110_000, duration_ns=60_000, layer_type=2, call_depth=4, src_port=54321, dst_port=8080),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 115_000, duration_ns=62_000, layer_type=2, call_depth=4, src_port=54322, dst_port=8080),
        # L3 User Entry (Socket + Syscall/Mem + L6 Pre-Compute)
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 300_000, duration_ns=190_000, layer_type=3, call_depth=5, pid=1000, tid=1001, src_port=54321, dst_port=8080),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 310_000, duration_ns=195_000, layer_type=3, call_depth=5, pid=1000, tid=1001, src_port=54322, dst_port=8080),
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 330_000, duration_ns=25_000, layer_type=3, call_depth=6, pid=1000, tid=1001, src_port=54321, dst_port=8080),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 340_000, duration_ns=26_000, layer_type=3, call_depth=6, pid=1000, tid=1001, src_port=54322, dst_port=8080),
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 500_000, duration_ns=65_000, layer_type=3, call_depth=8, pid=1000, tid=1002, parent_tid=1001, flags=0x01, src_port=54321, dst_port=8080),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 520_000, duration_ns=70_000, layer_type=3, call_depth=8, pid=1000, tid=1003, parent_tid=1001, flags=0x01, src_port=54322, dst_port=8080),
        # L4 User Func (uprobe entry & uretprobe return)
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 600_000, duration_ns=0, layer_type=4, is_return=0, call_depth=0, pid=1000, tid=1002, parent_tid=1001, ip=0x401100),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 610_000, duration_ns=0, layer_type=4, is_return=0, call_depth=0, pid=1000, tid=1003, parent_tid=1001, ip=0x401100),
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 18_600_000, duration_ns=18_000_000, layer_type=4, is_return=1, call_depth=0, pid=1000, tid=1002, parent_tid=1001, ip=0x401100),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 5_610_000, duration_ns=5_000_000, layer_type=4, is_return=1, call_depth=0, pid=1000, tid=1003, parent_tid=1001, ip=0x401100),
        # L5 User Exit
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 18_700_000, duration_ns=66_000, layer_type=5, call_depth=5, pid=1000, tid=1002, src_port=8080, dst_port=54321),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 5_700_000, duration_ns=64_000, layer_type=5, call_depth=5, pid=1000, tid=1003, src_port=8080, dst_port=54322),
        # L6 Egress NIC (L4 TCP -> L3 IP -> L2 NIC)
        tracer_agent.make_event(req_id=req1, timestamp=base_ts + 18_800_000, duration_ns=70_000, layer_type=6, call_depth=2, pid=1000, tid=1002, src_port=8080, dst_port=54321),
        tracer_agent.make_event(req_id=req2, timestamp=base_ts + 5_800_000, duration_ns=68_000, layer_type=6, call_depth=2, pid=1000, tid=1003, src_port=8080, dst_port=54322),
    ]

    for ev in interleaved_events:
        correlator.ingest(ev)

    completed = correlator.get_completed_traces()
    assert req1 in completed
    assert req2 in completed

    t1_layers = [ev.layer_type for ev in completed[req1]]
    t2_layers = [ev.layer_type for ev in completed[req2]]

    assert t1_layers == sorted(t1_layers)
    assert t2_layers == sorted(t2_layers)
    assert set(t1_layers) == {1, 2, 3, 4, 5, 6}
    assert set(t2_layers) == {1, 2, 3, 4, 5, 6}
    assert all(ev.req_id == req1 for ev in completed[req1])
    assert all(ev.req_id == req2 for ev in completed[req2])

    # 2. Verify 50ms Grace Window when LAYER_EGRESS_NIC is delayed/omitted (Flaw #10)
    req3 = 0x9F82A303
    correlator2 = tracer_agent.RequestCorrelator(grace_window_ms=50.0)
    exit_ts = base_ts + 20_000_000
    # Inject out-of-order events (Layer 5 before Layer 1) without Layer 6
    correlator2.ingest(tracer_agent.make_event(req_id=req3, timestamp=exit_ts, duration_ns=50_000, layer_type=5, call_depth=5))
    correlator2.ingest(tracer_agent.make_event(req_id=req3, timestamp=base_ts + 10_000, duration_ns=40_000, layer_type=1, call_depth=2))
    # At +20ms (< 50ms grace window), req3 must NOT be flushed yet
    correlator2.flush_expired(current_ts_ns=exit_ts + 20_000_000)
    assert req3 not in correlator2._completed
    # At +55ms (>= 50ms grace window), req3 MUST be finalized and canonically sorted
    correlator2.flush_expired(current_ts_ns=exit_ts + 55_000_000)
    assert req3 in correlator2._completed
    assert [e.layer_type for e in correlator2._completed[req3]] == [1, 5]

    # 3. Verify Disjoint (layer_type, call_depth) & Bit-Packing Decoding (Flaw #9 & #25)
    # Depth-6 and Depth-8 user functions (layer_type=4) MUST decode as OSI_L7_APP (7), never L5(6) or L6(8)
    u_depth6 = tracer_agent.decode_event_metadata(
        tracer_agent.make_event(req_id=req1, timestamp=base_ts, duration_ns=1000, layer_type=4, call_depth=6, ip=0x401234)
    )
    u_depth8 = tracer_agent.decode_event_metadata(
        tracer_agent.make_event(req_id=req1, timestamp=base_ts, duration_ns=1000, layer_type=4, call_depth=8, ip=0x401238)
    )
    assert u_depth6["osi_layer_id"] == 7 and u_depth6["user_call_depth"] == 6
    assert u_depth8["osi_layer_id"] == 7 and u_depth8["user_call_depth"] == 8

    # Kernel L5 (layer_type=3, call_depth=6) and L6 (layer_type=3, call_depth=8) bit-packing check
    l5_meta = tracer_agent.decode_event_metadata(
        tracer_agent.make_event(req_id=req1, timestamp=base_ts, duration_ns=25000, layer_type=3, call_depth=6, ip=(3 << 32) | 4096)
    )
    assert l5_meta["osi_layer_id"] == 6 and l5_meta["page_faults"] == 3 and l5_meta["copied_or_bio_bytes"] == 4096

    l6_meta = tracer_agent.decode_event_metadata(
        tracer_agent.make_event(req_id=req1, timestamp=base_ts, duration_ns=65000, layer_type=3, call_depth=8, ip=(115000 << 16) | (0 << 8) | 2)
    )
    assert l6_meta["osi_layer_id"] == 8 and l6_meta["lock_wait_ns"] == 115000 and l6_meta["prev_cpu_id"] == 0 and l6_meta["target_cpu_id"] == 2


# ==============================================================================
# TEST-04: Worker Thread-Pool Handoff (TID A -> TID B)
# ==============================================================================
def test_04_worker_thread_pool_handoff(tmp_path: Path):
    """
    TEST-04: Run a full trace against mock_server and verify I/O dispatcher thread
    (TID A) -> Worker thread (TID B) lineage propagation (parent_tid == TID A)
    and dashed blue Thread Handoff edge in Graphviz .dot.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    out_prefix = tmp_path / "trace_handoff"
    ai_json_path = tmp_path / "ai_handoff.json"

    result = tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(out_prefix),
        ai_report_path=str(ai_json_path),
        fast_mode=False,
    )

    assert ai_json_path.exists()
    dot_path = Path(f"{out_prefix}.dot")
    assert dot_path.exists()

    diag = json.loads(ai_json_path.read_text(encoding="utf-8"))
    hops = diag["hop_timeline"]
    handoff_hops = [h for h in hops if h.get("parent_tid", 0) != 0 and h["tid"] != h["parent_tid"]]
    assert len(handoff_hops) >= 1, "Expected at least one worker thread handoff (tid != parent_tid)"
    assert diag["network_layer_diagnostics"]["layers"]["L7"]["thread_handoffs"] >= 1

    dot_content = dot_path.read_text(encoding="utf-8")
    assert "Thread Handoff" in dot_content
    assert "#2980b9" in dot_content
    assert "dashed,bold" in dot_content


# ==============================================================================
# TEST-05: Stripped Shared Library (.so) Offset Fallback (module+0xoffset)
# ==============================================================================
def test_05_stripped_shared_library_offset_fallback(tmp_path: Path):
    """
    TEST-05: Verify that strip -x libcrypto_mock.so has its internal function
    symbolicated as libcrypto_mock.so+0x<hex_offset> with FLAG_STRIPPED_SYMBOL
    and purple border (#8e44ad) + [STRIPPED ELF OFFSET] badge in .dot.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    out_prefix = tmp_path / "trace_stripped"
    ai_json_path = tmp_path / "ai_stripped.json"

    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(out_prefix),
        ai_report_path=str(ai_json_path),
    )

    diag = json.loads(ai_json_path.read_text(encoding="utf-8"))
    stripped_hops = [
        h for h in diag["hop_timeline"] if re.match(r"^libcrypto_mock\.so\+0x[0-9a-fA-F]+$", h["symbol_or_probe"])
    ]
    assert len(stripped_hops) >= 1, "Expected stripped offset symbol matching libcrypto_mock.so+0x<hex>"

    dot_content = Path(f"{out_prefix}.dot").read_text(encoding="utf-8")
    assert "#8e44ad" in dot_content
    assert "[STRIPPED ELF OFFSET]" in dot_content

    # Verify /proc/<PID>/maps parsing, rel_offset = (ip - vm_start) + file_offset,
    # aarch64 64KB PT_LOAD uprobe_file_offset, and C++ uprobe explosion filter (Flaws #4, #6, #18)
    maps_sample = (
        "00400000-00405000 r-xp 00001000 08:01 101 /app/mock_server\n"
        "ffff80010000-ffff80020000 r-xp 00000000 08:01 102 /app/libcrypto_mock.so\n"
    )
    segs = tracer_agent.BinarySymbolicator.parse_proc_maps(maps_sample)
    assert len(segs) == 2
    sym_engine = tracer_agent.BinarySymbolicator(str(MOCK_SERVER_BIN), str(LIBCRYPTO_SO))
    resolved = sym_engine.resolve_runtime_ip(0xFFFF80011140, segs)
    assert resolved["symbol"] == "libcrypto_mock.so+0x1140"
    assert resolved["stripped"] is True
    assert resolved["flags"] == tracer_agent.FLAG_STRIPPED_SYMBOL

    # Verify aarch64 64KB PT_LOAD uprobe_file_offset formula: st_value - p_vaddr + p_offset
    assert tracer_agent.compute_uprobe_file_offset(0x11140, 0x10000, 0x0) == 0x1140

    # Verify C++ symbol filter excludes STL/compiler prefixes & <16B thunks and caps at MAX_AUTO_UPROBES=64
    raw_candidates = [
        ("_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_", 64),
        ("__cxa_allocate_exception", 48),
        ("tiny_thunk", 8),
        ("plt_stub@plt", 32),
    ] + [(f"domain_fn_{i}", 64) for i in range(100)]
    filtered_syms = tracer_agent.BinarySymbolicator.select_auto_uprobe_targets(raw_candidates)
    assert len(filtered_syms) == 64
    assert all(s.startswith("domain_fn_") for s in filtered_syms)


# ==============================================================================
# TEST-06: Ring Buffer Overflow Alert Banner (--simulate-drops 42)
# ==============================================================================
def test_06_ringbuf_overflow_alert_banner(tmp_path: Path):
    """
    TEST-06: Verify --simulate-drops 42 produces drop_count == 42 and renders
    subgraph cluster_alert_overflow at the top of .dot and .svg.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    out_prefix = tmp_path / "trace_overflow"
    ai_json_path = tmp_path / "ai_overflow.json"

    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(out_prefix),
        ai_report_path=str(ai_json_path),
        simulate_drops=42,
    )

    diag = json.loads(ai_json_path.read_text(encoding="utf-8"))
    assert diag["drop_count"] == 42
    # Verify Flaw #8 formula: max(max_event_drop_count, bpf_drop_cnt_map[0]) + simulate_drops
    assert tracer_agent.compute_final_drop_count(max_event_drop_count=0, bpf_drop_cnt_map_val=99, simulate_drops=42) == 141
    assert tracer_agent.compute_final_drop_count(max_event_drop_count=120, bpf_drop_cnt_map_val=99, simulate_drops=0) == 120

    dot_content = Path(f"{out_prefix}.dot").read_text(encoding="utf-8")
    assert "subgraph cluster_alert_overflow" in dot_content
    assert "#ffebee" in dot_content
    assert "#c0392b" in dot_content
    assert "42" in dot_content

    svg_path = Path(f"{out_prefix}.svg")
    assert svg_path.exists()
    svg_content = svg_path.read_text(encoding="utf-8")
    assert "BPF RING BUFFER OVERFLOW DETECTED" in svg_content
    assert "42" in svg_content


# ==============================================================================
# TEST-07: 4-Tier Clusters, Sanitized Subgraph ID, Heatmap Coloring & SVG
# ==============================================================================
def test_07_four_tier_graphviz_clusters_heatmap_and_svg(tmp_path: Path):
    """
    TEST-07: Verify 4-Tier cluster hierarchy, sanitized module subgraph name
    (cluster_mod_libcrypto_mock_so), 3-tier heatmap colors (#2ecc71, #f39c12, #e74c3c),
    and valid Graphviz .svg compilation.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    out_prefix = tmp_path / "trace_topology"
    ai_json_path = tmp_path / "ai_topology.json"

    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(out_prefix),
        ai_report_path=str(ai_json_path),
    )

    dot_path = Path(f"{out_prefix}.dot")
    svg_path = Path(f"{out_prefix}.svg")
    assert dot_path.exists()
    assert svg_path.exists()

    dot_content = dot_path.read_text(encoding="utf-8")
    for cluster_name in [
        "cluster_tier_ingress",
        "cluster_tier_kernel",
        "cluster_tier_app",
        "cluster_tier_egress",
        "cluster_mod_libcrypto_mock_so",
    ]:
        assert cluster_name in dot_content, f"Missing subgraph {cluster_name} in .dot"

    # Ensure unquoted dot in subgraph identifier is never emitted
    assert "cluster_mod_libcrypto_mock.so" not in dot_content

    # All 3 heatmap colors present
    for color in ["#2ecc71", "#f39c12", "#e74c3c"]:
        assert color in dot_content, f"Missing heatmap color {color} in .dot"

    svg_content = svg_path.read_text(encoding="utf-8")
    assert "<svg" in svg_content and "</svg>" in svg_content


# ==============================================================================
# TEST-08: AI Diagnosis Bundle (ai_diagnosis.json) Source & Assembly Extraction
# ==============================================================================
def test_08_ai_diagnosis_json_source_and_assembly_evidence(tmp_path: Path):
    """
    TEST-08: Verify all 8 mandatory top-level keys in ai_diagnosis.json, real C++
    source snippet extraction for execute_storage_query, and real disassembly
    extraction for stripped libcrypto_mock.so+0x... offset.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    out_prefix = tmp_path / "trace_diag"
    ai_json_path = tmp_path / "ai_diagnosis.json"

    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(out_prefix),
        ai_report_path=str(ai_json_path),
    )

    diag = json.loads(ai_json_path.read_text(encoding="utf-8"))
    mandatory_top_keys = [
        "req_id",
        "total_rtt_ms",
        "drop_count",
        "bottleneck_summary",
        "hop_timeline",
        "source_code_evidence",
        "stripped_assembly_evidence",
        "network_layer_diagnostics",
    ]
    for k in mandatory_top_keys:
        assert k in diag, f"Missing mandatory top-level key '{k}' in ai_diagnosis.json"

    assert diag["bottleneck_summary"]["primary_suspect"] == "execute_storage_query"
    assert diag["bottleneck_summary"]["pct_of_rtt"] > 35.0

    src_ev = diag["source_code_evidence"]
    assert "execute_storage_query" in src_ev
    assert "mock_server.cpp" in src_ev["execute_storage_query"]["file"]
    assert int(src_ev["execute_storage_query"]["line"]) > 0
    assert len(src_ev["execute_storage_query"]["snippet"].strip()) > 20

    asm_ev = diag["stripped_assembly_evidence"]
    assert len(asm_ev) >= 1
    first_asm_key = next(iter(asm_ev))
    assert first_asm_key.startswith("libcrypto_mock.so+0x")
    assert len(asm_ev[first_asm_key]["instructions"]) >= 2


# ==============================================================================
# TEST-09: Adaptive Zoom-In (--focus-symbol, --uprobe-offset) & --compare
# ==============================================================================
def test_09_adaptive_zoom_in_and_before_after_patch_compare(tmp_path: Path):
    """
    TEST-09: Verify --focus-symbol and --uprobe-offset selective probing, and
    verify --compare between baseline and --fast-mode patched traces (>50% RTT reduction).
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    zoom_json = tmp_path / "ai_zoom.json"
    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "trace_zoom"),
        ai_report_path=str(zoom_json),
        focus_symbol="execute_storage_query",
    )
    zoom_diag = json.loads(zoom_json.read_text(encoding="utf-8"))
    app_fns = [h["symbol_or_probe"] for h in zoom_diag["hop_timeline"] if h["layer_type"] == 4 and not h.get("is_return")]
    assert "execute_storage_query" in app_fns
    assert "parse_http_request" not in app_fns

    # Test --uprobe-offset selective probing on stripped shared library
    uprobe_json = tmp_path / "ai_uprobe_offset.json"
    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "trace_uprobe_off"),
        ai_report_path=str(uprobe_json),
        uprobe_offset="libcrypto_mock.so:0x1140",
    )
    uprobe_diag = json.loads(uprobe_json.read_text(encoding="utf-8"))
    uprobe_fns = [h["symbol_or_probe"] for h in uprobe_diag["hop_timeline"] if h["layer_type"] == 4 and not h.get("is_return")]
    assert "libcrypto_mock.so+0x1140" in uprobe_fns
    assert "parse_http_request" not in uprobe_fns
    assert "libcrypto_mock.so+0x1140" in uprobe_diag["stripped_assembly_evidence"]

    # Baseline vs Patched (--fast-mode)
    base_json = tmp_path / "ai_baseline.json"
    patch_json = tmp_path / "ai_patched.json"

    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "trace_base"),
        ai_report_path=str(base_json),
        fast_mode=False,
    )
    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "trace_patch"),
        ai_report_path=str(patch_json),
        fast_mode=True,
    )

    comparison = tracer_agent.compare_diagnoses(str(base_json), str(patch_json))
    assert comparison["rtt_reduction_pct"] > 50.0
    assert comparison["bottleneck_resolved"] is True


# ==============================================================================
# TEST-10: Human Interfaces (Interactive Web Dashboard & Terminal TUI)
# ==============================================================================
def test_10_human_interfaces_web_dashboard_and_tui(tmp_path: Path):
    """
    TEST-10: Verify trace_dashboard.html contains inline SVG, 7-layer filter pills,
    code/ASM/packet inspector, and 3 bottom tabs; and verify --ui tui console menu.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    html_path = tmp_path / "trace_dashboard.html"
    ai_json = tmp_path / "ai_ui.json"
    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "trace_ui"),
        ai_report_path=str(ai_json),
        html_out_path=str(html_path),
    )

    assert html_path.exists()
    html = html_path.read_text(encoding="utf-8")
    assert "<svg" in html
    assert "7-Layer Pre-Compute" in html
    assert "Before vs After" in html
    assert "execute_storage_query" in html
    assert "libcrypto_mock.so+0x" in html
    assert "PUT /api/v1/config" in html
    assert "Zoom-In Probe This Function/Offset" in html
    assert "inspectHop(" in html
    assert "kernel-packet-view" in html
    assert "cpp-source-view" in html
    assert "asm-source-view" in html

    # Test all 7 TUI actions via subprocess stdin piping ("1\n2\n3\n4\n5\n6\n7\nq\n")
    proc = subprocess.run(
        [
            sys.executable,
            str(AGENT_PY_PATH),
            "--mode",
            "simulate",
            "--binary",
            str(MOCK_SERVER_BIN),
            "--lib",
            str(LIBCRYPTO_SO),
            "--ui",
            "tui",
            "--out",
            str(tmp_path / "tui_out"),
            "--ai-report",
            str(tmp_path / "tui_ai.json"),
        ],
        input="1\n2\n3\n4\n5\n6\n7\nq\n",
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert proc.returncode == 0
    assert "7-Layer" in proc.stdout
    assert "Zoom-In Probe" in proc.stdout
    assert "Before vs After Patch Compare" in proc.stdout
    assert "RingBuf Overflow Simulation" in proc.stdout
    assert "Web Dashboard Exported" in proc.stdout


# ==============================================================================
# TEST-11: MCP Server (6 Tools) & REST API (/api/v1/*) 0ms Hot-Reload
# ==============================================================================
def test_11_mcp_server_6_tools_and_rest_api_hot_reload(tmp_path: Path):
    """
    TEST-11: Verify MCP JSON-RPC 2.0 server exposes all 6 tools and increments
    config_epoch in 0ms; and verify REST API server endpoints respond in <500ms.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    mcp = tracer_agent.MCPGatewayServer(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        work_dir=str(tmp_path),
    )

    init_resp = mcp.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init_resp["result"]["serverInfo"]["name"] == "eBPF-WireToCode-Tracer"

    list_resp = mcp.handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    expected_tools = {
        "ebpf_configure_target",
        "ebpf_capture_trace",
        "ebpf_inspect_network_layers",
        "ebpf_inspect_code_or_asm",
        "ebpf_compare_patches",
        "ebpf_render_topology",
    }
    assert expected_tools.issubset(tool_names)

    # Test 0ms Hot-Reload (ebpf_configure_target - Tool #1)
    cfg_resp = mcp.handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "ebpf_configure_target",
                "arguments": {"pid": 4242, "port": 9090, "iface": "lo", "capture_enabled": True},
            },
        }
    )
    cfg_payload = json.loads(cfg_resp["result"]["content"][0]["text"])
    assert cfg_payload["config_epoch"] >= 1
    assert cfg_payload["target_port"] == 9090

    # Test Tool #2: ebpf_capture_trace (baseline and fast)
    cap_base = json.loads(
        mcp.handle_jsonrpc(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "ebpf_capture_trace", "arguments": {"mode": "baseline"}}}
        )["result"]["content"][0]["text"]
    )
    cap_fast = json.loads(
        mcp.handle_jsonrpc(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "ebpf_capture_trace", "arguments": {"mode": "fast"}}}
        )["result"]["content"][0]["text"]
    )
    assert cap_base["total_rtt_ms"] > cap_fast["total_rtt_ms"]

    # Test Tool #3: ebpf_inspect_network_layers (with layer="sched" & proto="tcp")
    nl_mcp = json.loads(
        mcp.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "ebpf_inspect_network_layers", "arguments": {"layer": "sched", "proto": "tcp"}},
            }
        )["result"]["content"][0]["text"]
    )
    assert nl_mcp["requested_layer_filter"] == "sched"
    assert nl_mcp["requested_proto_filter"] == "tcp"
    assert nl_mcp["selected_layer"]["osi_layer"] == "L6_PRE_COMPUTE_SCHED_GATE"

    # Test Tool #4: ebpf_inspect_code_or_asm
    code_mcp = json.loads(
        mcp.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "ebpf_inspect_code_or_asm", "arguments": {"target": "execute_storage_query"}},
            }
        )["result"]["content"][0]["text"]
    )
    assert "execute_storage_query" in code_mcp["source"]

    # Test Tool #5: ebpf_compare_patches
    comp_mcp = json.loads(
        mcp.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "ebpf_compare_patches",
                    "arguments": {
                        "baseline_path": str(tmp_path / "mcp_ai_baseline.json"),
                        "patched_path": str(tmp_path / "mcp_ai_fast.json"),
                    },
                },
            }
        )["result"]["content"][0]["text"]
    )
    assert comp_mcp["rtt_reduction_pct"] > 50.0
    assert comp_mcp["bottleneck_resolved"] is True

    # Test Tool #6: ebpf_render_topology
    topo_mcp = json.loads(
        mcp.handle_jsonrpc(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "ebpf_render_topology", "arguments": {"format": "svg"}},
            }
        )["result"]["content"][0]["text"]
    )
    assert topo_mcp["svg_length"] > 100

    # Test all 10 REST API Server endpoints on ephemeral port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    rest_srv = tracer_agent.start_background_rest_server(
        host="127.0.0.1",
        port=port,
        mcp_gateway=mcp,
    )
    try:
        base_url = f"http://127.0.0.1:{port}"
        # 1. GET /
        with urllib.request.urlopen(f"{base_url}/", timeout=2.0) as r:
            root_html = r.read().decode("utf-8")
            assert "<svg" in root_html

        # 2. GET /api/v1/health
        with urllib.request.urlopen(f"{base_url}/api/v1/health", timeout=2.0) as r:
            health = json.loads(r.read().decode("utf-8"))
            assert "5.14.0-687.10.1.el9_8.0.1.aarch64" in health["target_kernel"]

        # 3. PUT /api/v1/config (0ms hot-reload)
        put_req = urllib.request.Request(
            f"{base_url}/api/v1/config",
            data=json.dumps({"pid": 7777, "port": 8081, "iface": "lo", "capture_enabled": True}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urllib.request.urlopen(put_req, timeout=2.0) as r:
            put_res = json.loads(r.read().decode("utf-8"))
            assert put_res["target_port"] == 8081
            assert put_res["config_epoch"] >= 2

        # 4. POST /api/v1/traces must complete in < 500ms without blocking
        t0 = time.monotonic()
        req = urllib.request.Request(
            f"{base_url}/api/v1/traces",
            data=json.dumps({"mode": "baseline"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2.0) as r:
            trace_res = json.loads(r.read().decode("utf-8"))
        elapsed_ms = (time.monotonic() - t0) * 1000.0
        assert elapsed_ms < 500.0, f"POST /api/v1/traces took {elapsed_ms:.1f}ms (> 500ms limit)"
        assert "req_id" in trace_res

        # 5. GET /api/v1/traces/latest
        with urllib.request.urlopen(f"{base_url}/api/v1/traces/latest", timeout=2.0) as r:
            latest_res = json.loads(r.read().decode("utf-8"))
            assert latest_res["req_id"] == trace_res["req_id"]

        # 6. GET /api/v1/network-layers?layer=sched&proto=tcp
        with urllib.request.urlopen(f"{base_url}/api/v1/network-layers?layer=sched&proto=tcp", timeout=2.0) as r:
            nl = json.loads(r.read().decode("utf-8"))
            assert nl["symmetric_io_verified"] is True
            assert nl["requested_layer_filter"] == "sched"
            assert nl["selected_layer"]["osi_layer"] == "L6_PRE_COMPUTE_SCHED_GATE"

        # 7. GET /api/v1/discovery
        with urllib.request.urlopen(f"{base_url}/api/v1/discovery", timeout=2.0) as r:
            disc = json.loads(r.read().decode("utf-8"))
            assert "port_protocol_inventory" in disc

        # 8. GET /api/v1/inspect?target=execute_storage_query
        with urllib.request.urlopen(f"{base_url}/api/v1/inspect?target=execute_storage_query", timeout=2.0) as r:
            insp = json.loads(r.read().decode("utf-8"))
            assert insp["target"] == "execute_storage_query"
            assert "execute_storage_query" in insp["source_code_evidence"]

        # 9. POST /api/v1/compare
        comp_req = urllib.request.Request(
            f"{base_url}/api/v1/compare",
            data=json.dumps(
                {
                    "baseline_path": str(tmp_path / "mcp_ai_baseline.json"),
                    "patched_path": str(tmp_path / "mcp_ai_fast.json"),
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(comp_req, timeout=2.0) as r:
            comp_http = json.loads(r.read().decode("utf-8"))
            assert comp_http["bottleneck_resolved"] is True

        # 10. POST /mcp (HTTP JSON-RPC 2.0 endpoint)
        mcp_http_req = urllib.request.Request(
            f"{base_url}/mcp",
            data=json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(mcp_http_req, timeout=2.0) as r:
            mcp_http_res = json.loads(r.read().decode("utf-8"))
            assert len(mcp_http_res["result"]["tools"]) == 6
    finally:
        rest_srv.shutdown()
        rest_srv.server_close()


# ==============================================================================
# TEST-12: 7-Layer Pre-Compute Matrix & Multi-Protocol / All-Port (0..65535)
# ==============================================================================
def test_12_seven_layer_precompute_matrix_and_multiproto_port_discovery(tmp_path: Path):
    """
    TEST-12: Verify all 7 layers (L2, L3, L4, SOCKET, SYSCALL, SCHED, L7) in
    network_layer_diagnostics, pure_on_cpu_compute_ms vs off_cpu_io_wait_ms split,
    --discover-ports (0..65535 classification), and --proto support.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()

    ai_json = tmp_path / "ai_7layer.json"
    tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "trace_7layer"),
        ai_report_path=str(ai_json),
        net_layer="sched",
        proto="udp",
    )

    diag = json.loads(ai_json.read_text(encoding="utf-8"))
    nld = diag["network_layer_diagnostics"]
    assert nld["symmetric_io_verified"] is True
    assert nld["c_harness_pipeline_verified"] is True
    assert nld["zero_templates_untouched"] is True
    assert nld["pre_compute_total_ms"] > 0.0
    assert nld["requested_layer_filter"] == "sched"
    assert nld["requested_proto_filter"] == "udp"

    layers = nld["layers"]
    for layer_key in ["L2", "L3", "L4", "SOCKET", "SYSCALL", "SCHED", "L7"]:
        assert layer_key in layers, f"Missing layer '{layer_key}' in network_layer_diagnostics"

    assert layers["L2"]["rx_pkt_bytes"] > 0 and layers["L2"]["tx_pkt_bytes"] > 0
    assert layers["SOCKET"]["rx_sock_dwell_ms"] > 0.0
    assert layers["SYSCALL"]["copy_to_user_bytes"] > 0
    assert layers["SYSCALL"]["storage_block_io_ms"] > 0.0
    assert layers["SCHED"]["runq_latency_ms"] > 0.0
    assert layers["SCHED"]["lock_wait_ms"] >= 0.0
    assert layers["SCHED"]["prev_cpu_id"] != layers["SCHED"]["target_cpu_id"]

    l7 = layers["L7"]
    assert l7["pure_on_cpu_compute_ms"] > 0.0
    assert l7["off_cpu_io_wait_ms"] > 0.0
    assert abs((l7["pure_on_cpu_compute_ms"] + l7["off_cpu_io_wait_ms"]) - l7["total_ms"]) < 0.05

    # Verify multi-port chain specification & wildcard port parsing
    assert tracer_agent.parse_port_spec("80,443,3000,5432,8080") == [80, 443, 3000, 5432, 8080]
    assert tracer_agent.parse_port_spec("all") == [0]
    assert tracer_agent.parse_port_spec("0") == [0]

    # Verify port discovery across 0..65535 and multi-protocol matrix
    inventory = tracer_agent.discover_ports_and_protocols()
    assert "port_protocol_inventory" in inventory
    inv = inventory["port_protocol_inventory"]
    assert "port_ranges" in inv
    for range_key in ["wildcard_0", "well_known_1_1023", "registered_1024_49151", "ephemeral_32768_65535"]:
        assert range_key in inv["port_ranges"]
        assert len(inv["port_ranges"][range_key]) >= 1

    for proto in ["tcp", "udp", "ipv4", "ipv6", "icmp", "arp", "unix", "tls"]:
        assert proto in inv["protocols"], f"Missing protocol '{proto}' in discovery inventory"
        assert len(inv["protocols"][proto]["hooks"]) >= 1


# ==============================================================================
# ADVANCED TEST SUITE (ADV-TEST-01 .. ADV-TEST-12)
# ==============================================================================
KERNEL_SIM_LIB = ROOT_DIR / ("libtracer_kernel_sim.dylib" if sys.platform == "darwin" else "libtracer_kernel_sim.so")


class SimKrayEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("req_id", ctypes.c_uint64),
        ("ip", ctypes.c_uint64),
        ("timestamp", ctypes.c_uint64),
        ("duration_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("parent_tid", ctypes.c_uint32),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("layer_type", ctypes.c_uint8),
        ("is_return", ctypes.c_uint8),
        ("call_depth", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("drop_count", ctypes.c_uint32),
    ]


class SimFlowKey(ctypes.Structure):
    _fields_ = [
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
        ("family", ctypes.c_uint8),
        ("pad", ctypes.c_uint16),
    ]


_SIM_LIB_INSTANCE = None


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _get_kernel_sim_lib():
    """Compile kernel_sim_harness.c (which includes tracer_kernel.c) and load via ctypes."""
    global _SIM_LIB_INSTANCE
    if _SIM_LIB_INSTANCE is not None and KERNEL_SIM_LIB.exists():
        return _SIM_LIB_INSTANCE

    cmd = ["clang", "-std=gnu11", "-O2", "-fPIC"]
    if sys.platform == "darwin":
        cmd.append("-dynamiclib")
    else:
        cmd.append("-shared")
    cmd.extend([str(ROOT_DIR / "kernel_sim_harness.c"), "-o", str(KERNEL_SIM_LIB)])
    subprocess.run(cmd, cwd=str(ROOT_DIR), check=True)

    lib = ctypes.CDLL(str(KERNEL_SIM_LIB))
    lib.sim_reset_all.argtypes = []
    lib.sim_reset_all.restype = None

    lib.sim_set_clock_ns.argtypes = [ctypes.c_uint64]
    lib.sim_set_clock_ns.restype = None

    lib.sim_set_context.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    lib.sim_set_context.restype = None

    lib.sim_set_ringbuf_full.argtypes = [ctypes.c_int]
    lib.sim_set_ringbuf_full.restype = None

    lib.sim_configure_runtime.argtypes = [ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint8, ctypes.c_uint64]
    lib.sim_configure_runtime.restype = None

    lib.sim_pending_events_count.argtypes = []
    lib.sim_pending_events_count.restype = ctypes.c_uint32

    lib.sim_pop_event.argtypes = [ctypes.POINTER(SimKrayEvent)]
    lib.sim_pop_event.restype = ctypes.c_int

    lib.sim_get_drop_count.argtypes = []
    lib.sim_get_drop_count.restype = ctypes.c_uint64

    lib.sim_has_active_ctx.argtypes = [ctypes.c_uint32]
    lib.sim_has_active_ctx.restype = ctypes.c_int

    lib.sim_get_tid_req_id.argtypes = [ctypes.c_uint32]
    lib.sim_get_tid_req_id.restype = ctypes.c_uint64

    lib.sim_verify_zero_templates_untouched.argtypes = []
    lib.sim_verify_zero_templates_untouched.restype = ctypes.c_int

    lib.sim_test_percpu_template_poisoning.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    lib.sim_test_percpu_template_poisoning.restype = ctypes.c_int

    lib.sim_test_map_capacity_and_flags.argtypes = []
    lib.sim_test_map_capacity_and_flags.restype = ctypes.c_int

    lib.sim_run_xdp_raw_frame.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]
    lib.sim_run_xdp_raw_frame.restype = ctypes.c_int

    lib.sim_tcp_v4_ingress_pipeline.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16,
        ctypes.c_uint8, ctypes.c_uint16, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    ]
    lib.sim_tcp_v4_ingress_pipeline.restype = ctypes.c_int

    lib.sim_tcp_recvmsg_call.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16,
        ctypes.c_int, ctypes.c_int,
    ]
    lib.sim_tcp_recvmsg_call.restype = ctypes.c_int

    lib.sim_skb_copy_and_faults.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.sim_skb_copy_and_faults.restype = ctypes.c_int

    lib.sim_sched_waking_and_switch.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint64, ctypes.c_uint64,
    ]
    lib.sim_sched_waking_and_switch.restype = ctypes.c_int

    lib.sim_uprobe_call.argtypes = [
        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int, ctypes.c_int,
    ]
    lib.sim_uprobe_call.restype = ctypes.c_int

    lib.sim_block_io_lifecycle.argtypes = [
        ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32,
    ]
    lib.sim_block_io_lifecycle.restype = ctypes.c_int

    lib.sim_tcp_egress_pipeline.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_int,
    ]
    lib.sim_tcp_egress_pipeline.restype = ctypes.c_int

    lib.sim_run_full_wire_to_code_pipeline.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16,
        ctypes.c_uint16, ctypes.c_uint16,
        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
        ctypes.c_uint64, ctypes.c_uint64,
        ctypes.c_int,
    ]
    lib.sim_run_full_wire_to_code_pipeline.restype = ctypes.c_int

    lib.sim_tcp_retransmit_skb_test.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16,
    ]
    lib.sim_tcp_retransmit_skb_test.restype = ctypes.c_int

    lib.sim_sched_process_fork_test.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    lib.sim_sched_process_fork_test.restype = ctypes.c_int

    lib.sim_ip6_output_test.argtypes = [
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16,
    ]
    lib.sim_ip6_output_test.restype = ctypes.c_int

    lib.sim_arp_rcv_test.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    lib.sim_arp_rcv_test.restype = ctypes.c_int

    lib.sim_icmp_rcv_test.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint16,
    ]
    lib.sim_icmp_rcv_test.restype = ctypes.c_int

    lib.sim_udp_unconnected_pipeline.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16,
    ]
    lib.sim_udp_unconnected_pipeline.restype = ctypes.c_int

    lib.sim_ipv6_tcp_pipeline.argtypes = [
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint16,
    ]
    lib.sim_ipv6_tcp_pipeline.restype = ctypes.c_int

    lib.sim_unix_stream_pipeline.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    lib.sim_unix_stream_pipeline.restype = ctypes.c_int

    lib.sim_kfree_skb_test.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_int, ctypes.c_int,
    ]
    lib.sim_kfree_skb_test.restype = ctypes.c_int

    lib.sim_dual_stack_sock_key_test.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(SimFlowKey),
    ]
    lib.sim_dual_stack_sock_key_test.restype = ctypes.c_int

    lib.sim_pure_ipv6_loopback4_sock_key_test.argtypes = [
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint16, ctypes.c_uint16, ctypes.POINTER(SimFlowKey),
    ]
    lib.sim_pure_ipv6_loopback4_sock_key_test.restype = ctypes.c_int

    lib.sim_publish_handoff_burst.argtypes = [
        ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_uint8,
    ]
    lib.sim_publish_handoff_burst.restype = ctypes.c_int

    lib.sim_claim_handoff_via_futex_exit.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint8]
    lib.sim_claim_handoff_via_futex_exit.restype = ctypes.c_int

    _SIM_LIB_INSTANCE = lib
    return lib


def _drain_sim_events(lib, tracer_agent):
    out = []
    raw = SimKrayEvent()
    while lib.sim_pop_event(ctypes.byref(raw)) == 1:
        ev = tracer_agent.KrayEvent.from_buffer_copy(bytes(raw))
        out.append(ev)
    return out


# ==============================================================================
# ADV-TEST-01: Native User-Space Emulation of tracer_kernel.c C Hooks
# ==============================================================================
def test_adv_01_native_c_kernel_hook_emulation():
    """
    ADV-TEST-01: Execute actual C hook functions compiled from tracer_kernel.c:
    - Focus Area 1: BPF_PERCPU_ARRAY zero_ctx_map & zero_ring_map read-only template integrity
      and per-CPU isolation against in-place mutation poisoning
    - Focus Area 2: bpf_map_update_elem / lookup capacity limits (max_entries, -E2BIG),
      true LRU eviction vs FIFO round-robin, and BPF_F_NO_EXIST (-EEXIST) / BPF_EXIST (-ENOENT) flags
    - Focus Area 3: Unified End-to-End Wire-to-Code pipeline wrapper -> RequestCorrelator -> Symbolicator
    - Real sys_enter_futex -> sched_waking -> sched_wakeup -> sched_switch lock_wait_ns without map-poking
    - 0-byte ACK non-overwrite when consumed == 0
    - sk_wait_data() delayed binding in kretprobe__tcp_recvmsg
    - [uprobes] trampoline IP restoration via fn_entry_ip[depth]
    - sys_exit_write non-deletion vs kretprobe__tcp_sendmsg context cleanup
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()
    lib = _get_kernel_sim_lib()

    # Focus Area 1: Verify per-CPU template poisoning detection & per-CPU slot isolation
    poison_rc = lib.sim_test_percpu_template_poisoning(0, 3)
    assert poison_rc == 0, f"Per-CPU template poisoning falsification failed with rc={poison_rc}"

    # Focus Area 2: Verify BPF map capacity (max_entries, -E2BIG), true LRU, and BPF_F_NO_EXIST / BPF_EXIST flags
    map_rc = lib.sim_test_map_capacity_and_flags()
    assert map_rc == 0, f"BPF map capacity & flags falsification failed with rc={map_rc}"

    lib.sim_reset_all()
    lib.sim_configure_runtime(5000, 8080, 1, 1)

    saddr = 0x0100007F
    daddr = 0x0100007F
    sport = 52100
    dport = 8080

    # 1. Run L2 (XDP + duplicate netif_receive_skb) + L3 (ip_rcv) + L4 (tcp_v4_rcv) with 128B payload
    lib.sim_set_context(5000, 5000, 0)
    lib.sim_tcp_v4_ingress_pipeline(saddr, daddr, sport, dport, 5, 128, 0, 1, 1, 0, 1, 1, 1, 1)
    evs_l2_l4 = _drain_sim_events(lib, tracer_agent)
    # XDP + netif_receive_skb deduplicated to 1 L2 event, plus L3 ip_rcv and L4 tcp_v4_rcv = 3 events
    assert len(evs_l2_l4) == 3, f"Expected 3 ingress events (L2 dedup + L3 + L4), got {len(evs_l2_l4)}"
    orig_req_id = evs_l2_l4[0].req_id
    assert orig_req_id != 0
    assert all(e.req_id == orig_req_id for e in evs_l2_l4)

    # 2. Send a 0-byte pure ACK on the same 4-tuple BEFORE tcp_recvmsg consumes it:
    #    must NOT mint a new req_id!
    lib.sim_tcp_v4_ingress_pipeline(saddr, daddr, sport, dport, 5, 0, 0, 1, 0, 0, 1, 0, 1, 1)
    ack_evs = _drain_sim_events(lib, tracer_agent)
    assert all(e.req_id == orig_req_id for e in ack_evs), "0-byte ACK overwrote unconsumed req_id!"

    # 3. Consume via kprobe__tcp_recvmsg on acceptor thread (tid=5000)
    lib.sim_set_context(5000, 5000, 0)
    lib.sim_tcp_recvmsg_call(saddr, daddr, sport, dport, 128, 0)
    assert lib.sim_get_tid_req_id(5000) == orig_req_id

    # 4. Verify sk_wait_data() delayed binding on a second connection (sport=52101)
    #    where tcp_recvmsg is entered BEFORE the packet arrives!
    lib.sim_set_context(5000, 5001, 1)
    lib.sim_tcp_recvmsg_call(saddr, daddr, 52101, dport, 256, 1)
    delayed_req_id = lib.sim_get_tid_req_id(5001)
    assert delayed_req_id != 0 and delayed_req_id != orig_req_id

    # 5. Continue first request: L5 skb_copy_datagram_iovec + 3 page faults
    lib.sim_set_context(5000, 5000, 0)
    lib.sim_skb_copy_and_faults(128, 3)

    # 6. Hand off from acceptor (tid=5000, cpu=0) to worker (tid=5010, cpu=3)
    #    via real sys_enter_futex -> sched_waking -> sched_wakeup -> sched_switch!
    lib.sim_sched_waking_and_switch(5000, 5010, 5000, 0, 3, 45000, 20000)
    assert lib.sim_get_tid_req_id(5010) == orig_req_id

    # 7. Nested uprobe/uretprobe on worker (tid=5010) with [uprobes] trampoline IP corruption (0x7fffffffe000)
    lib.sim_set_context(5000, 5010, 3)
    lib.sim_uprobe_call(0x401140, 0x7FFFFFFFE000, 50000, 1, 0)  # depth 0 entry
    lib.sim_uprobe_call(0x401280, 0x7FFFFFFFE000, 30000, 1, 1)  # depth 1 entry + return
    # Trigger Block I/O completing on IRQ thread (tid=9999) while worker is in depth 0
    lib.sim_block_io_lifecycle(259, 4096, 8, 5000, 80000, 9999)
    lib.sim_uprobe_call(0x401140, 0x7FFFFFFFE000, 10000, 0, 1)  # depth 0 return

    # 8. Egress pipeline (testing PT_REGS_PARM2 fallback in kprobe__ip_output + kretprobe__tcp_sendmsg cleanup)
    assert lib.sim_has_active_ctx(5010) == 1
    lib.sim_tcp_egress_pipeline(daddr, saddr, dport, sport, 64, 1)
    assert lib.sim_has_active_ctx(5010) == 0, "kretprobe__tcp_sendmsg must clean up active_ctx_map[&tid]"

    # Verify zero_ctx_map and zero_ring_map templates are 100% zero across all CPUs after hook execution
    assert lib.sim_verify_zero_templates_untouched() == 1, "zero_ctx_map or zero_ring_map was mutated in-place!"

    all_evs = evs_l2_l4 + _drain_sim_events(lib, tracer_agent)
    req1_evs = [e for e in all_evs if e.req_id == orig_req_id]
    layers_seen = {int(e.layer_type) for e in req1_evs}
    assert layers_seen == {1, 2, 3, 4, 5, 6}, f"Expected all 6 macro layers from C hooks, got {layers_seen}"

    # Verify real lock_wait_ns (45000 ns) and runq_or_off_cpu_ns (20000 ns) from sys_enter_futex -> sched_switch
    l6_evs = [e for e in req1_evs if e.layer_type == 3 and e.call_depth == 8]
    assert len(l6_evs) >= 1
    l6_meta = tracer_agent.decode_event_metadata(l6_evs[0])
    assert l6_meta["lock_wait_ns"] == 45000, f"Expected lock_wait_ns=45000, got {l6_meta['lock_wait_ns']}"
    assert l6_meta["runq_or_off_cpu_ns"] == 20000, f"Expected runq=20000, got {l6_meta['runq_or_off_cpu_ns']}"
    assert l6_meta["prev_cpu_id"] == 0 and l6_meta["target_cpu_id"] == 3

    # Verify Egress L3/L4 bit-packed TTL=64 and IHL=20 in decode_event_metadata
    egress_l3_l4 = [e for e in req1_evs if e.layer_type == 6 and e.call_depth in (3, 4)]
    assert len(egress_l3_l4) >= 2
    for eg_ev in egress_l3_l4:
        eg_meta = tracer_agent.decode_event_metadata(eg_ev)
        assert eg_meta["ttl"] == 64 and eg_meta["ihl_bytes"] == 20 and eg_meta["pkt_len"] == 64

    # Verify uretprobe events restored original entry IPs (0x401140, 0x401280) instead of 0x7FFFFFFFE000
    uret_evs = [e for e in req1_evs if e.layer_type == 4 and e.is_return == 1]
    assert len(uret_evs) == 2
    assert {e.ip for e in uret_evs} == {0x401140, 0x401280}

    # 9. Focus Area 3: Verify Unified End-to-End Wire-to-Code C Pipeline -> RequestCorrelator -> Symbolicator
    e2e_res = tracer_agent.run_c_harness_wire_to_code_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        fast_mode=False,
    )
    assert e2e_res["trace_count"] == 1
    assert e2e_res["zero_templates_untouched"] is True
    assert e2e_res["layers_seen"] == [1, 2, 3, 4, 5, 6]
    assert e2e_res["osi_sublayers_seen"] == [2, 3, 4, 5, 6, 7, 8]
    sym_fns = e2e_res["symbolicated_functions"]
    assert len(sym_fns) == 5
    assert sym_fns[0]["symbol_or_probe"] == "parse_http_request" and sym_fns[0]["stripped"] is False
    assert sym_fns[1]["symbol_or_probe"] == "validate_auth_header" and sym_fns[1]["stripped"] is False
    assert sym_fns[2]["symbol_or_probe"].startswith("libcrypto_mock.so+0x") and sym_fns[2]["stripped"] is True
    assert sym_fns[3]["symbol_or_probe"] == "execute_storage_query" and sym_fns[3]["tid"] == 10425 and sym_fns[3]["parent_tid"] == 10420
    assert abs(sym_fns[3]["on_cpu_ms"] - 17.250) < 0.01 and abs(sym_fns[3]["off_cpu_ms"] - 4.275) < 0.01
    assert sym_fns[4]["symbol_or_probe"] == "format_http_response"


# ==============================================================================
# ADV-TEST-02: Rocky Linux 9.8 vmlinux.h CO-RE Cross-Compilation Test
# ==============================================================================
def test_adv_02_rocky98_vmlinux_btf_cross_compilation(tmp_path: Path):
    """
    ADV-TEST-02: Compile tracer_kernel.c directly against the Rocky Linux 9.8
    (5.14.0-687.10.1.el9_8.0.1.aarch64) vmlinux.h and bpf/*.h headers into an
    aarch64 ELF object and verify all tracepoint and kprobe sections/symbols.
    """
    obj_out = tmp_path / "tracer_kernel_rocky98.o"
    btf_inc = REF_BASE_DIR / "rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1" / "btf-and-headers"
    assert (btf_inc / "vmlinux.h").exists(), "Missing Rocky 9.8 vmlinux.h"

    cmd = [
        "clang",
        "-target", "aarch64-linux-gnu",
        "-std=gnu11",
        "-DKRAY_BPF_CORE",
        "-O2",
        "-Wno-unknown-attributes",
        f"-I{ROOT_DIR}",
        f"-I{btf_inc}",
        "-c", str(ROOT_DIR / "tracer_kernel.c"),
        "-o", str(obj_out),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Rocky 9.8 vmlinux.h compilation failed:\n{res.stderr}"
    assert obj_out.exists() and obj_out.stat().st_size > 8192

    # Inspect ELF sections via objdump -h
    sec_out = subprocess.check_output(["/usr/bin/objdump", "-h", str(obj_out)], text=True)
    required_sections = [
        "tp/net/netif_receive_skb",
        "tp/tcp/tcp_retransmit_skb",
        "tp/skb/kfree_skb",
        "tp/skb/skb_copy_datagram_iovec",
        "tp/syscalls/sys_enter_futex",
        "tp/syscalls/sys_exit_futex",
        "tp/sched/sched_waking",
        "tp/sched/sched_switch",
        "tp/block/block_rq_insert",
        "tp/block/block_rq_issue",
        "tp/block/block_rq_complete",
        "tp/net/net_dev_queue",
        "tp/net/net_dev_xmit",
        ".maps",
        "license",
    ]
    for sec in required_sections:
        assert sec in sec_out, f"Missing ELF section '{sec}' in compiled Rocky 9.8 object"


# ==============================================================================
# ADV-TEST-03: eBPF Verifier Static Limits (Stack <= 512B, Loops, Null-Guards)
# ==============================================================================
def test_adv_03_ebpf_verifier_stack_512b_loop_and_null_guards(tmp_path: Path):
    """
    ADV-TEST-03: Enforce eBPF Verifier constraints:
    1. Every hook function stack frame <= 320 bytes (strictly under 512B BPF limit)
       enforced via clang -Wframe-larger-than=320 -Werror=frame-larger-than=
    2. All loops in tracer_kernel.c preceded by #pragma unroll
    3. Zero stack allocations of struct tid_ctx_t or struct handoff_ring_t
    """
    obj_out = tmp_path / "verifier_stack_check.o"
    btf_inc = REF_BASE_DIR / "rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1" / "btf-and-headers"

    cmd = [
        "clang",
        "-target", "aarch64-linux-gnu",
        "-std=gnu11",
        "-DKRAY_BPF_CORE",
        "-O2",
        "-Wno-unknown-attributes",
        "-Wframe-larger-than=320",
        "-Werror=frame-larger-than=",
        f"-I{ROOT_DIR}",
        f"-I{btf_inc}",
        "-c", str(ROOT_DIR / "tracer_kernel.c"),
        "-o", str(obj_out),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"BPF Stack Frame > 320B limit violated:\n{res.stderr}"

    src = (ROOT_DIR / "tracer_kernel.c").read_text(encoding="utf-8")
    # Ensure no stack instances of tid_ctx_t or handoff_ring_t exist
    assert not re.search(r"struct\s+tid_ctx_t\s+\w+\s*=", src), "Stack allocation of struct tid_ctx_t detected!"
    assert not re.search(r"struct\s+handoff_ring_t\s+\w+\s*=", src), "Stack allocation of struct handoff_ring_t detected!"
    assert "BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)" in src
    assert "BPF_PERCPU_ARRAY(zero_ring_map, struct handoff_ring_t, 1)" in src

    # Ensure every 'for (' loop in tracer_kernel.c has #pragma unroll immediately above it
    lines = src.splitlines()
    for idx, line in enumerate(lines):
        if re.search(r"\bfor\s*\(", line):
            prev_window = "\n".join(lines[max(0, idx - 3):idx])
            assert "#pragma unroll" in prev_window, f"Unbounded loop without #pragma unroll at line {idx + 1}"


# ==============================================================================
# ADV-TEST-04: Synthetic Raw Packet Byte Frames & Multi-Protocol Fuzzing
# ==============================================================================
def test_adv_04_synthetic_raw_packet_vlan_ipv6_arp_and_malformed_fuzzing():
    """
    ADV-TEST-04: Synthesize raw wire packet bytes (Single VLAN 802.1Q, Double QinQ 802.1AD,
    IPv4 options ihl=8, truncated/malformed headers) + execute C hooks for IPv6, Dual-Stack
    ::ffff:, Unconnected UDP, ICMP, ARP, AF_UNIX, tcp_retransmit_skb, sched_process_fork,
    ip6_output, and kfree_skb 3-stage drop resolution (Stages 1, 2, and 3).
    """
    tracer_agent = _import_tracer_agent()
    lib = _get_kernel_sim_lib()
    lib.sim_reset_all()
    lib.sim_configure_runtime(0, 8080, 1, 1)

    # Helper to invoke XDP with raw bytes
    def run_xdp_bytes(raw_bytes: bytes) -> int:
        arr = (ctypes.c_uint8 * len(raw_bytes)).from_buffer_copy(raw_bytes)
        return lib.sim_run_xdp_raw_frame(arr, len(raw_bytes))

    # 1. Malformed / truncated packet fuzzing: must all return XDP_PASS (2) and emit 0 events
    malformed_frames = [
        b"\x00" * 5,  # Shorter than Ethernet header (< 14B)
        b"\x00" * 12 + struct.pack("!H", 0x8100) + b"\x00" * 2,  # Truncated 802.1Q VLAN header
        b"\x00" * 12 + struct.pack("!H", 0x0800) + b"\x45\x00\x00\x28" + b"\x00" * 6,  # Truncated IPv4 header
        # Forged IPv4 ihl=2 (< 20B minimum header length)
        b"\x00" * 12 + struct.pack("!H", 0x0800) + b"\x42\x00\x00\x28" + b"\x00" * 36,
        # Forged IPv4 ihl=15 (60B options exceeding packet end)
        b"\x00" * 12 + struct.pack("!H", 0x0800) + b"\x4f\x00\x00\x3c" + b"\x00" * 24,
        # Valid IPv4 header but truncated TCP header (< 20B)
        b"\x00" * 12 + struct.pack("!H", 0x0800) + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01") + b"\x00" * 8,
    ]
    for frame in malformed_frames:
        rc = run_xdp_bytes(frame)
        assert rc == 2  # XDP_PASS
    assert lib.sim_pending_events_count() == 0, "Malformed frames must not emit events!"

    # 2. Single VLAN 802.1Q (0x8100) + Double QinQ 802.1AD (0x88A8 -> 0x8100) + IPv4 Options (ihl=8, 32B)
    eth_dst_src = b"\xaa\xbb\xcc\xdd\xee\xff" * 2
    qinq_tag = struct.pack("!HHHHH", 0x88A8, 100, 0x8100, 200, 0x0800)
    # IPv4 ihl=8 (32 bytes = 20B base + 12B options), tot_len = 32 + 20 + 16 = 68
    ip_hdr_opts = struct.pack("!BBHHHBBH4s4s", 0x48, 0, 68, 1, 0, 64, 6, 0, b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x01") + (b"\x01" * 12)
    tcp_hdr = struct.pack("!HHIIBBHHH", 53000, 8080, 1, 1, (5 << 4), 0x18, 65535, 0, 0)
    payload = b"GET /qinq HTTP/1.1"
    qinq_frame = eth_dst_src + qinq_tag + ip_hdr_opts + tcp_hdr + payload

    assert run_xdp_bytes(qinq_frame) == 2
    qinq_evs = _drain_sim_events(lib, tracer_agent)
    assert len(qinq_evs) == 1
    assert qinq_evs[0].src_port == 53000 and qinq_evs[0].dst_port == 8080
    qinq_meta = tracer_agent.decode_event_metadata(qinq_evs[0])
    assert qinq_meta["vlan_id"] == 200, f"Expected inner 802.1Q VLAN ID 200, got {qinq_meta['vlan_id']}"

    # 3. Execute C hooks for ARP, ICMP, Unconnected UDP, IPv6, Dual-Stack ::ffff:, AF_UNIX, and kfree_skb
    lib.sim_arp_rcv_test(0x0101A8C0, 0xFE01A8C0)
    arp_ev = _drain_sim_events(lib, tracer_agent)[0]
    assert arp_ev.src_ip == 0x0101A8C0 and arp_ev.dst_ip == 0xFE01A8C0

    lib.sim_icmp_rcv_test(0x0100007F, 0x0100007F, 8, 0, 0x4321)
    icmp_ev = _drain_sim_events(lib, tracer_agent)[0]
    assert icmp_ev.src_port == (8 << 8) and icmp_ev.dst_port == 0x4321

    lib.sim_set_context(6000, 6000, 1)
    lib.sim_udp_unconnected_pipeline(0x0200007F, 0x0100007F, 55111, 8080, 48)
    udp_evs = _drain_sim_events(lib, tracer_agent)
    assert len(udp_evs) == 3  # udp_rcv + kretprobe__udp_recvmsg + udp_sendmsg
    assert udp_evs[0].req_id == udp_evs[1].req_id == udp_evs[2].req_id
    # Finding 5 check: unconnected UDP sendmsg MUST preserve client peer IP (0x0200007F) and port (55111)!
    assert udp_evs[2].dst_ip == 0x0200007F and udp_evs[2].dst_port == 55111
    assert udp_evs[2].src_ip == 0x0100007F and udp_evs[2].src_port == 8080

    # Verify sched_process_fork propagates req_id and parent_tid from parent (6000) to child (6005)
    lib.sim_sched_process_fork_test(6000, 6005)
    assert lib.sim_get_tid_req_id(6005) == udp_evs[0].req_id

    s6 = (ctypes.c_uint32 * 4)(0x20010DB8, 0x00000000, 0x00000000, 0x00000001)
    d6 = (ctypes.c_uint32 * 4)(0x20010DB8, 0x00000000, 0x00000000, 0x00000002)
    lib.sim_ipv6_tcp_pipeline(s6, d6, 56000, 8080, 96)
    v6_evs = _drain_sim_events(lib, tracer_agent)
    assert len(v6_evs) == 2 and v6_evs[0].req_id == v6_evs[1].req_id
    assert v6_evs[0].src_ip == (0x20010DB8 ^ 1) and v6_evs[0].dst_ip == (0x20010DB8 ^ 2)
    v6_meta = tracer_agent.decode_event_metadata(v6_evs[1])
    assert v6_meta["ttl"] == 64 and v6_meta["ihl_bytes"] == 40 and v6_meta["pkt_len"] == 96

    # Verify kprobe__ip6_output (Finding 7)
    lib.sim_ip6_output_test(d6, s6, 8080, 56000, 120)
    ip6_out_evs = _drain_sim_events(lib, tracer_agent)
    assert len(ip6_out_evs) == 1 and ip6_out_evs[0].req_id == 0x66001122
    ip6_out_meta = tracer_agent.decode_event_metadata(ip6_out_evs[0])
    assert ip6_out_meta["ttl"] == 64 and ip6_out_meta["ihl_bytes"] == 40 and ip6_out_meta["pkt_len"] == 120

    # Dual-Stack ::ffff:127.0.0.1 normalization test (AF_INET6 + skc_daddr != 0 -> AF_INET = 2)
    ds_key = SimFlowKey()
    lib.sim_dual_stack_sock_key_test(0x0100007F, 0x0100007F, 57000, 8080, ctypes.byref(ds_key))
    assert ds_key.family == 2, f"Expected AF_INET (2) for Dual-Stack ::ffff: socket, got {ds_key.family}"

    # Pure IPv6 socket with Rocky 9.8 LOOPBACK4_IPV6 (htonl(0x7f000006)) in skc_daddr -> must remain AF_INET6 (10)!
    v6_loop_key = SimFlowKey()
    lib.sim_pure_ipv6_loopback4_sock_key_test(s6, d6, 56000, 8080, ctypes.byref(v6_loop_key))
    assert v6_loop_key.family == 10, f"Expected AF_INET6 (10) for Pure IPv6 with LOOPBACK4_IPV6, got {v6_loop_key.family}"
    assert v6_loop_key.saddr == (0x20010DB8 ^ 1) and v6_loop_key.daddr == (0x20010DB8 ^ 2)

    # AF_UNIX sendmsg -> recvmsg pointer correlation
    lib.sim_unix_stream_pipeline(0x1000, 0x2000)
    unix_evs = _drain_sim_events(lib, tracer_agent)
    assert len(unix_evs) == 1 and unix_evs[0].req_id != 0

    # Verify tcp_retransmit_skb (Finding 7) and kfree_skb Stages 1, 2, and 3
    lib.sim_tcp_v4_ingress_pipeline(0x0100007F, 0x0100007F, 58000, 8080, 5, 64, 0, 1, 1, 0, 1, 0, 1, 1)
    _drain_sim_events(lib, tracer_agent)
    lib.sim_tcp_retransmit_skb_test(0x0100007F, 0x0100007F, 58000, 8080)
    retx_evs = _drain_sim_events(lib, tracer_agent)
    assert len(retx_evs) == 1 and (retx_evs[0].flags & tracer_agent.FLAG_TCP_RETRANSMIT) != 0
    retx_meta = tracer_agent.decode_event_metadata(retx_evs[0])
    assert retx_meta["retransmit_count"] == 1

    lib.sim_kfree_skb_test(0x0100007F, 0x0100007F, 58000, 8080, 1, 2)  # reason=1 ignored
    assert lib.sim_pending_events_count() == 0
    lib.sim_kfree_skb_test(0x0100007F, 0x0100007F, 58000, 8080, 4, 1)  # Stage 1 skb_egress_map drop
    lib.sim_kfree_skb_test(0x0100007F, 0x0100007F, 58000, 8080, 5, 2)  # Stage 2 rx_sk drop
    lib.sim_kfree_skb_test(0x0100007F, 0x0100007F, 58000, 8080, 7, 3)  # Stage 3 skb->head drop
    drop_evs = _drain_sim_events(lib, tracer_agent)
    assert len(drop_evs) == 3
    assert all((e.flags & tracer_agent.FLAG_SKB_DROP) != 0 for e in drop_evs)
    assert [tracer_agent.decode_event_metadata(e)["skb_drop_reason"] for e in drop_evs] == [4, 5, 7]


# ==============================================================================
# ADV-TEST-05: Stateful Chaos & Property-Based Fuzzing of RequestCorrelator
# ==============================================================================
def test_adv_05_state_machine_chaos_and_property_based_fuzzing():
    """
    ADV-TEST-05: Feed 250 interleaved requests (~2,000 events) with randomized
    multi-core timestamp inversions, missing egress events, packet drops, and
    deep call_depth values into RequestCorrelator and verify lineage invariants.
    """
    tracer_agent = _import_tracer_agent()
    rng = random.Random(20261030)
    correlator = tracer_agent.RequestCorrelator(grace_window_ms=50.0)

    chaos_events = []
    expected_req_ids = set()

    for i in range(250):
        req_id = 0xC00000 + i
        expected_req_ids.add(req_id)
        base_ts = 1_000_000_000 + i * 100_000
        sport = 30000 + (i % 20000)

        # Generate 6-8 hops per request with intentional timestamp jitter
        layers = [
            (1, 2, 0),
            (2, 3, 0),
            (2, 4, 0),
            (3, 5, 0),
            (3, 8, 0),
            (4, rng.randint(0, 31), 0),
            (4, rng.randint(0, 31), 1),
            (5, 5, 0),
        ]
        # 80% of requests get LAYER_EGRESS_NIC (6, 2); 20% simulate dropped/aborted connections
        if i % 5 != 0:
            layers.append((6, 2, 0))

        for step_idx, (ltype, cdepth, is_ret) in enumerate(layers):
            jitter = rng.randint(-5_000, 5_000)
            ev = tracer_agent.KrayEvent(
                req_id=req_id,
                ip=0x401000 + step_idx * 4,
                timestamp=max(1, base_ts + step_idx * 10_000 + jitter),
                duration_ns=rng.randint(100, 500_000),
                pid=9000,
                tid=9000 + (i % 16),
                parent_tid=9000 if ltype >= 4 else 0,
                src_ip=0x0100007F,
                dst_ip=0x0100007F,
                src_port=sport,
                dst_port=8080,
                layer_type=ltype,
                is_return=is_ret,
                call_depth=cdepth,
                flags=0,
                drop_count=0,
            )
            chaos_events.append(ev)

    # Shuffle all ~2,000 events across all 250 requests to simulate multi-CPU out-of-order arrival
    rng.shuffle(chaos_events)
    for ev in chaos_events:
        correlator.ingest(ev)
        # Also verify decode_event_metadata never crashes on any fuzzed event
        meta = tracer_agent.decode_event_metadata(ev)
        assert "osi_layer_id" in meta

    # Flush expired requests (simulating +300ms elapsed)
    correlator.flush_expired(current_ts_ns=3_000_000_000)
    completed = correlator.get_completed_traces()
    assert len(completed) == 250, f"Expected all 250 chaos requests finalized, got {len(completed)}"

    for req_id, trace in completed.items():
        assert all(int(e.req_id) == req_id for e in trace), f"Cross-talk detected in req_id {req_id:#x}"
        sort_keys = [(int(e.layer_type), int(e.timestamp), int(e.is_return)) for e in trace]
        assert sort_keys == sorted(sort_keys), f"Canonical ordering violated in req_id {req_id:#x}"


# ==============================================================================
# ADV-TEST-06: 8-Slot Handoff Ring Contention & Wraparound Simulation
# ==============================================================================
def test_adv_06_eight_slot_handoff_ring_contention_and_wraparound():
    """
    ADV-TEST-06: Exercise the 8-slot per-TGID handoff_ring_t in tracer_kernel.c
    across 24 consecutive requests (3 full ring wraparounds of write_idx & 7 and
    read_idx & 7) and verify strict FIFO worker assignment and self-claim protection.
    """
    tracer_agent = _import_tracer_agent()
    lib = _get_kernel_sim_lib()
    lib.sim_reset_all()
    lib.sim_configure_runtime(7000, 8080, 1, 1)

    tgid = 7000
    waker_tid = 7000
    claimed_req_ids = []

    # Run 3 batches of 8 concurrent handoffs (24 total -> wraps 8-slot ring 3 times)
    for batch in range(3):
        batch_expected = []
        for slot in range(8):
            req_id = 0xB00000 + batch * 100 + slot
            batch_expected.append(req_id)
            lib.sim_publish_handoff_burst(tgid, req_id, waker_tid, 40000 + slot, 8080, slot % 4)

        # Verify waker_tid (7000) cannot claim its own handoff slot!
        lib.sim_claim_handoff_via_futex_exit(tgid, waker_tid, 0)
        assert lib.sim_get_tid_req_id(waker_tid) == 0

        # Now 8 worker threads (7100..7107) claim via sys_exit_futex or trace_uprobe_entry
        for slot in range(8):
            worker_tid = 7100 + batch * 10 + slot
            if slot % 2 == 0:
                lib.sim_claim_handoff_via_futex_exit(tgid, worker_tid, (slot + 1) % 4)
            else:
                lib.sim_set_context(tgid, worker_tid, (slot + 1) % 4)
                lib.sim_uprobe_call(0x402000 + slot * 4, 0x402000 + slot * 4, 1000, 1, 1)
            got_req = lib.sim_get_tid_req_id(worker_tid)
            claimed_req_ids.append(got_req)

        assert claimed_req_ids[-8:] == batch_expected, (
            f"Batch {batch} 8-slot ring FIFO mismatch: {claimed_req_ids[-8:]} != {batch_expected}"
        )

    assert len(claimed_req_ids) == 24
    _drain_sim_events(lib, tracer_agent)


# ==============================================================================
# ADV-TEST-07: ELF / DWARF / PIE ASLR & aarch64 64KB Page Symbolication Stress
# ==============================================================================
def test_adv_07_elf_dwarf_pie_aslr_and_aarch64_64kb_symbolication():
    """
    ADV-TEST-07: Stress-test BinarySymbolicator across multi-module /proc/<PID>/maps
    with randomized PIE ASLR bases, aarch64 64KB PT_LOAD alignment (p_vaddr != p_offset),
    and C++ mangled symbol filtering up to MAX_AUTO_UPROBES = 64.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()
    sym = tracer_agent.BinarySymbolicator(str(MOCK_SERVER_BIN), str(LIBCRYPTO_SO))

    maps_text = """
55a4b2c00000-55a4b2c04000 r--p 00000000 103:02 101 /opt/app/mock_server
55a4b2c04000-55a4b2c20000 r-xp 00004000 103:02 101 /opt/app/mock_server
7fb8c0000000-7fb8c0001000 r--p 00000000 103:02 202 /opt/app/libcrypto_mock.so
7fb8c0010000-7fb8c0025000 r-xp 00001000 103:02 202 /opt/app/libcrypto_mock.so
7fb8d0000000-7fb8d0180000 r-xp 00020000 103:02 303 /usr/lib64/libc.so.6
"""
    segs = sym.parse_proc_maps(maps_text)
    assert len(segs) == 3

    # Verify aarch64 64KB page alignment offset math: st_value=0x11480, p_vaddr=0x11000, p_offset=0x1000 -> 0x1480
    uprobe_off = tracer_agent.compute_uprobe_file_offset(0x11480, 0x11000, 0x1000)
    assert uprobe_off == 0x1480

    # Resolve PIE main binary symbol via Tier 1 symbol table
    sym_table = {("mock_server", 0x5240): "execute_storage_query(std::string const&)"}
    r1 = sym.resolve_runtime_ip(0x55A4B2C05240, segs, symbol_table=sym_table)
    assert r1["symbol"] == "execute_storage_query(std::string const&)"
    assert r1["stripped"] is False
    assert r1["rel_offset"] == 0x5240

    # Resolve stripped shared library offset via Tier 3 fallback
    r2 = sym.resolve_runtime_ip(0x7FB8C0010140, segs, symbol_table=sym_table)
    assert r2["symbol"] == "libcrypto_mock.so+0x1140"
    assert r2["stripped"] is True
    assert (r2["flags"] & tracer_agent.FLAG_STRIPPED_SYMBOL) != 0

    # Stress-test select_auto_uprobe_targets with 150 symbols (valid + STL noise)
    candidates = (
        [(f"_ZSt14_Function_base_{i}", 64) for i in range(40)]
        + [(f"__cxa_throw_{i}", 48) for i in range(20)]
        + [(f"tiny_thunk_{i}", 8) for i in range(20)]
        + [(f"app_business_handler_{i}", 128) for i in range(100)]
    )
    selected = sym.select_auto_uprobe_targets(candidates)
    assert len(selected) == 64  # Strictly capped at MAX_AUTO_UPROBES = 64
    assert all(s.startswith("app_business_handler_") for s in selected)

    # Verify deep recursion (> 16 frames, e.g., 20 nested uprobe calls) never overwrites root frame slot 0!
    lib = _get_kernel_sim_lib()
    lib.sim_reset_all()
    lib.sim_configure_runtime(8800, 8080, 1, 1)
    lib.sim_set_context(8800, 8800, 0)
    lib.sim_tcp_v4_ingress_pipeline(0x0100007F, 0x0100007F, 59900, 8080, 5, 64, 0, 1, 1, 0, 1, 0, 1, 1)
    lib.sim_tcp_recvmsg_call(0x0100007F, 0x0100007F, 59900, 8080, 64, 0)
    _drain_sim_events(lib, tracer_agent)
    for depth_i in range(20):
        lib.sim_uprobe_call(0x401000 + depth_i * 0x10, 0x7FFFFFFFE000, 1000, 1, 0)
    for depth_i in reversed(range(20)):
        lib.sim_uprobe_call(0x401000 + depth_i * 0x10, 0x7FFFFFFFE000, 1000, 0, 1)
    rec_evs = _drain_sim_events(lib, tracer_agent)
    root_return = rec_evs[-1]
    assert root_return.is_return == 1 and root_return.call_depth == 0
    assert root_return.ip == 0x401000, f"Root frame IP overwritten by depth >= 16 wrap-around: {root_return.ip:#x}"


# ==============================================================================
# ADV-TEST-08: Negative Fault-Injection & Boundary Guard Testing
# ==============================================================================
def test_adv_08_negative_fault_injection_and_boundary_guards(tmp_path: Path):
    """
    ADV-TEST-08: Verify resilience under fault injection and extreme boundaries:
    1. RingBuf 100% saturation (sim_set_ringbuf_full(1) -> 0 events, drop_cnt_map[0] == 15)
    2. Mid-execution attach orphan uretprobe (call_depth == 0 underflow guard)
    3. 32-bit lock_wait_ns overflow (> 4.29s capped to 0xFFFFFFFF without truncation)
    4. Invalid ports, unmapped IPs, corrupted paths, and malformed REST/MCP JSON payloads
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()
    lib = _get_kernel_sim_lib()
    lib.sim_reset_all()
    lib.sim_configure_runtime(8000, 8080, 1, 1)

    # 1. RingBuf 100% saturation fault injection
    lib.sim_set_ringbuf_full(1)
    for i in range(5):
        lib.sim_tcp_v4_ingress_pipeline(0x0100007F, 0x0100007F, 60000 + i, 8080, 5, 64, 0, 1, 1, 0, 1, 0, 1, 1)
    assert lib.sim_pending_events_count() == 0, "No events can be queued when RingBuf is 100% full"
    bpf_drops = lib.sim_get_drop_count()
    assert bpf_drops == 15, f"Expected 15 dropped events in drop_cnt_map[0], got {bpf_drops}"
    assert tracer_agent.compute_final_drop_count(0, bpf_drops, 0) == 15
    lib.sim_set_ringbuf_full(0)

    # 2. Mid-execution attach: orphan uretprobe when call_depth == 0
    lib.sim_set_context(8000, 8000, 0)
    lib.sim_tcp_v4_ingress_pipeline(0x0100007F, 0x0100007F, 60100, 8080, 5, 64, 0, 1, 1, 0, 1, 0, 1, 1)
    lib.sim_tcp_recvmsg_call(0x0100007F, 0x0100007F, 60100, 8080, 64, 0)
    _drain_sim_events(lib, tracer_agent)
    # Trigger return WITHOUT entry (call_depth is 0)
    lib.sim_uprobe_call(0x401000, 0x7FFFFFFFE000, 5000, 0, 1)
    assert lib.sim_pending_events_count() == 0, "Orphan uretprobe at call_depth==0 must be ignored!"

    # 3. 32-bit lock_wait_ns cap (> 4.29s = 10,000,000,000 ns -> capped to 0xFFFFFFFF)
    lib.sim_sched_waking_and_switch(8000, 8001, 8000, 0, 2, 10_000_000_000, 50_000)
    sched_ev = _drain_sim_events(lib, tracer_agent)[0]
    decoded = tracer_agent.decode_event_metadata(sched_ev)
    assert decoded["lock_wait_ns"] == 0xFFFFFFFF, (
        f"Expected 32-bit saturation cap 0xFFFFFFFF, got {decoded['lock_wait_ns']:#x}"
    )

    # 4. Port parser & REST/MCP negative input validation
    for bad_port in ["-1", "65536", "70000", "not_a_port"]:
        try:
            tracer_agent.parse_port_spec(bad_port)
            raise AssertionError(f"parse_port_spec should have rejected '{bad_port}'")
        except ValueError:
            pass

    sym = tracer_agent.BinarySymbolicator("/nonexistent/binary", "/nonexistent/lib.so")
    unmapped = sym.resolve_runtime_ip(0xDEADBEEF, [])
    assert unmapped["symbol"] == "unknown+0xdeadbeef" and unmapped["stripped"] is True

    gw = tracer_agent.MCPGatewayServer(str(MOCK_SERVER_BIN), str(LIBCRYPTO_SO), work_dir=str(tmp_path))
    err_rpc = gw.handle_jsonrpc({"jsonrpc": "2.0", "id": 7, "method": "unknown_method"})
    assert "error" in err_rpc and err_rpc["error"]["code"] == -32601
    err_tool = gw.handle_jsonrpc({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "no_such_tool"}})
    assert "error" in err_tool and err_tool["error"]["code"] == -32601

    rest_port = _find_free_port()
    srv = tracer_agent.start_background_rest_server("127.0.0.1", rest_port, gw)
    try:
        # Malformed JSON -> HTTP 400
        bad_req = urllib.request.Request(
            f"http://127.0.0.1:{rest_port}/api/v1/traces",
            data=b"{malformed_json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(bad_req, timeout=2.0)
            raise AssertionError("Expected HTTP 400 on malformed JSON")
        except urllib.error.HTTPError as e:
            assert e.code == 400

        # Out-of-range port in PUT /api/v1/config -> HTTP 400
        bad_put = urllib.request.Request(
            f"http://127.0.0.1:{rest_port}/api/v1/config",
            data=json.dumps({"port": 99999}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        try:
            urllib.request.urlopen(bad_put, timeout=2.0)
            raise AssertionError("Expected HTTP 400 on port 99999")
        except urllib.error.HTTPError as e:
            assert e.code == 400
    finally:
        srv.shutdown()
        srv.server_close()


# ==============================================================================
# ADV-TEST-09: Multi-Threaded Concurrency & Hot-Reload Stress Test
# ==============================================================================
def test_adv_09_multithreaded_concurrency_and_hot_reload_stress(tmp_path: Path):
    """
    ADV-TEST-09: Hammer ThreadingHTTPServer, MCPGatewayServer, and RequestCorrelator
    from 16 concurrent worker threads (80 concurrent operations) to verify zero
    deadlocks, thread-safe RLock isolation, and p99 < 500ms latency under contention.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()
    gw = tracer_agent.MCPGatewayServer(str(MOCK_SERVER_BIN), str(LIBCRYPTO_SO), work_dir=str(tmp_path))
    gw.capture_trace(mode="baseline")

    rest_port = _find_free_port()
    srv = tracer_agent.start_background_rest_server("127.0.0.1", rest_port, gw)
    base_url = f"http://127.0.0.1:{rest_port}"
    correlator = tracer_agent.RequestCorrelator()

    def worker_task(task_id: int) -> float:
        t0 = time.monotonic()
        op = task_id % 4
        if op == 0:
            req = urllib.request.Request(
                f"{base_url}/api/v1/config",
                data=json.dumps({"pid": 1000 + task_id, "port": 8080, "iface": "lo", "capture_enabled": True}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PUT",
            )
            with urllib.request.urlopen(req, timeout=3.0) as r:
                res = json.loads(r.read().decode("utf-8"))
                assert res["config_epoch"] >= 1
        elif op == 1:
            with urllib.request.urlopen(f"{base_url}/api/v1/network-layers?layer=sched&proto=tcp", timeout=3.0) as r:
                res = json.loads(r.read().decode("utf-8"))
                assert res["symmetric_io_verified"] is True
        elif op == 2:
            mcp_req = urllib.request.Request(
                f"{base_url}/mcp",
                data=json.dumps({
                    "jsonrpc": "2.0",
                    "id": task_id,
                    "method": "tools/call",
                    "params": {"name": "ebpf_inspect_code_or_asm", "arguments": {"target": "execute_storage_query"}},
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(mcp_req, timeout=3.0) as r:
                res = json.loads(r.read().decode("utf-8"))
                assert "result" in res
        else:
            rid = 0xD00000 + task_id
            correlator.ingest(tracer_agent.KrayEvent(req_id=rid, timestamp=1000, layer_type=1, call_depth=2))
            correlator.ingest(tracer_agent.KrayEvent(req_id=rid, timestamp=2000, layer_type=6, call_depth=2))
            _ = correlator.get_completed_traces()
        return (time.monotonic() - t0) * 1000.0

    try:
        latencies = []
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(worker_task, i) for i in range(80)]
            for fut in as_completed(futures):
                latencies.append(fut.result())

        assert len(latencies) == 80
        latencies.sort()
        p99_ms = latencies[int(len(latencies) * 0.99) - 1]
        assert p99_ms < 500.0, f"Concurrent p99 latency {p99_ms:.1f}ms exceeded 500ms SLA"
        assert gw.runtime_cfg["config_epoch"] == 20
    finally:
        srv.shutdown()
        srv.server_close()


# ==============================================================================
# ADV-TEST-10: High-Throughput SLA & MAX_COMPLETED_TRACES Memory Bound Test
# ==============================================================================
def test_adv_10_high_throughput_sla_and_lru_memory_cap_regression():
    """
    ADV-TEST-10: Ingest 5,000 complete traces (30,000 events) into RequestCorrelator:
    1. Verify ingestion throughput (> 20,000 events/sec)
    2. Verify MAX_COMPLETED_TRACES = 4096 LRU eviction cap prevents memory leaks
    3. Verify deterministic per-req_id sampling_rate (0.10 retains ~10% of intact traces)
    """
    tracer_agent = _import_tracer_agent()
    correlator = tracer_agent.RequestCorrelator(max_completed_traces=4096)

    t0 = time.monotonic()
    for i in range(5000):
        rid = 0xE00000 + i
        base_ts = i * 1000
        for step, (lt, cd) in enumerate([(1, 2), (2, 3), (3, 5), (4, 0), (5, 5), (6, 2)]):
            correlator.ingest(
                tracer_agent.KrayEvent(
                    req_id=rid,
                    timestamp=base_ts + step * 10,
                    layer_type=lt,
                    call_depth=cd,
                )
            )
    elapsed_s = max(1e-6, time.monotonic() - t0)
    throughput = 30000.0 / elapsed_s
    assert throughput > 20000.0, f"Throughput {throughput:.0f} ev/s below 20,000 ev/s SLA"

    completed = correlator.get_completed_traces()
    assert len(completed) == 4096, f"Expected strict 4096 LRU cap, got {len(completed)}"
    # Oldest 904 (0..903) must be evicted; newest (4999) must be present
    assert (0xE00000 + 0) not in completed
    assert (0xE00000 + 4999) in completed

    # Test deterministic 10% sampling rate
    sampled_correlator = tracer_agent.RequestCorrelator(sampling_rate=0.10)
    for i in range(1000):
        rid = 0xF00000 + i
        for step, (lt, cd) in enumerate([(1, 2), (3, 5), (6, 2)]):
            sampled_correlator.ingest(
                tracer_agent.KrayEvent(req_id=rid, timestamp=100 + step, layer_type=lt, call_depth=cd)
            )
    sampled_traces = sampled_correlator.get_completed_traces()
    assert 70 <= len(sampled_traces) <= 130, f"10% sampling retained {len(sampled_traces)}/1000 traces"
    assert all(len(evs) == 3 for evs in sampled_traces.values())


# ==============================================================================
# ADV-TEST-11: Visual Artifacts (Mermaid / FlameGraph / HTML / TUI Edge Cases)
# ==============================================================================
def test_adv_11_visual_artifacts_mermaid_flamegraph_html_and_tui_edge_cases(tmp_path: Path):
    """
    ADV-TEST-11: Verify syntax and edge-case resilience of visual outputs:
    - Mermaid sequenceDiagram generator (render_mermaid_sequence)
    - Brendan Gregg FlameGraph folded stack generator (render_flamegraph_folded)
    - Graphviz ID sanitizer on complex C++ template/library symbols
    - Interactive TUI handling of invalid menu numbers, blank lines, and EOF
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()
    diag = tracer_agent.run_tracer_pipeline(
        binary_path=str(MOCK_SERVER_BIN),
        lib_path=str(LIBCRYPTO_SO),
        port=8080,
        out_prefix=str(tmp_path / "vis_trace"),
        ai_report_path=str(tmp_path / "vis_ai.json"),
    )

    mermaid_txt = tracer_agent.render_mermaid_sequence(diag)
    assert mermaid_txt.startswith("sequenceDiagram")
    assert "NIC->>KNET:" in mermaid_txt
    assert "GATE->>APP:" in mermaid_txt
    assert "KNET->>NIC:" in mermaid_txt

    folded_txt = tracer_agent.render_flamegraph_folded(diag)
    folded_lines = [ln for ln in folded_txt.splitlines() if ln.strip()]
    assert len(folded_lines) == len(diag["hop_timeline"])
    for ln in folded_lines:
        stack_part, count_part = ln.rsplit(" ", 1)
        assert ";" in stack_part
        assert int(count_part) >= 1

    # Adversarial C++ symbol sanitization
    sanitized = tracer_agent.sanitize_graphviz_id("libcrypto-mock.so+0x1140::std::vector<int>(a,b)")
    assert re.match(r"^[a-zA-Z0-9_]+$", sanitized)

    # TUI resilience against invalid menu inputs ("99", "invalid", empty line) + Mermaid ("m") + FlameGraph ("f") before "q"
    proc = subprocess.run(
        [
            sys.executable,
            str(AGENT_PY_PATH),
            "--ui", "tui",
            "--binary", str(MOCK_SERVER_BIN),
            "--lib", str(LIBCRYPTO_SO),
            "--out", str(tmp_path / "tui_edge"),
            "--ai-report", str(tmp_path / "tui_edge.json"),
        ],
        input="99\ninvalid_key\n\nm\nf\nq\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 0
    assert "sequenceDiagram" in proc.stdout
    assert "Unknown option '99'" in proc.stdout


# ==============================================================================
# ADV-TEST-12: Target Kernel (Rocky 9.8 aarch64) Live Verifier & Loopback Bridge
# ==============================================================================
def test_adv_12_target_kernel_live_verifier_and_loopback_readiness(tmp_path: Path):
    """
    ADV-TEST-12: Verify target Rocky Linux 9.8 (5.14.0-687.10.1.el9_8.0.1.aarch64)
    reference kernel tree contracts and execute live mock_server TCP loopback socket
    request -> C kernel hook simulator -> RequestCorrelator end-to-end bridge.
    """
    _ensure_mock_binaries_built()
    tracer_agent = _import_tracer_agent()
    lib = _get_kernel_sim_lib()

    # 1. Verify Rocky 9.8 kernel source tree ground-truth files exist in references/
    kroot = REF_BASE_DIR / "rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1" / "linux-5.14.0-687.10.1.el9_8"
    required_kfiles = [
        kroot / "net" / "ipv4" / "tcp.c",
        kroot / "net" / "core" / "dev.c",
        kroot / "net" / "core" / "datagram.c",
        kroot / "include" / "trace" / "events" / "sched.h",
        kroot / "include" / "trace" / "events" / "block.h",
        kroot / "include" / "trace" / "events" / "net.h",
        kroot / "include" / "net" / "dropreason-core.h",
    ]
    for kf in required_kfiles:
        assert kf.exists(), f"Missing Rocky 9.8 kernel reference file: {kf}"

    # 2. Send a real live HTTP/TCP request to mock_server over loopback socket,
    #    feed the real socket's ephemeral client port & payload size into tracer_kernel.c's
    #    compiled C hooks, and verify end-to-end correlation!
    port = _find_free_port()
    srv = subprocess.Popen(
        [str(MOCK_SERVER_BIN), "--port", str(port), "--fast-storage"],
        cwd=str(ROOT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        sock = None
        for _ in range(30):
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
                break
            except OSError:
                time.sleep(0.05)
        assert sock is not None, f"mock_server did not bind to 127.0.0.1:{port} within 1.5s"
        with sock:
            client_port = sock.getsockname()[1]
            req_bytes = b"GET /live-bridge HTTP/1.1\r\nHost: localhost\r\n\r\n"
            sock.sendall(req_bytes)
            resp_bytes = sock.recv(1024)
        assert b"HTTP/1.1 200 OK" in resp_bytes

        # Feed the exact live loopback connection parameters through tracer_kernel.c C hooks
        lib.sim_reset_all()
        lib.sim_configure_runtime(srv.pid, port, 1, 1)
        lib.sim_set_context(srv.pid, srv.pid, 0)
        lib.sim_tcp_v4_ingress_pipeline(0x0100007F, 0x0100007F, client_port, port, 5, len(req_bytes), 0, 1, 1, 0, 1, 0, 1, 1)
        lib.sim_tcp_recvmsg_call(0x0100007F, 0x0100007F, client_port, port, len(req_bytes), 0)
        lib.sim_skb_copy_and_faults(len(req_bytes), 1)
        lib.sim_sched_waking_and_switch(srv.pid, srv.pid + 1, srv.pid, 0, 1, 10000, 15000)
        lib.sim_set_context(srv.pid, srv.pid + 1, 1)
        lib.sim_uprobe_call(0x401140, 0x7FFFFFFFE000, 120000, 1, 1)
        lib.sim_tcp_egress_pipeline(0x0100007F, 0x0100007F, port, client_port, len(resp_bytes), 0)

        evs = _drain_sim_events(lib, tracer_agent)
        correlator = tracer_agent.RequestCorrelator()
        for e in evs:
            correlator.ingest(e)
        traces = correlator.get_completed_traces()
        assert len(traces) == 1
        trace_evs = next(iter(traces.values()))
        assert {int(e.layer_type) for e in trace_evs} == {1, 2, 3, 4, 5, 6}
    finally:
        srv.terminate()
        srv.wait(timeout=3)

    # 3. Live Rocky Linux 9.8 Kernel Verifier (bpftool prog loadall) check:
    #    - Runs locally if on Linux with /usr/sbin/bpftool
    if sys.platform.startswith("linux") and Path("/usr/sbin/bpftool").exists():
        bpf_obj = tmp_path / "tracer_kernel_bpf.o"
        btf_inc = REF_BASE_DIR / "rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1" / "btf-and-headers"
        subprocess.run(
            [
                "clang", "-target", "bpf", "-D__TARGET_ARCH_arm64", "-DKRAY_BPF_CORE",
                "-O2", "-g", f"-I{ROOT_DIR}", f"-I{btf_inc}",
                "-c", str(ROOT_DIR / "tracer_kernel.c"), "-o", str(bpf_obj),
            ],
            check=True,
        )
        pin_dir = f"/sys/fs/bpf/kray_verify_{os.getpid()}"
        try:
            subprocess.run(["sudo", "-n", "rm", "-rf", pin_dir], check=True)
            subprocess.run(["sudo", "-n", "mkdir", "-p", pin_dir], check=True)
            subprocess.run(["sudo", "-n", "/usr/sbin/bpftool", "prog", "loadall", str(bpf_obj), pin_dir], check=True)
            pinned = subprocess.check_output(["sudo", "-n", "ls", "-1", pin_dir], text=True).splitlines()
            assert len(pinned) >= 42, f"Expected all eBPF programs pinned by Kernel Verifier, got {len(pinned)}"
        finally:
            subprocess.run(["sudo", "-n", "rm", "-rf", pin_dir], check=False)


if __name__ == "__main__":
    test_fns = [
        ("TEST-01", test_01_abi_struct_layout_and_offsets, True),
        ("TEST-02", test_02_ebpf_kernel_c_rocky98_symbols_and_core_safety, False),
        ("TEST-03", test_03_six_layer_correlation_and_multi_request_isolation, False),
        ("TEST-04", test_04_worker_thread_pool_handoff, True),
        ("TEST-05", test_05_stripped_shared_library_offset_fallback, True),
        ("TEST-06", test_06_ringbuf_overflow_alert_banner, True),
        ("TEST-07", test_07_four_tier_graphviz_clusters_heatmap_and_svg, True),
        ("TEST-08", test_08_ai_diagnosis_json_source_and_assembly_evidence, True),
        ("TEST-09", test_09_adaptive_zoom_in_and_before_after_patch_compare, True),
        ("TEST-10", test_10_human_interfaces_web_dashboard_and_tui, True),
        ("TEST-11", test_11_mcp_server_6_tools_and_rest_api_hot_reload, True),
        ("TEST-12", test_12_seven_layer_precompute_matrix_and_multiproto_port_discovery, True),
        ("ADV-TEST-01", test_adv_01_native_c_kernel_hook_emulation, False),
        ("ADV-TEST-02", test_adv_02_rocky98_vmlinux_btf_cross_compilation, True),
        ("ADV-TEST-03", test_adv_03_ebpf_verifier_stack_512b_loop_and_null_guards, True),
        ("ADV-TEST-04", test_adv_04_synthetic_raw_packet_vlan_ipv6_arp_and_malformed_fuzzing, False),
        ("ADV-TEST-05", test_adv_05_state_machine_chaos_and_property_based_fuzzing, False),
        ("ADV-TEST-06", test_adv_06_eight_slot_handoff_ring_contention_and_wraparound, False),
        ("ADV-TEST-07", test_adv_07_elf_dwarf_pie_aslr_and_aarch64_64kb_symbolication, False),
        ("ADV-TEST-08", test_adv_08_negative_fault_injection_and_boundary_guards, True),
        ("ADV-TEST-09", test_adv_09_multithreaded_concurrency_and_hot_reload_stress, True),
        ("ADV-TEST-10", test_adv_10_high_throughput_sla_and_lru_memory_cap_regression, False),
        ("ADV-TEST-11", test_adv_11_visual_artifacts_mermaid_flamegraph_html_and_tui_edge_cases, True),
        ("ADV-TEST-12", test_adv_12_target_kernel_live_verifier_and_loopback_readiness, True),
    ]
    passed = 0
    failed = 0
    total = len(test_fns)
    print("======================================================================")
    print(f"eBPF-WireToCode-Tracer Verification Suite (24 Suites: TEST-01..12 + ADV-TEST-01..12)")
    print("======================================================================")
    for test_id, fn, needs_tmp in test_fns:
        try:
            with tempfile.TemporaryDirectory() as td:
                if needs_tmp:
                    fn(Path(td))
                else:
                    fn()
            print(f"[PASS] {test_id}: {fn.__name__}")
            passed += 1
        except Exception as exc:
            print(f"[FAIL] {test_id}: {fn.__name__} -> {exc}")
            failed += 1
    print("----------------------------------------------------------------------")
    print(f"Summary: {passed}/{total} PASSED, {failed}/{total} FAILED")
    sys.exit(0 if failed == 0 else 1)
