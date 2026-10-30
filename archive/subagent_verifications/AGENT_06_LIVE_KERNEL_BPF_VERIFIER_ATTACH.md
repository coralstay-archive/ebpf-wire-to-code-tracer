# AGENT 06 — Adversarial Falsification Audit: Live Target VM BPF Verifier Load & Real Kernel Attachment (`ebpf-tracer-v2.0.0`)

## 1. Executive Summary of Live Kernel Falsifications on `ebpf-tracer-v2.0.0` (`5.14.0-687.10.1.el9_8.0.1.aarch64`)

* **Falsification #1 (`bpftool prog loadall` != Real Kernel Attachment)**:
  - Running `bpftool prog loadall` without `autoattach` only validates `BPF_PROG_LOAD` in the Verifier.
  - Testing real attachment via `libbpf` `bpf_program__attach()` on `ebpf-tracer-v2.0.0` revealed:
    1. `trace_uprobe_entry` (`SEC("kprobe/trace_uprobe_entry")`) and `trace_uprobe_return` (`SEC("kretprobe/trace_uprobe_return")`) failed with `errno = -2 (ENOENT)` because `kray_bpf_core_compat.h` marked them as kernel probes instead of `SEC("uprobe")` / `SEC("uretprobe")`.
    2. Loopback (`lo`) rejects `xdpdrv` native mode (`EOPNOTSUPP`) and requires `xdpgeneric` (`XDP_FLAGS_SKB_MODE`).
    3. All 39 kernel `kprobe`/`kretprobe`/`tp` hooks in `tracer_kernel_bpf.o` match real symbols in `/proc/kallsyms` (`ipv6_rcv`, `ip6_output`, `tcp_v4_rcv`, `tcp_v6_rcv`, `__tcp_transmit_skb`, etc.) and attach cleanly (`PASS=39`).
* **Falsification #2 (Prompt Hypothesis on 42 Programs Falsified + Empty `sys_exit_write` Stub Caught)**:
  - Inspecting `llvm-objdump -h tracer_kernel_bpf.o` proved there are zero duplicate macro-generated `tracepoint_probe_*` sections; the 42 sections are `1 XDP + 18 Tracepoints + 21 Kprobes/Kretprobes + 2 Uprobes = 42` real functions in `tracer_kernel.c`.
  - Caught an actual 16-byte no-op stub (`r0 = 0; exit;`) in `TRACEPOINT_PROBE(syscalls, sys_exit_write)`.
* **Falsification #3 (Live Kernel Data-Path Bugs)**:
  - `__tcp_transmit_skb` clones `oskb` (`skb = skb_clone(oskb, gfp_mask)`), so `kprobe__ip_output` and `kprobe__ip6_output` must register the post-clone `skb_ptr` into `skb_egress_map` on `PT_REGS_PARM2(ctx)` fallback.
  - 0-byte TCP `SYN` / `ACK` packets must be filtered out before creating entries in `ingress_flow_map`.
