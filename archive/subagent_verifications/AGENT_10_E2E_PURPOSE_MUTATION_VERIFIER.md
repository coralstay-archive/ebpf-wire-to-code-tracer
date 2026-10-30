# AGENT 10 — Adversarial Falsification Audit: End-to-End Wire-to-Code Purpose Alignment & Mutation Testing (`Mutants M1..M8`)

## 1. Executive Summary

* **Part A — End-to-End Wire-to-Code Purpose Alignment Audit (`E2E-01` .. `E2E-05`)**:
  - **E2E-01 (`run_tracer_pipeline()` Hardcoded Synthesis Bypass)**: `run_tracer_pipeline()` in `tracer_agent.py` was outputting hardcoded constants instead of feeding the 64-byte `KrayEvent` stream from `libtracer_kernel_sim` (or live BPF ringbuf) through `RequestCorrelator`, `decode_event_metadata()`, `compute_final_drop_count()`, and `BinarySymbolicator`.
  - **E2E-02 (DWARF Symbolication Bypass)**: `BinarySymbolicator.extract_cpp_source_evidence()` was searching `mock_server.cpp` text instead of querying `llvm-symbolizer` / `addr2line` / `dwarfdump` / `nm` on the compiled binary.
  - **E2E-03 (Interval Subtraction Engine)**: Needed event-driven calculation of `pure_on_cpu_compute_ms` vs `off_cpu_io_wait_ms` from `uretprobe` `duration_ns`, `off_cpu_delta`, and nested L5/L6 events.
  - **E2E-04 (`RequestCorrelator._finalize_request()` Sort Key Inversion)**: Sorted by `(layer_type, timestamp, is_return)` instead of `(timestamp, layer_type, is_return)`, pulling mid-function L5/L6 events (`block_rq_complete`, `sched_switch`) ahead of the L7 `uprobe` entry.
  - **E2E-05 (`mock_server.cpp` `--fast-mode` Flag & Relative `dlopen` Path)**: `mock_server.cpp` only checked `--fast-storage` (ignoring `--fast-mode`) and called `dlopen("./libcrypto_mock.so", RTLD_NOW)` with a CWD-relative path.

* **Part B — Mutation Testing of the 24 Test Suites (`Mutants M1` .. `M8`)**:
  - **Mutant M1**: `call_depth >= MAX_CALL_DEPTH (16/32)` bitmask wraparound (`16 & 15 == 0`) overwriting root frame slot 0 in `trace_uprobe_entry`.
  - **Mutant M2**: `sched_switch` in-function (`call_depth > 0`) Off-CPU sleep duration never tested through the C kernel simulator.
  - **Mutant M3**: `tcp_retransmit_skb` C tracepoint handler never executed in `kernel_sim_harness.c`.
  - **Mutant M4**: `kprobe__ip6_output` and `sched_process_fork` C handlers never executed in `kernel_sim_harness.c`.
  - **Mutant M5**: Unconnected UDP `kprobe__udp_sendmsg` emitting `dst_ip=0, dst_port=0` and leaking `active_ctx_map[&tid]`.
  - **Mutant M6**: `decode_event_metadata()` L2/L3/L4 bit-unpacking (`cpu_id`, `vlan_id`, `ttl`, `ihl_bytes`, `pkt_len`) not cross-verified against C kernel bit-packing.
  - **Mutant M7**: `RequestCorrelator._finalize_request()` timestamp ordering with mid-function L5/L6 events.
  - **Mutant M8**: `run_tracer_pipeline()` disconnected from `RequestCorrelator` and C kernel events.
