# Agent 15 Adversarial Falsification Report — Domain 15/20: 64-Byte `kray_event_t` ABI, Ringbuf Overflow Accounting & Out-of-Order `RequestCorrelator` State Machine

### 1. Executive Summary of Falsifications

* **Defect 15-1 — `kray_runtime_cfg_t.filter_flags` Dead ABI & `capture_enabled` / `target_pid` Bypass Bugs**:
  * In [`tracer_kernel.c:268-284`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L268-L284), `get_target_pid()` previously checked `if (cfg && cfg->target_pid != 0)` instead of `if (cfg && cfg->config_epoch > 0)`, preventing hot-reloading `target_pid = 0` when `__TARGET_PID__` was non-zero at compile time.
  * When `cfg->capture_enabled == 0 && cfg->config_epoch > 0`, `emit_kray_event()` itself should guard on `capture_enabled` so portless hooks (`icmp_rcv`, `arp_rcv`, `unix_stream_recvmsg`) also respect `capture_enabled == 0`.
* **Defect 15-2 — Unreset `tctx->copied_bytes` and `tctx->page_faults` in `kretprobe__skb_copy_datagram_iter` & 16-Bit `u16 copied_bytes` Truncation**:
  * In [`struct tid_ctx_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L197-L198), `page_faults` and `copied_bytes` were `u16` (truncating reads >= 64KB) and were not reset to `0` after `kretprobe__skb_copy_datagram_iter` emitted `OSI_L5_SYSCALL_MEM`. Upgrading both to `u32` and resetting them to `0` upon emission prevents cross-read accumulation.
* **Defect 15-3 — `run_tracer_pipeline` & `run_c_harness_wire_to_code_pipeline` Ignored `ev->drop_count` and `drop_cnt_map[0]`**:
  * [`compute_final_drop_count`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L188-L199) existed in `tracer_agent.py` but was not called in `run_tracer_pipeline`, which previously hardcoded `final_drop_count = int(simulate_drops)`. Wiring `correlator.max_event_drop_count` and `lib.sim_get_drop_count()` into `compute_final_drop_count()` ensures real C ringbuf drops propagate end-to-end into `ai_diagnosis.json`.
* **Defect 15-4 — Saturating 32-Bit `ev->drop_count` Cast in `emit_kray_event`**:
  * Caps `*cnt` at `0xFFFFFFFFU` before assigning `ev->drop_count` so $2^{32}$ ringbuf drops never wrap around to `0`.
* **Defect 15-5 & 15-6 — Late Out-of-Order Events Arriving After `L2_EGRESS` Finalization & `max_inflight` LRU Bound**:
  * When `req_id` is already in `self._completed` and a delayed event (`L4_EGRESS` or `L7_FUNC_EXIT`) arrives on another CPU, `ingest()` now immediately merges and re-finalizes `self._completed[req_id]`.
  * Added `max_inflight = 4096` LRU eviction on `self._buffers` and updated `_first_seen_ts[req_id]` with `min()` across out-of-order timestamps.
* **Defect 15-7 — Canonical Sub-Layer Sort Order**:
  * Within `LAYER_KERNEL_NET` (`2`) and `LAYER_USER_ENTRY` (`3`), OSI sub-layers ascend (`L3=3 -> L4=4 -> L4.5=5 -> L5=6 -> L6=8`), whereas within `LAYER_USER_EXIT` (`5`) and `LAYER_EGRESS_NIC` (`6`), OSI sub-layers descend (`L4=4 -> L3=3 -> L2=2`). Using `_canonical_sort_key` prevents egress/ingress sub-layer inversions when timestamps tie across CPUs.
