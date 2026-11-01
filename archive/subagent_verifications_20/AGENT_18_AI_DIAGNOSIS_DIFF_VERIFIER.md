# Agent 18 Adversarial Falsification Report — Domain 18/20: AI Bottleneck Diagnosis, Adaptive Zoom-In & Before/After Patch Differential Verification

### 1. Executive Summary of Falsifications

* **Flaw 18-A — Missing `self_time_ns` vs `inclusive_time_ns` Calculation & Double-Counting of Nested L7 Functions**:
  * Previously, `correlate_and_symbolicate_sim_events` and `run_tracer_pipeline` ranked bottlenecks by inclusive `duration_ms` and summed `on_cpu_ms` across all L7 functions regardless of `call_depth`. In a nested call chain (`handle_client_payload` at `depth=0` -> `verify_request_token` at `depth=1` -> `execute_storage_query` at `depth=2`), the outer wrapper has a larger inclusive duration than the leaf hotspot, causing naive `max(duration_ms)` ranking to blame the wrapper and double/triple-count nested durations in `l7_total_ms`.
  * Implemented `build_ai_diagnosis_report()` with per-`(tid, call_depth)` frame tracking that subtracts child inclusive durations and child Off-CPU wait times to compute exact exclusive `self_time_ns` (`self_on_cpu_ns` + `self_off_cpu_ns`) and ranks L7 hotspots by `self_time_ns`.
* **Flaw 18-B — Dynamic Per-Thread / Per-Frame Off-CPU & Block I/O Attribution**:
  * Replaced the hardcoded `tid == 10425` / `symbol == "execute_storage_query"` check with general timestamp-interval `[entry_ts, return_ts]` attribution of `OSI_L5_SYSCALL_MEM` and `OSI_L6_PRE_COMPUTE` wait events on any worker TID and any function symbol.
* **Flaw 18-C — Non-L7 Kernel Bottleneck Diagnosis (`L6_PRE_COMPUTE` Contention & `L3/L4` Drop/Retransmit)**:
  * `build_ai_diagnosis_report()` now diagnoses:
    * `KERNEL_NETWORK_DROP_OR_RETRANSMIT_BOTTLENECK` when `FLAG_SKB_DROP` or `FLAG_TCP_RETRANSMIT` anomalies occur, even when L7 userspace events are absent.
    * `L6_PRE_COMPUTE_SCHEDULER_OR_FUTEX_CONTENTION` when `pre_compute_latency_ns > userspace_compute_ns` due to Futex lock wait or CPU runqueue starvation.
    * `SOCKET_RECEIVE_QUEUE_DWELL_BOTTLENECK` when `sk_rcvbuf` dwell dominates RTT.
* **Flaw 18-D — `AdaptiveController` with Dual-Watermark Hysteresis & `sim_configure_runtime` Sync**:
  * Implemented `AdaptiveController` with `zoom_threshold_ns`, `low_watermark_ns` (`hysteresis_ratio = 0.70`), and `cooldown_windows` to prevent mode-switch thrashing around the threshold, while synchronizing `KrayRuntimeConfig` directly with `lib.sim_configure_runtime`.
* **Flaw 18-E — `compare_before_after_traces` Division-by-Zero Guards, Regression Detection & Per-Function/Per-Layer Deltas**:
  * Added `compare_before_after_traces()` (aliased as `compare_diagnoses`) supporting both file paths and diagnosis dicts, guarding `base_rtt == 0` and `patch_rtt == 0`, flagging `regression_detected = True` (`verdict = "REGRESSION"`) when `patch_rtt > base_rtt` or when drops occur, and computing `function_deltas` and `layer_deltas`.
