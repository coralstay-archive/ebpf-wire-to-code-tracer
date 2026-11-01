# Adversarial Falsification Report — Domain 12/20: L6 Pre-Compute Gate & Worker Thread Pool Attribution (`L6_PRE_COMPUTE_GATE`, Acceptor-to-Worker Causality, Multi-Worker Isolation)

### Executive Summary of Falsified Claims & Architectural Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against the core project philosophy falsified critical assumptions regarding the `L6_PRE_COMPUTE_GATE`:

* **Falsification 1 — Single-Threaded Event Loop Pre-Compute Gate Missing**:
  * In single-threaded servers (e.g. Node.js, Redis, or non-threaded Python/C++ event loops), there is NO Futex handoff between acceptor and worker threads (`acceptor_tid == worker_tid`).
  * If `L6_PRE_COMPUTE_GATE` (`OSI_L6_PRE_COMPUTE = 8`) is ONLY emitted upon Futex wake or scheduler context switch between distinct threads, single-threaded architectures would show a missing L6 gate in `seven_layer_matrix`.
  * `tracer_kernel.c` and `tracer_agent.py` must ensure that for single-threaded executions, the transition from kernel socket read (`sys_exit_recvmsg` / `skb_copy_datagram_iter`) to userspace execution entry (`uprobe` depth 0) synthesizes or emits `L6_PRE_COMPUTE_GATE` so that `pre_compute_latency_ns` is always accounted for.
* **Falsification 2 — Worker Thread Pool Attribution Inversion**:
  * In multi-threaded thread pools (such as the target server `mock_server.cpp`), the acceptor thread places work into a bounded queue and signals worker threads via `pthread_cond_signal` or `pthread_mutex_unlock` (`sys_futex(FUTEX_WAKE)`).
  * If multiple workers compete for the queue:
    * Worker A (TID 10425) wakes up, claims Request 1.
    * Worker B (TID 10426) wakes up, claims Request 2.
  * If `pending_handoff_map` uses a single global slot per process rather than an 8-slot ringbuffer indexed by modulo head/tail or monotonic sequence, Worker B can overwrite Request 1 before Worker A reads it, leading to request cross-talk and inverted latency attribution.
* **Falsification 3 — Pre-Compute Latency vs Inclusive Compute Boundary**:
  * By formal specification definition, `pre_compute_latency_ns` measures the wall-clock time from the initial wire packet arrival (`STAGE_L2_INGRESS`) to the instant the worker thread enters its first application-level compute function (`STAGE_L7_USERSPACE_COMPUTE`).
  * If userspace runtime initialization overhead (e.g., dynamic linker relocations, memory allocator initialization) is included inside compute time rather than pre-compute overhead, CPU bottleneck diagnosis in `ai_diagnosis.json` produces false leaf attribution.

### Root Cause Analysis & Line Citations

* [`tracer_kernel.c:1340-1420`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1340-L1420):
  * `publish_handoff_slot` records `req_id`, `now`, `waker_tid`, and network 4-tuple in `pending_handoff_map` using an 8-slot ringbuffer.
  * `sys_exit_futex` claims the oldest unconsumed slot for the waking worker thread.
  * If `ret == -EAGAIN` (-11), the worker thread retried without sleeping, which must still claim handoff if available.
* [`tracer_agent.py:1020-1080`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1020-L1080):
  * `_finalize_request` builds `seven_layer_matrix`:
  * If no explicit futex event occurred because `acceptor_tid == worker_tid`, `L6_PRE_COMPUTE_GATE` is synthesized between `L5_SYSCALL_MEMCPY` and `L7_APP_ALU` with duration computed from `first_uprobe_ts - last_l5_ts`.
* [`test_verification_suite.py:380-420`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L380-L420):
  * `test_04_worker_thread_pool_handoff` verifies handoff from Acceptor thread (TID 10420) to Worker thread (TID 10425) with exact req_id continuity and runqlat latency attribution.

### Verification & Remediation Invariants

1. Pre-Compute Gate Invariant: Every completed request MUST contain an `L6_PRE_COMPUTE_GATE` entry in `seven_layer_matrix`, regardless of whether the execution model is single-threaded or multi-threaded.
2. Thread Isolation Invariant: In concurrent multi-worker environments, no worker thread may claim another worker's assigned `req_id` or corrupt the 8-slot handoff ringbuffer.
3. Strict Pre-Compute Metric Invariant: `pre_compute_latency_ns = first_app_uprobe_ts - wire_ingress_ts`. It MUST equal the exact sum of L2, L3, L4, L4.5, L5, and L6 durations.
