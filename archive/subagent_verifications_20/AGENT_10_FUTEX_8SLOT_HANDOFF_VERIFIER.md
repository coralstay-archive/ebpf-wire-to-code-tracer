# Agent 10 Adversarial Falsification Report — Domain 10/20: L5/L6 Futex Synchronization & 8-Slot Handoff Ring Buffer (`sys_enter_futex`, `sys_exit_futex`, `FUTEX_WAIT`/`WAKE`, Contention & Wrap-Around)

### 1. Executive Summary of Falsifications

* **Flaw 1 — `sys_exit_futex` Drops `-EAGAIN` (`-11`) Contended Fast-Path Handoffs & Leaks Stale `futex_enter_ts` Across `-ETIMEDOUT` (`-110`) / `-EINTR` (`-4`)**:
  * In [`tracer_kernel.c:1142-1188`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1188), `sys_exit_futex` previously rejected all `args->ret < 0`. When a producer updates the futex word and calls `FUTEX_WAKE` just before the consumer acquires the kernel futex hash-bucket spinlock in `futex_wait_setup()`, `futex(FUTEX_WAIT)` returns `-EAGAIN` (`-11`) immediately without sleeping (`sched_switch` never fires). Allowing `args->ret == -11` (`-EAGAIN`) to claim a pending handoff slot while clearing `tctx->futex_enter_ts = 0` on genuine errors (`-ETIMEDOUT = -110`, `-EINTR = -4`) closes both the fast-path drop and the stale timestamp leak.
* **Flaw 2 — Futex Opcode Extraction (`cmd = op & 0x7F`) in `sys_enter_futex` & `FUTEX_LOCK_PI2` (`13`) Coverage**:
  * Separates `#ifdef KRAY_BPF_CORE`, `#elif defined(KRAY_USER_SIM)`, and `#else` (BCC) opcode extraction cleanly, and adds `FUTEX_LOCK_PI2` (`13`) to the wait opcode set (`0, 6, 9, 11, 13`).
* **Flaw 3 — 8-Slot Active Window Deduplication & Monotonic `u32` Wrap-Around Safety in `publish_handoff_slot`**:
  * Replaces the single-slot `ring->write_idx > ring->read_idx` check with an unrolled 8-slot active window scan (`u32 depth = (u32)(ring->write_idx - ring->read_idx)`) that prevents duplicate slot allocation even if an earlier slot for the same `req_id` was already claimed by `sched_waking`.
* **Flaw 4 — Unified `mark_handoff_slot_claimed()` and `consume_handoff_slot()` Helpers**:
  * Searches the active 8-slot window in `mark_handoff_slot_claimed()` when `sched_waking` claims a request out-of-order, and advances `read_idx` past any leading already-claimed slots in `consume_handoff_slot()`.
* **Flaw 5 — UDP (`kretprobe__udp_recvmsg`) and `AF_UNIX` (`kprobe__unix_stream_recvmsg`) Handoff Publishing**:
  * Calls `publish_handoff_slot()` in `kretprobe__udp_recvmsg` and `kprobe__unix_stream_recvmsg` so multi-threaded UDP and UDS servers also support Tier-2 worker pool handoff.
