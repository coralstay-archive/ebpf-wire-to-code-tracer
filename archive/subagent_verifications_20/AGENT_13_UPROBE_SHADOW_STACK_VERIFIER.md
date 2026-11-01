# Agent 13 Adversarial Falsification Report — Domain 13/20: L7 Uprobe/Uretprobe Shadow Call Stack (`trace_uprobe_entry`, `trace_uprobe_return`, Deep Recursion `> 16`, Unbalanced Stack Resilience)

### 1. Executive Summary of Falsifications

* **Flaw 13-1 [CRITICAL] — `trace_uprobe_return` Slot Wrap-Around IP Aliasing (`orig_ip = tctx->fn_entry_ip[raw_depth & 15]`) and Missing Userspace LIFO Shadow Stack Backfill at Deep Recursion (`raw_depth >= 16`)**:
  * In [`tracer_kernel.c:1494-1508`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1494-L1508), `fn_dur` was guarded by `(raw_depth < MAX_CALL_DEPTH) ? (now - saved_ts) : 0`, **but `orig_ip = tctx->fn_entry_ip[slot]` was NOT guarded by `(raw_depth < MAX_CALL_DEPTH)`**! Returning from depths `19..16` wrapped `slot = raw_depth & 15` to `3..0` and emitted false-alias instruction pointers stolen from outer frames `3..0`.
  * Guarding `orig_ip = (raw_depth < MAX_CALL_DEPTH) ? tctx->fn_entry_ip[slot] : 0`, preserving full `u8 report_depth = raw_depth`, and maintaining a per-`(req_id, tid)` LIFO shadow call stack of `is_return == 0` events in `RequestCorrelator._finalize_request` restores the exact `ev.ip` and `ev.duration_ns` for all recursive return frames at depth `>= 16`.
* **Flaw 13-2 — Spec Alignment in `PROMPT_SPEC.md`**:
  * Updated `PROMPT_SPEC.md` so the L7 shadow stack specification matches the non-wrapping `raw_depth < MAX_CALL_DEPTH` guard and LIFO userspace backfill.
* **Flaw 13-3 — Strengthened `ADV-TEST-07` Deep Recursion Assertions**:
  * Verified every single return frame across depths `19..0` (not just `depth 0`).
