### Domain 11 Adversarial Falsification Report: L5/L6 Scheduler & CPU Migration (`sched_waking`, `sched_wakeup`, `sched_switch`, `sched_process_fork`, `sys_enter_futex`, `sys_exit_futex`, Runqueue Latency, Preemption vs. Voluntary Sleep)

#### 1. Falsification of the Prompt's Premise (`active_ctx_map` Key Width & `swapper/0` Behavior)
* **Prompt Hypothesis Audited**:
  * The prompt hypothesized that `active_ctx_map` is keyed by `u64 pid_tgid` (`(u64)tgid << 32 | tid`) and that `tp_sched_switch` constructs a `u64` key using `bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000ULL`, which would fail when switching from `swapper/N` (`prev_pid == 0`, `tgid == 0`).
* **Physical Code Reality in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L251-L254)**:
  * In [`tracer_kernel.c:253`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L253), `active_ctx_map` is declared as `BPF_LRU_HASH(active_ctx_map, u32, struct tid_ctx_t, 8192);` (keyed by 32-bit `u32 tid`, NOT `u64 pid_tgid`), whereas `pending_handoff_map` in [`tracer_kernel.c:254`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L254) is keyed by `u32 tgid`.
  * In [`tp_sched_switch` (`tracer_kernel.c:1282-1327`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1282-L1327), `u32 prev_tid = (u32)args->prev_pid;` and `u32 next_tid = (u32)args->next_pid;` are used directly as keys into `active_ctx_map`, and the emitted event uses `nctx->pid` (the cached TGID stored inside [`struct tid_ctx_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L211-L234)), avoiding `bpf_get_current_pid_tgid()` inside `tp_sched_switch`.
* **Actual `swapper/N` (`tid == 0`) Defect Found in [`tracer_kernel.c:1288-1299`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1288-L1299)**:
  * Neither `prev_tid` nor `next_tid` is guarded against `0` (`swapper/N` idle threads on every CPU core). Every idle transition performs unnecessary BPF LRU hash lookups on key `0` (`active_ctx_map.lookup(&prev_tid)` and `active_ctx_map.lookup(&next_tid)`).

---

#### 2. Critical Flaw #1: Involuntary Preemption (`args->prev_state == 0` or `TASK_REPORT_MAX`) Drops Runqueue Wait Latency to `0 ns` at `call_depth == 0` and Fails to Distinguish Preemption from Voluntary Sleep
* **Target Kernel Ground Truth ([`include/trace/events/sched.h:190-265`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L190-L265))**:
  * In Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8`), `__trace_sched_switch_state(bool preempt, unsigned int prev_state, struct task_struct *p)` sets `args->prev_state` to `TASK_REPORT_MAX` (`0x100` / `256`) when `preempt == true`, or `0` (`TASK_RUNNING`) on voluntary yield/preemption, whereas voluntary sleep (`futex`, socket wait, block I/O) sets `args->prev_state` to `TASK_INTERRUPTIBLE` (`1`) or `TASK_UNINTERRUPTIBLE` (`2`).
  * When a task is involuntarily preempted (`prev_state == 0` or `prev_state >= 0x100`), it **remains on the CPU runqueue in `TASK_RUNNING` state** and **never triggers `sched_waking` or `sched_wakeup`** before being scheduled back On-CPU by `sched_switch`.
* **Root Cause in [`tp_sched_switch` (`tracer_kernel.c:1282-1327`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1282-L1327)**:
  * `tp_sched_switch` never reads `args->prev_state`!
  * When a thread with an active `req_id` is involuntarily preempted at `call_depth == 0` (for example, between `skb_copy_datagram_iter` and the first user-space `uprobe`, or after `sched_wakeup` + preemption before `uprobe`):
    1. On switch-out ([`tracer_kernel.c:1292-1296`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1292-L1296)), `pctx->off_cpu_enter_ts = now;` is recorded, while `pctx->wakeup_ts` remains `0` (because `sched_wakeup` never fires for an already-runnable preempted task).
    2. On switch-in ([`tracer_kernel.c:1303-1310`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1303-L1310)):
       * `u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts) : 0;` evaluates to **`0`**!
       * `u64 total_off_cpu_ns = nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : runq_ns;` evaluates to the true preemption runqueue wait (`now - off_cpu_enter_ts`).
       * `u64 emit_dur = (nctx->call_depth == 0) ? runq_ns : total_off_cpu_ns;` selects `runq_ns` (`0`) because `nctx->call_depth == 0`!
    3. Consequently, **100% of involuntary preemption runqueue latency at `call_depth == 0` is emitted with `duration_ns = 0`!**
  * Furthermore, when an involuntarily preempted thread at `call_depth > 0` stays on the runqueue waiting for CPU time, its entire `now - off_cpu_enter_ts` is actually **Runqueue Wait** (since `prev_state == 0` / `TASK_REPORT_MAX`), whereas `tp_sched_switch` does not record whether the switch-out was preemption (`prev_state == 0 || prev_state >= 0x80`) vs. voluntary sleep (`prev_state & 0x7f`).

---

#### 3. Critical Flaw #2: Tier-2 `sys_exit_futex` Handoff Claim Occurs *After* `sched_switch`, Skipping `OSI_L6_PRE_COMPUTE` Emission and Leaving Stale `wakeup_ts` / `futex_enter_ts`
* **Root Cause in [`sys_exit_futex` (`tracer_kernel.c:1142-1188`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1188) and [`kernel_sim_harness.c:1033-1038`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L1033-L1038)**:
  * Consider the physical Linux kernel execution order when a worker thread wakes from `futex(FUTEX_WAIT)` and claims a handoff via Tier 2 (`pending_handoff_map` in `sys_exit_futex`, e.g., when `sched_waking` did not populate `tctx` or in `FUTEX_REQUEUE` / burst handoff):
    1. Worker enters `sys_enter_futex(FUTEX_WAIT)` (`tctx->futex_enter_ts = t_enter`, `tctx->req_id = 0`).
    2. Worker is switched Off-CPU by `tp_sched_switch` (`tctx->req_id == 0`).
    3. Worker is switched **back On-CPU** by `tp_sched_switch` so it can exit the `futex` syscall. If Tier 1 (`tp_sched_waking`) did not assign `tctx->req_id`, then at the moment `tp_sched_switch` runs, `nctx->req_id` is still **`0`**, so `tp_sched_switch` ([`tracer_kernel.c:1299`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1299)) does **nothing**!
    4. Now already On-CPU, the worker executes [`tp_sys_exit_futex` (`tracer_kernel.c:1142-1188`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1188), which claims `ring->slots[r_idx]` and populates `tctx->req_id`, `tctx->futex_enter_ts = saved_futex_ts`, and `tctx->wakeup_ts = ring->slots[r_idx].wakeup_ts`.
    5. The worker immediately returns to user space and enters `trace_uprobe_entry` **without another `sched_switch`**!
  * **Two Severe Consequences**:
    1. **Missing `OSI_L6_PRE_COMPUTE` Event**: `tp_sys_exit_futex` never emits the `OSI_L6_PRE_COMPUTE` event for the Tier-2 handoff (`lock_wait_ns = wakeup_ts - futex_enter_ts`, `runq_ns = now - wakeup_ts`, and CPU migration `prev_cpu_id -> cur_cpu`).
    2. **Timestamp Poisoning on Next Context Switch**: Because `tctx->wakeup_ts` and `tctx->futex_enter_ts` are set in `tp_sys_exit_futex` and **not cleared**, when the worker later blocks inside a user function (`call_depth > 0`, e.g., during Block I/O), the next `tp_sched_switch` computes a corrupted `lock_wait_ns` using the stale `futex_enter_ts` from before the function even started!

---

#### 4. Critical Flaw #3: `tp_sched_waking` Unconditionally Clobbers Active Target Thread Contexts and Fails to Mark Non-Head `pending_handoff_map` Ring Slots as Claimed
* **Root Cause in [`tp_sched_waking` (`tracer_kernel.c:1220-1271`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1220-L1271)**:
  * **Sub-Flaw 3A (Context Clobbering of Active Threads & Cross-Process Kernel Threads)**:
    * At [`tracer_kernel.c:1236-1245`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1236-L1245):
      ```c
      struct tid_ctx_t *existing_tctx = active_ctx_map.lookup(&target_tid);
      u64 saved_futex_ts = existing_tctx ? existing_tctx->futex_enter_ts : 0;
      ...
      active_ctx_map.update(&target_tid, zero_template);
      ```
    * If `existing_tctx && existing_tctx->req_id != 0` (for example, `target_tid` is **already actively executing another traced request** `req_id_1` and was briefly blocked on a mutex/pagefault/I/O that `waker_tid` happened to wake while holding `req_id_2`), `tp_sched_waking` **wipes out `target_tid`'s entire `tid_ctx_t`** (`zero_template`), destroying its in-flight `req_id_1`, `call_depth`, `fn_entry_ts[]`, and `acc_off_cpu_ns`!
    * Even worse: if `existing_tctx && existing_tctx->req_id == wctx->req_id` (a worker thread already handling `wctx->req_id` at `call_depth > 0` is woken up by a helper thread sharing the same `req_id`), `active_ctx_map.update(&target_tid, zero_template)` zeroes out `target_tid`'s `call_depth` and `fn_entry_ts[]` stack mid-function!
    * Furthermore, when an Acceptor thread with `wctx->req_id != 0` wakes a kernel worker thread (`kworker/*`, `ksoftirqd/*`) or an unrelated daemon (`target_tid` not in `tgid`), `tp_sched_waking` injects `wctx->req_id` and `tctx->pid = tgid` into `active_ctx_map[&target_tid]`, causing the kernel thread's subsequent `sched_switch` to emit false `OSI_L6_PRE_COMPUTE` events attributed to the application's `req_id` and `tgid`!
  * **Sub-Flaw 3B (Ring Buffer Slot Leak & Double-Claim on Out-of-Order Wakeups)**:
    * At [`tracer_kernel.c:1261-1268`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1261-L1268):
      ```c
      struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
      if (ring) {
          u32 r_idx = ring->read_idx & 7;
          if (ring->slots[r_idx].req_id == wctx->req_id && ring->slots[r_idx].claimed == 0) {
              ring->slots[r_idx].claimed = 1;
              ring->read_idx++;
          }
      }
      ```
    * If Acceptor A publishes `req_id_1` at `slots[0]` (`read_idx == 0`) via `sys_enter_futex(FUTEX_WAKE)` where no sleeping thread was woken in `sched_waking` (because Worker 1 was spinning in user space and will call `FUTEX_WAIT` / `sys_exit_futex`), and Acceptor B concurrently publishes `req_id_2` at `slots[1]` and wakes Worker 2 via `tp_sched_waking`, then `ring->slots[r_idx].req_id` (`slots[0].req_id == req_id_1`) does **not** match `wctx->req_id` (`req_id_2`). As a result, `slots[1]` (`req_id_2`) is **left unclaimed (`claimed == 0`)** in `pending_handoff_map`, and the next Tier-2 worker in `sys_exit_futex` will claim `req_id_2` a **second time**!

---

#### 5. Critical Flaw #4: `tp_sched_switch` Overwrites `prev_cpu_id` During SMP Wakeup-Before-Switch Race, and `tp_sched_process_fork` Never Initializes `wakeup_ts` or `prev_cpu_id`
* **Root Cause A (`tp_sched_switch` Overwriting Waker's `prev_cpu_id` in [`tracer_kernel.c:1292-1296`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1292-L1296))**:
  * In [`tracer_kernel.c:1292-1296`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1292-L1296):
    ```c
    struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
    if (pctx && pctx->req_id != 0) {
        pctx->off_cpu_enter_ts = now;
        pctx->prev_cpu_id      = (u8)bpf_get_smp_processor_id();
    }
    ```
  * When a worker thread on CPU 2 sets `TASK_INTERRUPTIBLE` inside `futex_wait_queue_me()` and an Acceptor thread on CPU 0 immediately calls `FUTEX_WAKE` -> `try_to_wake_up()` -> `tp_sched_waking` *before* CPU 2 executes `tp_sched_switch` for `prev_tid`, `tp_sched_waking` on CPU 0 sets `tctx->req_id = wctx->req_id`, `tctx->wakeup_ts = now`, and `tctx->prev_cpu_id = 0` (the Acceptor's CPU).
  * Microseconds later, when CPU 2 runs `tp_sched_switch` (`prev_tid = worker`), `pctx->req_id != 0` is now TRUE, so `pctx->prev_cpu_id` is overwritten with `2` (the worker's old CPU), erasing the cross-CPU handoff provenance (`CPU 0 -> CPU 2`)!
* **Root Cause B (`tp_sched_process_fork` Missing `wakeup_ts` and `prev_cpu_id` in [`tracer_kernel.c:1190-1218`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1190-L1218))**:
  * In Linux `kernel/sched/core.c` (`wake_up_new_task`), a newly forked/cloned thread is woken via `trace_sched_wakeup_new(p)` ([`include/trace/events/sched.h:185`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L185)), **not** `sched_waking` or `sched_wakeup`.
  * Because [`tp_sched_process_fork` (`tracer_kernel.c:1206-1216`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1206-L1216) leaves `cctx->wakeup_ts = 0` and `cctx->prev_cpu_id = 0`, when the forked child thread is scheduled onto a CPU in `tp_sched_switch`, the guard `(nctx->wakeup_ts != 0 || nctx->off_cpu_enter_ts != 0)` at [`tracer_kernel.c:1299`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1299) evaluates to **FALSE**, completely dropping the child thread's initial `OSI_L6_PRE_COMPUTE` runqueue latency and CPU migration event!

---

#### 6. Critical Flaw #5: User-Space `correlate_and_symbolicate_sim_events` (`tracer_agent.py`) Hardcodes `tid == 10425`, Hardcodes `"execute_storage_query"`, Ignores `OSI_L6_PRE_COMPUTE` Off-CPU Events, and Hardcodes `sched_runq_ms` / `sched_lock_ms` in `run_tracer_pipeline`
* **Spec Contract ([`PROMPT_SPEC.md:716`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L716) & [`PROMPT_SPEC.md:925`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L925))**:
  * Requires `tracer_agent.py` to subtract direct child `OSI_L5_SYSCALL_MEM (6)` and `OSI_L6_PRE_COMPUTE (8)` wait events inside `[t_entry, t_return]` (or use the kernel-maintained `acc_off_cpu_ns` snapshot delta exported by `trace_uprobe_entry` / `trace_uprobe_return`) to separate `pure_on_cpu_compute_ms` and `off_cpu_io_wait_ms` for any traced function on any thread.
* **Actual Implementation in [`tracer_agent.py:746-785`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L746-L785)**:
  * At [`tracer_agent.py:747-751`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L747-L751):
    ```python
    worker_bio_ns = 0
    for ev in trace_events:
        meta = decode_event_metadata(ev)
        if int(ev.layer_type) == LAYER_USER_ENTRY and int(ev.call_depth) == OSI_L5_SYSCALL_MEM and int(ev.tid) == 10425:
            worker_bio_ns += int(ev.duration_ns)
    ```
  * And at [`tracer_agent.py:770`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L770):
    ```python
    off_cpu_ns = worker_bio_ns if resolved["symbol"] == "execute_storage_query" else 0
    ```
  * **Three Falsifications in `tracer_agent.py`**:
    1. **Mock-Pass Hardcoding of `tid == 10425` and `symbol == "execute_storage_query"`**: Any other worker thread TID (e.g., `20002`, `30001`, or forked child) or any other user function that sleeps on a mutex/condvar/futex (`OSI_L6_PRE_COMPUTE` at `call_depth > 0`) or performs Block I/O gets `off_cpu_ns = 0`!
    2. **Kernel Already Computes Exact Per-Function Off-CPU Delta via `fn_off_cpu_snap[depth]`**: Look at [`trace_uprobe_entry` (`tracer_kernel.c:1447-1461`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1447-L1461), which stores `tctx->fn_off_cpu_snap[depth] = tctx->acc_off_cpu_ns;` and emits `off_cpu_snap` in `ev.duration_ns` of the `LAYER_USER_ENTRY` event! However, [`trace_uprobe_return` (`tracer_kernel.c:1464-1509`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1464-L1509) never reads `tctx->acc_off_cpu_ns - tctx->fn_off_cpu_snap[depth]`, and `correlate_and_symbolicate_sim_events` completely ignores both `ev.duration_ns` on `LAYER_USER_ENTRY` and `OSI_L6_PRE_COMPUTE` events during `[t_entry, t_return]`!
    3. **Double-Counting Hazard Between `OSI_L5_SYSCALL_MEM` and `OSI_L6_PRE_COMPUTE` Inside `[t_entry, t_return]`**: In [`kernel_sim_harness.c:660-678`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L660-L678), while `execute_storage_query` is at `call_depth == 1`, the worker sleeps for `bio_ns` (`18,220,000 ns`). `block_rq_complete` emits `OSI_L5_SYSCALL_MEM` with `duration_ns = 18,220,000`, AND `sched_switch` emits `OSI_L6_PRE_COMPUTE` with `duration_ns = total_off_cpu_ns = 18,220,000`! Because `total_off_cpu_ns` (`now - off_cpu_enter_ts`) encompasses the entire sleep window of the Block I/O + post-wakeup runqueue latency (`runq_ns`), `OSI_L6_PRE_COMPUTE` (`total_off_cpu_ns`) is the **total Off-CPU time** of that function call, whereas `OSI_L5_SYSCALL_MEM` (`bio_ns`) is the Block I/O sub-component of that sleep!
    4. **Hardcoded `sched_runq_ms` and `sched_lock_ms` in [`run_tracer_pipeline` (`tracer_agent.py:1358-1363`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1358-L1363)**:
       * Lines 1359–1360 hardcode `sched_runq_ms = 0.065` and `sched_lock_ms = 0.115` instead of extracting them from the `OSI_L6_PRE_COMPUTE` event decoded in `c_harness_result["events"]` (`meta["lock_wait_ns"] / 1e6` and `ev.duration_ns / 1e6`)!

---

#### 7. Concrete Diff Recommendations

##### A. [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1327) — Fix `sys_exit_futex`, `sched_process_fork`, `sched_waking`, `sched_wakeup`, and `sched_switch`
```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -1173,16 +1173,30 @@ TRACEPOINT_PROBE(syscalls, sys_exit_futex)
         if (tctx) {
+            u64 now              = bpf_ktime_get_ns();
+            u8  cur_cpu          = (u8)bpf_get_smp_processor_id();
+            u64 wake_ts          = ring->slots[r_idx].wakeup_ts;
+            u64 runq_ns          = (wake_ts && now > wake_ts) ? (now - wake_ts) : 0;
+            u64 lock_wait_ns     = (saved_futex_ts && wake_ts > saved_futex_ts)
+                                       ? (wake_ts - saved_futex_ts)
+                                       : 0;
+            u64 capped_lock      = (lock_wait_ns > 0xFFFFFFFFULL) ? 0xFFFFFFFFULL : lock_wait_ns;
+            u64 encoded_ip       = (capped_lock << 16) |
+                                   (((u64)ring->slots[r_idx].prev_cpu_id & 0xff) << 8) |
+                                   ((u64)cur_cpu & 0xff);
+
             tctx->req_id         = ring->slots[r_idx].req_id;
-            tctx->futex_enter_ts = saved_futex_ts;
-            tctx->wakeup_ts      = ring->slots[r_idx].wakeup_ts;
+            tctx->futex_enter_ts = 0;
+            tctx->wakeup_ts      = 0;
             tctx->pid            = tgid;
             tctx->tid            = tid;
             tctx->parent_tid     = ring->slots[r_idx].waker_tid;
             tctx->saddr          = ring->slots[r_idx].saddr;
             tctx->daddr          = ring->slots[r_idx].daddr;
             tctx->sport          = ring->slots[r_idx].sport;
             tctx->dport          = ring->slots[r_idx].dport;
             tctx->prev_cpu_id    = ring->slots[r_idx].prev_cpu_id;
+            tctx->target_cpu_id  = cur_cpu;
             tctx->flags         |= FLAG_THREAD_HANDOFF;
+
+            emit_kray_event(
+                tctx->req_id, encoded_ip, now, runq_ns,
+                tctx->pid, tid, tctx->parent_tid,
+                tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
+                LAYER_USER_ENTRY, 0, OSI_L6_PRE_COMPUTE, tctx->flags);
         }
     }
     return 0;
 }
@@ -1206,10 +1220,12 @@ TRACEPOINT_PROBE(sched, sched_process_fork)
     if (cctx) {
         cctx->req_id     = pctx->req_id;
+        cctx->wakeup_ts  = bpf_ktime_get_ns();
         cctx->pid        = pctx->pid;
         cctx->tid        = child_tid;
         cctx->parent_tid = parent_tid;
         cctx->saddr      = pctx->saddr;
         cctx->daddr      = pctx->daddr;
         cctx->sport      = pctx->sport;
         cctx->dport      = pctx->dport;
+        cctx->prev_cpu_id = (u8)bpf_get_smp_processor_id();
         cctx->flags      = pctx->flags | FLAG_THREAD_HANDOFF;
     }
     return 0;
 }
@@ -1235,8 +1251,14 @@ TRACEPOINT_PROBE(sched, sched_waking)
     /* Preserve futex_enter_ts if worker thread already entered sys_enter_futex(FUTEX_WAIT) */
     struct tid_ctx_t *existing_tctx = active_ctx_map.lookup(&target_tid);
+    if (existing_tctx && existing_tctx->req_id != 0) {
+        /* Do not clobber a thread that is already actively tracing a request */
+        if (existing_tctx->req_id == wctx->req_id)
+            existing_tctx->wakeup_ts = bpf_ktime_get_ns();
+        return 0;
+    }
     u64 saved_futex_ts = existing_tctx ? existing_tctx->futex_enter_ts : 0;
@@ -1261,8 +1283,13 @@ TRACEPOINT_PROBE(sched, sched_waking)
         struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
         if (ring) {
-            u32 r_idx = ring->read_idx & 7;
-            if (ring->slots[r_idx].req_id == wctx->req_id && ring->slots[r_idx].claimed == 0) {
-                ring->slots[r_idx].claimed = 1;
-                ring->read_idx++;
+            #pragma unroll
+            for (int i = 0; i < 8; i++) {
+                u32 idx = (ring->read_idx + i) & 7;
+                if (ring->slots[idx].req_id == wctx->req_id && ring->slots[idx].claimed == 0) {
+                    ring->slots[idx].claimed = 1;
+                    if (i == 0)
+                        ring->read_idx++;
+                    break;
+                }
             }
         }
     }
@@ -1291,18 +1318,24 @@ TRACEPOINT_PROBE(sched, sched_switch)
     u32 prev_tid = (u32)args->prev_pid;
     u32 next_tid = (u32)args->next_pid;
     u64 now      = bpf_ktime_get_ns();
 
-    struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
-    if (pctx && pctx->req_id != 0) {
-        pctx->off_cpu_enter_ts = now;
-        pctx->prev_cpu_id      = (u8)bpf_get_smp_processor_id();
+    if (prev_tid > 0) {
+        struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
+        if (pctx && pctx->req_id != 0) {
+            pctx->off_cpu_enter_ts = now;
+            /* Preserve waker's prev_cpu_id if sched_waking already fired before switch-out */
+            if (pctx->wakeup_ts == 0)
+                pctx->prev_cpu_id = (u8)bpf_get_smp_processor_id();
+        }
     }
 
+    if (next_tid == 0)
+        return 0;
     struct tid_ctx_t *nctx = active_ctx_map.lookup(&next_tid);
     if (nctx && nctx->req_id != 0 && (nctx->wakeup_ts != 0 || nctx->off_cpu_enter_ts != 0)) {
         u8 cur_cpu = (u8)bpf_get_smp_processor_id();
         nctx->target_cpu_id = cur_cpu;
 
-        u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts) : 0;
+        /* If involuntarily preempted (wakeup_ts == 0, off_cpu_enter_ts != 0), entire wait is runqueue wait */
+        u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts)
+                                      : (nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : 0);
         u64 total_off_cpu_ns = nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : runq_ns;
```

##### B. [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L745-L785) — Remove Hardcoded `tid == 10425` / `"execute_storage_query"` and Extract Real Scheduler Wait Metrics
```diff
--- a/tracer_agent.py
+++ b/tracer_agent.py
@@ -744,12 +744,6 @@ def correlate_and_symbolicate_sim_events(
     fn_spans: list[dict[str, Any]] = []
     open_entries: dict[tuple[int, int], Any] = {}
 
-    worker_bio_ns = 0
-    for ev in trace_events:
-        meta = decode_event_metadata(ev)
-        if int(ev.layer_type) == LAYER_USER_ENTRY and int(ev.call_depth) == OSI_L5_SYSCALL_MEM and int(ev.tid) == 10425:
-            worker_bio_ns += int(ev.duration_ns)
-
     for ev in trace_events:
         ltype = int(ev.layer_type)
         tid = int(ev.tid)
@@ -767,8 +761,25 @@ def correlate_and_symbolicate_sim_events(
                 base_offset=base_load_offset,
             )
             total_dur_ns = int(ev.duration_ns)
-            off_cpu_ns = worker_bio_ns if resolved["symbol"] == "execute_storage_query" else 0
+            t_return = int(ev.timestamp_ns)
+            t_entry = t_return - total_dur_ns
+            sched_off_cpu_ns = 0
+            bio_off_cpu_ns = 0
+            for child_ev in trace_events:
+                if int(child_ev.tid) != tid or int(child_ev.layer_type) != LAYER_USER_ENTRY:
+                    continue
+                c_ts = int(child_ev.timestamp_ns)
+                if t_entry <= c_ts <= t_return:
+                    if int(child_ev.call_depth) == OSI_L6_PRE_COMPUTE:
+                        sched_off_cpu_ns += int(child_ev.duration_ns)
+                    elif int(child_ev.call_depth) == OSI_L5_SYSCALL_MEM:
+                        bio_off_cpu_ns += int(child_ev.duration_ns)
+            off_cpu_ns = max(sched_off_cpu_ns, bio_off_cpu_ns)
             on_cpu_ns = max(0, total_dur_ns - off_cpu_ns)
```
And in [`run_tracer_pipeline` (`tracer_agent.py:1358-1363`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1358-L1363), derive `sched_runq_ms` and `sched_lock_ms` from the pre-compute (`call_depth == OSI_L6_PRE_COMPUTE`) handoff event in `c_harness_result["events"]` when available, falling back to `0.065` / `0.115` only when no handoff event is present.
