/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * progs/tracer_l6_sched.bpf.c — Layer 6 Scheduler & Futex PreCompute Gate
 * ==============================================================================
 * Upstream References & Performance Standards:
 *   - BCC Libbpf Tools: [runqlat.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/bcc-libbpf-tools/libbpf-tools/runqlat.bpf.c), [wakeuptime.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/bcc-libbpf-tools/libbpf-tools/wakeuptime.bpf.c)
 *   - Brendan Gregg, "BPF Performance Tools", Chapter 6 (CPUs / Scheduler Latency & Wakeups)
 *   - Kernel Scheduler Subsystem: [rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/kernel/sched/core.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/)
 *   - 8-Slot Lock-Free FIFO Ring Handoff: [ebpf-production-postmortems-and-arm64-limits.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
 * ==============================================================================
 */

#include "kray_common.h"

TRACEPOINT_PROBE(syscalls, sys_enter_futex)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;
    u64 now  = bpf_ktime_get_ns();

#ifdef KRAY_BPF_CORE
    u32 cmd = ((u32)args->args[1]) & 0x7f;
#else
    u32 raw_op = args->op ? (u32)args->op : (u32)args->args[1];
    u32 cmd = raw_op & 0x7f;
#endif

    if (cmd == 0 || cmd == 9 || cmd == 6 || cmd == 11 || cmd == 13) {
        struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
        if (!tctx) {
            u32 target_pid = get_target_pid();
            if (target_pid != 0 && tgid != target_pid)
                return 0;
            u32 zero_idx = 0;
            struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
            if (!zero_template)
                return 0;
            active_ctx_map.update(&tid, zero_template);
            tctx = active_ctx_map.lookup(&tid);
            if (tctx) {
                tctx->pid = tgid;
                tctx->tid = tid;
            }
        }
        if (tctx)
            tctx->futex_enter_ts = now;
    } else if (cmd == 1 || cmd == 10 || cmd == 3 || cmd == 4 || cmd == 5 || cmd == 7 || cmd == 12) {
        struct tid_ctx_t *wctx = active_ctx_map.lookup(&tid);
        if (wctx && wctx->req_id != 0) {
            publish_handoff_slot(
                tgid, wctx->req_id, now, tid,
                wctx->saddr, wctx->daddr, wctx->sport, wctx->dport,
                (u8)bpf_get_smp_processor_id());
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_futex)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (args->ret < 0 && args->ret != -11) {
        if (tctx)
            tctx->futex_enter_ts = 0;
        return 0;
    }

    if (tctx && tctx->req_id != 0)
        return 0;

    u64 saved_futex_ts = tctx ? tctx->futex_enter_ts : 0;

    struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
    if (!ring)
        return 0;

    u32 r_idx = ring->read_idx & 7;
    if (ring->slots[r_idx].req_id != 0 && ring->slots[r_idx].claimed == 0 && ring->slots[r_idx].waker_tid != tid) {
        ring->slots[r_idx].claimed = 1;
        ring->read_idx++;

        u32 zero_idx = 0;
        struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
        if (!zero_template)
            return 0;
        active_ctx_map.update(&tid, zero_template);
        tctx = active_ctx_map.lookup(&tid);
        if (tctx) {
            tctx->req_id         = ring->slots[r_idx].req_id;
            tctx->futex_enter_ts = saved_futex_ts;
            tctx->wakeup_ts      = ring->slots[r_idx].wakeup_ts;
            tctx->pid            = tgid;
            tctx->tid            = tid;
            tctx->parent_tid     = ring->slots[r_idx].waker_tid;
            tctx->saddr          = ring->slots[r_idx].saddr;
            tctx->daddr          = ring->slots[r_idx].daddr;
            tctx->sport          = ring->slots[r_idx].sport;
            tctx->dport          = ring->slots[r_idx].dport;
            tctx->prev_cpu_id    = ring->slots[r_idx].prev_cpu_id;
            tctx->flags         |= FLAG_THREAD_HANDOFF;
        }
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_fork)
{
    u32 parent_tid = (u32)args->parent_pid;
    u32 child_tid  = (u32)args->child_pid;

    struct tid_ctx_t *pctx = active_ctx_map.lookup(&parent_tid);
    if (!pctx || pctx->req_id == 0)
        return 0;

    u32 zero_idx = 0;
    struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
    if (!zero_template)
        return 0;

    active_ctx_map.update(&child_tid, zero_template);
    struct tid_ctx_t *cctx = active_ctx_map.lookup(&child_tid);
    if (cctx) {
        cctx->req_id     = pctx->req_id;
        cctx->pid        = pctx->pid;
        cctx->tid        = child_tid;
        cctx->parent_tid = parent_tid;
        cctx->saddr      = pctx->saddr;
        cctx->daddr      = pctx->daddr;
        cctx->sport      = pctx->sport;
        cctx->dport      = pctx->dport;
        cctx->flags      = pctx->flags | FLAG_THREAD_HANDOFF;
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_waking)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u32 waker_tid = (u32)pid_tgid;
    u32 target_tid = (u32)args->pid;

    struct tid_ctx_t *wctx = active_ctx_map.lookup(&waker_tid);
    if (!wctx || wctx->req_id == 0 || waker_tid == target_tid)
        return 0;

    struct tid_ctx_t *existing_tctx = active_ctx_map.lookup(&target_tid);
    u64 saved_futex_ts = existing_tctx ? existing_tctx->futex_enter_ts : 0;

    u32 zero_idx = 0;
    struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
    if (!zero_template)
        return 0;

    active_ctx_map.update(&target_tid, zero_template);
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&target_tid);
    if (tctx) {
        u64 now = bpf_ktime_get_ns();
        tctx->req_id         = wctx->req_id;
        tctx->futex_enter_ts = saved_futex_ts;
        tctx->wakeup_ts      = now;
        tctx->pid            = tgid;
        tctx->tid            = target_tid;
        tctx->parent_tid     = waker_tid;
        tctx->saddr          = wctx->saddr;
        tctx->daddr          = wctx->daddr;
        tctx->sport          = wctx->sport;
        tctx->dport          = wctx->dport;
        tctx->prev_cpu_id    = (u8)bpf_get_smp_processor_id();
        tctx->flags          = FLAG_THREAD_HANDOFF;

        struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
        if (ring) {
            u32 r_idx = ring->read_idx & 7;
            if (ring->slots[r_idx].req_id == wctx->req_id && ring->slots[r_idx].claimed == 0) {
                ring->slots[r_idx].claimed = 1;
                ring->read_idx++;
            }
        }
    }
    return 0;
}

TRACEPOINT_PROBE(sched, sched_wakeup)
{
    u32 target_tid = (u32)args->pid;
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&target_tid);
    if (tctx && tctx->req_id != 0)
        tctx->wakeup_ts = bpf_ktime_get_ns();
    return 0;
}

TRACEPOINT_PROBE(sched, sched_switch)
{
    u32 prev_tid = (u32)args->prev_pid;
    u32 next_tid = (u32)args->next_pid;
    u64 now      = bpf_ktime_get_ns();

    struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
    if (pctx && pctx->req_id != 0) {
        pctx->off_cpu_enter_ts = now;
        pctx->prev_cpu_id      = (u8)bpf_get_smp_processor_id();
    }

    struct tid_ctx_t *nctx = active_ctx_map.lookup(&next_tid);
    if (nctx && nctx->req_id != 0 && (nctx->wakeup_ts != 0 || nctx->off_cpu_enter_ts != 0)) {
        u8 cur_cpu = (u8)bpf_get_smp_processor_id();
        nctx->target_cpu_id = cur_cpu;

        u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts) : 0;
        u64 total_off_cpu_ns = nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : runq_ns;
        u64 lock_wait_ns = (nctx->futex_enter_ts && nctx->wakeup_ts > nctx->futex_enter_ts)
                               ? (nctx->wakeup_ts - nctx->futex_enter_ts)
                               : 0;

        nctx->acc_off_cpu_ns += total_off_cpu_ns;
        u64 emit_dur = (nctx->call_depth == 0) ? runq_ns : total_off_cpu_ns;

        u64 capped_lock = (lock_wait_ns > 0xFFFFFFFFULL) ? 0xFFFFFFFFULL : lock_wait_ns;
        u64 encoded_ip = (capped_lock << 16) | (((u64)nctx->prev_cpu_id & 0xff) << 8) | ((u64)cur_cpu & 0xff);

        nctx->off_cpu_enter_ts = 0;
        nctx->wakeup_ts        = 0;
        nctx->futex_enter_ts   = 0;

        emit_kray_event(
            nctx->req_id, encoded_ip, now, emit_dur,
            nctx->pid, next_tid, nctx->parent_tid,
            nctx->saddr, nctx->daddr, nctx->sport, nctx->dport,
            LAYER_USER_ENTRY, 0, OSI_L6_PRE_COMPUTE, nctx->flags);
    }
    return 0;
}
