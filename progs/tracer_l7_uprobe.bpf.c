/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * progs/tracer_l7_uprobe.bpf.c — Layer 7 User Function Call Tree & ALU Shadow Stack
 * ==============================================================================
 * Upstream References & Hardware Architecture:
 *   - Libbpf-bootstrap Uprobe Pattern: [uprobe.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/libbpf-bootstrap/examples/c/uprobe.bpf.c)
 *   - BCC Uprobe Helpers: [uprobe_helpers.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/bcc-libbpf-tools/libbpf-tools/uprobe_helpers.c)
 *   - Brendan Gregg, "BPF Performance Tools", Chapter 12 (Application Probing & Symbolication)
 *   - ARM64 Hardware Uprobe Execution: [ebpf-production-postmortems-and-arm64-limits.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
 *     * ARM64 BRK #0x004 trapping vs x86 INT3 (0xCC)
 *     * 16-Slot Per-CPU Shadow Stack (512B BPF stack overflow immunity)
 *     * Uretprobe Trampoline ([uprobes]) Return IP Restoration
 * ==============================================================================
 */

#include "kray_common.h"

SEC("uprobe")
int trace_uprobe_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0) {
        u64 saved_futex_ts = tctx ? tctx->futex_enter_ts : 0;
        struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
        if (!ring)
            return 0;
        u32 r_idx = ring->read_idx & 7;
        if (ring->slots[r_idx].req_id == 0 || ring->slots[r_idx].claimed != 0 || ring->slots[r_idx].waker_tid == tid)
            return 0;

        ring->slots[r_idx].claimed = 1;
        ring->read_idx++;

        u32 zero_idx = 0;
        struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
        if (!zero_template)
            return 0;
        active_ctx_map.update(&tid, zero_template);
        tctx = active_ctx_map.lookup(&tid);
        if (!tctx)
            return 0;

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

    u64 now = bpf_ktime_get_ns();
    u64 entry_ip = PT_REGS_IP(ctx);
    u8 raw_depth = tctx->call_depth;
    u64 off_cpu_snap = tctx->acc_off_cpu_ns;

    /* Adaptive Uprobe Rate-Limiting Guard:
     * Track call rate across 1-second window (1,000,000,000 ns).
     * If call frequency exceeds 10,000 calls/sec, guard against CPU spike
     * and application latency collapse by throttling telemetry emission. */
    u32 zero_rate_idx = 0;
    bool throttle_uprobe = false;
    struct uprobe_rate_limiter_t *rate_limiter = uprobe_rate_limit_map.lookup(&zero_rate_idx);
    if (rate_limiter) {
        if (now - rate_limiter->window_start_ns >= 1000000000ULL) {
            rate_limiter->window_start_ns = now;
            rate_limiter->call_count = 1;
            rate_limiter->throttle_active = 0;
        } else {
            rate_limiter->call_count++;
            if (rate_limiter->call_count > 10000) {
                rate_limiter->throttle_active = 1;
                throttle_uprobe = true;
            }
        }
    }

    if (raw_depth < MAX_CALL_DEPTH) {
        u32 slot = raw_depth;
        asm volatile("" : "+r"(slot));
        slot &= (MAX_CALL_DEPTH - 1);
        tctx->fn_entry_ip[slot]     = entry_ip;
        tctx->fn_entry_ts[slot]     = now;
        tctx->fn_off_cpu_snap[slot] = off_cpu_snap;
    }
    if (tctx->call_depth < 255)
        tctx->call_depth++;

    if (!throttle_uprobe) {
        u8 report_depth = (raw_depth < MAX_CALL_DEPTH) ? raw_depth : (MAX_CALL_DEPTH - 1);
        emit_kray_event(
            tctx->req_id, entry_ip, now, off_cpu_snap,
            tgid, tid, tctx->parent_tid,
            tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
            LAYER_USER_FUNC, 0, report_depth, tctx->flags);
    }
    return 0;
}

SEC("uretprobe")
int trace_uprobe_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0)
        return 0;

    if (tctx->call_depth == 0)
        return 0;

    u32 zero_rate_idx = 0;
    struct uprobe_rate_limiter_t *rate_limiter = uprobe_rate_limit_map.lookup(&zero_rate_idx);
    if (rate_limiter && rate_limiter->throttle_active) {
        tctx->call_depth--;
        return 0;
    }

    tctx->call_depth--;
    u8 raw_depth = tctx->call_depth;
    u32 slot = raw_depth & (MAX_CALL_DEPTH - 1);
    u64 now = bpf_ktime_get_ns();
    u64 saved_ts = tctx->fn_entry_ts[slot];
    u64 orig_ip = (raw_depth < MAX_CALL_DEPTH) ? tctx->fn_entry_ip[slot] : 0;
    u64 fn_dur  = (raw_depth < MAX_CALL_DEPTH) ? (now - saved_ts) : 0;

    u8 report_depth = (raw_depth < MAX_CALL_DEPTH) ? raw_depth : (MAX_CALL_DEPTH - 1);
    emit_kray_event(
        tctx->req_id, orig_ip, now, fn_dur,
        tgid, tid, tctx->parent_tid,
        tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
        LAYER_USER_FUNC, 1, report_depth, tctx->flags);
    return 0;
}
