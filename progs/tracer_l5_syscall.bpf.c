/* SPDX-License-Identifier: GPL-2.0 */
/*
 * progs/tracer_l5_syscall.bpf.c — Layer 5 Syscall, Socket Queues, MM Faults & Block I/O
 * Grounded in Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)
 * References:
 *   - references/bcc-libbpf-tools/libbpf-tools/syscount.bpf.c
 *   - references/bcc-libbpf-tools/libbpf-tools/biolatency.bpf.c
 *   - references/bcc-libbpf-tools/libbpf-tools/biosnoop.bpf.c
 */

#include "kray_common.h"

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
#ifdef KRAY_BPF_CORE
    sk  = (struct sock *)PT_REGS_PARM1(ctx);
    msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    len = (size_t)PT_REGS_PARM3(ctx);
#endif
    if (!sk)
        return 0;

    u16 local_port = 0;
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    u16 target_port = get_target_port();
    if (target_port != 0 && local_port != target_port)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    u32 zero_idx = 0;
    struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
    if (!zero_template)
        return 0;

    struct tid_ctx_t *existing_ctx = active_ctx_map.lookup(&tid);
    u64 saved_epoll_wait_ns = existing_ctx ? existing_ctx->epoll_wait_ns : 0;
    u32 saved_epoll_ready_rem = existing_ctx ? existing_ctx->epoll_ready_rem : 0;

    active_ctx_map.update(&tid, zero_template);
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx)
        return 0;

    tctx->pid = tgid;
    tctx->tid = tid;
    tctx->active_sk_ptr = (u64)sk;
    tctx->epoll_wait_ns = saved_epoll_wait_ns;
    tctx->epoll_ready_rem = saved_epoll_ready_rem;

    struct flow_key_t key = {};
    populate_sock_flow_key(sk, &key, IPPROTO_TCP, 0);

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (state && state->consumed == 0) {
        u64 now = bpf_ktime_get_ns();
        state->consumed = 1;
        state->pid      = tgid;
        state->tid      = tid;
        tctx->req_id        = state->req_id;
        tctx->last_stage_ts = now;
        tctx->saddr         = key.saddr;
        tctx->daddr         = key.daddr;
        tctx->sport         = key.sport;
        tctx->dport         = key.dport;

        u64 dwell_ns = state->tcp_rcv_ts ? (now - state->tcp_rcv_ts) : 100000ULL;
        publish_handoff_slot(
            tgid, state->req_id, now, tid,
            key.saddr, key.daddr, key.sport, key.dport,
            (u8)bpf_get_smp_processor_id());

        emit_kray_event(
            state->req_id, (u64)state->pkt_len, now, dwell_ns,
            tgid, tid, 0,
            key.saddr, key.daddr, key.sport, key.dport,
            LAYER_USER_ENTRY, 0, OSI_L4_SOCKET, state->tcp_flags);
    }
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe__tcp_recvmsg(struct pt_regs *ctx)
{
    int copied = (int)PT_REGS_RC(ctx);
    if (copied <= 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || !tctx->active_sk_ptr)
        return 0;

    if (tctx->req_id == 0) {
        struct sock *sk = (struct sock *)tctx->active_sk_ptr;
        struct flow_key_t key = {};
        populate_sock_flow_key(sk, &key, IPPROTO_TCP, 0);

        struct flow_state_t *state = ingress_flow_map.lookup(&key);
        if (state && state->consumed == 0) {
            u64 now = bpf_ktime_get_ns();
            state->consumed = 1;
            state->pid      = tgid;
            state->tid      = tid;
            tctx->req_id        = state->req_id;
            tctx->last_stage_ts = now;
            tctx->saddr         = key.saddr;
            tctx->daddr         = key.daddr;
            tctx->sport         = key.sport;
            tctx->dport         = key.dport;

            u64 dwell_ns = state->tcp_rcv_ts ? (now - state->tcp_rcv_ts) : 100000ULL;
            publish_handoff_slot(
                tgid, state->req_id, now, tid,
                key.saddr, key.daddr, key.sport, key.dport,
                (u8)bpf_get_smp_processor_id());

            emit_kray_event(
                state->req_id, (u64)copied, now, dwell_ns,
                tgid, tid, 0,
                key.saddr, key.daddr, key.sport, key.dport,
                LAYER_USER_ENTRY, 0, OSI_L4_SOCKET, state->tcp_flags);
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx && tctx->copy_enter_ts == 0)
        tctx->copy_enter_ts = bpf_ktime_get_ns();
    return 0;
}

TRACEPOINT_PROBE(skb, skb_copy_datagram_iovec)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx)
        return 0;

    if (tctx->copy_enter_ts == 0)
        tctx->copy_enter_ts = bpf_ktime_get_ns();
    tctx->copied_bytes += (u16)args->len;
    return 0;
}

SEC("kretprobe/skb_copy_datagram_iter")
int kretprobe__skb_copy_datagram_iter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->copy_enter_ts == 0)
        return 0;

    if (tctx->req_id == 0 && tctx->active_sk_ptr != 0) {
        struct sock *sk = (struct sock *)tctx->active_sk_ptr;
        struct flow_key_t key = {};
        populate_sock_flow_key(sk, &key, IPPROTO_TCP, 0);
        struct flow_state_t *state = ingress_flow_map.lookup(&key);
        if (state && state->consumed == 0) {
            u64 bind_now = tctx->copy_enter_ts;
            state->consumed     = 1;
            state->pid          = tgid;
            state->tid          = tid;
            tctx->req_id        = state->req_id;
            tctx->last_stage_ts = bind_now;
            tctx->saddr         = key.saddr;
            tctx->daddr         = key.daddr;
            tctx->sport         = key.sport;
            tctx->dport         = key.dport;

            u64 dwell_ns = (state->tcp_rcv_ts && bind_now > state->tcp_rcv_ts)
                               ? (bind_now - state->tcp_rcv_ts)
                               : 100000ULL;
            publish_handoff_slot(
                tgid, state->req_id, bind_now, tid,
                key.saddr, key.daddr, key.sport, key.dport,
                (u8)bpf_get_smp_processor_id());

            emit_kray_event(
                state->req_id, (u64)tctx->copied_bytes, bind_now, dwell_ns,
                tgid, tid, 0,
                key.saddr, key.daddr, key.sport, key.dport,
                LAYER_USER_ENTRY, 0, OSI_L4_SOCKET, state->tcp_flags);
        }
    }

    if (tctx->req_id == 0)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 copy_dur = now - tctx->copy_enter_ts;
    u64 encoded_ip = ((u64)tctx->page_faults << 32) | (u64)tctx->copied_bytes;
    tctx->copy_enter_ts = 0;

    emit_kray_event(
        tctx->req_id, encoded_ip, now, copy_dur,
        tgid, tid, tctx->parent_tid,
        tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
        LAYER_USER_ENTRY, 0, OSI_L5_SYSCALL_MEM, tctx->flags);
    return 0;
}

SEC("kprobe/handle_mm_fault")
int kprobe__handle_mm_fault(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx)
        tctx->page_faults++;
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_epoll_pwait)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;
    u64 now  = bpf_ktime_get_ns();

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
    if (tctx) {
        tctx->epoll_enter_ts = now;
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_epoll_pwait)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->epoll_enter_ts == 0)
        return 0;

    if (args->ret <= 0) {
        tctx->epoll_enter_ts  = 0;
        tctx->epoll_wait_ns   = 0;
        tctx->epoll_ready_rem = 0;
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    tctx->epoll_wait_ns   = (now > tctx->epoll_enter_ts) ? (now - tctx->epoll_enter_ts) : 0;
    tctx->epoll_ready_rem = (u32)args->ret;
    tctx->epoll_enter_ts  = 0;
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_epoll_wait)
{
    return tracepoint__syscalls__sys_enter_epoll_pwait((tp_args_syscalls_sys_enter_epoll_pwait_t *)args);
}

TRACEPOINT_PROBE(syscalls, sys_exit_epoll_wait)
{
    return tracepoint__syscalls__sys_exit_epoll_pwait((tp_args_syscalls_sys_exit_epoll_pwait_t *)args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_write)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx && tctx->req_id != 0)
        tctx->last_stage_ts = bpf_ktime_get_ns();
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write)
{
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
#ifdef KRAY_BPF_CORE
    sk   = (struct sock *)PT_REGS_PARM1(ctx);
    msg  = (struct msghdr *)PT_REGS_PARM2(ctx);
    size = (size_t)PT_REGS_PARM3(ctx);
#endif
    if (!sk)
        return 0;

    u16 local_port = 0;
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    u16 target_port = get_target_port();
    if (target_port != 0 && local_port != target_port)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0)
        return 0;

    tctx->in_target_sendmsg = 1;

    struct flow_key_t egress_key = {};
    populate_sock_flow_key(sk, &egress_key, IPPROTO_TCP, 1);

    u64 now = bpf_ktime_get_ns();
    u64 dur_ns = (tctx->last_stage_ts && now > tctx->last_stage_ts) ? (now - tctx->last_stage_ts) : 25000ULL;
    struct flow_state_t estate = {};
    estate.req_id     = tctx->req_id;
    estate.sendmsg_ts = now;
    estate.pid        = tgid;
    estate.tid        = tid;
    estate.pkt_len    = (u16)size;
    egress_flow_map.update(&egress_key, &estate);

    emit_kray_event(
        tctx->req_id, (u64)size, now, dur_ns,
        tgid, tid, tctx->parent_tid,
        egress_key.saddr, egress_key.daddr, egress_key.sport, egress_key.dport,
        LAYER_USER_EXIT, 0, OSI_L4_SOCKET, tctx->flags);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx && tctx->in_target_sendmsg == 1)
        active_ctx_map.delete(&tid);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
#ifdef KRAY_BPF_CORE
    sk  = (struct sock *)PT_REGS_PARM1(ctx);
    msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    len = (size_t)PT_REGS_PARM3(ctx);
#endif
    if (!sk || !msg)
        return 0;
    u16 local_port = 0;
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    u16 target_port = get_target_port();
    if (target_port != 0 && local_port != target_port)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    u32 zero_idx = 0;
    struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
    if (!zero_template)
        return 0;
    active_ctx_map.update(&tid, zero_template);
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx)
        return 0;

    u32 loc_ip4 = 0;
    bpf_probe_read_kernel(&loc_ip4, sizeof(loc_ip4), &sk->__sk_common.skc_rcv_saddr);
    void *msg_name = NULL;
    bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
    tctx->pid             = tgid;
    tctx->tid             = tid;
    tctx->daddr           = loc_ip4;
    tctx->dport           = local_port;
    tctx->active_sk_ptr   = (u64)sk;
    tctx->active_msg_name = (u64)msg_name;
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int kretprobe__udp_recvmsg(struct pt_regs *ctx)
{
    int copied = (int)PT_REGS_RC(ctx);
    if (copied <= 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx)
        return 0;

    struct flow_key_t key = {};
    key.daddr  = tctx->daddr;
    key.dport  = tctx->dport;
    key.proto  = IPPROTO_UDP;
    key.family = AF_INET;

    if (tctx->active_msg_name != 0) {
        u16 sin_port_be = 0;
        u32 sin_addr = 0;
        bpf_probe_read_kernel(&sin_port_be, sizeof(sin_port_be), (void *)(tctx->active_msg_name + 2));
        bpf_probe_read_kernel(&sin_addr, sizeof(sin_addr), (void *)(tctx->active_msg_name + 4));
        key.saddr = sin_addr;
        key.sport = bpf_ntohs(sin_port_be);
    }

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (!state) {
        struct flow_key_t port_key = {};
        port_key.daddr  = 0;
        port_key.dport  = tctx->dport;
        port_key.proto  = IPPROTO_UDP;
        port_key.family = AF_INET;
        state = ingress_flow_map.lookup(&port_key);
    }
    if (state) {
        u64 now = bpf_ktime_get_ns();
        state->consumed = 1;
        tctx->req_id    = state->req_id;
        tctx->saddr     = key.saddr;
        tctx->sport     = key.sport;
        u64 dwell_ns = state->tcp_rcv_ts ? (now - state->tcp_rcv_ts) : 50000ULL;
        emit_kray_event(
            state->req_id, (u64)copied, now, dwell_ns,
            tgid, tid, 0,
            key.saddr, key.daddr, key.sport, key.dport,
            LAYER_USER_ENTRY, 0, OSI_L4_SOCKET, FLAG_NONE);
    }
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_insert)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0)
        return 0;

    struct bio_key_t bkey = {};
    bkey.dev    = args->dev;
    bkey.sector = args->sector;

    struct bio_state_t bstate = {};
    bstate.issue_ts = bpf_ktime_get_ns();
    bstate.req_id   = tctx->req_id;
    bstate.tid      = tid;
    bstate.bytes    = (u32)args->nr_sector * 512;
    inflight_bio_map.update(&bkey, &bstate);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_issue)
{
    struct bio_key_t bkey = {};
    bkey.dev    = args->dev;
    bkey.sector = args->sector;

    struct bio_state_t *existing = inflight_bio_map.lookup(&bkey);
    if (existing) {
        existing->issue_ts = bpf_ktime_get_ns();
        return 0;
    }

    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0)
        return 0;

    struct bio_state_t bstate = {};
    bstate.issue_ts = bpf_ktime_get_ns();
    bstate.req_id   = tctx->req_id;
    bstate.tid      = tid;
    bstate.bytes    = (u32)args->nr_sector * 512;
    inflight_bio_map.update(&bkey, &bstate);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete)
{
    struct bio_key_t bkey = {};
    bkey.dev    = args->dev;
    bkey.sector = args->sector;

    struct bio_state_t *bstate = inflight_bio_map.lookup(&bkey);
    if (!bstate)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 bio_dur = now - bstate->issue_ts;
    u64 bio_bytes = (u64)args->nr_sector * 512;

    u32 orig_tid = bstate->tid;
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&orig_tid);
    if (tctx) {
        tctx->acc_block_io_ns += bio_dur;
        u64 encoded_ip = ((u64)tctx->page_faults << 32) | bio_bytes;
        emit_kray_event(
            bstate->req_id, encoded_ip, now, bio_dur,
            tctx->pid, orig_tid, tctx->parent_tid,
            tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
            LAYER_USER_ENTRY, 0, OSI_L5_SYSCALL_MEM, tctx->flags);
    }
    inflight_bio_map.delete(&bkey);
    return 0;
}
