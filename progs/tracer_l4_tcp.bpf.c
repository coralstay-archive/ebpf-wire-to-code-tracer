/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * progs/tracer_l4_tcp.bpf.c — Layer 4 TCP/UDP/AF_UNIX Transport & Forensics
 * ==============================================================================
 * Upstream References & RFC Standards:
 *   - BCC Libbpf Tools: [tcpconnect.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/bcc-libbpf-tools/libbpf-tools/tcpconnect.bpf.c), [tcpretrans.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/bcc-libbpf-tools/libbpf-tools/tcpretrans.bpf.c)
 *   - Kernel TCP State Machine: [rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/net/ipv4/tcp.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/)
 *   - RFC 793 (Transmission Control Protocol), RFC 768 (User Datagram Protocol)
 *   - Defensive Hardening: [ebpf-production-postmortems-and-arm64-limits.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
 *     * SYN Epoch Rollover (Dynamic Ephemeral Port Reuse)
 *     * RST Immediate Eviction (Lingering State Elimination)
 *     * kfree_skb Drop Reason Code Interception
 * ==============================================================================
 */

#include "kray_common.h"

SEC("kprobe/tcp_v4_rcv")
int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (kprobe_enter_guard() < 0)
        return 0;
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb) {
        kprobe_exit_guard();
        return 0;
    }

    unsigned char *head = NULL;
    u16 net_off = 0;
    u16 trans_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    bpf_probe_read_kernel(&trans_off, sizeof(trans_off), &skb->transport_header);
    if (!head) {
        kprobe_exit_guard();
        return 0;
    }

    struct iphdr iph = {};
    struct tcphdr tcph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);

    u16 sport = bpf_ntohs(tcph.source);
    u16 dport = bpf_ntohs(tcph.dest);
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port) {
        kprobe_exit_guard();
        return 0;
    }

    struct flow_key_t key = {};
    key.saddr  = iph.saddr;
    key.daddr  = iph.daddr;
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_TCP;
    key.family = AF_INET;

    u64 now = bpf_ktime_get_ns();
    u8 tflags = extract_tcp_flags(&tcph);

    /* TCP RST Immediate Flow Eviction */
    if (tcph.rst || (tflags & 0x04)) {
        struct flow_state_t *rst_state = ingress_flow_map.lookup(&key);
        if (rst_state) {
            u64 rst_req_id = rst_state->req_id;
            u64 dur_ns = rst_state->ip_rcv_ts ? (now - rst_state->ip_rcv_ts) : 10000ULL;
            ingress_flow_map.delete(&key);
            u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
            u64 encoded_ip = ((u64)iph.ttl << 24) | ((u64)ihl_bytes << 16) | (u64)rst_state->pkt_len;
            emit_kray_event(
                rst_req_id, encoded_ip, now, dur_ns,
                0, 0, 0,
                key.saddr, key.daddr, sport, dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, tflags | 0x04);
        }
        kprobe_exit_guard();
        return 0;
    }

    u16 tot_len = bpf_ntohs(iph.tot_len);
    u16 ihl_len = (iph.ihl & 0x0f) * 4;
    u16 doff_len = (tcph.doff & 0x0f) * 4;
    u16 tcp_payload_len = (tot_len > (ihl_len + doff_len)) ? (tot_len - ihl_len - doff_len) : 0;

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (!state || (state->consumed == 1 && tcp_payload_len > 0)) {
        struct flow_state_t init_state = {};
        init_state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
        init_state.ip_rcv_ts = state ? state->ip_rcv_ts : now;
        init_state.pkt_len   = tot_len;
        init_state.tcp_flags = tflags;
        init_state.rx_cpu_id = (u8)bpf_get_smp_processor_id();
        init_state.consumed  = 0;
        ingress_flow_map.update(&key, &init_state);
        state = ingress_flow_map.lookup(&key);
        if (!state) {
            kprobe_exit_guard();
            return 0;
        }
    }

    u64 dur_ns = state->ip_rcv_ts ? (now - state->ip_rcv_ts) : 30000ULL;
    state->tcp_rcv_ts = now;
    state->tcp_flags  = tflags;
    u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
    u64 encoded_ip = ((u64)iph.ttl << 24) | ((u64)ihl_bytes << 16) | (u64)state->pkt_len;

    emit_kray_event(
        state->req_id, encoded_ip, now, dur_ns,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L4_TCP, tflags);
    kprobe_exit_guard();
    return 0;
}

SEC("kprobe/tcp_v6_rcv")
int kprobe__tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    if (kprobe_enter_guard() < 0)
        return 0;
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb) {
        kprobe_exit_guard();
        return 0;
    }
    unsigned char *head = NULL;
    u16 net_off = 0, trans_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    bpf_probe_read_kernel(&trans_off, sizeof(trans_off), &skb->transport_header);
    if (!head) {
        kprobe_exit_guard();
        return 0;
    }

    struct ipv6hdr ip6h = {};
    struct tcphdr tcph = {};
    bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + net_off);
    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);

    u16 sport = bpf_ntohs(tcph.source);
    u16 dport = bpf_ntohs(tcph.dest);
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port) {
        kprobe_exit_guard();
        return 0;
    }

    struct flow_key_t key = {};
    key.saddr  = fold_ipv6_addr32(ip6h.saddr.in6_u.u6_addr32);
    key.daddr  = fold_ipv6_addr32(ip6h.daddr.in6_u.u6_addr32);
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_TCP;
    key.family = AF_INET6;

    u64 now = bpf_ktime_get_ns();
    u8 tflags = extract_tcp_flags(&tcph);

    /* TCP RST Immediate Flow Eviction */
    if (tcph.rst || (tflags & 0x04)) {
        struct flow_state_t *rst_state = ingress_flow_map.lookup(&key);
        if (rst_state) {
            u64 rst_req_id = rst_state->req_id;
            ingress_flow_map.delete(&key);
            emit_kray_event(
                rst_req_id, (u64)(bpf_ntohs(ip6h.payload_len) + 40), now, 10000ULL,
                0, 0, 0,
                key.saddr, key.daddr, sport, dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, tflags | 0x04);
        }
        kprobe_exit_guard();
        return 0;
    }

    u16 payload_len = bpf_ntohs(ip6h.payload_len);
    u16 doff_len = (tcph.doff & 0x0f) * 4;
    u16 tcp_payload_len = (payload_len > doff_len) ? (payload_len - doff_len) : 0;

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (!state || (state->consumed == 1 && tcp_payload_len > 0)) {
        struct flow_state_t init_state = {};
        init_state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
        init_state.ip_rcv_ts = state ? state->ip_rcv_ts : now;
        init_state.pkt_len   = payload_len + 40;
        init_state.tcp_flags = tflags;
        init_state.rx_cpu_id = (u8)bpf_get_smp_processor_id();
        init_state.consumed  = 0;
        ingress_flow_map.update(&key, &init_state);
        state = ingress_flow_map.lookup(&key);
        if (!state) {
            kprobe_exit_guard();
            return 0;
        }
    }

    state->tcp_rcv_ts = now;
    state->tcp_flags  = tflags;
    u64 dur_ns = state->ip_rcv_ts ? (now - state->ip_rcv_ts) : 30000ULL;
    u64 encoded_ip = ((u64)ip6h.hop_limit << 24) | (40ULL << 16) | (u64)state->pkt_len;

    emit_kray_event(
        state->req_id, encoded_ip, now, dur_ns,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L4_TCP, tflags);
    kprobe_exit_guard();
    return 0;
}

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    u16 sport = args->sport;
    u16 dport = args->dport;
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port && sport != target_port)
        return 0;

    struct flow_key_t key = {};
    bpf_probe_read_kernel(&key.saddr, sizeof(u32), args->saddr);
    bpf_probe_read_kernel(&key.daddr, sizeof(u32), args->daddr);
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_TCP;
    key.family = AF_INET;

    struct flow_state_t *state = egress_flow_map.lookup(&key);
    if (!state)
        state = ingress_flow_map.lookup(&key);
    if (!state) {
        struct flow_key_t rev_key = key;
        rev_key.saddr = key.daddr;
        rev_key.daddr = key.saddr;
        rev_key.sport = key.dport;
        rev_key.dport = key.sport;
        state = ingress_flow_map.lookup(&rev_key);
        if (!state)
            state = egress_flow_map.lookup(&rev_key);
    }
    if (!state)
        return 0;

    state->retransmits++;
    u64 now = bpf_ktime_get_ns();
    emit_kray_event(
        state->req_id, (u64)state->retransmits, now, 0,
        state->pid, state->tid, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L4_TCP, state->tcp_flags | FLAG_TCP_RETRANSMIT);
    return 0;
}

TRACEPOINT_PROBE(skb, kfree_skb)
{
    if (args->reason <= 2)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 skb_ptr = (u64)args->skbaddr;

    /* Stage 1: Egress SKB pointer lookup */
    struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
    if (ekey) {
        struct flow_state_t *estate = egress_flow_map.lookup(ekey);
        if (estate) {
            emit_kray_event(
                estate->req_id, (u64)args->reason, now, 0,
                estate->pid, estate->tid, 0,
                ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
            return 0;
        }
    }

    /* Stage 2: Receiving socket pointer args->rx_sk */
    struct sock *rx_sk = (struct sock *)args->rx_sk;
    if (rx_sk) {
        struct flow_key_t sk_key = {};
        populate_sock_flow_key(rx_sk, &sk_key, IPPROTO_TCP, 0);
        struct flow_state_t *istate = ingress_flow_map.lookup(&sk_key);
        if (istate) {
            emit_kray_event(
                istate->req_id, (u64)args->reason, now, 0,
                istate->pid, istate->tid, 0,
                sk_key.saddr, sk_key.daddr, sk_key.sport, sk_key.dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
            return 0;
        }
    }

    /* Stage 3: Parse L3/L4 headers from (struct sk_buff *)args->skbaddr */
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (skb) {
        unsigned char *head = NULL;
        u16 net_off = 0;
        bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
        bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
        if (head) {
            struct iphdr iph = {};
            bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
            if ((iph.version & 0x0f) == 4 && iph.protocol == IPPROTO_TCP) {
                u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
                if (ihl_bytes >= sizeof(struct iphdr)) {
                    struct tcphdr tcph = {};
                    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + net_off + ihl_bytes);
                    struct flow_key_t ikey = {};
                    ikey.saddr  = iph.saddr;
                    ikey.daddr  = iph.daddr;
                    ikey.sport  = bpf_ntohs(tcph.source);
                    ikey.dport  = bpf_ntohs(tcph.dest);
                    ikey.proto  = IPPROTO_TCP;
                    ikey.family = AF_INET;
                    struct flow_state_t *istate = ingress_flow_map.lookup(&ikey);
                    if (istate) {
                        emit_kray_event(
                            istate->req_id, (u64)args->reason, now, 0,
                            istate->pid, istate->tid, 0,
                            ikey.saddr, ikey.daddr, ikey.sport, ikey.dport,
                            LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
                    }
                }
            }
        }
    }
    return 0;
}

SEC("kprobe/__tcp_transmit_skb")
int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
#ifdef KRAY_BPF_CORE
    sk  = (struct sock *)PT_REGS_PARM1(ctx);
    skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
#endif
    if (!sk || !skb)
        return 0;

    u16 local_port = 0;
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    u16 target_port = get_target_port();
    if (target_port != 0 && local_port != target_port)
        return 0;

    struct flow_key_t egress_key = {};
    populate_sock_flow_key(sk, &egress_key, IPPROTO_TCP, 1);

    struct flow_state_t *estate = egress_flow_map.lookup(&egress_key);
    if (!estate)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 dur_ns = estate->sendmsg_ts ? (now - estate->sendmsg_ts) : 35000ULL;
    estate->tcp_tx_ts = now;

    u64 skb_ptr = (u64)PT_REGS_PARM2(ctx);
    skb_egress_map.update(&skb_ptr, &egress_key);

    u64 encoded_ip = (64ULL << 24) | (20ULL << 16) | (u64)estate->pkt_len;
    emit_kray_event(
        estate->req_id, encoded_ip, now, dur_ns,
        estate->pid, estate->tid, 0,
        egress_key.saddr, egress_key.daddr, egress_key.sport, egress_key.dport,
        LAYER_EGRESS_NIC, 0, OSI_L4_TCP, FLAG_TCP_PSH | FLAG_TCP_ACK);
    return 0;
}

SEC("kprobe/udp_rcv")
int kprobe__udp_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb)
        return 0;
    unsigned char *head = NULL;
    u16 net_off = 0, trans_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    bpf_probe_read_kernel(&trans_off, sizeof(trans_off), &skb->transport_header);
    if (!head)
        return 0;

    struct iphdr iph = {};
    struct udphdr udph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
    bpf_probe_read_kernel(&udph, sizeof(udph), head + trans_off);

    u16 sport = bpf_ntohs(udph.source);
    u16 dport = bpf_ntohs(udph.dest);
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port)
        return 0;

    u64 now = bpf_ktime_get_ns();
    struct flow_key_t key = {};
    key.saddr  = iph.saddr;
    key.daddr  = iph.daddr;
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_UDP;
    key.family = AF_INET;

    struct flow_state_t state = {};
    state.req_id     = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
    state.tcp_rcv_ts = now;
    state.pkt_len    = bpf_ntohs(udph.len);
    ingress_flow_map.update(&key, &state);

    struct flow_key_t port_key = {};
    port_key.daddr  = 0;
    port_key.dport  = dport;
    port_key.proto  = IPPROTO_UDP;
    port_key.family = AF_INET;
    ingress_flow_map.update(&port_key, &state);

    emit_kray_event(
        state.req_id, (u64)state.pkt_len, now, 25000ULL,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_NONE);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
#ifdef KRAY_BPF_CORE
    sk  = (struct sock *)PT_REGS_PARM1(ctx);
    msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    len = (size_t)PT_REGS_PARM3(ctx);
#endif
    if (!sk)
        return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0)
        return 0;

    struct flow_key_t egress_key = {};
    populate_sock_flow_key(sk, &egress_key, IPPROTO_UDP, 1);

    if (egress_key.daddr == 0 && msg) {
        void *msg_name = NULL;
        bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
        if (msg_name) {
            u16 sin_port_be = 0;
            u32 sin_addr = 0;
            bpf_probe_read_kernel(&sin_port_be, sizeof(sin_port_be), (void *)((u64)msg_name + 2));
            bpf_probe_read_kernel(&sin_addr, sizeof(sin_addr), (void *)((u64)msg_name + 4));
            egress_key.daddr = sin_addr;
            egress_key.dport = bpf_ntohs(sin_port_be);
        }
    }
    if (egress_key.daddr == 0 && tctx->saddr != 0)
        egress_key.daddr = tctx->saddr;
    if (egress_key.dport == 0 && tctx->sport != 0)
        egress_key.dport = tctx->sport;
    if (egress_key.saddr == 0 && tctx->daddr != 0)
        egress_key.saddr = tctx->daddr;
    if (egress_key.sport == 0 && tctx->dport != 0)
        egress_key.sport = tctx->dport;

    u64 now = bpf_ktime_get_ns();
    struct flow_state_t estate = {};
    estate.req_id     = tctx->req_id;
    estate.sendmsg_ts = now;
    estate.pid        = tgid;
    estate.tid        = tid;
    estate.pkt_len    = (u16)len;
    egress_flow_map.update(&egress_key, &estate);

    emit_kray_event(
        tctx->req_id, (u64)len, now, 20000ULL,
        tgid, tid, tctx->parent_tid,
        egress_key.saddr, egress_key.daddr, egress_key.sport, egress_key.dport,
        LAYER_USER_EXIT, 0, OSI_L4_SOCKET, tctx->flags);
    return 0;
}

SEC("kprobe/unix_stream_recvmsg")
int kprobe__unix_stream_recvmsg(struct pt_regs *ctx, struct socket *sock)
{
#ifdef KRAY_BPF_CORE
    sock = (struct socket *)PT_REGS_PARM1(ctx);
#endif
    if (!sock)
        return 0;
    struct sock *sk = NULL;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
    if (!sk)
        return 0;

    struct unix_sock *usk = (struct unix_sock *)sk;
    struct sock *peer = NULL;
    bpf_probe_read_kernel(&peer, sizeof(peer), &usk->peer);

    struct flow_key_t key = {};
    key.saddr  = (u32)(u64)peer;
    key.daddr  = (u32)(u64)sk;
    key.proto  = PROTO_UNIX_TAG;
    key.family = AF_UNIX;

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (state) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = (u32)(pid_tgid >> 32);
        u32 tid  = (u32)pid_tgid;
        u64 now  = bpf_ktime_get_ns();
        state->consumed = 1;

        u32 zero_idx = 0;
        struct tid_ctx_t *zero_template = zero_ctx_map.lookup(&zero_idx);
        if (zero_template) {
            active_ctx_map.update(&tid, zero_template);
            struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
            if (tctx) {
                tctx->req_id        = state->req_id;
                tctx->last_stage_ts = now;
                tctx->pid           = tgid;
                tctx->tid           = tid;
                tctx->saddr         = key.saddr;
                tctx->daddr         = key.daddr;
            }
        }

        emit_kray_event(
            state->req_id, (u64)state->pkt_len, now, now - state->sendmsg_ts,
            tgid, tid, 0,
            key.saddr, key.daddr, 0, 0,
            LAYER_USER_ENTRY, 0, OSI_L4_SOCKET, FLAG_NONE);
    }
    return 0;
}

SEC("kprobe/unix_stream_sendmsg")
int kprobe__unix_stream_sendmsg(struct pt_regs *ctx, struct socket *sock)
{
#ifdef KRAY_BPF_CORE
    sock = (struct socket *)PT_REGS_PARM1(ctx);
#endif
    if (!sock)
        return 0;
    struct sock *sk = NULL;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
    if (!sk)
        return 0;

    struct unix_sock *usk = (struct unix_sock *)sk;
    struct sock *peer = NULL;
    bpf_probe_read_kernel(&peer, sizeof(peer), &usk->peer);

    struct flow_key_t key = {};
    key.saddr  = (u32)(u64)sk;
    key.daddr  = (u32)(u64)peer;
    key.proto  = PROTO_UNIX_TAG;
    key.family = AF_UNIX;

    u64 now = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);

    struct flow_state_t state = {};
    state.req_id     = (tctx && tctx->req_id != 0) ? tctx->req_id : (((now & 0xFFFFFFFFULL) << 16) ^ (u64)key.saddr);
    state.sendmsg_ts = now;
    state.pkt_len    = 128;
    ingress_flow_map.update(&key, &state);
    return 0;
}
