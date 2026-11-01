/* SPDX-License-Identifier: GPL-2.0 */
/*
 * progs/tracer_l3_ip.bpf.c — Layer 3 IPv4/IPv6 Routing & Protocol Telemetry
 * Grounded in Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)
 * References:
 *   - tools/testing/selftests/bpf/progs/test_tc_tunnel.c
 *   - references/bcc-libbpf-tools/libbpf-tools/tcptracer.bpf.c
 */

#include "kray_common.h"

SEC("kprobe/ip_rcv")
int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb)
        return 0;

    unsigned char *head = NULL;
    u16 net_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    if (!head)
        return 0;

    struct iphdr iph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
    if ((iph.version & 0x0f) != 4 || iph.protocol != IPPROTO_TCP)
        return 0;

    u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
    if (ihl_bytes < sizeof(struct iphdr))
        return 0;
    if ((bpf_ntohs(iph.frag_off) & 0x1FFF) != 0)
        return 0;

    u16 trans_off = net_off + ihl_bytes;
    struct tcphdr tcph = {};
    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);
    u16 doff_len = (tcph.doff & 0x0f) * 4;
    if (doff_len < sizeof(struct tcphdr))
        return 0;

    u16 sport = bpf_ntohs(tcph.source);
    u16 dport = bpf_ntohs(tcph.dest);
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port)
        return 0;

    struct flow_key_t key = {};
    key.saddr  = iph.saddr;
    key.daddr  = iph.daddr;
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_TCP;
    key.family = AF_INET;

    u64 now = bpf_ktime_get_ns();
    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (!state)
        return 0;

    u64 dur_ns = state->xdp_ts ? (now - state->xdp_ts) : 20000ULL;
    state->ip_rcv_ts = now;
    u64 encoded_ip = ((u64)iph.ttl << 24) | ((u64)ihl_bytes << 16) | (u64)state->pkt_len;

    emit_kray_event(
        state->req_id, encoded_ip, now, dur_ns,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L3_IP, state->tcp_flags);
    return 0;
}

SEC("kprobe/ipv6_rcv")
int kprobe__ipv6_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb)
        return 0;
    unsigned char *head = NULL;
    u16 net_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    if (!head)
        return 0;

    struct ipv6hdr ip6h = {};
    bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + net_off);

    u8 nexthdr = ip6h.nexthdr;
    u16 trans_off = net_off + sizeof(struct ipv6hdr);
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
            u8 ext_hdr[2] = {};
            bpf_probe_read_kernel(ext_hdr, sizeof(ext_hdr), head + trans_off);
            nexthdr = ext_hdr[0];
            trans_off += (u16)(ext_hdr[1] + 1) * 8;
        } else if (nexthdr == 44) {
            u8 frag_hdr[4] = {};
            bpf_probe_read_kernel(frag_hdr, sizeof(frag_hdr), head + trans_off);
            nexthdr = frag_hdr[0];
            u16 frag_off = ((u16)frag_hdr[2] << 8) | frag_hdr[3];
            if ((frag_off & 0xFFF8) != 0)
                return 0;
            trans_off += 8;
        } else if (nexthdr == 51) {
            u8 ah_hdr[2] = {};
            bpf_probe_read_kernel(ah_hdr, sizeof(ah_hdr), head + trans_off);
            nexthdr = ah_hdr[0];
            trans_off += (u16)(ah_hdr[1] + 2) * 4;
        }
    }
    if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
        return 0;

    u16 ports[2] = {};
    bpf_probe_read_kernel(ports, sizeof(ports), head + trans_off);
    u16 sport = bpf_ntohs(ports[0]);
    u16 dport = bpf_ntohs(ports[1]);
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port)
        return 0;

    struct flow_key_t key = {};
    key.saddr  = fold_ipv6_addr32(ip6h.saddr.in6_u.u6_addr32);
    key.daddr  = fold_ipv6_addr32(ip6h.daddr.in6_u.u6_addr32);
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = nexthdr;
    key.family = AF_INET6;

    u64 now = bpf_ktime_get_ns();
    struct flow_state_t state = {};
    state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
    state.ip_rcv_ts = now;
    state.pkt_len   = bpf_ntohs(ip6h.payload_len) + 40;
    ingress_flow_map.update(&key, &state);

    emit_kray_event(
        state.req_id, ((u64)ip6h.hop_limit << 24) | (40ULL << 16) | state.pkt_len, now, 20000ULL,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L3_IP, FLAG_NONE);
    return 0;
}

SEC("kprobe/ip_output")
int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    u64 skb_ptr = (u64)PT_REGS_PARM3(ctx);
    struct flow_key_t fallback_key = {};
    struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
    if (!ekey) {
        struct sock *sk_arg = (struct sock *)PT_REGS_PARM2(ctx);
        if (!sk_arg)
            return 0;
        populate_sock_flow_key(sk_arg, &fallback_key, IPPROTO_TCP, 1);
        u16 target_port = get_target_port();
        if (target_port != 0 && fallback_key.sport != target_port)
            return 0;
        ekey = &fallback_key;
        skb_egress_map.update(&skb_ptr, ekey);
    }

    struct flow_state_t *estate = egress_flow_map.lookup(ekey);
    if (!estate)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 dur_ns = estate->tcp_tx_ts ? (now - estate->tcp_tx_ts) : 25000ULL;
    estate->ip_out_ts = now;

    u64 encoded_ip = (64ULL << 24) | (20ULL << 16) | (u64)estate->pkt_len;
    emit_kray_event(
        estate->req_id, encoded_ip, now, dur_ns,
        estate->pid, estate->tid, 0,
        ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
        LAYER_EGRESS_NIC, 0, OSI_L3_IP, FLAG_TCP_PSH | FLAG_TCP_ACK);
    return 0;
}

SEC("kprobe/ip6_output")
int kprobe__ip6_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    u64 skb_ptr = (u64)PT_REGS_PARM3(ctx);
    struct flow_key_t fallback_key = {};
    struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
    if (!ekey) {
        struct sock *sk_arg = (struct sock *)PT_REGS_PARM2(ctx);
        if (!sk_arg)
            return 0;
        populate_sock_flow_key(sk_arg, &fallback_key, IPPROTO_TCP, 1);
        u16 target_port = get_target_port();
        if (target_port != 0 && fallback_key.sport != target_port)
            return 0;
        ekey = &fallback_key;
        skb_egress_map.update(&skb_ptr, ekey);
    }

    struct flow_state_t *estate = egress_flow_map.lookup(ekey);
    if (!estate)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 dur_ns = estate->tcp_tx_ts ? (now - estate->tcp_tx_ts) : 25000ULL;
    estate->ip_out_ts = now;

    u64 encoded_ip = (64ULL << 24) | (40ULL << 16) | (u64)estate->pkt_len;
    emit_kray_event(
        estate->req_id, encoded_ip, now, dur_ns,
        estate->pid, estate->tid, 0,
        ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
        LAYER_EGRESS_NIC, 0, OSI_L3_IP, FLAG_TCP_PSH | FLAG_TCP_ACK);
    return 0;
}

SEC("kprobe/icmp_rcv")
int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb)
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
    struct icmphdr icmph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
    bpf_probe_read_kernel(&icmph, sizeof(icmph), head + trans_off);

    u16 sport = ((u16)icmph.type << 8) | (u16)icmph.code;
    u16 dport = bpf_ntohs(icmph.un.echo.id);
    u64 now   = bpf_ktime_get_ns();
    u64 req_id = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;

    emit_kray_event(
        req_id, (u64)bpf_ntohs(iph.tot_len), now, 15000ULL,
        0, 0, 0,
        iph.saddr, iph.daddr, sport, dport,
        LAYER_KERNEL_NET, 0, OSI_L3_IP, FLAG_NONE);
    return 0;
}

SEC("kprobe/arp_rcv")
int kprobe__arp_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb)
        return 0;
    unsigned char *head = NULL;
    u16 net_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    if (!head)
        return 0;

    struct arphdr *arp = (struct arphdr *)(head + net_off);
    u32 ar_sip = 0, ar_tip = 0;
    bpf_probe_read_kernel(&ar_sip, sizeof(ar_sip), (u8 *)(arp + 1) + 6);
    bpf_probe_read_kernel(&ar_tip, sizeof(ar_tip), (u8 *)(arp + 1) + 16);

    u64 now = bpf_ktime_get_ns();
    u64 req_id = ((now & 0xFFFFFFFFULL) << 16) ^ (u64)(ar_sip & 0xffff);
    emit_kray_event(
        req_id, 28ULL, now, 10000ULL,
        0, 0, 0,
        ar_sip, ar_tip, 0, 0,
        LAYER_INGRESS_NIC, 0, OSI_L2_DATALINK, FLAG_NONE);
    return 0;
}
