/* SPDX-License-Identifier: GPL-2.0 */
/*
 * progs/tracer_l2_xdp.bpf.c — Layer 2 NIC DMA / XDP & Netif Ingress Telemetry
 * Grounded in Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)
 * References:
 *   - tools/testing/selftests/bpf/progs/test_xdp_vlan.c
 *   - references/xdp-tutorial/packet01-parsing/
 *   - references/bcc-libbpf-tools/libbpf-tools/softirqs.bpf.c
 */

#include "kray_common.h"

SEC("xdp")
int xdp_ingress_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    u16 h_proto = bpf_ntohs(eth->h_proto);
    u16 vlan_id = 0;
    void *nh_ptr = (void *)(eth + 1);
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == 0x8100 || h_proto == 0x88A8 || h_proto == 0x9100) {
            if (nh_ptr + 4 > data_end)
                return XDP_PASS;
            u16 *vlan_hdr = (u16 *)nh_ptr;
            vlan_id = bpf_ntohs(vlan_hdr[0]) & 0x0FFF;
            h_proto = bpf_ntohs(vlan_hdr[1]);
            nh_ptr += 4;
        }
    }
    if (h_proto != ETH_P_IP_HOST)
        return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)nh_ptr;
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if ((iph->version & 0x0f) != 4 || (bpf_ntohs(iph->frag_off) & 0x1FFF) != 0)
        return XDP_PASS;

    u32 ihl_len = (iph->ihl & 0x0f) * 4;
    if (ihl_len < sizeof(struct iphdr))
        return XDP_PASS;
    if ((void *)iph + ihl_len > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + ihl_len;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    u16 doff_len = (tcph->doff & 0x0f) * 4;
    if (doff_len < sizeof(struct tcphdr))
        return XDP_PASS;
    if ((void *)tcph + doff_len > data_end)
        return XDP_PASS;

    u16 sport = bpf_ntohs(tcph->source);
    u16 dport = bpf_ntohs(tcph->dest);
    u16 target_port = get_target_port();

    /* Loopback Server-Role Direction Guard: only accept packets destined for target_port */
    if (target_port != 0 && dport != target_port)
        return XDP_PASS;

    struct flow_key_t key = {};
    key.saddr  = iph->saddr;
    key.daddr  = iph->daddr;
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_TCP;
    key.family = AF_INET;

    u64 now = bpf_ktime_get_ns();
    u16 tot_len = bpf_ntohs(iph->tot_len);
    u16 tcp_payload_len = (tot_len > (ihl_len + doff_len)) ? (tot_len - ihl_len - doff_len) : 0;

    struct flow_state_t *existing = ingress_flow_map.lookup(&key);
    /* Bidirectional L2 Deduplication + Payload-Gated req_id Minting */
    if (existing && existing->consumed == 0) {
        if (existing->xdp_ts != 0)
            return XDP_PASS;
        if (tcp_payload_len == 0)
            return XDP_PASS;
    }
    if ((!existing || existing->consumed == 1) && tcp_payload_len == 0)
        return XDP_PASS;

    u64 req_id = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
    u32 rx_cpu = bpf_get_smp_processor_id();
    u8 tflags  = extract_tcp_flags(tcph);

    struct flow_state_t state = {};
    state.req_id    = req_id;
    state.xdp_ts    = now;
    state.pkt_len   = (u16)((long)data_end - (long)data);
    state.tcp_flags = tflags;
    state.rx_cpu_id = (u8)rx_cpu;
    state.consumed  = 0;
    ingress_flow_map.update(&key, &state);

    u64 encoded_ip = ((u64)rx_cpu << 32) | (((u64)(vlan_id & 0x0FFF)) << 16) | (u64)state.pkt_len;
    /* XDP runs in NAPI driver/SoftIRQ context without task_struct */
    emit_kray_event(
        req_id, encoded_ip, now, 15000ULL,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_INGRESS_NIC, 0, OSI_L2_DATALINK, tflags);

    return XDP_PASS;
}

TRACEPOINT_PROBE(net, netif_receive_skb)
{
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (!skb)
        return 0;

    /*
     * Per net/core/dev.c:5606-5636, trace_netif_receive_skb(skb) fires BEFORE
     * skb_reset_network_header(skb) and BEFORE skb_vlan_untag(skb), so skb->data
     * points directly to struct iphdr (or software 802.1Q/802.1AD VLAN tags)!
     */
    unsigned char *data = NULL;
    u16 proto = 0;
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);
    bpf_probe_read_kernel(&proto, sizeof(proto), &skb->protocol);
    if (!data)
        return 0;

    u16 h_proto = bpf_ntohs(proto);
    u16 vlan_id = 0;
    u16 vlan_tci = 0;
    bpf_probe_read_kernel(&vlan_tci, sizeof(vlan_tci), &skb->vlan_tci);
    if ((vlan_tci & 0x0FFF) != 0)
        vlan_id = vlan_tci & 0x0FFF;

    unsigned char *nh_ptr = data;
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == 0x8100 || h_proto == 0x88A8 || h_proto == 0x9100) {
            u16 vlan_hdr[2] = {};
            bpf_probe_read_kernel(vlan_hdr, sizeof(vlan_hdr), nh_ptr);
            vlan_id = bpf_ntohs(vlan_hdr[0]) & 0x0FFF;
            h_proto = bpf_ntohs(vlan_hdr[1]);
            nh_ptr += 4;
        }
    }
    if (h_proto != ETH_P_IP_HOST)
        return 0;

    struct iphdr iph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), nh_ptr);
    if ((iph.version & 0x0f) != 4 || iph.protocol != IPPROTO_TCP)
        return 0;
    if ((bpf_ntohs(iph.frag_off) & 0x1FFF) != 0)
        return 0;

    u32 ihl_len = (iph.ihl & 0x0f) * 4;
    if (ihl_len < sizeof(struct iphdr))
        return 0;
    struct tcphdr tcph = {};
    bpf_probe_read_kernel(&tcph, sizeof(tcph), nh_ptr + ihl_len);
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

    u16 tot_len = bpf_ntohs(iph.tot_len);
    u16 tcp_payload_len = (tot_len > (ihl_len + doff_len)) ? (tot_len - ihl_len - doff_len) : 0;

    struct flow_state_t *existing = ingress_flow_map.lookup(&key);
    if (existing && existing->consumed == 0) {
        if (existing->xdp_ts != 0)
            return 0;
        if (tcp_payload_len == 0)
            return 0;
    }
    if ((!existing || existing->consumed == 1) && tcp_payload_len == 0)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 req_id = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
    u32 rx_cpu = bpf_get_smp_processor_id();
    u8 tflags  = extract_tcp_flags(&tcph);

    struct flow_state_t state = {};
    state.req_id    = req_id;
    state.xdp_ts    = now;
    state.pkt_len   = (u16)args->len;
    state.tcp_flags = tflags;
    state.rx_cpu_id = (u8)rx_cpu;
    state.consumed  = 0;
    ingress_flow_map.update(&key, &state);

    u64 encoded_ip = ((u64)rx_cpu << 32) | (((u64)(vlan_id & 0x0FFF)) << 16) | (u64)state.pkt_len;
    emit_kray_event(
        req_id, encoded_ip, now, 15000ULL,
        0, 0, 0,
        key.saddr, key.daddr, sport, dport,
        LAYER_INGRESS_NIC, 0, OSI_L2_DATALINK, tflags);
    return 0;
}
