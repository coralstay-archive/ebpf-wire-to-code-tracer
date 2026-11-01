/*
 * eBPF-WireToCode-Tracer — 7-Layer (Wire-to-PreCompute-to-ALU) eBPF Collector
 * Target Kernel: Rocky Linux 9.8 (Blue Onyx) aarch64 — 5.14.0-687.10.1.el9_8.0.1.aarch64
 * Grounded in:
 *   1. references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/ (vmlinux.h, net/ipv4/tcp.c, dev.c, datagram.c)
 *   2. references/ebpf-docs-master/docs/ (XDP, Kprobe, Tracepoint, RingBuf, Verifier)
 *   3. references/BPF-성능-분석-도구.pdf (Ch.6 runqlat, Ch.7 MM, Ch.9 Block I/O, Ch.10.1.4 SoftIRQ PID trap, Ch.12 Symbolication)
 */

#if defined(__aarch64__) || !defined(__x86_64__)
#ifndef __TARGET_ARCH_arm64
#define __TARGET_ARCH_arm64
#endif
#else
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif
#endif

#ifdef KRAY_BPF_CORE
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "kray_bpf_core_compat.h"
#elif defined(KRAY_USER_SIM)
#include "mock_bpf_runtime.h"
#else
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/futex.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <bcc/proto.h>
#endif

#ifndef __TARGET_PID__
#define __TARGET_PID__ 0
#endif

#ifndef __TARGET_PORT__
#define __TARGET_PORT__ 8080
#endif

#define MAX_CALL_DEPTH 16
#define ETH_P_IP_HOST   0x0800
#define ETH_P_IPV6_HOST 0x86DD
#define ETH_P_ARP_HOST  0x0806

#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define PROTO_ARP_TAG  0xFE
#define PROTO_UNIX_TAG 0xFF

enum kray_layer_e {
    LAYER_INGRESS_NIC = 1,
    LAYER_KERNEL_NET  = 2,
    LAYER_USER_ENTRY  = 3,
    LAYER_USER_FUNC   = 4,
    LAYER_USER_EXIT   = 5,
    LAYER_EGRESS_NIC  = 6
};

enum kray_osi_layer_e {
    OSI_L2_DATALINK    = 2,  // NIC DMA / XDP / netif_receive_skb / Qdisc / net_dev_xmit
    OSI_L3_IP          = 3,  // IPv4 & IPv6 Routing & Netfilter (ip_rcv / ip_output / ipv6_rcv / ip6_output)
    OSI_L4_TCP         = 4,  // L4 Transport (tcp_v4_rcv / tcp_v6_rcv / udp_rcv / __tcp_transmit_skb / kfree_skb)
    OSI_L4_SOCKET      = 5,  // Socket Buffer Queue (sk_rcvbuf tcp_recvmsg / sk_sndbuf tcp_sendmsg)
    OSI_L5_SYSCALL_MEM = 6,  // Syscall / skb_copy_datagram_iovec / handle_mm_fault / block_rq_complete
    OSI_L7_APP         = 7,  // Compute Unit (ALU) On-CPU User Function & Stripped .so Execution
    OSI_L6_PRE_COMPUTE = 8   // Pre-Compute Gate: Futex Lock + CPU Runqueue (sched_wakeup->sched_switch) + Core Dispatch
};

enum kray_flags_e {
    FLAG_NONE            = 0x00,
    FLAG_THREAD_HANDOFF  = 0x01,  // Cross-thread wakeup/fork handoff
    FLAG_STRIPPED_SYMBOL = 0x02,  // Stripped binary/library offset
    FLAG_TCP_RETRANSMIT  = 0x04,  // TCP retransmission detected (tcp_retransmit_skb)
    FLAG_SKB_DROP        = 0x08,  // Kernel skb drop detected (kfree_skb, reason > 2)
    FLAG_TCP_SYN         = 0x10,
    FLAG_TCP_ACK         = 0x20,
    FLAG_TCP_PSH         = 0x40,
    FLAG_TCP_FIN         = 0x80
};

/* ============================================================================
 * 16-Byte Hot-Reloadable Runtime Configuration Struct (Zero Recompile)
 * ============================================================================ */
struct __attribute__((packed)) kray_runtime_cfg_t {
    u32 target_pid;       // [Bytes 0..3]   Dynamic target TGID (falls back to __TARGET_PID__ if 0)
    u16 target_port;      // [Bytes 4..5]   Dynamic target port in host byte order (0 = All ports 0..65535)
    u8  capture_enabled;  // [Byte  6]      1: Active, 0: Paused
    u8  filter_flags;     // [Byte  7]      [Bits 0..3]: Proto mask; [Bits 4..7]: Layer mask
    u64 config_epoch;     // [Bytes 8..15]  Monotonic version counter incremented on REST/MCP update
};

/* ============================================================================
 * 64-Byte Shared Telemetry Event Struct (C <-> Python ctypes 1:1 ABI)
 * ============================================================================ */
struct __attribute__((packed)) kray_event_t {
    u64 req_id;        // [Bytes 0..7]   Unique 64-bit correlated request ID
    u64 ip;            // [Bytes 8..15]  Instruction Pointer (or encoded pkt_len/cpu_id/hook metadata)
    u64 timestamp;     // [Bytes 16..23] bpf_ktime_get_ns() monotonic nanoseconds
    u64 duration_ns;   // [Bytes 24..31] Stage delta, runqueue latency, block I/O wait, or function duration in ns
    u32 pid;           // [Bytes 32..35] Process ID (TGID)
    u32 tid;           // [Bytes 36..39] Thread ID (PID)
    u32 parent_tid;    // [Bytes 40..43] Dispatcher/Waker TID if handed off across threads (0 otherwise)
    u32 src_ip;        // [Bytes 44..47] IPv4 Source Address (network byte order) or folded hash
    u32 dst_ip;        // [Bytes 48..51] IPv4 Destination Address (network byte order) or folded hash
    u16 src_port;      // [Bytes 52..53] Source Port (host byte order)
    u16 dst_port;      // [Bytes 54..55] Destination Port (host byte order)
    u8  layer_type;    // [Byte  56]     1..6 (enum kray_layer_e)
    u8  is_return;     // [Byte  57]     0: Entry / Point Event, 1: Function Return (uretprobe)
    u8  call_depth;    // [Byte  58]     Call depth (0..15) ONLY when layer_type==LAYER_USER_FUNC; OSI layer otherwise
    u8  flags;         // [Byte  59]     Bitmask (enum kray_flags_e)
    u32 drop_count;    // [Bytes 60..63] Cumulative ring-buffer drop counter snapshot
};

/* ============================================================================
 * Internal BPF Map Key & Value Structures
 * ============================================================================ */
struct flow_key_t {
    u32 saddr;         // IPv4 addr / folded IPv6 hash / AF_UNIX local sk low32
    u32 daddr;         // IPv4 addr / folded IPv6 hash / AF_UNIX peer sk low32
    u16 sport;         // Source port (host order) or ICMP (type<<8)|code
    u16 dport;         // Dest port (host order) or ICMP echo_id / 0 for AF_UNIX
    u8  proto;         // IPPROTO_TCP(6), IPPROTO_UDP(17), IPPROTO_ICMP(1), 0xFE(ARP), 0xFF(AF_UNIX)
    u8  family;        // AF_INET(2), AF_INET6(10), AF_UNIX(1)
    u16 pad;           // Explicit zero-padding for 16-byte verifier alignment (sizeof == 16)
};

struct flow_state_t {
    u64 req_id;
    u64 xdp_ts;        // L2 Ingress timestamp (xdp_ingress_filter / netif_receive_skb)
    u64 ip_rcv_ts;     // L3 Ingress timestamp (kprobe:ip_rcv / kprobe:ipv6_rcv)
    u64 tcp_rcv_ts;    // L4 Ingress timestamp (kprobe:tcp_v4_rcv / tcp_v6_rcv / udp_rcv)
    u64 sendmsg_ts;    // L4.5 Socket Egress timestamp (kprobe:tcp_sendmsg / udp_sendmsg)
    u64 tcp_tx_ts;     // L4 TCP Egress timestamp (kprobe:__tcp_transmit_skb)
    u64 ip_out_ts;     // L3 IP Egress timestamp (kprobe:ip_output / ip6_output)
    u64 qdisc_enq_ts;  // L2 Qdisc Enqueue timestamp (tracepoint:net:net_dev_queue)
    u32 pid;
    u32 tid;
    u16 pkt_len;
    u8  tcp_flags;
    u8  retransmits;
    u8  rx_cpu_id;
    u8  consumed;      // 1 once tcp_recvmsg consumes this req_id (prevents 0-byte ACK overwrite)
};

struct tid_ctx_t {
    u64 req_id;
    u64 last_stage_ts;
    u64 futex_enter_ts;     // L6 Pre-Compute: sys_enter_futex lock wait start timestamp
    u64 wakeup_ts;          // L6 Pre-Compute: sched:sched_wakeup timestamp (for runqlat = t_switch - t_wakeup)
    u64 off_cpu_enter_ts;   // L6/L7 Off-CPU: sched_switch (prev_pid == tid) timestamp
    u64 acc_off_cpu_ns;     // Cumulative Off-CPU sleep/preemption/I/O wait ns for this thread
    u64 acc_block_io_ns;    // Cumulative Block I/O wait ns (block_rq_issue -> block_rq_complete)
    u64 copy_enter_ts;      // L5 MM/SKB: skb_copy_datagram_iter entry timestamp
    u64 epoll_enter_ts;     // L5 Event Multiplexing: sys_enter_epoll_pwait entry timestamp
    u64 epoll_wait_ns;      // L5 Event Multiplexing: duration spent inside epoll_pwait
    u32 epoll_ready_rem;    // L5 Event Multiplexing: count of ready FDs returned by epoll_pwait
    u64 active_sk_ptr;      // L4.5 Socket: Stashed struct sock *sk across blocking sk_wait_data() -> kretprobe__tcp_recvmsg
    u64 active_msg_name;    // L4.5 UDP Socket: Stashed msg->msg_name across udp_recvmsg -> kretprobe__udp_recvmsg
    u32 pid;
    u32 tid;
    u32 parent_tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 page_faults;        // L5 MM: Count of handle_mm_fault events
    u16 copied_bytes;       // L5 SKB: Accumulated bytes in skb_copy_datagram_iovec / skb_copy_datagram_iter
    u8  prev_cpu_id;        // L6 Pre-Compute: Previous CPU core ID before sched_switch
    u8  target_cpu_id;      // L6 Pre-Compute: Dispatched CPU core ID on sched_switch
    u8  call_depth;
    u8  flags;
    u8  in_target_sendmsg;  // 1 while inside server-socket tcp_sendmsg (guards kretprobe__tcp_sendmsg context teardown)
    u8  pad_ctx[1];
    u64 fn_entry_ip[MAX_CALL_DEPTH];      // Per-depth uprobe entry IP (prevents uretprobe [uprobes] trampoline IP corruption!)
    u64 fn_entry_ts[MAX_CALL_DEPTH];      // Per-depth uprobe entry timestamp
    u64 fn_off_cpu_snap[MAX_CALL_DEPTH];  // Per-depth snapshot of acc_off_cpu_ns
};

struct handoff_slot_t {
    u64 req_id;
    u64 wakeup_ts;
    u32 waker_tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  prev_cpu_id;
    u8  claimed;
};

struct handoff_ring_t {
    u32 write_idx;
    u32 read_idx;
    struct handoff_slot_t slots[8]; // 8-slot per-TGID FIFO prevents concurrent TEST-03 requests from overwriting each other
};

struct bio_key_t {
    u32 dev;
    u32 pad;
    u64 sector;
};

struct bio_state_t {
    u64 issue_ts;
    u64 req_id;
    u32 tid;
    u32 bytes;
};

/* ============================================================================
 * BPF Maps Declarations
 * ============================================================================ */
BPF_ARRAY(runtime_config_map, struct kray_runtime_cfg_t, 1);
BPF_LRU_HASH(ingress_flow_map, struct flow_key_t, struct flow_state_t, 8192);

/*
 * CRITICAL VERIFIER & READ-ONLY TEMPLATE RULE:
 * sizeof(struct tid_ctx_t) > 400B, so NEVER allocate struct tid_ctx_t on the 512B BPF stack!
 * Moreover, zero_ctx_map[0] MUST be treated as a strictly READ-ONLY all-zero template:
 * Always call active_ctx_map.update(&tid, zero_template) first, then lookup & mutate active_ctx_map.lookup(&tid).
 */
BPF_LRU_HASH(active_ctx_map, u32, struct tid_ctx_t, 8192);
BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1);
BPF_LRU_HASH(pending_handoff_map, u32, struct handoff_ring_t, 1024);
BPF_PERCPU_ARRAY(zero_ring_map, struct handoff_ring_t, 1);

BPF_LRU_HASH(egress_flow_map, struct flow_key_t, struct flow_state_t, 8192);
BPF_LRU_HASH(skb_egress_map, u64, struct flow_key_t, 8192);
BPF_LRU_HASH(inflight_bio_map, struct bio_key_t, struct bio_state_t, 4096);

BPF_RINGBUF_OUTPUT(events, 1 << 16);
BPF_ARRAY(drop_cnt_map, u64, 1);

/* ============================================================================
 * Helper Functions
 * ============================================================================ */
static __always_inline u16 get_target_port(void) {
    u32 idx = 0;
    struct kray_runtime_cfg_t *cfg = runtime_config_map.lookup(&idx);
    if (cfg && cfg->capture_enabled == 0 && cfg->config_epoch > 0)
        return 0xFFFF;
    if (cfg && cfg->config_epoch > 0)
        return cfg->target_port;
    return (u16)__TARGET_PORT__;
}

static __always_inline u32 get_target_pid(void) {
    u32 idx = 0;
    struct kray_runtime_cfg_t *cfg = runtime_config_map.lookup(&idx);
    if (cfg && cfg->target_pid != 0)
        return cfg->target_pid;
    return (u32)__TARGET_PID__;
}

static __always_inline u8 extract_tcp_flags(struct tcphdr *tcph) {
    u8 flags = 0;
    if (tcph->syn) flags |= FLAG_TCP_SYN;
    if (tcph->ack) flags |= FLAG_TCP_ACK;
    if (tcph->psh) flags |= FLAG_TCP_PSH;
    if (tcph->fin) flags |= FLAG_TCP_FIN;
    return flags;
}

static __always_inline u32 fold_ipv6_addr32(const u32 addr[4]) {
    return addr[0] ^ addr[1] ^ addr[2] ^ addr[3];
}

static __always_inline void populate_sock_flow_key(
    struct sock *sk, struct flow_key_t *key, u8 proto, int is_egress)
{
    u16 family = 0, local_port = 0, rem_port_be = 0;
    u32 rem_ip4 = 0, loc_ip4 = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&local_port, sizeof(local_port), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&rem_port_be, sizeof(rem_port_be), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&rem_ip4, sizeof(rem_ip4), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&loc_ip4, sizeof(loc_ip4), &sk->__sk_common.skc_rcv_saddr);

    u16 rem_port = bpf_ntohs(rem_port_be);
    key->proto = proto;

    /*
     * Dual-Stack IPv4-mapped IPv6 Normalization (Flaw #31) + Pure IPv6 XOR Folding (Flaw #19):
     * Note: Linux tcp_v6_syn_recv_sock (net/ipv6/tcp_ipv6.c:1356) sets skc_daddr = skc_rcv_saddr =
     * LOOPBACK4_IPV6 (htonl(0x7f000006)) on pure IPv6 sockets!
     * Check whether skc_v6_daddr is a real non-v4mapped IPv6 address or rem_ip4 is 0 / LOOPBACK4_IPV6.
     */
    if (family == AF_INET6) {
        u32 rem6[4] = {};
        u32 loc6[4] = {};
        bpf_probe_read_kernel(rem6, sizeof(rem6), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(loc6, sizeof(loc6), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        int v6_non_zero = (rem6[0] | rem6[1] | rem6[2] | rem6[3]) != 0;
        int is_v4_mapped = (rem6[0] == 0 && rem6[1] == 0 && rem6[2] == bpf_htonl(0x0000ffff));
        if (rem_ip4 == 0 || rem_ip4 == bpf_htonl(0x7f000006) || (v6_non_zero && !is_v4_mapped)) {
            u32 rem_hash = fold_ipv6_addr32(rem6);
            u32 loc_hash = fold_ipv6_addr32(loc6);
            key->saddr  = is_egress ? loc_hash : rem_hash;
            key->daddr  = is_egress ? rem_hash : loc_hash;
            key->family = AF_INET6;
        } else {
            key->saddr  = is_egress ? loc_ip4 : rem_ip4;
            key->daddr  = is_egress ? rem_ip4 : loc_ip4;
            key->family = AF_INET;
        }
    } else {
        key->saddr  = is_egress ? loc_ip4 : rem_ip4;
        key->daddr  = is_egress ? rem_ip4 : loc_ip4;
        key->family = AF_INET;
    }
    key->sport = is_egress ? local_port : rem_port;
    key->dport = is_egress ? rem_port : local_port;
}

static __always_inline void emit_kray_event(
    u64 req_id, u64 ip, u64 ts, u64 dur_ns,
    u32 pid, u32 tid, u32 parent_tid,
    u32 saddr, u32 daddr, u16 sport, u16 dport,
    u8 layer_type, u8 is_return, u8 call_depth, u8 flags)
{
    u32 zero = 0;
    struct kray_event_t *ev = events.ringbuf_reserve(sizeof(struct kray_event_t));
    if (!ev) {
        u64 *cnt = drop_cnt_map.lookup(&zero);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return;
    }
    u64 *cnt = drop_cnt_map.lookup(&zero);
    ev->req_id      = req_id;
    ev->ip          = ip;
    ev->timestamp   = ts;
    ev->duration_ns = dur_ns;
    ev->pid         = pid;
    ev->tid         = tid;
    ev->parent_tid  = parent_tid;
    ev->src_ip      = saddr;
    ev->dst_ip      = daddr;
    ev->src_port    = sport;
    ev->dst_port    = dport;
    ev->layer_type  = layer_type;
    ev->is_return   = is_return;
    ev->call_depth  = call_depth;
    ev->flags       = flags;
    ev->drop_count  = cnt ? (u32)(*cnt) : 0;
    events.ringbuf_submit(ev, 0);
}

static __always_inline void publish_handoff_slot(
    u32 tgid, u64 req_id, u64 now, u32 waker_tid,
    u32 saddr, u32 daddr, u16 sport, u16 dport, u8 cpu_id)
{
    struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
    if (!ring) {
        u32 zero_idx = 0;
        struct handoff_ring_t *zero_ring = zero_ring_map.lookup(&zero_idx);
        if (!zero_ring)
            return;
        pending_handoff_map.update(&tgid, zero_ring);
        ring = pending_handoff_map.lookup(&tgid);
        if (!ring)
            return;
    }
    /* Avoid duplicate consecutive slot creation when tcp_recvmsg + sys_enter_futex publish the same req_id */
    if (ring->write_idx > ring->read_idx) {
        u32 prev_idx = (ring->write_idx - 1) & 7;
        if (ring->slots[prev_idx].req_id == req_id && ring->slots[prev_idx].claimed == 0) {
            ring->slots[prev_idx].wakeup_ts   = now;
            ring->slots[prev_idx].waker_tid   = waker_tid;
            ring->slots[prev_idx].prev_cpu_id = cpu_id;
            return;
        }
    }
    /* Sliding window overflow protection: keep read_idx pointing to the oldest valid slot in the 8-slot ring */
    if ((u32)(ring->write_idx - ring->read_idx) >= 8) {
        ring->read_idx = ring->write_idx - 7;
    }
    u32 slot_idx = ring->write_idx & 7;
    ring->slots[slot_idx].req_id      = req_id;
    ring->slots[slot_idx].wakeup_ts   = now;
    ring->slots[slot_idx].waker_tid   = waker_tid;
    ring->slots[slot_idx].saddr       = saddr;
    ring->slots[slot_idx].daddr       = daddr;
    ring->slots[slot_idx].sport       = sport;
    ring->slots[slot_idx].dport       = dport;
    ring->slots[slot_idx].prev_cpu_id = cpu_id;
    ring->slots[slot_idx].claimed     = 0;
    ring->write_idx++;
}

/* ============================================================================
 * LAYER 1: INGRESS_NIC (OSI_L2_DATALINK = 2)
 * Hooks: xdp_ingress_filter + tracepoint:net:netif_receive_skb
 * ============================================================================ */
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

/* ============================================================================
 * LAYER 2: KERNEL_NET (OSI_L3_IP = 3 & OSI_L4_TCP = 4)
 * Hooks: kprobe__ip_rcv, kprobe__tcp_v4_rcv, tcp_retransmit_skb, kfree_skb
 * ============================================================================ */
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

    /* At ip_rcv entry (ip_input.c:552), skb->transport_header is uninitialized! */
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

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
#ifdef KRAY_BPF_CORE
    skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
#endif
    if (!skb)
        return 0;

    unsigned char *head = NULL;
    u16 net_off = 0;
    u16 trans_off = 0;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
    bpf_probe_read_kernel(&trans_off, sizeof(trans_off), &skb->transport_header);
    if (!head)
        return 0;

    struct iphdr iph = {};
    struct tcphdr tcph = {};
    bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);

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
    u8 tflags = extract_tcp_flags(&tcph);
    u16 tot_len = bpf_ntohs(iph.tot_len);
    u16 ihl_len = (iph.ihl & 0x0f) * 4;
    u16 doff_len = (tcph.doff & 0x0f) * 4;
    u16 tcp_payload_len = (tot_len > (ihl_len + doff_len)) ? (tot_len - ihl_len - doff_len) : 0;

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    /* Loopback fallback or new Keep-Alive request when previous req_id was consumed */
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
        if (!state)
            return 0;
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
    return 0;
}

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)
{
    /*
     * Per include/trace/events/tcp.h:47-48, args->sport and args->dport are
     * ALREADY in host byte order via ntohs(), and saddr/daddr are __u8[4] arrays!
     */
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
    /*
     * Per include/net/dropreason-core.h:129-138, SKB_CONSUMED (1) and
     * SKB_DROP_REASON_NOT_SPECIFIED (2) include normal frees; only reason > 2 is a drop!
     * 3-Stage Flow Resolution: (1) skb_egress_map, (2) args->rx_sk, (3) skb->head + network_header.
     */
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

/* ============================================================================
 * LAYER 3: USER_ENTRY (OSI_L4_SOCKET = 5 & OSI_L5_SYSCALL_MEM = 6)
 * Hooks: kprobe__tcp_recvmsg, kretprobe__tcp_recvmsg, skb_copy_datagram_iovec,
 *        kretprobe__skb_copy_datagram_iter, kprobe__handle_mm_fault
 * ============================================================================ */
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
    /* Server-Role Guard: exclude loopback client sockets */
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

    /* Strictly read-only zero_ctx_map[0] template initialization */
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

    /* Delayed binding if thread blocked inside sk_wait_data() (tcp.c:2638) */
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

    /* Per datagram.c:534, fires right before simple_copy_to_iter() */
    if (tctx->copy_enter_ts == 0)
        tctx->copy_enter_ts = bpf_ktime_get_ns();
    tctx->copied_bytes += (u16)args->len;
    return 0;
}

int kretprobe__skb_copy_datagram_iter(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->copy_enter_ts == 0)
        return 0;

    /*
     * Lazy req_id binding for blocking tcp_recvmsg:
     * In Linux net/ipv4/tcp.c:2638-2675, skb_copy_datagram_iter runs inside tcp_recvmsg
     * AFTER sk_wait_data() wakes up, which is BEFORE kretprobe__tcp_recvmsg fires!
     */
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

int kprobe__handle_mm_fault(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx)
        tctx->page_faults++;
    return 0;
}

/* ============================================================================
 * LAYER 4: PRE-COMPUTE GATE (OSI_L6_PRE_COMPUTE = 8) & USER_FUNC (OSI_L7_APP = 7)
 * Hooks: sys_enter_futex, sys_exit_futex, sched_process_fork, sched_waking,
 *        sched_wakeup, sched_switch, block_rq_insert/issue/complete, uprobe/uretprobe
 * ============================================================================ */
TRACEPOINT_PROBE(syscalls, sys_enter_futex)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;
    u64 now  = bpf_ktime_get_ns();

#ifdef KRAY_BPF_CORE
    /* Per vmlinux.h struct syscall_trace_enter, args->args[1] is at offset 24 (op) */
    u32 cmd = ((u32)args->args[1]) & 0x7f;
#else
    u32 raw_op = args->op ? (u32)args->op : (u32)args->args[1];
    u32 cmd = raw_op & 0x7f;
#endif

    /* Wait operations: FUTEX_WAIT(0), FUTEX_WAIT_BITSET(9), FUTEX_LOCK_PI(6), FUTEX_WAIT_REQUEUE_PI(11), FUTEX_LOCK_PI2(13) */
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
        /* Wake / Requeue operations */
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
    /*
     * Per include/trace/events/sched.h:145-171, sched_waking is guaranteed to
     * execute in Waker context even on SMP cross-CPU wakeups!
     */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid      = (u32)(pid_tgid >> 32);
    u32 waker_tid = (u32)pid_tgid;
    u32 target_tid = (u32)args->pid;

    struct tid_ctx_t *wctx = active_ctx_map.lookup(&waker_tid);
    if (!wctx || wctx->req_id == 0 || waker_tid == target_tid)
        return 0;

    /* Preserve futex_enter_ts if worker thread already entered sys_enter_futex(FUTEX_WAIT) */
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
    /*
     * Per include/trace/events/sched.h:222-265, TP_STRUCT__entry exposes
     * integer fields args->prev_pid, args->next_pid, and args->prev_state.
     */
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

        /* Reset timestamps immediately to prevent stale leak across context switches */
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

    /* Preserve user thread tid/req_id if block_rq_insert already populated inflight_bio_map */
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
    /* Per include/trace/events/block.h:124-130, compute bytes via args->nr_sector * 512 */
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

int trace_uprobe_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    /* Tier 2 Already-Awake Worker Fallback via 8-slot FIFO pending_handoff_map */
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

    /*
     * Protect fn_entry_ip[0..15] and fn_entry_ts[0..15] from wrap-around overwrite
     * when recursion / call depth exceeds MAX_CALL_DEPTH (16)!
     * Note: asm volatile barrier prevents Clang from optimizing away &= 15 inside
     * the (raw_depth < 16) branch, keeping the Linux 5.14 BPF Verifier range tracker happy.
     */
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

    u8 report_depth = (raw_depth < MAX_CALL_DEPTH) ? raw_depth : (MAX_CALL_DEPTH - 1);
    emit_kray_event(
        tctx->req_id, entry_ip, now, off_cpu_snap,
        tgid, tid, tctx->parent_tid,
        tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
        LAYER_USER_FUNC, 0, report_depth, tctx->flags);
    return 0;
}

int trace_uprobe_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 tid  = (u32)pid_tgid;

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (!tctx || tctx->req_id == 0)
        return 0;

    /* Mandatory u8 call_depth underflow guard */
    if (tctx->call_depth == 0)
        return 0;

    tctx->call_depth--;
    u8 raw_depth = tctx->call_depth;
    u32 slot = raw_depth & (MAX_CALL_DEPTH - 1);
    u64 now = bpf_ktime_get_ns();
    u64 saved_ts = tctx->fn_entry_ts[slot];
    /* Restore saved fn_entry_ip[slot] instead of [uprobes] trampoline PT_REGS_IP(ctx)! Guard against recursion depth >= 16 */
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

/* ============================================================================
 * LAYER 5: USER_EXIT (OSI_L5_SYSCALL_MEM = 6 & OSI_L4_SOCKET = 5)
 * Hooks: sys_enter_write, sys_exit_write, kprobe__tcp_sendmsg & kretprobe__tcp_sendmsg
 * ============================================================================ */
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
    /*
     * Flaw #11 Guard: NEVER call active_ctx_map.delete(&tid) inside sys_exit_write
     * because stdout/file logging calls write() before socket response send!
     */
    return 0;
}

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

int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx && tctx->in_target_sendmsg == 1)
        active_ctx_map.delete(&tid);
    return 0;
}

/* ============================================================================
 * LAYER 6: EGRESS_NIC (OSI_L4_TCP = 4, OSI_L3_IP = 3 & OSI_L2_DATALINK = 2)
 * Hooks: kprobe____tcp_transmit_skb, kprobe__ip_output, net_dev_queue, net_dev_xmit
 * ============================================================================ */
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

int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)
{
    /*
     * Per net/ipv4/ip_output.c:426 & net/ipv4/tcp_output.c:1267, __tcp_transmit_skb
     * clones oskb (skb = skb_clone(oskb, gfp_mask)), so skb at ip_output is a post-clone
     * pointer! Resolve via PT_REGS_PARM2(ctx) (struct sock *sk) and register the post-clone
     * skb_ptr into skb_egress_map so net_dev_queue and net_dev_xmit match it!
     */
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

TRACEPOINT_PROBE(net, net_dev_queue)
{
    u64 skb_ptr = (u64)args->skbaddr;
    struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
    if (!ekey)
        return 0;

    struct flow_state_t *estate = egress_flow_map.lookup(ekey);
    if (estate)
        estate->qdisc_enq_ts = bpf_ktime_get_ns();
    return 0;
}

TRACEPOINT_PROBE(net, net_dev_xmit)
{
    /*
     * Per include/trace/events/net.h:71, net_dev_xmit runs AFTER driver transmit
     * where skb->head may already be freed; look up via skb_egress_map[(u64)args->skbaddr]!
     */
    u64 skb_ptr = (u64)args->skbaddr;
    struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
    if (!ekey)
        return 0;

    struct flow_state_t *estate = egress_flow_map.lookup(ekey);
    if (!estate) {
        skb_egress_map.delete(&skb_ptr);
        return 0;
    }

    u64 now = bpf_ktime_get_ns();
    u64 qdisc_delay = estate->qdisc_enq_ts ? (now - estate->qdisc_enq_ts)
                      : (estate->ip_out_ts ? (now - estate->ip_out_ts) : 20000ULL);
    u32 tx_cpu = bpf_get_smp_processor_id();
    u64 encoded_ip = ((u64)tx_cpu << 32) | (((u64)(args->rc & 0xffff)) << 16) | (u64)estate->pkt_len;

    emit_kray_event(
        estate->req_id, encoded_ip, now, qdisc_delay,
        estate->pid, estate->tid, 0,
        ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
        LAYER_EGRESS_NIC, 0, OSI_L2_DATALINK, FLAG_TCP_PSH | FLAG_TCP_ACK);

    egress_flow_map.delete(ekey);
    skb_egress_map.delete(&skb_ptr);
    return 0;
}

/* ============================================================================
 * MULTI-PROTOCOL ADAPTER HOOKS (IPv6, UDP, ICMP, ARP, AF_UNIX)
 * ============================================================================ */
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

    /* At ipv6_rcv entry (ip6_input.c:302), unroll up to 4 IPv6 extension headers (0, 43, 44, 51, 60) */
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
                return 0; /* Non-first IPv6 fragment lacks L4 header */
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

int kprobe__tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb)
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

    struct ipv6hdr ip6h = {};
    struct tcphdr tcph = {};
    bpf_probe_read_kernel(&ip6h, sizeof(ip6h), head + net_off);
    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);

    u16 sport = bpf_ntohs(tcph.source);
    u16 dport = bpf_ntohs(tcph.dest);
    u16 target_port = get_target_port();
    if (target_port != 0 && dport != target_port)
        return 0;

    struct flow_key_t key = {};
    key.saddr  = fold_ipv6_addr32(ip6h.saddr.in6_u.u6_addr32);
    key.daddr  = fold_ipv6_addr32(ip6h.daddr.in6_u.u6_addr32);
    key.sport  = sport;
    key.dport  = dport;
    key.proto  = IPPROTO_TCP;
    key.family = AF_INET6;

    u64 now = bpf_ktime_get_ns();
    u8 tflags = extract_tcp_flags(&tcph);
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
        if (!state)
            return 0;
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
    return 0;
}

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

    /* Unconnected UDP server fallback key: { .daddr = 0, .dport = skc_num, .proto = IPPROTO_UDP } */
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

    /*
     * Per net/ipv4/udp.c:1938-1944, DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name)
     * is populated right before udp_recvmsg returns!
     */
    struct flow_key_t key = {};
    key.daddr  = tctx->daddr;
    key.dport  = tctx->dport;
    key.proto  = IPPROTO_UDP;
    key.family = AF_INET;

    if (tctx->active_msg_name != 0) {
        u16 sin_port_be = 0;
        u32 sin_addr = 0;
        /* struct sockaddr_in: sin_family(2B), sin_port(2B @ +2), sin_addr(4B @ +4) */
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

    /* Unconnected UDP server socket has skc_daddr == 0; extract peer from msg->msg_name or tctx */
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

int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    /*
     * Per net/ipv4/icmp.c:1200 & include/uapi/linux/icmp.h:89-95, encode
     * sport = (icmph.type << 8) | icmph.code and dport = bpf_ntohs(icmph.un.echo.id).
     */
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

int kprobe__arp_rcv(struct pt_regs *ctx, struct sk_buff *skb)
{
    /*
     * Per include/uapi/linux/if_arp.h:144-161, ar_sip/ar_tip are inside #if 0;
     * extract sender IP at (u8 *)(arp + 1) + 6 and target IP at (u8 *)(arp + 1) + 16.
     */
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

int kprobe__unix_stream_recvmsg(struct pt_regs *ctx, struct socket *sock)
{
    /*
     * Per net/unix/af_unix.c:2733, normalize AF_UNIX receive key as:
     * saddr = (u32)(u64)unix_sk(sk)->peer, daddr = (u32)(u64)sk.
     */
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

int kprobe__unix_stream_sendmsg(struct pt_regs *ctx, struct socket *sock)
{
    /*
     * Per net/unix/af_unix.c:2053, normalize AF_UNIX send key as:
     * saddr = (u32)(u64)sk, daddr = (u32)(u64)unix_sk(sk)->peer.
     */
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
