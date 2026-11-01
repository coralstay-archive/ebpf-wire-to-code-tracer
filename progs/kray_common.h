/* SPDX-License-Identifier: GPL-2.0 */
/*
 * progs/kray_common.h — Common Header & BPF Map Declarations for Micro-BPF Modules
 * Grounded in Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)
 * Modeled after tools/testing/selftests/bpf/progs/
 */
#ifndef PROGS_KRAY_COMMON_H
#define PROGS_KRAY_COMMON_H

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
#include "../kray_bpf_core_compat.h"
#elif defined(KRAY_USER_SIM)
#include "../mock_bpf_runtime.h"
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

/* 16-Byte Hot-Reloadable Runtime Configuration Struct (Zero Recompile) */
struct __attribute__((packed)) kray_runtime_cfg_t {
    u32 target_pid;       // [Bytes 0..3]   Dynamic target TGID (falls back to __TARGET_PID__ if 0)
    u16 target_port;      // [Bytes 4..5]   Dynamic target port in host byte order (0 = All ports 0..65535)
    u8  capture_enabled;  // [Byte  6]      1: Active, 0: Paused
    u8  filter_flags;     // [Byte  7]      [Bits 0..3]: Proto mask; [Bits 4..7]: Layer mask
    u64 config_epoch;     // [Bytes 8..15]  Monotonic version counter incremented on REST/MCP update
};

/* 64-Byte Shared Telemetry Event Struct (C <-> Python ctypes 1:1 ABI) */
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
    u64 fn_entry_ip[MAX_CALL_DEPTH];      // Per-depth uprobe entry IP
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
    struct handoff_slot_t slots[8];
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

#ifndef KRAY_COMMON_MAPS_DECLARED
#define KRAY_COMMON_MAPS_DECLARED

BPF_ARRAY(runtime_config_map, struct kray_runtime_cfg_t, 1);
BPF_LRU_HASH(ingress_flow_map, struct flow_key_t, struct flow_state_t, 8192);
BPF_LRU_HASH(active_ctx_map, u32, struct tid_ctx_t, 8192);
BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1);
BPF_LRU_HASH(pending_handoff_map, u32, struct handoff_ring_t, 1024);
BPF_PERCPU_ARRAY(zero_ring_map, struct handoff_ring_t, 1);
BPF_LRU_HASH(egress_flow_map, struct flow_key_t, struct flow_state_t, 8192);
BPF_LRU_HASH(skb_egress_map, u64, struct flow_key_t, 8192);
BPF_LRU_HASH(inflight_bio_map, struct bio_key_t, struct bio_state_t, 4096);
BPF_RINGBUF_OUTPUT(events, 1 << 16);
BPF_ARRAY(drop_cnt_map, u64, 1);

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
    if (ring->write_idx > ring->read_idx) {
        u32 prev_idx = (ring->write_idx - 1) & 7;
        if (ring->slots[prev_idx].req_id == req_id && ring->slots[prev_idx].claimed == 0) {
            ring->slots[prev_idx].wakeup_ts   = now;
            ring->slots[prev_idx].waker_tid   = waker_tid;
            ring->slots[prev_idx].prev_cpu_id = cpu_id;
            return;
        }
    }
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

#endif /* KRAY_COMMON_MAPS_DECLARED */

#endif /* PROGS_KRAY_COMMON_H */
