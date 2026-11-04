/*
 * kray_bpf_core_compat.h — Rocky Linux 9.8 CO-RE (vmlinux.h + libbpf) Compatibility Layer
 * Bridges BCC map/tracepoint syntax in tracer_kernel.c to standard libbpf CO-RE BTF maps
 * and Rocky Linux 9.8 (5.14.0-687.10.1.el9_8.0.1.aarch64) trace_event_raw_* structs.
 */
#ifndef KRAY_BPF_CORE_COMPAT_H
#define KRAY_BPF_CORE_COMPAT_H

#ifndef barrier
#define barrier() asm volatile("" ::: "memory")
#endif

#define tp_args_net_netif_receive_skb_t        struct trace_event_raw_net_dev_template
#define tp_args_net_net_dev_queue_t            struct trace_event_raw_net_dev_template
#define tp_args_net_net_dev_xmit_t             struct trace_event_raw_net_dev_xmit
#define tp_args_tcp_tcp_retransmit_skb_t       struct trace_event_raw_tcp_event_sk_skb
#define tp_args_skb_kfree_skb_t                struct trace_event_raw_kfree_skb
#define tp_args_skb_skb_copy_datagram_iovec_t  struct trace_event_raw_skb_copy_datagram_iovec
#define tp_args_syscalls_sys_enter_read_t      struct syscall_trace_enter
#define tp_args_syscalls_sys_enter_futex_t     struct syscall_trace_enter
#define tp_args_syscalls_sys_exit_futex_t      struct syscall_trace_exit
#define tp_args_syscalls_sys_enter_write_t     struct syscall_trace_enter
#define tp_args_syscalls_sys_exit_write_t      struct syscall_trace_exit
#define tp_args_syscalls_sys_enter_epoll_pwait_t struct syscall_trace_enter
#define tp_args_syscalls_sys_exit_epoll_pwait_t  struct syscall_trace_exit
#define tp_args_syscalls_sys_enter_epoll_wait_t  struct syscall_trace_enter
#define tp_args_syscalls_sys_exit_epoll_wait_t   struct syscall_trace_exit
#define tp_args_sched_sched_process_fork_t     struct trace_event_raw_sched_process_fork
#define tp_args_sched_sched_waking_t           struct trace_event_raw_sched_wakeup_template
#define tp_args_sched_sched_wakeup_t           struct trace_event_raw_sched_wakeup_template
#define tp_args_sched_sched_switch_t           struct trace_event_raw_sched_switch
#define tp_args_block_block_rq_insert_t        struct trace_event_raw_block_rq
#define tp_args_block_block_rq_issue_t         struct trace_event_raw_block_rq
#define tp_args_block_block_rq_complete_t      struct trace_event_raw_block_rq_completion

#define TRACEPOINT_PROBE(category, event) \
    SEC("tp/" #category "/" #event) \
    int tracepoint__##category##__##event(tp_args_##category##_##event##_t *args)

#define KRAY_DEFINE_TYPED_MAP(name, map_type, key_t, val_t, max_ent) \
    struct { \
        __uint(type, map_type); \
        __uint(max_entries, max_ent); \
        __type(key, key_t); \
        __type(value, val_t); \
    } __bpf_map_##name SEC(".maps"); \
    static __always_inline val_t *__kray_lookup_##name(const key_t *k) { \
        return (val_t *)bpf_map_lookup_elem(&__bpf_map_##name, k); \
    } \
    static __always_inline int __kray_update_##name(const key_t *k, const val_t *v) { \
        return (int)bpf_map_update_elem(&__bpf_map_##name, k, v, BPF_ANY); \
    } \
    static __always_inline int __kray_delete_##name(const key_t *k) { \
        return (int)bpf_map_delete_elem(&__bpf_map_##name, k); \
    } \
    struct __kray_map_ops_##name { \
        val_t *(*lookup)(const key_t *); \
        int (*update)(const key_t *, const val_t *); \
        int (*delete)(const key_t *); \
    }; \
    static const struct __kray_map_ops_##name name = { \
        .lookup = __kray_lookup_##name, \
        .update = __kray_update_##name, \
        .delete = __kray_delete_##name, \
    }

#define BPF_LRU_HASH(name, key_t, val_t, max_entries) \
    KRAY_DEFINE_TYPED_MAP(name, BPF_MAP_TYPE_LRU_HASH, key_t, val_t, max_entries)

#define BPF_ARRAY(name, val_t, max_entries) \
    KRAY_DEFINE_TYPED_MAP(name, BPF_MAP_TYPE_ARRAY, u32, val_t, max_entries)

#define BPF_PERCPU_ARRAY(name, val_t, max_entries) \
    KRAY_DEFINE_TYPED_MAP(name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, val_t, max_entries)

#define BPF_RINGBUF_OUTPUT(name, pages) \
    struct { \
        __uint(type, BPF_MAP_TYPE_RINGBUF); \
        __uint(max_entries, (pages) * 4096); \
    } __bpf_rb_##name SEC(".maps"); \
    static __always_inline void *__kray_rb_reserve_##name(u64 size) { \
        return bpf_ringbuf_reserve(&__bpf_rb_##name, size, 0); \
    } \
    static __always_inline void __kray_rb_submit_##name(void *data, u64 flags) { \
        bpf_ringbuf_submit(data, flags); \
    } \
    struct __kray_rb_ops_##name { \
        void *(*ringbuf_reserve)(u64); \
        void (*ringbuf_submit)(void *, u64); \
    }; \
    static const struct __kray_rb_ops_##name name = { \
        .ringbuf_reserve = __kray_rb_reserve_##name, \
        .ringbuf_submit  = __kray_rb_submit_##name, \
    }

char LICENSE[] SEC("license") = "GPL";

/* Forward declarations with libbpf SEC() annotations for all 22 kprobe/kretprobe/uprobe/xdp hooks */
SEC("xdp") int xdp_ingress_filter(struct xdp_md *ctx);
SEC("kprobe/ip_rcv") int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/tcp_v4_rcv") int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/tcp_recvmsg") int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len);
SEC("kretprobe/tcp_recvmsg") int kretprobe__tcp_recvmsg(struct pt_regs *ctx);
SEC("kretprobe/skb_copy_datagram_iter") int kretprobe__skb_copy_datagram_iter(struct pt_regs *ctx);
SEC("kprobe/handle_mm_fault") int kprobe__handle_mm_fault(struct pt_regs *ctx);
SEC("uprobe") int trace_uprobe_entry(struct pt_regs *ctx);
SEC("uretprobe") int trace_uprobe_return(struct pt_regs *ctx);
SEC("kprobe/tcp_sendmsg") int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size);
SEC("kretprobe/tcp_sendmsg") int kretprobe__tcp_sendmsg(struct pt_regs *ctx);
SEC("kprobe/__tcp_transmit_skb") int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb);
SEC("kprobe/ip_output") int kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb);
SEC("kprobe/ipv6_rcv") int kprobe__ipv6_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/ip6_output") int kprobe__ip6_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb);
SEC("kprobe/tcp_v6_rcv") int kprobe__tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/udp_rcv") int kprobe__udp_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/udp_recvmsg") int kprobe__udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len);
SEC("kretprobe/udp_recvmsg") int kretprobe__udp_recvmsg(struct pt_regs *ctx);
SEC("kprobe/udp_sendmsg") int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len);
SEC("kprobe/icmp_rcv") int kprobe__icmp_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/arp_rcv") int kprobe__arp_rcv(struct pt_regs *ctx, struct sk_buff *skb);
SEC("kprobe/unix_stream_recvmsg") int kprobe__unix_stream_recvmsg(struct pt_regs *ctx, struct socket *sock);
SEC("kprobe/unix_stream_sendmsg") int kprobe__unix_stream_sendmsg(struct pt_regs *ctx, struct socket *sock);

#endif /* KRAY_BPF_CORE_COMPAT_H */
