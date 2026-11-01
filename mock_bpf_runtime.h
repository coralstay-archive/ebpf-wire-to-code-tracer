/*
 * mock_bpf_runtime.h — User-Space Native Emulation Runtime for tracer_kernel.c
 * Allows compiling tracer_kernel.c directly into a native shared library
 * (libtracer_kernel_sim.dylib / .so) and executing all eBPF kernel hooks
 * from Python/C unit tests with full map, ringbuffer, and fault-injection support.
 */
#ifndef MOCK_BPF_RUNTIME_H
#define MOCK_BPF_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  s32;
typedef int64_t  s64;

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static inline u16 bpf_ntohs(u16 v) { return __builtin_bswap16(v); }
static inline u16 bpf_htons(u16 v) { return __builtin_bswap16(v); }
static inline u32 bpf_ntohl(u32 v) { return __builtin_bswap32(v); }
static inline u32 bpf_htonl(u32 v) { return __builtin_bswap32(v); }

/* ============================================================================
 * Standard BPF Map Update Flags & Kernel Error Codes (include/uapi/linux/bpf.h)
 * ============================================================================ */
#ifndef BPF_ANY
#define BPF_ANY         0ULL /* create new element or update existing */
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST     1ULL /* create new element if it didn't exist */
#endif
#ifndef BPF_F_NO_EXIST
#define BPF_F_NO_EXIST  1ULL /* alias used in specifications/tests */
#endif
#ifndef BPF_EXIST
#define BPF_EXIST       2ULL /* update existing element */
#endif
#ifndef BPF_F_EXIST
#define BPF_F_EXIST     2ULL
#endif

#define KRAY_ERR_ENOENT  (-2)
#define KRAY_ERR_E2BIG   (-7)
#define KRAY_ERR_EEXIST  (-17)
#define KRAY_ERR_EINVAL  (-22)

/* ============================================================================
 * Kernel Networking & Tracing Structs (Rocky Linux 9.8 aarch64 Layout)
 * ============================================================================ */
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP    = 1,
    XDP_PASS    = 2,
    XDP_TX      = 3,
    XDP_REDIRECT = 4
};

struct xdp_md {
    u64 data;
    u64 data_end;
    u64 data_meta;
    u32 ingress_ifindex;
    u32 rx_queue_index;
    u32 egress_ifindex;
};

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    u16 h_proto;
} __attribute__((packed));

struct iphdr {
    u8  ihl:4,
        version:4;
    u8  tos;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u8  ttl;
    u8  protocol;
    u16 check;
    u32 saddr;
    u32 daddr;
} __attribute__((packed));

struct in6_addr {
    union {
        u8  u6_addr8[16];
        u16 u6_addr16[8];
        u32 u6_addr32[4];
    } in6_u;
};

struct ipv6hdr {
    u8  priority:4,
        version:4;
    u8  flow_lbl[3];
    u16 payload_len;
    u8  nexthdr;
    u8  hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
} __attribute__((packed));

struct tcphdr {
    u16 source;
    u16 dest;
    u32 seq;
    u32 ack_seq;
    u16 res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
    u16 window;
    u16 check;
    u16 urg_ptr;
} __attribute__((packed));

struct udphdr {
    u16 source;
    u16 dest;
    u16 len;
    u16 check;
} __attribute__((packed));

struct icmphdr {
    u8  type;
    u8  code;
    u16 checksum;
    union {
        struct {
            u16 id;
            u16 sequence;
        } echo;
        u32 gateway;
    } un;
} __attribute__((packed));

struct arphdr {
    u16 ar_hrd;
    u16 ar_pro;
    unsigned char ar_hln;
    unsigned char ar_pln;
    u16 ar_op;
} __attribute__((packed));

struct sk_buff {
    unsigned char *head;
    unsigned char *data;
    u16 network_header;
    u16 transport_header;
    u16 protocol;
    u16 vlan_tci;
    u32 len;
};

struct sock_common {
    u32 skc_daddr;
    u32 skc_rcv_saddr;
    u16 skc_dport;
    u16 skc_num;
    u16 skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
};

struct sock {
    struct sock_common __sk_common;
};

struct unix_sock {
    struct sock sk;
    struct sock *peer;
};

struct socket {
    struct sock *sk;
};

struct msghdr {
    void *msg_name;
    int   msg_namelen;
};

struct net {
    int dummy;
};

struct pt_regs {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

#define PT_REGS_PARM1(ctx) ((ctx)->regs[0])
#define PT_REGS_PARM2(ctx) ((ctx)->regs[1])
#define PT_REGS_PARM3(ctx) ((ctx)->regs[2])
#define PT_REGS_RC(ctx)    ((ctx)->regs[0])
#define PT_REGS_IP(ctx)    ((ctx)->pc)

/* ============================================================================
 * Tracepoint Argument Structs
 * ============================================================================ */
typedef struct { void *skbaddr; unsigned int len; } tp_args_net_netif_receive_skb_t;
typedef struct { void *skbaddr; unsigned int len; } tp_args_net_net_dev_queue_t;
typedef struct { void *skbaddr; unsigned int len; int rc; } tp_args_net_net_dev_xmit_t;
typedef struct {
    const void *skbaddr;
    const void *skaddr;
    int state;
    u16 sport;
    u16 dport;
    u16 family;
    u8  saddr[4];
    u8  daddr[4];
    u8  saddr_v6[16];
    u8  daddr_v6[16];
} tp_args_tcp_tcp_retransmit_skb_t;
typedef struct {
    void *skbaddr;
    void *location;
    void *rx_sk;
    u16   protocol;
    int   reason;
} tp_args_skb_kfree_skb_t;
typedef struct { const void *skbaddr; int len; } tp_args_skb_skb_copy_datagram_iovec_t;
typedef struct { union { int nr; long id; }; unsigned long op; unsigned long args[6]; } tp_args_syscalls_sys_enter_read_t;
typedef struct { union { int nr; long id; }; unsigned long op; unsigned long args[6]; } tp_args_syscalls_sys_enter_futex_t;
typedef struct { union { int nr; long id; }; long ret; } tp_args_syscalls_sys_exit_futex_t;
typedef struct { union { int nr; long id; }; unsigned long op; unsigned long args[6]; } tp_args_syscalls_sys_enter_write_t;
typedef struct { union { int nr; long id; }; long ret; } tp_args_syscalls_sys_exit_write_t;
typedef struct { union { int nr; long id; }; unsigned long op; unsigned long args[6]; } tp_args_syscalls_sys_enter_epoll_pwait_t;
typedef struct { union { int nr; long id; }; long ret; } tp_args_syscalls_sys_exit_epoll_pwait_t;
typedef struct { union { int nr; long id; }; unsigned long op; unsigned long args[6]; } tp_args_syscalls_sys_enter_epoll_wait_t;
typedef struct { union { int nr; long id; }; long ret; } tp_args_syscalls_sys_exit_epoll_wait_t;
typedef struct { int parent_pid; int child_pid; } tp_args_sched_sched_process_fork_t;
typedef struct { int pid; int prio; int target_cpu; } tp_args_sched_sched_waking_t;
typedef struct { int pid; int prio; int target_cpu; } tp_args_sched_sched_wakeup_t;
typedef struct { int prev_pid; int next_pid; long prev_state; } tp_args_sched_sched_switch_t;
typedef struct { u32 dev; u64 sector; u32 nr_sector; u32 bytes; } tp_args_block_block_rq_insert_t;
typedef struct { u32 dev; u64 sector; u32 nr_sector; u32 bytes; } tp_args_block_block_rq_issue_t;
typedef struct { u32 dev; u64 sector; u32 nr_sector; int error; } tp_args_block_block_rq_complete_t;

#define TRACEPOINT_PROBE(category, event) \
    int tracepoint__##category##__##event(tp_args_##category##_##event##_t *args)

/* ============================================================================
 * Controllable User-Space BPF Helpers & Fault-Injection State
 * ============================================================================ */
#define KRAY_SIM_MAX_CPUS 16

static u64 g_sim_clock_ns        = 1000000000ULL;
static u64 g_sim_pid_tgid        = ((1000ULL << 32) | 1000ULL);
static u32 g_sim_cpu_id          = 0;
static int g_sim_ringbuf_full    = 0;
static u64 g_sim_lru_seq         = 1ULL;

static inline u64 bpf_ktime_get_ns(void) {
    u64 cur = g_sim_clock_ns;
    g_sim_clock_ns += 1000ULL;
    return cur;
}

static inline u64 bpf_get_current_pid_tgid(void) {
    return g_sim_pid_tgid;
}

static inline u32 bpf_get_smp_processor_id(void) {
    return g_sim_cpu_id % KRAY_SIM_MAX_CPUS;
}

static inline int bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr) {
    if (!dst)
        return -1;
    if (!unsafe_ptr) {
        memset(dst, 0, size);
        return -1;
    }
    memcpy(dst, unsafe_ptr, size);
    return 0;
}

/* ============================================================================
 * In-Memory BPF Map & RingBuffer Emulation Macros (True LRU, Capacity & Flags)
 * ============================================================================ */
#define KRAY_DEFINE_SIM_HASH_INTERNAL(name, key_t, val_t, max_entries, default_lru) \
    struct __sim_entry_##name { \
        int   used; \
        u64   last_used; \
        key_t key; \
        val_t val; \
    }; \
    static struct __sim_entry_##name __sim_store_##name[max_entries]; \
    static int __sim_cap_##name = (max_entries); \
    static int __sim_is_lru_##name = (default_lru); \
    static val_t *__sim_lookup_##name(const key_t *k) { \
        if (!k) return NULL; \
        int cap = (__sim_cap_##name > 0 && __sim_cap_##name <= (max_entries)) ? __sim_cap_##name : (max_entries); \
        for (int i = 0; i < cap; i++) { \
            if (__sim_store_##name[i].used && memcmp(&__sim_store_##name[i].key, k, sizeof(key_t)) == 0) { \
                __sim_store_##name[i].last_used = ++g_sim_lru_seq; \
                return &__sim_store_##name[i].val; \
            } \
        } \
        return NULL; \
    } \
    static int __sim_update_flags_##name(const key_t *k, const val_t *v, u64 flags) { \
        if (!k || !v) return KRAY_ERR_EINVAL; \
        if (flags > BPF_EXIST) return KRAY_ERR_EINVAL; \
        int cap = (__sim_cap_##name > 0 && __sim_cap_##name <= (max_entries)) ? __sim_cap_##name : (max_entries); \
        for (int i = 0; i < cap; i++) { \
            if (__sim_store_##name[i].used && memcmp(&__sim_store_##name[i].key, k, sizeof(key_t)) == 0) { \
                if (flags == BPF_NOEXIST) \
                    return KRAY_ERR_EEXIST; \
                memcpy(&__sim_store_##name[i].val, v, sizeof(val_t)); \
                __sim_store_##name[i].last_used = ++g_sim_lru_seq; \
                return 0; \
            } \
        } \
        if (flags == BPF_EXIST) \
            return KRAY_ERR_ENOENT; \
        for (int i = 0; i < cap; i++) { \
            if (!__sim_store_##name[i].used) { \
                __sim_store_##name[i].used = 1; \
                __sim_store_##name[i].last_used = ++g_sim_lru_seq; \
                memcpy(&__sim_store_##name[i].key, k, sizeof(key_t)); \
                memcpy(&__sim_store_##name[i].val, v, sizeof(val_t)); \
                return 0; \
            } \
        } \
        if (!__sim_is_lru_##name) \
            return KRAY_ERR_E2BIG; \
        /* True LRU eviction: find entry with minimum last_used sequence */ \
        int victim = 0; \
        u64 min_seq = __sim_store_##name[0].last_used; \
        for (int i = 1; i < cap; i++) { \
            if (__sim_store_##name[i].last_used < min_seq) { \
                min_seq = __sim_store_##name[i].last_used; \
                victim = i; \
            } \
        } \
        __sim_store_##name[victim].used = 1; \
        __sim_store_##name[victim].last_used = ++g_sim_lru_seq; \
        memcpy(&__sim_store_##name[victim].key, k, sizeof(key_t)); \
        memcpy(&__sim_store_##name[victim].val, v, sizeof(val_t)); \
        return 0; \
    } \
    static int __sim_update_##name(const key_t *k, const val_t *v) { \
        return __sim_update_flags_##name(k, v, BPF_ANY); \
    } \
    static int __sim_delete_##name(const key_t *k) { \
        if (!k) return KRAY_ERR_EINVAL; \
        int cap = (__sim_cap_##name > 0 && __sim_cap_##name <= (max_entries)) ? __sim_cap_##name : (max_entries); \
        for (int i = 0; i < cap; i++) { \
            if (__sim_store_##name[i].used && memcmp(&__sim_store_##name[i].key, k, sizeof(key_t)) == 0) { \
                __sim_store_##name[i].used = 0; \
                __sim_store_##name[i].last_used = 0; \
                return 0; \
            } \
        } \
        return KRAY_ERR_ENOENT; \
    } \
    struct __sim_map_ops_##name { \
        val_t *(*lookup)(const key_t *); \
        int (*update)(const key_t *, const val_t *); \
        int (*update_flags)(const key_t *, const val_t *, u64); \
        int (*delete)(const key_t *); \
    }; \
    static const struct __sim_map_ops_##name name = { \
        .lookup       = __sim_lookup_##name, \
        .update       = __sim_update_##name, \
        .update_flags = __sim_update_flags_##name, \
        .delete       = __sim_delete_##name, \
    }

#define BPF_LRU_HASH(name, key_t, val_t, max_entries) \
    KRAY_DEFINE_SIM_HASH_INTERNAL(name, key_t, val_t, max_entries, 1)

#define BPF_HASH(name, key_t, val_t, max_entries) \
    KRAY_DEFINE_SIM_HASH_INTERNAL(name, key_t, val_t, max_entries, 0)

#define BPF_ARRAY(name, val_t, max_entries) \
    static val_t __sim_arr_##name[max_entries]; \
    static val_t *__sim_arr_lookup_##name(const u32 *idx) { \
        if (!idx || *idx >= (max_entries)) return NULL; \
        return &__sim_arr_##name[*idx]; \
    } \
    static int __sim_arr_update_flags_##name(const u32 *idx, const val_t *v, u64 flags) { \
        if (!idx || !v || *idx >= (max_entries)) return KRAY_ERR_EINVAL; \
        if (flags == BPF_NOEXIST) return KRAY_ERR_EEXIST; \
        if (flags > BPF_EXIST) return KRAY_ERR_EINVAL; \
        memcpy(&__sim_arr_##name[*idx], v, sizeof(val_t)); \
        return 0; \
    } \
    static int __sim_arr_update_##name(const u32 *idx, const val_t *v) { \
        return __sim_arr_update_flags_##name(idx, v, BPF_ANY); \
    } \
    struct __sim_arr_ops_##name { \
        val_t *(*lookup)(const u32 *); \
        int (*update)(const u32 *, const val_t *); \
        int (*update_flags)(const u32 *, const val_t *, u64); \
    }; \
    static const struct __sim_arr_ops_##name name = { \
        .lookup       = __sim_arr_lookup_##name, \
        .update       = __sim_arr_update_##name, \
        .update_flags = __sim_arr_update_flags_##name, \
    }

/*
 * True Per-CPU Array Emulation:
 * Indexes into __sim_percpu_arr_##name[bpf_get_smp_processor_id()][*idx] so
 * per-CPU template mutation or cross-CPU isolation can be accurately verified.
 */
#define BPF_PERCPU_ARRAY(name, val_t, max_entries) \
    static val_t __sim_percpu_arr_##name[KRAY_SIM_MAX_CPUS][max_entries]; \
    static val_t *__sim_percpu_lookup_##name(const u32 *idx) { \
        if (!idx || *idx >= (max_entries)) return NULL; \
        u32 cpu = bpf_get_smp_processor_id(); \
        return &__sim_percpu_arr_##name[cpu][*idx]; \
    } \
    static int __sim_percpu_update_flags_##name(const u32 *idx, const val_t *v, u64 flags) { \
        if (!idx || !v || *idx >= (max_entries)) return KRAY_ERR_EINVAL; \
        if (flags == BPF_NOEXIST) return KRAY_ERR_EEXIST; \
        if (flags > BPF_EXIST) return KRAY_ERR_EINVAL; \
        u32 cpu = bpf_get_smp_processor_id(); \
        memcpy(&__sim_percpu_arr_##name[cpu][*idx], v, sizeof(val_t)); \
        return 0; \
    } \
    static int __sim_percpu_update_##name(const u32 *idx, const val_t *v) { \
        return __sim_percpu_update_flags_##name(idx, v, BPF_ANY); \
    } \
    struct __sim_percpu_ops_##name { \
        val_t *(*lookup)(const u32 *); \
        int (*update)(const u32 *, const val_t *); \
        int (*update_flags)(const u32 *, const val_t *, u64); \
    }; \
    static const struct __sim_percpu_ops_##name name = { \
        .lookup       = __sim_percpu_lookup_##name, \
        .update       = __sim_percpu_update_##name, \
        .update_flags = __sim_percpu_update_flags_##name, \
    }

#define bpf_map_lookup_elem(map, key)            ((map)->lookup(key))
#define bpf_map_update_elem(map, key, val, flg)  ((map)->update_flags((key), (val), (flg)))
#define bpf_map_delete_elem(map, key)            ((map)->delete(key))

#define KRAY_SIM_RINGBUF_MAX_EVENTS 4096

/*
 * Fidelity Note: Real kernel bpf_ringbuf_reserve() does NOT zero-fill memory;
 * we poison reserved slots with 0xAA to catch any uninitialized struct fields.
 */
#define BPF_RINGBUF_OUTPUT(name, pages) \
    static unsigned char __sim_rb_buf_##name[KRAY_SIM_RINGBUF_MAX_EVENTS][64]; \
    static u32 __sim_rb_write_##name = 0; \
    static u32 __sim_rb_read_##name  = 0; \
    static void *__sim_rb_reserve_##name(u64 size) { \
        if (g_sim_ringbuf_full || size > 64) \
            return NULL; \
        if ((__sim_rb_write_##name - __sim_rb_read_##name) >= KRAY_SIM_RINGBUF_MAX_EVENTS) \
            return NULL; \
        u32 idx = __sim_rb_write_##name % KRAY_SIM_RINGBUF_MAX_EVENTS; \
        memset(__sim_rb_buf_##name[idx], 0xAA, 64); \
        return (void *)__sim_rb_buf_##name[idx]; \
    } \
    static void __sim_rb_submit_##name(void *data, u64 flags) { \
        (void)data; \
        (void)flags; \
        __sim_rb_write_##name++; \
    } \
    struct __sim_rb_ops_##name { \
        void *(*ringbuf_reserve)(u64); \
        void (*ringbuf_submit)(void *, u64); \
    }; \
    static const struct __sim_rb_ops_##name name = { \
        .ringbuf_reserve = __sim_rb_reserve_##name, \
        .ringbuf_submit  = __sim_rb_submit_##name, \
    }

#endif /* MOCK_BPF_RUNTIME_H */
