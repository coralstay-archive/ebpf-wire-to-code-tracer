/*
 * kernel_sim_harness.c — Native C Execution Harness for tracer_kernel.c
 * Compiles tracer_kernel.c under KRAY_USER_SIM into a shared library
 * (libtracer_kernel_sim.dylib / .so) so unit tests can directly invoke every
 * eBPF hook function and inspect map states and emitted kray_event_t records.
 */

#define KRAY_USER_SIM 1
#include "tracer_kernel.c"

/* ============================================================================
 * Simulation Control & Inspection API (Exported for Python ctypes)
 * ============================================================================ */
void sim_reset_all(void)
{
    memset(__sim_arr_runtime_config_map, 0, sizeof(__sim_arr_runtime_config_map));
    memset(__sim_store_ingress_flow_map, 0, sizeof(__sim_store_ingress_flow_map));
    memset(__sim_store_active_ctx_map, 0, sizeof(__sim_store_active_ctx_map));
    memset(__sim_percpu_arr_zero_ctx_map, 0, sizeof(__sim_percpu_arr_zero_ctx_map));
    memset(__sim_store_pending_handoff_map, 0, sizeof(__sim_store_pending_handoff_map));
    memset(__sim_percpu_arr_zero_ring_map, 0, sizeof(__sim_percpu_arr_zero_ring_map));
    memset(__sim_store_egress_flow_map, 0, sizeof(__sim_store_egress_flow_map));
    memset(__sim_store_skb_egress_map, 0, sizeof(__sim_store_skb_egress_map));
    memset(__sim_store_inflight_bio_map, 0, sizeof(__sim_store_inflight_bio_map));
    memset(__sim_rb_buf_events, 0, sizeof(__sim_rb_buf_events));
    memset(__sim_arr_drop_cnt_map, 0, sizeof(__sim_arr_drop_cnt_map));

    __sim_cap_ingress_flow_map    = 8192;
    __sim_cap_active_ctx_map      = 8192;
    __sim_cap_pending_handoff_map = 1024;
    __sim_cap_egress_flow_map     = 8192;
    __sim_cap_skb_egress_map      = 8192;
    __sim_cap_inflight_bio_map    = 4096;

    __sim_is_lru_ingress_flow_map    = 1;
    __sim_is_lru_active_ctx_map      = 1;
    __sim_is_lru_pending_handoff_map = 1;
    __sim_is_lru_egress_flow_map     = 1;
    __sim_is_lru_skb_egress_map      = 1;
    __sim_is_lru_inflight_bio_map    = 1;

    __sim_rb_write_events = 0;
    __sim_rb_read_events  = 0;
    g_sim_clock_ns        = 1000000000ULL;
    g_sim_pid_tgid        = ((1000ULL << 32) | 1000ULL);
    g_sim_cpu_id          = 0;
    g_sim_ringbuf_full    = 0;
    g_sim_lru_seq         = 1ULL;
}

void sim_set_clock_ns(u64 ns)
{
    g_sim_clock_ns = ns;
}

void sim_set_context(u32 tgid, u32 tid, u32 cpu_id)
{
    g_sim_pid_tgid = (((u64)tgid) << 32) | (u64)tid;
    g_sim_cpu_id   = cpu_id;
}

void sim_set_ringbuf_full(int full)
{
    g_sim_ringbuf_full = full;
}

void sim_configure_runtime(u32 target_pid, u16 target_port, u8 capture_enabled, u64 epoch)
{
    u32 zero = 0;
    struct kray_runtime_cfg_t cfg = {};
    cfg.target_pid      = target_pid;
    cfg.target_port     = target_port;
    cfg.capture_enabled = capture_enabled;
    cfg.config_epoch    = epoch;
    runtime_config_map.update(&zero, &cfg);
}

u32 sim_pending_events_count(void)
{
    return __sim_rb_write_events - __sim_rb_read_events;
}

int sim_pop_event(struct kray_event_t *out_ev)
{
    if (__sim_rb_read_events >= __sim_rb_write_events)
        return 0;
    u32 idx = __sim_rb_read_events % KRAY_SIM_RINGBUF_MAX_EVENTS;
    if (out_ev)
        memcpy(out_ev, __sim_rb_buf_events[idx], sizeof(struct kray_event_t));
    __sim_rb_read_events++;
    return 1;
}

u64 sim_get_drop_count(void)
{
    u32 zero = 0;
    u64 *cnt = drop_cnt_map.lookup(&zero);
    return cnt ? *cnt : 0;
}

int sim_has_active_ctx(u32 tid)
{
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    return (tctx != NULL && tctx->req_id != 0) ? 1 : 0;
}

u64 sim_get_tid_req_id(u32 tid)
{
    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    return tctx ? tctx->req_id : 0;
}

/* ============================================================================
 * Focus Area 1: Per-CPU Template Integrity & In-Place Mutation Falsification
 * ============================================================================ */
int sim_verify_zero_templates_untouched(void)
{
    const u8 *ctx_bytes = (const u8 *)__sim_percpu_arr_zero_ctx_map;
    for (size_t i = 0; i < sizeof(__sim_percpu_arr_zero_ctx_map); i++) {
        if (ctx_bytes[i] != 0)
            return 0;
    }
    const u8 *ring_bytes = (const u8 *)__sim_percpu_arr_zero_ring_map;
    for (size_t i = 0; i < sizeof(__sim_percpu_arr_zero_ring_map); i++) {
        if (ring_bytes[i] != 0)
            return 0;
    }
    return 1;
}

int sim_test_percpu_template_poisoning(u32 polluted_cpu, u32 clean_cpu)
{
    u32 zero = 0;
    /* Simulate buggy in-place mutation of zero_ctx_map[0] on polluted_cpu */
    sim_set_context(9000, 9001, polluted_cpu);
    struct tid_ctx_t *z_bad = zero_ctx_map.lookup(&zero);
    if (!z_bad)
        return -1;
    z_bad->req_id      = 0xDEADCAFEBEEFULL;
    z_bad->page_faults = 77;
    z_bad->call_depth  = 9;

    /* Verify sim_verify_zero_templates_untouched immediately detects the corruption */
    if (sim_verify_zero_templates_untouched() != 0)
        return -2;

    /* Verify clean_cpu per-CPU slot is strictly isolated from polluted_cpu */
    sim_set_context(9000, 9002, clean_cpu);
    struct tid_ctx_t *z_clean = zero_ctx_map.lookup(&zero);
    if (!z_clean || z_clean->req_id != 0 || z_clean->page_faults != 0 || z_clean->call_depth != 0)
        return -3;

    /* Restore zero_ctx_map on polluted_cpu */
    memset(__sim_percpu_arr_zero_ctx_map, 0, sizeof(__sim_percpu_arr_zero_ctx_map));
    return sim_verify_zero_templates_untouched() == 1 ? 0 : -4;
}

/* ============================================================================
 * Focus Area 2: BPF Map Capacity (max_entries), True LRU vs Strict Hash, & Flags
 * ============================================================================ */
int sim_test_map_capacity_and_flags(void)
{
    sim_reset_all();

    /* 1. Test BPF_NOEXIST (BPF_F_NO_EXIST), BPF_EXIST (BPF_F_EXIST), BPF_ANY & invalid flags */
    u32 tid_key = 4242;
    u32 missing_key = 9999;
    struct tid_ctx_t val1 = {};
    struct tid_ctx_t val2 = {};
    val1.req_id = 0x1111ULL;
    val2.req_id = 0x2222ULL;

    /* Updating non-existent key with BPF_EXIST must fail with KRAY_ERR_ENOENT (-2) */
    if (bpf_map_update_elem(&active_ctx_map, &missing_key, &val1, BPF_EXIST) != KRAY_ERR_ENOENT)
        return -1;

    /* Inserting new key with BPF_NOEXIST (BPF_F_NO_EXIST) must succeed (0) */
    if (bpf_map_update_elem(&active_ctx_map, &tid_key, &val1, BPF_F_NO_EXIST) != 0)
        return -2;

    /* Re-inserting existing key with BPF_F_NO_EXIST must fail with KRAY_ERR_EEXIST (-17) and preserve val1 */
    if (bpf_map_update_elem(&active_ctx_map, &tid_key, &val2, BPF_F_NO_EXIST) != KRAY_ERR_EEXIST)
        return -3;
    struct tid_ctx_t *looked = bpf_map_lookup_elem(&active_ctx_map, &tid_key);
    if (!looked || looked->req_id != 0x1111ULL)
        return -4;

    /* Updating existing key with BPF_EXIST must succeed (0) and overwrite with val2 */
    if (bpf_map_update_elem(&active_ctx_map, &tid_key, &val2, BPF_EXIST) != 0)
        return -5;
    looked = bpf_map_lookup_elem(&active_ctx_map, &tid_key);
    if (!looked || looked->req_id != 0x2222ULL)
        return -6;

    /* Invalid flag (> BPF_EXIST) or NULL key/val must return KRAY_ERR_EINVAL (-22) */
    if (bpf_map_update_elem(&active_ctx_map, &tid_key, &val2, 99ULL) != KRAY_ERR_EINVAL)
        return -7;
    if (bpf_map_update_elem(&active_ctx_map, NULL, &val2, BPF_ANY) != KRAY_ERR_EINVAL)
        return -8;

    /* 2. Test strict capacity limit (-E2BIG = -7) when non-LRU hash table reaches max_entries */
    sim_reset_all();
    __sim_cap_active_ctx_map    = 4;
    __sim_is_lru_active_ctx_map = 0; /* Strict BPF_MAP_TYPE_HASH mode */
    for (u32 k = 1; k <= 4; k++) {
        struct tid_ctx_t v = {};
        v.req_id = k * 100ULL;
        if (bpf_map_update_elem(&active_ctx_map, &k, &v, BPF_ANY) != 0)
            return -9;
    }
    /* 5th distinct key must fail with KRAY_ERR_E2BIG (-7) */
    u32 fifth_key = 5;
    if (bpf_map_update_elem(&active_ctx_map, &fifth_key, &val1, BPF_ANY) != KRAY_ERR_E2BIG)
        return -10;
    /* Updating an existing key (k=2) when full must still succeed (0) */
    u32 second_key = 2;
    if (bpf_map_update_elem(&active_ctx_map, &second_key, &val2, BPF_EXIST) != 0)
        return -11;

    /* 3. Test True LRU eviction in BPF_LRU_HASH (accessing key=1 protects it from eviction!) */
    sim_reset_all();
    __sim_cap_active_ctx_map    = 4;
    __sim_is_lru_active_ctx_map = 1; /* True LRU mode */
    for (u32 k = 1; k <= 4; k++) {
        struct tid_ctx_t v = {};
        v.req_id = k * 100ULL;
        if (active_ctx_map.update(&k, &v) != 0)
            return -12;
    }
    /* Touch key=1 via lookup so key=2 becomes the Least Recently Used entry */
    u32 hot_key = 1;
    u32 cold_key = 2;
    if (active_ctx_map.lookup(&hot_key) == NULL)
        return -13;
    /* Insert key=5: must evict cold_key (2), NOT hot_key (1)! */
    if (active_ctx_map.update(&fifth_key, &val1) != 0)
        return -14;
    if (active_ctx_map.lookup(&hot_key) == NULL)
        return -15; /* Failed: round-robin evicted hot_key (1)! */
    if (active_ctx_map.lookup(&cold_key) != NULL)
        return -16; /* Failed: cold_key (2) was not evicted! */

    /* 4. Verify real max_entries > 256 (e.g. 300 concurrent entries in active_ctx_map) without eviction */
    sim_reset_all();
    for (u32 k = 1; k <= 300; k++) {
        struct tid_ctx_t v = {};
        v.req_id = k;
        if (active_ctx_map.update(&k, &v) != 0)
            return -17;
    }
    for (u32 k = 1; k <= 300; k++) {
        struct tid_ctx_t *p = active_ctx_map.lookup(&k);
        if (!p || p->req_id != k)
            return -18;
    }

    sim_reset_all();
    return 0;
}

/* ============================================================================
 * High-Level Hook Invokers for Unit & Fuzz Testing
 * ============================================================================ */
int sim_run_xdp_raw_frame(const u8 *frame, u32 frame_len)
{
    struct xdp_md ctx = {};
    ctx.data     = (u64)(uintptr_t)frame;
    ctx.data_end = (u64)(uintptr_t)(frame + frame_len);
    return xdp_ingress_filter(&ctx);
}

/* Build a synthetic IPv4+TCP packet buffer and invoke XDP / netif_receive_skb / ip_rcv / tcp_v4_rcv */
static void build_ipv4_tcp_buf(
    u8 *buf, u32 saddr, u32 daddr, u16 sport, u16 dport,
    u8 ihl_words, u16 payload_len, u8 syn, u8 ack, u8 psh, u8 fin,
    u16 *out_net_off, u16 *out_trans_off, u16 *out_total_len)
{
    memset(buf, 0, 512);
    struct ethhdr *eth = (struct ethhdr *)buf;
    eth->h_proto = bpf_htons(ETH_P_IP_HOST);

    u16 net_off = sizeof(struct ethhdr);
    struct iphdr *iph = (struct iphdr *)(buf + net_off);
    u16 ihl_bytes = (u16)(ihl_words * 4);
    u16 tcp_bytes = sizeof(struct tcphdr);
    u16 ip_tot    = ihl_bytes + tcp_bytes + payload_len;

    iph->version  = 4;
    iph->ihl      = ihl_words;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->tot_len  = bpf_htons(ip_tot);
    iph->saddr    = saddr;
    iph->daddr    = daddr;

    u16 trans_off = net_off + ihl_bytes;
    struct tcphdr *tcph = (struct tcphdr *)(buf + trans_off);
    tcph->source = bpf_htons(sport);
    tcph->dest   = bpf_htons(dport);
    tcph->doff   = 5;
    tcph->syn    = syn ? 1 : 0;
    tcph->ack    = ack ? 1 : 0;
    tcph->psh    = psh ? 1 : 0;
    tcph->fin    = fin ? 1 : 0;

    *out_net_off   = net_off;
    *out_trans_off = trans_off;
    *out_total_len = net_off + ip_tot;
}

int sim_tcp_v4_ingress_pipeline(
    u32 saddr, u32 daddr, u16 sport, u16 dport,
    u8 ihl_words, u16 payload_len, u8 syn, u8 ack, u8 psh, u8 fin,
    int run_xdp, int run_netif, int run_ip_rcv, int run_tcp_rcv)
{
    u8 pkt[512];
    u16 net_off = 0, trans_off = 0, total_len = 0;
    build_ipv4_tcp_buf(
        pkt, saddr, daddr, sport, dport,
        ihl_words, payload_len, syn, ack, psh, fin,
        &net_off, &trans_off, &total_len);

    if (run_xdp) {
        sim_run_xdp_raw_frame(pkt, total_len);
    }
    struct sk_buff skb = {};
    skb.head             = pkt;
    skb.data             = pkt + net_off; /* At netif_receive_skb entry, skb->data points to iphdr */
    skb.network_header   = net_off;
    skb.transport_header = trans_off;
    skb.len              = total_len - net_off;

    if (run_netif) {
        tp_args_net_netif_receive_skb_t args = { .skbaddr = &skb, .len = skb.len };
        tracepoint__net__netif_receive_skb(&args);
    }
    struct pt_regs regs = {};
    if (run_ip_rcv) {
        /* At ip_rcv entry, skb->transport_header is uninitialized (0xFFFF) */
        skb.transport_header = 0xFFFF;
        kprobe__ip_rcv(&regs, &skb);
        skb.transport_header = trans_off;
    }
    if (run_tcp_rcv) {
        kprobe__tcp_v4_rcv(&regs, &skb);
    }
    return 0;
}

int sim_tcp_recvmsg_call(
    u32 saddr, u32 daddr, u16 client_port, u16 server_port,
    int copied_bytes, int delayed_packet_arrival)
{
    struct sock sk = {};
    sk.__sk_common.skc_family    = AF_INET;
    sk.__sk_common.skc_num       = server_port;
    sk.__sk_common.skc_dport     = bpf_htons(client_port);
    sk.__sk_common.skc_daddr     = saddr;
    sk.__sk_common.skc_rcv_saddr = daddr;

    struct msghdr msg = {};
    struct pt_regs regs = {};

    /* Entry: if delayed_packet_arrival == 1, packet has not arrived in ingress_flow_map yet */
    kprobe__tcp_recvmsg(&regs, &sk, &msg, (size_t)(copied_bytes > 0 ? copied_bytes : 1024));

    if (delayed_packet_arrival) {
        /* Simulate packet arriving while thread was sleeping in sk_wait_data() */
        sim_tcp_v4_ingress_pipeline(
            saddr, daddr, client_port, server_port,
            5, (u16)(copied_bytes > 0 ? copied_bytes : 128), 0, 1, 1, 0,
            1, 0, 1, 1);
    }

    regs.regs[0] = (u64)(s64)copied_bytes;
    return kretprobe__tcp_recvmsg(&regs);
}

int sim_skb_copy_and_faults(int copied_len, int num_page_faults)
{
    tp_args_syscalls_sys_enter_read_t r_args = {};
    tracepoint__syscalls__sys_enter_read(&r_args);

    struct pt_regs regs = {};
    for (int i = 0; i < num_page_faults; i++) {
        kprobe__handle_mm_fault(&regs);
    }

    tp_args_skb_skb_copy_datagram_iovec_t c_args = { .skbaddr = NULL, .len = copied_len };
    tracepoint__skb__skb_copy_datagram_iovec(&c_args);

    return kretprobe__skb_copy_datagram_iter(&regs);
}

/*
 * Exercises the REAL L6 Pre-Compute Gate hook chain without manual map poking:
 * sys_enter_futex(FUTEX_WAIT) -> sys_enter_futex(FUTEX_WAKE) ->
 * sched_waking -> sched_wakeup -> sched_switch
 */
int sim_sched_waking_and_switch(
    u32 waker_tid, u32 worker_tid, u32 tgid,
    u8 waker_cpu, u8 worker_cpu, u64 lock_wait_ns, u64 runq_ns)
{
    u64 base_ts = g_sim_clock_ns;
    if (lock_wait_ns > 0) {
        /* 1. Worker enters FUTEX_WAIT (op = 0) at base_ts */
        sim_set_context(tgid, worker_tid, worker_cpu);
        sim_set_clock_ns(base_ts);
        tp_args_syscalls_sys_enter_futex_t f_wait = { .id = 98, .op = 0, .args = { 0, 0, 0, 0, 0, 0 } };
        tracepoint__syscalls__sys_enter_futex(&f_wait);

        /* 2. Waker issues FUTEX_WAKE (op = 1) + sched_waking + sched_wakeup at base_ts + lock_wait_ns */
        u64 wake_ts = base_ts + lock_wait_ns;
        sim_set_context(tgid, waker_tid, waker_cpu);
        sim_set_clock_ns(wake_ts);
        tp_args_syscalls_sys_enter_futex_t f_wake = { .id = 98, .op = 1, .args = { 0, 1, 0, 0, 0, 0 } };
        tracepoint__syscalls__sys_enter_futex(&f_wake);

        sim_set_clock_ns(wake_ts);
        tp_args_sched_sched_waking_t w_args = { .pid = (int)worker_tid, .prio = 120, .target_cpu = (int)worker_cpu };
        tracepoint__sched__sched_waking(&w_args);

        sim_set_clock_ns(wake_ts);
        tp_args_sched_sched_wakeup_t wu_args = { .pid = (int)worker_tid, .prio = 120, .target_cpu = (int)worker_cpu };
        tracepoint__sched__sched_wakeup(&wu_args);

        sim_set_clock_ns(wake_ts + runq_ns);
    } else {
        sim_set_context(tgid, waker_tid, waker_cpu);
        sim_set_clock_ns(base_ts);
        tp_args_sched_sched_waking_t w_args = { .pid = (int)worker_tid, .prio = 120, .target_cpu = (int)worker_cpu };
        tracepoint__sched__sched_waking(&w_args);

        sim_set_clock_ns(base_ts);
        tp_args_sched_sched_wakeup_t wu_args = { .pid = (int)worker_tid, .prio = 120, .target_cpu = (int)worker_cpu };
        tracepoint__sched__sched_wakeup(&wu_args);

        sim_set_clock_ns(base_ts + runq_ns);
    }

    sim_set_context(tgid, worker_tid, worker_cpu);
    tp_args_sched_sched_switch_t sw_args = {
        .prev_pid   = (int)waker_tid,
        .next_pid   = (int)worker_tid,
        .prev_state = 1
    };
    return tracepoint__sched__sched_switch(&sw_args);
}

int sim_uprobe_call(u64 entry_ip, u64 return_trampoline_ip, u64 duration_ns, int trigger_entry, int trigger_return)
{
    struct pt_regs regs = {};
    if (trigger_entry) {
        regs.pc = entry_ip;
        trace_uprobe_entry(&regs);
    }
    if (duration_ns > 0) {
        g_sim_clock_ns += duration_ns;
    }
    if (trigger_return) {
        /* Simulate kernel [uprobes] trampoline overwriting PT_REGS_IP(ctx) on uretprobe! */
        regs.pc = return_trampoline_ip;
        trace_uprobe_return(&regs);
    }
    return 0;
}

int sim_block_io_lifecycle(u32 dev, u64 sector, u32 nr_sector, u64 io_Issue_delay_ns, u64 io_complete_delay_ns, u32 irq_tid)
{
    u64 t0 = g_sim_clock_ns;
    tp_args_block_block_rq_insert_t ins = { .dev = dev, .sector = sector, .nr_sector = nr_sector, .bytes = nr_sector * 512 };
    tracepoint__block__block_rq_insert(&ins);

    g_sim_clock_ns = t0 + io_Issue_delay_ns;
    tp_args_block_block_rq_issue_t iss = { .dev = dev, .sector = sector, .nr_sector = nr_sector, .bytes = nr_sector * 512 };
    tracepoint__block__block_rq_issue(&iss);

    /* Complete in SoftIRQ / unrelated thread context (irq_tid) to verify bstate->tid preservation */
    u64 saved_pid_tgid = g_sim_pid_tgid;
    g_sim_pid_tgid = ((u64)irq_tid << 32) | (u64)irq_tid;
    g_sim_clock_ns = t0 + io_Issue_delay_ns + io_complete_delay_ns;

    tp_args_block_block_rq_complete_t cmp = { .dev = dev, .sector = sector, .nr_sector = nr_sector, .error = 0 };
    int rc = tracepoint__block__block_rq_complete(&cmp);
    g_sim_pid_tgid = saved_pid_tgid;
    return rc;
}

int sim_tcp_egress_pipeline(
    u32 server_ip, u32 client_ip, u16 server_port, u16 client_port,
    u16 payload_size, int test_ip_output_parm2_fallback)
{
    /* First verify sys_enter_write + sys_exit_write do NOT delete active_ctx_map */
    tp_args_syscalls_sys_enter_write_t ew = {};
    tp_args_syscalls_sys_exit_write_t xw = {};
    tracepoint__syscalls__sys_enter_write(&ew);
    tracepoint__syscalls__sys_exit_write(&xw);

    struct sock sk = {};
    sk.__sk_common.skc_family    = AF_INET;
    sk.__sk_common.skc_num       = server_port;
    sk.__sk_common.skc_dport     = bpf_htons(client_port);
    sk.__sk_common.skc_rcv_saddr = server_ip;
    sk.__sk_common.skc_daddr     = client_ip;

    struct msghdr msg = {};
    struct pt_regs regs = {};
    kprobe__tcp_sendmsg(&regs, &sk, &msg, payload_size);

    struct sk_buff oskb = {};
    struct sk_buff cloned_skb = {};
    struct sk_buff *post_clone_skb = test_ip_output_parm2_fallback ? &cloned_skb : &oskb;

    regs.regs[0] = (u64)(uintptr_t)&sk;
    regs.regs[1] = (u64)(uintptr_t)&oskb;
    kprobe____tcp_transmit_skb(&regs, &sk, &oskb);

    struct net dummy_net = {};
    struct pt_regs ip_regs = {};
    ip_regs.regs[0] = (u64)(uintptr_t)&dummy_net;
    ip_regs.regs[1] = (u64)(uintptr_t)&sk;
    ip_regs.regs[2] = (u64)(uintptr_t)post_clone_skb;
    kprobe__ip_output(&ip_regs, &dummy_net, &sk, post_clone_skb);

    tp_args_net_net_dev_queue_t q_args = { .skbaddr = post_clone_skb, .len = payload_size };
    tracepoint__net__net_dev_queue(&q_args);

    tp_args_net_net_dev_xmit_t x_args = { .skbaddr = post_clone_skb, .len = payload_size, .rc = 0 };
    tracepoint__net__net_dev_xmit(&x_args);

    kretprobe__tcp_sendmsg(&regs);
    return 0;
}

/* ============================================================================
 * Focus Area 3: Unified End-to-End Wire-to-Code Full Pipeline Wrapper
 * Executes xdp_ingress_filter -> netif_receive_skb -> ip_rcv -> tcp_v4_rcv ->
 * tcp_recvmsg -> sys_enter_read -> skb_copy_datagram_iovec -> kretprobe__skb_copy_datagram_iter ->
 * uprobe/uretprobe (Acceptor) -> sys_enter_futex -> sched_waking -> sched_wakeup -> sched_switch ->
 * uprobe (Worker) -> block_rq_insert -> block_rq_issue -> sched_switch (Off-CPU) ->
 * block_rq_complete -> sched_wakeup -> sched_switch (On-CPU) -> uretprobe (Worker) ->
 * sys_enter_write -> tcp_sendmsg -> __tcp_transmit_skb -> ip_output ->
 * net_dev_queue -> net_dev_xmit -> kretprobe__tcp_sendmsg in a single pass!
 * ============================================================================ */
int sim_run_full_wire_to_code_pipeline(
    u32 tgid, u32 acceptor_tid, u32 worker_tid,
    u32 client_ip, u32 server_ip, u16 client_port, u16 server_port,
    u16 req_payload_len, u16 resp_payload_len,
    u64 parse_fn_ip, u64 auth_fn_ip, u64 stripped_crypto_ip,
    u64 storage_query_ip, u64 format_resp_ip,
    int fast_mode)
{
    u64 t_cur = 1000000000ULL;
    sim_set_clock_ns(t_cur);
    sim_configure_runtime(tgid, server_port, 1, 1);

    u8 pkt[512];
    u16 net_off = 0, trans_off = 0, total_len = 0;
    build_ipv4_tcp_buf(
        pkt, client_ip, server_ip, client_port, server_port,
        5, req_payload_len, 0, 1, 1, 0,
        &net_off, &trans_off, &total_len);

    /* 1. L2 Ingress: xdp_ingress_filter + netif_receive_skb (deduplicated) on CPU 0 */
    sim_set_context(tgid, acceptor_tid, 0);
    sim_set_clock_ns(t_cur);
    sim_run_xdp_raw_frame(pkt, total_len);

    struct sk_buff rx_skb = {};
    rx_skb.head             = pkt;
    rx_skb.data             = pkt + net_off;
    rx_skb.network_header   = net_off;
    rx_skb.transport_header = trans_off;
    rx_skb.len              = total_len - net_off;

    tp_args_net_netif_receive_skb_t netif_args = { .skbaddr = &rx_skb, .len = rx_skb.len };
    tracepoint__net__netif_receive_skb(&netif_args);

    /* 2. L3 Ingress: kprobe__ip_rcv (+38us) */
    t_cur += 38000ULL;
    sim_set_clock_ns(t_cur);
    struct pt_regs regs = {};
    rx_skb.transport_header = 0xFFFF;
    kprobe__ip_rcv(&regs, &rx_skb);
    rx_skb.transport_header = trans_off;

    /* 3. L4 Ingress: kprobe__tcp_v4_rcv (+65us) */
    t_cur += 65000ULL;
    sim_set_clock_ns(t_cur);
    kprobe__tcp_v4_rcv(&regs, &rx_skb);

    /* 4. L4.5 Socket Ingress: kprobe__tcp_recvmsg + kretprobe__tcp_recvmsg (+195us dwell) */
    t_cur += 195000ULL;
    sim_set_clock_ns(t_cur);
    struct sock sk = {};
    sk.__sk_common.skc_family    = AF_INET;
    sk.__sk_common.skc_num       = server_port;
    sk.__sk_common.skc_dport     = bpf_htons(client_port);
    sk.__sk_common.skc_daddr     = client_ip;
    sk.__sk_common.skc_rcv_saddr = server_ip;
    struct msghdr msg = {};
    kprobe__tcp_recvmsg(&regs, &sk, &msg, req_payload_len);
    regs.regs[0] = req_payload_len;
    kretprobe__tcp_recvmsg(&regs);

    /* 5. L5 Syscall & SKB Copy to User (+25us) */
    sim_set_clock_ns(t_cur);
    tp_args_syscalls_sys_enter_read_t r_args = {};
    tracepoint__syscalls__sys_enter_read(&r_args);
    tp_args_skb_skb_copy_datagram_iovec_t c_args = { .skbaddr = &rx_skb, .len = req_payload_len };
    tracepoint__skb__skb_copy_datagram_iovec(&c_args);
    t_cur += 25000ULL;
    sim_set_clock_ns(t_cur);
    kretprobe__skb_copy_datagram_iter(&regs);

    /* 6. L7 Acceptor Thread Functions: parse_http_request, validate_auth_header, stripped libcrypto */
    u64 trampoline_ip = 0x7FFFFFFFE000ULL;
    if (parse_fn_ip != 0) {
        sim_set_clock_ns(t_cur);
        sim_uprobe_call(parse_fn_ip, trampoline_ip, 420000ULL, 1, 1);
        t_cur += 420000ULL;
    }
    if (auth_fn_ip != 0) {
        sim_set_clock_ns(t_cur);
        sim_uprobe_call(auth_fn_ip, trampoline_ip, 680000ULL, 1, 1);
        t_cur += 680000ULL;
    }
    if (stripped_crypto_ip != 0) {
        u64 crypto_dur = fast_mode ? 450000ULL : 3450000ULL;
        sim_set_clock_ns(t_cur);
        sim_uprobe_call(stripped_crypto_ip, trampoline_ip, crypto_dur, 1, 1);
        t_cur += crypto_dur;
    }

    /* 7. L6 Pre-Compute Gate: Futex Lock Wait (115us) + Runqueue Wait (65us) + CPU #0 -> CPU #2 Migration */
    sim_set_clock_ns(t_cur);
    sim_sched_waking_and_switch(acceptor_tid, worker_tid, tgid, 0, 2, 115000ULL, 65000ULL);
    t_cur += (115000ULL + 65000ULL);

    /* 8. L7 Worker Thread Functions: execute_storage_query (with Block I/O + Off-CPU sleep) & format_http_response */
    sim_set_context(tgid, worker_tid, 2);
    if (storage_query_ip != 0) {
        u64 bio_ns    = fast_mode ? 350000ULL  : 4275000ULL;
        u64 on_cpu_ns = fast_mode ? 850000ULL  : 17250000ULL;

        /* Enter execute_storage_query */
        sim_set_clock_ns(t_cur);
        sim_uprobe_call(storage_query_ip, trampoline_ip, 0, 1, 0);

        /* Issue Block I/O and switch Off-CPU during storage wait */
        tp_args_block_block_rq_insert_t ins = { .dev = 259, .sector = 8192, .nr_sector = 8, .bytes = 4096 };
        tracepoint__block__block_rq_insert(&ins);
        sim_set_clock_ns(t_cur);
        tp_args_block_block_rq_issue_t iss = { .dev = 259, .sector = 8192, .nr_sector = 8, .bytes = 4096 };
        tracepoint__block__block_rq_issue(&iss);

        /* Worker goes Off-CPU while waiting for Block I/O */
        sim_set_clock_ns(t_cur);
        tp_args_sched_sched_switch_t sw_out = { .prev_pid = (int)worker_tid, .next_pid = 0, .prev_state = 2 };
        tracepoint__sched__sched_switch(&sw_out);

        /* Block I/O completes in IRQ context after bio_ns */
        t_cur += bio_ns;
        sim_set_context(0, 9999, 2);
        sim_set_clock_ns(t_cur);
        tp_args_block_block_rq_complete_t cmp = { .dev = 259, .sector = 8192, .nr_sector = 8, .error = 0 };
        tracepoint__block__block_rq_complete(&cmp);

        /* Worker wakes up and switches back On-CPU */
        sim_set_context(tgid, worker_tid, 2);
        sim_set_clock_ns(t_cur);
        tp_args_sched_sched_wakeup_t wu = { .pid = (int)worker_tid, .prio = 120, .target_cpu = 2 };
        tracepoint__sched__sched_wakeup(&wu);
        sim_set_clock_ns(t_cur);
        tp_args_sched_sched_switch_t sw_in = { .prev_pid = 0, .next_pid = (int)worker_tid, .prev_state = 0 };
        tracepoint__sched__sched_switch(&sw_in);

        /* Pure On-CPU ALU scan completes, then uretprobe fires */
        t_cur += on_cpu_ns;
        sim_set_clock_ns(t_cur);
        sim_uprobe_call(storage_query_ip, trampoline_ip, 0, 0, 1);
    }

    if (format_resp_ip != 0) {
        sim_set_clock_ns(t_cur);
        sim_uprobe_call(format_resp_ip, trampoline_ip, 280000ULL, 1, 1);
        t_cur += 280000ULL;
    }

    /* 9. L5 Syscall Write (+22us) -> L4.5 Socket Egress kprobe__tcp_sendmsg (+66us) */
    sim_set_context(tgid, worker_tid, 2);
    sim_set_clock_ns(t_cur);
    tp_args_syscalls_sys_enter_write_t ew = {};
    tracepoint__syscalls__sys_enter_write(&ew);

    t_cur += 66000ULL;
    sim_set_clock_ns(t_cur);
    kprobe__tcp_sendmsg(&regs, &sk, &msg, resp_payload_len);

    tp_args_syscalls_sys_exit_write_t xw = {};
    tracepoint__syscalls__sys_exit_write(&xw);

    /* 10. L4 Egress (__tcp_transmit_skb +40us) -> L3 Egress (ip_output +32us) -> L2 Qdisc/Xmit (+70us, qdisc=18us) */
    struct sk_buff tx_skb = {};
    regs.regs[0] = (u64)(uintptr_t)&sk;
    regs.regs[1] = (u64)(uintptr_t)&tx_skb;

    t_cur += 40000ULL;
    sim_set_clock_ns(t_cur);
    kprobe____tcp_transmit_skb(&regs, &sk, &tx_skb);

    t_cur += 32000ULL;
    sim_set_clock_ns(t_cur);
    struct net dummy_net = {};
    struct pt_regs ip_regs = {};
    ip_regs.regs[0] = (u64)(uintptr_t)&dummy_net;
    ip_regs.regs[1] = (u64)(uintptr_t)&sk;
    ip_regs.regs[2] = (u64)(uintptr_t)&tx_skb;
    kprobe__ip_output(&ip_regs, &dummy_net, &sk, &tx_skb);

    t_cur += 52000ULL;
    sim_set_clock_ns(t_cur);
    tp_args_net_net_dev_queue_t q_args = { .skbaddr = &tx_skb, .len = resp_payload_len };
    tracepoint__net__net_dev_queue(&q_args);

    t_cur += 18000ULL;
    sim_set_clock_ns(t_cur);
    tp_args_net_net_dev_xmit_t x_args = { .skbaddr = &tx_skb, .len = resp_payload_len, .rc = 0 };
    tracepoint__net__net_dev_xmit(&x_args);

    kretprobe__tcp_sendmsg(&regs);
    return (int)sim_pending_events_count();
}

/* ============================================================================
 * Multi-Protocol, Fork, Retransmit & Drop Simulation Helpers
 * ============================================================================ */
int sim_tcp_retransmit_skb_test(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
    tp_args_tcp_tcp_retransmit_skb_t args = {};
    args.sport  = sport;
    args.dport  = dport;
    args.family = AF_INET;
    memcpy(args.saddr, &saddr, 4);
    memcpy(args.daddr, &daddr, 4);
    return tracepoint__tcp__tcp_retransmit_skb(&args);
}

int sim_sched_process_fork_test(u32 parent_tid, u32 child_tid)
{
    tp_args_sched_sched_process_fork_t args = {
        .parent_pid = (int)parent_tid,
        .child_pid  = (int)child_tid,
    };
    return tracepoint__sched__sched_process_fork(&args);
}

int sim_ip6_output_test(const u32 saddr6[4], const u32 daddr6[4], u16 sport, u16 dport, u16 payload_len)
{
    struct sock sk = {};
    sk.__sk_common.skc_family = AF_INET6;
    sk.__sk_common.skc_num    = sport;
    sk.__sk_common.skc_dport  = bpf_htons(dport);
    memcpy(sk.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, saddr6, 16);
    memcpy(sk.__sk_common.skc_v6_daddr.in6_u.u6_addr32, daddr6, 16);

    struct flow_key_t ekey = {};
    populate_sock_flow_key(&sk, &ekey, IPPROTO_TCP, 1);

    u64 now = bpf_ktime_get_ns();
    struct flow_state_t estate = {};
    estate.req_id     = 0x66001122ULL;
    estate.sendmsg_ts = now;
    estate.tcp_tx_ts  = now + 10000ULL;
    estate.pkt_len    = payload_len;
    egress_flow_map.update(&ekey, &estate);

    struct sk_buff skb = {};
    u64 skb_ptr = (u64)(uintptr_t)&skb;
    skb_egress_map.update(&skb_ptr, &ekey);

    struct net dummy_net = {};
    struct pt_regs ip6_regs = {};
    ip6_regs.regs[0] = (u64)(uintptr_t)&dummy_net;
    ip6_regs.regs[1] = (u64)(uintptr_t)&sk;
    ip6_regs.regs[2] = skb_ptr;
    return kprobe__ip6_output(&ip6_regs, &dummy_net, &sk, &skb);
}

int sim_arp_rcv_test(u32 sender_ip, u32 target_ip)
{
    u8 buf[128];
    memset(buf, 0, sizeof(buf));
    u16 net_off = 14;
    struct arphdr *arp = (struct arphdr *)(buf + net_off);
    arp->ar_hrd = bpf_htons(1);
    arp->ar_pro = bpf_htons(ETH_P_IP_HOST);
    arp->ar_hln = 6;
    arp->ar_pln = 4;
    arp->ar_op  = bpf_htons(1);

    u8 *arp_payload = (u8 *)(arp + 1);
    memcpy(arp_payload + 6, &sender_ip, 4);
    memcpy(arp_payload + 16, &target_ip, 4);

    struct sk_buff skb = {};
    skb.head           = buf;
    skb.network_header = net_off;
    struct pt_regs regs = {};
    return kprobe__arp_rcv(&regs, &skb);
}

int sim_icmp_rcv_test(u32 saddr, u32 daddr, u8 icmp_type, u8 icmp_code, u16 echo_id)
{
    u8 buf[128];
    memset(buf, 0, sizeof(buf));
    u16 net_off = 14;
    u16 trans_off = net_off + sizeof(struct iphdr);
    struct iphdr *iph = (struct iphdr *)(buf + net_off);
    iph->version  = 4;
    iph->ihl      = 5;
    iph->protocol = IPPROTO_ICMP;
    iph->tot_len  = bpf_htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    iph->saddr    = saddr;
    iph->daddr    = daddr;

    struct icmphdr *icmph = (struct icmphdr *)(buf + trans_off);
    icmph->type       = icmp_type;
    icmph->code       = icmp_code;
    icmph->un.echo.id = bpf_htons(echo_id);

    struct sk_buff skb = {};
    skb.head             = buf;
    skb.network_header   = net_off;
    skb.transport_header = trans_off;
    struct pt_regs regs = {};
    return kprobe__icmp_rcv(&regs, &skb);
}

int sim_udp_unconnected_pipeline(u32 client_ip, u32 server_ip, u16 client_port, u16 server_port, u16 payload_len)
{
    u8 buf[256];
    memset(buf, 0, sizeof(buf));
    u16 net_off = 14;
    u16 trans_off = net_off + sizeof(struct iphdr);

    struct iphdr *iph = (struct iphdr *)(buf + net_off);
    iph->version  = 4;
    iph->ihl      = 5;
    iph->protocol = IPPROTO_UDP;
    iph->saddr    = client_ip;
    iph->daddr    = server_ip;

    struct udphdr *udph = (struct udphdr *)(buf + trans_off);
    udph->source = bpf_htons(client_port);
    udph->dest   = bpf_htons(server_port);
    udph->len    = bpf_htons(sizeof(struct udphdr) + payload_len);

    struct sk_buff skb = {};
    skb.head             = buf;
    skb.network_header   = net_off;
    skb.transport_header = trans_off;
    struct pt_regs regs = {};
    kprobe__udp_rcv(&regs, &skb);

    /* Unconnected UDP socket: skc_daddr == 0, msg->msg_name populated before return */
    struct sock sk = {};
    sk.__sk_common.skc_family    = AF_INET;
    sk.__sk_common.skc_num       = server_port;
    sk.__sk_common.skc_rcv_saddr = server_ip;

    u8 sin_buf[16];
    memset(sin_buf, 0, sizeof(sin_buf));
    u16 sin_port_be = bpf_htons(client_port);
    memcpy(sin_buf + 2, &sin_port_be, 2);
    memcpy(sin_buf + 4, &client_ip, 4);

    struct msghdr msg = { .msg_name = sin_buf, .msg_namelen = 16 };
    kprobe__udp_recvmsg(&regs, &sk, &msg, payload_len);
    regs.regs[0] = payload_len;
    kretprobe__udp_recvmsg(&regs);
    return kprobe__udp_sendmsg(&regs, &sk, &msg, payload_len);
}

int sim_ipv6_tcp_pipeline(const u32 saddr6[4], const u32 daddr6[4], u16 sport, u16 dport, u16 payload_len)
{
    u8 buf[256];
    memset(buf, 0, sizeof(buf));
    u16 net_off = 14;
    u16 trans_off = net_off + sizeof(struct ipv6hdr);

    struct ipv6hdr *ip6h = (struct ipv6hdr *)(buf + net_off);
    ip6h->version     = 6;
    ip6h->nexthdr     = IPPROTO_TCP;
    ip6h->hop_limit   = 64;
    ip6h->payload_len = bpf_htons(payload_len > 40 ? (payload_len - 40) : payload_len);
    memcpy(ip6h->saddr.in6_u.u6_addr32, saddr6, 16);
    memcpy(ip6h->daddr.in6_u.u6_addr32, daddr6, 16);

    struct tcphdr *tcph = (struct tcphdr *)(buf + trans_off);
    tcph->source = bpf_htons(sport);
    tcph->dest   = bpf_htons(dport);
    tcph->doff   = 5;
    tcph->psh    = 1;
    tcph->ack    = 1;

    struct sk_buff skb = {};
    skb.head             = buf;
    skb.network_header   = net_off;
    skb.transport_header = trans_off;
    struct pt_regs regs = {};
    kprobe__ipv6_rcv(&regs, &skb);
    return kprobe__tcp_v6_rcv(&regs, &skb);
}

int sim_unix_stream_pipeline(u64 client_sk_addr, u64 server_sk_addr)
{
    struct unix_sock c_real = {};
    struct unix_sock s_real = {};
    c_real.peer = &s_real.sk;
    s_real.peer = &c_real.sk;

    struct socket c_sock = { .sk = &c_real.sk };
    struct socket s_sock = { .sk = &s_real.sk };
    struct pt_regs regs = {};
    (void)client_sk_addr;
    (void)server_sk_addr;

    kprobe__unix_stream_sendmsg(&regs, &c_sock);
    return kprobe__unix_stream_recvmsg(&regs, &s_sock);
}

int sim_kfree_skb_test(u32 saddr, u32 daddr, u16 sport, u16 dport, int drop_reason, int stage_mode)
{
    u8 pkt[512];
    u16 net_off = 0, trans_off = 0, total_len = 0;
    build_ipv4_tcp_buf(
        pkt, saddr, daddr, sport, dport,
        5, 64, 0, 1, 1, 0,
        &net_off, &trans_off, &total_len);

    struct sk_buff skb = {};
    skb.head             = pkt;
    skb.data             = pkt + net_off;
    skb.network_header   = net_off;
    skb.transport_header = trans_off;
    skb.len              = total_len - net_off;

    struct sock rx_sk = {};
    rx_sk.__sk_common.skc_family    = AF_INET;
    rx_sk.__sk_common.skc_num       = dport;
    rx_sk.__sk_common.skc_dport     = bpf_htons(sport);
    rx_sk.__sk_common.skc_daddr     = saddr;
    rx_sk.__sk_common.skc_rcv_saddr = daddr;

    tp_args_skb_kfree_skb_t args = {};
    args.reason = drop_reason;
    if (stage_mode == 1) {
        /* Stage 1: Egress skb_egress_map lookup */
        struct flow_key_t ekey = {};
        ekey.saddr  = daddr;
        ekey.daddr  = saddr;
        ekey.sport  = dport;
        ekey.dport  = sport;
        ekey.proto  = IPPROTO_TCP;
        ekey.family = AF_INET;
        struct flow_state_t estate = {};
        estate.req_id = 0xE67E5501ULL;
        estate.pid    = 5000;
        estate.tid    = 5010;
        egress_flow_map.update(&ekey, &estate);
        u64 skb_ptr = (u64)(uintptr_t)&skb;
        skb_egress_map.update(&skb_ptr, &ekey);
        args.skbaddr = &skb;
        args.rx_sk   = NULL;
    } else if (stage_mode == 2) {
        /* Stage 2: rx_sk lookup */
        args.rx_sk   = &rx_sk;
        args.skbaddr = NULL;
    } else {
        /* Stage 3: skb->head + network_header parsing */
        args.rx_sk   = NULL;
        args.skbaddr = &skb;
    }
    return tracepoint__skb__kfree_skb(&args);
}

int sim_dual_stack_sock_key_test(u32 rem_ip4, u32 loc_ip4, u16 rem_port, u16 loc_port, struct flow_key_t *out_key)
{
    struct sock sk = {};
    sk.__sk_common.skc_family    = AF_INET6; /* Dual-stack ::ffff: socket has AF_INET6 */
    sk.__sk_common.skc_daddr     = rem_ip4;  /* Non-zero IPv4-mapped address */
    sk.__sk_common.skc_rcv_saddr = loc_ip4;
    sk.__sk_common.skc_dport     = bpf_htons(rem_port);
    sk.__sk_common.skc_num       = loc_port;

    if (out_key) {
        memset(out_key, 0, sizeof(*out_key));
        populate_sock_flow_key(&sk, out_key, IPPROTO_TCP, 0);
    }
    return 0;
}

int sim_pure_ipv6_loopback4_sock_key_test(
    const u32 rem6[4], const u32 loc6[4], u16 rem_port, u16 loc_port, struct flow_key_t *out_key)
{
    struct sock sk = {};
    sk.__sk_common.skc_family    = AF_INET6;
    /* Rocky 9.8 tcp_v6_syn_recv_sock (net/ipv6/tcp_ipv6.c:1356) sets LOOPBACK4_IPV6 (htonl(0x7f000006)) */
    sk.__sk_common.skc_daddr     = bpf_htonl(0x7f000006);
    sk.__sk_common.skc_rcv_saddr = bpf_htonl(0x7f000006);
    sk.__sk_common.skc_dport     = bpf_htons(rem_port);
    sk.__sk_common.skc_num       = loc_port;
    memcpy(sk.__sk_common.skc_v6_daddr.in6_u.u6_addr32, rem6, 16);
    memcpy(sk.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, loc6, 16);

    if (out_key) {
        memset(out_key, 0, sizeof(*out_key));
        populate_sock_flow_key(&sk, out_key, IPPROTO_TCP, 0);
    }
    return 0;
}

int sim_publish_handoff_burst(u32 tgid, u64 req_id, u32 waker_tid, u16 sport, u16 dport, u8 cpu_id)
{
    u64 now = bpf_ktime_get_ns();
    publish_handoff_slot(tgid, req_id, now, waker_tid, 0x0100007f, 0x0100007f, sport, dport, cpu_id);
    return 0;
}

int sim_claim_handoff_via_futex_exit(u32 tgid, u32 worker_tid, u8 cpu_id)
{
    sim_set_context(tgid, worker_tid, cpu_id);
    tp_args_syscalls_sys_exit_futex_t args = { .id = 98, .ret = 0 };
    return tracepoint__syscalls__sys_exit_futex(&args);
}

int sim_epoll_pwait_cycle(u32 tgid, u32 tid, int ret, u64 wait_ns)
{
    sim_set_context(tgid, tid, 0);
    tp_args_syscalls_sys_enter_epoll_pwait_t enter_args = { .id = 22 };
    tracepoint__syscalls__sys_enter_epoll_pwait(&enter_args);
    if (wait_ns > 0)
        g_sim_clock_ns += wait_ns;
    tp_args_syscalls_sys_exit_epoll_pwait_t exit_args = { .id = 22, .ret = ret };
    return tracepoint__syscalls__sys_exit_epoll_pwait(&exit_args);
}
