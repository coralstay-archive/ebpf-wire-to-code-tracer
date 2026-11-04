/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * daemon/daemon_sweeper.h — Active Orphan Flow TTL Sweeper & XDP Pre-flight Flush
 * ==============================================================================
 * Reference: README.md
 * Prevents map exhaustion under asymmetric connection teardowns (missing FIN/RST)
 * and recovers cleanly when previous instances were terminated by SIGKILL/OOM.
 * ==============================================================================
 */
#ifndef KRAY_DAEMON_SWEEPER_H
#define KRAY_DAEMON_SWEEPER_H

#include "daemon_types.h"

static void flush_orphan_xdp(int ifindex)
{
    if (ifindex <= 0)
        return;
    /* Idempotently detach any residual Generic or Native XDP links left by SIGKILL/OOM */
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_xdp_detach(ifindex, 0, NULL);
}

static void sweep_stale_flows(int flow_map_fd, uint64_t max_age_ns)
{
    if (flow_map_fd < 0)
        return;

    struct flow_key_t key, next_key;
    bool has_key = false;
    uint32_t evicted = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(flow_map_fd, has_key ? &key : NULL, &next_key) == 0) {
        has_key = true;
        key = next_key;

        struct flow_state_t state;
        if (bpf_map_lookup_elem(flow_map_fd, &key, &state) == 0) {
            uint64_t ref_ts = state.tcp_rcv_ts ? state.tcp_rcv_ts : state.xdp_ts;
            if (ref_ts > 0 && (now_ns > ref_ts) && (now_ns - ref_ts > max_age_ns)) {
                bpf_map_delete_elem(flow_map_fd, &key);
                evicted++;
            }
        }
    }

    if (evicted > 0 && config.verbose) {
        fprintf(stderr, "[+] [TTL Sweeper] Cleaned up %u stranded/orphaned flow context entries\n", evicted);
    }
}

#endif /* KRAY_DAEMON_SWEEPER_H */
