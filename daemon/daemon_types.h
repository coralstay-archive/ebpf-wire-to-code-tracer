/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * daemon/daemon_types.h — Daemon Configuration, Atomic State & Signal Handling
 * ==============================================================================
 */
#ifndef KRAY_DAEMON_TYPES_H
#define KRAY_DAEMON_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <getopt.h>
#include <sysexits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#ifdef __linux__
#include <libelf.h>
#include <gelf.h>
#include <linux/if_link.h>
#endif

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef FLAG_TCP_RST
#define FLAG_TCP_RST 0x04
#endif

#define KRAY_USER_DAEMON
#include "../progs/kray_common.h"
#include "../tracer_kernel.skel.h"

static volatile bool exiting = false;
static bool s_cgroup_low_headroom = false;
static uint64_t s_telemetry_seq_counter = 0;
static uint64_t s_emitted_event_count = 0;
static uint32_t s_telemetry_drop_counter = 0;
static time_t s_last_drop_alert_ts = 0;
static uint64_t s_uprobe_rate_window_ns = 0;
static uint32_t s_uprobe_rate_calls = 0;
static time_t s_uprobe_rate_alert_ts = 0;
static uint64_t s_skb_drop_events = 0;
static uint64_t s_tcp_retrans_events = 0;

struct layer_stats_t {
    uint64_t count;
    uint64_t sum_ns;
    uint64_t max_ns;
    uint64_t max_req_id;
};

static struct layer_stats_t s_layer_stats[8];

struct daemon_cfg {
    uint32_t target_pid;
    uint16_t target_port;
    const char *iface;
    const char *binary_path;
    const char *symbol_name;
    uint64_t uprobe_offset;
    uint64_t min_latency_ns;
    uint32_t duration_sec;
    uint64_t max_events;
    uint8_t filter_layer;
    bool json_output;
    bool verbose;
};

static struct daemon_cfg config = {
    .target_pid = 0,
    .target_port = 8080,
    .iface = NULL,
    .binary_path = NULL,
    .symbol_name = NULL,
    .uprobe_offset = 0,
    .min_latency_ns = 0,
    .duration_sec = 0,
    .max_events = 0,
    .filter_layer = 0,
    .json_output = false,
    .verbose = false,
};

static void sig_handler(int sig)
{
    (void)sig;
    exiting = true;
}

#endif /* KRAY_DAEMON_TYPES_H */
