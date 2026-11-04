/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * daemon/daemon_formatter.h — RingBuffer Consumer, ARM64 Barriers & Output Stream
 * ==============================================================================
 * Reference: references/libbpf-bootstrap/examples/c/bootstrap.c#L115-L165
 * Hardening: README.md
 *   - Incident 1: Boundary check & null pointer prevention
 *   - Section 4: ARM64 weakly ordered memory barrier (__atomic_thread_fence)
 *   - Incident 3: Non-blocking telemetry drop detection & visual alert
 * ==============================================================================
 */
#ifndef KRAY_DAEMON_FORMATTER_H
#define KRAY_DAEMON_FORMATTER_H

#include "daemon_types.h"

static uint8_t event_osi_layer(uint8_t layer, uint8_t osi_sublayer)
{
    switch (layer) {
    case 1: return 2; /* L2 NIC Ingress */
    case 2:
        if (osi_sublayer == 3) return 3; /* L3 IP */
        if (osi_sublayer == 4) return 4; /* L4 TCP */
        return 2; /* L2 Net */
    case 3:
        if (osi_sublayer == 8) return 6; /* L6 Sched Handoff */
        if (osi_sublayer == 6) return 5; /* L5 Syscall Mem */
        return 5; /* L5 Socket Recv */
    case 4: return 7; /* L7 Uprobe */
    case 5: return 5; /* L5 Socket Send */
    case 6:
        if (osi_sublayer == 4) return 4; /* L4 TCP Transmit */
        if (osi_sublayer == 3) return 3; /* L3 IP Output */
        return 2; /* L2 NIC Egress */
    default: return 0;
    }
}

static const char *layer_name(uint8_t layer, uint8_t osi_sublayer, uint8_t is_return)
{
    switch (layer) {
    case 1: return "L2:NIC_INGRESS";
    case 2:
        if (osi_sublayer == 3) return "L3:KERNEL_IP";
        if (osi_sublayer == 4) return "L4:KERNEL_TCP";
        return "L2:KERNEL_NET";
    case 3:
        if (osi_sublayer == 8) return "L6:PRE_COMPUTE";
        if (osi_sublayer == 6) return "L5:SYSCALL_MEM";
        return "L5:SOCKET_RECV";
    case 4:
        return is_return ? "L7:USER_EXIT" : "L7:USER_ENTRY";
    case 5:
        return "L5:SOCKET_SEND";
    case 6:
        if (osi_sublayer == 4) return "L4:TCP_TRANSMIT";
        if (osi_sublayer == 3) return "L3:IP_OUTPUT";
        return "L2:NIC_EGRESS";
    default:
        return "UNKNOWN";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct kray_event_t))
        return 0;

    /* ARM64 Weak Memory Ordering Protection:
     * Acquire fence to ensure producer writes from remote ARM64 CPU cores are visible */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);

    const struct kray_event_t *ev = data;

    /* Telemetry sequence counter increment with atomic acquire-release */
    uint64_t seq = __atomic_load_n(&s_telemetry_seq_counter, __ATOMIC_ACQUIRE);
    __atomic_store_n(&s_telemetry_seq_counter, seq + 1, __ATOMIC_RELEASE);

    /* Adaptive Uprobe Rate-Limiting Guard:
     * Track call rate across 1-second window. Guard against CPU spike if > 10,000 calls/sec */
    if (ev->layer_type == 4) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        if (now_ns - s_uprobe_rate_window_ns >= 1000000000ULL) {
            s_uprobe_rate_window_ns = now_ns;
            s_uprobe_rate_calls = 1;
        } else {
            s_uprobe_rate_calls++;
            if (s_uprobe_rate_calls > 10000) {
                time_t now_sec = time(NULL);
                if (now_sec - s_uprobe_rate_alert_ts >= 2) {
                    s_uprobe_rate_alert_ts = now_sec;
                    if (!config.json_output) {
                        fprintf(stderr, "\033[1;33m[!] WARNING: Adaptive Uprobe Rate-Limiting Guard engaged: "
                                        "Call rate exceeded 10,000 calls/sec (%u calls/sec). "
                                        "Throttling uprobe telemetry to prevent latency collapse.\033[0m\n",
                                s_uprobe_rate_calls);
                    }
                }
                return 0; /* Throttle event processing */
            }
        }
    }

    uint8_t osi = event_osi_layer(ev->layer_type, ev->call_depth);
    if (config.filter_layer != 0 && osi != config.filter_layer)
        return 0;

    /* Surgical Tail-Latency Spike Filter (-m / --min-latency-us):
     * Suppress fast normal telemetry events unless they exceed the latency threshold
     * or carry critical anomaly flags (SKB Drop 0x08 / TCP Retransmit or RST 0x04) */
    if (config.min_latency_ns > 0 && ev->duration_ns < config.min_latency_ns && (ev->flags & (0x08 | 0x04)) == 0)
        return 0;

    if (config.max_events > 0 && s_emitted_event_count >= config.max_events) {
        exiting = true;
        return 0;
    }

    if (osi >= 2 && osi <= 7) {
        s_layer_stats[osi].count++;
        s_layer_stats[osi].sum_ns += ev->duration_ns;
        if (ev->duration_ns > s_layer_stats[osi].max_ns) {
            s_layer_stats[osi].max_ns = ev->duration_ns;
            s_layer_stats[osi].max_req_id = ev->req_id;
        }
    }
    if (ev->flags & 0x08)
        s_skb_drop_events++;
    if ((ev->flags & 0x04) && ev->layer_type > 2)
        s_tcp_retrans_events++;

    s_emitted_event_count++;
    if (config.max_events > 0 && s_emitted_event_count >= config.max_events)
        exiting = true;

    char s_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    char d_ip[INET_ADDRSTRLEN] = "0.0.0.0";
    struct in_addr sa = { .s_addr = ev->src_ip };
    struct in_addr da = { .s_addr = ev->dst_ip };
    inet_ntop(AF_INET, &sa, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &da, d_ip, sizeof(d_ip));

    uint32_t traffic_bytes = 0;
    if (ev->layer_type == 1 || ev->layer_type == 6) {
        traffic_bytes = (uint32_t)(ev->ip & 0xffff);
    } else if ((ev->layer_type == 3 && ev->call_depth == 5) || ev->layer_type == 5) {
        traffic_bytes = (uint32_t)(ev->ip & 0xffffffff);
    }

    uint32_t ev_drop_count = __atomic_load_n(&ev->drop_count, __ATOMIC_ACQUIRE);
    uint32_t last_drop_cnt = __atomic_load_n(&s_telemetry_drop_counter, __ATOMIC_ACQUIRE);
    if (ev_drop_count > 0 && ev_drop_count != last_drop_cnt) {
        uint32_t drops_delta = ev_drop_count - last_drop_cnt;
        __atomic_store_n(&s_telemetry_drop_counter, ev_drop_count, __ATOMIC_RELEASE);
        time_t now = time(NULL);
        if (now - s_last_drop_alert_ts >= 2) {
            s_last_drop_alert_ts = now;
            if (!config.json_output) {
                fprintf(stderr, "\033[1;31m[!] WARNING: Ring Buffer Overrun Detected! +%u events dropped (Cumulative: %u)\033[0m\n",
                        drops_delta, ev_drop_count);
            }
        }
    }

    if (config.json_output) {
        printf("{\"req_id\":\"0x%llx\",\"ts\":%llu,\"duration_ns\":%llu,\"layer\":%u,\"osi\":%u,\"is_ret\":%u,"
               "\"pid\":%u,\"tid\":%u,\"parent_tid\":%u,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"src_port\":%u,\"dst_port\":%u,"
               "\"payload_bytes\":%u,\"proto\":\"%s\",\"ip\":\"0x%llx\",\"flags\":%u,\"drops\":%u}\n",
               (unsigned long long)ev->req_id,
               (unsigned long long)ev->timestamp,
               (unsigned long long)ev->duration_ns,
               ev->layer_type,
               ev->call_depth,
               ev->is_return,
               ev->pid,
               ev->tid,
               ev->parent_tid,
               s_ip, d_ip,
               ev->src_port, ev->dst_port,
               traffic_bytes,
               (ev->dst_port == 8080 || ev->src_port == 8080) ? "HTTP" : "TCP",
               (unsigned long long)ev->ip,
               ev->flags,
               ev_drop_count);
        fflush(stdout);
        return 0;
    }

    time_t raw_time = time(NULL);
    struct tm *tm_info = localtime(&raw_time);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    const char *color_code = "\033[0m";
    switch (ev->layer_type) {
    case 1: color_code = "\033[36m"; break; /* Cyan (L2) */
    case 2: color_code = "\033[34m"; break; /* Blue (L3/L4) */
    case 3: color_code = "\033[33m"; break; /* Yellow (L5/L6) */
    case 4: color_code = "\033[32m"; break; /* Green (L7 Code) */
    case 5: color_code = "\033[35m"; break; /* Magenta (L5 Exit) */
    case 6: color_code = "\033[31m"; break; /* Red (L2-L4 Egress) */
    }

    const char *lname = layer_name(ev->layer_type, ev->call_depth, ev->is_return);

    printf("%s[%s]\033[0m %s%-16s\033[0m req:0x%016llx tid:%-5u | dur:%8.2fus | %s:%-5u -> %s:%-5u",
           color_code, time_str,
           color_code, lname,
           (unsigned long long)ev->req_id,
           ev->tid,
           (double)ev->duration_ns / 1000.0,
           s_ip, ev->src_port,
           d_ip, ev->dst_port);

    if (ev->flags & 0x10) printf(" [SYN]");
    if (ev->flags & 0x20) printf(" [ACK]");
    if (ev->flags & 0x40) printf(" [PSH]");
    if (ev->flags & 0x80) printf(" [FIN]");
    if (ev->flags & 0x01) printf(" [HANDOFF waker:%u]", ev->parent_tid);
    if (ev->flags & 0x08) printf(" [DROP reason:%llu]", (unsigned long long)ev->ip);
    if (ev->flags & 0x04) {
        if (ev->layer_type == 1 || ev->layer_type == 2)
            printf(" [RST]");
        else
            printf(" [RETRANS count:%llu]", (unsigned long long)ev->ip);
    }

    if (traffic_bytes > 0) {
        if (ev->dst_port == 8080 || ev->dst_port == 80) {
            printf(" [HTTP Req: %u B]", traffic_bytes);
        } else if (ev->src_port == 8080 || ev->src_port == 80) {
            printf(" [HTTP Resp: %u B]", traffic_bytes);
        } else {
            printf(" [%u B]", traffic_bytes);
        }
    }

    if (ev->layer_type == 4) {
        printf(" [depth:%u fn:0x%llx]", ev->call_depth, (unsigned long long)ev->ip);
    }
    printf("\n");
    fflush(stdout);

    return 0;
}

static const char *osi_layer_title(uint8_t osi)
{
    switch (osi) {
    case 2: return "L2 (NIC XDP / Driver / Qdisc)";
    case 3: return "L3 (Kernel IP Routing / Netfilter)";
    case 4: return "L4 (Kernel TCP/UDP State Machine)";
    case 5: return "L5 (Socket sk_rcvbuf Dwell & Copy)";
    case 6: return "L6 (Scheduler runqlat & Handoff)";
    case 7: return "L7 (Userspace Uprobe / Native Code)";
    default: return "Unknown Layer";
    }
}

static void print_production_diagnostic_summary(void)
{
    if (config.json_output || s_emitted_event_count == 0)
        return;

    uint8_t bottleneck_osi = 0;
    uint64_t bottleneck_max_ns = 0;
    uint64_t bottleneck_req_id = 0;

    fprintf(stderr, "================================================================================\n");
    fprintf(stderr, " [PRODUCTION DIAGNOSTIC SUMMARY & BOTTLENECK VERDICT]\n");
    fprintf(stderr, " Total Captured Events: %llu | SKB Drops: %llu | TCP Retransmits: %llu | RingBuf Drops: %u\n",
            (unsigned long long)s_emitted_event_count,
            (unsigned long long)s_skb_drop_events,
            (unsigned long long)s_tcp_retrans_events,
            s_telemetry_drop_counter);
    fprintf(stderr, "--------------------------------------------------------------------------------\n");
    fprintf(stderr, " %-36s | %8s | %12s | %12s\n", "OSI Layer Stage", "Events", "Avg (us)", "Max (us)");
    fprintf(stderr, "--------------------------------------------------------------------------------\n");

    for (uint8_t osi = 2; osi <= 7; osi++) {
        if (s_layer_stats[osi].count == 0)
            continue;
        double avg_us = ((double)s_layer_stats[osi].sum_ns / (double)s_layer_stats[osi].count) / 1000.0;
        double max_us = (double)s_layer_stats[osi].max_ns / 1000.0;
        fprintf(stderr, " %-36s | %8llu | %12.2f | %12.2f\n",
                osi_layer_title(osi),
                (unsigned long long)s_layer_stats[osi].count,
                avg_us,
                max_us);
        if (s_layer_stats[osi].max_ns > bottleneck_max_ns) {
            bottleneck_max_ns = s_layer_stats[osi].max_ns;
            bottleneck_osi = osi;
            bottleneck_req_id = s_layer_stats[osi].max_req_id;
        }
    }

    if (bottleneck_osi >= 2 && bottleneck_osi <= 7) {
        fprintf(stderr, "--------------------------------------------------------------------------------\n");
        fprintf(stderr, " [VERDICT] Primary Bottleneck: %s\n", osi_layer_title(bottleneck_osi));
        fprintf(stderr, "           Peak Spike: %.2f us (req_id: 0x%016llx)\n",
                (double)bottleneck_max_ns / 1000.0,
                (unsigned long long)bottleneck_req_id);
    }
    fprintf(stderr, "================================================================================\n");
}

#endif /* KRAY_DAEMON_FORMATTER_H */
