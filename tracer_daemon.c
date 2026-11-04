/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * tracer_daemon.c — Production C eBPF Wire-to-Code Telemetry Daemon Entrypoint
 * ==============================================================================
 * Modular Architecture (daemon/*.h):
 *   - [daemon/daemon_types.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_types.h): Configuration state, atomic counters & signals
 *   - [daemon/daemon_preflight.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h): Privilege, BTF, Cgroups v2 & stripped ELF checks
 *   - [daemon/daemon_sweeper.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_sweeper.h): 30s TTL orphan flow sweeper & XDP pre-flight guardian
 *   - [daemon/daemon_formatter.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h): ARM64 barrier ringbuffer consumer & JSON/ANSI output
 *
 * Authoritative CLI Standards:
 *   - Michael Kerrisk, "The Linux Programming Interface" (TLPI), Appendix B
 *   - POSIX IEEE Std 1003.1-2017 Utility Conventions & BSD <sysexits.h>
 * ==============================================================================
 */
#include "daemon/daemon_types.h"
#include "daemon/daemon_preflight.h"
#include "daemon/daemon_sweeper.h"
#include "daemon/daemon_formatter.h"

static void print_usage(const char *prog)
{
    fprintf(stdout, "Usage: %s [options]\n", prog);
    fprintf(stdout, "eBPF-WireToCode-Tracer Production C Daemon (Rocky Linux 9.8 aarch64)\n\n");
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  -p, --port <port>             Target server TCP/UDP port (0..65535, default: 8080, 0 = all)\n");
    fprintf(stdout, "  -t, --pid <pid>               Target process PID/TGID (default: 0 = all)\n");
    fprintf(stdout, "  -L, --layer <2..7>            Filter by specific OSI layer (2:XDP, 3:IP, 4:TCP, 5:Socket, 6:Sched, 7:Uprobe)\n");
    fprintf(stdout, "  -i, --iface <dev>             Attach XDP to network interface (e.g. lo, eth0)\n");
    fprintf(stdout, "  -b, --binary <path>           Target binary or shared library (.so) path for Uprobe tracking\n");
    fprintf(stdout, "  -s, --symbol <name>           Auto-resolve ELF symbol (.symtab/.dynsym) for Uprobe (e.g. SSL_read)\n");
    fprintf(stdout, "  -o, --offset <hex>            Explicit symbol file offset for Uprobe (e.g. 0x1180)\n");
    fprintf(stdout, "  -m, --min-latency-us <us>     Surgical tail-latency threshold filter in microseconds\n");
    fprintf(stdout, "  -d, --duration <sec>          Auto-detach and exit after <sec> seconds\n");
    fprintf(stdout, "  -c, --max-events <count>      Auto-detach and exit after capturing <count> events\n");
    fprintf(stdout, "  -j, --json                    Output telemetry in JSON Lines format to stdout\n");
    fprintf(stdout, "  -v, --verbose                 Enable libbpf debug prints\n");
    fprintf(stdout, "  -V, --version                 Print daemon version and exit\n");
    fprintf(stdout, "  -h, --help                    Show this help message\n");
}

int main(int argc, char **argv)
{
    /* Stream separation: unbuffered stderr for real-time diagnostic emission */
    setvbuf(stderr, NULL, _IONBF, 0);

    static const struct option long_options[] = {
        {"port",           required_argument, NULL, 'p'},
        {"pid",            required_argument, NULL, 't'},
        {"layer",          required_argument, NULL, 'L'},
        {"iface",          required_argument, NULL, 'i'},
        {"binary",         required_argument, NULL, 'b'},
        {"symbol",         required_argument, NULL, 's'},
        {"offset",         required_argument, NULL, 'o'},
        {"min-latency-us", required_argument, NULL, 'm'},
        {"duration",       required_argument, NULL, 'd'},
        {"max-events",     required_argument, NULL, 'c'},
        {"json",           no_argument,       NULL, 'j'},
        {"verbose",        no_argument,       NULL, 'v'},
        {"version",        no_argument,       NULL, 'V'},
        {"help",           no_argument,       NULL, 'h'},
        {NULL,             0,                 NULL,  0 }
    };

    /*
     * Leading colon (":") in optstring enables Kerrisk TLPI error discrimination:
     * - opt == ':' : Option requires an argument but none was supplied
     * - opt == '?' : Unrecognized option
     */
    int opt;
    while ((opt = getopt_long(argc, argv, ":p:t:L:i:b:s:o:m:d:c:jvVh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p': {
                char *endptr = NULL;
                long val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val < 0 || val > 65535) {
                    fprintf(stderr, "%s: invalid port value '%s' (must be 0..65535)\n", argv[0], optarg);
                    return EX_USAGE;
                }
                config.target_port = (uint16_t)val;
                break;
            }
            case 't': {
                char *endptr = NULL;
                long val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val < 0) {
                    fprintf(stderr, "%s: invalid PID value '%s'\n", argv[0], optarg);
                    return EX_USAGE;
                }
                config.target_pid = (uint32_t)val;
                break;
            }
            case 'L': {
                if (strcasecmp(optarg, "l2") == 0 || strcasecmp(optarg, "xdp") == 0 || strcmp(optarg, "2") == 0)
                    config.filter_layer = 2;
                else if (strcasecmp(optarg, "l3") == 0 || strcasecmp(optarg, "ip") == 0 || strcmp(optarg, "3") == 0)
                    config.filter_layer = 3;
                else if (strcasecmp(optarg, "l4") == 0 || strcasecmp(optarg, "tcp") == 0 || strcmp(optarg, "4") == 0)
                    config.filter_layer = 4;
                else if (strcasecmp(optarg, "l5") == 0 || strcasecmp(optarg, "socket") == 0 || strcasecmp(optarg, "syscall") == 0 || strcmp(optarg, "5") == 0)
                    config.filter_layer = 5;
                else if (strcasecmp(optarg, "l6") == 0 || strcasecmp(optarg, "sched") == 0 || strcasecmp(optarg, "handoff") == 0 || strcmp(optarg, "6") == 0)
                    config.filter_layer = 6;
                else if (strcasecmp(optarg, "l7") == 0 || strcasecmp(optarg, "uprobe") == 0 || strcasecmp(optarg, "app") == 0 || strcmp(optarg, "7") == 0)
                    config.filter_layer = 7;
                else {
                    char *endptr = NULL;
                    long val = strtol(optarg, &endptr, 10);
                    if (*endptr != '\0' || val < 2 || val > 7) {
                        fprintf(stderr, "%s: invalid layer '%s' (valid range: 2..7 or names: l2..l7)\n", argv[0], optarg);
                        return EX_USAGE;
                    }
                    config.filter_layer = (uint8_t)val;
                }
                break;
            }
            case 'i':
                config.iface = optarg;
                break;
            case 'b':
                config.binary_path = optarg;
                break;
            case 's':
                config.symbol_name = optarg;
                break;
            case 'o':
                config.uprobe_offset = strtoull(optarg, NULL, 16);
                break;
            case 'm': {
                char *endptr = NULL;
                long val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val < 0) {
                    fprintf(stderr, "%s: invalid min-latency-us value '%s'\n", argv[0], optarg);
                    return EX_USAGE;
                }
                config.min_latency_ns = (uint64_t)val * 1000ULL;
                break;
            }
            case 'd': {
                char *endptr = NULL;
                long val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val <= 0 || val > 86400) {
                    fprintf(stderr, "%s: invalid duration value '%s' (must be 1..86400 seconds)\n", argv[0], optarg);
                    return EX_USAGE;
                }
                config.duration_sec = (uint32_t)val;
                break;
            }
            case 'c': {
                char *endptr = NULL;
                long val = strtol(optarg, &endptr, 10);
                if (*endptr != '\0' || val <= 0) {
                    fprintf(stderr, "%s: invalid max-events value '%s' (must be >= 1)\n", argv[0], optarg);
                    return EX_USAGE;
                }
                config.max_events = (uint64_t)val;
                break;
            }
            case 'j':
                config.json_output = true;
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'V':
                fprintf(stdout, "tracer_daemon v2.0.0 (Rocky Linux 9.8 aarch64)\n");
                return EX_OK;
            case 'h':
                print_usage(argv[0]);
                return EX_OK;
            case ':':
                fprintf(stderr, "%s: option '-%c' requires an argument\n", argv[0], optopt);
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return EX_USAGE;
            case '?':
                fprintf(stderr, "%s: unrecognized option '-%c'\n", argv[0], optopt);
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return EX_USAGE;
            default:
                fprintf(stderr, "%s: unexpected argument vector state\n", argv[0]);
                return EX_USAGE;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP, sig_handler);

    if (!config.verbose)
        libbpf_set_print(NULL);

    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    /* Pre-flight system and permission checks BEFORE banner output */
    int prereq_err = check_system_prerequisites(config.json_output);
    if (prereq_err != 0) {
        if (prereq_err == -EPERM)
            return EX_NOPERM;
        if (prereq_err == -ENOENT)
            return EX_UNAVAILABLE;
        return EX_OSERR;
    }

    if (!config.json_output) {
        fprintf(stderr, "================================================================================\n");
        fprintf(stderr, " [tracer_daemon] Starting 7-Layer Wire-to-Code eBPF Telemetry Collector\n");
        if (config.filter_layer > 0) {
            fprintf(stderr, " Target Port: %u | Target PID: %u | Layer Filter: L%u Only | Interface: %s\n",
                    config.target_port, config.target_pid, config.filter_layer, config.iface ? config.iface : "auto/lo");
        } else {
            fprintf(stderr, " Target Port: %u | Target PID: %u | Layer Filter: All 7 Layers | Interface: %s\n",
                    config.target_port, config.target_pid, config.iface ? config.iface : "auto/lo");
        }
        fprintf(stderr, "================================================================================\n");
    }

    /* Binary stripping, dynamic symbol resolution, and accessibility inspection */
    if (config.binary_path) {
        if (access(config.binary_path, R_OK) != 0) {
            fprintf(stderr, "[-] Target binary '%s' does not exist or is not readable: %s\n",
                    config.binary_path, strerror(errno));
        } else if (config.symbol_name && config.uprobe_offset == 0) {
            char resolved_sym[256] = {0};
            const char *sym_table = ".symtab";
            if (resolve_elf_symbol_offset(
                    config.binary_path, config.symbol_name, &config.uprobe_offset,
                    resolved_sym, sizeof(resolved_sym), &sym_table)) {
                if (!config.json_output) {
                    fprintf(stderr, "[+] Auto-resolved ELF symbol '%s' -> '%s' (%s) at file offset 0x%llx\n",
                            config.symbol_name, resolved_sym, sym_table, (unsigned long long)config.uprobe_offset);
                }
            } else {
                fprintf(stderr, "[-] Error: ELF symbol '%s' not found in .symtab or .dynsym of '%s'\n",
                        config.symbol_name, config.binary_path);
                return EX_DATAERR;
            }
        } else if (config.uprobe_offset == 0) {
            if (check_elf_stripped(config.binary_path)) {
                fprintf(stderr, "================================================================================\n");
                fprintf(stderr, " [!] WARNING: Binary '%s' is stripped (no .symtab found).\n", config.binary_path);
                fprintf(stderr, "     Dynamic function symbol resolution is impossible on stripped binaries.\n");
                fprintf(stderr, " [!] Remediation:\n");
                fprintf(stderr, "     Pass explicit instruction file offset via -o / --offset (e.g. -o 0x1180),\n");
                fprintf(stderr, "     pass -s / --symbol <name> to query .dynsym exported symbols,\n");
                fprintf(stderr, "     or recompile target binary with debug symbols (-g).\n");
                fprintf(stderr, "================================================================================\n");
            }
        }
    }

    struct tracer_kernel_bpf *skel = tracer_kernel_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton: %s\n", strerror(errno));
        return 1;
    }

    /* Dynamic BPF map sizing based on cgroup memory headroom guard */
    if (s_cgroup_low_headroom) {
        bpf_map__set_max_entries(skel->maps.__bpf_map_ingress_flow_map, 2048);
        bpf_map__set_max_entries(skel->maps.__bpf_map_active_ctx_map, 2048);
        bpf_map__set_max_entries(skel->maps.__bpf_map_egress_flow_map, 2048);
        bpf_map__set_max_entries(skel->maps.__bpf_map_skb_egress_map, 2048);
        if (!config.json_output)
            fprintf(stderr, "[*] Adaptive dynamic BPF map sizing: scaled LRU maps to 2048 entries to avoid container OOM\n");
    }

    int err = tracer_kernel_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] BPF Verifier failed to load skeleton: %d (%s)\n", err, strerror(-err));
        tracer_kernel_bpf__destroy(skel);
        return 1;
    }

    /* Configure runtime settings in BPF map */
    int cfg_fd = bpf_map__fd(skel->maps.__bpf_map_runtime_config_map);
    if (cfg_fd >= 0) {
        uint32_t zero = 0;
        struct kray_runtime_cfg_t cfg = {
            .target_pid = config.target_pid,
            .target_port = config.target_port,
            .capture_enabled = 1,
            .filter_flags = 0,
            .config_epoch = 1,
        };
        bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
    }

    /* Attach tracepoints and kprobes (with Selective Layer Overhead Isolation) */
    struct bpf_program *prog;
    int attached = 0;
    int skipped_sched = 0;
    bpf_object__for_each_program(prog, skel->obj) {
        const char *sec = bpf_program__section_name(prog);
        if (strncmp(sec, "xdp", 3) == 0 || strncmp(sec, "uprobe", 6) == 0 || strncmp(sec, "uretprobe", 9) == 0)
            continue;
        if (config.filter_layer > 0 && config.filter_layer != 6 && sec) {
            if (strstr(sec, "sched/") != NULL || strstr(sec, "futex") != NULL) {
                skipped_sched++;
                continue;
            }
        }
        struct bpf_link *link = bpf_program__attach(prog);
        if (libbpf_get_error(link) == 0)
            attached++;
    }
    if (skipped_sched > 0 && !config.json_output) {
        fprintf(stderr, "[*] Selective Layer Isolation (L%u): bypassed %d high-frequency L6 scheduler/futex hooks\n",
                config.filter_layer, skipped_sched);
    }

    /* Optional XDP attachment with Pre-flight Orphan Flush & Driver -> Generic SKB Fallback */
    struct bpf_link *xdp_link = NULL;
    int xdp_generic_ifindex = 0;
    if (config.iface) {
        int ifindex = if_nametoindex(config.iface);
        if (ifindex == 0) {
            fprintf(stderr, "[!] WARNING: Interface '%s' not found; continuing without XDP link attachment.\n", config.iface);
        } else if (ifindex > 0) {
            flush_orphan_xdp(ifindex);

            xdp_link = bpf_program__attach_xdp(skel->progs.xdp_ingress_filter, ifindex);
            long xdp_err = libbpf_get_error(xdp_link);
            if (xdp_err == 0) {
                if (!config.json_output)
                    fprintf(stderr, "[+] Attached XDP ingress filter (Native Driver Mode) to interface '%s' (ifindex %d)\n", config.iface, ifindex);
            } else if (xdp_err == -EOPNOTSUPP || xdp_err == -ENOTSUPP || xdp_err == -EINVAL || xdp_err != 0) {
                xdp_link = NULL;
                if (!config.json_output) {
                    fprintf(stderr, "================================================================================\n");
                    fprintf(stderr, " [!] ADVISORY: Native XDP driver attachment failed on interface '%s' (err: %ld: %s).\n",
                            config.iface, xdp_err, strerror(-xdp_err));
                    fprintf(stderr, "     Notice: Common on VirtIO-Net, AWS ENA, and cloud NICs on ARM64.\n");
                    fprintf(stderr, "     Gracefully falling back to Generic SKB mode (XDP_FLAGS_SKB_MODE)...\n");
                    fprintf(stderr, "================================================================================\n");
                }
                int prog_fd = bpf_program__fd(skel->progs.xdp_ingress_filter);
                int ret = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
                if (ret == 0) {
                    xdp_generic_ifindex = ifindex;
                    if (!config.json_output)
                        fprintf(stderr, "[+] Attached XDP ingress filter (Generic SKB Mode) to interface '%s' (ifindex %d)\n", config.iface, ifindex);
                } else {
                    fprintf(stderr, "[-] Failed to attach XDP in generic SKB mode: %s (ret: %d)\n", strerror(-ret), ret);
                }
            }
        }
    }

    /* Optional Uprobe attachment (in libbpf: pid == -1 attaches to all processes, pid == 0 means self) */
    struct bpf_link *uprobe_entry_link = NULL;
    struct bpf_link *uprobe_ret_link = NULL;
    if (config.binary_path && config.uprobe_offset > 0) {
        pid_t uprobe_pid = (config.target_pid > 0) ? (pid_t)config.target_pid : -1;
        uprobe_entry_link = bpf_program__attach_uprobe(
            skel->progs.trace_uprobe_entry, false, uprobe_pid, config.binary_path, config.uprobe_offset);
        uprobe_ret_link = bpf_program__attach_uprobe(
            skel->progs.trace_uprobe_return, true, uprobe_pid, config.binary_path, config.uprobe_offset);
        if (libbpf_get_error(uprobe_entry_link) == 0 && !config.json_output) {
            fprintf(stderr, "[+] Attached Uprobes to %s at offset 0x%llx\n", config.binary_path, (unsigned long long)config.uprobe_offset);
        }
    }

    /* Ring buffer listener */
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.__bpf_rb_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] Failed to create BPF ringbuffer reader: %s\n", strerror(errno));
        tracer_kernel_bpf__destroy(skel);
        return 1;
    }

    if (!config.json_output) {
        fprintf(stderr, "[+] Attached %d kernel tracepoints/kprobes. Listening for requests...\n", attached);
        fprintf(stderr, "--------------------------------------------------------------------------------\n");
    }

    int loop_cnt = 0;
    int flow_map_fd = bpf_map__fd(skel->maps.__bpf_map_ingress_flow_map);
    struct timespec ts_start = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    while (!exiting) {
        int polled = ring_buffer__poll(rb, 100);
        if (polled < 0 && polled != -EINTR) {
            fprintf(stderr, "[-] Error polling ringbuffer: %d\n", polled);
            break;
        }

        if (config.duration_sec > 0) {
            struct timespec ts_now = {0, 0};
            clock_gettime(CLOCK_MONOTONIC, &ts_now);
            if ((uint32_t)(ts_now.tv_sec - ts_start.tv_sec) >= config.duration_sec) {
                break;
            }
        }

        /* Periodic stale flow context sweep every ~5 seconds (50 iterations * 100ms) */
        if (++loop_cnt >= 50) {
            loop_cnt = 0;
            sweep_stale_flows(flow_map_fd, 30000000000ULL); /* 30 seconds TTL */
        }
    }

    print_production_diagnostic_summary();

    if (!config.json_output)
        fprintf(stderr, "\n[+] Detaching hooks and stopping tracer_daemon...\n");

    if (xdp_link) {
        bpf_link__destroy(xdp_link);
    } else if (xdp_generic_ifindex > 0) {
        bpf_xdp_detach(xdp_generic_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    }
    if (uprobe_entry_link)
        bpf_link__destroy(uprobe_entry_link);
    if (uprobe_ret_link)
        bpf_link__destroy(uprobe_ret_link);

    ring_buffer__free(rb);
    tracer_kernel_bpf__destroy(skel);

    if (!config.json_output)
        fprintf(stderr, "[+] All BPF programs safely detached and destroyed. Done.\n");

    return 0;
}
