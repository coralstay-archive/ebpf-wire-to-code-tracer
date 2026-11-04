"""
kray/verify_scenarios.py — The 5 Real-World Architectural Verification Scenarios.
Demonstrates why kernel eBPF wire-to-code tracing exists despite Java/Go/Node.js I/O APIs.
"""

import sys
from kray import RED, GREEN, BOLD, NC, EX_OK, EX_CLI_INVALID_CMD
from kray.help_docs import print_banner, help_verify


def run_verify(args: list[str], trace_callback) -> int:
    scenario = "list"
    run_live = False

    valid_scenarios = {
        "list", "all",
        "1", "ingress", "dwell",
        "2", "handoff", "sched",
        "3", "offcpu", "alu",
        "4", "mm", "copy",
        "5", "drops", "egress",
    }

    for arg in args:
        if arg in ("-h", "--help", "help"):
            return help_verify()
        if arg in ("-l", "--live"):
            run_live = True
        elif arg in valid_scenarios:
            scenario = arg
        else:
            sys.stderr.write(f"{RED}Error: Unknown verification scenario '{arg}'{NC}\n")
            sys.stderr.write("Try 'krayctl verify --help' or 'krayctl verify list'.\n")
            return EX_CLI_INVALID_CMD

    print_banner()
    if scenario in ("list", "all"):
        print(f"{BOLD}WHY THIS PROJECT EXISTS (BEYOND JAVA NIO/NETTY, GO NETPOLL, RUST TOKIO):{NC}")
        print("  High-level language I/O APIs only start their clock AFTER epoll_wait() wakes up")
        print("  and read()/recvmsg() is invoked, and stop their clock as soon as write()/sendmsg()")
        print("  copies bytes into the kernel socket buffer. They are structurally blind to:")
        print("    [Blind Spot 1] Ingress Socket Queue Dwell (sk_rcvbuf stall during GC / loop saturation)")
        print("    [Blind Spot 2] Inter-Thread Futex Lock Contention & OS CPU Runqueue Delay (runqlat)")
        print("    [Blind Spot 3] Off-CPU Preemption, Page Faults & Disk I/O inside User Functions")
        print("    [Blind Spot 4] Egress Socket Queueing, Qdisc Delay, kfree_skb Drops & TCP Retransmits")
        print("")
        print(f"{BOLD}5 REAL-WORLD ARCHITECTURAL VERIFICATION SCENARIOS:{NC}")
        print(f"  {GREEN}[Scenario 1] Ingress Socket Buffer Dwell Time (sk_rcvbuf vs App GC/EventLoop){NC}")
        print("    - Inspects: kprobe:tcp_v4_rcv -> kprobe:tcp_recvmsg (dwell_ns = t_recvmsg - t_tcp_rcv)")
        print("    - Command : krayctl verify 1 [--live]   (krayctl trace -L 5 -d 3)")
        print("")
        print(f"  {GREEN}[Scenario 2] Reactor/Epoll to Worker Thread Pool Handoff Tax (Futex & Runqueue){NC}")
        print("    - Inspects: sys_enter_futex -> 8-Slot Handoff Ring -> sched_wakeup -> sched_switch")
        print("    - Command : krayctl verify 2 [--live]   (krayctl trace -L 6 -d 3)")
        print("")
        print(f"  {GREEN}[Scenario 3] Pure On-CPU ALU Execution vs Off-CPU Scheduler Preemption{NC}")
        print("    - Inspects: ELF .symtab/.dynsym auto-resolution (-s) + 16-Slot Shadow Stack & Off-CPU subtraction")
        print("    - Command : krayctl verify 3 [--live]   (krayctl trace -L 7 -b ./mock_server -s execute_storage_query -d 3)")
        print("")
        print(f"  {GREEN}[Scenario 4] Kernel-to-User Buffer Copy, Page Faults & Block I/O Correlation{NC}")
        print("    - Inspects: skb_copy_datagram_iter + handle_mm_fault + tail-latency filter (-m)")
        print("    - Command : krayctl verify 4 [--live]   (krayctl trace -L 5 -m 1 -d 3)")
        print("")
        print(f"  {GREEN}[Scenario 5] Egress Blindness, Per-Request kfree_skb Drop Reason & Retransmits{NC}")
        print("    - Inspects: tcp_sendmsg -> __tcp_transmit_skb -> kfree_skb (reason) + event cap (-c)")
        print("    - Command : krayctl verify 5 [--live]   (krayctl trace -L 4 -c 10 -d 3)")
        return EX_OK

    if scenario in ("1", "ingress", "dwell"):
        print(f"{BOLD}[VERIFICATION SCENARIO 1] Socket Receive Buffer (sk_rcvbuf) Dwell vs App Delay{NC}")
        print("  * Problem   : Client reports 100ms tail latency, but Java/Go server logs 2ms processing time.")
        print("  * Language  : Selector.select() / epoll_wait() only timestamps when userspace reads the socket.")
        print("  * Kernel eBPF: Measures exact dwell_ns = kprobe:tcp_recvmsg(now) - kprobe:tcp_v4_rcv(tcp_rcv_ts)")
        print("                inside progs/tracer_l5_syscall.bpf.c via ingress_flow_map[4-tuple].")
        print("  * Run Live  : krayctl trace -L 5 -d 3")
        return trace_callback(["-L", "5", "-d", "3"]) if run_live else EX_OK

    if scenario in ("2", "handoff", "sched"):
        print(f"{BOLD}[VERIFICATION SCENARIO 2] Reactor/Epoll -> Worker Pool Futex & Runqueue Handoff Tax{NC}")
        print("  * Problem   : Passing a request from Netty EventLoop to ExecutorService worker pool adds hidden latency.")
        print("  * Language  : CompletableFuture / channel handoff looks instantaneous in application code.")
        print("  * Kernel eBPF: Correlates epoll listener TID -> worker TID via 8-slot lock-free pending_handoff_map,")
        print("                measuring futex lock wait + OS runqueue latency (runqlat = t_switch - t_wakeup)")
        print("                and cross-core CPU migration (prev_cpu_id -> target_cpu_id) in progs/tracer_l6_sched.bpf.c.")
        print("  * Run Live  : krayctl trace -L 6 -d 3")
        return trace_callback(["-L", "6", "-d", "3"]) if run_live else EX_OK

    if scenario in ("3", "offcpu", "alu"):
        print(f"{BOLD}[VERIFICATION SCENARIO 3] Pure On-CPU ALU Compute vs Off-CPU Preemption Separation{NC}")
        print("  * Problem   : A business method takes 30ms wall-clock time; developers blame slow algorithm.")
        print("  * Language  : Wall-clock timers conflate CPU execution with OS thread preemption and lock sleeps.")
        print("  * Kernel eBPF: Auto-resolves ELF symbol (-s execute_storage_query) from .symtab/.dynsym and tracks")
        print("                16-depth ALU Shadow Stack in progs/tracer_l7_uprobe.bpf.c alongside sched_switch")
        print("                off-CPU accumulation (acc_off_cpu_ns), separating pure CPU ALU time from preemption.")
        print("  * Run Live  : krayctl trace -L 7 -b ./mock_server -s execute_storage_query -d 3")
        return trace_callback(["-L", "7", "-b", "./mock_server", "-s", "execute_storage_query", "-d", "3"]) if run_live else EX_OK

    if scenario in ("4", "mm", "copy"):
        print(f"{BOLD}[VERIFICATION SCENARIO 4] Kernel-to-User Memory Copy, Page Faults & Block I/O Attribution{NC}")
        print("  * Problem   : Large payload read() stalls sporadically without obvious GC or CPU spikes.")
        print("  * Language  : InputStream.read() / ByteBuf allocation hides kernel virtual memory faults.")
        print("  * Kernel eBPF: Hooks skb_copy_datagram_iovec / skb_copy_datagram_iter, kprobe:handle_mm_fault,")
        print("                and block_rq_issue -> block_rq_complete in progs/tracer_l5_syscall.bpf.c, encoding")
        print("                ((page_faults << 32) | copied_bytes) directly into the request's L5:SYSCALL_MEM event.")
        print("  * Run Live  : krayctl trace -L 5 -m 1 -d 3")
        return trace_callback(["-L", "5", "-m", "1", "-d", "3"]) if run_live else EX_OK

    if scenario in ("5", "drops", "egress"):
        print(f"{BOLD}[VERIFICATION SCENARIO 5] Egress Blindness, Per-Request kfree_skb Drop Reason & Retransmits{NC}")
        print("  * Problem   : writeAndFlush() / send() returns in 0.1ms, yet client experiences timeouts.")
        print("  * Language  : Socket write APIs return as soon as data is queued in kernel sk_sndbuf.")
        print("  * Kernel eBPF: Tracks tcp_sendmsg -> __tcp_transmit_skb -> ip_output -> net_dev_xmit, and hooks")
        print("                tracepoint:skb:kfree_skb (reason > 2) & tracepoint:tcp:tcp_retransmit_skb in")
        print("                progs/tracer_l4_tcp.bpf.c to attribute exact kernel drop reasons to req_id & TID.")
        print("  * Run Live  : krayctl trace -L 4 -c 10 -d 3")
        return trace_callback(["-L", "4", "-c", "10", "-d", "3"]) if run_live else EX_OK

    return EX_OK
