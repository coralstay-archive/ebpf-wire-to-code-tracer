"""
kray/help_docs.py — Human-Readable CLI Synopses, Help Pages & Operator Cheatsheets.
"""

import sys
from kray import (
    VERSION, TARGET_HOST, REMOTE_DIR,
    GREEN, CYAN, YELLOW, BOLD, NC, EX_OK
)


def print_banner() -> None:
    sys.stderr.write(
        f"{CYAN}{BOLD}\n"
        "================================================================================\n"
        "           krayctl — eBPF-WireToCode-Tracer Command-Line Control\n"
        f"  Target: Rocky Linux 9.8 aarch64 ({TARGET_HOST} -> {REMOTE_DIR})\n"
        "================================================================================\n"
        f"{NC}\n"
    )
    sys.stderr.flush()


def cmd_version() -> int:
    print(f"krayctl version {VERSION} (eBPF-WireToCode-Tracer)")
    print("Copyright (C) 2026 Antigravity Kernel Performance Engineering")
    print("License GPLv2: GNU GPL version 2 <https://gnu.org/licenses/gpl-2.0.html>")
    print("Target Kernel: Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)")
    return EX_OK


def usage(exit_code: int = EX_OK) -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl — eBPF-powered wire-to-code network latency and protocol tracer")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl [GLOBAL-OPTIONS] <COMMAND> [OPTIONS] [ARGUMENTS]")
    print("")
    print(f"{BOLD}GLOBAL OPTIONS{NC}")
    print("  -h, --help                 Display top-level help and exit")
    print("  -v, -V, --version          Display version information and exit")
    print("")
    print(f"{BOLD}AVAILABLE COMMANDS{NC}")
    print(f"  {GREEN}status{NC}             Check target VM connectivity, kernel release, BTF & BPF JIT status")
    print(f"  {GREEN}verify [1..5|list]{NC} Run or inspect the 5 Real-World I/O & Kernel Verification Scenarios")
    print(f"  {GREEN}test [options]{NC}     Execute 23/23 REAL packet wire transmission and eBPF experiments")
    print(f"  {GREEN}trace [options]{NC}    Execute live 7-layer wire-to-code tracing (filter with -L 2..7)")
    print(f"  {GREEN}proto [subcmd]{NC}     22-Protocol Data Frame Inspector (list, ports, ieee, test, inspect <proto>)")
    print(f"  {GREEN}selftest [layer]{NC}   Run native C selftests (all 7 layers, or filter: l2, l4, l6, etc.)")
    print(f"  {GREEN}build{NC}              Compile micro-BPF objects, skeletons, daemon, and test runners")
    print(f"  {GREEN}sync{NC}               Sync workspace files from local host to target VM")
    print(f"  {GREEN}claims{NC}             Verify all 6 empirical hardware, BTF, JIT & CLI claims on target VM")
    print(f"  {GREEN}run-all{NC}            Execute all 7 master automated test suites (350/350 tests)")
    print(f"  {GREEN}chaos{NC}              Run edge-case chaos & fuzzing stress test suite")
    print(f"  {GREEN}dashboard{NC}          Generate & open the HTML Trace Dashboard and SVG diagrams")
    print(f"  {GREEN}inspect{NC}            Display Linux native commands (bpftool, ss, curl, ip) cheat-sheet")
    print(f"  {GREEN}install [--user]{NC}   Install krayctl to PATH (~/.local/bin or /usr/local/bin)")
    print(f"  {GREEN}uninstall{NC}          Remove krayctl symlink from PATH")
    print("")
    print(f"{BOLD}QUICK EXAMPLES{NC}")
    print("  krayctl verify list                # View 5 Real-World Verification Scenarios (vs Java/Go I/O APIs)")
    print("  krayctl verify 1                   # Verify Scenario 1: Socket Receive Buffer (sk_rcvbuf) Dwell Time")
    print("  krayctl verify 2                   # Verify Scenario 2: Epoll -> Worker Pool Futex & Runqueue Handoff")
    print("  krayctl trace                      # View ALL 7 layers end-to-end")
    print("  krayctl trace -L 4                 # Isolate L4 TCP transport & drop layer only")
    print("  krayctl trace -L 6                 # Isolate L6 scheduler handoff & futex layer")
    print("  krayctl trace -j                   # Output raw JSON lines for downstream tooling / jq")
    print("  krayctl proto ports                # View 4 port categories (Non-IP, 0..1023, 1024..49151, Ephem)")
    print("  krayctl proto ieee                 # Display comprehensive IEEE 802 standards guide")
    print("  krayctl proto inspect wifi         # Inspect Wi-Fi IEEE 802.11 MAC frame")
    print("  krayctl proto test                 # Run 22/22 protocol decode bit-exact test")
    print("")
    print(f"{BOLD}HELP ON SPECIFIC COMMANDS{NC}")
    print("  krayctl help <command>      (e.g. 'krayctl help trace' or 'krayctl trace --help')")
    print("")
    return exit_code


def help_status() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-status — Inspect target VM environment and eBPF readiness")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl status [OPTIONS]")
    print("")
    print(f"{BOLD}DESCRIPTION{NC}")
    print("  Verifies remote VM connectivity over SSH, confirms target kernel version,")
    print("  checks BTF (/sys/kernel/btf/vmlinux), BPF JIT compiler status, Clang, and bpftool.")
    print("")
    print(f"{BOLD}OPTIONS{NC}")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def help_trace() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-trace — Execute live 7-layer wire-to-code eBPF tracing")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl trace [OPTIONS] [URL_PATH]")
    print("")
    print(f"{BOLD}DESCRIPTION{NC}")
    print("  Attaches eBPF probes across all 7 layers (L2 XDP through L7 Uprobe), spawns")
    print("  the target workload service, issues a test request, decodes live packet")
    print("  payloads, and outputs correlated latency metrics.")
    print("")
    print(f"{BOLD}OPTIONS{NC}")
    print("  -L, --layer <2..7>         Filter trace to specific layer only:")
    print("                               2 = Link Layer (XDP / VLAN)")
    print("                               3 = Network Layer (IPv4 / IPv6 / ARP)")
    print("                               4 = Transport Layer (TCP state & drops)")
    print("                               5 = Socket Buffer & Syscall ABI")
    print("                               6 = Scheduler Handoff & Futex")
    print("                               7 = Userspace Uprobe & Shadow Stack")
    print("  -j, --json                 Output machine-readable JSON lines stream to stdout")
    print("  -p, --port <port>          Target server port filter (default: 8080)")
    print("  -t, --pid <pid>            Target process PID/TGID filter (default: 0 = all)")
    print("  -i, --iface <dev>          Attach XDP to network interface (e.g. lo, eth0)")
    print("  -b, --binary <path>        Target binary or shared library (.so) for Uprobe")
    print("  -s, --symbol <name>        Auto-resolve ELF symbol (.symtab/.dynsym) for Uprobe")
    print("  -o, --offset <hex>         Explicit symbol file offset for Uprobe (e.g. 0x1180)")
    print("  -m, --min-latency-us <us>  Surgical tail-latency threshold filter in microseconds")
    print("  -d, --duration <sec>       Auto-detach and exit after <sec> seconds")
    print("  -c, --max-events <count>   Auto-detach and exit after <count> captured events")
    print("  -u, --url <path>           Custom HTTP request path (default: /compute?input=live_kray_eval)")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def help_proto() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-proto — Multi-protocol data frame dissector and IEEE 802 inspector")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl proto <ACTION> [ARGUMENTS]")
    print("")
    print(f"{BOLD}ACTIONS{NC}")
    print("  list                       List all 22 supported protocols across OSI L2~L7")
    print("  ports                      List protocols categorized by Port Groups (Non-IP, 0..1023, 1024..49151, Ephemeral)")
    print("  ieee                       Display comprehensive IEEE 802.1/3/11/15 standards reference")
    print("  inspect <protocol>         Inspect bit-exact decoded packet tree and hex dump")
    print("  test                       Run bit-level decoder verification across all 22 protocols")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def help_selftest() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-selftest — Run kernel-style BPF skeleton verification selftests")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl selftest [LAYER]")
    print("")
    print(f"{BOLD}ARGUMENTS{NC}")
    print("  [LAYER]                    Optional layer filter: 'all', 'l2', 'l3', 'l4', 'l5', 'l6', 'l7'")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def help_install() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-install — Install krayctl CLI to system PATH")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl install [OPTIONS]")
    print("")
    print(f"{BOLD}OPTIONS{NC}")
    print("  --user                     Install to ~/.local/bin (default for non-root)")
    print("  --system, -s               Install to /usr/local/bin (requires root/sudo)")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def help_test() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-test — Execute real wire packet transmission & eBPF experiments")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl test [OPTIONS]")
    print("")
    print(f"{BOLD}OPTIONS{NC}")
    print("  --failure, -f, failure     Execute 8/8 failure conditions, degradation & edge case test suite")
    print("  --cli, -c, cli             Execute Michael Kerrisk TLPI CLI Standards & stream separation test suite")
    print("  --scenarios, -m, scenarios Execute exhaustive CLI command scenario matrix test suite")
    print("  --remote, -r               Execute real packet / failure tests remotely on target Linux VM")
    print("  --suite, -s                Execute the full 24-suite integration test verification suite")
    print("  --all, all                 Execute all 7 master test suites (350/350 tests)")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def help_verify() -> int:
    print_banner()
    print(f"{BOLD}NAME{NC}")
    print("  krayctl-verify — Real-world I/O & kernel latency verification scenarios (Beyond Java/Go I/O APIs)")
    print("")
    print(f"{BOLD}SYNOPSIS{NC}")
    print("  krayctl verify [SCENARIO] [OPTIONS]")
    print("")
    print(f"{BOLD}SCENARIOS{NC}")
    print("  list                       Display all 5 verification scenarios and language I/O blind spots")
    print("  1, ingress, dwell          Scenario 1: Socket Receive Queue (sk_rcvbuf) Dwell vs App GC/Loop Delay")
    print("  2, handoff, sched          Scenario 2: Reactor/Epoll -> Worker Pool Futex & Runqueue Handoff Tax")
    print("  3, offcpu, alu             Scenario 3: Pure On-CPU ALU Compute vs Off-CPU Preemption Separation")
    print("  4, mm, copy                Scenario 4: Kernel-to-User Buffer Copy, Page Faults & Block I/O Attribution")
    print("  5, drops, egress           Scenario 5: Egress Blindness, Per-Request kfree_skb Drop Reason & Retransmit")
    print("")
    print(f"{BOLD}OPTIONS{NC}")
    print("  --live, -l                 Execute live eBPF trace on target VM for the selected scenario")
    print("  -h, --help                 Display this help and exit")
    return EX_OK


def cmd_inspect(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl inspect")
        print("Display native Linux CLI inspection commands cheat-sheet.")
        return EX_OK
    print_banner()
    print(f"{BOLD}LINUX OPERATOR INSPECTION CHEAT-SHEET:{NC}\n")
    print(f"{YELLOW}1. eBPF Program Inspection (via bpftool):{NC}")
    print(f'   ssh {TARGET_HOST} "sudo bpftool prog show"')
    print(f'   ssh {TARGET_HOST} "sudo bpftool prog dump xlated name xdp_ingress_filter"\n')
    print(f"{YELLOW}2. eBPF Map State & Flow Inspection:{NC}")
    print(f'   ssh {TARGET_HOST} "sudo bpftool map show"')
    print(f'   ssh {TARGET_HOST} "sudo bpftool map dump name ingress_flow_map"')
    print(f'   ssh {TARGET_HOST} "sudo bpftool map dump name active_ctx_map"\n')
    print(f"{YELLOW}3. Network Interface & Attached XDP Hooks:{NC}")
    print(f'   ssh {TARGET_HOST} "sudo bpftool net show"')
    print(f'   ssh {TARGET_HOST} "ip link show lo"\n')
    print(f"{YELLOW}4. Socket & Port Listening Status:{NC}")
    print(f'   ssh {TARGET_HOST} "ss -tulpn | grep 8080"\n')
    print(f"{YELLOW}5. Live Manual Request Generation:{NC}")
    print(f'   ssh {TARGET_HOST} "curl -i http://127.0.0.1:8080/compute?input=hello"\n')
    print(f"{YELLOW}6. Kernel Tracing Pipe (Printk Debug Logs):{NC}")
    print(f'   ssh {TARGET_HOST} "sudo cat /sys/kernel/debug/tracing/trace_pipe"\n')
    print(f"{YELLOW}7. Real-World I/O & Kernel Verification Scenarios:{NC}")
    print("   krayctl verify list")
    print("   krayctl verify 1          # Socket Queue Dwell (sk_rcvbuf) vs JVM GC/EventLoop Delay")
    print("   krayctl verify 2          # Epoll -> Worker Pool Futex & Scheduler Runqueue Handoff")
    print("   krayctl verify 3          # On-CPU Pure ALU Compute vs Off-CPU Preemption Separation")
    print("   krayctl verify 4          # Kernel-to-User Copy (skb_copy_datagram_iter) & Page Faults")
    print("   krayctl verify 5          # Per-Request Egress Blindness, kfree_skb Drop & Retransmit\n")
    return EX_OK
