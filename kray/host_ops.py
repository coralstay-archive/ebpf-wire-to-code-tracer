"""
kray/host_ops.py — Host-Side Operations, Direct rsync/ssh Dispatch & Test Orchestration.
Zero shell-script (.sh) dependency; all external binaries are invoked via execve (shell=False).
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from kray import (
    TARGET_HOST, REMOTE_DIR, LOCAL_DIR,
    RED, GREEN, BLUE, CYAN, YELLOW, BOLD, NC,
    EX_OK
)
from kray.help_docs import (
    print_banner, help_status, help_trace, help_proto,
    help_selftest, help_install, help_test
)


def _sync_workspace(quiet_stdout: bool = False) -> int:
    out_stream = sys.stderr if quiet_stdout else sys.stdout
    out_stream.write(f"{BLUE}[*] Synchronizing workspace to {TARGET_HOST}:{REMOTE_DIR}...{NC}\n")
    out_stream.flush()
    rsync_cmd = [
        "rsync", "-avz", "--delete",
        "--exclude", ".git",
        "--exclude", "references",
        "--exclude", "*.dSYM",
        "--exclude", "__pycache__",
        "--exclude", ".pytest_cache",
        "--exclude", "*.so",
        "--exclude", "*.dylib",
        "--exclude", "mock_server",
        "--exclude", "tracer_daemon",
        "--exclude", "test_progs",
        "--exclude", "*.o",
        "--exclude", "*.skel.h",
        f"{LOCAL_DIR}/",
        f"{TARGET_HOST}:{REMOTE_DIR}/",
    ]
    res = subprocess.run(
        rsync_cmd,
        stdout=sys.stderr if quiet_stdout else None,
        stderr=sys.stderr,
        check=False,
    )
    if res.returncode == 0:
        out_stream.write(f"{GREEN}[+] Synchronization complete.{NC}\n")
        out_stream.flush()
    return res.returncode


def _run_remote(action: str, extra_args: list[str] | None = None, quiet_stderr: bool = False) -> int:
    argv = [
        "ssh", "-q", "-o", "LogLevel=QUIET",
        TARGET_HOST,
        "python3", f"{REMOTE_DIR}/kray/remote_target.py",
        action,
    ]
    if extra_args:
        argv.extend(extra_args)
    res = subprocess.run(
        argv,
        stderr=subprocess.DEVNULL if quiet_stderr else None,
        check=False,
    )
    return res.returncode


def cmd_status(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        return help_status()
    print_banner()
    print(f"{BLUE}[*] Checking Target VM Environment ({TARGET_HOST})...{NC}")
    _sync_workspace(quiet_stdout=True)
    rc = _run_remote("status")
    if rc == 0:
        print(f"{GREEN}[+] Target VM is healthy and ready for eBPF tracing!{NC}")
    return rc


def cmd_sync(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl sync")
        print("Synchronize workspace files to remote target VM.")
        return EX_OK
    return _sync_workspace(quiet_stdout=False)


def cmd_build(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl build")
        print("Compile BPF programs, skeletons, and binaries on remote target VM.")
        return EX_OK
    print_banner()
    print(f"{BLUE}[*] Compiling all BPF modules, skeletons, mock servers, and daemon on {TARGET_HOST}...{NC}")
    rc = _sync_workspace()
    if rc != 0:
        return rc
    rc = _run_remote("build")
    if rc == 0:
        print(f"{GREEN}[+] All BPF and user binaries compiled and ready on {TARGET_HOST}.{NC}")
    return rc


def cmd_selftest(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        return help_selftest()
    layer_filter = args[0] if args else "all"
    print_banner()
    print(f"{BLUE}[*] Running Native BPF Skeleton C Selftests on {TARGET_HOST} (Filter: {layer_filter})...{NC}")
    rc = _sync_workspace()
    if rc != 0:
        return rc
    rc = _run_remote("selftest", [layer_filter])
    if rc == 0:
        print(f"{GREEN}[+] Selftests passed successfully!{NC}")
    return rc


def cmd_trace(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        return help_trace()

    daemon_args: list[str] = []
    custom_url = "/compute?input=live_kray_eval"
    json_mode = False

    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok in ("-L", "--layer") and idx + 1 < len(args):
            daemon_args.extend(["-L", args[idx + 1]])
            idx += 2
        elif tok.startswith("--layer="):
            daemon_args.extend(["-L", tok.split("=", 1)[1]])
            idx += 1
        elif tok in ("-p", "--port") and idx + 1 < len(args):
            daemon_args.extend(["-p", args[idx + 1]])
            idx += 2
        elif tok.startswith("--port="):
            daemon_args.extend(["-p", tok.split("=", 1)[1]])
            idx += 1
        elif tok in (
            "-t", "--pid", "-i", "--iface", "-b", "--binary", "-s", "--symbol",
            "-o", "--offset", "-m", "--min-latency-us", "-d", "--duration", "-c", "--max-events"
        ) and idx + 1 < len(args):
            daemon_args.extend([tok, args[idx + 1]])
            idx += 2
        elif tok in ("-j", "--json"):
            json_mode = True
            daemon_args.append(tok)
            idx += 1
        elif tok in ("-v", "--verbose"):
            daemon_args.append(tok)
            idx += 1
        elif tok in ("-u", "--url") and idx + 1 < len(args):
            custom_url = args[idx + 1]
            idx += 2
        elif tok.startswith("--url="):
            custom_url = tok.split("=", 1)[1]
            idx += 1
        elif tok.startswith("http") or tok.startswith("/"):
            custom_url = tok
            idx += 1
        else:
            daemon_args.append(tok)
            idx += 1

    print_banner()
    if json_mode:
        _sync_workspace(quiet_stdout=True)
        return _run_remote("trace", ["--custom-url", custom_url, *daemon_args], quiet_stderr=True)

    print(f"{BLUE}[*] Launching Live Tracing Workflow on {TARGET_HOST}...{NC}")
    if daemon_args:
        print(f"{YELLOW}[*] Filter/Options: {' '.join(daemon_args)}{NC}")
    else:
        print(f"{GREEN}[*] Scope: All 7 Layers (Wire-to-Code End-to-End){NC}")
    print(f"{CYAN}[*] Target Traffic URL: http://127.0.0.1:8080{custom_url}{NC}")

    _sync_workspace()
    return _run_remote("trace", ["--custom-url", custom_url, *daemon_args])


def cmd_proto(args: list[str]) -> int:
    sub_cmd = args[0] if args else "list"
    rest = args[1:] if len(args) > 1 else []

    if sub_cmd in ("-h", "--help", "help"):
        return help_proto()

    print_banner()
    dissector = str(LOCAL_DIR / "kray_proto_dissector.py")
    if sub_cmd == "list":
        return subprocess.run([sys.executable, dissector, "list"], check=False).returncode
    if sub_cmd in ("ports", "port"):
        return subprocess.run([sys.executable, dissector, "ports"], check=False).returncode
    if sub_cmd in ("ieee", "standards"):
        return subprocess.run([sys.executable, dissector, "ieee"], check=False).returncode
    if sub_cmd == "test":
        return subprocess.run([sys.executable, dissector, "test"], check=False).returncode
    if sub_cmd in ("inspect", "show", "dump"):
        target_proto = rest[0] if rest else "http1"
        return subprocess.run([sys.executable, dissector, "inspect", target_proto], check=False).returncode
    return subprocess.run([sys.executable, dissector, "inspect", sub_cmd], check=False).returncode


def cmd_chaos(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl chaos")
        print("Execute chaos & fuzzing stress test suite.")
        return EX_OK
    print_banner()
    print(f"{BLUE}[*] Executing Chaos Edge-Case Stress Validation Suite...{NC}")
    return subprocess.run(
        [sys.executable, str(LOCAL_DIR / "test_verification_suite.py"), "-v", "-k", "adv_04|adv_05|adv_06|adv_08"],
        check=False,
    ).returncode


def cmd_dashboard(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl dashboard")
        print("Generate HTML trace dashboard and open it in browser.")
        return EX_OK
    print_banner()
    print(f"{BLUE}[*] Regenerating Web Dashboard and SVG Architecture Artifacts...{NC}")
    rc = subprocess.run([sys.executable, str(LOCAL_DIR / "tracer_agent.py")], check=False).returncode
    dash_path = LOCAL_DIR / "trace_dashboard.html"
    print(f"{GREEN}[+] Dashboard generated at: file://{dash_path}{NC}")
    if shutil.which("open"):
        subprocess.run(["open", str(dash_path)], check=False)
    return rc


def cmd_claims(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl claims")
        print("Verify all 6 empirical hardware, BTF, JIT & CLI claims on target VM.")
        return EX_OK
    print_banner()
    _sync_workspace()
    rc = _run_remote("verify-claims")
    if rc != 0:
        return rc
    print(f"\n{BOLD}{BLUE}[CLAIM 6] Continuous Failure Conditions Verification Suite{NC}")
    rc = subprocess.run([sys.executable, str(LOCAL_DIR / "test_failure_conditions.py"), "--iterations", "5"], check=False).returncode
    if rc == 0:
        print(f"{GREEN}[+] ALL 6 EMPIRICAL CLAIMS VERIFIED AGAINST REAL LINUX KERNEL & ARM64 HARDWARE!{NC}")
    return rc


def cmd_run_all(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl run-all")
        print("Execute all 7 master automated test suites (350/350 tests).")
        return EX_OK
    print_banner()
    suites = [
        ("[SUITE 1/7] Michael Kerrisk TLPI CLI Standards & Sysexits Suite", [sys.executable, str(LOCAL_DIR / "test_cli_standards.py")]),
        ("[SUITE 2/7] Failure Conditions 20-Iteration Continuous Reliability Suite", [sys.executable, str(LOCAL_DIR / "test_failure_conditions.py"), "--iterations", "20"]),
        ("[SUITE 3/7] Real Packet Wire Transmission & Socket Interception Suite", [sys.executable, str(LOCAL_DIR / "test_live_packets.py")]),
        ("[SUITE 4/7] 22-Protocol Data Frame Decode Suite", [sys.executable, str(LOCAL_DIR / "kray_proto_dissector.py"), "test"]),
        ("[SUITE 5/7] 24-Suite Full Integration Verification Suite", [sys.executable, str(LOCAL_DIR / "test_verification_suite.py")]),
    ]
    for title, cmd_argv in suites:
        print(f"\n{BOLD}{BLUE}{title}{NC}")
        rc = subprocess.run(cmd_argv, check=False).returncode
        if rc != 0:
            return rc

    print(f"\n{BOLD}{BLUE}[SUITE 6/7] Target Machine (Rocky Linux 9.8 aarch64) Native Selftests{NC}")
    rc = cmd_selftest(["all"])
    if rc != 0:
        return rc

    print(f"\n{BOLD}{BLUE}[SUITE 7/7] Exhaustive 105 CLI Command Scenario Matrix Verification Suite{NC}")
    rc = subprocess.run([sys.executable, str(LOCAL_DIR / "test_all_command_scenarios.py")], check=False).returncode
    if rc == 0:
        print(f"\n{BOLD}{GREEN}ALL 7 TEST SUITES EXECUTED SUCCESSFULLY WITH 100% PASS RATE!{NC}")
    return rc


def cmd_test(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        return help_test()

    run_remote = any(a in ("-r", "--remote") for a in args)
    run_suite = any(a in ("-s", "--suite") for a in args)
    run_failure = any(a in ("-f", "--failure", "failure") for a in args)
    run_cli = any(a in ("-c", "--cli", "cli") for a in args)
    run_scenarios = any(a in ("-m", "--scenarios", "scenarios") for a in args)
    run_all = any(a in ("--all", "all") for a in args)

    if run_all:
        return cmd_run_all([])
    if run_scenarios:
        print_banner()
        print(f"{BLUE}[*] Executing Exhaustive 105 CLI Command Scenario Matrix Test Suite...{NC}")
        cmd_build([])
        return subprocess.run([sys.executable, str(LOCAL_DIR / "test_all_command_scenarios.py")], check=False).returncode
    if run_cli:
        print_banner()
        print(f"{BLUE}[*] Executing Michael Kerrisk TLPI CLI Standards & Stream Separation Test Suite...{NC}")
        cmd_build([])
        return subprocess.run([sys.executable, str(LOCAL_DIR / "test_cli_standards.py")], check=False).returncode
    if run_failure:
        print_banner()
        if run_remote:
            _sync_workspace()
            return subprocess.run(
                ["ssh", "-q", "-o", "LogLevel=QUIET", TARGET_HOST, "python3", f"{REMOTE_DIR}/test_failure_conditions.py"],
                check=False,
            ).returncode
        return subprocess.run([sys.executable, str(LOCAL_DIR / "test_failure_conditions.py")], check=False).returncode
    if run_suite:
        print_banner()
        return subprocess.run([sys.executable, str(LOCAL_DIR / "test_verification_suite.py"), "-v"], check=False).returncode
    if run_remote:
        print_banner()
        _sync_workspace()
        return subprocess.run(
            ["ssh", "-q", "-o", "LogLevel=QUIET", TARGET_HOST, "sudo", "python3", f"{REMOTE_DIR}/test_live_packets.py"],
            check=False,
        ).returncode

    print_banner()
    return subprocess.run([sys.executable, str(LOCAL_DIR / "test_live_packets.py")], check=False).returncode


def cmd_install(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        return help_install()

    target_dir = Path.home() / ".local" / "bin"
    for arg in args:
        if arg in ("--system", "-s", "/usr/local/bin"):
            target_dir = Path("/usr/local/bin")
        elif arg == "--user":
            target_dir = Path.home() / ".local" / "bin"

    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / "krayctl"
    src = LOCAL_DIR / "krayctl"

    if os.access(target_dir, os.W_OK):
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.symlink_to(src)
    else:
        subprocess.run(["sudo", "ln", "-sf", str(src), str(dest)], check=True)

    print(f"{GREEN}[+] Successfully installed 'krayctl' to {dest}{NC}")
    return EX_OK


def cmd_uninstall(args: list[str]) -> int:
    if "-h" in args or "--help" in args:
        print("Usage: krayctl uninstall [--user|--system]")
        print("Remove krayctl symlink from PATH (~/.local/bin or /usr/local/bin).")
        return EX_OK

    target_dir = Path.home() / ".local" / "bin"
    for arg in args:
        if arg in ("--system", "-s", "/usr/local/bin"):
            target_dir = Path("/usr/local/bin")
        elif arg == "--user":
            target_dir = Path.home() / ".local" / "bin"

    dest = target_dir / "krayctl"
    if dest.exists() or dest.is_symlink():
        if os.access(target_dir, os.W_OK):
            dest.unlink()
        else:
            subprocess.run(["sudo", "rm", "-f", str(dest)], check=True)
        print(f"{GREEN}[+] Successfully uninstalled 'krayctl' from {dest}{NC}")
    else:
        print(f"{YELLOW}[-] 'krayctl' not found in {target_dir}{NC}")
    return EX_OK
