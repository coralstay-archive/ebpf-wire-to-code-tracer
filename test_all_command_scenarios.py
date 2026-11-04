#!/usr/bin/env python3
"""
================================================================================
test_all_command_scenarios.py — Exhaustive CLI Command Scenario Verification
================================================================================
Authoritative References:
  - Michael Kerrisk, "The Linux Programming Interface", Chapter 56, 63, Appendix B
  - POSIX IEEE Std 1003.1-2017 Utility Guidelines 1..13
  - BSD <sysexits.h> Standardized Process Exit Status Codes
  - Master Specification & Reference: [README.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)

Validates 110 Exhaustive Command Scenarios Across All Subcommands, Flags, Error Codes,
and Stream Separation Invariants on Both Host and Target VM Environments.
================================================================================
"""

import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Tuple

EX_OK = 0
EX_USAGE = 64
EX_DATAERR = 65
EX_UNAVAILABLE = 69
EX_NOPERM = 77
EX_CLI_INVALID_CMD = 2

ROOT_DIR = Path(__file__).resolve().parent
KRAYCTL = str(ROOT_DIR / "krayctl")
SSH_TARGET = os.getenv("KRAY_HOST", "ebpf-vm")
REMOTE_DIR = os.getenv("KRAY_DIR", "ebpf-wire-to-code-tracer")


def run_local(cmd_args: str) -> subprocess.CompletedProcess:
    """Run local krayctl command without a shell and capture stdout/stderr."""
    cmd_list = [sys.executable, KRAYCTL, *shlex.split(cmd_args)] if cmd_args else [sys.executable, KRAYCTL]
    return subprocess.run(
        cmd_list,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def run_remote_action(*action_args: str) -> subprocess.CompletedProcess:
    """Execute kray/remote_target.py action on remote target VM without a shell."""
    remote_script = f"{REMOTE_DIR}/kray/remote_target.py"
    cmd = ["ssh", "-q", "-o", "LogLevel=QUIET", SSH_TARGET, "python3", remote_script, *action_args]
    return subprocess.run(
        cmd,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


def run_daemon_remote(args_str: str) -> subprocess.CompletedProcess:
    """Execute tracer_daemon on remote target VM without a shell and capture stdout/stderr."""
    remote_bin = f"{REMOTE_DIR}/tracer_daemon"
    cmd = ["ssh", "-q", "-o", "LogLevel=QUIET", SSH_TARGET, remote_bin, *shlex.split(args_str)]
    res = subprocess.run(
        cmd,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # Filter SSH transport banner noise
    clean_stderr = "\n".join(
        line for line in res.stderr.splitlines()
        if not line.startswith("**") and "post-quantum" not in line and "openssh.com" not in line
    ).strip()
    res.stderr = clean_stderr
    return res


class TestAllCommandScenarios(unittest.TestCase):
    """Exhaustive Scenario Matrix Verification Suite."""

    # --------------------------------------------------------------------------
    # GROUP 1: Global krayctl Help & Version Invocations (8 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_01_bare_krayctl_shows_usage(self):
        """Scenario 1: Running bare 'krayctl' with no arguments displays usage and exits 0."""
        res = run_local("")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("SYNOPSIS", res.stdout)
        self.assertIn("AVAILABLE COMMANDS", res.stdout)

    def test_scen_02_krayctl_short_help(self):
        """Scenario 2: 'krayctl -h' displays top-level help and exits 0."""
        res = run_local("-h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("SYNOPSIS", res.stdout)

    def test_scen_03_krayctl_long_help(self):
        """Scenario 3: 'krayctl --help' displays top-level help and exits 0."""
        res = run_local("--help")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("SYNOPSIS", res.stdout)

    def test_scen_04_krayctl_help_command(self):
        """Scenario 4: 'krayctl help' displays top-level help and exits 0."""
        res = run_local("help")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("SYNOPSIS", res.stdout)

    def test_scen_05_krayctl_short_version(self):
        """Scenario 5: 'krayctl -v' prints version info and exits 0."""
        res = run_local("-v")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl version", res.stdout)

    def test_scen_06_krayctl_uppercase_version(self):
        """Scenario 6: 'krayctl -V' prints version info and exits 0."""
        res = run_local("-V")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl version", res.stdout)

    def test_scen_07_krayctl_long_version(self):
        """Scenario 7: 'krayctl --version' prints version info and exits 0."""
        res = run_local("--version")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl version", res.stdout)

    def test_scen_08_krayctl_subcommand_version(self):
        """Scenario 8: 'krayctl version' prints version info and exits 0."""
        res = run_local("version")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl version", res.stdout)

    # --------------------------------------------------------------------------
    # GROUP 2: Contextual Help Subcommands ('krayctl help <cmd>') (6 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_09_help_status(self):
        """Scenario 9: 'krayctl help status' prints status command synopsis and exits 0."""
        res = run_local("help status")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-status", res.stdout)

    def test_scen_10_help_test(self):
        """Scenario 10: 'krayctl help test' prints test command synopsis and exits 0."""
        res = run_local("help test")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-test", res.stdout)

    def test_scen_11_help_trace(self):
        """Scenario 11: 'krayctl help trace' prints trace command synopsis and exits 0."""
        res = run_local("help trace")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-trace", res.stdout)

    def test_scen_12_help_proto(self):
        """Scenario 12: 'krayctl help proto' prints proto command synopsis and exits 0."""
        res = run_local("help proto")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-proto", res.stdout)

    def test_scen_13_help_selftest(self):
        """Scenario 13: 'krayctl help selftest' prints selftest synopsis and exits 0."""
        res = run_local("help selftest")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-selftest", res.stdout)

    def test_scen_14_help_install(self):
        """Scenario 14: 'krayctl help install' prints install synopsis and exits 0."""
        res = run_local("help install")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-install", res.stdout)

    # --------------------------------------------------------------------------
    # GROUP 3: Subcommand Help Flags ('<cmd> -h' / '--help') (8 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_15_status_help_flag(self):
        """Scenario 15: 'krayctl status -h' prints status help and exits 0."""
        res = run_local("status -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-status", res.stdout)

    def test_scen_16_test_help_flag(self):
        """Scenario 16: 'krayctl test -h' prints test help and exits 0."""
        res = run_local("test -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-test", res.stdout)

    def test_scen_17_trace_help_flag(self):
        """Scenario 17: 'krayctl trace -h' prints trace help and exits 0."""
        res = run_local("trace -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-trace", res.stdout)

    def test_scen_18_proto_help_flag(self):
        """Scenario 18: 'krayctl proto -h' prints proto help and exits 0."""
        res = run_local("proto -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-proto", res.stdout)

    def test_scen_19_selftest_help_flag(self):
        """Scenario 19: 'krayctl selftest -h' prints selftest help and exits 0."""
        res = run_local("selftest -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-selftest", res.stdout)

    def test_scen_20_sync_help_flag(self):
        """Scenario 20: 'krayctl sync -h' prints sync usage and exits 0."""
        res = run_local("sync -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("Usage: krayctl sync", res.stdout)

    def test_scen_21_build_help_flag(self):
        """Scenario 21: 'krayctl build -h' prints build usage and exits 0."""
        res = run_local("build -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("Usage: krayctl build", res.stdout)

    def test_scen_22_install_help_flag(self):
        """Scenario 22: 'krayctl install -h' prints install help and exits 0."""
        res = run_local("install -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-install", res.stdout)

    # --------------------------------------------------------------------------
    # GROUP 4: Local Operational Subcommands (inspect, proto) (5 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_23_inspect_cheatsheet(self):
        """Scenario 23: 'krayctl inspect' outputs Linux native inspection tools and exits 0."""
        res = run_local("inspect")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("bpftool", res.stdout)
        self.assertIn("trace_pipe", res.stdout)

    def test_scen_24_proto_list(self):
        """Scenario 24: 'krayctl proto list' lists all 22 supported protocols and exits 0."""
        res = run_local("proto list")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("22 Communication Protocols", res.stdout)
        self.assertIn("Wi-Fi", res.stdout)
        self.assertIn("Bluetooth", res.stdout)
        self.assertIn("gRPC", res.stdout)

    def test_scen_25_proto_ports(self):
        """Scenario 25: 'krayctl proto ports' displays systematic 4-tier port inventory and exits 0."""
        res = run_local("proto ports")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("GROUP 1: Non-IP", res.stdout)
        self.assertIn("GROUP 2: Well-Known System Ports", res.stdout)
        self.assertIn("GROUP 3: Registered Ports", res.stdout)
        self.assertIn("GROUP 4: Dynamic & Ephemeral Ports", res.stdout)

    def test_scen_26_proto_ieee(self):
        """Scenario 26: 'krayctl proto ieee' displays IEEE standards guide and exits 0."""
        res = run_local("proto ieee")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("IEEE 802.3", res.stdout)
        self.assertIn("IEEE 802.11", res.stdout)
        self.assertIn("IEEE 802.15.1", res.stdout)

    def test_scen_27_proto_test(self):
        """Scenario 27: 'krayctl proto test' verifies bit-exact decode across 22/22 protocols."""
        res = run_local("proto test")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("22/22 PASSED (100% VERIFIED)", res.stdout)

    # --------------------------------------------------------------------------
    # GROUP 5: All 22 Individual Protocol Inspections (22 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_28_to_49_proto_inspect_all_22_protocols(self):
        """Scenarios 28..49: 'krayctl proto inspect <proto>' for each of all 22 protocols."""
        protocols = [
            "wifi", "bluetooth", "vlan", "arp", "icmp", "unix",
            "ftp", "ssh", "dns", "http1", "ntp", "tls", "smb",
            "mqtt", "nfs", "iscsi", "mysql", "postgres", "redis",
            "kafka", "grpc", "http2"
        ]
        for proto in protocols:
            with self.subTest(protocol=proto):
                res = run_local(f"proto inspect {proto}")
                self.assertEqual(res.returncode, EX_OK, f"Failed on protocol: {proto}")
                self.assertIn("OSI Layer:", res.stdout, f"Missing OSI Layer header for: {proto}")
                self.assertIn("RAW FRAME DATA & HEX DUMP", res.stdout, f"Missing HEX DUMP for: {proto}")

    # --------------------------------------------------------------------------
    # GROUP 6: Error & Boundary Argument Handling (2 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_50_unknown_subcommand_exits_2(self):
        """Scenario 50: Unknown subcommand 'krayctl nonexistent_cmd' returns exit code 2."""
        res = run_local("nonexistent_cmd")
        self.assertEqual(res.returncode, EX_CLI_INVALID_CMD)
        self.assertIn("Error: Unknown command", res.stderr)

    def test_scen_51_unknown_flag_exits_2(self):
        """Scenario 51: Unknown top-level option 'krayctl --nonexistent-option' returns exit code 2."""
        res = run_local("--nonexistent-option")
        self.assertEqual(res.returncode, EX_CLI_INVALID_CMD)
        self.assertIn("Error: Unknown command", res.stderr)

    # --------------------------------------------------------------------------
    # GROUP 7: Direct tracer_daemon CLI Standards & POSIX Guidelines (26 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_52_daemon_short_help(self):
        """Scenario 52: 'tracer_daemon -h' prints to stdout, 0 stderr, returns EX_OK (0)."""
        res = run_daemon_remote("-h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("Usage:", res.stdout)
        self.assertEqual(len(res.stderr.strip()), 0)

    def test_scen_53_daemon_long_help(self):
        """Scenario 53: 'tracer_daemon --help' prints to stdout, 0 stderr, returns EX_OK (0)."""
        res = run_daemon_remote("--help")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("Usage:", res.stdout)
        self.assertEqual(len(res.stderr.strip()), 0)

    def test_scen_54_daemon_short_version(self):
        """Scenario 54: 'tracer_daemon -V' prints to stdout, 0 stderr, returns EX_OK (0)."""
        res = run_daemon_remote("-V")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("tracer_daemon v", res.stdout)
        self.assertEqual(len(res.stderr.strip()), 0)

    def test_scen_55_daemon_long_version(self):
        """Scenario 55: 'tracer_daemon --version' prints to stdout, 0 stderr, returns EX_OK (0)."""
        res = run_daemon_remote("--version")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("tracer_daemon v", res.stdout)
        self.assertEqual(len(res.stderr.strip()), 0)

    def test_scen_56_to_61_daemon_missing_arguments(self):
        """Scenarios 56..61: Options requiring arguments (-p, -t, -L, -i, -b, -o) return EX_USAGE (64)."""
        for flag in ["-p", "-t", "-L", "-i", "-b", "-o"]:
            with self.subTest(flag=flag):
                res = run_daemon_remote(flag)
                self.assertEqual(res.returncode, EX_USAGE)
                self.assertIn("requires an argument", res.stderr)
                self.assertEqual(len(res.stdout.strip()), 0)

    def test_scen_62_and_63_daemon_unrecognized_options(self):
        """Scenarios 62 & 63: Unrecognized options (-z, --invalid) return EX_USAGE (64)."""
        for flag in ["-z", "--invalid-option"]:
            with self.subTest(flag=flag):
                res = run_daemon_remote(flag)
                self.assertEqual(res.returncode, EX_USAGE)
                self.assertIn("unrecognized option", res.stderr)
                self.assertEqual(len(res.stdout.strip()), 0)

    def test_scen_64_to_67_daemon_out_of_range_values(self):
        """Scenarios 64..67: Out-of-range port and layer numbers return EX_USAGE (64)."""
        bad_args = [
            ("-p 99999", "invalid port value"),
            ("-p -1", "invalid port value"),
            ("-p nonnum", "invalid port value"),
            ("-t -10", "invalid PID value"),
            ("-L 0", "invalid layer"),
            ("-L 8", "invalid layer"),
            ("-L invalid_layer", "invalid layer"),
        ]
        for arg_str, expected_err in bad_args:
            with self.subTest(arg_str=arg_str):
                res = run_daemon_remote(arg_str)
                self.assertEqual(res.returncode, EX_USAGE)
                self.assertIn(expected_err, res.stderr)
                self.assertEqual(len(res.stdout.strip()), 0)

    def test_scen_68_daemon_clustered_options_and_stream_separation(self):
        """Scenario 68: Clustered options '-jv' execute correctly, produce EX_NOPERM (77) for non-root."""
        res = run_daemon_remote("-jv")
        self.assertEqual(res.returncode, EX_NOPERM)
        self.assertEqual(len(res.stdout.strip()), 0)
        self.assertIn('"error":"EPERM"', res.stderr)

    def test_scen_69_daemon_end_of_options_delimiter(self):
        """Scenario 69: End-of-options delimiter '--' terminates option parsing."""
        res = run_daemon_remote("-- -p 80")
        # Options after '--' are treated as non-options; daemon proceeds to preflight check
        self.assertEqual(res.returncode, EX_NOPERM)

    def test_scen_70_to_81_daemon_valid_layer_names(self):
        """Scenarios 70..81: All 12 valid layer names parse cleanly and advance to preflight."""
        layer_names = [
            "l2", "xdp", "l3", "ip", "l4", "tcp",
            "l5", "socket", "l6", "sched", "l7", "uprobe"
        ]
        for layer in layer_names:
            with self.subTest(layer=layer):
                res = run_daemon_remote(f"-L {layer}")
                self.assertEqual(res.returncode, EX_NOPERM)

    # --------------------------------------------------------------------------
    # GROUP 8: Live Operational VM Scenarios (2 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_82_remote_krayctl_status(self):
        """Scenario 82: 'krayctl status' connects to target VM, verifies kernel, BTF, JIT."""
        res = run_local("status")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("Kernel Release:    5.14.0", res.stdout)
        self.assertIn("BTF vmlinux:       Available", res.stdout)
        self.assertIn("BPF JIT Enabled:   1", res.stdout)

    def test_scen_83_remote_krayctl_selftest(self):
        """Scenario 83: 'krayctl selftest' executes 7/7 native BPF skeleton selftests on target VM."""
        res = run_local("selftest")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("7/7 PASSED", res.stdout)

    # --------------------------------------------------------------------------
    # GROUP 9: Real-World I/O & Kernel Verification Scenarios (8 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_84_help_verify(self):
        """Scenario 84: 'krayctl help verify' prints verify synopsis and exits 0."""
        res = run_local("help verify")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-verify", res.stdout)

    def test_scen_85_verify_help_flag(self):
        """Scenario 85: 'krayctl verify -h' prints verify help and exits 0."""
        res = run_local("verify -h")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("krayctl-verify", res.stdout)

    def test_scen_86_verify_list(self):
        """Scenario 86: 'krayctl verify list' displays all 5 real-world verification scenarios."""
        res = run_local("verify list")
        self.assertEqual(res.returncode, EX_OK)
        self.assertIn("WHY THIS PROJECT EXISTS", res.stdout)
        self.assertIn("5 REAL-WORLD ARCHITECTURAL VERIFICATION SCENARIOS", res.stdout)

    def test_scen_87_to_91_verify_all_5_scenarios(self):
        """Scenarios 87..91: 'krayctl verify <1..5>' validates each real-world I/O & kernel scenario."""
        scenarios = [
            ("1", "VERIFICATION SCENARIO 1"),
            ("2", "VERIFICATION SCENARIO 2"),
            ("3", "VERIFICATION SCENARIO 3"),
            ("4", "VERIFICATION SCENARIO 4"),
            ("5", "VERIFICATION SCENARIO 5"),
        ]
        for scen_arg, expected_header in scenarios:
            with self.subTest(scenario=scen_arg):
                res = run_local(f"verify {scen_arg}")
                self.assertEqual(res.returncode, EX_OK)
                self.assertIn(expected_header, res.stdout)

    # --------------------------------------------------------------------------
    # GROUP 10: Idempotency, Failure Recovery, Isolation, Sync & Doc Consistency
    #           (Scenarios 92..105 — 14 Scenarios)
    # --------------------------------------------------------------------------

    def test_scen_92_to_97_all_remaining_subcommand_help_parity(self):
        """Scenarios 92..97: Help flags & 'help <cmd>' for chaos, dashboard, inspect, uninstall, sync, build."""
        cmds = ["chaos", "dashboard", "inspect", "uninstall", "sync", "build"]
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                res_flag = run_local(f"{cmd} -h")
                self.assertEqual(res_flag.returncode, EX_OK)
                self.assertIn("Usage:", res_flag.stdout)
                res_help = run_local(f"help {cmd}")
                self.assertEqual(res_help.returncode, EX_OK)
                self.assertIn("Usage:", res_help.stdout)

    def test_scen_98_idempotency_install_and_uninstall(self):
        """Scenario 98: Repeated install and uninstall calls are 100% idempotent and exit 0."""
        # 1. Double uninstall (even when already absent)
        u1 = run_local("uninstall --user")
        u2 = run_local("uninstall --user")
        self.assertEqual(u1.returncode, EX_OK)
        self.assertEqual(u2.returncode, EX_OK)
        # 2. Double install (replaces symlink cleanly without error)
        i1 = run_local("install --user")
        i2 = run_local("install --user")
        self.assertEqual(i1.returncode, EX_OK)
        self.assertEqual(i2.returncode, EX_OK)

    def test_scen_99_idempotency_sync_and_artifact_preservation(self):
        """Scenario 99: Repeated 'krayctl sync' is idempotent and preserves remote compiled binaries."""
        s1 = run_local("sync")
        s2 = run_local("sync")
        self.assertEqual(s1.returncode, EX_OK)
        self.assertEqual(s2.returncode, EX_OK)
        # Verify remote compiled artifacts were not deleted by rsync --delete
        chk = run_remote_action("check-artifacts")
        self.assertEqual(chk.returncode, EX_OK, "Remote compiled binaries must survive krayctl sync")

    def test_scen_100_failure_recovery_sigkill_orphan_xdp_guardian(self):
        """Scenario 100: SIGKILL crash during XDP attachment on 'lo' is auto-recovered on next run."""
        res = run_remote_action("test-sigkill-recovery")
        self.assertIn("Attached XDP ingress filter", res.stdout)
        self.assertIn("All BPF programs safely detached", res.stdout)

    def test_scen_101_failure_recovery_invalid_interface_graceful_fallback(self):
        """Scenario 101: Non-existent network interface (-i nonexistent_nic0) warns on stderr & recovers."""
        res = run_remote_action("test-invalid-nic")
        self.assertIn("WARNING: Interface 'nonexistent_nic0' not found", res.stdout)
        self.assertIn("Listening for requests", res.stdout)

    def test_scen_102_failure_recovery_verify_invalid_then_valid(self):
        """Scenario 102: Invalid 'krayctl verify bad_arg' exits 2 on stderr, next valid call exits 0."""
        bad = run_local("verify invalid_scenario_name")
        self.assertEqual(bad.returncode, EX_CLI_INVALID_CMD)
        self.assertEqual(len(bad.stdout.strip()), 0)
        self.assertIn("Error: Unknown verification scenario", bad.stderr)
        good = run_local("verify 1")
        self.assertEqual(good.returncode, EX_OK)
        self.assertIn("VERIFICATION SCENARIO 1", good.stdout)

    def test_scen_103_isolation_selftest_individual_layers(self):
        """Scenario 103: Layer-isolated selftests (l2, l4, l6) run independently without cross-layer interference."""
        for layer in ["l2", "l4", "l6"]:
            with self.subTest(layer=layer):
                res = run_local(f"selftest {layer}")
                self.assertEqual(res.returncode, EX_OK)
                self.assertIn("1/1 PASSED", res.stdout)

    def test_scen_104_isolation_live_json_stream_purity(self):
        """Scenario 104: Live 'tracer_daemon -j' outputs 100% pure JSON Lines on stdout with 0 banner pollution."""
        res = run_remote_action("test-json-purity")
        lines = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        self.assertGreater(len(lines), 0, "Expected at least one JSON telemetry event on stdout")
        for line in lines:
            self.assertTrue(line.startswith("{") and line.endswith("}"), f"Non-JSON line on stdout: {line}")
            self.assertIn('"req_id":', line)

    def test_scen_105_documentation_consistency_and_clickable_links(self):
        """Scenario 105: Verify unified README.md contains all 10 Books, kernel source links, and valid file:// links."""
        import re
        doc_path = ROOT_DIR / "README.md"
        self.assertTrue(doc_path.exists(), "Missing unified master document: README.md")
        content = doc_path.read_text(encoding="utf-8")
        # 1. Verify all 10 consolidated Books and 5 verification scenarios exist in unified README.md
        for required_token in [
            "[Book I]", "[Book II]", "[Book III]", "[Book IV]", "[Book V]",
            "[Book VI]", "[Book VII]", "[Book VIII]", "[Book IX]", "[Book X]",
            "krayctl verify 1", "krayctl verify 5", "sk_rcvbuf",
            "kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm",
            "Apple Virtualization.framework", "utmctl start", "Rocky-9.8-aarch64-minimal.iso",
        ]:
            self.assertIn(required_token, content, f"README.md missing required token: {required_token}")
        # 2. Verify no fragmented root .md files remain outside README.md
        root_mds = [p.name for p in ROOT_DIR.glob("*.md")]
        self.assertEqual(root_mds, ["README.md"], f"Expected only README.md in root, found: {root_mds}")
        # 3. Verify every clickable file:// link resolves to an existing path on disk and valid #L line bounds
        link_pattern = re.compile(r"\]\(file://(/[^)#]+)(?:#L(\d+)(?:-L(\d+))?)?\)")
        for match in link_pattern.finditer(content):
            target_file = Path(match.group(1))
            self.assertTrue(
                target_file.exists(),
                f"Broken clickable file:// link in README.md: {target_file}"
            )
            if target_file.is_file() and match.group(2):
                total_lines = len(target_file.read_text(encoding="utf-8", errors="replace").splitlines())
                start_l = int(match.group(2))
                end_l = int(match.group(3)) if match.group(3) else start_l
                self.assertLessEqual(
                    end_l,
                    total_lines,
                    f"Out-of-bounds line anchor in README.md: {match.group(0)} (max line {total_lines})"
                )

    def test_scen_106_production_elf_symbol_and_dynsym_auto_resolution(self):
        """Scenario 106: Auto-resolve ELF symbols (-s) from .symtab (C++ mangled) and .dynsym (stripped .so), and reject unknown symbols (EX_DATAERR=65)."""
        res = run_remote_action("test-symbol-resolve")
        self.assertIn("RC1=0", res.stdout)
        self.assertIn("Auto-resolved ELF symbol 'execute_storage_query'", res.stdout)
        self.assertIn("(.symtab)", res.stdout)
        self.assertIn("RC2=0", res.stdout)
        self.assertIn("Auto-resolved ELF symbol 'verify_request_token'", res.stdout)
        self.assertIn("(.dynsym)", res.stdout)
        self.assertIn("RC3=65", res.stdout)
        self.assertIn("not found in .symtab or .dynsym", res.stdout)

    def test_scen_107_production_selective_layer_overhead_isolation(self):
        """Scenario 107: Selective layer filter (-L 4) bypasses attaching high-frequency L6 scheduler/futex kernel hooks."""
        res = run_remote_action("test-selective-layer")
        self.assertIn("RC=0", res.stdout)
        self.assertIn("Selective Layer Isolation (L4): bypassed 6 high-frequency L6 scheduler/futex hooks", res.stdout)

    def test_scen_108_production_fail_safe_bounded_execution_and_verdict(self):
        """Scenario 108..110: Bounded capture (-c 3, -d 4), tail-latency validation (-m), and automated Root-Cause Bottleneck Verdict on exit."""
        res = run_remote_action("test-verdict-and-max-events")
        self.assertIn("RC=0", res.stdout)
        self.assertIn("STDOUT_LINES=3", res.stdout)
        self.assertIn("[PRODUCTION DIAGNOSTIC SUMMARY & BOTTLENECK VERDICT]", res.stdout)
        self.assertIn("[VERDICT] Primary Bottleneck:", res.stdout)
        # Also verify invalid -m / -d / -c flags return EX_USAGE (64)
        bad_m = run_daemon_remote("-m -10")
        self.assertEqual(bad_m.returncode, EX_USAGE)
        bad_d = run_daemon_remote("-d 0")
        self.assertEqual(bad_d.returncode, EX_USAGE)
        bad_c = run_daemon_remote("-c 0")
        self.assertEqual(bad_c.returncode, EX_USAGE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
