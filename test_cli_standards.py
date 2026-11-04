#!/usr/bin/env python3
"""
================================================================================
test_cli_standards.py — Michael Kerrisk TLPI & POSIX CLI Standards Verification
================================================================================
Authoritative References:
  - Michael Kerrisk, "The Linux Programming Interface", Chapter 56, 63, Appendix B
  - POSIX IEEE Std 1003.1-2017 Utility Guidelines 1..13
  - BSD <sysexits.h> Process Status Standards (EX_OK, EX_USAGE, EX_NOPERM)
  - Specification Document: [cli-argument-standards-and-conventions.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
Target Architecture: Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64)
================================================================================
"""

import shlex
import subprocess
import unittest
import sys
import os

EX_OK = 0
EX_USAGE = 64
EX_UNAVAILABLE = 69
EX_SOFTWARE = 70
EX_OSERR = 71
EX_NOPERM = 77

SSH_TARGET = os.getenv("KRAY_HOST", "ebpf-vm")
REMOTE_DIR = os.getenv("KRAY_DIR", "ebpf-wire-to-code-tracer")


def run_daemon_remote(args_str: str) -> subprocess.CompletedProcess:
    """Execute tracer_daemon on remote target VM without a shell and capture stdout/stderr."""
    remote_bin = f"{REMOTE_DIR}/tracer_daemon"
    cmd = ["ssh", "-q", "-o", "LogLevel=QUIET", SSH_TARGET, remote_bin, *shlex.split(args_str)]
    res = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Filter any SSH transport warnings if present
    clean_stderr = "\n".join(
        line for line in res.stderr.splitlines()
        if not line.startswith("**") and "post-quantum" not in line and "openssh.com" not in line
    ).strip()
    res.stderr = clean_stderr
    return res


class TestCliStandards(unittest.TestCase):
    """Test suite validating Michael Kerrisk TLPI CLI Standards."""

    def test_01_help_synopsis_stdout_and_ex_ok(self):
        """Verify -h and --help print to stdout, produce 0 bytes on stderr, and return EX_OK (0)."""
        for flag in ["-h", "--help"]:
            res = run_daemon_remote(flag)
            self.assertEqual(res.returncode, EX_OK, f"Expected EX_OK (0) for {flag}, got {res.returncode}")
            self.assertIn("Usage:", res.stdout, f"{flag} stdout must contain usage synopsis")
            self.assertIn("Options:", res.stdout, f"{flag} stdout must contain options documentation")
            self.assertEqual(len(res.stderr.strip()), 0, f"{flag} stderr must be empty, got: {res.stderr}")

    def test_02_version_stdout_and_ex_ok(self):
        """Verify -V and --version print to stdout and return EX_OK (0)."""
        for flag in ["-V", "--version"]:
            res = run_daemon_remote(flag)
            self.assertEqual(res.returncode, EX_OK, f"Expected EX_OK (0) for {flag}, got {res.returncode}")
            self.assertIn("tracer_daemon v", res.stdout, f"{flag} stdout must contain version string")
            self.assertEqual(len(res.stderr.strip()), 0, f"{flag} stderr must be empty, got: {res.stderr}")

    def test_03_missing_required_arguments_ex_usage(self):
        """Verify options requiring arguments return EX_USAGE (64) when missing."""
        flags_requiring_args = ["-p", "-t", "-L", "-i", "-b", "-o"]
        for flag in flags_requiring_args:
            res = run_daemon_remote(flag)
            self.assertEqual(res.returncode, EX_USAGE, f"Expected EX_USAGE (64) for missing arg on {flag}, got {res.returncode}")
            self.assertIn("requires an argument", res.stderr, f"Missing argument error must be printed on stderr for {flag}")
            self.assertEqual(len(res.stdout.strip()), 0, f"stdout must be empty on missing argument error for {flag}")

    def test_04_unrecognized_options_ex_usage(self):
        """Verify unrecognized flags return EX_USAGE (64) and print error to stderr."""
        invalid_flags = ["-z", "-X", "--non-existent-option", "-9"]
        for flag in invalid_flags:
            res = run_daemon_remote(flag)
            self.assertEqual(res.returncode, EX_USAGE, f"Expected EX_USAGE (64) for invalid flag {flag}, got {res.returncode}")
            self.assertIn("unrecognized option", res.stderr, f"Unrecognized option error must be printed on stderr for {flag}")
            self.assertEqual(len(res.stdout.strip()), 0, f"stdout must be empty on unrecognized option error for {flag}")

    def test_05_out_of_range_port_values_ex_usage(self):
        """Verify out-of-range ports return EX_USAGE (64)."""
        for bad_port in ["-1", "65536", "99999", "abc"]:
            res = run_daemon_remote(f"-p {bad_port}")
            self.assertEqual(res.returncode, EX_USAGE, f"Expected EX_USAGE for port {bad_port}, got {res.returncode}")
            self.assertIn("invalid port value", res.stderr)
            self.assertEqual(len(res.stdout.strip()), 0)

    def test_06_out_of_range_layer_values_ex_usage(self):
        """Verify out-of-range layers return EX_USAGE (64)."""
        for bad_layer in ["0", "1", "8", "99", "invalid"]:
            res = run_daemon_remote(f"-L {bad_layer}")
            self.assertEqual(res.returncode, EX_USAGE, f"Expected EX_USAGE for layer {bad_layer}, got {res.returncode}")
            self.assertIn("invalid layer", res.stderr)
            self.assertEqual(len(res.stdout.strip()), 0)

    def test_07_valid_layer_names_parse_cleanly(self):
        """Verify named layers (l2, xdp, l3, ip, l4, tcp, l5, socket, l6, sched, l7, uprobe) parse cleanly."""
        for layer_name in ["l2", "xdp", "l3", "ip", "l4", "tcp", "l5", "socket", "l6", "sched", "l7", "uprobe"]:
            res = run_daemon_remote(f"-L {layer_name}")
            # Non-root user should advance to preflight check and return EX_NOPERM (77)
            self.assertEqual(res.returncode, EX_NOPERM, f"Layer {layer_name} should parse cleanly and fail at preflight (EX_NOPERM)")

    def test_08_option_clustering_and_stream_separation(self):
        """Verify short option clustering (-jv) and absolute stream separation."""
        res = run_daemon_remote("-jv")
        # Should cluster -j (json) and -v (verbose) and reach preflight privilege check -> EX_NOPERM (77)
        self.assertEqual(res.returncode, EX_NOPERM)
        # JSON error must be on stderr, stdout must have 0 bytes
        self.assertEqual(len(res.stdout.strip()), 0, f"stdout must have zero bytes, got: {res.stdout}")
        self.assertIn('"error":"EPERM"', res.stderr, "stderr must contain structured JSON error")

    def test_09_end_of_options_delimiter(self):
        """Verify '--' terminates option processing and treats subsequent arguments as operands."""
        # '-- -p' means -p is an operand, not a flag missing an argument
        res = run_daemon_remote("-- -p")
        # Should not fail with EX_USAGE for missing argument; advances to preflight -> EX_NOPERM
        self.assertEqual(res.returncode, EX_NOPERM, f"Expected EX_NOPERM when -p is preceded by '--', got {res.returncode}")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCliStandards)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
