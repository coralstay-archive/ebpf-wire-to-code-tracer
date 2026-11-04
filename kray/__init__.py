"""
kray — Modular Python Control Plane for eBPF Wire-to-Code Tracer.
Zero shell-script (.sh) dependency; executes native OS processes via execve (shell=False).
"""

import os
import sys
from pathlib import Path

VERSION = "2.0.0"
TARGET_HOST = os.getenv("KRAY_HOST", os.getenv("VM_HOST", "ebpf-vm"))
REMOTE_DIR = os.getenv("KRAY_DIR", os.getenv("VM_DIR", "ebpf-wire-to-code-tracer"))
LOCAL_DIR = Path(__file__).resolve().parent.parent

# Standardized Exit Status Codes (BSD <sysexits.h> & POSIX)
EX_OK = 0
EX_CLI_INVALID_CMD = 2
EX_USAGE = 64
EX_DATAERR = 65
EX_UNAVAILABLE = 69
EX_SOFTWARE = 70
EX_OSERR = 71
EX_NOPERM = 77

# Terminal ANSI Colors (auto-disabled when stdout is not a TTY or NO_COLOR is set)
USE_COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")
RED = "\033[0;31m" if USE_COLOR else ""
GREEN = "\033[0;32m" if USE_COLOR else ""
BLUE = "\033[0;34m" if USE_COLOR else ""
CYAN = "\033[0;36m" if USE_COLOR else ""
YELLOW = "\033[1;33m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
NC = "\033[0m" if USE_COLOR else ""
