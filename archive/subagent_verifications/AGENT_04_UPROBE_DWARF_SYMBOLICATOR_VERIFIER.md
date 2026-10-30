# AGENT 04 — Adversarial Falsification Audit: Uprobe/Uretprobe Call Stack & 3-Tier DWARF/ELF Symbolicator

## 1. Executive Summary of Falsified Defects

* **Defect 1-A (`bpf_get_func_ip(ctx)` vs `PT_REGS_IP(ctx)` & `uretprobe` Return Address Corruption)**:
  - Verified against Rocky Linux 9.8 `kernel/trace/bpf_trace.c:1050-1063` and `kernel/events/uprobes.c:2155`: `PT_REGS_IP(ctx)` reads `((const struct user_pt_regs *)ctx)->pc` (offset 256 on `arm64`). In `handle_trampoline()`, the kernel overwrites `regs->pc` with `ri->orig_ret_vaddr` before invoking `uretprobe` handlers, so `trace_uprobe_return` must restore `tctx->fn_entry_ip[depth]`.
* **Defect 1-B (Incorrect ELF Section `SEC("kprobe/trace_uprobe_entry")` in `kray_bpf_core_compat.h`)**:
  - `trace_uprobe_entry` and `trace_uprobe_return` were annotated with `SEC("kprobe/...")` and `SEC("kretprobe/...")` instead of `SEC("uprobe")` and `SEC("uretprobe")`, causing `libbpf` autoattach to fail with `-ENOENT`.
* **Defect 2-A & 2-B (`MAX_CALL_DEPTH` Overflow Bitmask Wraparound & Asymmetric Push/Pop Desynchronization in `tracer_kernel.c`)**:
  - `trace_uprobe_entry` computed `u32 depth = tctx->call_depth & (MAX_CALL_DEPTH - 1);` **before** checking `if (tctx->call_depth < MAX_CALL_DEPTH)`, causing recursion at `call_depth >= MAX_CALL_DEPTH` to wrap around (`depth = 0`) and overwrite the root function frame (`fn_entry_ip[0]`, `fn_entry_ts[0]`).
  - Furthermore, `trace_uprobe_entry` only incremented `call_depth` when `< MAX_CALL_DEPTH`, whereas `trace_uprobe_return` unconditionally decremented `call_depth`, shifting all parent return frames upon returning from deep recursion.
* **Defect 3-A (`_discover_stripped_internal_offset()` False Positive Returning `strlen@plt`)**:
  - In `libcrypto_mock.cpp`, `verify_request_token()` calls `std::strlen(token)` before `verify_hmac_signature_internal(token, len)`. Because `_discover_stripped_internal_offset()` did not skip `@plt` / `strlen` targets, it returned the PLT stub offset of `strlen@plt` instead of `verify_hmac_signature_internal`.
* **Defect 3-B & 3-C (Real DWARF `llvm-symbolizer`/`addr2line` and ELF `discover_auto_uprobes()` Integration)**:
  - `BinarySymbolicator` relied on text search over `mock_server.cpp` instead of invoking `llvm-symbolizer` / `addr2line` / `nm` / `readelf` on the compiled ELF binary.
