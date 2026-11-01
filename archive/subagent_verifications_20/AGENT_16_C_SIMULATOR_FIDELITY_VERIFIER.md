# Agent 16 Adversarial Falsification Report — Domain 16/20: Userspace C Simulation Harness Fidelity (`mock_bpf_runtime.h`, `kernel_sim_harness.c`, Per-CPU Maps, True LRU, Poison Memory)

### 1. Executive Summary of Falsifications

* **Flaw 16.1 — Missing Emulated BPF Helpers & Low-Pointer Fault Protection in `mock_bpf_runtime.h`**:
  * Added `bpf_probe_read`, `bpf_probe_read_user`, `bpf_get_current_comm`, `bpf_get_prandom_u32`, `bpf_ringbuf_reserve`, `bpf_ringbuf_submit`, and `bpf_ringbuf_discard`.
  * Updated `bpf_probe_read_kernel` to return `KRAY_ERR_EFAULT (-14)` and zero-fill `dst` on NULL or near-NULL (`(uintptr_t)unsafe_ptr < 4096ULL`) pointers.
* **Flaw 16.2 — Array Map Out-of-Bounds Error Code (`-E2BIG`), `.delete` Operation, and `0xDD` Delete Poisoning**:
  * Fixed `BPF_ARRAY` and `BPF_PERCPU_ARRAY` out-of-bounds updates to return `KRAY_ERR_E2BIG (-7)` (matching Linux `array_map_update_elem`), added `.delete` returning `KRAY_ERR_EINVAL (-22)`, guarded self-overlapping `memmove`, and poisoned deleted hash/LRU entries with `0xDD`.
* **Flaw 16.3 — Configurable RingBuf Capacity (`sim_set_ringbuf_capacity`) & Drop-Budget (`sim_set_ringbuf_drop_limit`)**:
  * Added `g_sim_ringbuf_cap`, `g_sim_ringbuf_drop_budget`, and reservation tracking so C tests can trigger ringbuf exhaustion and verify `ev->drop_count` recovery in `emit_kray_event`.
* **Flaw 16.4 — Blocking `tcp_recvmsg` Lazy Iter Binding & UDP L3/L2 Egress Simulation**:
  * Extended `sim_tcp_recvmsg_call` (`delayed_packet_arrival == 2`) to exercise lazy `req_id` binding inside `kretprobe__skb_copy_datagram_iter`, updated `kprobe__ip_output` to support `IPPROTO_UDP` egress fallback, and added `sim_udp_egress_pipeline`.
