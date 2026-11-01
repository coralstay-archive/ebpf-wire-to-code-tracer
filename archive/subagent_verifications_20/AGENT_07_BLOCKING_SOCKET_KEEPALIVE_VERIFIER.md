# Adversarial Falsification Report — Domain 07/20: L4 Blocking Sockets & Keep-Alive Filtering (`sk_wait_data`, 0-Byte Probes, TCP Keepalive, Delayed Binding)

### Executive Summary of Falsified Claims & Architectural Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against Rocky Linux 9.8 kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64`) falsified core assumptions regarding blocking sockets and keepalive packet handling:

* **Falsification 1 — Zero-Byte Keepalive Probe False Positives**:
  * TCP keep-alive packets and window probes contain `payload_len == 0` or `1` with ACK flags and sequence numbers set to `rcv_nxt - 1`.
  * If `kprobe__tcp_recvmsg` or `netif_receive_skb` processes these keepalive ACK packets without checking payload length or state changes, it generates false `req_id`s, polluting the trace with synthetic request lifecycles that never correspond to application layer RPCs.
  * In `tracer_kernel.c`, `netif_receive_skb` and `tcp_rcv_established` must strictly ignore 0-byte pure ACKs unless they are part of a valid connection handshake or FIN teardown.
* **Falsification 2 — Delayed Binding in Blocking Sockets (`sk_wait_data`)**:
  * In blocking I/O models, a thread calls `recv()` or `read()` before the network packet arrives at the NIC.
  * In Linux `net/ipv4/tcp.c:2150`, `tcp_recvmsg` enters and sleeps on `sk_wait_data()`.
  * When the packet arrives via NAPI SoftIRQ (`netif_receive_skb` -> `tcp_v4_rcv`), `req_id` is minted at L2/L3 in interrupt context where `current->pid` is the NAPI SoftIRQ kworker (`pid == 0` or idle).
  * If `active_ctx_map` relies on `kprobe__tcp_recvmsg` to bind `req_id` to the calling thread TID, the binding fails because `ingress_flow_map` does not have `req_id` yet at the instant `tcp_recvmsg` entry was hooked.
  * Therefore, `kretprobe__tcp_recvmsg` is REQUIRED to bind `req_id` to the thread upon socket read completion when data has actually been copied into userspace buffers.
* **Falsification 3 — Epoll Wakeup Latency Attribution in Long-Polling / Idle Sockets**:
  * For keepalive/long-polling connections, sockets remain idle inside `epoll_wait` for seconds or minutes.
  * If epoll wait latency is attributed to request processing time, total RTT inflates to 30,000ms+ (the idle timeout).
  * `tracer_kernel.c` and `tracer_agent.py` must isolate idle epoll wait time from active request processing time by tracking `now - epoll_exit_ts` rather than `epoll_enter_ts`.

### Root Cause Analysis & Line Citations

* [`tracer_kernel.c:710-756`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L710-L756):
  * `kprobe__tcp_rcv_established` validates `payload_len == 0`: if `payload_len == 0 && !(tflags & (FLAG_TCP_SYN | FLAG_TCP_FIN | FLAG_TCP_RST))`, packet is filtered out.
* [`tracer_kernel.c:1470-1540`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1470-L1540):
  * `kprobe__tcp_recvmsg` and `kretprobe__tcp_recvmsg`:
  * If `state` is not found at entry (delayed arrival case where thread blocked first), `kretprobe__tcp_recvmsg` checks `ingress_flow_map` at exit when `copied > 0` and binds `state->req_id` to `active_ctx_map[tid]`.
* [`test_verification_suite.py:1370-1378`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1370-L1378):
  * Explicitly tests delayed arrival: `sim_tcp_recvmsg_call` before packet arrival, followed by packet injection and verification that delayed binding succeeds.

### Verification & Remediation Invariants

1. 0-Byte Filter Invariant: Packets with zero TCP payload without SYN/FIN/RST flags MUST NOT create new `flow_state_t` entries or mint `req_id`s.
2. Delayed Binding Invariant: When `tcp_recvmsg` is called prior to packet arrival on the wire, the request ID MUST be resolved and bound to the thread context at `kretprobe__tcp_recvmsg` when bytes are returned (`ret > 0`).
3. Idle Separation Invariant: Epoll wait timeout and idle socket polling MUST NOT be counted towards `total_rtt_ms` or `pre_compute_latency_ns`.
