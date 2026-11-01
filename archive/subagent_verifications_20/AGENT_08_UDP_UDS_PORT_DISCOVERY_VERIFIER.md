# Agent 08 Adversarial Falsification Report — Domain 08/20: L4 Multi-Protocol Discovery & IPC (`UDP`, `UDS`, `inet_csk_accept`)

### 1. Executive Summary of Falsifications

* **Falsification 1 — UDP Wildcard (`0.0.0.0:9090` / `INADDR_ANY`) 4-Tuple Mismatch & Test Cheat**:
  * On an unconnected UDP server bound to `0.0.0.0:9090`, `sk->__sk_common.skc_rcv_saddr` is `0`, whereas `kprobe__udp_rcv` inserts `key.daddr = iph.daddr` (`127.0.0.1`). Updating both the exact 4-tuple `key` and the wildcard-local key `wild_key` (`wild_key.daddr = 0`) in `kprobe__udp_rcv` and checking `wild_key` in `kretprobe__udp_recvmsg` preserves full client `(saddr, sport, dport)` isolation even when `skc_rcv_saddr == 0`.
* **Falsification 2 — Connected UDP Sockets (`skc_daddr != 0, skc_dport != 0`) & Kernel vs. User `msg_name` Reading**:
  * `kprobe__udp_recvmsg` now reads `skc_daddr` and `skc_dport` so connected UDP sockets (`msg_name == NULL`) correlate cleanly, and `kretprobe__udp_recvmsg` tries `bpf_probe_read_kernel` before `bpf_probe_read_user` on `msg->msg_name`.
* **Falsification 3 — Blocking `unix_stream_recvmsg` Race Condition Across Process A and Process B**:
  * When Process B blocks in `unix_stream_recvmsg` (`unix_stream_data_wait`) *before* Process A calls `unix_stream_sendmsg`, `kprobe__unix_stream_recvmsg` runs when `ingress_flow_map` is empty. Saving `sk` and `peer` in `active_ctx_map` at entry and adding `kretprobe__unix_stream_recvmsg` resolves `req_id` upon wakeup/exit, checks `state->consumed == 0`, reads actual `len` (`PT_REGS_PARM3(ctx)`) in `kprobe__unix_stream_sendmsg`, and calls `publish_handoff_slot()`.
* **Falsification 4 — `kretprobe__inet_csk_accept` & `FLAG_PORT_DISCOVERY` / `PROTO_TCP` / `PROTO_UDP` / `PROTO_UDS`**:
  * Added `kretprobe__inet_csk_accept` to `tracer_kernel.c` and protocol/port discovery metadata decoding in `tracer_agent.py`.
