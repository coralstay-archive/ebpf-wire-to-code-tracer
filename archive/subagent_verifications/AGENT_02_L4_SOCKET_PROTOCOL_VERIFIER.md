# AGENT 02 — Adversarial Falsification Audit: L4 TCP/UDP/UNIX Socket State Transitions & Kernel Struct Offsets

## 1. Executive Summary

Cross-checking `PROMPT_SPEC.md`, `tracer_kernel.c`, `kernel_sim_harness.c`, and `test_verification_suite.py` against the Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) kernel source (`net/ipv4/`, `net/ipv6/`, `net/unix/`) and `vmlinux.h` BTF layout uncovered **5 critical defects**:

* **Defect #1 (Pure IPv6 vs Dual-Stack `LOOPBACK4_IPV6 = 127.0.0.6` Trap)**:
  - `PROMPT_SPEC.md` and `populate_sock_flow_key` assumed `family == AF_INET6 && skc_daddr == 0` identifies pure IPv6 sockets.
  - In Rocky 9.8 kernel `net/ipv6/tcp_ipv6.c:1356` (`tcp_v6_syn_recv_sock`), accepted pure IPv6 TCP sockets have `inet_daddr = inet_rcv_saddr = LOOPBACK4_IPV6` (`cpu_to_be32(0x7f000006)` = `127.0.0.6`). Checking `skc_daddr == 0` misclassifies every real pure IPv6 server socket as IPv4 `127.0.0.6`!
  - Fix: Check `ipv6_is_v4mapped(&v6_rem)` (`addr32[0]==0 && addr32[1]==0 && addr32[2]==htonl(0x0000ffff)`) or `rem_ip4 != bpf_htonl(0x7f000006)`.
* **Defect #2 (Blocking `tcp_recvmsg` Execution Order Inversion on `skb_copy_datagram_iter`)**:
  - In `net/ipv4/tcp.c:2638-2679` (`tcp_recvmsg_locked`), `skb_copy_datagram_iter` executes **before** `tcp_recvmsg` returns (`kretprobe__tcp_recvmsg`).
  - When a thread blocks in `sk_wait_data()`, `tctx->req_id` is still `0` when `kprobe__skb_copy_datagram_iter` / `kretprobe__skb_copy_datagram_iter` runs, causing 100% of `OSI_L5_SYSCALL_MEM` copy events to be dropped.
  - Fix: Perform lazy `req_id` binding from `tctx->active_sk_ptr` inside `kprobe__skb_copy_datagram_iter`.
* **Defect #3 (UDP Connected vs Unconnected 4-Tuple & Egress Correlation Breakage)**:
  - `kretprobe__udp_recvmsg` left `key.daddr == 0`, failed on connected UDP (`msg_name == NULL`), and did not populate `tctx` peer fields or `publish_handoff_slot`. `kprobe__udp_sendmsg` did not read `msg->msg_name` or clean up `active_ctx_map`.
* **Defect #4 (`AF_UNIX` `unix_stream_recvmsg` / `unix_stream_sendmsg` One-Way Breakage)**:
  - `kprobe__unix_stream_recvmsg` did not bind `req_id` into `active_ctx_map[&tid]` or publish handoff, and `kprobe__unix_stream_sendmsg` always minted a new random `req_id` instead of propagating `tctx->req_id`.
* **Defect #5 (`get_target_pid()` Dead Helper)**:
  - `get_target_pid()` was defined in `tracer_kernel.c` but never called.
