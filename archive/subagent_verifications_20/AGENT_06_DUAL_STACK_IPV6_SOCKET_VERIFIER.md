# Adversarial Falsification Report — Domain 06/20: L4 Dual-Stack Normalization & IPv6 Sockets (`AF_INET6`, `::ffff:x.x.x.x`, `IPV6_V6ONLY`, `tcp_v6_syn_recv_sock`, `populate_sock_flow_key`)

### Executive Summary of Falsified Claims & Architectural Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against Rocky Linux 9.8 kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64` in [`references/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8)) falsified core assumptions regarding dual-stack socket flow correlation:

* **Falsification 1 — IPv4-Mapped IPv6 Asymmetric Normalization in `populate_sock_flow_key`**:
  * In Linux kernel `net/ipv6/tcp_ipv6.c:1356`, when a dual-stack socket receives an IPv4 connection, `tcp_v6_syn_recv_sock` initializes the child socket with `skc_family = AF_INET6`, but `skc_v6_daddr` is set to `::ffff:1.2.3.4` (`in6_u.u6_addr32[2] = bpf_htonl(0x0000ffff)` and `in6_u.u6_addr32[3] = ipv4_daddr`).
  * In `tracer_kernel.c:populate_sock_flow_key`, the socket family is checked. If `rem_ip4 != 0` is present, it directly treats it as IPv4. However, if the socket was created via `bind(::)` without `IPV6_V6ONLY`, the local address `skc_v6_rcv_saddr` might be `::` (all zeros) or `::ffff:127.0.0.1`.
  * If `rem_v4_mapped` is true but `loc_v4_mapped` is false (e.g., listening on wildcard `::`), the previous key calculation left `key->daddr = 0` or failed to extract the IPv4 address from the mapped representation, leading to lookup mismatch against wire packets arriving on `netif_receive_skb` which are parsed as pure `AF_INET` (`127.0.0.1`).
* **Falsification 2 — `LOOPBACK4_IPV6` Synthetic Constant Collision**:
  * In Rocky Linux 9.8 `net/ipv6/tcp_ipv6.c:1356`, `LOOPBACK4_IPV6` (`bpf_htonl(0x7f000006)`) is used internally by the kernel for loopback routing acceleration in IPv6 child sockets.
  * In `tracer_kernel.c:populate_sock_flow_key`, reading `skc_rcv_saddr` directly on an `AF_INET6` socket without checking `skc_family` or mapped state can read `0x7f000006` instead of the actual IPv4 loopback address `127.0.0.1` (`0x7f000001`), corrupting the 4-tuple hash key.
* **Falsification 3 — UDP Dual-Stack Recvmsg Flow Association**:
  * In `tracer_kernel.c`, while TCP sockets have `skc_family` and `skc_num` populated, unconnected UDP sockets using `recvfrom()` or `recvmmsg()` on dual-stack wildcards do not set `skc_daddr` prior to reception.
  * Attempting to populate `egress_key` or `ingress_key` from `sock` in `udp_recvmsg` without reading `struct sockaddr_in6` from `struct msghdr` results in all-zero remote IP, breaking causality correlation.

### Root Cause Analysis & Line Citations

* [`tracer_kernel.c:290-340`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L290-L340):
  * `populate_sock_flow_key` handles `AF_INET` and `AF_INET6`.
  * For `AF_INET6`, it checks `ipv6_addr_is_v4_mapped(&rem6)` and `ipv6_addr_is_v4_mapped(&loc6)`.
  * If either is mapped or if `rem_ip4 != 0`, it normalizes to `AF_INET` and sets `key->family = AF_INET`.
  * However, when `rem_v4_mapped` is detected, `key->saddr = is_egress ? eff_loc4 : eff_rem4` must be strictly validated so that `eff_rem4` is taken from `rem6[3]` when `rem_ip4 == 0`.
* [`kernel_sim_harness.c:980-1025`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L980-L1025):
  * `sim_dual_stack_mapped_sock_key_test` and `sim_pure_ipv6_loopback4_sock_key_test` verify this behavior in unit testing.
  * Tested whether `skc_rcv_saddr = bpf_htonl(0x7f000006)` (Rocky 9.8 `LOOPBACK4_IPV6`) gets normalized properly to `AF_INET6` for pure IPv6, while mapped `::ffff:127.0.0.1` correctly normalizes to `AF_INET`.

### Verification & Remediation Invariants

1. Dual-Stack Normalization Invariant: Any socket connection terminating on an IPv4-mapped IPv6 address (`::ffff:x.x.x.x`) MUST produce a `flow_key_t` with `family = AF_INET`, `saddr = client_ipv4`, and `daddr = server_ipv4`.
2. Pure IPv6 Invariant: Sockets using native IPv6 addresses MUST preserve `family = AF_INET6` and store the 32-bit FNV-1a hash of the 128-bit IPv6 addresses in `saddr` and `daddr`.
3. Loopback4 Guard Invariant: In `AF_INET6` mode, `skc_rcv_saddr` containing `0x7f000006` MUST NOT override the 128-bit address `skc_v6_rcv_saddr` unless the 128-bit address is verified to be `::ffff:127.0.0.6`.
