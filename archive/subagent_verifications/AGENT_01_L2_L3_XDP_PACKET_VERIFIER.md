# AGENT 01 — Adversarial Falsification Audit: L2/L3 XDP & TC/Netif Packet Parser, Egress Port/SKB-Clone Correlation & Kernel Drop (`kfree_skb`) Verification

## 1. Executive Summary & Adversarial Verification Scope

* **Auditor Role**: Autonomous Adversarial Falsification TDD & Target-Kernel Verification Subagent (`AGENT_01_L2_L3_XDP_PACKET_VERIFIER`)
* **Target Kernel Ground Truth**:
  - **Live Target VM**: `ebpf-tracer-v2.0.0` (`192.168.64.14`, `Rocky Linux 9.8 (Blue Onyx) aarch64`, kernel release `5.14.0-687.10.1.el9_8.0.1.aarch64`)
  - **Kernel Source & BTF Reference**: `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`
* **Overall Falsification Verdict**:
  - **7 critical specification, kernel C code, and false-positive test harness defects** were uncovered across the L2/L3/L4 packet parsers (`xdp_ingress_filter`, `netif_receive_skb`, `ip_rcv`, `ipv6_rcv`, `tcp_v4_rcv`, `tcp_v6_rcv`), Egress correlation (`__tcp_transmit_skb`, `ip_output`, `ip6_output`, `net_dev_queue`, `net_dev_xmit`, `udp_sendmsg`), and the 3-stage `kfree_skb` drop tracker.

## 2. Detailed Summary of the 7 Falsified Defects

* **Defect #1 (CRITICAL — Egress SKB Clone Blind Spot & Tautological Test Harness Cheat)**:
  - In `net/ipv4/tcp_output.c:1258-1268`, `__tcp_transmit_skb(sk, skb, clone_it, ...)` clones the master `oskb` (`skb = skb_clone(oskb, gfp_mask)`) before calling `ip_queue_xmit` -> `ip_output` -> `net_dev_queue` -> `net_dev_xmit`.
  - `kprobe____tcp_transmit_skb` records the uncloned `oskb` in `skb_egress_map`, while `kprobe__ip_output` receives `cloned_skb != oskb`. Although `kprobe__ip_output` fell back to `PT_REGS_PARM2(ctx)` (`struct sock *sk`), it never inserted `cloned_skb` into `skb_egress_map`, causing 100% of `net_dev_queue` and `net_dev_xmit` (`LAYER_EGRESS_NIC`) events to be dropped on real kernels. `kprobe__ip6_output` also lacked the `PT_REGS_PARM2(ctx)` fallback.
  - Meanwhile, `sim_tcp_egress_pipeline` in `kernel_sim_harness.c` hid this defect by calling `kprobe____tcp_transmit_skb` *after* `kprobe__ip_output` with the same `&skb` pointer.
* **Defect #2 (CRITICAL — 0-Byte TCP Handshake `SYN`/`ACK` Poisoning of `ingress_flow_map`)**:
  - In `xdp_ingress_filter` and `tracepoint__net__netif_receive_skb`, `if (tcp_payload_len == 0)` was only checked inside `if (existing && existing->consumed == 0)`, allowing the initial 0-byte `SYN` (`existing == NULL`) or post-consumption keep-alive `ACK` (`existing->consumed == 1`) to mint an unconsumed `req_id` and block the subsequent real HTTP payload packet.
* **Defect #3 (Software VLAN `802.1Q`/`802.1AD` Blind Spot in `netif_receive_skb`)**:
  - In `net/core/dev.c:5606-5639`, `trace_netif_receive_skb(skb)` executes before `skb_vlan_untag(skb)`. `tracepoint__net__netif_receive_skb` must unroll up to 2 software VLAN headers from `skb->data` when `skb->protocol` is `0x8100` or `0x88A8`.
* **Defect #4 (Unvalidated IPv4 `ihl < 5` & TCP `doff < 5`)**:
  - At `kprobe__ip_rcv` entry (`net/ipv4/ip_input.c:552`), `ip_rcv_core()` has not yet validated `iph->ihl >= 5` or `iph->version == 4`. Explicit checks `ihl_bytes >= 20` and `doff_len >= 20` are required.
* **Defect #5 (IPv6 Extension Headers in `kprobe__ipv6_rcv` & Missing Fallback State in `kprobe__tcp_v6_rcv`)**:
  - `kprobe__ipv6_rcv` must unroll up to 2 RFC 8200 extension headers (`NEXTHDR_HOP`, `NEXTHDR_ROUTING`, `NEXTHDR_FRAGMENT`, `NEXTHDR_DEST`), and `kprobe__tcp_v6_rcv` must initialize a fallback `flow_state_t` when `!state || state->consumed == 1`.
* **Defect #6 (Unconnected UDP Server Egress Blind Spot in `kprobe__udp_sendmsg`)**:
  - Must extract peer IP/port from `msg->msg_name` (`struct sockaddr_in`) or `tctx`, update `egress_flow_map`, and delete `active_ctx_map[&tid]`.
* **Defect #7 (`kfree_skb` Stage 1/2/3 Egress & UDP Drop Blind Spots + `decode_event_metadata` Flag Check)**:
  - Stage 1 (`skb_egress_map`) should emit `LAYER_EGRESS_NIC` and clean up `skb_egress_map`/`egress_flow_map`; Stage 2/3 should support `IPPROTO_UDP` and `egress_flow_map`; `decode_event_metadata` must check `FLAG_SKB_DROP` and `FLAG_TCP_RETRANSMIT` before unpacking `(ttl, ihl_bytes, pkt_len)`.
