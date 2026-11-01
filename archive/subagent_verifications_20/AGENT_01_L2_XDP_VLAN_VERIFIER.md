# Agent 01 Adversarial Falsification Report — Domain 01/20: L2 XDP & Ethernet Frame Parsing (802.1Q/802.1AD QinQ VLAN, Truncated Frames, Non-IP EtherTypes)

### 1. Executive Summary of Falsifications

* **Finding 1.1 [CRITICAL] — Missing `h_proto != ETH_P_IP_HOST` Guard After VLAN Unrolling in `TRACEPOINT_PROBE(net, netif_receive_skb)`**:
  * In [`tracer_kernel.c:548-565`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L548-L565), `h_proto` was initialized from `skb->protocol` and updated inside the 2-tag VLAN unroll loop, **but `if (h_proto != ETH_P_IP_HOST) return 0;` was missing after the loop**! Any non-IPv4 frame (ARP `0x0806`, LLDP `0x88CC`, MPLS `0x8847`, or triple-tagged VLAN) whose payload bytes at `nh_ptr` happened to have `(byte[0] & 0x0f) == 4` and `byte[9] == 6` falsely minted a `req_id` in `ingress_flow_map`.
* **Finding 1.2 [HIGH] — Missing `iph->version == 4` in `xdp_ingress_filter`, Missing `doff_len < sizeof(struct tcphdr)` in `netif_receive_skb`, and Unchecked `iph->tot_len` vs. Physical Buffer Length**:
  * In [`xdp_ingress_filter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L452-L481), `iph->version == 4` and `(u64)tot_len <= (u64)((long)data_end - (long)iph)` must be verified so spoofed `tot_len` on truncated frames never bypasses the 0-byte payload filter.
  * In [`TRACEPOINT_PROBE(net, netif_receive_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L586-L590), `if (doff_len < sizeof(struct tcphdr)) return 0;` and `if (args->len < pulled_vlan_bytes + (u32)tot_len) return 0;` must be enforced.
* **Finding 1.3 [HIGH] — Shared `parse_eth_vlan_cursor` Helper, Legacy QinQ `0x9100` (`ETH_P_QINQ1`), and Hardware VLAN Offload (`skb->vlan_tci`)**:
  * Added `ETH_P_QINQ1_HOST` (`0x9100`), factored out `parse_eth_vlan_cursor()`, and read `skb->vlan_tci & 0x0FFF` in `netif_receive_skb` when hardware VLAN RX stripping is active.
* **Finding 1.4 [MEDIUM] — `decode_event_metadata` `vlan_id` vs. `rc` Bit-Packing Collision on `LAYER_INGRESS_NIC`**:
  * In [`tracer_agent.py:224-235`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L224-L235), `LAYER_INGRESS_NIC` packs `vlan_id` in `ev->ip` bits `[27:16]`, so `result["rc"]` must be `0` on ingress events instead of reporting `vlan_id` as `rc`.
