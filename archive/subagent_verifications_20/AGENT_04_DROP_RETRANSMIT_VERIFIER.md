# Agent 04 Adversarial Falsification Report — Domain 04/20: L3/L4 Packet Drop & TCP Retransmit Forensics (`kfree_skb`, `tcp_retransmit_skb`, Rocky 9.8 Drop Reasons)

### Executive Summary of Falsified Claims

* **Falsification 1 (CRITICAL — Rocky 9.8 `enum skb_drop_reason` Enum Value Shift & Tautological Test)**:
  * [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L139-L151) (`SKB_DROP_REASON_MAP`) and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L862-L870) hardcode obsolete Linux 5.17 drop reason integers (`4 = PKT_TOO_SMALL`, `5 = TCP_CSUM`, `6 = SOCKET_FILTER`, `7 = UDP_CSUM`, `8 = NETFILTER_DROP`, `9 = OTHERHOST`, `10 = IP_CSUM`, `11 = IP_INHDR`, `12 = IP_RPFILTER`).
  * In Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`), [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L23324-L23444) and [`include/net/dropreason-core.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h#L129-L295) insert `SKB_DROP_REASON_SOCKET_CLOSE = 4`, `SKB_DROP_REASON_SOCKET_FILTER = 5`, `SKB_DROP_REASON_SOCKET_RCVBUFF = 6`, and `SKB_DROP_REASON_UNIX_DISCONNECT = 7` immediately after `SKB_DROP_REASON_NO_SOCKET = 3`.
  * Consequently, every kernel drop reason `>= 4` on Rocky 9.8 is misdiagnosed in [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L139-L151) (e.g., `TCP_CSUM = 9` is reported as `OTHERHOST`, `NETFILTER_DROP = 11` is reported as `IP_INHDR`, `PKT_TOO_SMALL = 8` is reported as `NETFILTER_DROP`, `SOCKET_RCVBUFF = 6` is reported as `SOCKET_FILTER`), andreasons `13..116` are missing altogether.
* **Falsification 2 (CRITICAL — `trace_event_raw_kfree_skb` Layout, Ignored `location`/`protocol`, Hardcoded `OSI_L4_TCP`, and Stage 2/3 IPv6/UDP/L2 Blind Spots)**:
  * In Rocky Linux 9.8 [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L117515-L117523) and [`include/trace/events/skb.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24-L52), `struct trace_event_raw_kfree_skb` contains `ent` (8B), `skbaddr` (8B), `location` (8B), `rx_sk` (8B), `protocol` (2B + 2B pad), and `reason` (4B).
  * [`TRACEPOINT_PROBE(skb, kfree_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L794-L870) completely discards `args->location` (the exact kernel instruction pointer where `kfree_skb_reason` was invoked) and `args->protocol`, and hardcodes `call_depth = OSI_L4_TCP (4)` across all three stages (`lines 816, 832, 864`), making L3 IP drops (`OSI_L3_IP = 3`) impossible to emit despite [`decode_event_metadata`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L239-L248) checking `if cdepth in (OSI_L3_IP, OSI_L4_TCP):`.
  * Stage 2 (`rx_sk`) hardcodes `IPPROTO_TCP` and `is_egress = 0`, and Stage 3 (`skb` header parse) only parses IPv4 + TCP (`iph.protocol == IPPROTO_TCP`), completely failing on IPv6 drops, UDP drops, and early L2/L3 drops where `skb->network_header` is unset (`0` or `0xFFFF`).
* **Falsification 3 (HIGH — `tp_kfree_skb` Drop Reason Filtering Rejects Valid `SKB_DROP_REASON_NOT_SPECIFIED == 2` Drops & Leaks `skb_egress_map`)**:
  * In Rocky 9.8 [`net/core/skbuff.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/skbuff.c#L1035-L1052), normal packet consumption (`consume_skb` / `sk_skb_reason_drop(..., SKB_CONSUMED)`) fires `trace_consume_skb`, **never** `trace_kfree_skb`. `trace_kfree_skb` only fires on actual drops (`reason >= SKB_DROP_REASON_NOT_SPECIFIED (2)`).
  * Because [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L801) filters `if (args->reason <= 2) return 0;`, every subsystem/driver/qdisc drop in Rocky 9.8 that calls plain `kfree_skb(skb)` (which passes `SKB_DROP_REASON_NOT_SPECIFIED = 2`, [`include/linux/skbuff.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/ net/core/skbuff.c#L1060-L1068)) is silently discarded! And if an old kernel or mock passes `reason == 0`, it is also discarded instead of falling back to `SKB_DROP_REASON_NOT_SPECIFIED (2)`.
  * Furthermore, Stage 1 in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L808-L819) does not call `skb_egress_map.delete(&skb_ptr)` when an egress `skb` is dropped, leaving a dangling `skb_ptr` entry in `skb_egress_map` that corrupts future packets when the slab recycles that `struct sk_buff` pointer.
* **Falsification 4 (CRITICAL — `tcp_retransmit_skb` Tuple Direction Inversion, Premature `egress_flow_map` Deletion on `net_dev_xmit`, and IPv6 Blind Spot)**:
  * In [`TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L766-L791), `args->saddr` / `args->sport` are always the local socket address/port (`inet->inet_saddr`, `ntohs(inet->inet_sport)` per [`include/trace/events/tcp.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L42-L55)).
  * For a server socket (`sport == target_port`), `ingress_flow_map` was keyed with the wire ingress direction (`saddr = ClientIP, daddr = ServerIP, sport = ClientPort, dport = ServerPort`). Yet [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L772-L779) queries `ingress_flow_map.lookup(&key)` using the un-reversed socket tuple (`sport = ServerPort, dport = ClientPort`), which **always misses** `ingress_flow_map` for server sockets!
  * Worse, [`TRACEPOINT_PROBE(net, net_dev_xmit)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1714-L1715) deletes `egress_flow_map.delete(ekey)` as soon as the **first** transmission leaves the NIC! When the RTO or fast-retransmit timer fires later (`tcp_retransmit_skb`), `egress_flow_map[ekey]` has already been deleted and `ingress_flow_map[key]` has the reversed tuple—meaning **100% of real post-xmit server TCP retransmissions are silently dropped by `tracer_kernel.c`**!
  * Additionally, `tcp_retransmit_skb` hardcodes `key.family = AF_INET` and ignores `args->family`, `args->saddr_v6`, and `args->daddr_v6`.
* **Falsification 5 (CRITICAL — `RequestCorrelator` & `run_tracer_pipeline` Hardcode `retransmits: 0` and `skb_drops: 0`, Mis-sort Egress Drops/Retransmits, and Stall on L3/L4 Drops)**:
  * In [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1596-L1599), `run_tracer_pipeline` hardcodes `"retransmits": 0`, `"skb_drops": 0`, `"input_verdict": "PASS"`, and `"output_verdict": "PASS"` in `ai_diagnosis.json` (`network_layer_diagnostics["layers"]["L4"]`), completely ignoring actual `FLAG_SKB_DROP` and `FLAG_TCP_RETRANSMIT` events in `trace_events`!
  * In [`RequestCorrelator._finalize_request`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L413), events are sorted by `(int(e.layer_type), int(e.timestamp), int(e.is_return))`. Because [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L790-L816) emits `LAYER_KERNEL_NET (2)` even for **egress** retransmissions and **egress** `skb_egress_map` drops, sorting by `layer_type` first teleports egress drops/retransmits (which occurred after `LAYER_USER_EXIT = 5`) backwards in time before `LAYER_USER_ENTRY (3)`!
  * In [`RequestCorrelator.ingest`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L383-L407), an ingress packet dropped at L3/L4 (`FLAG_SKB_DROP`) never reaches `LAYER_USER_EXIT` or `LAYER_EGRESS_NIC`, so `_exit_seen_ts` is never set; the dropped request stalls in `_buffers` for `4 * grace_window_ns` (200ms) and exposes no summary attributes (`dropped`, `drop_reason`, `retransmit_count`) on the completed trace or diagnosis report.

---

### Detailed Falsification Analysis by Mission Area

#### 1. Rocky Linux 9.8 `trace_event_raw_kfree_skb` & `enum skb_drop_reason` Layout vs. Code & Tests

* **Physical Ground Truth in Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`)**:
  * In [`references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L117515-L117523) and [`include/trace/events/skb.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24-L52):
    * Offset `0..7` (8B): `struct trace_entry ent;`
    * Offset `8..15` (8B): `void *skbaddr;`
    * Offset `16..23` (8B): `void *location;` (set to `__builtin_return_address(0)` in [`net/core/skbuff.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/skbuff.c#L1048))
    * Offset `24..31` (8B): `void *rx_sk;`
    * Offset `32..33` (2B): `short unsigned int protocol;` (`ntohs(skb->protocol)`)
    * Offset `34..35` (2B): implicit alignment padding
    * Offset `36..39` (4B): `enum skb_drop_reason reason;`
* **Conflict 1A (`SKB_DROP_REASON_MAP` in `tracer_agent.py` vs. Rocky 9.8 `vmlinux.h`)**:
  * Compare [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L139-L151) against [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L23324-L23444):
    * Value `4`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_SOCKET_CLOSE = 4`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L142) maps `4` to `"SKB_DROP_REASON_PKT_TOO_SMALL"`.
    * Value `5`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_SOCKET_FILTER = 5`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L143) maps `5` to `"SKB_DROP_REASON_TCP_CSUM"`.
    * Value `6`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_SOCKET_RCVBUFF = 6`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L144) maps `6` to `"SKB_DROP_REASON_SOCKET_FILTER"`.
    * Value `7`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_UNIX_DISCONNECT = 7`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L145) maps `7` to `"SKB_DROP_REASON_UDP_CSUM"`.
    * Value `8`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_PKT_TOO_SMALL = 8`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L146) maps `8` to `"SKB_DROP_REASON_NETFILTER_DROP"`.
    * Value `9`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_TCP_CSUM = 9`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L147) maps `9` to `"SKB_DROP_REASON_OTHERHOST"`.
    * Value `10`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_UDP_CSUM = 10`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L148) maps `10` to `"SKB_DROP_REASON_IP_CSUM"`.
    * Value `11`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_NETFILTER_DROP = 11`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L149) maps `11` to `"SKB_DROP_REASON_IP_INHDR"`.
    * Value `12`: Rocky 9.8 `vmlinux.h` is `SKB_DROP_REASON_OTHERHOST = 12`, whereas [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L150) maps `12` to `"SKB_DROP_REASON_IP_RPFILTER"`.
    * Values `13..116` (`IP_CSUM = 13`, `IP_INHDR = 14`, `IP_RPFILTER = 15`, `SOCKET_BACKLOG = 23`, `TCP_FLAGS = 24`, `TCP_ZEROWINDOW = 26`, `TCP_LISTEN_OVERFLOW = 34`, `TCP_INVALID_SEQUENCE = 36`, `TCP_RESET = 38`, `IP_OUTNOROUTES = 47`, `TC_EGRESS = 55`, `QDISC_DROP = 57`, `XDP = 65`, `TC_INGRESS = 66`, `NOMEM = 74`, etc.) are completely absent from [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L139-L151).
* **Conflict 1B (Ignored `args->location` and Hardcoded `OSI_L4_TCP` in `tp_kfree_skb`)**:
  * In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L794-L870), `tp_kfree_skb` only reads `args->skbaddr`, `args->rx_sk`, and `args->reason`, completely ignoring `args->location` and `args->protocol`.
  * Even when a packet is dropped at L3 (`ip_rcv_core`, `ip_rcv_finish`, `ip_output`, or `reason` in `{SKB_DROP_REASON_IP_CSUM (13), SKB_DROP_REASON_IP_INHDR (14), SKB_DROP_REASON_IP_RPFILTER (15), SKB_DROP_REASON_IP_NOPROTO (18), SKB_DROP_REASON_IP_OUTNOROUTES (47), SKB_DROP_REASON_IP_INADDRERRORS (80), SKB_DROP_REASON_IP_INNOROUTES (81)}` or when `istate->tcp_rcv_ts == 0`), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L816) (`lines 816, 832, 864`) hardcodes `call_depth = OSI_L4_TCP (4)`.
  * Moreover, `dur_ns` is hardcoded to `0` (`emit_trace_event(..., 0, ...)` at `lines 813, 829, 861`) instead of computing elapsed time since `istate->xdp_ts` / `istate->ip_rcv_ts` (or packing `(u64)args->location` or elapsed drop latency).
* **Conflict 1C (Stage 2 & Stage 3 IPv6/UDP/Unset-Network-Header Blind Spots in `tp_kfree_skb`)**:
  * In Stage 2 ([`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L820-L835)), `populate_sock_flow_key(rx_sk, &sk_key, IPPROTO_TCP, 0)` hardcodes `IPPROTO_TCP`, failing if `rx_sk` is a UDP socket (`IPPROTO_UDP`).
  * In Stage 3 ([`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L837-L868)), `tp_kfree_skb` only checks `if (head && net_off > 0 && net_off != 0xFFFF)` and `if (iph.protocol == IPPROTO_TCP)` with `ikey.family = AF_INET`. It fails on:
    * Early L2/L3 drops where `skb->network_header == 0` (valid offset `0` when `skb->head == skb->data`!) or `0xFFFF` (where `skb->data` should be used as fallback, as done in `netif_receive_skb` at [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L536-L546)).
    * IPv6 packet drops (`iph.version == 6` / `args->protocol == ETH_P_IPV6_HOST`).
    * UDP packet drops (`iph.protocol == IPPROTO_UDP`, including unconnected server UDP fallback key `{.daddr = 0, .dport = dport, .proto = IPPROTO_UDP}`).

---

#### 2. `tp_kfree_skb` Normal Consumption vs. Drop Reason `<= 2` / `== 0` & Egress Map Leak

* **Physical Ground Truth in Rocky Linux 9.8 [`net/core/skbuff.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/skbuff.c#L1026-L1068)**:
  * In `sk_skb_reason_drop(struct sock *sk, struct sk_buff *skb, enum skb_drop_reason reason)`:
    ```c
    if (reason == SKB_CONSUMED)
        trace_consume_skb(skb, __builtin_return_address(0));
    else
        trace_kfree_skb(skb, __builtin_return_address(0), reason, sk);
    ```
  * And in `kfree_skb(struct sk_buff *skb)`:
    ```c
    kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);
    ```
* **Conflict 2A (`if (args->reason <= 2) return 0;` Drops All `kfree_skb(skb)` Calls with `SKB_DROP_REASON_NOT_SPECIFIED == 2`)**:
  * Normal packet frees invoke `consume_skb(skb)` (`reason == SKB_CONSUMED == 1`), which fires `tracepoint/skb/consume_skb`, **never** `tracepoint/skb/kfree_skb`.
  * When `tracepoint/skb/kfree_skb` fires with `reason == SKB_DROP_REASON_NOT_SPECIFIED (2)`, it is a **real packet drop** via `kfree_skb(skb)` from a kernel path that did not specify a granular `SKB_DROP_REASON_*` enum!
  * Only `reason == SKB_CONSUMED (1)` (if ever passed to `kfree_skb_reason` by mistake, though `sk_skb_reason_drop` routes `1` to `trace_consume_skb`) is a normal consumption. And if `reason == 0` (`SKB_NOT_DROPPED_YET` or legacy/mock callers), `tp_kfree_skb` should normalize `reason = 2` (`SKB_DROP_REASON_NOT_SPECIFIED`) rather than silently dropping the event, or only ignore `args->reason == 1` (`SKB_CONSUMED`).
  * Furthermore, in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L801), `args->reason` is cast/compared as signed in `mock_bpf_runtime.h` (`int reason`); casting `u32 reason = (u32)args->reason; if (reason == 1) return 0; if (reason == 0) reason = 2;` properly handles both `reason == 0` fallback and `SKB_DROP_REASON_NOT_SPECIFIED == 2` while ignoring `SKB_CONSUMED == 1`.
* **Conflict 2B (Dangling `skb_egress_map` Entry on Stage 1 Egress Drop)**:
  * In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L808-L819), when `flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr)` succeeds, `tp_kfree_skb` emits the drop event and returns `0` **without** calling `skb_egress_map.delete(&skb_ptr)`.
  * Because the dropped `skb` will never reach `net_dev_xmit` (where `skb_egress_map.delete(&skb_ptr)` normally happens at [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1715)), that `skb_ptr` remains leaked in `skb_egress_map`!

---

#### 3. `tcp_retransmit_skb` Multiple Firing, Direction Inversion, and Post-`net_dev_xmit` Blind Spot

* **Physical Ground Truth in Rocky Linux 9.8 [`include/trace/events/tcp.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L22-L75) & [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119968-L119981)**:
  * `TRACE_EVENT(tcp_retransmit_skb, ...)` uses `trace_event_raw_tcp_event_sk_skb`.
  * In `TP_fast_assign`:
    * `__entry->sport = ntohs(inet->inet_sport);` (local port)
    * `__entry->dport = ntohs(inet->inet_dport);` (remote port)
    * `*(__be32 *)__entry->saddr = inet->inet_saddr;` (local IPv4)
    * `*(__be32 *)__entry->daddr = inet->inet_daddr;` (remote IPv4)
    * `__entry->family = sk->sk_family;` and `saddr_v6` / `daddr_v6` hold the full IPv6 addresses.
* **Conflict 3A (Direction Inversion When Looking Up `ingress_flow_map` in `tcp_retransmit_skb`)**:
  * In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L770-L783):
    ```c
    flow_key_t key = {};
    key.family = AF_INET;
    __builtin_memcpy(&key.saddr.v4, args->saddr, 4);
    __builtin_memcpy(&key.daddr.v4, args->daddr, 4);
    key.sport = args->sport;
    key.dport = args->dport;
    key.proto = IPPROTO_TCP;

    flow_state_t *state = ingress_flow_map.lookup(&key);
    if (!state) {
        state = egress_flow_map.lookup(&key);
        if (!state) return 0;
    }
    ```
  * On the traced server (`inet_sport == target_port`), `key` built from `args` has `saddr = ServerIP, daddr = ClientIP, sport = ServerPort, dport = ClientPort`.
  * That is the **egress** key orientation (`is_egress = 1` in [`populate_sock_flow_key`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L329-L337))!
  * `ingress_flow_map` is always keyed in the **ingress** wire orientation (`saddr = ClientIP, daddr = ServerIP, sport = ClientPort, dport = ServerPort`, per [`populate_sock_flow_key(..., is_egress=0)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L338-L343) and [`tcp_v4_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L713-L719)).
  * Therefore, `ingress_flow_map.lookup(&key)` in `tcp_retransmit_skb` **never matches a server socket** unless `saddr/daddr` and `sport/dport` are swapped!
* **Conflict 3B (`net_dev_xmit` Deletes `egress_flow_map` Before Any Real Retransmission Can Happen!)**:
  * In [`TRACEPOINT_PROBE(net, net_dev_xmit)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1714-L1715):
    ```c
    egress_flow_map.delete(ekey);
    skb_egress_map.delete(&skb_ptr);
    ```
  * In the Linux TCP stack ([`net/ipv4/tcp_output.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L3203-L3350)), a TCP segment is first transmitted via `__tcp_transmit_skb` -> `ip_output` -> `dev_queue_xmit` -> `net_dev_xmit` (which deletes `egress_flow_map[ekey]`).
  * Only **after** that initial transmission (when the packet is lost on the wire or dropped by the peer and RTO/fast-retransmit triggers) does the kernel call `tcp_retransmit_skb(sk, skb, segs)` -> `trace_tcp_retransmit_skb(sk, skb)`!
  * Because `net_dev_xmit` already deleted `egress_flow_map[ekey]` AND `tcp_retransmit_skb` uses the un-reversed key for `ingress_flow_map.lookup(&key)`, **both lookups fail (`!state`) on every real post-xmit server TCP retransmission**!
  * Even if `tcp_retransmit_skb` checks `egress_flow_map.lookup(&ekey)` first and then falls back to `ingress_flow_map.lookup(&ikey)` (with swapped `saddr/daddr` and `sport/dport`), `ingress_flow_map` is also deleted at [`tcp_recvmsg` exit](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1127). And if `egress_flow_map` is NOT deleted in `net_dev_xmit` (since `tcp_sendmsg` overwrites `egress_flow_map` on the next request and `BPF_MAP_TYPE_LRU_HASH` auto-evicts oldest entries), `egress_flow_map.lookup(&ekey)` remains available for post-`net_dev_xmit` retransmissions and re-populates `skb_egress_map` on retransmit!
* **Conflict 3C (`state->retransmits` Counter Split & Saturating Increment)**:
  * In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L785-L790):
    ```c
    state->retransmits++;
    emit_trace_event(args, LAYER_KERNEL_NET, state->req_id,
                     (u64)state->retransmits, 0, state->pid, state->tid,
                     0, FLAG_TCP_RETRANSMIT, OSI_L4_TCP);
    ```
  * If `tcp_retransmit_skb` fires multiple times for the same `sk`/`skb`, `state->retransmits` increments `1, 2, 3, ...` (saturating guard `if (state->retransmits < 255) state->retransmits++;` is needed to prevent `u8` wrap-around to `0` at 256).
  * Furthermore, in [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), `RequestCorrelator` does not track `retransmit_count` across the emitted `FLAG_TCP_RETRANSMIT` events!

---

#### 4. `RequestCorrelator` & `build_ai_diagnosis_report` (`run_tracer_pipeline`) Blind Spots in `tracer_agent.py`

* **Conflict 4A (`run_tracer_pipeline` Hardcodes `retransmits: 0` and `skb_drops: 0` in `ai_diagnosis.json`)**:
  * In [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1590-L1605):
    ```python
    "L4": {
        "status": "HEALTHY",
        "protocol": "TCP",
        " tcp_v4_rcv_to_sock_queue_ns": l4_ns,
        "socket_backlog_len": 0,
        "receive_buffer_drops": 0,
        "retransmits": 0,
        "skb_drops": 0,
        "input_verdict": "PASS",
        "output_verdict": "PASS",
    },
    ```
  * Even when `trace_events` contains `FLAG_SKB_DROP` (`0x10`) or `FLAG_TCP_RETRANSMIT` (`0x08`) events, `run_tracer_pipeline` (`lines 1500-1710`) and `correlate_and_symbolicate_sim_events` (`lines 714-795`) **never inspect `FLAG_SKB_DROP` or `FLAG_TCP_RETRANSMIT`**!
  * As a result, `ai_diagnosis.json` always reports `"retransmits": 0`, `"skb_drops": 0`, `"status": "HEALTHY"`, and `"input_verdict": "PASS"` even when the packet was dropped in the kernel or retransmitted 5 times!
* **Conflict 4B (`RequestCorrelator._finalize_request` Out-of-Order Sorting of Egress Drops & Retransmits)**:
  * In [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L413):
    ```python
    events_list.sort(key=lambda e: (int(e.layer_type), int(e.timestamp), int(e.is_return)))
    ```
  * When an egress packet is dropped in Stage 1 of `tp_kfree_skb` (`skb_egress_map` match, [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L808-L819)) or retransmitted on egress in `tcp_retransmit_skb` (`egress_flow_map` match, [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L778-L790)), `tracer_kernel.c` emits `layer_type = LAYER_KERNEL_NET (2)`.
  * Because `RequestCorrelator._finalize_request` sorts by `layer_type` before `timestamp`, an egress drop or egress retransmit occurring at `t = 5000ns` (after `LAYER_USER_EXIT = 5` at `t = 4000ns`) is placed at index `layer_type = 2` **before** `LAYER_USER_ENTRY (3)` (`t = 1000ns`)!
* **Conflict 4C (`RequestCorrelator` Drop Stall & Missing Drop/Retransmit Forensics Summary)**:
  * In [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L383-L429), when an ingress packet is dropped at L3/L4 (`FLAG_SKB_DROP`) and never reaches `L2_EGRESS` (`LAYER_EGRESS_NIC` + `OSI_L2_DATALINK`), `_exit_seen_ts` is never recorded on `req_id`.
  * Setting `self._exit_seen_ts[req_id] = int(event.timestamp)` when `int(event.flags) & FLAG_SKB_DROP` is ingested allows `flush_expired` to finalize dropped requests within a single `grace_window_ns` (after any trailing forensic events) instead of stalling for `4 * grace_window_ns`, and `RequestCorrelator` should record per-request drop/retransmit forensic summaries (`request_forensics[req_id]`).

---

### Concrete Diff Recommendations

#### Diff 1: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L766-L870) & [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1705-L1717)

* Fix `tcp_retransmit_skb` to:
  1. Support both IPv4 and IPv6 (`args->family == AF_INET6`).
  2. Look up `egress_flow_map` first (using local `saddr`/`sport` -> remote `daddr`/`dport`), and if not found, look up `ingress_flow_map` using the **reversed** wire tuple (`saddr = args->daddr`, `daddr = args->saddr`, `sport = args->dport`, `dport = args->sport`).
  3. Use saturating increment `if (state->retransmits < 255) state->retransmits++;` and emit `LAYER_EGRESS_NIC` when matched via `egress_flow_map` (or `LAYER_KERNEL_NET` when matched via `ingress_flow_map`).
* Fix `tp_kfree_skb` to:
  1. Normalize `reason`: ignore only `reason == 1` (`SKB_CONSUMED`); if `reason == 0`, fallback to `2` (`SKB_DROP_REASON_NOT_SPECIFIED`).
  2. Determine L3 vs L4 `call_depth` (`OSI_L3_IP` vs `OSI_L4_TCP`) accurately from `reason` / `istate->tcp_rcv_ts` and pass `(u64)args->location` (or elapsed drop latency) in `dur_ns`.
  3. Delete `skb_egress_map.delete(&skb_ptr)` in Stage 1 and emit `LAYER_EGRESS_NIC` for egress drops so chronological sorting in `RequestCorrelator` is preserved.
  4. Support UDP and IPv6 in Stage 2 (`rx_sk`) and Stage 3 (`skb` header parsing), plus fallback to `skb->data` when `network_header` is unset.
* Keep `egress_flow_map` entry in `net_dev_xmit` (relying on LRU eviction / next `tcp_sendmsg` overwrite) so post-xmit TCP retransmissions still find `egress_flow_map`.

```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -766,29 +766,73 @@
 TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
     if (!is_tracer_enabled()) return 0;
 
-    flow_key_t key = {};
-    key.family = AF_INET;
-    __builtin_memcpy(&key.saddr.v4, args->saddr, 4);
-    __builtin_memcpy(&key.daddr.v4, args->daddr, 4);
-    key.sport = args->sport;
-    key.dport = args->dport;
-    key.proto = IPPROTO_TCP;
-
-    flow_state_t *state = ingress_flow_map.lookup(&key);
+    flow_key_t ekey = {};
+    flow_key_t ikey = {};
+    u16 family = args->family ? args->family : AF_INET;
+    ekey.family = (u8)family;
+    ikey.family = (u8)family;
+    if (family == AF_INET6) {
+        __builtin_memcpy(ekey.saddr.v6, args->saddr_v6, 16);
+        __builtin_memcpy(ekey.daddr.v6, args->daddr_v6, 16);
+        __builtin_memcpy(ikey.saddr.v6, args->daddr_v6, 16);
+        __builtin_memcpy(ikey.daddr.v6, args->saddr_v6, 16);
+    } else {
+        __builtin_memcpy(&ekey.saddr.v4, args->saddr, 4);
+        __builtin_memcpy(&ekey.daddr.v4, args->daddr, 4);
+        __builtin_memcpy(&ikey.saddr.v4, args->daddr, 4);
+        __builtin_memcpy(&ikey.daddr.v4, args->saddr, 4);
+    }
+    ekey.sport = args->sport;
+    ekey.dport = args->dport;
+    ekey.proto = IPPROTO_TCP;
+
+    /* Ingress map keys for a local server socket have remote peer as saddr/sport */
+    ikey.sport = args->dport;
+    ikey.dport = args->sport;
+    ikey.proto = IPPROTO_TCP;
+
+    u8 layer = LAYER_EGRESS_NIC;
+    flow_state_t *state = egress_flow_map.lookup(&ekey);
+    if (!state) {
+        /* Fallback: direct key in case tracepoint fired on client-oriented tuple */
+        state = ingress_flow_map.lookup(&ekey);
+        if (state) layer = LAYER_KERNEL_NET;
+    }
     if (!state) {
-        state = egress_flow_map.lookup(&key);
+        state = ingress_flow_map.lookup(&ikey);
         if (!state) return 0;
+        layer = LAYER_KERNEL_NET;
     }
 
     u64 now = bpf_ktime_get_ns();
     if (!check_and_consume_token(now)) return 0;
 
-    state->retransmits++;
-    emit_trace_event(args, LAYER_KERNEL_NET, state->req_id,
+    if (state->retransmits < 255)
+        state->retransmits++;
+    emit_trace_event(args, layer, state->req_id,
                      (u64)state->retransmits, 0, state->pid, state->tid,
                      0, FLAG_TCP_RETRANSMIT, OSI_L4_TCP);
     return 0;
 }
 
+static __always_inline u8 classify_drop_osi_layer(u32 reason, const flow_state_t *st) {
+    if (reason == 13 || reason == 14 || reason == 15 || reason == 17 ||
+        reason == 18 || reason == 47 || reason == 49 ||
+        (reason >= 80 && reason <= 89) || (reason >= 91 && reason <= 96)) {
+        return OSI_L3_IP;
+    }
+    if (st && st->tcp_rcv_ts == 0 && st->ip_rcv_ts != 0)
+        return OSI_L3_IP;
+    return OSI_L4_TCP;
+}
+
 /* =========================================================================
  * 5b. TRACEPOINT: skb:kfree_skb — Packet Drop Forensics
  * ========================================================================= */
 TRACEPOINT_PROBE(skb, kfree_skb) {
     if (!is_tracer_enabled()) return 0;
 
-    /* SKB_DROP_REASON_NOT_SPECIFIED = 2; reasons <= 2 are normal frees */
-    if (args->reason <= 2) return 0;
+    /* SKB_CONSUMED = 1 is normal consumption; reason == 0 falls back to 2 (NOT_SPECIFIED) */
+    u32 reason = (u32)args->reason;
+    if (reason == 1) return 0;
+    if (reason == 0) reason = 2;
 
     struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
     if (!skb) return 0;
@@ -807,14 +851,17 @@
     /* Stage 1: Check egress skb map */
     flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
     if (ekey) {
         flow_state_t *estate = egress_flow_map.lookup(ekey);
         if (estate) {
+            u8 drop_layer = classify_drop_osi_layer(reason, estate);
             if (check_and_consume_token(now)) {
-                emit_trace_event(args, LAYER_KERNEL_NET, estate->req_id,
-                                 (u64)args->reason, 0, estate->pid, estate->tid,
-                                 0, FLAG_SKB_DROP, OSI_L4_TCP);
+                emit_trace_event(args, LAYER_EGRESS_NIC, estate->req_id,
+                                 (u64)reason, (u64)args->location, estate->pid, estate->tid,
+                                 0, FLAG_SKB_DROP, drop_layer);
             }
+            skb_egress_map.delete(&skb_ptr);
             return 0;
         }
+        skb_egress_map.delete(&skb_ptr);
     }
 
     /* Stage 2: Check rx_sk from tracepoint args */
@@ -825,11 +872,16 @@
         populate_sock_flow_key(rx_sk, &sk_key, IPPROTO_TCP, 0);
         flow_state_t *sstate = ingress_flow_map.lookup(&sk_key);
+        if (!sstate) {
+            populate_sock_flow_key(rx_sk, &sk_key, IPPROTO_UDP, 0);
+            sstate = ingress_flow_map.lookup(&sk_key);
+        }
         if (sstate) {
+            u8 drop_layer = classify_drop_osi_layer(reason, sstate);
             if (check_and_consume_token(now)) {
                 emit_trace_event(args, LAYER_KERNEL_NET, sstate->req_id,
-                                 (u64)args->reason, 0, sstate->pid, sstate->tid,
-                                 0, FLAG_SKB_DROP, OSI_L4_TCP);
+                                 (u64)reason, (u64)args->location, sstate->pid, sstate->tid,
+                                 0, FLAG_SKB_DROP, drop_layer);
             }
             return 0;
         }
     }
@@ -860,9 +912,10 @@
                 flow_state_t *istate = ingress_flow_map.lookup(&ikey);
                 if (istate) {
+                    u8 drop_layer = classify_drop_osi_layer(reason, istate);
                     if (check_and_consume_token(now)) {
                         emit_trace_event(args, LAYER_KERNEL_NET, istate->req_id,
-                                         (u64)args->reason, 0, istate->pid, istate->tid,
-                                         0, FLAG_SKB_DROP, OSI_L4_TCP);
+                                         (u64)reason, (u64)args->location, istate->pid, istate->tid,
+                                         0, FLAG_SKB_DROP, drop_layer);
                     }
                 }
             }
```

And in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1713-L1716) (`net_dev_xmit`):
```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -1711,6 +1711,5 @@
             emit_trace_event(args, LAYER_EGRESS_NIC, state->req_id,
                              tx_Bytes, qdisc_lat, state->pid, state->tid, 1, 0, OSI_L2_DATALINK);
         }
-        egress_flow_map.delete(ekey);
     }
     skb_egress_map.delete(&skb_ptr);
     return 0;
```

---

#### Diff 2: [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L139-L151), [`RequestCorrelator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L375-L445), and [`run_tracer_pipeline`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1580-L1620)

* Update `SKB_DROP_REASON_MAP` to match Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L23324-L23444).
* Track per-request `retransmit_count`, `skb_drops`, and `drop_reasons` in `RequestCorrelator` and mark `_exit_seen_ts` when `FLAG_SKB_DROP` arrives so dropped packets do not stall for `4 * grace_window_ns`.
* Populate `retransmits`, `skb_drops`, `input_verdict`, and `output_verdict` dynamically in `run_tracer_pipeline` (`build_ai_diagnosis_report`) instead of hardcoding `0` and `"PASS"`.

```diff
--- a/tracer_agent.py
+++ b/tracer_agent.py
@@ -137,15 +137,39 @@
 # skb_drop_reason enum mapping (Rocky Linux 9.8 / kernel 5.14.0-687.10.1.el9_8.0.1 vmlinux.h)
 SKB_DROP_REASON_MAP: dict[int, str] = {
+    0: "SKB_NOT_DROPPED_YET",
+    1: "SKB_CONSUMED",
     2: "SKB_DROP_REASON_NOT_SPECIFIED",
     3: "SKB_DROP_REASON_NO_SOCKET",
-    4: "SKB_DROP_REASON_PKT_TOO_SMALL",
-    5: "SKB_DROP_REASON_TCP_CSUM",
-    6: "SKB_DROP_REASON_SOCKET_FILTER",
-    7: "SKB_DROP_REASON_UDP_CSUM",
-    8: "SKB_DROP_REASON_NETFILTER_DROP",
-    9: "SKB_DROP_REASON_OTHERHOST",
-    10: "SKB_DROP_REASON_IP_CSUM",
-    11: "SKB_DROP_REASON_IP_INHDR",
-    12: "SKB_DROP_REASON_IP_RPFILTER",
+    4: "SKB_DROP_REASON_SOCKET_CLOSE",
+    5: "SKB_DROP_REASON_SOCKET_FILTER",
+    6: "SKB_DROP_REASON_SOCKET_RCVBUFF",
+    7: "SKB_DROP_REASON_UNIX_DISCONNECT",
+    8: "SKB_DROP_REASON_PKT_TOO_SMALL",
+    9: "SKB_DROP_REASON_TCP_CSUM",
+    10: "SKB_DROP_REASON_UDP_CSUM",
+    11: "SKB_DROP_REASON_NETFILTER_DROP",
+    12: "SKB_DROP_REASON_OTHERHOST",
+    13: "SKB_DROP_REASON_IP_CSUM",
+    14: "SKB_DROP_REASON_IP_INHDR",
+    15: "SKB_DROP_REASON_IP_RPFILTER",
+    18: "SKB_DROP_REASON_IP_NOPROTO",
+    19: "SKB_DROP_REASON_PROTO_MEM",
+    23: "SKB_DROP_REASON_SOCKET_BACKLOG",
+    24: "SKB_DROP_REASON_TCP_FLAGS",
+    25: "SKB_DROP_REASON_TCP_ABORT_ON_DATA",
+    26: "SKB_DROP_REASON_TCP_ZEROWINDOW",
+    34: "SKB_DROP_REASON_TCP_LISTEN_OVERFLOW",
+    36: "SKB_DROP_REASON_TCP_INVALID_SEQUENCE",
+    38: "SKB_DROP_REASON_TCP_RESET",
+    39: "SKB_DROP_REASON_TCP_INVALID_SYN",
+    40: "SKB_DROP_REASON_TCP_CLOSE",
+    47: "SKB_DROP_REASON_IP_OUTNOROUTES",
+    55: "SKB_DROP_REASON_TC_EGRESS",
+    57: "SKB_DROP_REASON_QDISC_DROP",
+    58: "SKB_DROP_REASON_QDISC_OVERLIMIT",
+    59: "SKB_DROP_REASON_QDISC_CONGESTED",
+    64: "SKB_DROP_REASON_CPU_BACKLOG",
+    65: "SKB_DROP_REASON_XDP",
+    66: "SKB_DROP_REASON_TC_INGRESS",
+    74: "SKB_DROP_REASON_NOMEM",
 }
```

And in [`RequestCorrelator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L375-L445):
```diff
--- a/tracer_agent.py
+++ b/tracer_agent.py
@@ -380,6 +380,7 @@
         self._first_seen_ts: dict[int, int] = {}
         self._exit_seen_ts: dict[int, int] = {}
         self.completed_requests: dict[int, list[KrayEvent]] = {}
+        self.request_forensics: dict[int, dict[str, Any]] = {}
 
     def ingest(self, event: KrayEvent) -> Optional[list[KrayEvent]]:
         req_id = int(event.req_id)
@@ -399,6 +400,9 @@
         if int(event.layer_type) == LAYER_USER_EXIT:
             self._exit_seen_ts[req_id] = int(event.timestamp)
 
+        if int(event.flags) & FLAG_SKB_DROP:
+            self._exit_seen_ts.setdefault(req_id, int(event.timestamp))
+
         if int(event.layer_type) == LAYER_EGRESS_NIC and int(event.call_depth) == OSI_L2_DATALINK:
             return self._finalize_request(req_id)
 
@@ -411,6 +415,25 @@
         if not events_list:
             return None
         events_list.sort(key=lambda e: (int(e.layer_type), int(e.timestamp), int(e.is_return)))
+        retransmit_events = [e for e in events_list if int(e.flags) & FLAG_TCP_RETRANSMIT]
+        drop_events = [e for e in events_list if int(e.flags) & FLAG_SKB_DROP]
+        retransmit_count = max(
+            len(retransmit_events),
+            max((int(e.ip) for e in retransmit_events), default=0),
+        )
+        drop_reasons = [
+            SKB_DROP_REASON_MAP.get(int(e.ip), f"SKB_DROP_REASON_{int(e.ip)}")
+            for e in drop_events
+        ]
+        self.request_forensics[req_id] = {
+            "retransmit_count": retransmit_count,
+            "skb_drop_count": len(drop_events),
+            "dropped": len(drop_events) > 0,
+            "drop_reasons": drop_reasons,
+            "drop_locations": [int(e.dur_ns) for e in drop_events if int(e.dur_ns) != 0],
+        }
         self.completed_requests[req_id] = events_list
         return events_list
```

And in [`run_tracer_pipeline`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1580-L1608):
```diff
--- a/tracer_agent.py
+++ b/tracer_agent.py
@@ -1580,22 +1580,35 @@
+        retransmit_hops = [h for h in decoded_hops if int(h.get("flags", 0)) & FLAG_TCP_RETRANSMIT]
+        drop_hops = [h for h in decoded_hops if int(h.get("flags", 0)) & FLAG_SKB_DROP]
+        l3_drop_hops = [h for h in drop_hops if int(h.get("call_depth", 0)) == OSI_L3_IP]
+        l4_drop_hops = [h for h in drop_hops if int(h.get("call_depth", 0)) != OSI_L3_IP]
+        retransmit_count = max(
+            len(retransmit_hops),
+            max((int(h.get("meta", {}).get("retransmit_count", 0)) for h in retransmit_hops), default=0),
+        )
+        skb_drop_count = len(drop_hops)
+        rcvbuf_drops = sum(
+            1 for h in drop_hops
+            if h.get("meta", {}).get("skb_drop_reason") == 6
+        )
         network_layer_diagnostics = {
             "layers": {
                 "L2": {
                     "status": "HEALTHY",
                     "interface": "lo",
                     "xdp_verdict": "XDP_PASS",
                     "tc_ingress_verdict": "TC_ACT_OK",
                     "qdisc_Delay_ns": qdisc_ns,
                     "wire_to_socket_ns": l2_ns,
                 },
                 "L3": {
-                    "status": "HEALTHY",
+                    "status": "DEGRADED" if l3_drop_hops else "HEALTHY",
                     "protocol": "IPv4",
                     "ip_rcv_to_tcp_v4_rcv_ns": l3_ns,
-                    "routing_decision": "LOCAL_DELIVERY",
+                    "routing_decision": "DROPPED" if l3_drop_hops else "LOCAL_DELIVERY",
                 },
                 "L4": {
-                    "status": "HEALTHY",
+                    "status": "DEGRADED" if (l4_drop_hops or retransmit_count > 0) else "HEALTHY",
                     "protocol": "TCP",
                     "tcp_v4_rcv_to_sock_queue_ns": l4_ns,
                     "socket_backlog_len": 0,
-                    "receive_buffer_drops": 0,
-                    "retransmits": 0,
-                    "skb_drops": 0,
-                    "input_verdict": "PASS",
-                    "output_verdict": "PASS",
+                    "receive_buffer_drops": rcvbuf_drops,
+                    "retransmits": retransmit_count,
+                    "skb_drops": skb_drop_count,
+                    "drop_reasons": [
+                        h.get("meta", {}).get("skb_drop_reason_str", "UNKNOWN")
+                        for h in drop_hops
+                    ],
+                    "input_verdict": "DROP" if any(int(h.get("layer_type", 0)) == LAYER_KERNEL_NET for h in drop_hops) else "PASS",
+                    "output_verdict": "DROP" if any(int(h.get("layer_type", 0)) == LAYER_EGRESS_NIC for h in drop_hops) else "PASS",
                 },
             }
         }
```

#### Diff 3: [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L862-L870)

* Fix the tautological test `test_decode_event_metadata_l4_drop_reason` in [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L862-L870) to use Rocky Linux 9.8's actual `vmlinux.h` enum value `9` for `SKB_DROP_REASON_TCP_CSUM` (and verify `5` is `SKB_DROP_REASON_SOCKET_FILTER`):

```diff
--- a/test_verification_suite.py
+++ b/test_verification_suite.py
@@ -862,8 +862,10 @@
     def test_decode_event_metadata_l4_drop_reason(self):
         ev = KrayEvent(
             timestamp=2000, req_id=1, pid=100, tid=100,
-            ip=5, dur_ns=0, layer_type=LAYER_KERNEL_NET,
+            ip=9, dur_ns=0, layer_type=LAYER_KERNEL_NET,
             is_return=0, flags=FLAG_SKB_DROP, call_depth=OSI_L4_TCP,
         )
         meta = decode_event_metadata(ev)
-        self.assertEqual(meta["skb_drop_reason"], 5)
+        self.assertEqual(meta["skb_drop_reason"], 9)
         self.assertEqual(meta["skb_drop_reason_str"], "SKB_DROP_REASON_TCP_CSUM")
```
