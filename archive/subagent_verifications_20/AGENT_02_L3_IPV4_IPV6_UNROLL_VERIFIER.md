## Adversarial Falsification Report — Domain 02/20: L2/L3 Ingress SKB & IP Header Unrolling (`netif_receive_skb`, `ip_rcv`, `ipv6_rcv`, IPv4 Options `IHL`, IPv6 Extension Header Chains & Fragmentation)

### Executive Summary of Falsified Claims & Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against the target Rocky Linux 9.8 kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64` in [`references/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8)) falsified **10 distinct assumptions and implementation claims** across three core areas:

* **Area 1 — IPv4 Variable Header Length (`IHL`), Malformed Header Bounds (`ihl < 5`), and Non-First Fragment Guards**:
  * [`kprobe__ip_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L622-L685) fires at `ip_rcv()` entry ([`net/ipv4/ip_input.c:552`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552)) **before** `ip_rcv_core()` validates `iph->ihl < 5 || iph->version != 4` ([`net/ipv4/ip_input.c:488`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L488)). Yet `kprobe__ip_rcv` ([`tracer_kernel.c:646-647`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L646-L647)) and `TRACEPOINT_PROBE(skb, kfree_skb)` ([`tracer_kernel.c:848-849`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L848-L849)) never check `ihl_bytes < 20` or `(iph.version & 0x0f) != 4`!
  * [`kernel_sim_harness.c:284-285`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L284-L285) (`build_ipv4_tcp_buf`) contains a **silent test-masking clamp**: `if (ihl_words < 5) ihl_words = 5;`, making it impossible for simulator tests to expose the missing `ihl < 5` check in `kprobe__ip_rcv` and `kfree_skb`.
  * None of `xdp_ingress_filter`, `tp_netif_receive_skb`, or `kprobe__ip_rcv` check for **non-first IPv4 fragments** (`(bpf_ntohs(iph.frag_off) & 0x1FFF) != 0`), causing raw L7 payload bytes in subsequent fragments to be misinterpreted as `struct tcphdr`.
  * Neither `tp_netif_receive_skb` ([`tracer_kernel.c:588-589`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L588-L589)) nor `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:724-725`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L724-L725)) validates `doff_len >= sizeof(struct tcphdr)` (`20B`), allowing malformed `doff < 5` to inflate `tcp_payload_len > 0` on 0-byte ACKs.
* **Area 2 — IPv6 Extension Header Unrolling (`0`, `43`, `44`, `60`, `51`) & Non-First Fragment Misparse**:
  * [`PROMPT_SPEC.md:202`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L202) and [`PROMPT_SPEC.md:1199`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L1199) falsely specify a fixed `trans_off = net_off + sizeof(struct ipv6hdr)` (`40` bytes), contradicting RFC 8200 and Rocky 9.8 [`net/ipv6/ip6_input.c:230-313`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L230-L313) where `skb->transport_header` is still at the start of the first header after `struct ipv6hdr` upon `ipv6_rcv` entry.
  * In [`kprobe__ipv6_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1749-L1754), when `nexthdr == 44` (IPv6 Fragment Header, RFC 8200 Section 4.5, [`struct frag_hdr` in `include/net/ipv6.h:148-153`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/ipv6.h#L148-L153)), the code reads only the first 2 bytes (`nexthdr` and `reserved`) and advances `trans_off += 8`, **completely ignoring `frag_off` (`__be16` at bytes 2..3)**. When `(bpf_ntohs(frag_off) & 0xFFF8) != 0` (non-first fragment), there is **no L4 TCP/UDP header** after the 8-byte fragment header (matching kernel `ipv6_skip_exthdr` in [`net/ipv6/exthdrs_core.c:98-100`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/exthdrs_core.c#L98-L100): `if (ntohs(*frag_offp) & ~0x7) break;`), yet `kprobe__ipv6_rcv` parses the L7 payload as TCP/UDP ports and overwrites `ingress_flow_map`!
  * [`kprobe__ipv6_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1743-L1764) omits IPsec Authentication Header (`NEXTHDR_AUTH == 51`), whose length per [`include/linux/ipv6.h:11`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/linux/ipv6.h#L11) (`ipv6_authlen(p) = (((p)->hdrlen+2) << 2)`) is `(ext_hdr[1] + 2) * 4` bytes, and caps its unroll loop at `i < 2`, breaking any 3+ extension header chain (e.g., `Hop-by-Hop (0) -> Routing (43) -> Fragment (44)`).
  * [`kprobe__tcp_v6_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1860-L1862) computes `tcp_payload_len = payload_len - doff_len` from `ip6h.payload_len` without subtracting the unrolled IPv6 extension header length `(trans_off - net_off) - sizeof(struct ipv6hdr)`, causing 0-byte IPv6 TCP ACKs carrying extension headers to fake `tcp_payload_len > 0`.
* **Area 3 — L2 (`tp_netif_receive_skb`) ↔ L3 (`kprobe__ip_rcv` / `kprobe__ipv6_rcv`) Correlation Discontinuities**:
  * [`kprobe__ipv6_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1774-L1780) unconditionally calls `ingress_flow_map.update(&key, &state)` with a freshly minted `req_id` without checking `ingress_flow_map.lookup(&key)`, `existing->consumed`, or `tcp_payload_len`, destroying any prior L2 `req_id` and allowing 0-byte IPv6 ACKs to clobber active requests.
  * [`kprobe__ip_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L669-L684) neither checks `state->consumed` nor calculates `tcp_payload_len`. Consequently: (a) a 0-byte ACK arriving after Request #1 was consumed (`state->consumed == 1`) causes `kprobe__ip_rcv` to emit a spurious `STAGE_L3_INGRESS` event carrying Request #1's stale `req_id`, and (b) when a second data request (`tcp_payload_len > 0`) arrives over loopback (`lo`, where XDP may not run) or when `state->consumed == 1`, `kprobe__ip_rcv` emits Request #1's stale `req_id` at L3 while `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:730`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L730)) mints a new `req_id` at L4, fracturing L3↔L4 correlation!
  * [`tp_netif_receive_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L564) and [`xdp_ingress_filter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L449) drop all IPv6 (`ETH_P_IPV6_HOST`) and UDP (`IPPROTO_UDP`) packets, while [`kprobe__ip_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L645) drops all IPv4 UDP packets (`iph.protocol != IPPROTO_TCP`), leaving zero L2->L3 correlation for IPv6 or UDP flows.

---

### Detailed Adversarial Findings & Ground-Truth Proofs

#### Finding 02-01: Missing `ihl < 5` (`ihl_bytes < 20`) and `iph.version != 4` Validation in `kprobe__ip_rcv` and `TRACEPOINT_PROBE(skb, kfree_skb)`

* **Target Kernel Ground Truth**:
  * In Rocky Linux 9.8 [`net/ipv4/ip_input.c:552-563`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552-L563), `ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)` is the top-level `ETH_P_IP` packet handler registered in `ip_packet_type`.
  * `ip_rcv()` invokes `ip_rcv_core(skb, net)` ([`net/ipv4/ip_input.c:449-534`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L449-L534)), which performs IPv4 header validation at line 488:
    ```c
    iph = ip_hdr(skb);
    if (iph->ihl < 5 || iph->version != 4)
        goto inhdr_error;
    ```
    And if invalid, jumps to `inhdr_error:` (`drop_reason = SKB_DROP_REASON_IP_INHDR; goto drop;` -> `kfree_skb_reason(skb, drop_reason)` at line 531).
* **Falsification of `tracer_kernel.c`**:
  * Because `kprobe__ip_rcv` attaches to the **entry** of `ip_rcv`, `ip_rcv_core()` has **not yet run**.
  * Look at [`tracer_kernel.c:643-653`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L643-L653):
    ```c
    struct iphdr iph = {};
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off) < 0) return 0;
    if (iph.protocol != IPPROTO_TCP) return 0;

    u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
    u16 trans_off = net_off + ihl_bytes;
    struct tcphdr tcph = {};
    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off) < 0) return 0;
    ```
  * Compare this with `tp_netif_receive_skb` at [`tracer_kernel.c:566-567`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L566-L567):
    ```c
    u32 ihl_len = (iph.ihl & 0x0f) * 4;
    if (ihl_len < sizeof(struct iphdr)) return 0;
    ```
  * In `kprobe__ip_rcv`, `if (ihl_bytes < sizeof(struct iphdr) || ihl_bytes > 60) return 0;` and `if ((iph.version & 0x0f) != 4) return 0;` are **completely missing**!
  * Furthermore, when `ip_rcv_core()` subsequently drops that malformed `ihl < 5` packet via `kfree_skb_reason(skb, SKB_DROP_REASON_IP_INHDR)`, `TRACEPOINT_PROBE(skb, kfree_skb)` ([`tracer_kernel.c:845-851`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L845-L851)) runs on the exact same malformed `skb` and executes:
    ```c
    u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
    u16 trans_off = net_off + ihl_bytes;
    ```
    Again, without `if (ihl_bytes < sizeof(struct iphdr))`! When `ihl == 0`, `trans_off == net_off`, so `kprobe__ip_rcv` and `kfree_skb` read bytes `0..3` of `struct iphdr` (`version/ihl/tos/tot_len`) as `tcph.source` and `tcph.dest`.

#### Finding 02-02: Silent Test-Masking Clamp in `kernel_sim_harness.c` (`if (ihl_words < 5) ihl_words = 5`) and Hardcoded `sizeof(struct iphdr)` in Simulator

* **Falsification of `kernel_sim_harness.c`**:
  * In [`kernel_sim_harness.c:283-286`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L283-L286), `build_ipv4_tcp_buf` is defined as:
    ```c
    static u32 build_ipv4_tcp_buf(u8 *pkt, size_t cap, u8 ihl_words,
                                  __be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                                  const char *payload, u16 payload_len) {
        if (ihl_words < 5) ihl_words = 5;
        if (ihl_words > 15) ihl_words = 15;
    ```
  * Because `build_ipv4_tcp_buf` silently rewrites any `ihl_words < 5` to `5`, any test attempting to pass `ihl_words = 0` or `ihl_words = 3` into `build_ipv4_tcp_buf` actually tests a valid 20-byte IPv4 header (`ihl = 5`)!
  * Even worse, in [`kernel_sim_harness.c:455`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L455), `sim_tcp_v4_ingress_pipeline` hardcodes `ihl_words = 5`:
    ```c
    u32 pkt_len = build_ipv4_tcp_buf(pkt, sizeof(pkt), 5, saddr, daddr,
                                     bpf_htons(sport_h), bpf_htons(dport_h),
                                     http_payload, payload_len);
    ```
    While `sim_xdp_ipv4_options_test` ([`kernel_sim_harness.c:369-388`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L369-L388)) only runs `xdp_ingress_filter(&xdp)` on `ihl_words`, **never invoking `tp_netif_receive_skb`, `kprobe__ip_rcv`, or `kprobe__tcp_v4_rcv` on packets with `ihl < 5` or `ihl > 5` (e.g., `ihl = 8`, 32-byte IPv4 header with 12B IP options)**!
  * Additionally, [`kernel_sim_harness.c:820`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L820) (`sim_icmp_rcv_test`) and [`kernel_sim_harness.c:847`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L847) (`sim_udp_unconnected_pipeline`) hardcode `u16 trans_off = net_off + sizeof(struct iphdr);` instead of `(iph->ihl & 0x0f) * 4`.

#### Finding 02-03: Missing IPv4 Non-First Fragment Guard (`frag_off & 0x1FFF`) and Missing TCP `doff >= 5` Validation Across Ingress Hooks

* **Target Kernel Ground Truth**:
  * In IPv4 (`struct iphdr` in [`include/uapi/linux/ip.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/linux/ip.h)), `frag_off` is a big-endian 16-bit field where the lower 13 bits (`IP_OFFSET = 0x1FFF`) store the fragment offset in 8-octet units.
  * When `(bpf_ntohs(iph.frag_off) & 0x1FFF) != 0`, the packet is a **non-first IPv4 fragment** arriving prior to `ip_defrag()` (which runs inside `ip_local_deliver()`, *after* `xdp_ingress_filter`, `netif_receive_skb`, and `ip_rcv`). The bytes at `head + net_off + ihl_bytes` are **continuation L7 payload bytes**, not a TCP/UDP header.
* **Falsification of `tracer_kernel.c`**:
  * Neither `xdp_ingress_filter` ([`tracer_kernel.c:452-466`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L452-L466)), `tp_netif_receive_skb` ([`tracer_kernel.c:562-571`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L562-L571)), nor `kprobe__ip_rcv` ([`tracer_kernel.c:643-653`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L643-L653)) checks `if (bpf_ntohs(iph.frag_off) & 0x1FFF) return 0;` (or `XDP_PASS`).
  * Furthermore, in `tp_netif_receive_skb` ([`tracer_kernel.c:588-589`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L588-L589)) and `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:724-725`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L724-L725)) and `kprobe__tcp_v6_rcv` ([`tracer_kernel.c:1860-1861`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1860-L1861)):
    ```c
    u32 doff_len = (tcph.doff & 0x0f) * 4;
    if (tot_len > ihl_len + doff_len) tcp_payload_len = tot_len - ihl_len - doff_len;
    ```
    Unlike `xdp_ingress_filter` ([`tracer_kernel.c:473`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L473): `if (doff_len < sizeof(struct tcphdr)) return XDP_PASS;`), none of the SKB hooks check `if (doff_len < sizeof(struct tcphdr)) return 0;`! If `tcph.doff < 5` (e.g., `doff == 0`), `doff_len == 0` and a 40-byte TCP packet with 0 payload computes `tcp_payload_len = 40 - 20 - 0 = 20 > 0`.

#### Finding 02-04: `PROMPT_SPEC.md` Contradicts RFC 8200 and Rocky 9.8 `ip6_input.c` on IPv6 `trans_off` Calculation

* **Target Kernel Ground Truth**:
  * In Rocky Linux 9.8 [`net/ipv6/ip6_input.c:230-313`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L230-L313), `ipv6_rcv` invokes `ip6_rcv_core`, which sets `skb->transport_header = skb->network_header + sizeof(*hdr);` (i.e., immediately after the 40-byte base IPv6 header, pointing to the **first Extension Header**, not the L4 header!). Extension headers are only traversed later inside `ip6_input_finish()` ([`net/ipv6/ip6_input.c:52-88`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L52-L88)).
* **Falsification of `PROMPT_SPEC.md`**:
  * [`PROMPT_SPEC.md:202`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L202) and [`PROMPT_SPEC.md:1199`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L1199) state:
    > "`ipv6_rcv` 진입 시점에는 `skb->transport_header`가 아직 L4 헤더로 설정되지 않았으므로, 반드시 `net_off + sizeof(struct ipv6hdr)` (`40` 바이트) 오프셋에서 L4 포트(`sport`, `dport`)를 직접 추출하라."
  * This instruction in `PROMPT_SPEC.md` is physically wrong whenever any IPv6 extension header (`0`, `43`, `44`, `51`, `60`) is present, and contradicts Section 3.3 item 7 ([`PROMPT_SPEC.md:280`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L280)) in the same document.

#### Finding 02-05: IPv6 Fragment Header (`nexthdr == 44`) Non-First Fragment L4 Port Misparse in `kprobe__ipv6_rcv`

* **Target Kernel & RFC 8200 Ground Truth**:
  * Per RFC 8200 Section 4.5 and Rocky Linux 9.8 [`include/net/ipv6.h:148-153`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/ipv6.h#L148-L153), the IPv6 Fragment Header is a fixed 8-byte structure:
    ```c
    struct frag_hdr {
        __u8    nexthdr;
        __u8    reserved;
        __be16  frag_off;
        __be32  identification;
    };
    ```
  * Notice two critical facts:
    1. Byte 1 (`reserved`) is initialized to zero by compliant senders, so a naive formula `(ext[1] + 1) * 8` happens to evaluate to `8` when `reserved == 0`, **but fails if `reserved != 0`**. `tracer_kernel.c:1753` rightly uses fixed `+ 8` (`trans_off += 8`).
    2. Bytes 2..3 (`frag_off`) contain the 13-bit Fragment Offset in the upper 13 bits (`0xFFF8`, `#define IP6_OFFSET 0xFFF8` in [`include/net/ipv6.h:35`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/ipv6.h#L35)) and the `M` (More Fragments) flag in bit 0 (`0x0001`).
    3. In Rocky Linux 9.8 [`net/ipv6/exthdrs_core.c:89-101`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/exthdrs_core.c#L89-L101) (`ipv6_skip_exthdr`), when `nexthdr == NEXTHDR_FRAGMENT`:
       ```c
       frag_offp = skb_header_pointer(skb, start + offsetof(struct frag_hdr, frag_off),
                                      sizeof(_frag_off), &_frag_off);
       if (!frag_offp)
           return -1;
       if (ntohs(*frag_offp) & ~0x7)
           break;
       hdrlen = 8;
       ```
       When `(ntohs(frag_off) & 0xFFF8) != 0`, the packet is a **non-first fragment**. Only the first fragment (`frag_off & 0xFFF8 == 0`) contains the L4 TCP/UDP header! Non-first fragments contain raw L4/L7 data immediately at `trans_off + 8`.
* **Falsification of `tracer_kernel.c`**:
  * Look at [`tracer_kernel.c:1749-1754`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1749-L1754):
    ```c
    if (nexthdr == 44) {
        u8 frag_hdr[2] = {};
        if (bpf_probe_read_kernel(frag_hdr, sizeof(frag_hdr), head + trans_off) < 0) return 0;
        nexthdr = frag_hdr[0];
        trans_off += 8;
    }
    ```
  * `kprobe__ipv6_rcv` only reads `u8 frag_hdr[2]` and **never reads `frag_off` at bytes 2..3**!
  * When a non-first IPv6 fragment (`(bpf_ntohs(fhdr.frag_off) & 0xFFF8) != 0`) with `nexthdr == IPPROTO_TCP` arrives at `kprobe__ipv6_rcv`, `kprobe__ipv6_rcv` advances `trans_off += 8` and reads the first 4 bytes of the fragment's data payload as `ports[0]` (`sport`) and `ports[1]` (`dport`), polluting `ingress_flow_map` and emitting bogus L3 events.

#### Finding 02-06: Missing IPv6 `NEXTHDR_AUTH` (`51`), Unroll Depth Truncation at `i < 2`, Hardcoded `40ULL << 16`, and Broken `kprobe__tcp_v6_rcv` Extension-Header `tcp_payload_len`

* **Target Kernel Ground Truth**:
  * In Rocky Linux 9.8 [`net/ipv6/exthdrs_core.c:13-24`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/exthdrs_core.c#L13-L24) (`ipv6_ext_hdr(u8 nexthdr)`), extension headers include `NEXTHDR_HOP (0)`, `NEXTHDR_ROUTING (43)`, `NEXTHDR_FRAGMENT (44)`, `NEXTHDR_AUTH (51)`, `NEXTHDR_NONE (59)`, and `NEXTHDR_DEST (60)`.
  * For `NEXTHDR_AUTH (51)` (RFC 4302 Section 2.2), [`net/ipv6/exthdrs_core.c:102-103`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/exthdrs_core.c#L102-L103) and [`include/linux/ipv6.h:11`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/linux/ipv6.h#L11) define the length in **4-octet units minus 2**:
    ```c
    #define ipv6_authlen(p) (((p)->hdrlen+2) << 2)
    ```
    whereas `0`, `43`, `60` use **8-octet units minus 1**:
    ```c
    #define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
    ```
* **Falsification of `tracer_kernel.c`**:
  1. **Missing `nexthdr == 51` (AH) and `nexthdr == 59` (No Next Header)**: [`tracer_kernel.c:1744`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1744) only checks `nexthdr == 0 || nexthdr == 43 || nexthdr == 44 || nexthdr == 60`. If `nexthdr == 51` is present, the loop exits immediately and `kprobe__ipv6_rcv` drops the packet.
  2. **Loop Depth `i < 2` Truncation**: [`tracer_kernel.c:1743`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1743) uses `for (int i = 0; i < 2; i++)`. Any valid RFC 8200 chain with 3+ headers (such as `Hop-by-Hop (0) -> Routing (43) -> Fragment (44)` or `Hop-by-Hop (0) -> DestOpts (60) -> Routing (43) -> DestOpts (60)`) stops after the 2nd extension header and fails to reach `IPPROTO_TCP` / `IPPROTO_UDP`. Unrolling up to `i < 6` (`#pragma unroll`) is completely safe for the eBPF verifier on kernel 5.14.
  3. **Hardcoded `40ULL << 16` L3 Header Size in `kprobe__ipv6_rcv` and `kprobe__tcp_v6_rcv`**: In [`tracer_kernel.c:1783`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1783) and [`tracer_kernel.c:1882`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1882), `bytes_acked` encodes `(40ULL << 16)` even when extension headers increased the L3 header size to `trans_off - net_off` (e.g., `48` or `56` bytes), causing [`tracer_agent.py:678-680`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L678-L680) (`l3_hdr_bytes = (ev.bytes_acked >> 16) & 0xFF`) to report `40B` instead of the true IPv6 L3 header + extension header length!
  4. **Miscomputed `tcp_payload_len` in `kprobe__tcp_v6_rcv` When Extension Headers Exist**: In [`tracer_kernel.c:1860-1862`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1860-L1862):
     ```c
     u16 payload_len = bpf_ntohs(ip6h.payload_len);
     u16 doff_len = (tcph.doff & 0x0f) * 4;
     u32 tcp_payload_len = (payload_len > doff_len) ? (payload_len - doff_len) : 0;
     ```
     Per RFC 8200 Section 3, `ip6h.payload_len` includes **both** the IPv6 extension headers and the upper-layer PDU (`ext_hdr_len + doff_len + tcp_payload_len`). Because `kprobe__tcp_v6_rcv` does not subtract `ext_hdr_len = (trans_off > net_off + sizeof(struct ipv6hdr)) ? (trans_off - (net_off + sizeof(struct ipv6hdr))) : 0`, any 0-byte IPv6 TCP ACK carrying an 8-byte extension header has `payload_len = 28`, `doff_len = 20`, and computes `tcp_payload_len = 8 > 0`, bypassing the 0-byte ACK filter!

#### Finding 02-07: Correlation Discontinuity Between `tp_netif_receive_skb` (`STAGE_L2_INGRESS`), `kprobe__ip_rcv`/`kprobe__ipv6_rcv` (`STAGE_L3_INGRESS`), and `kprobe__tcp_v4_rcv`/`kprobe__tcp_v6_rcv` (`STAGE_L4_INGRESS`)

* **3A — `kprobe__ipv6_rcv` Blindly Overwrites `ingress_flow_map` on Every Packet (Including 0-Byte ACKs)**:
  * Look at [`tracer_kernel.c:1774-1780`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1774-L1780):
    ```c
    u64 req_id = get_Pseudo_Random_ID();
    struct ingress_flow_state state = {};
    state.req_id = req_id;
    state.xdp_ts = now;
    state.expected_seq = 0;
    state.consumed = 0;
    ingress_flow_map.update(&key, &state);
    ```
  * Unlike `tp_netif_receive_skb` ([`tracer_kernel.c:594-606`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L594-L606)) and `kprobe__tcp_v6_rcv` ([`tracer_kernel.c:1864-1878`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1864-L1878)), `kprobe__ipv6_rcv` **never looks up `ingress_flow_map.lookup(&key)`** and **never checks `tcp_payload_len > 0` for TCP packets**!
  * Consequently:
    1. If `tp_netif_receive_skb` (or an earlier hook) recorded `state.req_id` and `state.xdp_ts`, `kprobe__ipv6_rcv` destroys it and mints a brand-new `req_id`.
    2. If an IPv6 HTTP request arrives (`req_id = R1`) and before the application thread wakes up in `tcp_recvmsg` (`consumed == 0`), a 0-byte IPv6 TCP ACK arrives on the same 5-tuple, `kprobe__ipv6_rcv` overwrites `ingress_flow_map[key].req_id` with `R2`! Even though `kprobe__tcp_v6_rcv` has a guard (`if (!existing || existing->consumed == 1) { if (tcp_payload_len == 0) return 0; }`), `kprobe__ipv6_rcv` already clobbered `existing->req_id` with `R2` and set `existing->consumed = 0`!
* **3B — `kprobe__ip_rcv` Emits Spurious L3 Events for Post-Consumption 0-Byte ACKs (`state->consumed == 1`) and Splits `req_id` Between L3 and L4 on Loopback / Multi-Request Flows**:
  * Trace a persistent HTTP/1.1 keep-alive connection through `tracer_kernel.c`:
    1. Request #1 (`tcp_payload_len = 100`) arrives -> `req_id = R1` is stored in `ingress_flow_map` with `consumed = 0`.
    2. Application calls `tcp_recvmsg` ([`tracer_kernel.c:1158`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1158)) -> sets `flow_state->consumed = 1` (the entry remains in `ingress_flow_map` with `consumed = 1`).
    3. Now a **0-byte TCP ACK** (`tcp_payload_len = 0`) arrives from the client on the same 5-tuple:
       * `xdp_ingress_filter` ([`tracer_kernel.c:503`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L503)): `existing->consumed == 1` and `tcp_payload_len == 0` -> returns `XDP_PASS` (ignores ACK, leaves `consumed = 1`).
       * `tp_netif_receive_skb` ([`tracer_kernel.c:598`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L598)): `existing->consumed == 1` and `tcp_payload_len == 0` -> returns `0` (ignores ACK, leaves `consumed = 1`).
       * `kprobe__ip_rcv` ([`tracer_kernel.c:669-684`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L669-L684)):
         ```c
         struct ingress_flow_state *state = ingress_flow_map.lookup(&key);
         if (!state) return 0;
         ...
         ev->req_id = state->req_id;
         ```
         Because `state` is non-NULL (`state->consumed == 1`), `kprobe__ip_rcv` **emits a spurious `STAGE_L3_INGRESS` event with Request #1's dead `req_id = R1` for the 0-byte ACK**!
       * Even worse, in `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:728-747`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L728-L747)): when `state->consumed == 1` and `tcp_payload_len == 0`, the `if (!state || state->consumed == 1)` block at line 730 checks `if (tcp_payload_len > 0)` (which is false), **does not `return 0;`**, and falls through to `if (!state) return 0;` (which is false because `state != NULL`), **emitting a spurious `STAGE_L4_INGRESS` event with Request #1's dead `req_id = R1`**!
    4. Conversely, suppose Request #2 (`tcp_payload_len = 120`) arrives over loopback (`lo`) where `xdp_ingress_filter` does not run, or where `tp_netif_receive_skb` was skipped/missed while `state->consumed == 1` (or `state == NULL`):
       * `kprobe__ip_rcv` either drops L3 (`if (!state) return 0;`) or emits L3 with stale `R1` (`state->consumed == 1`), and then `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:730-738`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L730-L738)) mints `R2`, splitting the L3 and L4 events of the same packet across two different `req_id`s!
* **3C — Missing IPv6 (`ETH_P_IPV6_HOST`) and UDP (`IPPROTO_UDP`) Support in `tp_netif_receive_skb` and `kprobe__ip_rcv`**:
  * In [`tracer_kernel.c:564`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L564), `tp_netif_receive_skb` has `if (eth_proto != ETH_P_IP_HOST) return 0;`, dropping all IPv6 packets at L2 so IPv6 never gets a `STAGE_L2_INGRESS` event or L2 `req_id` correlation into `kprobe__ipv6_rcv`.
  * In [`tracer_kernel.c:645`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L645), `kprobe__ip_rcv` has `if (iph.protocol != IPPROTO_TCP) return 0;` (whereas `kprobe__ipv6_rcv` at line 1766 supports `IPPROTO_TCP` and `IPPROTO_UDP`), preventing IPv4 UDP packets (`__udp4_lib_rcv`) from ever receiving L3 `kprobe__ip_rcv` events or `ingress_flow_map` correlation.

---

### Exact Unified Diff Recommendations

#### 1. [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md)

* **Lines 199–205 & 280 & 1197–1202**: Correct the contradictory IPv6 `trans_off` specification, mandate IPv6 Extension Header unrolling (`0, 43, 44, 51, 60`) up to 6 headers with non-first fragment (`frag_off & 0xFFF8`) bailout, and mandate IPv4 `ihl >= 5` + non-first fragment (`frag_off & 0x1FFF`) validation across all L2/L3 hooks.

```diff
--- a/PROMPT_SPEC.md
+++ b/PROMPT_SPEC.md
@@ -200,7 +200,9 @@
    * **IPv4 가변 헤더(`IHL`) 오프셋 계산**: IPv4 패킷에서 L4(TCP/UDP) 헤더 오프셋을 구할 때 절대 `sizeof(struct iphdr)` (`20` 바이트)를 하드코딩하지 마라. IP 옵션이 포함된 패킷에서 오프셋이 밀리는 것을 방지하기 위해 반드시 `(iph.ihl & 0x0F) * 4`로 동적 계산하고, `ihl_len < 20`인 기형 패킷은 즉시 폐기하라.
    * **`skb->head` + `network_header` / `transport_header` 포인터 산술**: `skb` 내부의 헤더를 읽을 때는 `BPF_CORE_READ(skb, head)`로 버퍼 시작점을 얻고, `BPF_CORE_READ(skb, network_header)`(`net_off`) 및 `BPF_CORE_READ(skb, transport_header)`(`trans_off`)를 더하여 `bpf_probe_read_kernel()`로 읽어라.
-   * **L3 진입 시점(`ip_rcv`, `ipv6_rcv`)의 `transport_header` 미설정 주의**: `ip_rcv` 및 `ipv6_rcv` 진입 시점에는 커널이 아직 `skb->transport_header`를 갱신하지 않았거나(`0` 또는 `0xFFFF` 상태) L3 헤더 직후를 가리키므로, 절대 `skb->transport_header`를 신뢰하지 말고 `net_off + ihl_bytes`(IPv4) 또는 `net_off + sizeof(struct ipv6hdr)`(IPv6)로 L4 오프셋을 직접 산출하라.
+   * **L3 진입 시점(`ip_rcv`, `ipv6_rcv`)의 `transport_header` 미설정 주의**: `ip_rcv` 및 `ipv6_rcv` 진입 시점에는 커널이 아직 `skb->transport_header`를 L4 헤더로 갱신하지 않았으므로, 절대 `skb->transport_header`를 신뢰하지 말고 `net_off + ihl_bytes`(IPv4, `ihl >= 5` 및 비-첫번째 단편 `(ntohs(iph.frag_off) & 0x1FFF) == 0` 검증 필수) 또는 `net_off + sizeof(struct ipv6hdr) + ext_hdrs_len`(IPv6 확장 헤더 체인 언롤링 결과)로 L4 오프셋을 직접 산출하라.
@@ -278,7 +280,7 @@
 5. **`STAGE_L3_INGRESS` (`kprobe/ip_rcv`)**:
    * `skb->head + skb->network_header`에서 `struct iphdr`를 읽고 `ihl_bytes = (iph.ihl & 0x0f) * 4` (`ihl_bytes >= 20`, `(iph.version & 0x0f) == 4`, `(bpf_ntohs(iph.frag_off) & 0x1FFF) == 0`)를 계산한 뒤 `head + net_off + ihl_bytes`에서 L4 헤더를 추출하여 `ingress_flow_map`을 조회(또는 미존재/`consumed == 1` 시 데이터 패킷에 한해 폴백 생성)하고 `OSI_L3_IP` 이벤트를 방출한다. `bytes_acked` 상위 바이트에 실제 `ihl_bytes`와 `doff_bytes`를 인코딩한다.
 6. **`STAGE_L3_INGRESS` (`kprobe/ipv6_rcv`)**:
-   * `skb->head + skb->network_header`에서 `struct ipv6hdr`를 읽는다. `nexthdr`가 확장 헤더(`0` Hop-by-Hop, `43` Routing, `44` Fragment, `60` Dest Options)인 경우 `#pragma unroll` 루프(최대 2~4회)로 확장 헤더 체인을 순회하여 실제 L4 프로토콜(`IPPROTO_TCP` 또는 `IPPROTO_UDP`)과 L4 오프셋(`trans_off`)을 찾는다.
+   * `skb->head + skb->network_header`에서 `struct ipv6hdr`를 읽는다. `nexthdr`가 확장 헤더(`0` Hop-by-Hop, `43` Routing, `44` Fragment, `51` AH, `60` Dest Options)인 경우 `#pragma unroll` 루프(최대 6회)로 확장 헤더 체인을 순회하여 실제 L4 프로토콜(`IPPROTO_TCP` 또는 `IPPROTO_UDP`)과 L4 오프셋(`trans_off`)을 찾는다. 단, Fragment 헤더(`44`)는 고정 8바이트이며 `(bpf_ntohs(frag_off) & 0xFFF8) != 0`인 비-첫번째 단편은 L4 헤더가 없으므로 즉시 반환하고, AH 헤더(`51`)는 `(hdrlen + 2) * 4` 바이트로 계산한다.
```

#### 2. [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)

* **Fixes in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)**:
  1. Add a shared inline helper `unroll_ipv6_ext_hdrs()` supporting `0`, `43`, `44` (with `frag_off & 0xFFF8` non-first fragment detection), `51` (`(hdrlen + 2) * 4`), `59` (No Next Header), and `60` up to 6 headers (`#pragma unroll`).
  2. In `xdp_ingress_filter` (lines 456–475), `tp_netif_receive_skb` (lines 562–591), `kprobe__ip_rcv` (lines 643–685), and `TRACEPOINT_PROBE(skb, kfree_skb)` (lines 845–855):
     * Validate `(iph.version & 0x0f) == 4`, `ihl_bytes >= sizeof(struct iphdr)` (`20B`), and `(bpf_ntohs(iph.frag_off) & 0x1FFF) == 0` (first fragment or unfragmented).
     * Validate `doff_len >= sizeof(struct tcphdr)` (`20B`) before computing `tcp_payload_len`.
  3. In `kprobe__ip_rcv` (lines 645–685):
     * Compute `doff_len` and `tcp_payload_len` identically to `tp_netif_receive_skb` and `kprobe__tcp_v4_rcv`.
     * Apply the exact same `state->consumed` + `tcp_payload_len` state-machine guard as `tp_netif_receive_skb` and `kprobe__tcp_v4_rcv`: if `!state || state->consumed == 1`, ignore 0-byte ACKs (`if (tcp_payload_len == 0) return 0;`) and mint a fallback `req_id` when `tcp_payload_len > 0` so loopback/non-XDP packets maintain identical `req_id` across `kprobe__ip_rcv` and `kprobe__tcp_v4_rcv`.
     * Also Fix `kprobe__tcp_v4_rcv` (line 730) so that when `state && state->consumed == 1 && tcp_payload_len == 0`, it returns `0` immediately instead of falling through and emitting a stale L4 event.
  4. In `kprobe__ipv6_rcv` (lines 1735–1785) and `kprobe__tcp_v6_rcv` (lines 1835–1885):
     * Use `unroll_ipv6_ext_hdrs()` (aborting on non-first fragments `is_non_first_frag`).
     * Subtract `ext_hdr_len = trans_off - (net_off + sizeof(struct ipv6hdr))` when computing `tcp_payload_len` from `bpf_ntohs(ip6h.payload_len)`.
     * In `kprobe__ipv6_rcv`, look up `ingress_flow_map.lookup(&key)` first and apply the `existing->consumed` / `tcp_payload_len` guard instead of blindly overwriting `ingress_flow_map`.
     * Encode actual L3 header length `(u64)(trans_off - net_off) << 16` in `ev->bytes_acked` instead of hardcoded `40ULL << 16`.

```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -429,6 +429,43 @@ static __always_inline void check_and_emit_phase_transition(void *ctx, u64 req_i
     }
 }
 
+struct ipv6_frag_hdr_min {
+    u8 nexthdr;
+    u8 reserved;
+    __be16 frag_off;
+};
+
+static __always_inline int unroll_ipv6_ext_hdrs(const void *head, u16 *trans_off, u8 *nexthdr_inout) {
+    u8 nexthdr = *nexthdr_inout;
+    u16 off = *trans_off;
+    #pragma unroll
+    for (int i = 0; i < 6; i++) {
+        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 60) {
+            u8 ext_hdr[2] = {};
+            if (bpf_probe_read_kernel(ext_hdr, sizeof(ext_hdr), head + off) < 0)
+                return -1;
+            nexthdr = ext_hdr[0];
+            off += ((u16)ext_hdr[1] + 1) * 8;
+        } else if (nexthdr == 51) {
+            u8 auth_hdr[2] = {};
+            if (bpf_probe_read_kernel(auth_hdr, sizeof(auth_hdr), head + off) < 0)
+                return -1;
+            nexthdr = auth_hdr[0];
+            off += ((u16)auth_hdr[1] + 2) * 4;
+        } else if (nexthdr == 44) {
+            struct ipv6_frag_hdr_min fhdr = {};
+            if (bpf_probe_read_kernel(&fhdr, sizeof(fhdr), head + off) < 0)
+                return -1;
+            if ((bpf_ntohs(fhdr.frag_off) & 0xFFF8) != 0)
+                return -1; /* Non-first IPv6 fragment has no L4 header */
+            nexthdr = fhdr.nexthdr;
+            off += 8;
+        } else {
+            break;
+        }
+    }
+    *trans_off = off;
+    *nexthdr_inout = nexthdr;
+    return 0;
+}
+
 SEC("xdp")
 int xdp_ingress_filter(struct xdp_md *ctx) {
     void *data_end = (void *)(long)ctx->data_end;
@@ -453,10 +490,13 @@ int xdp_ingress_filter(struct xdp_md *ctx) {
     struct iphdr iph = {};
     if (bpf_xdp_load_bytes(ctx, nh_off, &iph, sizeof(iph)) < 0)
         return XDP_PASS;
+    if ((iph.version & 0x0f) != 4)
+        return XDP_PASS;
     u32 ihl_len = (iph.ihl & 0x0f) * 4;
     if (ihl_len < sizeof(struct iphdr))
         return XDP_PASS;
+    if ((bpf_ntohs(iph.frag_off) & 0x1FFF) != 0)
+        return XDP_PASS;
     if (iph.protocol != IPPROTO_TCP)
         return XDP_PASS;
 
@@ -564,8 +604,11 @@ TRACEPOINT_PROBE(net, netif_receive_skb) {
     if (eth_proto != ETH_P_IP_HOST) return 0;
     struct iphdr iph = {};
     if (bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off) < 0) return 0;
+    if ((iph.version & 0x0f) != 4) return 0;
     u32 ihl_len = (iph.ihl & 0x0f) * 4;
     if (ihl_len < sizeof(struct iphdr)) return 0;
+    if ((bpf_ntohs(iph.frag_off) & 0x1FFF) != 0) return 0;
     if (iph.protocol != IPPROTO_TCP) return 0;
 
     struct tcphdr tcph = {};
@@ -586,6 +629,7 @@ TRACEPOINT_PROBE(net, netif_receive_skb) {
     u32 tot_len = bpf_ntohs(iph.tot_len);
     u32 doff_len = (tcph.doff & 0x0f) * 4;
+    if (doff_len < sizeof(struct tcphdr)) return 0;
     u32 tcp_payload_len = 0;
     if (tot_len > ihl_len + doff_len) tcp_payload_len = tot_len - ihl_len - doff_len;
 
@@ -642,9 +686,13 @@ int kprobe__ip_rcv(struct pt_regs *ctx) {
     struct iphdr iph = {};
     if (bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off) < 0) return 0;
+    if ((iph.version & 0x0f) != 4) return 0;
     if (iph.protocol != IPPROTO_TCP) return 0;
 
     u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
+    if (ihl_bytes < sizeof(struct iphdr)) return 0;
+    if ((bpf_ntohs(iph.frag_off) & 0x1FFF) != 0) return 0;
     u16 trans_off = net_off + ihl_bytes;
     struct tcphdr tcph = {};
     if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off) < 0) return 0;
+    u16 doff_bytes = (tcph.doff & 0x0f) * 4;
+    if (doff_bytes < sizeof(struct tcphdr)) return 0;
+    u16 tot_len = bpf_ntohs(iph.tot_len);
+    u32 tcp_payload_len = (tot_len > ihl_bytes + doff_bytes) ? (tot_len - ihl_bytes - doff_bytes) : 0;
 
     u16 sport_h = bpf_ntohs(tcph.source);
@@ -666,8 +714,22 @@ int kprobe__ip_rcv(struct pt_regs *ctx) {
     key.dport = tcph.dest;
     key.proto = IPPROTO_TCP;
 
+    u64 now = bpf_ktime_get_ns();
     struct ingress_flow_state *state = ingress_flow_map.lookup(&key);
-    if (!state) return 0;
+    if (!state || state->consumed == 1) {
+        if (tcp_payload_len == 0) return 0;
+        struct ingress_flow_state new_state = {};
+        new_state.req_id = get_Pseudo_Random_ID();
+        new_state.xdp_ts = now;
+        new_state.expected_seq = bpf_ntohl(tcph.seq) + tcp_payload_len;
+        new_state.consumed = 0;
+        ingress_flow_map.update(&key, &new_state);
+        state = ingress_flow_map.lookup(&key);
+        if (!state) return 0;
+    } else if (tcp_payload_len > 0 && state->expected_seq == 0) {
+        state->expected_seq = bpf_ntohl(tcph.seq) + tcp_payload_len;
+    }
 
     int zero = 0;
     struct trace_event *ev = scratch_event_map.lookup(&zero);
     if (!ev) return 0;
     __builtin_memset(ev, 0, sizeof(*ev));
     ev->timestamp_ns = now;
     ev->req_id = state->req_id;
     ev->stage_id = STAGE_L3_INGRESS;
     ev->osi_layer = OSI_L3_IP;
     ev->saddr = key.saddr;
     ev->daddr = key.daddr;
     ev->sport = sport_h;
     ev->dport = dport_h;
     ev->protocol = IPPROTO_TCP;
     ev->skb_len = BPF_CORE_READ(skb, len);
     ev->seq = bpf_ntohl(tcph.seq);
     ev->ack_seq = bpf_ntohl(tcph.ack_seq);
     ev->pkt_Disposition = PKT_PASS;
-    ev->bytes_acked = ((u64)ihl_bytes << 16) | ((u64)((tcph.doff & 0x0f) * 4) << 24);
+    ev->bytes_acked = ((u64)ihl_bytes << 16) | ((u64)doff_bytes << 24);
     events.perf_submit(ctx, ev, sizeof(*ev));
     return 0;
 }
@@ -721,13 +783,16 @@ int kprobe__tcp_v4_rcv(struct pt_regs *ctx) {
     u32 tot_len = bpf_ntohs(iph.tot_len);
     u32 ihl_len = (iph.ihl & 0x0f) * 4;
+    if (ihl_len < sizeof(struct iphdr)) return 0;
     u32 doff_len = (tcph.doff & 0x0f) * 4;
+    if (doff_len < sizeof(struct tcphdr)) return 0;
     u32 tcp_payload_len = 0;
     if (tot_len > ihl_len + doff_len) tcp_payload_len = tot_len - ihl_len - doff_len;
 
     u64 now = bpf_ktime_get_ns();
     struct ingress_flow_state *state = ingress_flow_map.lookup(&key);
     if (!state || state->consumed == 1) {
-        if (tcp_payload_len > 0) {
-            struct ingress_flow_state new_state = {};
-            new_state.req_id = get_Pseudo_Random_ID();
-            new_state.xdp_ts = now;
-            new_state.expected_seq = bpf_ntohl(tcph.seq) + tcp_payload_len;
-            new_state.consumed = 0;
-            ingress_flow_map.update(&key, &new_state);
-            state = ingress_flow_map.lookup(&key);
-        }
+        if (tcp_payload_len == 0) return 0;
+        struct ingress_flow_state new_state = {};
+        new_state.req_id = get_Pseudo_Random_ID();
+        new_state.xdp_ts = now;
+        new_state.expected_seq = bpf_ntohl(tcph.seq) + tcp_payload_len;
+        new_state.consumed = 0;
+        ingress_flow_map.update(&key, &new_state);
+        state = ingress_flow_map.lookup(&key);
     } else if (tcp_payload_len > 0 && state->expected_seq == 0) {
         state->expected_seq = bpf_ntohl(tcph.seq) + tcp_payload_len;
     }
     if (!state) return 0;
@@ -845,8 +910,11 @@ TRACEPOINT_PROBE(skb, kfree_skb) {
         struct iphdr iph = {};
         if (bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off) == 0 &&
+            (iph.version & 0x0f) == 4 &&
+            (bpf_ntohs(iph.frag_off) & 0x1FFF) == 0 &&
             (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP)) {
             u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
+            if (ihl_bytes < sizeof(struct iphdr)) return 0;
             u16 trans_off = net_off + ihl_bytes;
             __be16 ports[2] = {};
             if (bpf_probe_read_kernel(ports, sizeof(ports), head + trans_off) == 0) {
@@ -1740,26 +1808,9 @@ int kprobe__ipv6_rcv(struct pt_regs *ctx) {
     u8 nexthdr = ip6h.nexthdr;
     u16 trans_off = net_off + sizeof(struct ipv6hdr);
-    #pragma unroll
-    for (int i = 0; i < 2; i++) {
-        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 44 || nexthdr == 60) {
-            if (nexthdr == 44) {
-                u8 frag_hdr[2] = {};
-                if (bpf_probe_read_kernel(frag_hdr, sizeof(frag_hdr), head + trans_off) < 0) return 0;
-                nexthdr = frag_hdr[0];
-                trans_off += 8;
-            } else {
-                u8 ext_hdr[2] = {};
-                if (bpf_probe_read_kernel(ext_hdr, sizeof(ext_hdr), head + trans_off) < 0) return 0;
-                nexthdr = ext_hdr[0];
-                u16 hdr_len = ((u16)ext_hdr[1] + 1) * 8;
-                trans_off += hdr_len;
-            }
-        } else {
-            break;
-        }
-    }
+    if (unroll_ipv6_ext_hdrs(head, &trans_off, &nexthdr) < 0) return 0;
 
     if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP) return 0;
 
     __be16 ports[2] = {};
     if (bpf_probe_read_kernel(ports, sizeof(ports), head + trans_off) < 0) return 0;
+
+    u16 l3_hdr_bytes = trans_off - net_off;
+    u16 ext_hdr_bytes = l3_hdr_bytes - sizeof(struct ipv6hdr);
+    u16 doff_bytes = 0;
+    u32 tcp_payload_len = 0;
+    if (nexthdr == IPPROTO_TCP) {
+        struct tcphdr tcph = {};
+        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off) < 0) return 0;
+        doff_bytes = (tcph.doff & 0x0f) * 4;
+        if (doff_bytes < sizeof(struct tcphdr)) return 0;
+        u16 payload_len = bpf_ntohs(ip6h.payload_len);
+        if (payload_len > ext_hdr_bytes + doff_bytes)
+            tcp_payload_len = payload_len - ext_hdr_bytes - doff_bytes;
+    } else {
+        u16 payload_len = bpf_ntohs(ip6h.payload_len);
+        if (payload_len > ext_hdr_bytes + 8)
+            tcp_payload_len = payload_len - ext_hdr_bytes - 8;
+    }
 
     struct flow_key key = {};
     key.saddr = fold_ipv6_addr(&ip6h.saddr);
@@ -1774,14 +1840,21 @@ int kprobe__ipv6_rcv(struct pt_regs *ctx) {
     u64 now = bpf_ktime_get_ns();
-    u64 req_id = get_Pseudo_Random_ID();
-    struct ingress_flow_state state = {};
-    state.req_id = req_id;
-    state.xdp_ts = now;
-    state.expected_seq = 0;
-    state.consumed = 0;
-    ingress_flow_map.update(&key, &state);
+    struct ingress_flow_state *existing = ingress_flow_map.lookup(&key);
+    u64 req_id = 0;
+    if (!existing || existing->consumed == 1) {
+        if (nexthdr == IPPROTO_TCP && tcp_payload_len == 0) return 0;
+        req_id = get_Pseudo_Random_ID();
+        struct ingress_flow_state state = {};
+        state.req_id = req_id;
+        state.xdp_ts = now;
+        state.expected_seq = 0;
+        state.consumed = 0;
+        ingress_flow_map.update(&key, &state);
+    } else {
+        req_id = existing->req_id;
+    }
 
     ev->timestamp_ns = now;
     ev->req_id = req_id;
-    ev->bytes_acked = (40ULL << 16);
+    ev->bytes_acked = ((u64)l3_hdr_bytes << 16) | ((u64)doff_bytes << 24);
     ev->stage_id = STAGE_L3_INGRESS;
@@ -1838,24 +1911,8 @@ int kprobe__tcp_v6_rcv(struct pt_regs *ctx) {
     u8 nexthdr = ip6h.nexthdr;
     u16 trans_off = net_off + sizeof(struct ipv6hdr);
-    #pragma unroll
-    for (int i = 0; i < 2; i++) {
-        if (nexthdr == 0 || nexthdr == 43 || nexthdr == 44 || nexthdr == 60) {
-            if (nexthdr == 44) {
-                u8 frag_hdr[2] = {};
-                if (bpf_probe_read_kernel(frag_hdr, sizeof(frag_hdr), head + trans_off) < 0) return 0;
-                nexthdr = frag_hdr[0];
-                trans_off += 8;
-            } else {
-                u8 ext_hdr[2] = {};
-                if (bpf_probe_read_kernel(ext_hdr, sizeof(ext_hdr), head + trans_off) < 0) return 0;
-                nexthdr = ext_hdr[0];
-                u16 hdr_len = ((u16)ext_hdr[1] + 1) * 8;
-                trans_off += hdr_len;
-            }
-        } else {
-            break;
-        }
-    }
+    if (unroll_ipv6_ext_hdrs(head, &trans_off, &nexthdr) < 0) return 0;
     if (nexthdr != IPPROTO_TCP) return 0;
 
     struct tcphdr tcph = {};
     if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off) < 0) return 0;
@@ -1859,8 +1916,11 @@ int kprobe__tcp_v6_rcv(struct pt_regs *ctx) {
     if (!should_trace_port(sport_h, dport_h)) return 0;
 
+    u16 l3_hdr_bytes = trans_off - net_off;
+    u16 ext_hdr_bytes = l3_hdr_bytes - sizeof(struct ipv6hdr);
     u16 payload_len = bpf_ntohs(ip6h.payload_len);
     u16 doff_len = (tcph.doff & 0x0f) * 4;
-    u32 tcp_payload_len = (payload_len > doff_len) ? (payload_len - doff_len) : 0;
+    if (doff_len < sizeof(struct tcphdr)) return 0;
+    u32 tcp_payload_len = (payload_len > ext_hdr_bytes + doff_len) ? (payload_len - ext_hdr_bytes - doff_len) : 0;
 
     struct flow_key key = {};
@@ -1881,5 +1941,5 @@ int kprobe__tcp_v6_rcv(struct pt_regs *ctx) {
     ev->timestamp_ns = now;
     ev->req_id = req_id;
-    ev->bytes_acked = (40ULL << 16) | ((u64)doff_len << 24);
+    ev->bytes_acked = ((u64)l3_hdr_bytes << 16) | ((u64)doff_len << 24);
     ev->stage_id = STAGE_L4_INGRESS;
```

#### 3. [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c)

* **Fixes in [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c)**:
  1. Remove the test-masking clamp `if (ihl_words < 5) ihl_words = 5;` in `build_ipv4_tcp_buf` ([`kernel_sim_harness.c:284`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L284)) so `ihl_words < 5` actually writes `iph->ihl = ihl_words` into the wire header while keeping the buffer allocation at least `sizeof(struct iphdr)` to test malformed `ihl < 5` against `xdp_ingress_filter`, `tp_netif_receive_skb`, `kprobe__ip_rcv`, and `kfree_skb`.
  2. Replace hardcoded `sizeof(struct iphdr)` in `sim_icmp_rcv_test` ([`kernel_sim_harness.c:820`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L820)) and `sim_udp_unconnected_pipeline` ([`kernel_sim_harness.c:847`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L847)) with `(iph->ihl & 0x0f) * 4`.
  3. Extend `sim_ipv6_ext_hdr_test` ([`kernel_sim_harness.c:752-805`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L752-L805)) or add a companion simulator entry point to test:
     * Full L2->L3->L4 IPv4 pipeline with `ihl_words = 8` (32B IPv4 header with options) and `ihl_words = 3` (malformed `ihl < 5` rejected at `kprobe__ip_rcv`).
     * IPv6 Fragment Header (`nexthdr = 44`) with `frag_off = htons(0x0001)` (first fragment, `M=1`, accepted) vs `frag_off = htons(0x0008)` (non-first fragment, offset=1, rejected).
     * IPv6 3-header chain (`Hop-by-Hop 0 -> Routing 43 -> Fragment 44 -> TCP 6`) and `NEXTHDR_AUTH (51)` (`(hdrlen + 2) * 4`).

```diff
--- a/kernel_sim_harness.c
+++ b/kernel_sim_harness.c
@@ -281,10 +281,10 @@ static u32 build_ipv4_tcp_buf(u8 *pkt, size_t cap, u8 ihl_words,
                               __be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
                               const char *payload, u16 payload_len) {
-    if (ihl_words < 5) ihl_words = 5;
     if (ihl_words > 15) ihl_words = 15;
-    u32 ihl_bytes = (u32)ihl_words * 4;
+    u32 effective_words = (ihl_words < 5) ? 5 : ihl_words;
+    u32 ihl_bytes = effective_words * 4;
     u32 total = sizeof(struct ethhdr) + ihl_bytes + sizeof(struct tcphdr) + payload_len;
     if (total > cap) return 0;
     memset(pkt, 0, total);
 
     struct ethhdr *eth = (struct ethhdr *)pkt;
     eth->h_proto = bpf_htons(ETH_P_IP_HOST);
 
     struct iphdr *iph = (struct iphdr *)(pkt + sizeof(struct ethhdr));
-    iph->ihl = ihl_words;
+    iph->ihl = ihl_words & 0x0f;
     iph->version = 4;
@@ -817,7 +817,7 @@ int sim_icmp_rcv_test(u16 orig_dport_h, u8 icmp_type, u8 icmp_code) {
     iph->saddr = bpf_htonl(0x0A000002);
     iph->daddr = bpf_htonl(0x0A000001);
 
-    u16 trans_off = net_off + sizeof(struct iphdr);
+    u16 trans_off = net_off + (iph->ihl & 0x0f) * 4;
     struct icmphdr *icmph = (struct icmphdr *)(pkt + trans_off);
@@ -844,7 +844,7 @@ int sim_udp_unconnected_pipeline(u16 dport_h, u32 payload_len) {
     iph->saddr = bpf_htonl(0x0A000001);
     iph->daddr = bpf_htonl(0x0A000002);
 
-    u16 trans_off = net_off + sizeof(struct iphdr);
+    u16 trans_off = net_off + (iph->ihl & 0x0f) * 4;
     struct udphdr *udph = (struct udphdr *)(pkt + trans_off);
```

#### 4. [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py)

* **Fixes in [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py)**:
  * Expand `test_34_xdp_ipv4_options_ihl_unrolling` ([`test_verification_suite.py:665-680`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L665-L680)) and `test_35_ipv6_extension_header_unrolling` ([`test_verification_suite.py:682-698`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L682-L698)) so they do not stop at XDP or 2-header IPv6 chains:
    * Verify `ihl_words = 3` (`12B < 20B`) produces `0` events across `xdp_ingress_filter`, `tp_netif_receive_skb`, and `kprobe__ip_rcv`.
    * Verify `ihl_words = 8` (`32B` IPv4 header with 12B IP options) preserves identical `req_id` across `STAGE_XDP_INGRESS` -> `STAGE_L2_INGRESS` -> `STAGE_L3_INGRESS` -> `STAGE_L4_INGRESS` and encodes `l3_hdr_bytes == 32` in `(ev.bytes_acked >> 16) & 0xFF`.
    * Verify IPv6 non-first fragment (`nexthdr == 44`, `frag_off = 0x0008`) produces `0` events at `kprobe__ipv6_rcv` and `kprobe__tcp_v6_rcv`.
    * Verify IPv6 0-byte TCP ACK with extension headers does not overwrite an active unconsumed `req_id` in `ingress_flow_map` at `kprobe__ipv6_rcv`.
