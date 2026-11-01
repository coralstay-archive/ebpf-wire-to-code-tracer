### Agent 05 Adversarial Falsification Report — Domain 05/20: L4 TCP State Machine & 0-Byte Handshake/FIN/RST Filtering (`tcp_v4_rcv`, `tcp_v6_rcv`, `doff` Validation, Piggybacked ACKs)

#### Executive Summary of Falsified Assumptions
* **Target Scope Audited**:
  * [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L426-L756) (`xdp_ingress_filter`, `TRACEPOINT_PROBE(net, netif_receive_skb)`, `kprobe__ip_rcv`, `kprobe__tcp_v4_rcv`) and [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1722-L1890) (`kprobe__ipv6_rcv`, `kprobe__tcp_v6_rcv`)
  * [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L526-L532) (Iteration 1: Payload-Gated `req_id` Minting) & [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L574-L591) (Layer 1 & Layer 2 Hook Specifications)
  * [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L273-L350) (`build_ipv4_tcp_buf`, `sim_tcp_v4_ingress_pipeline`, `sim_ipv6_tcp_pipeline`)
  * [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1351-L1366) (`ADV-TEST-01`) & [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1551-L1631) (`ADV-TEST-04`)
  * **Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) Ground-Truth Kernel Sources**: [`net/ipv4/ip_input.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L227-L564), [`net/ipv4/tcp_ipv4.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1945-L2155), [`net/ipv6/ip6_input.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L149-L497), [`net/ipv6/tcp_ipv6.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/tcp_ipv6.c#L1582-L1700)
* **Key Falsification Verdict**:
  * Six (6) concrete kernel/spec/test flaws were uncovered across L2/L3/L4 TCP header validation, 0-byte handshake/FIN/RST/ACK filtering, IPv6 extension-header payload math, and Ethernet L2 60B/64B frame padding.

---

### Detailed Falsification Findings & Root-Cause Analysis

#### Finding 05-01 [CRITICAL]: `kprobe__tcp_v4_rcv` and `kprobe__tcp_v6_rcv` Unconditionally Mint Bogus `req_id`s and Emit L4 Events on 0-Byte Handshake (`SYN` / `ACK`), `FIN`, and `RST` Segments When `!state`
* **Exact Citations**:
  * [`tracer_kernel.c:728-755`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L728-L755) (`kprobe__tcp_v4_rcv`)
  * [`tracer_kernel.c:1864-1889`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1864-L1889) (`kprobe__tcp_v6_rcv`)
  * [`PROMPT_SPEC.md:587`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L587)
* **Physical Kernel Proof**:
  * During a TCP 3-Way Handshake (`SYN` -> `SYN,ACK` -> `ACK`), the client's initial 0-byte `SYN` (`tcp_payload_len == 0`) arrives at `xdp_ingress_filter` ([`tracer_kernel.c:503-504`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L503-L504)) and `netif_receive_skb` ([`tracer_kernel.c:598-599`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L598-L599)). Both L2 hooks see `!existing && tcp_payload_len == 0` and return early without inserting `key` into `ingress_flow_map`.
  * Next, `kprobe__ip_rcv` ([`tracer_kernel.c:669-671`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L669-L671)) sees `!state` and returns `0`.
  * However, when `kprobe__tcp_v4_rcv` runs at [`tracer_kernel.c:730`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L730) (and `kprobe__tcp_v6_rcv` at [`tracer_kernel.c:1865`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1865)):
    ```c
    if (!state || (state->consumed == 1 && tcp_payload_len > 0)) {
    ```
    Because `!state` is **not** guarded by `tcp_payload_len > 0`, `kprobe__tcp_v4_rcv` enters the block for the 0-byte `SYN` packet, mints a bogus `req_id_SYN` with `init_state.consumed = 0`, `init_state.xdp_ts = 0`, and `init_state.pkt_len = 40`, updates `ingress_flow_map`, and emits a spurious `LAYER_KERNEL_NET (OSI_L4_TCP)` event!
  * **Cascade Failure on Loopback / Non-XDP Path**: Because a 0-byte `SYN` is handled by `tcp_conn_request` and never consumed by `tcp_recvmsg`, `state->consumed` remains `0` in `ingress_flow_map`. When the actual HTTP payload segment (`tcp_payload_len = 128`) arrives later on a loopback/non-XDP path, `state` is already non-NULL and `state->consumed == 0`, so `kprobe__tcp_v4_rcv` fails to mint a new `req_id` for the HTTP request, reuses the stale handshake `req_id_SYN`, retains `state->pkt_len = 40` (from the `SYN`), and computes `dur_ns = now - state->ip_rcv_ts` using the timestamp of the `SYN` packet!

---

#### Finding 05-02 [CRITICAL]: Post-Consumption (`state->consumed == 1`) 0-Byte `ACK` / `FIN,ACK` / `RST` Emits Spurious L3/L4 Events with Completed `req_id`, and Pre-Consumption (`state->consumed == 0`) 0-Byte `ACK` Corrupts `tcp_rcv_ts` Dwell Time and Wipes Out `FLAG_TCP_PSH`
* **Exact Citations**:
  * [`tracer_kernel.c:669-682`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L669-L682) (`kprobe__ip_rcv`)
  * [`tracer_kernel.c:728-755`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L728-L755) (`kprobe__tcp_v4_rcv`)
  * [`tracer_kernel.c:1864-1889`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1864-L1889) (`kprobe__tcp_v6_rcv`)
  * [`test_verification_suite.py:1361-1365`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1361-L1365) (`ADV-TEST-01`)
* **Physical Kernel Proof**:
  * **Case A — Post-Consumption (`state->consumed == 1 && tcp_payload_len == 0`)**:
    * After `tcp_recvmsg` consumes a request (`state->consumed = 1`) and the server sends its response, the client sends a 0-byte `ACK` (acknowledging the response) and/or a 0-byte `FIN,ACK` (closing the connection).
    * While `xdp_ingress_filter` (line 503) and `netif_receive_skb` (line 598) explicitly drop 0-byte segments when `existing->consumed == 1`, `kprobe__ip_rcv` (lines 669-682), `kprobe__tcp_v4_rcv` (lines 728-755), and `kprobe__tcp_v6_rcv` (lines 1864-1889) **do not return `0` when `tcp_payload_len == 0`**.
    * In `kprobe__tcp_v4_rcv`, when `state != NULL && state->consumed == 1 && tcp_payload_len == 0`, the `if` condition at line 730 evaluates to `false`, and execution falls straight through to lines 744-755, emitting a bogus `OSI_L4_TCP` event with the already-completed request's `state->req_id` and `dur_ns = now - state->ip_rcv_ts` (equal to the entire HTTP RTT!). `kprobe__ip_rcv` similarly emits a bogus `OSI_L3_IP` event with the completed `state->req_id`.
  * **Case B — Pre-Consumption (`state->consumed == 0 && tcp_payload_len == 0`)**:
    * When a 0-byte pure `ACK` (e.g., window update or pure ACK) arrives on the same 4-tuple *after* a `[PSH, ACK]` payload segment but *before* `tcp_recvmsg` consumes `state` (`state->consumed == 0`):
      1. `kprobe__ip_rcv` ([`tracer_kernel.c:674`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L674)) overwrites `state->ip_rcv_ts = now`.
      2. `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:745-746`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L745-L746)) and `kprobe__tcp_v6_rcv` ([`tracer_kernel.c:1879-1880`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1879-L1880)) overwrite `state->tcp_rcv_ts = now` (corrupting the `sk_rcvbuf` dwell time `dwell_ns = now - state->tcp_rcv_ts` calculated later in `tcp_recvmsg` at line 929) and overwrite `state->tcp_flags = tflags` (replacing `FLAG_TCP_PSH | FLAG_TCP_ACK` with `FLAG_TCP_ACK` so `FLAG_TCP_PSH` is lost on the `OSI_L4_SOCKET` event!).
      3. In [`test_verification_suite.py:1363-1365`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1363-L1365), `ADV-TEST-01` only checked `assert all(e.req_id == orig_req_id for e in ack_evs)` and drained `ack_evs`, masking the fact that `kprobe__ip_rcv` and `kprobe__tcp_v4_rcv` emitted duplicate L3/L4 events for the 0-byte ACK and overwrote `state->tcp_flags` and `state->tcp_rcv_ts`!
  * **Case C — TCP `RST` and `SYN` Control Segments**:
    * Neither `xdp_ingress_filter`, `netif_receive_skb`, `kprobe__ip_rcv`, `kprobe__tcp_v4_rcv`, `kprobe__ipv6_rcv`, nor `kprobe__tcp_v6_rcv` checks `tcph.rst` or `tcph.syn`. A `RST` segment with an RFC 793 diagnostic text payload (or a `SYN` segment) has `tcp_payload_len > 0` or `syn/rst == 1`, which would overwrite an unconsumed or consumed `ingress_flow_map` entry even though `tcp_recvmsg` will never read payload from a `RST`/`SYN` segment.
    * Conversely, **Piggybacked ACKs** (`tcph.ack == 1 && tcph.syn == 0 && tcph.rst == 0 && tcp_payload_len > 0`, including `[PSH, ACK]`, `[ACK]` with data, and `[FIN, PSH, ACK]` with data) carry real application bytes that `tcp_recvmsg` reads and MUST be accepted.

---

#### Finding 05-03 [CRITICAL]: `kprobe__ipv6_rcv` Unconditionally Overwrites `ingress_flow_map` on Every 0-Byte IPv6 TCP `SYN` / `ACK` / `FIN` / `RST`, and `kprobe__tcp_v6_rcv` Fails to Subtract IPv6 Extension Header Length from `ip6h.payload_len`
* **Exact Citations**:
  * [`tracer_kernel.c:1739-1788`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1739-L1788) (`kprobe__ipv6_rcv`)
  * [`tracer_kernel.c:1860-1863`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1860-L1863) (`kprobe__tcp_v6_rcv`)
  * [`kernel_sim_harness.c:887-916`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L887-L916) (`sim_ipv6_tcp_pipeline`)
* **Physical Kernel Proof**:
  * In `kprobe__ipv6_rcv` ([`tracer_kernel.c:1759-1780`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1759-L1780)), when `nexthdr == IPPROTO_TCP`, the probe only reads 4 bytes (`u16 ports[2]`), never reads `struct tcphdr`, never validates `tcph.doff`, never computes `tcp_payload_len`, and never looks up `ingress_flow_map.lookup(&key)`. It **unconditionally** mints a new `state.req_id` and calls `ingress_flow_map.update(&key, &state)` on every IPv6 packet!
  * Therefore, if an IPv6 TCP payload request is followed by a 0-byte IPv6 TCP `ACK` before `tcp_recvmsg` runs, `kprobe__ipv6_rcv` **unconditionally overwrites `ingress_flow_map[key]` with a new `req_id`**, breaking IPv6 L3/L4-to-Socket correlation (violating Iteration 1 of `PROMPT_SPEC.md`).
  * Furthermore, in `kprobe__tcp_v6_rcv` ([`tracer_kernel.c:1860-1862`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1860-L1862)):
    ```c
    u16 payload_len = bpf_ntohs(ip6h.payload_len);
    u16 doff_len = (tcph.doff & 0x0f) * 4;
    u16 tcp_payload_len = (payload_len > doff_len) ? (payload_len - doff_len) : 0;
    ```
    Per RFC 8200 and [`net/ipv6/ip6_input.c:263-284`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L263-L284), `ip6h.payload_len` includes the length of any IPv6 extension headers between `struct ipv6hdr` (`net_off + 40`) and `struct tcphdr` (`trans_off`). If a 0-byte IPv6 TCP `ACK` carries an 8-byte IPv6 extension header (`ext_len = trans_off - (net_off + 40) = 8`, `payload_len = 28`, `doff_len = 20`), `payload_len - doff_len` evaluates to `8 > 0`, misclassifying a 0-byte IPv6 TCP `ACK` as having 8 bytes of TCP payload!
  * Also in [`kernel_sim_harness.c:898`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L898), `sim_ipv6_tcp_pipeline` sets `ip6h->payload_len = bpf_htons(payload_len > 40 ? (payload_len - 40) : payload_len);`, which sets `ip6h->payload_len = 0` (`< 20B` TCP header) when `payload_len == 0` is passed.

---

#### Finding 05-04 [HIGH]: Missing Malformed TCP `doff` Validation (`doff < 5` and `ihl_len + doff_len > tot_len`) in `netif_receive_skb`, `kprobe__ip_rcv`, `kprobe__tcp_v4_rcv`, `kprobe__ipv6_rcv`, and `kprobe__tcp_v6_rcv`
* **Exact Citations**:
  * [`tracer_kernel.c:587-589`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L587-L589) (`TRACEPOINT_PROBE(net, netif_receive_skb)`)
  * [`tracer_kernel.c:649-653`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L649-L653) (`kprobe__ip_rcv`)
  * [`tracer_kernel.c:723-726`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L723-L726) (`kprobe__tcp_v4_rcv`)
  * [`tracer_kernel.c:1860-1862`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1860-L1862) (`kprobe__tcp_v6_rcv`)
  * Rocky 9.8 Kernel Source: [`net/ipv4/tcp_ipv4.c:1965-1975`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1965-L1975) & [`net/ipv6/tcp_ipv6.c:1604-1615`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/tcp_ipv6.c#L1604-L1615)
* **Physical Kernel Proof**:
  * In Rocky Linux 9.8 [`net/ipv4/tcp_ipv4.c:1970-1975`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1970-L1975), the kernel validates `th->doff < sizeof(struct tcphdr) / 4` (`doff < 5`, i.e., `< 20` bytes) and `!pskb_may_pull(skb, th->doff * 4)` *inside* `tcp_v4_rcv` (and similarly at [`net/ipv6/tcp_ipv6.c:1609-1614`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/tcp_ipv6.c#L1609-L1614)), which executes **after** the `kprobe` at function entry!
  * In `tracer_kernel.c`, only `xdp_ingress_filter` checks `if (doff_len < sizeof(struct tcphdr))` (line 470). None of `netif_receive_skb`, `kprobe__ip_rcv`, `kprobe__tcp_v4_rcv`, `kprobe__ipv6_rcv`, or `kprobe__tcp_v6_rcv` check `doff_len < sizeof(struct tcphdr)` (`20B`) or `tot_len < ihl_len + doff_len`!
  * **Arithmetic Under-Subtraction Exploit**: If a 40-byte packet (`20B IP + 20B TCP`, 0 bytes of payload) has a malformed `tcph.doff = 2` (`doff_len = 8`), `netif_receive_skb` (line 589) and `kprobe__tcp_v4_rcv` (line 726) compute:
    `tcp_payload_len = tot_len - ihl_len - doff_len = 40 - 20 - 8 = 12 > 0`!
    This fabricates a non-zero `tcp_payload_len = 12` on a 0-byte malformed packet, mints a bogus `req_id` in `ingress_flow_map`, and when `tcp_v4_rcv` drops the packet 10 instructions later with `SKB_DROP_REASON_PKT_TOO_SMALL (3)`, `tracepoint:skb:kfree_skb` Stage 3 ([`tracer_kernel.c:847-865`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L847-L865)) matches that bogus `ingress_flow_map` entry and emits a false `FLAG_SKB_DROP` event!

---

#### Finding 05-05 [HIGH]: Ethernet L2 60B/64B Minimum Frame Padding vs Truncated IP `tot_len` Validation in `xdp_ingress_filter` & `netif_receive_skb`
* **Exact Citations**:
  * [`tracer_kernel.c:492-514`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L492-L514) (`xdp_ingress_filter`)
  * [`tracer_kernel.c:587-610`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L587-L610) (`netif_receive_skb`)
  * Rocky 9.8 Kernel Source: [`net/ipv4/ip_input.c:506-521`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L506-L521)
* **Physical Kernel Proof**:
  * On Ethernet links, IEEE 802.3 requires a minimum 60-byte (64-byte with FCS) L2 frame. A 0-byte IPv4 TCP `ACK` (`14B Eth + 20B IP + 20B TCP = 54B`) arrives at `xdp_ingress_filter` with `data_end - data == 60` (6 bytes of L2 zero trailer padding) and at `netif_receive_skb` with `skb->len == 46` (`40B IP/TCP + 6B L2 padding`), because `ip_rcv_core` does not call `pskb_trim_rcsum(skb, len)` until [`net/ipv4/ip_input.c:518`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L518).
  * `xdp_ingress_filter` (line 492) and `netif_receive_skb` (line 587) rightly use `tot_len = bpf_ntohs(iph->tot_len)` (`40B`) rather than `data_end - data` (`60B`) to compute `tcp_payload_len`, which prevents legitimate 60B-padded 0-byte ACKs from looking like they have 6 bytes of TCP payload.
  * **However**, neither `xdp_ingress_filter` nor `netif_receive_skb` checks the upper/lower bounds of `tot_len` against the actual captured packet length (`tot_len < ihl_len + doff_len` or `tot_len > (u32)((long)data_end - (long)iph)` in XDP / `args->len < (u32)(nh_ptr - data) + tot_len` in `netif_receive_skb`)!
  * If a truncated/malformed packet arrives with `data_end - (void *)iph == 40` (0 bytes of payload in the frame) but a forged `iph->tot_len = htons(100)`, `xdp_ingress_filter` and `netif_receive_skb` trust `tot_len = 100` without checking `tot_len <= l3_wire_len`, computing a fake `tcp_payload_len = 60 > 0` for a truncated packet that `ip_rcv_core` ([`net/ipv4/ip_input.c:507`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L507)) immediately drops with `SKB_DROP_REASON_PKT_TOO_SMALL`!

---

#### Finding 05-06 [MEDIUM]: Loopback / Non-XDP Keep-Alive Request #2 Causes `kprobe__ip_rcv` to Emit `OSI_L3_IP` Under Request #1's Consumed `req_id`
* **Exact Citations**:
  * [`tracer_kernel.c:669-682`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L669-L682) (`kprobe__ip_rcv`)
  * [`tracer_kernel.c:728-742`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L728-L742) (`kprobe__tcp_v4_rcv`)
* **Physical Kernel Proof**:
  * When XDP/`netif_receive_skb` is not triggered (e.g., loopback fallback `run_xdp=0, run_netif=0`), `kprobe__ip_rcv` runs *before* `kprobe__tcp_v4_rcv`.
  * On Request #1 of a connection (`!state`), `kprobe__ip_rcv` returns `0` at line 671 because only `kprobe__tcp_v4_rcv` has the `!state` fallback initializer.
  * On Request #2 of a Keep-Alive connection (`state != NULL && state->consumed == 1 && tcp_payload_len > 0`), `kprobe__ip_rcv` finds Request #1's consumed `state` in `ingress_flow_map`, does **not** mint a new `req_id`, and emits Request #2's `OSI_L3_IP` event with **Request #1's old `req_id`**! Only when `kprobe__tcp_v4_rcv` runs next does it see `state->consumed == 1 && tcp_payload_len > 0` and mint Request #2's new `req_id`.
  * Minting `init_state` in `kprobe__ip_rcv` (and `kprobe__ipv6_rcv`) when `(!state || state->consumed == 1) && tcp_payload_len > 0` ensures both L3 (`ip_rcv`/`ipv6_rcv`) and L4 (`tcp_v4_rcv`/`tcp_v6_rcv`) share the exact same `req_id` on loopback and Keep-Alive flows.

---

### Concrete Diff Recommendations

#### 1. Recommended Patch for [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)
```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -472,6 +472,9 @@ int xdp_ingress_filter(struct xdp_md *ctx)
     if ((void *)tcph + doff_len > data_end)
         return XDP_PASS;
+    if (tcph->rst || tcph->syn)
+        return XDP_PASS;
 
     u16 sport = bpf_ntohs(tcph->source);
     u16 dport = bpf_ntohs(tcph->dest);
@@ -490,7 +493,10 @@ int xdp_ingress_filter(struct xdp_md *ctx)
 
     u64 now = bpf_ktime_get_ns();
     u16 tot_len = bpf_ntohs(iph->tot_len);
+    u32 l3_wire_len = (u32)((long)data_end - (long)iph);
+    if (tot_len < (ihl_len + doff_len) || (u32)tot_len > l3_wire_len)
+        return XDP_PASS;
     u16 tcp_payload_len = tot_len - ihl_len - doff_len;
 
     struct flow_state_t *existing = ingress_flow_map.lookup(&key);
@@ -570,6 +576,12 @@ TRACEPOINT_PROBE(net, netif_receive_skb)
     struct tcphdr tcph = {};
     bpf_probe_read_kernel(&tcph, sizeof(tcph), nh_ptr + ihl_len);
+    u16 doff_len = (tcph.doff & 0x0f) * 4;
+    if (doff_len < sizeof(struct tcphdr))
+        return 0;
+    if (tcph.rst || tcph.syn)
+        return 0;
 
     u16 sport = bpf_ntohs(tcph.source);
     u16 dport = bpf_ntohs(tcph.dest);
@@ -585,8 +597,10 @@ TRACEPOINT_PROBE(net, netif_receive_skb)
     key.family = AF_INET;
 
     u16 tot_len = bpf_ntohs(iph.tot_len);
-    u16 doff_len = (tcph.doff & 0x0f) * 4;
-    u16 tcp_payload_len = (tot_len > (ihl_len + doff_len)) ? (tot_len - ihl_len - doff_len) : 0;
+    u32 vlan_off = (u32)((unsigned long)nh_ptr - (unsigned long)data);
+    if (tot_len < (ihl_len + doff_len) || (args->len > 0 && args->len < vlan_off + (u32)tot_len))
+        return 0;
+    u16 tcp_payload_len = tot_len - ihl_len - doff_len;
 
     struct flow_state_t *existing = ingress_flow_map.lookup(&key);
     if (existing && existing->consumed == 0) {
@@ -647,10 +661,21 @@ int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
     if (iph.protocol != IPPROTO_TCP)
         return 0;
 
     /* At ip_rcv entry (ip_input.c:552), skb->transport_header is uninitialized! */
     u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
+    if ((iph.version & 0x0f) != 4 || ihl_bytes < sizeof(struct iphdr))
+        return 0;
     u16 trans_off = net_off + ihl_bytes;
     struct tcphdr tcph = {};
     bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);
+    u16 doff_len = (tcph.doff & 0x0f) * 4;
+    if (doff_len < sizeof(struct tcphdr) || tcph.rst || tcph.syn)
+        return 0;
+    u16 tot_len = bpf_ntohs(iph.tot_len);
+    if (tot_len < (ihl_bytes + doff_len))
+        return 0;
+    u16 tcp_payload_len = tot_len - ihl_bytes - doff_len;
+    if (tcp_payload_len == 0)
+        return 0;
 
     u16 sport = bpf_ntohs(tcph.source);
     u16 dport = bpf_ntohs(tcph.dest);
@@ -667,8 +692,20 @@ int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)
 
     u64 now = bpf_ktime_get_ns();
     struct flow_state_t *state = ingress_flow_map.lookup(&key);
-    if (!state)
-        return 0;
+    if (!state || state->consumed == 1) {
+        struct flow_state_t init_state = {};
+        init_state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
+        init_state.ip_rcv_ts = now;
+        init_state.pkt_len   = tot_len;
+        init_state.tcp_flags = extract_tcp_flags(&tcph);
+        init_state.rx_cpu_id = (u8)bpf_get_smp_processor_id();
+        init_state.consumed  = 0;
+        ingress_flow_map.update(&key, &init_state);
+        state = ingress_flow_map.lookup(&key);
+        if (!state)
+            return 0;
+    }
 
     u64 dur_ns = state->xdp_ts ? (now - state->xdp_ts) : 20000ULL;
     state->ip_rcv_ts = now;
@@ -702,6 +739,12 @@ int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
     struct iphdr iph = {};
     struct tcphdr tcph = {};
     bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
+    u16 ihl_len = (iph.ihl & 0x0f) * 4;
+    if ((iph.version & 0x0f) != 4 || ihl_len < sizeof(struct iphdr))
+        return 0;
+    if (trans_off == 0 || trans_off == 0xFFFF || trans_off < net_off + ihl_len)
+        trans_off = net_off + ihl_len;
     bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);
 
     u16 sport = bpf_ntohs(tcph.source);
@@ -721,13 +764,17 @@ int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb)
     u64 now = bpf_ktime_get_ns();
     u8 tflags = extract_tcp_flags(&tcph);
     u16 tot_len = bpf_ntohs(iph.tot_len);
-    u16 ihl_len = (iph.ihl & 0x0f) * 4;
     u16 doff_len = (tcph.doff & 0x0f) * 4;
-    u16 tcp_payload_len = (tot_len > (ihl_len + doff_len)) ? (tot_len - ihl_len - doff_len) : 0;
+    if (doff_len < sizeof(struct tcphdr) || tot_len < (ihl_len + doff_len) || tcph.rst || tcph.syn)
+        return 0;
+    u16 tcp_payload_len = tot_len - ihl_len - doff_len;
+    if (tcp_payload_len == 0)
+        return 0;
 
     struct flow_state_t *state = ingress_flow_map.lookup(&key);
     /* Loopback fallback or new Keep-Alive request when previous req_id was consumed */
-    if (!state || (state->consumed == 1 && tcp_payload_len > 0)) {
+    if (!state || state->consumed == 1) {
         struct flow_state_t init_state = {};
         init_state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
         init_state.ip_rcv_ts = state ? state->ip_rcv_ts : now;
@@ -1772,15 +1819,35 @@ int kprobe__ipv6_rcv(struct pt_regs *ctx, struct sk_buff *skb)
     key.proto  = nexthdr;
     key.family = AF_INET6;
 
+    u8 tflags = FLAG_NONE;
+    u16 payload_len = bpf_ntohs(ip6h.payload_len);
+    u16 ext_len = (trans_off > net_off + sizeof(struct ipv6hdr)) ? (trans_off - net_off - sizeof(struct ipv6hdr)) : 0;
+    if (nexthdr == IPPROTO_TCP) {
+        struct tcphdr tcph = {};
+        bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);
+        u16 doff_len = (tcph.doff & 0x0f) * 4;
+        if (doff_len < sizeof(struct tcphdr) || payload_len < (ext_len + doff_len) || tcph.rst || tcph.syn)
+            return 0;
+        u16 tcp_payload_len = payload_len - ext_len - doff_len;
+        if (tcp_payload_len == 0)
+            return 0;
+        tflags = extract_tcp_flags(&tcph);
+    }
+
     u64 now = bpf_ktime_get_ns();
-    struct flow_state_t state = {};
-    state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
-    state.ip_rcv_ts = now;
-    state.pkt_len   = bpf_ntohs(ip6h.payload_len) + 40;
-    ingress_flow_map.update(&key, &state);
+    struct flow_state_t *existing = ingress_flow_map.lookup(&key);
+    if (!existing || existing->consumed == 1) {
+        struct flow_state_t state = {};
+        state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
+        state.ip_rcv_ts = now;
+        state.pkt_len   = payload_len + 40;
+        state.tcp_flags = tflags;
+        state.consumed  = 0;
+        ingress_flow_map.update(&key, &state);
+        existing = ingress_flow_map.lookup(&key);
+        if (!existing)
+            return 0;
+    } else {
+        existing->ip_rcv_ts = now;
+    }
 
     emit_kray_event(
-        state.req_id, ((u64)ip6h.hop_limit << 24) | (40ULL << 16) | state.pkt_len, now, 20000ULL,
+        existing->req_id, ((u64)ip6h.hop_limit << 24) | (40ULL << 16) | existing->pkt_len, now, 20000ULL,
         0, 0, 0,
         key.saddr, key.daddr, sport, dport,
-        LAYER_KERNEL_NET, 0, OSI_L3_IP, FLAG_NONE);
+        LAYER_KERNEL_NET, 0, OSI_L3_IP, tflags);
     return 0;
 }
@@ -1858,11 +1925,16 @@ int kprobe__tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb)
     u64 now = bpf_ktime_get_ns();
     u8 tflags = extract_tcp_flags(&tcph);
     u16 payload_len = bpf_ntohs(ip6h.payload_len);
     u16 doff_len = (tcph.doff & 0x0f) * 4;
-    u16 tcp_payload_len = (payload_len > doff_len) ? (payload_len - doff_len) : 0;
+    u16 ext_len = (trans_off > net_off + sizeof(struct ipv6hdr)) ? (trans_off - net_off - sizeof(struct ipv6hdr)) : 0;
+    if (doff_len < sizeof(struct tcphdr) || payload_len < (ext_len + doff_len) || tcph.rst || tcph.syn)
+        return 0;
+    u16 tcp_payload_len = payload_len - ext_len - doff_len;
+    if (tcp_payload_len == 0)
+        return 0;
 
     struct flow_state_t *state = ingress_flow_map.lookup(&key);
-    if (!state || (state->consumed == 1 && tcp_payload_len > 0)) {
+    if (!state || state->consumed == 1) {
         struct flow_state_t init_state = {};
         init_state.req_id    = ((now & 0xFFFFFFFFULL) << 16) ^ ((u64)sport << 4) ^ (u64)dport;
         init_state.ip_rcv_ts = state ? state->ip_rcv_ts : now;
```

#### 2. Recommended Patch for [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c)
* Fix `sim_ipv6_tcp_pipeline` ([`kernel_sim_harness.c:898`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L898)) so `ip6h->payload_len` always includes `sizeof(struct tcphdr)` (`20B`) when `payload_len == 0` (0-byte IPv6 TCP `ACK`) while preserving `pkt_len == payload_len` when `payload_len >= 60`:
```diff
--- a/kernel_sim_harness.c
+++ b/kernel_sim_harness.c
@@ -895,7 +895,8 @@ int sim_ipv6_tcp_pipeline(const u32 saddr6[4], const u32 daddr6[4], u16 sport, u
     ip6h->version     = 6;
     ip6h->nexthdr     = IPPROTO_TCP;
     ip6h->hop_limit   = 64;
-    ip6h->payload_len = bpf_htons(payload_len > 40 ? (payload_len - 40) : payload_len);
+    u16 ip6_plen      = (payload_len >= 60) ? (payload_len - 40) : (sizeof(struct tcphdr) + payload_len);
+    ip6h->payload_len = bpf_htons(ip6_plen);
     memcpy(ip6h->saddr.in6_u.u6_addr32, saddr6, 16);
     memcpy(ip6h->daddr.in6_u.u6_addr32, daddr6, 16);
```

#### 3. Recommended Additions to [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) (`ADV-TEST-01` & `ADV-TEST-04`)
* Add explicit adversarial assertions in `test_adv_01_native_c_kernel_hook_emulation` and `test_adv_04_synthetic_raw_packet_vlan_ipv6_arp_and_malformed_fuzzing` for:
  * **60B/64B Ethernet-Padded 0-Byte TCP `ACK`**: Construct a 64-byte raw Ethernet frame (`14B Eth + 20B IPv4 [tot_len=40] + 20B TCP [doff=5, ack=1] + 10B L2 zero padding`) and assert `run_xdp_bytes` returns `XDP_PASS (2)` and emits `0` events.
  * **Malformed TCP `doff < 5` (`doff = 0, 2, 4`) & `doff = 15` (`doff * 4 > tot_len - ihl_len`)**: Feed into `xdp_ingress_filter`, `netif_receive_skb`, `kprobe__ip_rcv`, and `kprobe__tcp_v4_rcv`, asserting `0` events emitted and no `ingress_flow_map` pollution.
  * **0-Byte Handshake `SYN`, Pre-Consumption 0-Byte `ACK`, and Post-Consumption (`consumed == 1`) 0-Byte `ACK` / `FIN,ACK`**: Assert `0` spurious L2/L3/L4 events emitted on 0-byte `SYN` and post-consumption 0-byte `FIN,ACK`, and assert pre-consumption 0-byte `ACK` does not overwrite `FLAG_TCP_PSH` or `tcp_rcv_ts` dwell time.
