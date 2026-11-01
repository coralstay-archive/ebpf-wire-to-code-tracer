### Agent 03 Adversarial Falsification Report: L2/L3 Egress Pipeline & `skb_clone` Causality (`__tcp_transmit_skb` -> `ip_output`/`ip6_output` -> `net_dev_queue` -> `net_dev_xmit`)

#### Executive Summary of Falsified Claims & Discovered Defects
* **Defect 1 (Critical — `skb_clone` Pre-Clone `oskb` Leak in `skb_egress_map` & SLUB `kmem_cache` Pointer Recycling Corruption)**:
  - In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1562-L1629), [`kprobe____tcp_transmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1562-L1629) unconditionally inserts `PARM2` (`oskb`, the uncloned TCP write-queue buffer) into `skb_egress_map` at line 1621 (`skb_egress_map.update(&skb_ptr, &egress_key);`), completely ignoring `int clone_it = (int)PT_REGS_PARM3(ctx)`.
  - In Linux kernel [`__tcp_transmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238-L1269) (`net/ipv4/tcp_output.c:1238-1269`), 100% of TCP data transmissions pass `clone_it = 1` (`tcp_write_xmit` -> `tcp_transmit_skb(sk, skb, 1, gfp)`), which executes `skb = skb_clone(skb, gfp_mask)` at line 1267. Only the newly allocated `cloned_skb` (`!= oskb`) is passed down to `ip_queue_xmit` -> `ip_output` -> `net_dev_queue` -> `net_dev_xmit`.
  - While [`kprobe__ip_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1631-L1670) (lines 1640–1653) and [`kprobe__ip6_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1783-L1822) (lines 1792–1805) recover `cloned_skb` via the `PT_REGS_PARM2(ctx)` (`struct sock *sk`) fallback and [`TRACEPOINT_PROBE(net, net_dev_xmit)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1687-L1718) deletes `cloned_skb` at line 1715 (`skb_egress_map.delete(&skb_ptr)`), **the pre-clone `oskb` pointer is NEVER deleted from `skb_egress_map`**.
  - When the peer ACKs the TCP segment (`tcp_clean_rtx_queue` -> `sk_wmem_free_skb`), `oskb` is returned to the `skbuff_head_cache` (`kmem_cache`) with `SKB_DROP_REASON_NOT_SPECIFIED` / `SKB_CONSUMED` (`reason <= 2`), which [`TRACEPOINT_PROBE(skb, kfree_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L796-L819) ignores at line 801. Because `kmem_cache` LIFO-recycles hot `struct sk_buff *` addresses on the same CPU, subsequent unrelated packets (or UDP/non-tracked packets) allocated at `oskb`'s address hit the stale `skb_egress_map[&oskb]` entry, causing cross-request telemetry attribution corruption, false-positive egress drop alerts in `kfree_skb` Stage 1, and `skb_egress_map` capacity exhaustion.
* **Defect 2 (Critical — Complete Failure of UDP Egress Pipeline to Emit `L3_IP` and `L2_EGRESS` Events)**:
  - On UDP egress (`udp_sendmsg` -> `ip_make_skb` -> `udp_send_skb` -> `ip_send_skb` -> `ip_local_out` -> `ip_output` -> `net_dev_queue` -> `net_dev_xmit`), `__tcp_transmit_skb` is never called.
  - **Root Cause 2A (Hardcoded `IPPROTO_TCP` in `ip_output` / `ip6_output` Fallback)**: In [`kprobe__udp_sendmsg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L2067-L2098), `egress_key.proto` is stored in `egress_flow_map` as `IPPROTO_UDP (17)`. When [`kprobe__ip_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1640-L1655) or [`kprobe__ip6_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1792-L1807) runs, `skb_egress_map.lookup(&skb_ptr)` returns `NULL`, so it falls back to `PT_REGS_PARM2(ctx)` (`sk_arg`) and calls `populate_sock_flow_key(sk_arg, &fallback_key, IPPROTO_TCP, 1)` at lines 1650 and 1802. Because `IPPROTO_TCP (6)` is hardcoded, `egress_flow_map.lookup(ekey)` at lines 1655 and 1807 **100% fails (`NULL`) for every UDP packet**. Even worse, lines 1652 and 1804 write that wrong `IPPROTO_TCP` key into `skb_egress_map[&skb_ptr]`, causing [`tp_net_dev_queue`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1672-L1685) (line 1679) and [`tp_net_dev_xmit`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1687-L1718) (line 1696) to also fail `egress_flow_map.lookup(ekey)` and emit **zero `LAYER_IP_ROUTING` (`L3_IP`) and zero `LAYER_EGRESS_NIC` (`L2_EGRESS`) events for UDP**.
  - **Root Cause 2B (Unconnected UDP Server Socket `skc_daddr == 0, skc_dport == 0` Key Mismatch)**: For an unconnected UDP server socket (`bind(8080)`, `sendto(client_addr)`), `sk->__sk_common.skc_daddr == 0` and `skc_dport == 0` ([`net/ipv4/udp.c:1123-1135`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1123-L1135)). However, [`kprobe__udp_sendmsg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L2070-L2098) extracts the peer IP/port from `msg->msg_name` (or `tctx`) and inserts the full 4-tuple into `egress_flow_map`. Thus, reading `sk_arg` via `populate_sock_flow_key` in `kprobe__ip_output` produces `{daddr=0, dport=0}`, which still misses `egress_flow_map` even if `proto == IPPROTO_UDP`!
  - **Root Cause 2C (Hardcoded TCP Latency Baseline & Flags in `ip_output` / `ip6_output` / `net_dev_xmit`)**: For UDP, `estate->tcp_tx_ts` is `0`, so [`kprobe__ip_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1660) (line 1660) and [`kprobe__ip6_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1812) (line 1812) ignore `estate->sendmsg_ts` and emit a hardcoded `25000ULL` ns dummy duration, and lines 1668, 1712, and 1820 hardcode `FLAG_TCP_PSH | FLAG_TCP_ACK` on UDP packets.
  - **Root Cause 2D (Simulator & Test Suite Blind Spot)**: [`sim_udp_unconnected_pipeline`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L842-L885) in `kernel_sim_harness.c` stops after `kprobe__udp_sendmsg` and never calls `kprobe__ip_output`, `tracepoint__net__net_dev_queue`, or `tracepoint__net__net_dev_xmit`. [`test_adv_04`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1611-L1617) in `test_verification_suite.py` asserts `len(udp_evs) == 3`, cementing a false-positive test that hides the missing UDP L3/L2 egress events.
* **Defect 3 (High — Egress Drop Leak in `kfree_skb` Stage 1 & Premature Deletion on `NETDEV_TX_BUSY` / Multi-Segment TX in `tp_net_dev_xmit`)**:
  - **Root Cause 3A (`kfree_skb` Stage 1 Leak)**: In [`TRACEPOINT_PROBE(skb, kfree_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L808-L819), when an egress `skb` is dropped (`args->reason > 2`), Stage 1 looks up `ekey = skb_egress_map.lookup(&skb_ptr)`, emits the `FLAG_SKB_DROP` event, and immediately executes `return 0;` at line 817 **without calling `skb_egress_map.delete(&skb_ptr)`**. Because a dropped egress `skb` never reaches `tp_net_dev_xmit`, its `skb_ptr` permanently leaks in `skb_egress_map`.
  - **Root Cause 3B (`tp_net_dev_xmit` Premature Cleanup on `rc != NETDEV_TX_OK`)**: In [`net/core/dev.c:3803-3813`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c#L3803-L3813), when `ndo_start_xmit` returns `rc != NETDEV_TX_OK (0)` (e.g., `NETDEV_TX_BUSY = 0x10`), `trace_net_dev_xmit(skb, rc, dev, len)` still fires, and the Qdisc requeues the exact same `skb` (`dev_requeue_skb`) for a later `net_dev_xmit`. However, [`TRACEPOINT_PROBE(net, net_dev_xmit)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1714-L1715) unconditionally deletes both `egress_flow_map.delete(ekey)` and `skb_egress_map.delete(&skb_ptr)` even when `args->rc != 0`, breaking the retry transmission. Furthermore, unconditionally deleting `egress_flow_map.delete(ekey)` on the first segment of a multi-segment TCP write or prior to a TCP retransmission (`tcp_retransmit_skb` at [`tracer_kernel.c:1750`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1750)) destroys `egress_flow_map` state needed by subsequent segments/retransmissions.

---

### Detailed Trace & Ground-Truth Kernel Verification

#### 1. Exact Linux Kernel Egress Call Chain vs. `tracer_kernel.c`
* **Step 1: `kprobe____tcp_transmit_skb`** ([`tracer_kernel.c:1562-1629`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1562-L1629))
  - **Target Kernel Signature** ([`net/ipv4/tcp_output.c:1238-1240`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238-L1240)):
    `static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)`
  - **Kernel `skb_clone` Behavior** ([`net/ipv4/tcp_output.c:1251-1269`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1251-L1269)):
    - When `clone_it != 0` (which is true for all TCP data segments via `tcp_write_xmit` -> `tcp_transmit_skb(sk, skb, 1, gfp)` and `tcp_retransmit_skb` -> `__tcp_retransmit_skb` -> `tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC)`), `__tcp_transmit_skb` clones `skb` (`oskb`) into a newly allocated `struct sk_buff *` via `skb = skb_clone(skb, gfp_mask)` (or `pskb_copy` if cloned & head-shared).
    - Only when `clone_it == 0` (pure bare ACK in `tcp_send_ack` or SYN-ACK in `tcp_make_synack`) does `__tcp_transmit_skb` transmit the original `skb` directly without cloning.
  - **What `tracer_kernel.c` Does Wrong**:
    - At [`tracer_kernel.c:1563-1565`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1563-L1565), `kprobe____tcp_transmit_skb` reads `sk = (struct sock *)PT_REGS_PARM1(ctx)` and `skb = (struct sk_buff *)PT_REGS_PARM2(ctx)`, and at line 1621 unconditionally executes `skb_egress_map.update(&skb_ptr, &egress_key)`.
    - Whenever `clone_it != 0`, `skb_ptr` (`oskb`) stays on `sk->sk_write_queue` / `tcp_rtx_queue` and never reaches `ip_output`, `net_dev_queue`, or `net_dev_xmit`.
    - Consequently, `skb_egress_map[&oskb]` is **never removed** by `tp_net_dev_xmit`. When `oskb` is later freed upon ACK arrival (`tcp_clean_rtx_queue` -> `sk_wmem_free_skb`), the SLUB allocator (`skbuff_head_cache`) recycles `oskb`'s address for a new packet, polluting `skb_egress_map`.
  - **How `kprobe____tcp_transmit_skb` Must Work**:
    - Read `int clone_it = (int)PT_REGS_PARM3(ctx);`.
    - Only insert `skb_ptr` into `skb_egress_map` when `clone_it == 0`! When `clone_it != 0`, do NOT insert the uncloned `oskb` into `skb_egress_map`; instead, stash `egress_key` indexed by `u64 sk_key = (u64)sk;` in `skb_egress_map` (or resolve via `sk` in `kprobe__ip_output` / `kprobe__ip6_output`) so `kprobe__ip_output` / `kprobe__ip6_output` registers the actual post-clone `skb_ptr` (`PT_REGS_PARM3(ctx)`).

* **Step 2: `kprobe__ip_output` & `kprobe__ip6_output`** ([`tracer_kernel.c:1631-1670`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1631-L1670), [`tracer_kernel.c:1783-1822`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1783-L1822))
  - **Target Kernel Signatures**:
    - IPv4 ([`net/ipv4/ip_output.c:430`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_output.c#L430)): `int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)`
    - IPv6 ([`net/ipv6/ip6_output.c:190`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_output.c#L190)): `int ip6_output(struct net *net, struct sock *sk, struct sk_buff *skb)`
  - **Cloned TCP SKB Handling**:
    - In `kprobe__ip_output` / `kprobe__ip6_output`, `PT_REGS_PARM3(ctx)` is the **post-clone** `cloned_skb`, and `PT_REGS_PARM2(ctx)` is `struct sock *sk`.
    - Because `cloned_skb` is a newly allocated `sk_buff`, `skb_egress_map.lookup(&skb_ptr)` returns `NULL` (unless `cloned_skb` happened to collide with a leaked `oskb`!).
    - The fallback block at lines 1642–1654 (IPv4) and 1794–1806 (IPv6) reads `sk_arg = (struct sock *)PT_REGS_PARM2(ctx)`, constructs `fallback_key`, and calls `skb_egress_map.update(&skb_ptr, ekey)`.
  - **Why UDP Egress Completely Fails Here**:
    - First, at [`tracer_kernel.c:2092-2098`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L2092-L2098), `kprobe__udp_sendmsg` stores `egress_key` (`proto = IPPROTO_UDP`) in `egress_flow_map`, and does NOT store anything in `skb_egress_map` (because the UDP `skb` is constructed inside `udp_sendmsg` -> `ip_make_skb` after `kprobe__udp_sendmsg` entry).
    - Second, when `ip_send_skb` -> `ip_local_out` -> `ip_output(net, sk, skb)` runs, `kprobe__ip_output` (line 1650) and `kprobe__ip6_output` (line 1802) hardcode `IPPROTO_TCP` in `populate_sock_flow_key(sk_arg, &fallback_key, IPPROTO_TCP, 1)`.
    - Third, for unconnected UDP sockets (`sendto` without `connect`), `sk_arg->__sk_common.skc_daddr` and `skc_dport` are `0` at `ip_output` time, whereas `kprobe__udp_sendmsg` populated `egress_flow_map` with the actual client IP/port from `msg->msg_name` or `active_req_map`.
    - Fourth, if we stash `egress_key` in `skb_egress_map` keyed by `u64 sk_ptr = (u64)sk;` inside `kprobe__udp_sendmsg` (and `kprobe____tcp_transmit_skb` when `clone_it != 0`), then in `kprobe__ip_output` and `kprobe__ip6_output` we can immediately look up `u64 sk_key = (u64)sk_arg; struct flow_key_t *sk_ekey = skb_egress_map.lookup(&sk_key);`! That recovers the exact 4-tuple and protocol (`IPPROTO_UDP` or `IPPROTO_TCP`) in O(1) even for unconnected UDP sockets where `skc_daddr == 0`, and registers `skb_egress_map.update(&skb_ptr, &fallback_key)` for `tp_net_dev_queue` and `tp_net_dev_xmit`! (And if `sk_ekey` is not found, reading `sk_arg->sk_protocol` or trying `IPPROTO_TCP` then `IPPROTO_UDP` handles any direct `sk_arg` fallback).

* **Step 3: `tp_net_dev_queue` & `tp_net_dev_xmit` Ordering, GSO, and Slab Recycling** ([`tracer_kernel.c:1672-1718`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1672-L1718))
  - **Kernel Call Order in `net/core/dev.c`**:
    1. [`__dev_queue_xmit`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c#L4594) calls `trace_net_dev_queue(skb)` BEFORE entering the Qdisc (`__dev_xmit_skb`) or direct xmit (`dev_hard_start_xmit`).
    2. Inside [`xmit_one`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c#L3776-L3791) (`net/core/dev.c:3787-3788`):
       ```c
       rc = netdev_start_xmit(skb, dev, txq, more);
       trace_net_dev_xmit(skb, rc, dev, len);
       ```
       Notice that `netdev_start_xmit` (`ndo_start_xmit`) executes **BEFORE** `trace_net_dev_xmit`! Many virtual/loopback drivers call `dev_kfree_skb` / `consume_skb(skb)` inside `ndo_start_xmit`, firing `trace_kfree_skb(skb, ..., SKB_CONSUMED=1)` **before** `trace_net_dev_xmit` runs, while using the saved `skb` pointer and `len` for `trace_net_dev_xmit`.
       Therefore:
       - `TRACEPOINT_PROBE(skb, kfree_skb)` **correctly** ignores `args->reason <= 2` (`SKB_CONSUMED = 1`), so it does NOT delete `skb_egress_map[&skb_ptr]` before `tp_net_dev_xmit` runs.
       - However, when `args->reason > 2` (an actual packet drop in L3/Qdisc/driver), `trace_net_dev_xmit` will NEVER run (or the packet was dropped before xmit). Yet [`TRACEPOINT_PROBE(skb, kfree_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L808-L819) (Stage 1) forgets to call `skb_egress_map.delete(&skb_ptr);` at line 816!
    3. In [`TRACEPOINT_PROBE(net, net_dev_xmit)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1687-L1718):
       - If `args->rc == 0` (`NETDEV_TX_OK`), the driver accepted the `skb` and `skb_egress_map.delete(&skb_ptr)` **must** be called immediately so the `skb_ptr` cannot be recycled by `kmem_cache` with a stale `skb_egress_map` entry.
       - If `args->rc != 0` (e.g., `NETDEV_TX_BUSY`), [`dev_hard_start_xmit`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c#L3803-L3813) stops and the Qdisc requeues the same `skb` (`dev_requeue_skb`) for a later `net_dev_xmit`. Deleting `skb_egress_map` or `egress_flow_map` when `args->rc != 0` causes the subsequent retry `net_dev_xmit` to miss!
       - Even when `args->rc == 0`, deleting `egress_flow_map.delete(ekey)` at line 1714 destroys the flow state if a second TCP segment (or `tcp_retransmit_skb` at [`tracer_kernel.c:1750`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1750)) transmits on the same flow before the next `tcp_sendmsg`. Instead, `skb_egress_map.delete(&skb_ptr)` must always run on `args->rc == 0`, while `egress_flow_map` is cleaned up on socket close (`inet_sock_set_state` `TCP_CLOSE` at [`tracer_kernel.c:1915`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1915)) or overwritten on the next `sendmsg`.

---

### Exact File / Line Citations & Diff Recommendations

#### 1. [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)
* **Lines 808–819 (`TRACEPOINT_PROBE(skb, kfree_skb)` Stage 1)**: Delete `skb_ptr` from `skb_egress_map` when an egress `skb` is dropped (`args->reason > 2`) so the freed `sk_buff *` is not poisoned in `kmem_cache`.
* **Lines 1562–1629 (`kprobe____tcp_transmit_skb`)**: Check `int clone_it = (int)PT_REGS_PARM3(ctx);`. Only insert `skb_ptr` into `skb_egress_map` when `clone_it == 0`. Also stash `(u64)sk -> egress_key` in `skb_egress_map` so `kprobe__ip_output` / `kprobe__ip6_output` can resolve the post-clone `skb_ptr`.
* **Lines 1631–1670 (`kprobe__ip_output`), Lines 1687–1718 (`TRACEPOINT_PROBE(net, net_dev_xmit)`), and Lines 1783–1822 (`kprobe__ip6_output`)**:
  - In `kprobe__ip_output` and `kprobe__ip6_output`, when `skb_egress_map.lookup(&skb_ptr)` misses, first check `u64 sk_key = (u64)sk_arg; skb_egress_map.lookup(&sk_key)` (which resolves both cloned TCP SKBs and unconnected/connected UDP SKBs with their exact 4-tuple and `proto`). If that also misses, inspect `sk_arg->sk_protocol` (instead of hardcoding `IPPROTO_TCP`) before calling `populate_sock_flow_key`.
  - Only call `skb_egress_map.update(&skb_ptr, ekey)` **after** verifying `egress_flow_map.lookup(ekey) != NULL`, preventing untracked sockets from polluting `skb_egress_map`.
  - Compute `dur_ns` using `estate->tcp_tx_ts ? (now - estate->tcp_tx_ts) : (estate->sendmsg_ts ? (now - estate->sendmsg_ts) : 25000ULL)` and set TCP flags only when `ekey->proto == IPPROTO_TCP`.
  - In `TRACEPOINT_PROBE(net, net_dev_xmit)`, only delete `skb_egress_map.delete(&skb_ptr)` (and clean up `sk` entry) when `args->rc == 0` (`NETDEV_TX_OK`).
* **Lines 2067–2098 (`kprobe__udp_sendmsg`)**: Stash `u64 sk_key = (u64)sk; skb_egress_map.update(&sk_key, &egress_key);` alongside `egress_flow_map.update(&egress_key, &estate);` so `kprobe__ip_output` and `kprobe__ip6_output` can map the newly created UDP `skb_ptr` to `egress_key` even when `sk` is an unconnected UDP socket (`skc_daddr == 0, skc_dport == 0`).

```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -808,11 +808,13 @@ TRACEPOINT_PROBE(skb, kfree_skb) {
     /* Stage 1: Check Egress Flow Tracking */
     struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
     if (ekey) {
+        struct flow_key_t ekey_copy = *ekey;
+        skb_egress_map.delete(&skb_ptr);
-        struct egress_state_t *estate = egress_flow_map.lookup(ekey);
+        struct egress_state_t *estate = egress_flow_map.lookup(&ekey_copy);
         if (estate) {
             u32 len = 0;
             bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
-            emit_Drop_event(ctx, estate->req_id, ekey, args->reason, args->location, len, 0);
+            emit_Drop_event(ctx, estate->req_id, &ekey_copy, args->reason, args->location, len, 0);
             return 0;
         }
     }
@@ -1562,6 +1564,7 @@
 int kprobe____tcp_transmit_skb(struct pt_regs *ctx) {
     struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
     struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
+    int clone_it = (int)PT_REGS_PARM3(ctx);
     if (!sk || !skb) return 0;
 
     u16 family = get_sock_family(sk);
@@ -1617,8 +1620,13 @@
         egress_flow_map.update(&egress_key, &new_estate);
     }
 
-    u64 skb_ptr = (u64)skb;
-    skb_egress_map.update(&skb_ptr, &egress_key);
+    if (clone_it == 0) {
+        u64 skb_ptr = (u64)skb;
+        skb_egress_map.update(&skb_ptr, &egress_key);
+    }
+    u64 sk_ptr_key = (u64)sk;
+    skb_egress_map.update(&sk_ptr_key, &egress_key);
+
     u32 len = 0;
     bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
 
@@ -1642,27 +1650,41 @@
     if (!ekey) {
         struct sock *sk_arg = (struct sock *)PT_REGS_PARM2(ctx);
         if (sk_arg) {
-            u16 family = get_sock_family(sk_arg);
-            if (family == AF_INET || family == AF_INET6) {
-                populate_sock_flow_key(sk_arg, &fallback_key, IPPROTO_TCP, 1);
+            u64 sk_ptr_key = (u64)sk_arg;
+            struct flow_key_t *sk_ekey = skb_egress_map.lookup(&sk_ptr_key);
+            if (sk_ekey) {
+                fallback_key = *sk_ekey;
                 ekey = &fallback_key;
-                skb_egress_map.update(&skb_ptr, ekey);
+            } else {
+                u16 family = get_sock_family(sk_arg);
+                if (family == AF_INET || family == AF_INET6) {
+                    u16 sk_proto = 0;
+                    bpf_probe_read_kernel(&sk_proto, sizeof(sk_proto), &sk_arg->sk_protocol);
+                    u8 proto = (sk_proto == IPPROTO_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
+                    populate_sock_flow_key(sk_arg, &fallback_key, proto, 1);
+                    ekey = &fallback_key;
+                }
             }
         }
         if (!ekey) return 0;
     }
     struct egress_state_t *estate = egress_flow_map.lookup(ekey);
     if (!estate) return 0;
+    skb_egress_map.update(&skb_ptr, ekey);
 
     u64 now = bpf_ktime_get_ns();
     estate->ip_out_ts = now;
     u32 len = 0;
     bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
 
-    u64 dur_ns = estate->tcp_tx_ts ? (now - estate->tcp_tx_ts) : 25000ULL;
+    u64 base_ts = estate->tcp_tx_ts ? estate->tcp_tx_ts : estate->sendmsg_ts;
+    u64 dur_ns = base_ts ? (now - base_ts) : 25000ULL;
+    u8 ev_flags = (ekey->proto == IPPROTO_TCP) ? (FLAG_TCP_PSH | FLAG_TCP_ACK) : 0;
     emit_trace_event(ctx, estate->req_id,
                      ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
                      ekey->saddr_v6, ekey->daddr_v6, ekey->family,
                      STAGE_EGRESS, LAYER_IP_ROUTING,
                      dur_ns, len, 0,
-                     0, 0, 0, 0, FLAG_TCP_PSH | FLAG_TCP_ACK, 0, 0,
+                     0, 0, 0, 0, ev_flags, 0, 0,
                      "ip_output");
     return 0;
 }
@@ -1703,14 +1725,17 @@
     u64 dur_ns = base_ts ? (now - base_ts) : 15000ULL;
     u32 len = args->len;
     int rc = args->rc;
+    u8 ev_flags = (ekey->proto == IPPROTO_TCP) ? (FLAG_TCP_PSH | FLAG_TCP_ACK) : 0;
     emit_trace_event(args, estate->req_id,
                      ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
                      ekey->saddr_v6, ekey->daddr_v6, ekey->family,
                      STAGE_EGRESS, LAYER_EGRESS_NIC,
                      dur_ns, len, (s32)rc,
-                     0, 0, 0, 0, FLAG_TCP_PSH | FLAG_TCP_ACK, 0, 0,
+                     0, 0, 0, 0, ev_flags, 0, 0,
                      "net_dev_xmit");
-    egress_flow_map.delete(ekey);
-    skb_egress_map.delete(&skb_ptr);
+    if (rc == 0) {
+        egress_flow_map.delete(ekey);
+        skb_egress_map.delete(&skb_ptr);
+    }
     return 0;
 }
@@ -1794,27 +1819,41 @@
     if (!ekey) {
         struct sock *sk_arg = (struct sock *)PT_REGS_PARM2(ctx);
         if (sk_arg) {
-            u16 family = get_sock_family(sk_arg);
-            if (family == AF_INET || family == AF_INET6) {
-                populate_sock_flow_key(sk_arg, &fallback_key, IPPROTO_TCP, 1);
+            u64 sk_ptr_key = (u64)sk_arg;
+            struct flow_key_t *sk_ekey = skb_egress_map.lookup(&sk_ptr_key);
+            if (sk_ekey) {
+                fallback_key = *sk_ekey;
                 ekey = &fallback_key;
-                skb_egress_map.update(&skb_ptr, ekey);
+            } else {
+                u16 family = get_sock_family(sk_arg);
+                if (family == AF_INET || family == AF_INET6) {
+                    u16 sk_proto = 0;
+                    bpf_probe_read_kernel(&sk_proto, sizeof(sk_proto), &sk_arg->sk_protocol);
+                    u8 proto = (sk_proto == IPPROTO_UDP) ? IPPROTO_UDP : IPPROTO_TCP;
+                    populate_sock_flow_key(sk_arg, &fallback_key, proto, 1);
+                    ekey = &fallback_key;
+                }
             }
         }
         if (!ekey) return 0;
     }
     struct egress_state_t *estate = egress_flow_map.lookup(ekey);
     if (!estate) return 0;
+    skb_egress_map.update(&skb_ptr, ekey);
 
     u64 now = bpf_ktime_get_ns();
     estate->ip_out_ts = now;
     u32 len = 0;
     bpf_probe_read_kernel(&len, sizeof(len), &skb->len);
 
-    u64 dur_ns = estate->tcp_tx_ts ? (now - estate->tcp_tx_ts) : 25000ULL;
+    u64 base_ts = estate->tcp_tx_ts ? estate->tcp_tx_ts : estate->sendmsg_ts;
+    u64 dur_ns = base_ts ? (now - base_ts) : 25000ULL;
+    u8 ev_flags = (ekey->proto == IPPROTO_TCP) ? (FLAG_TCP_PSH | FLAG_TCP_ACK) : 0;
     emit_trace_event(ctx, estate->req_id,
                      ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
                      ekey->saddr_v6, ekey->daddr_v6, ekey->family,
                      STAGE_EGRESS, LAYER_IP_ROUTING,
                      dur_ns, len, 0,
-                     0, 0, 0, 0, FLAG_TCP_PSH | FLAG_TCP_ACK, 0, 0,
+                     0, 0, 0, 0, ev_flags, 0, 0,
                      "ip6_output");
     return 0;
 }
@@ -2096,6 +2135,8 @@
     estate.req_id = req_id;
     estate.sendmsg_ts = now;
     egress_flow_map.update(&egress_key, &estate);
+    u64 sk_ptr_key = (u64)sk;
+    skb_egress_map.update(&sk_ptr_key, &egress_key);
 
     emit_trace_event(ctx, req_id,
                      egress_key.saddr, egress_key.daddr, egress_key.sport, egress_key.dport,
```

#### 2. [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c) & [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py)
* **In [`kernel_sim_harness.c:295-321`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L295-L321) (`sim_http_200_pipeline`)**:
  - Pass `regs.regs[2] = 1;` (`clone_it = 1`) to `kprobe____tcp_transmit_skb(&regs)` and assert after `tracepoint__net__net_dev_xmit(&tp_xmit)` that `skb_egress_map.lookup(&(u64){(u64)&tx_skb_orig}) == NULL` and `skb_egress_map.lookup(&(u64){(u64)&tx_skb_cloned}) == NULL`, proving zero pre-clone `oskb` leak.
* **In [`kernel_sim_harness.c:842-885`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L842-L885) (`sim_udp_unconnected_pipeline`)**:
  - Extend the UDP egress simulation after `kprobe__udp_sendmsg(&regs)` to allocate `struct sk_buff udp_tx_skb`, invoke `kprobe__ip_output(&regs)`, `tracepoint__net__net_dev_queue(&tp_q)`, and `tracepoint__net__net_dev_xmit(&tp_xmit)`, and update [`test_verification_suite.py:1611-1617`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1611-L1617) (`test_adv_04`) to assert that UDP egress emits `ip_output` (`LAYER_IP_ROUTING` / `L3_IP`) and `net_dev_xmit` (`LAYER_EGRESS_NIC` / `L2_DATALINK`) with matching `req_id` and cleans up `skb_egress_map`.
