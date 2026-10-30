# Agent 08 Adversarial Falsification & Target-Kernel Verification Report: Visualization (DOT/SVG/Mermaid/FlameGraph), Interactive Web UI & TUI Wire-to-Code Alignment

### 1. Executive Summary & Overall Verdict

* **Verification Role**: Agent 08 — Visualization (`DOT`/`SVG`/`Mermaid`/`FlameGraph`), Interactive Web Dashboard (`trace_dashboard.html` / `trace_report.html`), Interactive TUI (`run_interactive_tui`), and End-to-End Wire-to-Code (`L2 NIC -> L3/L4 Kernel -> L5/L6 Socket/Sched/Futex -> L7 C++ file:line -> Egress/Drop`) Purpose Alignment Verifier.
* **Target Environment & Ground Truth**:
  - Target Kernel Release: `Rocky Linux 9.8 (5.14.0-687.10.1.el9_8.0.1.aarch64)`
  - Kernel Source Reference: [dropreason-core.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h), [skb.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h), [tcp.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h)
  - Verification Harness Scratch Script: [verify_agent08.py](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/520741f5-6723-47b3-b5f3-c1f7a0de9b6e/scratch/verify_agent08.py)
* **Overall Falsification Verdict**: **6 CRITICAL/HIGH DEFECTS FALSIFIED AND REPRODUCED (WITH COMPLETE DROP-IN PATCHES)**
  - Even though `test_verification_suite.py` passed 23 of 24 tests out of the box (with `ADV-TEST-12` failing due to a process-startup race and CLI flag mismatch), adversarial cross-falsification proved that those passing tests relied on shallow substring assertions against **static hardcoded dictionaries** in [`run_tracer_pipeline()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1059-L1415), masking severe structural breaks between the C eBPF telemetry engine, [`RequestCorrelator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L291-L396), and the visualization/UI layer.
  - **Summary of the 6 Falsified Defects**:
    1. **Defect 08-01 (Critical — Total Disconnect Between `RequestCorrelator` and Visualization Engines)**: [`run_tracer_pipeline()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1059-L1415) never instantiates `RequestCorrelator` or calls `decode_event_metadata()`. It feeds hardcoded floating-point numbers (`l2_in_ms = 0.042`, `l3_in_ms = 0.038`, etc.) into DOT/SVG/HTML/Mermaid/FlameGraph/TUI.
    2. **Defect 08-02 (Critical — Inverted Thread Handoff Order & Omitted `delta_ns`, CPU Core Migration, `file:line`, and `SKB_DROP_REASON_*`)**: In [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1197-L1249), `L6_PRE_COMPUTE_GATE` (`tid=10425, parent_tid=10420`) is placed at Hop 6 **before** Acceptor's `parse_http_request` (`tid=10420`) at Hop 7, causing the timeline to jump `10420 -> 10425 -> 10420 -> 10425` with two broken `Thread Handoff` edges. Furthermore, [`RequestCorrelator._finalize_request()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L347) sorts primarily by `layer_type` (`1..6`) instead of `timestamp`, scrambling chronological mid-request handoffs and block I/O events. Four of the five L7 functions lack `file:line` (`mock_server.cpp:XX`), and DOT/Mermaid/FlameGraph omit `delta_ns`, CPU core IDs (`CPU #0 -> CPU #2`), and `SKB_DROP_REASON_*`.
    3. **Defect 08-03 (High — `decode_event_metadata()` & `xdp_ingress_filter` Blind Spot on `kfree_skb` Drop Reasons, TCP Retransmits, and 802.1Q `vlan_id`)**: [`decode_event_metadata()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L228-L239) ignores `FLAG_SKB_DROP` (`1 << 5`) and `FLAG_TCP_RETRANSMIT` (`1 << 4`), misdecoding `kfree_skb`'s `args->reason` (e.g., `6` = `SKB_DROP_REASON_SOCKET_RCVBUFF`) as `pkt_len = 6, ttl = 0`. Meanwhile, [`xdp_ingress_filter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L414-L488) parses 802.1Q/802.1AD VLAN tags (`vlan_hdr[0]`) to advance `nh_off` but discards the 12-bit `vlan_id` (`bpf_ntohs(vlan_hdr[0]) & 0x0FFF`) instead of packing it into `ev->ip` bits `[31:16]`.
    4. **Defect 08-04 (Critical — Web UI `inspectHop()` Stub, Off-By-One SVG Click Mapping When `drop_count > 0`, Non-Functional `Zoom-In Probe` Button, and Unhandled CLI `--ui web` / `--serve rest`)**: In [`render_interactive_dashboard_html()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1020-L1048), `inspectHop(hopObj)` only dumps raw JSON into `#kernel-meta-view` without updating `#cpp-source-view` or `#asm-source-view`; `svgNodes.forEach((nodeEl, idx) => ... DIAGNOSIS_DATA.hop_timeline[idx])` is shifted by `+1` whenever `drop_count > 0` because `alert_node` is `svgNodes[0]`; `applyZoomInProbe()` and `filterLayer()` are `console.log` stubs; top control buttons call `filterLayer()` instead of `POST /api/v1/traces`; and [`main()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1888-L1900) ignores `--ui web` and `--serve rest`.
    5. **Defect 08-05 (Critical — Unescaped XSS `<script>` Breakout, Graphviz DOT Quote Crash, Mermaid Syntax Corruption, FlameGraph Sibling Stack Accumulation, and TUI Hardcoded Strings)**: Embedding unescaped `json.dumps(diag)` into `<script>` ([`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L995)) allows `</script><script>alert(1)</script>` breakout XSS; unescaped `"` in C++ symbols (`operator""_json`) crashes `dot -Tsvg` with `CalledProcessError`; [`render_flamegraph_folded()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1445-L1458) appends every sequential `LAYER_USER_FUNC` hop to `app_stack` without popping, nesting sibling functions across Acceptor (`TID 10420`) and Worker (`TID 10425`) into a fake 6-deep recursive stack; and [`run_interactive_tui()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1802-L1838) prints hardcoded text on commands `[1]`, `[4]`, `[5]`, `[6]`, `[7]`.
    6. **Defect 08-06 (Medium — `ADV-TEST-12` Process Startup Race & CLI Flag Mismatch `--fast-mode` vs `--fast-storage`)**: [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2044) passes `--fast-mode` to `mock_server` (which expects `--fast-storage` at [`mock_server.cpp:124`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L124)) and uses a single `time.sleep(0.25)` without a socket retry loop, failing with `[Errno 61] Connection refused` on cold binary execution.

---

### 2. Phase-by-Phase Audit Results (Phase 1 through Phase 6)

#### Phase 1: Target Kernel BTF & Header Ground Truth (`5.14.0-687.10.1.el9_8.0.1.aarch64`)
* **Verified Kernel Artifacts**:
  - Cross-checked [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c) and [`kray_bpf_core_compat.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h) against the target Rocky Linux 9.8 kernel headers in `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/`.
  - Confirmed `TRACE_EVENT(kfree_skb, ...)` in [skb.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L15-L45) exposes `void *skbaddr`, `void *location`, `unsigned short protocol`, and `enum skb_drop_reason reason`.
  - Confirmed `enum skb_drop_reason` in [dropreason-core.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h#L69-L265) defines exact integer values:
    * `SKB_NOT_DROPPED_YET = 0`
    * `SKB_CONSUMED = 1`
    * `SKB_DROP_REASON_NOT_SPECIFIED = 2`
    * `SKB_DROP_REASON_NO_SOCKET = 3`
    * `SKB_DROP_REASON_SOCKET_CLOSE = 4`
    * `SKB_DROP_REASON_SOCKET_FILTER = 5`
    * `SKB_DROP_REASON_SOCKET_RCVBUFF = 6`
    * `SKB_DROP_REASON_TCP_CSUM = 9`
    * `SKB_DROP_REASON_NETFILTER_DROP = 11`
    * `SKB_DROP_REASON_SOCKET_BACKLOG = 22`
    * `SKB_DROP_REASON_TCP_FLAGS = 23`
    * `SKB_DROP_REASON_TCP_ZEROWINDOW = 25`
    * `SKB_DROP_REASON_TCP_LISTEN_OVERFLOW = 33`
    * `SKB_DROP_REASON_TCP_RESET = 37`
    * `SKB_DROP_REASON_QDISC_DROP = 56`
* **Phase 1 Falsification Finding**:
  - While `tracer_kernel.c` (`kfree_skb` tracepoint at lines 751–804) reads `args->reason` and assigns `ev->ip = (u64)args->reason; ev->flags = FLAG_SKB_DROP;`, the user-space Python agent [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py) contains zero mapping for `enum skb_drop_reason` and fails to decode `FLAG_SKB_DROP` in `decode_event_metadata()`.
  - Additionally, `xdp_ingress_filter` in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L430-L488) parses 802.1Q/802.1AD VLAN tags (`vlan_hdr[0]`) but leaves bits `[31:16]` of `encoded_ip = ((u64)rx_cpu << 32) | (u64)state.pkt_len` as `0` instead of packing `vlan_id = bpf_ntohs(vlan_hdr[0]) & 0x0FFF`.

#### Phase 2: Native C Hook Simulation (`kernel_sim_harness.c`) & ABI Bit-Packing Audit
* **Verified Native Execution**:
  - Compiled `kernel_sim_harness.c` + `tracer_kernel.c` into `libkernel_sim.dylib` and executed all 21 eBPF hook functions across the 56-byte `struct event_t` (`KrayEvent`) binary ABI.
* **Phase 2 Falsification Finding**:
  - When `sim_kfree_skb_test(saddr, daddr, sport, dport, 6, 2)` is invoked on `libkernel_sim.dylib`, the C hook emits `layer_type = LAYER_KERNEL_NET (2)`, `call_depth = OSI_L4_TCP (4)`, `ip = 6`, `flags = FLAG_SKB_DROP (32)`.
  - Passing that real C event into `tracer_agent.decode_event_metadata(ev)` returns `{'osi_layer_id': 4, 'osi_layer_name': 'L4_TRANSPORT_TCP', 'ttl': 0, 'ihl_bytes': 0, 'pkt_len': 6, 'duration_ns': 0}` — completely losing `drop_reason = SKB_DROP_REASON_SOCKET_RCVBUFF (6)` and falsely reporting a 6-byte packet with `ttl = 0`.

#### Phase 3: `RequestCorrelator` & Dynamic Wire-to-Code Pipeline Audit
* **Phase 3 Falsification Findings**:
  - [`RequestCorrelator._finalize_request()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L347) sorts events by `key=lambda e: (int(e.layer_type), int(e.timestamp), int(e.is_return))`. Because `LAYER_USER_ENTRY` is `3` and `LAYER_USER_FUNC` is `4`, sorting by `layer_type` first forces `L6_PRE_COMPUTE_GATE` (`sched_waking+sched_switch`, which happens **after** Acceptor's `parse_http_request` and `validate_auth_header`) and `L5_SYSCALL_MEM` (`block_rq_complete`, which happens **inside** Worker's `execute_storage_query`) ahead of all user-space functions!
  - [`run_tracer_pipeline()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1059-L1415) is 100% disconnected from `RequestCorrelator`. It never ingests events or builds `hop_timeline` dynamically.

#### Phase 4: Visualization Engines Audit (`DOT`/`SVG`, `Mermaid`, `FlameGraph`)
* **Phase 4 Falsification Findings**:
  - `render_graphviz_dot_and_svg` omits `delta_ns`, `file:line` (`mock_server.cpp:XX`), CPU core IDs/migration (`CPU #0 -> CPU #2`), and `SKB_DROP_REASON_*` badges; hardcodes Tier 3 module subgraphs to `mock_server` and `libcrypto_mock.so`; and crashes (`CalledProcessError`) when a symbol contains double quotes (`"`).
  - `render_mermaid_sequence` omits Acceptor-to-Worker thread handoff, CPU migration, `file:line`, and `SKB_DROP_REASON_*`, and fails to sanitize `;`, `<`, `>`.
  - `render_flamegraph_folded` never pops `app_stack`, turning sequential sibling functions across Acceptor (`TID 10420`) and Worker (`TID 10425`) into a single 6-deep fake recursive call stack: `mock_server_main;parse_http_request;validate_auth_header;libcrypto_mock.so+0x...;execute_storage_query;format_http_response`.

#### Phase 5: Interactive Web Dashboard (`trace_dashboard.html`), REST API, & Interactive TUI Audit
* **Phase 5 Falsification Findings**:
  - `inspectHop(hopObj)` in `trace_dashboard.html` only writes raw JSON to `#kernel-meta-view` and never updates `#cpp-source-view` or `#asm-source-view`.
  - Clicking SVG nodes in `trace_dashboard.html` uses `svgNodes.forEach((nodeEl, idx) => ... DIAGNOSIS_DATA.hop_timeline[idx])`, which is off by `+1` whenever `drop_count > 0` because `alert_node` is the first `<g class="node">` in the SVG DOM.
  - `applyZoomInProbe()` and `filterLayer()` are `console.log` stubs, and `main()` ignores `--ui web` and `--serve rest`.
  - `run_interactive_tui()` prints hardcoded static text instead of reading `diag`.

#### Phase 6: Adversarial Injection & Test Suite Audit
* **Phase 6 Falsification Findings**:
  - Injecting `</script><script>alert(1)</script>` into a symbol breaks out of `<script>const DIAGNOSIS_DATA = ...` in `trace_dashboard.html`.
  - `ADV-TEST-12` in `test_verification_suite.py` fails intermittently with `[Errno 61] Connection refused` and passes `--fast-mode` instead of `--fast-storage` to `mock_server`.

---

### 3. Detailed Technical Proof of All 6 Falsified Defects

#### Defect 08-01: Total Disconnect Between `RequestCorrelator` and Visualization Engines
* **Location**: [`tracer_agent.py` lines 1059–1415 (`run_tracer_pipeline`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1059-L1415)
* **Evidence**:
  - In `run_tracer_pipeline()`, lines 1093–1116 hardcode every single latency value:
    * `l2_in_ms = 0.042`
    * `l3_in_ms = 0.038`
    * `l4_in_ms = 0.065`
    * `sock_in_ms = 0.210`
    * `l5_in_ms = 0.047`
    * `l6_lock_wait_ms = 0.115`
    * `l6_runq_ms = 0.065`
    * `parse_ms = 0.420`
    * `auth_wrapper_ms = 0.230`
    * `crypto_Verify_ms = 3.450`
    * `storage_total_ms = 1.150 if fast_mode else 16.750`
  - Neither `RequestCorrelator` nor `decode_event_metadata()` is ever called inside `run_tracer_pipeline()`.
  - Furthermore, `source_code_evidence` (lines 1301–1303) only extracts source code for `"execute_storage_query"`, leaving `"parse_http_request"`, `"validate_auth_header"`, and `"format_http_response"` without any `file:line` or C++ source snippet in the diagnosis report or Web UI.

#### Defect 08-02: Inverted Thread Handoff Order & Omitted Wire-to-Code Telemetry (`delta_ns`, CPU Migration, `file:line`, `SKB_DROP_REASON_*`)
* **Location**:
  - [`mock_server.cpp` lines 173–190](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L173-L190)
  - [`tracer_agent.py` lines 347 (`_finalize_request`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L347) and [lines 1197–1259 (`hop_timeline`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1197-L1259)
* **Evidence**:
  - In the actual C++ server ([`mock_server.cpp`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L173-L183)), the Acceptor thread (`TID 10420`) executes:
    1. `recv()` (`tcp_recvmsg` + `skb_copy_datagram_iovec`)
    2. `parse_http_request()` (`mock_server.cpp:41`)
    3. `validate_auth_header()` (`mock_server.cpp:54`) -> `libcrypto_mock.so`
    4. `g_queue_cv.notify_one()` (Futex + `sched_waking` + `sched_switch` handoff from `TID 10420` on `CPU #0` to Worker `TID 10425` on `CPU #2`)
    5. Worker thread (`TID 10425`) executes `execute_storage_query()` (`mock_server.cpp:65`) -> `format_http_response()` (`mock_server.cpp:83`) -> `send()`.
  - Yet in [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1197-L1249):
    * Hop 6 (`index 5`) is `L6_PRE_COMPUTE_GATE` with `tid=10425, parent_tid=10420`.
    * Hop 7 (`index 6`) is `parse_http_request` with `tid=10420, parent_tid=0`.
    * Hop 8 (`index 7`) is `validate_auth_header` with `tid=10420, parent_tid=0`.
    * Hop 9 (`index 8`) is `libcrypto_mock.so` with `tid=10420, parent_tid=0`.
    * Hop 10 (`index 9`) is `execute_storage_query` with `tid=10425, parent_tid=10420`.
  - Because `hop_timeline` jumps `10420 -> 10425 -> 10420 -> 10425`, [`render_graphviz_dot_and_svg()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L848-L855) draws **two** separate dashed blue `Thread Handoff` edges (`hop_5 -> hop_6` and `hop_9 -> hop_10`), falsely claiming the request handed off to the worker thread before `parse_http_request`, jumped back to the acceptor thread without a handoff, and then handed off to the worker thread a second time!

#### Defect 08-03: `decode_event_metadata()` & `xdp_ingress_filter` Blind Spot on `kfree_skb` Drop Reasons, TCP Retransmits, and 802.1Q `vlan_id`
* **Location**:
  - [`tracer_kernel.c` lines 430–488 (`xdp_ingress_filter`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L430-L488) and [lines 751–804 (`kfree_skb`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L751-L804)
  - [`tracer_agent.py` lines 199–285 (`decode_event_metadata`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L199-L285)
* **Evidence**:
  - In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L801-L802), `kfree_skb` sets `ev->call_depth = OSI_L4_TCP; ev->ip = (u64)args->reason; ev->flags = FLAG_SKB_DROP;`.
  - In [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L228-L239), `decode_event_metadata()` checks `if cdepth in (OSI_L3_IP, OSI_L4_TCP):` without checking `ev.flags & FLAG_SKB_DROP` or `ev.flags & FLAG_TCP_RETRANSMIT`, unconditionally unpacking `ttl = (raw_ip >> 24) & 0xFF` and `pkt_len = raw_ip & 0xFFFF`. Thus `reason = 6` (`SKB_DROP_REASON_SOCKET_RCVBUFF`) becomes `ttl = 0, pkt_len = 6`, and `drop_reason` is completely absent.
  - In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L430-L445), `xdp_ingress_filter` parses up to two `802.1Q`/`802.1AD` VLAN headers (`vlan_hdr[0]`, `vlan_hdr[1]`), yet never stores `vlan_id = bpf_ntohs(vlan_hdr[0]) & 0x0FFF` into `state` or `encoded_ip`. Since `encoded_ip` at line 486 is `((u64)rx_cpu << 32) | (u64)state.pkt_len`, bits `[31:16]` are unused `0x0000` on ingress and can losslessly carry the 12-bit `vlan_id`.

#### Defect 08-04: Web UI `inspectHop()` Stub, SVG Click Off-By-One Bug, Non-Functional `Zoom-In Probe` Button, and Unhandled CLI `--ui web` / `--serve rest`
* **Location**: [`tracer_agent.py` lines 912–1056 (`render_interactive_dashboard_html`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L912-L1056) and [lines 1888–1900 (`main`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1888-L1900)
* **Evidence**:
  - **Broken `inspectHop(hopObj)`** ([lines 1020–1027](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1020-L1027)):
    * Only executes `kernelView.textContent = JSON.stringify(hopObj, null, 2);` and calls `zoomInSelectedNode(hopObj.symbol_or_probe, hopObj.module)`.
    * Never updates `#cpp-source-view` or `#asm-source-view` when the user clicks different L7 or kernel hops!
    * For stripped offsets (`libcrypto_mock.so+0x1140`), `zoomInSelectedNode()` writes the symbol into `#zoom-symbol` instead of populating `#zoom-offset` (`libcrypto_mock.so:0x1140`) and clearing `#zoom-symbol`.
  - **Off-By-One SVG Click Handler** ([lines 1038–1047](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1038-L1047)):
    * Uses `svgNodes.forEach((nodeEl, idx) => ... DIAGNOSIS_DATA.hop_timeline[idx])`.
    * When `drop_count > 0`, Graphviz emits `<g id="node1" class="node"><title>alert_node</title>...` as `svgNodes[0]`, and `<title>hop_1</title>` as `svgNodes[1]`. Clicking `hop_1` inspects `hop_timeline[1]` (`hop_2`), and clicking the final hop inspects `undefined`!
    * Furthermore, when `dot` is unavailable, the fallback SVG ([lines 881–887](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L881-L887)) emits zero `<g class="node">` elements, making clicking impossible.
  - **Stubbed Buttons & Unhandled CLI Modes**:
    * `filterLayer(layer)` (line 998) and `applyZoomInProbe()` (line 1034) only call `console.log(...)`.
    * Top toolbar buttons `[Run Baseline Trace]`, `[Run Optimized (--fast-mode) Trace]`, and `[Simulate RingBuf Overflow (128 Drops)]` ([lines 948–950](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L948-L950)) mistakenly call `onclick="filterLayer('ALL')"` / `onclick="filterLayer('L7')"` / `onclick="filterLayer('KERNEL')"` instead of invoking `POST /api/v1/traces`.
    * In `main()` ([lines 1888–1900](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1888-L1900)), only `if args.ui == "tui":` is checked; passing `--ui web` or `--serve rest` prints the console matrix and exits immediately without starting `serve_rest_api()`.

#### Defect 08-05: XSS / DOT / Mermaid / FlameGraph Injection & Syntax Corruption + TUI Hardcoded Strings
* **Location**:
  - [`tracer_agent.py` line 773 (`render_graphviz_dot_and_svg`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L773)
  - [`tracer_agent.py` line 995 (`render_interactive_dashboard_html`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L995)
  - [`tracer_agent.py` lines 1417–1458 (`render_mermaid_sequence`, `render_flamegraph_folded`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1417-L1458)
  - [`tracer_agent.py` lines 1802–1838 (`run_interactive_tui`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1802-L1838)
* **Evidence**:
  - **DOT Crash**: `hop['symbol_or_probe']` containing `"` (such as C++ user-defined literals `operator""_json(char const*, unsigned long)`) produces unescaped `label="[L7_COMPUTE_ALU] operator""_json..."`, causing `dot -Tsvg` to abort with `Error: syntax error in line ...`.
  - **HTML `<script>` Breakout XSS**: `const DIAGNOSIS_DATA = {diag_json_str};` embeds raw `json.dumps(diag)` inside `<script>`. Any symbol or source comment containing `</script><script>alert(1)</script>` terminates the script block and executes arbitrary JavaScript in the browser.
  - **FlameGraph Sibling Stack Corruption**: `render_flamegraph_folded()` ([lines 1455–1457](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1455-L1457)) runs `app_stack.append(sym)` on every `LAYER_USER_FUNC` hop and never pops, producing:
    `mock_server_main;parse_http_request;validate_auth_header;libcrypto_mock.so+0x...;execute_storage_query;format_http_response 280`
    This claims `format_http_response` on Worker `TID 10425` was called inside `execute_storage_query`, which was called inside `libcrypto_mock.so`, inside `validate_auth_header`, inside `parse_http_request` on Acceptor `TID 10420`!

#### Defect 08-06: `ADV-TEST-12` Process Startup Race & CLI Flag Mismatch (`--fast-mode` vs `--fast-storage`)
* **Location**: [`test_verification_suite.py` lines 2033–2047](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2033-L2047)
* **Evidence**:
  - Line 2035 launches `[str(MOCK_SERVER_BIN), "--port", str(port), "--fast-mode", "--single-shot"]`, whereas [`mock_server.cpp` line 124](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L124) checks `if (arg == "--fast-storage" || arg == "--fast")`.
  - Line 2040 performs a single `time.sleep(0.25)` before `socket.create_connection(("127.0.0.1", port))`, which fails with `ConnectionRefusedError: [Errno 61] Connection refused` when the OS scans or initializes the newly compiled binary.

---

### 4. Concrete Wire-to-Code Patch Proposals

#### 4.1 Patch for `tracer_kernel.c`: Pack 12-bit 802.1Q `vlan_id` into L2 Ingress `ev->ip` Bits `[31:16]`
* **Target File**: [`tracer_kernel.c` lines 414–491](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L414-L491)
* **Patch Code**:
```c
    u16 vlan_id = 0;
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            if (data + nh_off + 4 > data_end)
                return XDP_PASS;
            u16 *vlan_hdr = (u16 *)(data + nh_off);
            if (vlan_id == 0)
                vlan_id = bpf_ntohs(vlan_hdr[0]) & 0x0FFF;
            h_proto = vlan_hdr[1];
            nh_off += 4;
        }
    }
    /* ... after packet parsing ... */
    u32 rx_cpu = bpf_get_smp_processor_id();
    u64 encoded_ip = ((u64)rx_cpu << 32) | (((u64)vlan_id & 0x0FFFULL) << 16) | (u64)state.pkt_len;
    emit_trace_event(req_id, state.ingress_ns, 0, LAYER_INGRESS_NIC, OSI_L2_DATALINK,
                     encoded_ip, 0, 0, state.tcp_flags, 0);
```

#### 4.2 Patch for `tracer_agent.py`: `SKB_DROP_REASON_NAMES`, `decode_event_metadata()`, and Chronological `RequestCorrelator` Ordering
* **Target File**: [`tracer_agent.py` lines 199–355](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L199-L355)
* **Patch Code**:
```python
# Grounded in Rocky Linux 9.8 (5.14.0-687.10.1.el9_8.0.1.aarch64) include/net/dropreason-core.h
SKB_DROP_REASON_NAMES: Dict[int, str] = {
    0: "SKB_NOT_DROPPED_YET",
    1: "SKB_CONSUMED",
    2: "SKB_DROP_REASON_NOT_SPECIFIED",
    3: "SKB_DROP_REASON_NO_SOCKET",
    4: "SKB_DROP_REASON_SOCKET_CLOSE",
    5: "SKB_DROP_REASON_SOCKET_FILTER",
    6: "SKB_DROP_REASON_SOCKET_RCVBUFF",
    7: "SKB_DROP_REASON_UNIX_DISCONNECT",
    8: "SKB_DROP_REASON_PKT_TOO_SMALL",
    9: "SKB_DROP_REASON_TCP_CSUM",
    10: "SKB_DROP_REASON_UDP_CSUM",
    11: "SKB_DROP_REASON_NETFILTER_DROP",
    12: "SKB_DROP_REASON_OTHERHOST",
    13: "SKB_DROP_REASON_IP_CSUM",
    14: "SKB_DROP_REASON_IP_INHDR",
    15: "SKB_DROP_REASON_IP_RPFILTER",
    22: "SKB_DROP_REASON_SOCKET_BACKLOG",
    23: "SKB_DROP_REASON_TCP_FLAGS",
    25: "SKB_DROP_REASON_TCP_ZEROWINDOW",
    33: "SKB_DROP_REASON_TCP_LISTEN_OVERFLOW",
    37: "SKB_DROP_REASON_TCP_RESET",
    56: "SKB_DROP_REASON_QDISC_DROP",
}


def decode_tcp_flags_list(flags: int) -> List[str]:
    out: List[str] = []
    if flags & FLAG_TCP_SYN:
        out.append("SYN")
    if flags & FLAG_TCP_PSH:
        out.append("PSH")
    if flags & FLAG_TCP_ACK:
        out.append("ACK")
    if flags & FLAG_TCP_FIN:
        out.append("FIN")
    return out


def decode_event_metadata(ev: KrayEvent) -> Dict[str, Any]:
    ltype = int(ev.layer_type)
    cdepth = int(ev.call_depth)
    raw_ip = int(ev.ip)
    dur_ns = int(ev.duration_ns)
    flags = int(ev.flags)
    tcp_flags = decode_tcp_flags_list(flags)

    if ltype == LAYER_USER_FUNC:
        return {
            "osi_layer_id": OSI_L7_APP,
            "osi_layer_name": "L7_COMPUTE_ALU",
            "user_call_depth": cdepth,
            "instruction_pointer": raw_ip,
            "is_return": bool(ev.is_return),
            "duration_ns": dur_ns,
            "thread_handoff": bool(flags & FLAG_THREAD_HANDOFF),
            "stripped": bool(flags & FLAG_STRIPPED_SYMBOL),
        }

    if cdepth == OSI_L2_DATALINK:
        cpu_id = (raw_ip >> 32) & 0xFFFFFFFF
        mid_16 = (raw_ip >> 16) & 0xFFFF
        pkt_len = raw_ip & 0xFFFF
        vlan_id = (mid_16 & 0x0FFF) if ltype == LAYER_INGRESS_NIC else 0
        rc = 0 if ltype == LAYER_INGRESS_NIC else mid_16
        return {
            "osi_layer_id": OSI_L2_DATALINK,
            "osi_layer_name": "L2_DATALINK",
            "cpu_id": cpu_id,
            "vlan_id": vlan_id,
            "rc": rc,
            "pkt_len": pkt_len,
            "tcp_flags": tcp_flags,
            "duration_ns": dur_ns,
        }

    if cdepth in (OSI_L3_IP, OSI_L4_TCP):
        if flags & FLAG_SKB_DROP:
            reason_code = raw_ip & 0xFFFF
            reason_name = SKB_DROP_REASON_NAMES.get(reason_code, f"SKB_DROP_REASON_CODE_{reason_code}")
            return {
                "osi_layer_id": cdepth,
                "osi_layer_name": "L4_TRANSPORT_TCP" if cdepth == OSI_L4_TCP else "L3_NETWORK_IP",
                "is_skb_drop": True,
                "drop_reason_code": reason_code,
                "drop_reason": reason_name,
                "tcp_flags": tcp_flags,
                "duration_ns": dur_ns,
            }
        if flags & FLAG_TCP_RETRANSMIT:
            return {
                "osi_layer_id": cdepth,
                "osi_layer_name": "L4_TRANSPORT_TCP",
                "is_retransmit": True,
                "retransmits": raw_ip & 0xFFFF,
                "tcp_flags": tcp_flags,
                "duration_ns": dur_ns,
            }
        ttl = (raw_ip >> 24) & 0xFF
        ihl_bytes = (raw_ip >> 16) & 0xFF
        pkt_len = raw_ip & 0xFFFF
        return {
            "osi_layer_id": cdepth,
            "osi_layer_name": "L3_NETWORK_IP" if cdepth == OSI_L3_IP else "L4_TRANSPORT_TCP",
            "ttl": ttl,
            "ip_ttl": ttl if ttl > 0 else 64,
            "ihl_bytes": ihl_bytes,
            "pkt_len": pkt_len,
            "tcp_flags": tcp_flags,
            "drop_reason": "SKB_NOT_DROPPED_YET (0)",
            "duration_ns": dur_ns,
        }
```

#### 4.3 Patch for `tracer_agent.py`: Dynamic `build_diagnosis_from_correlator_events()` & Sanitized DOT/SVG/Mermaid/FlameGraph/HTML/TUI Renderers
* **Target File**: [`tracer_agent.py` lines 714–1460 and 1802–1904](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L714-L1460)
* **Key Architectural Fixes Implemented & Verified in [verify_agent08.py](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/520741f5-6723-47b3-b5f3-c1f7a0de9b6e/scratch/verify_agent08.py)**:
  - **Dynamic Correlator-to-Visualization Bridge (`build_diagnosis_from_correlator_events`)**:
    * Accepts any `List[KrayEvent]` emitted by `RequestCorrelator`, sorts chronologically by `(int(e.timestamp), int(e.layer_type), int(e.is_return))`, pairs uprobe entry/return events per `(tid, call_depth)`, subtracts mid-function L5/L6 waits (`block_rq_complete`, `sched_switch`) to compute exact `on_cpu_ms` vs `off_cpu_ms`, resolves every non-stripped L7 function via `BinarySymbolicator.extract_cpp_source_evidence()` to populate `file`, `line`, `file_line` (`mock_server.cpp:41`, `mock_server.cpp:54`, `mock_server.cpp:65`, `mock_server.cpp:83`), tracks per-TID CPU core migration (`CPU #0 -> CPU #2`), and decodes `SKB_DROP_REASON_*`.
  - **Sanitized DOT & SVG (`escape_dot_label`, `data-hop-index` / `<title>hop_N</title>` Lookup)**:
    * Escapes `\`, `"`, `\r`, `\n` on all node and cluster labels so C++ templates and user-defined literals (`std::vector<int, std::allocator<int> >::push_back(int const&) ["operator""_json"]`) compile cleanly through `dot -Tsvg` and validate with `xml.etree.ElementTree.parse()`.
    * Dynamically groups Tier 3 subgraphs by `hop["module"]` instead of hardcoding `mock_server` and `libcrypto_mock.so`.
    * Includes `delta_ns`, `file:line`, `CPU #X` / `CPU #X -> CPU #Y`, and `[KERNEL DROP: SKB_DROP_REASON_*]` badges on every node.
  - **Interactive Web Dashboard (`render_interactive_dashboard_html`)**:
    * Uses `safe_json_for_html_script()` (`<` -> `\u003c`, `>` -> `\u003e`, `&` -> `\u0026`) so `</script>` breakout XSS is impossible.
    * Maps SVG node clicks by parsing `<title>hop_(\d+)</title>` or `data-hop-index` rather than DOM array index `idx`, eliminating the off-by-one bug when `drop_count > 0` (`alert_node`).
    * Implements full `inspectHop(hopObj)` logic:
      1. If `hopObj` is a kernel hop (`layer_type` in `1, 2, 3, 5, 6`), renders structured L2/L3/L4/L5/L6 packet & scheduler metadata (`vlan_id`, `ip_ttl`, `ihl_bytes`, `pkt_len`, `tcp_flags`, `drop_reason`, `cpu_id`, `prev_cpu_id -> target_cpu_id`, `delta_ns`) in `#kernel-meta-view`.
      2. If `hopObj` is an L7 hop (`layer_type == 4`), updates `#cpp-source-view` with the function's exact `file:line` (`mock_server.cpp:XX`) and highlighted C++ snippet from `DIAGNOSIS_DATA.source_code_evidence[hopObj.symbol_or_probe]`, or updates `#asm-source-view` if stripped, and populates `#zoom-symbol` (for non-stripped symbols) or `#zoom-offset` (`module:0xOFFSET` for stripped symbols) plus a live copyable CLI command (`python3 tracer_agent.py --focus-symbol ...` / `--focus-offset ...`) and a working `applyZoomInProbe()` `fetch('/api/v1/traces', {method: 'POST', ...})` call!
  - **Mermaid & FlameGraph (`patched_render_mermaid_sequence`, `patched_render_flamegraph_folded`)**:
    * Mermaid sanitizes `;`, `#`, `<`, `>`, `"` and explicitly renders Acceptor (`APP_IO`) to Worker (`APP_WORK`) thread handoffs (`TID 10420 -> TID 10425`), CPU core migrations (`CPU#0->CPU#2`), `mock_server.cpp:XX` source lines, and `[DROP: SKB_DROP_REASON_*]`.
    * FlameGraph maintains per-TID call stacks (`call_stack_by_tid[tid]`) indexed by `call_depth` (`del stack[1 + depth:]`), preventing sibling functions from accumulating into false recursive chains and sanitizing whitespace/`:`/`;` in frame names.
  - **CLI & Interactive TUI (`main`, `run_interactive_tui`)**:
    * Wires `--ui web` and `--serve rest` in `main()` to launch `serve_rest_api()` (and open/print the dashboard URL).
    * Updates `run_interactive_tui()` commands `[1]`, `[4]`, `[5]`, `[6]`, `[7]` to dynamically read `diag['hop_timeline']`, `diag['source_code_evidence']`, `diag['stripped_assembly_evidence']`, and write the HTML report on `[7]`.

#### 4.4 Patch for `test_verification_suite.py`: Fix `ADV-TEST-12` Startup Race & Flag Mismatch + Add `ADV-TEST-25..28`
* **Target File**: [`test_verification_suite.py` lines 2033–2047](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2033-L2047)
* **Patch Code**:
```python
        proc = subprocess.Popen(
            [str(MOCK_SERVER_BIN), "--port", str(port), "--fast-storage", "--single-shot"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            payload = b"GET / trace HTTP/1.1\r\nAuthorization: Bearer sec_tok_99\r\n\r\n"
            resp = b""
            for attempt in range(30):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
                        sock.sendall(payload)
                        resp = sock.recv(1024)
                    break
                except (ConnectionRefusedError, OSError):
                    time.sleep(0.05)
            self.assertIn(b"HTTP/1.1 200 OK", resp)
```

---

### 5. Verification Summary & Artifacts Produced

* **Verification Scratch Harness**: [verify_agent08.py](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/520741f5-6723-47b3-b5f3-c1f7a0de9b6e/scratch/verify_agent08.py)
  - Contains `run_red_phase_falsification()` (6 deterministic assertions proving every unpatched defect) and `run_green_phase_verification()` (end-to-end C `libkernel_sim.dylib` hook execution -> `RequestCorrelator` -> dynamic `build_diagnosis_from_correlator_events()` -> sanitized DOT/SVG/XML validation, Mermaid, FlameGraph, and XSS-safe HTML dashboard).
* **Compliance Checklist**:
  - Phase 1–6 adversarial audit completed: **YES**
  - Target kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64`) `dropreason-core.h` & `skb.h` cross-verified: **YES**
  - Shared root files left unmodified (isolation rule respected): **YES**
  - Zero Markdown tables used in report: **YES**
