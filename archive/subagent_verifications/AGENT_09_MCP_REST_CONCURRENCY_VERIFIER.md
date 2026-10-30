# Agent 09 반증 기반 TDD 및 타겟 커널 검증 보고서: 6-Tool MCP 서버, 10-Endpoint REST API 계약 및 멀티스레드 스레드 안전성(Thread Safety)

## 1. 감사 개요 및 검증 환경 (Executive Summary & Verification Environment)

* **검증 에이전트**: `AGENT_09_MCP_REST_CONCURRENCY_VERIFIER`
* **격리 실험 경로**:
  * 로컬 호스트(macOS): `/tmp/kray_agent_09`
  * 타겟 VM(`ebpf-tracer-v2.0.0`, `192.168.64.14`): `/tmp/kray_agent_09` 및 `/sys/fs/bpf/kray_agent_09`
* **타겟 실물 커널 증거 (1순위 기준)**:
  * 커널 릴리스: `Linux ebpf-wire-to-code-tracer-v2-0-0-rocky9-8 5.14.0-687.10.1.el9_8.0.1.aarch64 #1 SMP PREEMPT_DYNAMIC Sun May 24 13:01:44 UTC 2026 aarch64 GNU/Linux`
  * 로컬 커널 소스 및 BTF 레퍼런스: [`references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/)
* **핵심 반증 결과 요약**:
  * 기존 테스트 스위트([`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py))의 `TEST-01..12` 및 `ADV-TEST-01..11`은 통과(`PASS`)하나, 반증 실험 결과 **가짜 통과(False Positive / 테스트 사각지대) 5건**과 **런타임·프로토콜·동시성 결함 5대 항목**이 적발되었다.
  * 첫째, [`RequestCorrelator.get_completed_traces()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L366-L370)가 내부적으로 `self.flush_expired(current_ts_ns=None)`을 무조건 호출하여 **현재 다른 스레드가 수집 중인 미완료(In-Flight) 요청(`self._buffers`)까지 강제로 팝(pop)·완료 처리함으로써 멀티스레드 환경에서 진행 중인 트레이스를 두 동강 내고 앞단 계층(Layer 1~2) 이벤트를 영구 유실시키는 치명적 레이스 컨디션**을 확인하였다.
  * 둘째, [`MCPGatewayServer.handle_jsonrpc()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1565-L1650) 및 `--serve mcp` / `POST /mcp`가 실제 AI 에이전트(Claude Desktop, Cursor, Antigravity) 연결 시 필수인 **`notifications/initialized` 알림 메서드를 `-32601 Unknown method` 에러로 거부**하고, `tools/list`에서 MCP 필수 필드인 **`inputSchema`를 누락**하며, 표준 JSON-RPC 2.0 에러 코드인 **`-32700 Parse error`, `-32600 Invalid Request`, `-32602 Invalid params`를 전혀 처리하지 못하고 `JSONDecodeError` / `KeyError` / `AttributeError`로 크래시**함을 입증하였다.
  * 셋째, [`MCPGatewayServer`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1506-L1650)와 [`start_background_rest_server()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1653-L1776)가 [`RequestCorrelator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L284-L370)와 완전히 단절되어 실시간 수집된 `KrayEvent` 스트림(재전송, SKB 드롭 사유, 동적 uprobe 오프셋, 링버퍼 드롭 카운트)을 반영하지 못하고, `GET /api/v1/inspect?target=...` 및 `ebpf_inspect_code_or_asm`이 요청된 `target` 파라미터(`validate_auth_header`, `parse_http_request`, `libcrypto_mock.so+0x...`)를 무시한 채 하드코딩된 `execute_storage_query`만 반환하는 결함을 적발하였다.

---

## 2. Phase 1 ~ Phase 6 전 과정 교차 검증 결과 (Stage-Gate Audit)

### Phase 1: 64B 이벤트 및 16B 런타임 설정 구조체 ABI 무결성 검증
* **검증 대상**: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L118-L160)의 [`struct kray_runtime_cfg_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L118-L124)(`16B`), [`struct kray_event_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L129-L146)(`64B`), [`struct flow_key_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L151-L159)(`16B`) vs [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L78-L112)의 [`KrayRuntimeCfg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L78-L86), [`KrayEvent`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L89-L108)
* **검증 결과**: `clang++` 네이티브 바이너리 컴파일 및 `offsetof()` 대조 결과 16개 이벤트 필드와 5개 설정 필드의 바이트 크기 및 오프셋이 100% 일치함을 확인하였다 (`TEST-01 PASS`).

### Phase 2: Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) BTF CO-RE 컴파일 및 Verifier 정적 한계 검증
* **검증 대상**: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kray_bpf_core_compat.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h), [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h)
* **검증 결과**:
  * `-target aarch64-linux-gnu -DKRAY_BPF_CORE -Wframe-larger-than=320 -Werror=frame-larger-than=` 컴파일 통과(`ADV-TEST-02`, `ADV-TEST-03 PASS`).
  * 모든 훅의 스택 프레임이 320B 이하(512B BPF Verifier 한계 이내)이며, `struct tid_ctx_t` 및 `struct handoff_ring_t`의 스택 할당이 없고 `BPF_PERCPU_ARRAY` 제로 템플릿(`zero_ctx_map`, `zero_ring_map`)을 통해 초기화됨을 확인하였다.

### Phase 3: 유저스페이스 C 훅 에뮬레이션 및 다중 프로토콜 패킷 퍼징 검증
* **검증 대상**: [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c)
* **검증 결과**:
  * 6개 매크로 계층 및 7대 세부 계층 C 훅 실행, 802.1Q/802.1AD QinQ VLAN, IPv4 옵션(`ihl=8`), IPv6 XOR 폴딩, Dual-Stack `::ffff:` `AF_INET` 정규화, 비연결 UDP `msg->msg_name` 지연 추출, ICMP, ARP(`(u8 *)(arp + 1) + 6/16`), `AF_UNIX` 피어 포인터 정규화, `kfree_skb` 3단계 드롭 추적이 정상 동작함을 확인하였다 (`ADV-TEST-01`, `ADV-TEST-04`, `ADV-TEST-06`, `ADV-TEST-08 PASS`).

### Phase 4: ELF/DWARF/Stripped `.so` 심볼리케이터 및 시각화 파이프라인 검증
* **검증 대상**: [`BinarySymbolicator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L375-L587), [`render_graphviz_dot_and_svg()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L716-L889), [`render_interactive_dashboard_html()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L895-L1053)
* **검증 결과**: `strip -x` 처리된 `libcrypto_mock.so`에서 `bl`/`call` 분기 타겟 오프셋 발굴 및 `objdump -d` 역어셈블리 추출, 4-Tier Graphviz 클러스터 생성, TUI/Mermaid/FlameGraph 출력은 정상 동작하나(`TEST-04..10`, `ADV-TEST-07`, `ADV-TEST-11 PASS`), 특정 심볼/오프셋을 동적으로 조회할 때의 API 연동 결함(결함 #4)이 발견되었다.

### Phase 5: 6-Tool MCP 서버, 10-Endpoint REST API 및 멀티스레드 동시성 검증 (집중 반증 대상)
* **검증 대상**: [`RequestCorrelator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L284-L370), [`MCPGatewayServer`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1506-L1650), [`start_background_rest_server()`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1653-L1776)
* **검증 결과**: 기존 `TEST-11` 및 `ADV-TEST-09`는 통과하였으나, 실제 동시성 경쟁 조건과 MCP/JSON-RPC 2.0 표준 규격으로 교차 반증한 결과 **치명적 결함 4건(결함 #1 ~ #4)**이 적발되었다(3절에 상세 기술).

### Phase 6: 실물 타겟 커널(`ebpf-tracer-v2.0.0`) Verifier 및 라이브 루프백 브릿지 검증
* **검증 대상**: [`test_adv_12_target_kernel_live_verifier_and_loopback_readiness`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2007-L2096) 및 [`mock_server.cpp`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L115-L130)
* **검증 결과**: `/tmp/kray_agent_09`에서 최초 실행 시 `ADV-TEST-12`가 `[Errno 61] Connection refused`로 실패하는 현상을 포착하여 **프로세스 기동 레이스 컨디션 및 CLI 플래그 불일치 결함(결함 #5)**을 적발하였다.

---

## 3. 집중 반증으로 적발한 5대 핵심 결함 및 재현 증거 (Adversarial Falsification Findings)

### 결함 #1: `RequestCorrelator.get_completed_traces()`의 미완료(In-Flight) 트레이스 강제 절단(Tearing) 레이스 컨디션 및 얕은 복사(Shallow Copy) 결함

* **적발 위치**:
  * [`tracer_agent.py:355-370`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L355-L370) (`RequestCorrelator.flush_expired` 및 `RequestCorrelator.get_completed_traces`)
  * [`test_verification_suite.py:382-386`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L382-L386), [`test_verification_suite.py:1872-1875`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1872-L1875)
* **원인 분석**:
  * `RequestCorrelator`는 `self._lock = threading.RLock()`을 보유하고 있으나, `get_completed_traces()` 구현이 다음과 같이 작성되어 있다:
    ```python
    def get_completed_traces(self) -> Dict[int, List[KrayEvent]]:
        with self._lock:
            self.flush_expired(current_ts_ns=None)
            return dict(self._completed)
    ```
  * `flush_expired(current_ts_ns=None)` 내부의 `elif current_ts_ns is None: self._finalize_request(req_id)` 분기([`tracer_agent.py:361-362`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L361-L362))는 **타임스탬프나 `LAYER_USER_EXIT` 도달 여부와 무관하게 현재 `self._buffers`에 들어 있는 모든 진행 중인(In-Flight) `req_id`를 즉시 팝(pop)하여 `self._completed`로 이동**시킨다.
  * 결과적으로 워커 스레드 A가 하나의 요청(`req_id`)에 대해 Layer 1(`INGRESS_NIC`), Layer 2(`KERNEL_NET`) 이벤트를 `ingest()`한 직후, HTTP 워커 스레드 B가 `GET /api/v1/traces` 또는 `get_completed_traces()`를 호출하면, 아직 Layer 3~6이 도착하지 않은 미완료 요청이 `[Layer 1, Layer 2]`만으로 강제 완료 처리된다.
  * 직후 워커 스레드 A가 동일 `req_id`의 나머지 Layer 3, 4, 5, 6 이벤트를 `ingest()`하면 `self._buffers[req_id]`가 새로 생성되고, Layer 6 도착 시 `_finalize_request(req_id)`([`tracer_agent.py:348-350`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L348-L350))가 기존 `self._completed[req_id]`를 덮어써 버리므로 **최종 완료된 트레이스에서 Layer 1~2가 영구 증발(`[3, 4, 5, 6]`만 남음)**한다!
  * 또한 `return dict(self._completed)`는 외부 딕셔너리만 얕은 복사(Shallow Copy)하므로 내부 `List[KrayEvent]`는 호출자 간에 공유되며, `RequestCorrelator`에 명세서/인터페이스 호환 메서드(`ingest_event`, `flush_ready`, `_active` 프로퍼티)가 누락되어 있다.
  * **기존 테스트(`ADV-TEST-09`)의 사각지대**: [`test_verification_suite.py:1872-1875`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1872-L1875)는 2개 이벤트(`layer_type=1`, `layer_type=6`)만 주입하고 `_ = correlator.get_completed_traces()` 반환값을 전혀 검증하지 않아 이 트레이스 절단(Trace Tearing) 버그를 놓쳤다.
* **반증 재현 코드**:
  ```python
  correlator = tracer_agent.RequestCorrelator(grace_window_ms=50.0)
  req_id = 0xABCDEF01
  # Thread A: Layer 1, 2 수집 중
  correlator.ingest(tracer_agent.make_event(req_id=req_id, timestamp=1000, duration_ns=100, layer_type=1, call_depth=2))
  correlator.ingest(tracer_agent.make_event(req_id=req_id, timestamp=2000, duration_ns=100, layer_type=2, call_depth=3))
  # Thread B: 동시에 get_completed_traces() 호출 -> 미완료 req_id가 강제 finalize 됨!
  _ = correlator.get_completed_traces()
  # Thread A: 나머지 Layer 3, 4, 5, 6 수집 완료
  for lt, cd, ts in [(3, 5, 3000), (4, 0, 4000), (5, 5, 5000), (6, 2, 6000)]:
      correlator.ingest(tracer_agent.make_event(req_id=req_id, timestamp=ts, duration_ns=100, layer_type=lt, call_depth=cd))
  # 검증: [1, 2, 3, 4, 5, 6]이어야 하나 [3, 4, 5, 6]만 남고 Layer 1, 2가 소실됨!
  assert [e.layer_type for e in correlator.get_completed_traces()[req_id]] == [3, 4, 5, 6]
  ```

---

### 결함 #2: `MCPGatewayServer` 및 `RestHandler`의 비동기화(Unlocked) 상태 읽기, 공유 파일 덮어쓰기 경합 및 `0ms` 핫리로드 블로킹

* **적발 위치**:
  * [`tracer_agent.py:1534-1564`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1534-L1564) (`MCPGatewayServer.capture_trace`)
  * [`tracer_agent.py:1609-1641`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1609-L1641) (`MCPGatewayServer.handle_jsonrpc`)
  * [`tracer_agent.py:1666-1715`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1666-L1715) (`RestHandler.do_GET`)
* **원인 분석**:
  * `RestHandler.do_GET`의 `/api/v1/health`([`tracer_agent.py:1674`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1674))는 `mcp_gateway._lock`을 획득하지 않은 채 `mcp_gateway.runtime_cfg` 딕셔너리를 직접 직렬화하며, `/api/v1/traces/latest`, `/api/v1/network-layers`, `/api/v1/inspect` 역시 락 없이 `mcp_gateway.latest_diagnosis`를 읽는다.
  * `GET /`([`tracer_agent.py:1708-1709`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1708-L1709))는 락 없이 디스크의 `trace_dashboard.html`을 읽는 동안 다른 워커 스레드의 `capture_trace()`가 동일 파일(`self.work_dir / "trace_dashboard.html"`)을 덮어쓰므로 파일 I/O 경합이 발생한다.
  * 반대로 `capture_trace()`([`tracer_agent.py:1541`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1541))는 무거운 외부 프로세스(`objdump -d`, `dot -Tsvg`)를 실행하는 내내 `self._lock`을 독점 보유하므로, 캡처 실행 중에 들어오는 `PUT /api/v1/config` 또는 `ebpf_configure_target` 호출이 블로킹되어 명세서의 **`0ms` 무블로킹 핫리로드 계약**을 위반한다.

---

### 결함 #3: MCP JSON-RPC 2.0 표준 프로토콜 위반 (`notifications/initialized`, `inputSchema`, `-32700`, `-32600`, `-32602` 미지원)

* **적발 위치**:
  * [`tracer_agent.py:1565-1650`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1565-L1650) (`MCPGatewayServer.handle_jsonrpc`)
  * [`tracer_agent.py:1736-1766`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1736-L1766) (`RestHandler.do_POST` `/mcp`)
  * [`tracer_agent.py:1890-1897`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1890-L1897) (`main` `--serve mcp` 루프)
* **원인 분석**:
  1. **초기화 핸드셰이크 알림(`notifications/initialized`) 거부**: Claude Desktop, Cursor, Antigravity 등 표준 MCP 클라이언트는 `initialize` 응답 수신 직후 `{"jsonrpc": "2.0", "method": "notifications/initialized"}`를 전송한다. 그러나 `handle_jsonrpc`는 이를 처리하지 않고 `-32601 Unknown method notifications/initialized` 에러를 반환하여 세션 초기화를 중단시킨다 (`ping` 메서드도 미지원).
  2. **`tools/list`의 `inputSchema` 누락**: [`tracer_agent.py:1581-1590`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1581-L1590)에서 6개 도구가 `"name"`과 `"description"`만 반환하고 MCP 표준 필수 필드인 `"inputSchema": {"type": "object", "properties": {...}}`를 누락하여 AI 에이전트가 도구 파라미터 스키마를 인식하지 못한다.
  3. **`-32700 Parse error` 미처리 및 프로세스 크래시**:
     * `--serve mcp` 표준입력 루프([`tracer_agent.py:1896`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1896))에서 잘못된 JSON 입력 시 `json.loads(line)`가 예외 처리 없이 `json.JSONDecodeError`를 발생시켜 MCP 서버 프로세스가 즉시 종료된다.
     * `POST /mcp`([`tracer_agent.py:1744-1745`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1744-L1745))에서도 깨진 JSON 수신 시 JSON-RPC 2.0 에러 포맷(`code: -32700`)이 아닌 일반 `{"error": "Invalid JSON: ..."}`를 반환한다.
  4. **`-32600 Invalid Request` 미처리**:
     * 요청이 `dict`가 아니거나(예: `[]`), `"jsonrpc": "2.0"`이 아니거나, `"method"`가 없거나 문자열이 아닐 때 `-32600 Invalid Request`를 반환하지 않고 `AttributeError`로 죽거나 `-32601 Unknown method`를 반환한다.
  5. **`-32602 Invalid params` 미처리 및 `KeyError` 크래시**:
     * `params`가 `dict`가 아닐 때, 또는 `tools/call`에서:
       * `ebpf_compare_patches` 호출 시 `baseline_path`나 `patched_path`가 누락되면 [`tracer_agent.py:1630`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1630)에서 `KeyError: 'baseline_path'`가 발생하여 서버 스레드가 크래시한다.
       * `ebpf_configure_target`에 범위 밖 포트(`port: 99999` 또는 `port: -1`)나 음수 `pid`를 전달해도 검증 없이 수용하거나 `ValueError`로 크래시한다.
       * `ebpf_capture_trace`에 허용되지 않은 `mode`, `ebpf_inspect_network_layers`에 허용되지 않은 `layer`/`proto`, `ebpf_render_topology`에 허용되지 않은 `format`을 전달해도 `-32602 Invalid params`를 반환하지 않는다.

---

### 결함 #4: `RequestCorrelator` 실시간 트레이스와의 단절 및 `GET /api/v1/inspect` / `ebpf_inspect_code_or_asm`의 `target` 파라미터 무시

* **적발 위치**:
  * [`tracer_agent.py:1509-1648`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1509-L1648) (`MCPGatewayServer`)
  * [`tracer_agent.py:1666-1715`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1666-L1715) (`RestHandler.do_GET`)
* **원인 분석**:
  1. **`RequestCorrelator` 실시간 연동 부재**: `MCPGatewayServer` 내부에 `RequestCorrelator` 인스턴스가 존재하지 않아, 실시간으로 `correlator.ingest(ev)`를 통해 유입된 `KrayEvent` 스트림(실제 병목 홉, TCP 재전송 플래그 `FLAG_TCP_RETRANSMIT`, 커널 SKB 드롭 `FLAG_SKB_DROP` 및 드롭 사유, 스레드 핸드오프, 동적 uprobe 오프셋, 링버퍼 드롭 카운트)이 `GET /api/v1/traces/latest`, `GET /api/v1/network-layers`, `ebpf_capture_trace`, `ebpf_inspect_network_layers`에 반영되지 않는다.
  2. **`target` 심볼/오프셋 동적 추출 누락**:
     * [`tracer_agent.py:1620-1628`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1620-L1628) 및 [`tracer_agent.py:1694-1704`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1694-L1704)에서 `target="validate_auth_header"`, `target="parse_http_request"`, `target="format_http_response"`, 또는 `target="libcrypto_mock.so+0x1140"`을 요청하더라도 `BinarySymbolicator`를 호출하지 않고 오직 고정된 `execute_storage_query` 스니펫만 반환한다.
  3. **`ebpf_render_topology` 경로 하드코딩**:
     * [`tracer_agent.py:1639`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1639)에서 `fast`나 `overflow` 모드로 캡처된 후에도 `mcp_trace_baseline.{fmt}` 경로만 반환하며, `format="html"`일 때 실제 파일(`trace_dashboard.html`)이 아닌 존재하지 않는 `mcp_trace_baseline.html` 경로를 반환한다.
  4. **`GET /api/v1/health` 필드 누락 및 미정의 `/api/*` 경로의 `200 OK` 오반환**:
     * `GET /api/v1/health`에 명세서 3.6.2절이 요구하는 로드된 모듈 목록(`loaded_modules`), 동적 uprobe 등록 상태(`registered_uprobes`), 상관관계 상태(`correlator_stats`)가 누락되어 있다.
     * `RestHandler.do_GET`의 `else:` 분기([`tracer_agent.py:1705`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1705))가 존재하지 않는 `/api/v1/unknown` 요청에 대해서도 `404 Not Found` 대신 `200 OK` HTML을 반환한다.

---

### 결함 #5: `ADV-TEST-12` 라이브 루프백 서버 기동 레이스 컨디션(`Connection refused`) 및 `--fast-mode` vs `--fast-storage` 플래그 불일치

* **적발 위치**:
  * [`test_verification_suite.py:2035-2043`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2043) (`test_adv_12_target_kernel_live_verifier_and_loopback_readiness`)
  * [`mock_server.cpp:124-126`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L124-L126)
* **원인 분석**:
  * `ADV-TEST-12`는 `mock_server` 바이너리를 자식 프로세스로 기동한 뒤 고정 `time.sleep(0.25)`만 대기하고 곧바로 `socket.create_connection(("127.0.0.1", port))`을 호출한다. 새로운 경로(`/tmp/kray_agent_09`)에 컴파일된 바이너리를 최초 실행할 때 OS 바이너리 검증(`syspolicyd`) 또는 CPU 부하로 인해 `bind()`/`listen()`까지 250ms 이상 소요되면 즉시 `[Errno 61] Connection refused`로 실패한다.
  * 또한 `ADV-TEST-12`는 `[str(MOCK_SERVER_BIN), "--port", str(port), "--fast-mode"]`로 기동하나, [`mock_server.cpp:124`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L124)는 `--fast-storage`만 파싱하고 `--fast-mode`를 무시하므로 베이스라인 `18ms` 슬립이 그대로 실행된다.

---

## 4. 근본 원인 해결을 위한 구체적 코드 패치안 (Concrete Remediation Patches)

### 4.1 [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py) 수정 패치안

#### (1) `RequestCorrelator` 스레드 안전성 강화 및 미완료 트레이스 절단 방지 (`tracer_agent.py:284-370`)
* `get_completed_traces(flush_all: bool = False)`가 기본 호출 시 진행 중인 미완료 요청을 강제로 완료 처리하지 않도록 분리하고(`flush_ready`는 `LAYER_USER_EXIT` 이후 grace window가 경과한 요청만 완료 처리), 반환 시 내부 이벤트 리스트까지 깊은 스냅샷(`{k: list(v) for k, v in self._completed.items()}`)을 반환하며, `ingest_event()`, `flush_ready()`, `_active` 프로퍼티 및 실시간 `build_diagnosis_from_events()` 메서드를 제공한다.

```python
class RequestCorrelator:
    MAX_COMPLETED_TRACES = 4096

    def __init__(
        self,
        grace_window_ms: float = 50.0,
        max_completed_traces: int = 4096,
        sampling_rate: float = 1.0,
    ) -> None:
        self._lock = threading.RLock()
        self.grace_window_ns = int(grace_window_ms * 1_000_000)
        self.max_completed_traces = max(1, int(max_completed_traces))
        self.sampling_rate = max(0.0, min(1.0, float(sampling_rate)))
        self._buffers: Dict[int, List[KrayEvent]] = {}
        self._first_seen_ts: Dict[int, int] = {}
        self._exit_seen_ts: Dict[int, int] = {}
        self._completed: Dict[int, List[KrayEvent]] = {}
        self.max_event_drop_count: int = 0

    @property
    def _active(self) -> Dict[int, List[KrayEvent]]:
        with self._lock:
            return {k: list(v) for k, v in self._buffers.items()}

    def ingest_event(self, ev: KrayEvent) -> None:
        self.ingest(ev)

    def flush_ready(self, current_ts_ns: Optional[int] = None) -> Dict[int, List[KrayEvent]]:
        with self._lock:
            if current_ts_ns is not None:
                self.flush_expired(current_ts_ns=current_ts_ns)
            return {k: list(v) for k, v in self._completed.items()}

    def get_completed_traces(self, flush_all: bool = False) -> Dict[int, List[KrayEvent]]:
        with self._lock:
            if flush_all:
                self.flush_expired(current_ts_ns=None)
            return {k: list(v) for k, v in self._completed.items()}
```

#### (2) `MCPGatewayServer` 및 `RestHandler`의 JSON-RPC 2.0 표준 준수, 실시간 `RequestCorrelator` 통합 및 세밀한 락(Fine-Grained RLock) 적용 (`tracer_agent.py:1506-1776`)

```python
MCP_TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "name": "ebpf_configure_target",
        "description": "0ms hot-reload runtime_config_map[0]",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "minimum": 0},
                "port": {"type": "integer", "minimum": 0, "maximum": 65535},
                "iface": {"type": "string"},
                "capture_enabled": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "ebpf_capture_trace",
        "description": "Capture full 7-layer Wire-to-PreCompute-to-ALU trace",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["baseline", "fast", "overflow"]},
                "focus_symbol": {"type": "string"},
                "uprobe_offset": {"type": "string"},
                "simulate_drops": {"type": "integer", "minimum": 0},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "ebpf_inspect_network_layers",
        "description": "Inspect L2/L3/L4/Socket/Syscall/Sched/L7 telemetry",
        "inputSchema": {
            "type": "object",
            "properties": {
                "req_id": {"type": "string"},
                "layer": {"type": "string", "enum": ["all", "l2", "l3", "l4", "socket", "syscall", "sched", "l7"]},
                "proto": {"type": "string", "enum": ["all", "tcp", "udp", "icmp", "arp", "ipv4", "ipv6", "unix", "tls"]},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "ebpf_inspect_code_or_asm",
        "description": "Extract DWARF C++ source or stripped ELF disassembly",
        "inputSchema": {
            "type": "object",
            "properties": {
                "req_id": {"type": "string"},
                "target": {"type": "string"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ebpf_compare_patches",
        "description": "Compare baseline vs patched ai_diagnosis.json",
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_path": {"type": "string"},
                "patched_path": {"type": "string"},
            },
            "required": ["baseline_path", "patched_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ebpf_render_topology",
        "description": "Render 4-Tier Graphviz .dot/.svg/HTML topology",
        "inputSchema": {
            "type": "object",
            "properties": {
                "req_id": {"type": "string"},
                "format": {"type": "string", "enum": ["svg", "dot", "html"]},
            },
            "additionalProperties": False,
        },
    },
]
```

* `MCPGatewayServer.handle_jsonrpc` 및 `handle_jsonrpc_raw`:
  * `raw` 문자열/바이트 입력 시 `json.loads` 실패를 포착하여 `{"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}` 반환.
  * `req`가 `dict`가 아니거나 `req.get("jsonrpc") != "2.0"`이거나 `method`가 비어 있는 경우 `{"jsonrpc": "2.0", "id": req_id, "error": {"code": -32600, "message": "Invalid Request"}}` 반환.
  * `method in ("notifications/initialized", "notifications/cancelled")`일 때 에러가 아닌 정상 응답(`{"jsonrpc": "2.0", "id": req_id, "result": {}}`) 반환 및 `method == "ping"` 지원.
  * `params`가 `dict`가 아니거나 도구별 인자(`port`, `pid`, `mode`, `layer`, `proto`, `target`, `baseline_path`, `patched_path`, `format`)가 유효하지 않을 때 `{"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid params: ..."}}` 반환.
  * `self.correlator = RequestCorrelator()`를 내장하여 `correlator.ingest(ev)`로 실시간 이벤트가 적재되면 해당 이벤트들의 실제 `req_id`, 홉 소요 시간, `FLAG_TCP_RETRANSMIT`, `FLAG_SKB_DROP`, `FLAG_STRIPPED_SYMBOL`, `drop_count`를 기반으로 진단 번들을 동적 재구성하여 반환.
  * `inspect_target(target)` 메서드를 통해 요청된 임의의 C++ 함수 심볼(`parse_http_request`, `validate_auth_header`, `execute_storage_query`, `format_http_response`) 또는 임의의 Stripped 오프셋(`libcrypto_mock.so+0x...`)을 실시간 추출하여 `source_code_evidence` 및 `stripped_assembly_evidence`에 반영.

### 4.2 [`mock_server.cpp`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp) 및 [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) 수정 패치안

* [`mock_server.cpp:124`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L124): `--fast-storage`뿐만 아니라 `--fast-mode` 플래그도 동일하게 인식하도록 `else if (arg == "--fast-storage" || arg == "--fast-mode")`로 보강.
* [`test_verification_suite.py:2042-2048`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2042-L2048): 고정 `time.sleep(0.25)` 대신 최대 3.0초 동안 50ms 간격으로 소켓 연결을 재시도하는 결정론적 준비 대기 루프(Readiness Retry Loop)로 교체하여 첫 컴파일 직후 실행 시에도 `[Errno 61] Connection refused`가 절대 발생하지 않도록 교정.
* [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) 내 `TEST-11`, `ADV-TEST-08`, `ADV-TEST-09`에 다음 반증 어서션 추가:
  * 멀티스레드 환경에서 `RequestCorrelator.ingest()`(6개 계층 순차 주입)와 `get_completed_traces()`가 동시에 실행될 때 단 하나의 트레이스도 중간에 절단되지 않고 완료된 모든 트레이스가 6개 계층(`{1, 2, 3, 4, 5, 6}`)을 온전히 보존하는지 검증.
  * MCP `notifications/initialized`, `tools/list` 내 6개 도구의 `inputSchema`, `-32700 Parse error`, `-32600 Invalid Request`, `-32602 Invalid params` 응답 코드를 전수 검증.
  * `GET /api/v1/inspect?target=validate_auth_header` 및 `ebpf_inspect_code_or_asm(target="validate_auth_header")` 호출 시 실제로 `validate_auth_header`의 C++ 소스 코드와 줄 번호가 추출되는지 검증.
  * `RequestCorrelator`에 실시간 주입된 이벤트(`FLAG_TCP_RETRANSMIT`, `FLAG_SKB_DROP`, 커스텀 `req_id` 및 `drop_count`)가 REST `/api/v1/traces/latest` 및 `/api/v1/network-layers` 응답에 실시간 반영되는지 검증.
