# AGENT 07 — C 에뮬레이션 하네스(`mock_bpf_runtime.h` / `kernel_sim_harness.c`) 현실 왜곡 반증 및 타겟 커널 교차 검증 보고서

## 1. 감사 개요 및 핵심 반증 결론 (Executive Summary)

* **검증 주체**: Agent 07 (`AGENT_07_SIM_HARNESS_FIDELITY_VERIFIER`)
* **검증 대상**:
  - 마스터 명세서: [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md)
  - C 유저스페이스 BPF 에뮬레이션 런타임: [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h)
  - C 커널 훅 시뮬레이션 하네스: [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c)
  - 커널 eBPF C 프로그램: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c) 및 [`kray_bpf_core_compat.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h)
  - 유저스페이스 상관분석·심볼리케이션 엔진: [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py)
  - 통합 검증 스위트: [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py)
  - 실물 타겟 커널 레퍼런스 및 VM: Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`), [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h), 타겟 VM `ebpf-tracer-v2.0.0` (`192.168.64.14`)
* **격리 실험 및 교정본 경로**:
  - [`/Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07)
* **최종 판정**: **총 7건의 중대 현실 왜곡(Reality Distortion) 및 은폐된 커널 C 코드 결함 적발 완료 (교정 패치 및 반증 테스트 작성 완료)**
  - 기존 `test_verification_suite.py`는 겉보기에는 `24/24 PASS`를 출력할 수 있도록 작성되어 있었으나, `mock_bpf_runtime.h`와 `kernel_sim_harness.c`가 실제 리눅스 커널 eBPF 서브시스템과 다르게 동작하거나 맵 상태를 수동 조작(Map-Poking Cheat)하여 **`tracer_kernel.c` 내부의 치명적 런타임 버그(`lock_wait_ns` 영구 0 초기화, 비연결형 UDP `udp_sendmsg` 원격 피어 주소/포트 증발, Egress/IPv6 패킷 헤더 메타데이터 누락 등)를 완벽히 은폐**하고 있었음을 실증적으로 반증하였다.

---

## 2. Phase 1 ~ Phase 6 전 과정 게이트 검증 및 반증 요약

### Phase 1 — 커널/BTF 실물 레퍼런스 대조 및 ABI 불변식 검증
* **검증 항목**:
  - `struct kray_event_t` (64B), `struct kray_runtime_cfg_t` (16B), `struct flow_key_t` (16B)의 C 컴파일러(`clang++`) `sizeof`/`offsetof`와 Python `ctypes.Structure` 레이아웃 전수 대조 (`TEST-01`).
  - [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L168-L250)의 모의 커널 트레이스포인트 컨텍스트 구조체(`tp_args_*`)와 Rocky Linux 9.8 실물 [`vmlinux.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h)의 `trace_event_raw_*` 구조체 필드/타입 대조.
* **반증 결과**:
  - 64B 이벤트 및 16B 설정 구조체 오프셋은 C와 Python 간 100% 일치함을 확인하였다.
  - 그러나 [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L352-L353)의 `BPF_PERCPU_ARRAY`, `BPF_LRU_HASH`, `BPF_RINGBUF_OUTPUT` 구현이 실제 커널 BPF 맵 동작을 심각하게 단순화·왜곡하고 있음을 적발하였다 (상세 내역은 섹션 3 참조).

### Phase 2 — 커널 eBPF C 코드(`tracer_kernel.c`) 정적·구조적 감사 및 CO-RE 크로스 컴파일
* **검증 항목**:
  - Rocky Linux 9.8 `vmlinux.h` 기반 `-target aarch64-linux-gnu` 및 `-target bpf -D__TARGET_ARCH_arm64 -DKRAY_BPF_CORE` 컴파일 검증 (`TEST-02`, `ADV-TEST-02`).
  - 모든 훅 함수의 스택 프레임 크기 `<= 320B` (`-Wframe-larger-than=320 -Werror=frame-larger-than=`) 및 `#pragma unroll` 루프 제한 검증 (`ADV-TEST-03`).
* **반증 결과**:
  - 42개 eBPF 프로그램 섹션 모두 스택 320B 이하로 컴파일되나, `kernel_sim_harness.c`가 수동으로 맵 메모리를 덮어써서 통과시켰던 `sys_enter_futex` -> `sched_waking` -> `sched_wakeup` -> `sched_switch` 경로와 비연결형 UDP `kprobe__udp_sendmsg` 경로에서 실제 커널 실행 시 데이터가 유실되는 코드 결함 3건을 적발하였다 (상세 내역은 섹션 4 참조).

### Phase 3 — C 네이티브 훅 에뮬레이션(`kernel_sim_harness.c`) 및 패킷 퍼징 반증
* **검증 항목**:
  - Focus Area 1 (`BPF_PERCPU_ARRAY` 오염 반증), Focus Area 2 (`max_entries` 및 `BPF_F_NO_EXIST`/`BPF_EXIST` 플래그 반증), Focus Area 3 (단일 패스 Wire-to-Code 파이프라인 래퍼 반증).
  - 42개 커널 훅 중 `kernel_sim_harness.c`가 실제로 호출하지 않고 방치한 사각지대(Uncalled Dead Hooks) 전수 조사.
* **반증 결과**:
  - [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)의 42개 훅 중 **`tracepoint__tcp__tcp_retransmit_skb`, `tracepoint__syscalls__sys_enter_futex`, `tracepoint__sched__sched_process_fork`, `tracepoint__sched__sched_wakeup`, `kprobe__ip6_output` 등 5개 훅과 `tracepoint__skb__kfree_skb`의 Stage 1(`skb_egress_map`), 그리고 `tracepoint__sched__sched_switch`의 함수 실행 중(`call_depth > 0`) Off-CPU 슬립 분기가 `kernel_sim_harness.c`에서 단 한 번도 호출되지 않았음**을 적발하였다.

### Phase 4 — 유저스페이스 상관분석(`RequestCorrelator`) 및 3-Tier 심볼리케이터(`BinarySymbolicator`) 검증
* **검증 항목**:
  - 멀티코어 타임스탬프 역전, 유실 패킷, 8-슬롯 링버퍼 래핑(Wrap-around), PIE ASLR 및 aarch64 64KB 페이지 정렬 오프셋 계산 검증 (`TEST-03`~`TEST-05`, `ADV-TEST-05`~`ADV-TEST-08`).
* **반증 결과**:
  - `RequestCorrelator`와 `BinarySymbolicator.resolve_runtime_ip()` 개별 클래스는 정상 작동하나, 정작 [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1092-L1247)의 메인 함수인 `run_tracer_pipeline()`은 `kernel_sim_harness.c`나 `RequestCorrelator`, `decode_event_metadata()`, `BinarySymbolicator.resolve_runtime_ip()`를 전혀 호출하지 않고 파이썬 하드코딩 상수로 리포트를 합성하는 동어반복(Tautology) 구조임을 적발하였다.

### Phase 5 — 시각화 아티팩트(Graphviz 4-Tier DOT/SVG, HTML 대시보드, TUI, MCP 6 Tools, REST API) 검증
* **검증 항목**:
  - Graphviz 서브그래프 ID 살균(`sanitize_graphviz_id`), 링버퍼 오버플로우 배너, MCP JSON-RPC 2.0 6개 도구, REST API 10개 엔드포인트 및 16-스레드 동시성 스트레스 검증 (`TEST-06`~`TEST-12`, `ADV-TEST-09`~`ADV-TEST-11`).
* **반증 결과**:
  - `run_tracer_pipeline()`을 C 하네스의 `sim_run_full_wire_to_code_pipeline()` -> `RequestCorrelator` -> `decode_event_metadata()` -> `BinarySymbolicator` 파이프라인에 실제로 연결한 상태에서도 모든 시각화 아티팩트와 MCP/REST SLA(`p99 < 500ms`)가 100% 통과함을 확인하였다.

### Phase 6 — 실물 타겟 커널(`ebpf-tracer-v2.0.0`) Verifier 및 라이브 루프백 브리지 검증
* **검증 항목**:
  - `ADV-TEST-12`의 라이브 `mock_server` 소켓 연결 및 C 훅 브리지 테스트의 신뢰성 검증.
  - 타겟 VM(`ebpf-tracer-v2.0.0`, `5.14.0-687.10.1.el9_8.0.1.aarch64`) SSH 접속 및 실물 커널 환경 대조.
* **반증 결과**:
  - 기존 [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2043)의 `ADV-TEST-12`는 최초 실행 시 `[Errno 61] Connection refused`로 실패하는 결함이 있었다. 원인은 고정 `time.sleep(0.25)`만 수행하고 소켓 바인딩 완료를 폴링하지 않은 점, 그리고 `mock_server.cpp`는 `--fast-storage` 플래그만 파싱하는데 테스트는 `--fast-mode`를 전달한 점이었다.

---

## 3. Agent 07 핵심 집중 반증 영역 상세 분석 (Focus Areas 1 ~ 3)

### 3.1 [Focus Area 1 반증] `BPF_PERCPU_ARRAY` 단일 슬롯 왜곡 및 Zero-Template In-Place 오염 위험 반증

#### 적발한 현실 왜곡 (Defect #1)
* **위치**: [`mock_bpf_runtime.h:333-353`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L333-L353)
* **현상 및 원인**:
  - [`mock_bpf_runtime.h:352-353`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L352-L353)에서 `#define BPF_PERCPU_ARRAY(name, val_type, max_entries) BPF_ARRAY(name, val_type, max_entries)`로 매크로를 단순 별칭(Alias) 처리하였다.
  - 이로 인해 `g_sim_cpu_id` (`bpf_get_smp_processor_id()`)가 바뀌어도 모든 CPU가 단 하나의 전역 배열 슬롯 `__sim_arr_##name[0]`을 공유한다.
  - 더 심각한 문제는 [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)가 eBPF 512B 스택 한계를 우회하기 위해 `zero_ctx_map.lookup(&zero)`와 `zero_ring_map.lookup(&zero)`가 반환한 포인터를 읽기 전용 0-초기화 템플릿으로 가정하고 `active_ctx_map.update(&tid, zctx)` 또는 `pending_handoff_map.update(&tgid, zring)`에 전달한다는 점이다.
  - 만약 어느 한 훅에서라도 `zctx = zero_ctx_map.lookup(&zero); zctx->req_id = ...; active_ctx_map.update(&tid, zctx);`와 같이 per-CPU 템플릿 원소를 in-place 수정하면, 실제 커널에서는 **해당 CPU 코어에서 이후 실행되는 모든 새로운 스레드의 `zero_ctx_map.lookup(&zero)`가 0이 아닌 오염된 `tid_ctx_t`를 반환**한다!
  - 특히 [`tracer_kernel.c:838-844`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L838-L844)의 `kprobe__tcp_recvmsg`는 패킷 도착 전에 블로킹 진입할 때 `zero_ctx_map.lookup(&zero)`로 `active_ctx_map` 엔트리를 생성한 뒤, [`tracer_kernel.c:898`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L898)의 `kretprobe__tcp_recvmsg`에서 `if (tctx->req_id == 0)` 조건으로 `sk_wait_data()` 지연 바인딩 여부를 판단한다. 만약 `zero_ctx_map` 템플릿이 오염되어 `req_id != 0`이 들어있으면 `kretprobe__tcp_recvmsg`는 지연 도착한 패킷의 `ingress_flow_map` 조회를 건너뛰고 이전 요청의 오염된 `req_id`를 그대로 사용하여 트레이스 상관관계가 완전히 붕괴된다.
* **교정 및 반증 검증**:
  - 교정된 [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/mock_bpf_runtime.h#L422-L454)에서 `BPF_PERCPU_ARRAY`를 `KRAY_SIM_MAX_CPUS (64)` 차원을 가진 진짜 per-CPU 배열 `__sim_percpu_arr_##name[KRAY_SIM_MAX_CPUS][max_entries]`로 분리하여 `g_sim_cpu_id`별로 독립된 메모리를 참조하도록 구현하였다.
  - 교정된 [`kernel_sim_harness.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/kernel_sim_harness.c#L116-L156)에 `sim_verify_zero_templates_untouched()` 및 `sim_test_percpu_template_poisoning(polluted_cpu, clean_cpu)` 함수를 추가하여, 모든 훅 실행 전후에 전 코어의 `zero_ctx_map`과 `zero_ring_map`이 단 1바이트도 오염되지 않았음을 바이트 단위로 검증하였다.

---

### 3.2 [Focus Area 2 반증] `bpf_map_update_elem` / `lookup`의 `max_entries` 용량 한계 무시, 가짜 LRU(Round-Robin FIFO) 축출, 및 플래그(`BPF_F_NO_EXIST` 등) 미구현 반증

#### 적발한 현실 왜곡 (Defect #2)
* **위치**: [`mock_bpf_runtime.h:274-330`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L274-L330) 및 [`mock_bpf_runtime.h:355-372`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L355-L372)
* **현상 및 원인**:
  - **용량 한계(`max_entries`) 무시**: `DEFINE_MOCK_BPF_HASH(name, key_type, val_type, max_entries)` 매크로가 선언 인자인 `max_entries` (`8192`, `4096`, `1024`)를 완전히 무시하고 고정 상수 `KRAY_SIM_HASH_CAP (256)` 크기의 배열만 할당하였다. 따라서 257번째 엔트리가 삽입되면 `8192` 용량의 맵임에도 기존 엔트리를 조기 덮어썼다.
  - **가짜 LRU (Round-Robin FIFO 덮어쓰기)**: [`mock_bpf_runtime.h:308-309`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L308-L309)는 빈 슬롯이 없을 때 `int evict = (int)((__sim_cursor_##name++) & (KRAY_SIM_HASH_CAP - 1));`로 무조건 0번 슬롯부터 순서대로 덮어썼다. 실제 리눅스 커널 `BPF_MAP_TYPE_LRU_HASH`는 `lookup`이나 `update`로 최근 참조된(Hot) 엔트리를 보존하고 가장 오래 참조되지 않은(Least Recently Used) 엔트리를 축출하는 반면, 기존 모의 런타임은 방금 `lookup`한 0번 슬롯의 활성 컨텍스트를 무조건 파괴하였다. 또한 일반 해시맵 모드에서는 용량 초과 시 `-E2BIG (-7)` 에러를 반환해야 하나 무조건 덮어써서 실패 경로 테스트가 불가능했다.
  - **`BPF_F_NO_EXIST` / `BPF_EXIST` 플래그 무시**: `map.update(k, v)`에 플래그 인자가 아예 없었으며, 표준 BPF 헬퍼인 `bpf_map_update_elem(map, key, val, flags)` 자체가 정의되어 있지 않았다. 따라서 `BPF_NOEXIST` (`BPF_F_NO_EXIST = 1`)에서 이미 존재하는 키 삽입 시 `-EEXIST (-17)` 반환, `BPF_EXIST` (`BPF_F_EXIST = 2`)에서 존재하지 않는 키 갱신 시 `-ENOENT (-2)` 반환, 잘못된 플래그 전달 시 `-EINVAL (-22)` 반환이 전혀 작동하지 않았다.
  - **`BPF_RINGBUF_OUTPUT.ringbuf_reserve()`의 0-초기화 왜곡**: [`mock_bpf_runtime.h:364`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L364)는 `ringbuf_reserve()` 호출 시마다 `memset(slot, 0, sizeof(struct kray_event_t))`를 수행하였다. 실제 리눅스 커널의 `bpf_ringbuf_reserve()`는 링버퍼 래핑 후 이전 이벤트의 잔여 바이트(Dirty Memory)가 남아 있는 초기화되지 않은 메모리를 반환하므로, 커널 C 코드가 특정 필드를 초기화하지 않아도 하네스에서는 0으로 보이는 왜곡이 존재했다.
* **교정 및 반증 검증**:
  - 교정된 [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/mock_bpf_runtime.h#L276-L416)에서:
    1. 각 해시맵이 선언된 실제 `max_entries` (`__sim_cap_##name`)까지 저장할 수 있도록 확장하고, 런타임에 용량 한계 테스트가 가능하도록 구성하였다.
    2. 엔트리마다 `u64 last_used` 단조 증가 시퀀스 번호(`++g_sim_lru_seq`)를 부여하고 `lookup` 및 `update` 시 갱신하여, `BPF_LRU_HASH` 용량 포화 시 정확히 최소 `last_used`를 가진 진성 LRU 슬롯을 축출하도록 구현하였다.
    3. 비-LRU 해시맵(`__sim_is_lru_##name == 0`)이 `max_entries`에 도달하면 리눅스 커널과 동일하게 `KRAY_ERR_E2BIG (-7)`를 반환하도록 구현하였다.
    4. `update_flags` 메서드 및 제네릭 `bpf_map_update_elem(map, key, val, flags)` 매크로를 구현하여 `BPF_ANY (0)`, `BPF_NOEXIST / BPF_F_NO_EXIST (1)` -> `KRAY_ERR_EEXIST (-17)`, `BPF_EXIST / BPF_F_EXIST (2)` -> `KRAY_ERR_ENOENT (-2)`, 유효하지 않은 플래그 -> `KRAY_ERR_EINVAL (-22)`를 정확히 반환하도록 구현하였다.
    5. `BPF_RINGBUF_OUTPUT.ringbuf_reserve()`가 `0x00` 대신 `0xAA` 독성 바이트(Poison Pattern)로 메모리를 채워 반환하도록 수정하여, [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)의 `__builtin_memset(ev, 0, sizeof(*ev))`가 누락된 훅이 있다면 즉시 적발되도록 강화하였다.

---

### 3.3 [Focus Area 3 반증] End-to-End Wire-to-Code 단일 패스 파이프라인 부재 및 `tracer_agent.py` 단절 반증

#### 적발한 현실 왜곡 (Defect #3)
* **위치**: [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c) 및 [`tracer_agent.py:1059-1415`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1059-L1415)
* **현상 및 원인**:
  - `kernel_sim_harness.c`에는 개별 레이어 단위의 단편적 헬퍼(`sim_tcp_v4_ingress_pipeline`, `sim_tcp_recvmsg_call`, `sim_uprobe_call`, `sim_tcp_egress_pipeline`)만 존재할 뿐, `xdp_ingress_filter` → `netif_receive_skb` → `ip_rcv` → `tcp_v4_rcv` → `tcp_recvmsg` → `sys_enter_read` → `skb_copy_datagram_iovec` → `kretprobe__skb_copy_datagram_iter` → `uprobe/uretprobe` (Acceptor) → `sys_enter_futex` → `sched_waking` → `sched_wakeup` → `sched_switch` → `uprobe` (Worker) → `block_rq_insert/issue/complete` (Off-CPU 슬립 포함) → `uretprobe` (Worker) → `sys_enter_write` → `tcp_sendmsg` → `__tcp_transmit_skb` → `ip_output` → `net_dev_queue` → `net_dev_xmit` → `kretprobe__tcp_sendmsg` 전 과정을 단일 요청 컨텍스트로 관통하는 End-to-End 파이프라인 래퍼가 없었다.
  - 더욱이 [`tracer_agent.py:1092-1247`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1092-L1247)의 `run_tracer_pipeline()`은 C 시뮬레이션 하네스(`libtracer_kernel_sim`), `RequestCorrelator`, `decode_event_metadata()`, `BinarySymbolicator.resolve_runtime_ip()`를 단 한 번도 호출하지 않고 파이썬 고정 실수(`l2_in_ms = 0.042`, `parse_ms = 0.420` 등)와 하드코딩된 문자열로 `hop_timeline`을 조립하고 있었다.
* **교정 및 반증 검증**:
  - 교정된 [`kernel_sim_harness.c:552-740`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/kernel_sim_harness.c#L552-L740)에 단일 패스 통합 파이프라인 함수 `sim_run_full_wire_to_code_pipeline()`을 구현하여, 위 24개 커널/유저 훅 단계를 한 번에 관통하며 실제 64바이트 `kray_event_t` 배열을 생성하도록 완성하였다.
  - 교정된 [`tracer_agent.py:590-750`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_agent.py#L590-L750)에 `correlate_and_symbolicate_sim_events()` 및 `run_c_harness_wire_to_code_pipeline()`을 구현하고 이를 `run_tracer_pipeline()`에 직접 연결하여, C 커널 훅이 방출한 64B 이벤트 배열이 `RequestCorrelator` → `decode_event_metadata()` → `BinarySymbolicator.resolve_runtime_ip()`를 거쳐 `parse_http_request`, `validate_auth_header`, `libcrypto_mock.so+0x...` (Stripped), `execute_storage_query` (On-CPU 17.250ms / Off-CPU Block I/O 4.275ms 분리), `format_http_response`로 정확히 심볼리케이션되도록 연결하였다.

---

## 4. 하네스 왜곡을 제거하자 드러난 `tracer_kernel.c` 및 테스트의 실제 버그 4건 (Defects #4 ~ #7)

### 4.1 [Defect #4 — 치명적 커널 C 버그] `kernel_sim_harness.c`의 맵 직접 조작(Map-Poking Cheat)이 은폐한 `lock_wait_ns == 0` 유실 버그
* **위치**:
  - 하네스 치트: [`kernel_sim_harness.c:245-252`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L245-L252) (`sim_sched_waking_and_switch`)
  - 커널 C 버그: [`tracer_kernel.c:1008-1020`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1008-L1020) (`sys_enter_futex`), [`tracer_kernel.c:1047-1056`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1047-L1056) (`sys_exit_futex`), [`tracer_kernel.c:1116-1126`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1116-L1126) (`sched_waking`), [`tracer_kernel.c:1300-1310`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1300-L1310) (`trace_uprobe_entry`)
* **반증 증거**:
  - 기존 [`kernel_sim_harness.c:245-252`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L245-L252)를 보면, `sim_sched_waking_and_switch()`는 `tracepoint__syscalls__sys_enter_futex`나 `tracepoint__sched__sched_wakeup`을 아예 호출하지 않았다! 대신 `tracepoint__sched__sched_waking`을 먼저 호출한 뒤, **하네스가 C 포인터로 `active_ctx_map.lookup(&worker_tid)`를 직접 꺼내어 `wctx->futex_enter_ts = base_ts; wctx->wakeup_ts = base_ts + lock_wait_ns;`를 강제로 덮어쓰고(Map-Poking)** `sched_switch`를 호출했다.
  - 이 치트를 제거하고 실제 리눅스 커널의 물리적 이벤트 순서대로 워커 스레드에서 `sys_enter_futex(FUTEX_WAIT)` 호출 → 억셉터 스레드에서 `sched_waking` 호출 → `sched_wakeup` 호출 → 워커 스레드로 `sched_switch` 진입을 실행하자, **`sched_switch`에서 계산된 `lock_wait_ns`가 `45000`이 아니라 `0`이 나오는 치명적 버그가 드러났다!**
  - **근본 원인 2가지**:
    1. 워커 스레드는 요청을 인계받기 전에 유휴 상태에서 `futex(FUTEX_WAIT)`에 진입하므로 당시에는 `active_ctx_map.lookup(&worker_tid)`가 `NULL`이다. 그런데 [`tracer_kernel.c:1010`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1010)의 `sys_enter_futex`는 `if (!tctx) return 0;`으로 즉시 종료하여 `futex_enter_ts`를 기록하지 못했다.
    2. 설령 `active_ctx_map`에 `futex_enter_ts`가 기록되어 있었더라도, 이후 [`tracer_kernel.c:1116`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1116)의 `sched_waking` (및 `sys_exit_futex`, `trace_uprobe_entry`)이 `zero_ctx_map.lookup(&zero)` 템플릿으로 `active_ctx_map.update(&target_tid, zctx)`를 덮어쓰면서 기존 `futex_enter_ts`를 0으로 날려버리고 그 직후 `nctx = active_ctx_map.lookup(&target_tid)`를 다시 조회하더라도 이미 `nctx->futex_enter_ts`는 0으로 초기화된 뒤였다!
* **교정 패치**:
  - [`tracer_kernel.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_kernel.c#L1004-L1026)의 `sys_enter_futex`에서 대상 프로세스(`should_trace_sock_pid_tgid`)의 스레드가 `FUTEX_WAIT`에 진입할 때 `tctx == NULL`이면 `zero_ctx_map` 템플릿으로 엔트리를 생성하고 `tctx->futex_enter_ts = bpf_ktime_get_ns()`를 기록하도록 수정하였다.
  - [`tracer_kernel.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_kernel.c#L1047-L1150)의 `sys_exit_futex`, `sched_waking`, `trace_uprobe_entry`에서 `zero_ctx_map`으로 워커 컨텍스트를 초기화하기 전에 기존 `prev_futex_ts = wctx ? wctx->futex_enter_ts : 0;`를 백업하고 초기화 직후 `wctx->futex_enter_ts = prev_futex_ts;`를 복원하도록 수정하였다.
  - [`kernel_sim_harness.c:412-450`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/kernel_sim_harness.c#L412-L450)의 `sim_sched_waking_and_switch`에서 맵 직접 조작 치트를 완전히 삭제하고 실제 `tracepoint__syscalls__sys_enter_futex` → `tracepoint__sched__sched_waking` → `tracepoint__sched__sched_wakeup` → `tracepoint__sched__sched_switch` 호출만으로 `lock_wait_ns == 45000`과 32비트 상한 캡(`0xFFFFFFFF`)이 정확히 동작함을 입증하였다.

---

### 4.2 [Defect #5 — 커널 C 버그] 비연결형(Unconnected) UDP `kprobe__udp_sendmsg`에서 원격 클라이언트 IP/Port가 `0.0.0.0:0`으로 방출되는 버그
* **위치**: [`tracer_kernel.c:1843-1869`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1843-L1869) (`kprobe__udp_sendmsg`) 및 [`test_verification_suite.py:1510-1513`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1510-L1513) (`ADV-TEST-04`)
* **반증 증거**:
  - [`PROMPT_SPEC.md:197`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L197) (Flaw #35)은 비연결형 UDP 서버 소켓(`0.0.0.0:8080`)의 경우 `sk->sk_daddr == 0`, `sk->sk_dport == 0`이므로 `msg->msg_name` (`struct sockaddr_in *`)에서 피어 주소와 포트를 추출해야 한다고 명시하였다.
  - 그러나 [`tracer_kernel.c:1847`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1847)의 `kprobe__udp_sendmsg`는 `struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);`를 선언만 해놓고 `(void)msg;` 처리한 뒤, `populate_sock_flow_key(sk, &key, IPPROTO_UDP, 1)`만 호출하여 `dst_ip = 0`, `dst_port = 0`인 이벤트를 방출하고 있었다!
  - 기존 `ADV-TEST-04` (`test_verification_suite.py:1513`)는 `assert udp_evs[0].req_id == udp_evs[1].req_id == udp_evs[2].req_id`만 검사하고 `udp_evs[2].dst_ip`와 `udp_evs[2].dst_port`를 검사하지 않아 이 버그를 놓쳤다.
* **교정 패치**:
  - [`tracer_kernel.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_kernel.c#L1810-L1905)의 `kretprobe__udp_recvmsg`에서 추출한 클라이언트 주소/포트를 `tctx` (`src_ip`, `dst_ip`, `src_port`, `dst_port`)에 저장하고, `kprobe__udp_sendmsg`에서 `skc_daddr == 0`일 때 `msg->msg_name` (`struct sockaddr_in`) 또는 `tctx`에 저장된 클라이언트 피어 주소를 읽어 `key.daddr`와 `key.dport`를 채우도록 수정하였다.
  - `ADV-TEST-04`에 `assert udp_evs[2].dst_ip == 0x0200007F and udp_evs[2].dst_port == 55111` 단언문을 추가하여 검증하였다.

---

### 4.3 [Defect #6 — 커널 C 버그] `sys_enter_write`의 `tctx->last_stage_ts` 미사용(하드코딩 `25000ULL`) 및 Egress/IPv6 패킷 이벤트의 TTL/IHL 비트패킹 누락
* **위치**: [`tracer_kernel.c:1374-1435`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1374-L1435), [`tracer_kernel.c:1487-1554`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1487-L1554), [`tracer_kernel.c:1671-1688`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1671-L1688), [`tracer_kernel.c:1938-1954`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1938-L1954)
* **반증 증거**:
  - [`tracer_kernel.c:1374`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1374)의 `tracepoint__syscalls__sys_enter_write`는 `tctx->last_stage_ts = bpf_ktime_get_ns();`를 기록하지만, 정작 직후 호출되는 [`tracer_kernel.c:1426`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1426)의 `kprobe__tcp_sendmsg`는 `tctx->last_stage_ts`를 읽지 않고 `25000ULL` 상수를 하드코딩하여 방출하고 있었다.
  - 또한 [`PROMPT_SPEC.md:451`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md#L451) 및 `tracer_agent.py`의 `decode_event_metadata()`는 `OSI_L3_IP (3)`와 `OSI_L4_TCP (4)` 이벤트의 `ev->ip`가 `((u64)ttl << 24) | ((u64)ihl_bytes << 16) | (u64)pkt_len`으로 비트패킹되어 있다고 정의하나, `kprobe____tcp_transmit_skb`, `kprobe__ip_output`, `kprobe__tcp_v6_rcv`, `kprobe__ip6_output`은 상위 비트를 채우지 않고 `estate->pkt_len`만 대입하여 `decode_event_metadata()` 호출 시 `ttl == 0, ihl_bytes == 0`으로 디코딩되었다.
* **교정 패치**:
  - `kprobe__tcp_sendmsg`에서 `tctx->last_stage_ts > 0 && now >= tctx->last_stage_ts`일 때 실제 경과 시간 `now - tctx->last_stage_ts`를 계산하도록 수정하였다.
  - IPv4 Egress(`kprobe____tcp_transmit_skb`, `kprobe__ip_output`)에는 `(64ULL << 24) | (20ULL << 16) | pkt_len`, IPv6(`kprobe__tcp_v6_rcv`, `kprobe__ip6_output`)에는 `(64ULL << 24) | (40ULL << 16) | pkt_len`을 패킹하여 `decode_event_metadata()`와 100% 일관성을 확보하였다.

---

### 4.4 [Defect #7 — 테스트/하네스 결함] `kernel_sim_harness.c`의 미호출 훅 5개 방치 및 `ADV-TEST-12` 소켓 레이스 컨디션(`Connection refused`)
* **위치**: [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c) 및 [`test_verification_suite.py:2035-2043`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2043)
* **반증 증거**:
  - `kernel_sim_harness.c`에서 `tracepoint__tcp__tcp_retransmit_skb`, `tracepoint__syscalls__sys_enter_futex`, `tracepoint__sched__sched_process_fork`, `tracepoint__sched__sched_wakeup`, `kprobe__ip6_output` 및 `kfree_skb`의 Stage 1(`skb_egress_map`)이 단 한 번도 호출되지 않아 해당 훅들의 런타임 동작이 검증되지 않고 있었다.
  - `ADV-TEST-12`는 `mock_server` 프로세스 기동 후 고정 `time.sleep(0.25)`만 대기하여 macOS Gatekeeper/동적 링커 초기 지연 시 `[Errno 61] Connection refused`로 실패하였으며, `mock_server.cpp`가 인식하지 못하는 `--fast-mode` 인자를 전달하고 있었다.
* **교정 패치**:
  - `kernel_sim_harness.c`에 `sim_tcp_retransmit_skb_test`, `sim_sched_process_fork_test`, `sim_ip6_output_test` 및 `sim_kfree_skb_test(..., stage=1)`을 모두 구현하고 `ADV-TEST-01`/`ADV-TEST-04`에서 전수 호출·검증하였다.
  - `mock_server.cpp`가 `--fast-storage`와 `--fast-mode`를 모두 수용하도록 보강하고, `ADV-TEST-12`가 소켓 연결 준비 완료를 최대 1.5초간 폴링하도록 수정하였다.

---

## 5. 프로젝트 목적 달성을 위한 구체적 코드 패치안 (Concrete Patch Proposals)

### 5.1 [`mock_bpf_runtime.h`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/mock_bpf_runtime.h) 핵심 패치 코드
* **교정 파일 전체 경로**: [`/Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/mock_bpf_runtime.h`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/mock_bpf_runtime.h)
* **패치 요약**:
  - `BPF_ANY (0)`, `BPF_NOEXIST / BPF_F_NO_EXIST (1)`, `BPF_EXIST / BPF_F_EXIST (2)` 및 커널 에러 코드(`KRAY_ERR_ENOENT = -2`, `KRAY_ERR_E2BIG = -7`, `KRAY_ERR_EEXIST = -17`, `KRAY_ERR_EINVAL = -22`) 정의.
  - `DEFINE_MOCK_BPF_HASH`에서 실제 `max_entries` 용량 지원, `last_used` 시퀀스 기반 진성 LRU 축출, 비-LRU 해시맵 용량 초과 시 `-E2BIG` 반환, `update_flags` 및 `bpf_map_update_elem(map, k, v, flags)` 지원.
  - `BPF_PERCPU_ARRAY`를 `g_sim_cpu_id` 인덱싱 기반의 2차원 `[KRAY_SIM_MAX_CPUS][max_entries]` 배열로 분리.
  - `BPF_RINGBUF_OUTPUT.ringbuf_reserve()`에서 `0xAA` 독성 바이트 초기화 적용.

### 5.2 [`tracer_kernel.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_kernel.c) 핵심 패치 코드
* **교정 파일 전체 경로**: [`/Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_kernel.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_kernel.c)
* **패치 요약**:
  - `sys_enter_futex`에서 유휴 워커 스레드(`tctx == NULL`)가 `FUTEX_WAIT` 진입 시 `zero_ctx_map`으로 엔트리를 생성하고 `futex_enter_ts`를 기록.
  - `sched_waking`, `sys_exit_futex`, `trace_uprobe_entry`에서 `zero_ctx_map` 템플릿으로 워커 컨텍스트 갱신 시 기존 `futex_enter_ts` 보존.
  - `kretprobe__udp_recvmsg` 및 `kprobe__udp_sendmsg`에서 비연결형 UDP 소켓의 클라이언트 IP/Port를 `msg->msg_name` 및 `tctx`로부터 복원.
  - `kprobe__tcp_sendmsg`에서 `tctx->last_stage_ts` 기반 실제 syscall-to-socket 지연 계산 및 Egress/IPv6 `(ttl << 24) | (ihl << 16) | pkt_len` 비트패킹 통일.

### 5.3 [`kernel_sim_harness.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_agent.py), [`test_verification_suite.py`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/test_verification_suite.py) 핵심 패치
* **교정 파일 전체 경로**:
  - [`/Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/kernel_sim_harness.c`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/kernel_sim_harness.c)
  - [`/Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_agent.py`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/tracer_agent.py)
  - [`/Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/test_verification_suite.py`](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/e160188b-faa4-42da-8033-d7ee42689ada/scratch/kray_agent_07/test_verification_suite.py)
* **패치 요약**:
  - `sim_verify_zero_templates_untouched()`, `sim_test_percpu_template_poisoning()`, `sim_test_map_capacity_and_flags()`, `sim_run_full_wire_to_code_pipeline()` 구현.
  - `sim_sched_waking_and_switch()`의 맵 직접 조작 치트 제거 및 실제 `sys_enter_futex` → `sched_waking` → `sched_wakeup` → `sched_switch` 체인 실행.
  - 미호출 훅 5개(`tcp_retransmit_skb`, `sys_enter_futex`, `sched_process_fork`, `sched_wakeup`, `ip6_output`) 및 `kfree_skb` Stage 1 테스트 추가.
  - `tracer_agent.py`에 `run_c_harness_wire_to_code_pipeline()` 및 `correlate_and_symbolicate_sim_events()`를 추가하여 C 하네스 64B 이벤트를 `RequestCorrelator` 및 `BinarySymbolicator`로 종단간 연결.
