# [Draft RFC] Pre-Implementation Single-Sheet Specification, Multi-Pass Ground-Truth Design Audit, and Audit Report Pipeline

- **문서 경로**: `docs/drafts/DRAFT_SPEC_AUDIT_REPORT_PIPELINE.md`
- **패키지 루트**: `archive/softwarefactory-draft/`
- **상태**: Draft RFC / Ready for `softwarefactory` Adoption
- **적용 계층**:
  - **Tier 1 (Hard Lifecycle Gate)**: `.agents/hooks.json` + `.agents/scripts/design_audit_gate.py`
  - **Tier 2 (On-Demand Progressive Disclosure Runbook)**: `.agents/skills/pre-implementation-design-audit/SKILL.md`
  - **Tier 3 (Architecture & Empirical Reference)**: `docs/drafts/DRAFT_SPEC_AUDIT_REPORT_PIPELINE.md`

---

## 1. 개요 및 핵심 원칙 (Overview & Core Principle)

복잡한 시스템 소프트웨어(커널 트레이서, 분산 엔진, 프로토콜 브릿지, 컴파일러/바이트코드 검증기 등)를 개발할 때 대략적인 요구사항만 적고 곧바로 구현 코드(`*.c`, `*.cpp`, `*.py`, `*.rs`, `*.go`, `*.ts` 등)를 작성하면 다음과 같은 구조적 실패가 반복됩니다.

- **추상적 가정과 실제 런타임/커널 ABI 간 괴리**:
  - 함수 이름이나 개략적 인터페이스만 보고 코드를 작성하면, 함수 진입 시점에 아직 초기화되지 않은 포인터/헤더 오프셋을 참조하거나 이미 해제된 버퍼(Use-After-Free)를 읽는 치명적 결함이 구현 후반부에야 발견됩니다.
- **정적 검증기(Verifier) 및 하드웨어/OS 한계 위반**:
  - eBPF 512바이트 스택 한계(`MAX_BPF_STACK = 512`), 비신뢰 커널 포인터 직접 역참조 거부, Per-CPU 맵 인플레이스 오염, SMP 멀티코어 인터럽트 컨텍스트 불일치 등은 단순 코드 디버깅으로 해결할 수 없으며 아키텍처 자체를 재설계해야 합니다.
- **부분 수정(Patchwork)으로 인한 설계 일관성 붕괴**:
  - 구현 도중 에러가 발생할 때마다 임시방편으로 코드를 덧붙이면 데이터 구조체, 바이트 오더(Endianness), 상태 머신, JSON 출력 스키마 간의 정합성이 깨집니다.

이를 원천 차단하기 위해 **`softwarefactory` 표준 사전 설계 감사 파이프라인(Pre-Implementation Design Audit Pipeline)** 은 단 한 줄의 프로덕션 코드를 작성하기 전에 반드시 아래 **3단계(3-Step Pipeline)** 를 완료하고 하드 게이트(Hard Gate)의 검증을 통과하도록 강제합니다.

### Step 1 — 1장 마스터 설계 문서 작성 (`PROMPT_SPEC.md`)
- 프로젝트 루트에 단일 마스터 설계 명세서(`PROMPT_SPEC.md` 또는 `SPEC.md`)를 작성합니다.
- 시스템 아키텍처, 계층별 상태 전이, 고정 크기 메모리/맵 레이아웃, 바이트 오더 및 ABI 규약, 수식, 출력 JSON/CLI 스키마, E2E 테스트 케이스를 빈틈없이 단일 문서에 정의합니다.

### Step 2 — 다회차 실증 디자인 어딧 수행 (Iterative Ground-Truth Design Audit)
- 작성된 `PROMPT_SPEC.md`의 모든 가정을 백지화(Zero-Assumption)하고, 실제 타겟 환경의 Ground-Truth 레퍼런스(커널 소스 트리의 정확한 파일/줄 번호, BTF `vmlinux.h`, ELF/DWARF 규격, 공식 언어/런타임 문서)와 1:1로 대조하여 최소 **3회차(3 Phases)** 에 걸친 적대적 설계 감사(Adversarial Design Audit)를 수행합니다.
- 발견된 모든 설계 결함은 즉시 `PROMPT_SPEC.md` 본문과 수식에 인플레이스(In-Place)로 반영하여 명세서를 무결점 상태로 진화시킵니다.

### Step 3 — 디자인 어딧 리포트 아카이빙 (`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`)
- 각 감사 회차(Phase 1, Phase 2, Phase 3)에서 발굴한 설계 결함의 정확한 원인(소스 파일/줄 번호 및 메커니즘)과 교정된 명세 해법 공식을 `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`에 체계적으로 기록합니다.
- 이 리포트가 완성되어 검증 기준을 충족하기 전까지는 어떠한 구현 코드 파일 생성도 허용되지 않습니다.

---

## 2. 배치 위치 및 아키텍처 설계 근거 (Placement & Architectural Rationale: Where & Why)

Antigravity 커스터마이제이션 시스템의 로딩 우선순위와 점진적 공개(Progressive Disclosure) 원칙에 맞추어, 본 파이프라인은 역할을 **3개 계층(3-Tier Architecture)** 으로 분리 배치합니다.

### 2.1 Tier 1 — 결정론적 생명주기 하드 게이트 (`.agents/hooks.json` + `.agents/scripts/design_audit_gate.py`)

#### 배치 위치
- `.agents/hooks.json`
- `.agents/scripts/design_audit_gate.py`

#### 설계 근거 (Why Here?)
- 단순 프롬프트 지시문(`GEMINI.md`나 `AGENTS.md`)만으로는 에이전트가 복잡한 태스크 수행 중 지시를 건너뛰고 곧바로 `write_file`이나 `edit_file`로 소스 코드(`*.c`, `*.py` 등)를 생성하는 것을 100% 막을 수 없습니다.
- Antigravity의 **`PreToolUse` Lifecycle Hook**은 도구 실행 직전에 인터셉트하여 결정론적 파이썬 스크립트(`design_audit_gate.py`)를 실행하고, 조건 미충족 시 `{"decision": "deny", "reason": "..."}`를 반환하여 **도구 실행 자체를 하드 블록(Hard Block)** 합니다.
- 또한 **`Stop` Lifecycle Hook**은 에이전트가 `PROMPT_SPEC.md`만 작성하고 디자인 어딧 리포트(`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`)를 작성하지 않은 채 턴을 종료(`terminationReason == "NO_TOOL_CALL"`)하려 할 때 `{"decision": "continue", "reason": "..."}`를 반환하여 **자동으로 루프를 재진입시켜 디자인 어딧과 리포트 작성을 완수**하게 만듭니다.

#### 게이트 동작 규칙
- **항상 허용(`"decision": "allow"`)되는 경로**:
  - `PROMPT_SPEC.md`, `SPEC.md`
  - `archive/*` (특히 `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`)
  - `docs/*`, `README.md`, `.agents/*`, 스크래치 및 아티팩트 경로
- **게이트 검증 대상(구현 코드 및 빌드 파일)**:
  - `*.c`, `*.cpp`, `*.cc`, `*.h`, `*.hpp`, `*.py`, `*.rs`, `*.go`, `*.ts`, `*.tsx`, `*.js`, `*.java`, `Dockerfile`, `Makefile`, `CMakeLists.txt`, `*.sh`
- **통과 조건**:
  1. `<workspace>/PROMPT_SPEC.md` (또는 `SPEC.md`) 파일이 존재하고 최소 100줄 이상일 것.
  2. `<workspace>/archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md` 파일이 존재하고 최소 100줄 이상이며, 다회차 감사 결과(Phase 1 / Phase 2 / Phase 3 섹션 또는 최소 10개 이상의 결함 분석 항목)를 포함할 것.

---

### 2.2 Tier 2 — 온디맨드 점진적 공개 런북 스킬 (`.agents/skills/pre-implementation-design-audit/SKILL.md`)

#### 배치 위치
- `.agents/skills/pre-implementation-design-audit/SKILL.md`

#### 설계 근거 (Why Here?)
- 디자인 어딧을 수행하는 상세 체크리스트와 리포트 템플릿은 분량이 크므로 모든 대화 턴마다 컨텍스트 윈도우에 상주시키면 토큰 낭비가 발생합니다.
- Antigravity의 **Skills (Progressive Disclosure)** 메커니즘을 사용하면 평소에는 스킬의 `name`과 `description`만 노출되고, 에이전트가 실제로 설계서 작성 및 디자인 어딧 단계에 진입하거나 `PreToolUse` 게이트로부터 `"deny"` 메시지를 받았을 때만 온디맨드로 `SKILL.md` 전문을 로드하여 정밀한 3단계 절차를 수행합니다.

---

### 2.3 Tier 3 — 아키텍처 드래프트 및 실증 케이스 스터디 (`docs/drafts/DRAFT_SPEC_AUDIT_REPORT_PIPELINE.md`)

#### 배치 위치
- `docs/drafts/DRAFT_SPEC_AUDIT_REPORT_PIPELINE.md`

#### 설계 근거 (Why Here?)
- `softwarefactory`의 아키텍처 표준 문서 및 엔지니어링 온보딩 레퍼런스로서, 왜 이 파이프라인이 도입되었는지와 실제 프로젝트(`ebpf-wire-to-code-tracer`)에서 코드 작성 전 45건의 치명적 결함을 어떻게 사전에 제거했는지 실증 데이터를 보존합니다.

---

## 3. 실증 케이스 스터디 (Empirical Case Study): `ebpf-wire-to-code-tracer`

본 3단계 파이프라인은 리눅스 커널 네트워크 스택(L2~L4)부터 스케줄러, 시스템콜, 유저 공간 C++/Python 함수 및 Stripped 바이너리 어셈블리(L7)까지 단일 요청(`req_id`)으로 관통 추적하는 **`ebpf-wire-to-code-tracer`** 프로젝트에서 실증되었습니다.

단 한 줄의 C(eBPF) 코드나 Python/C++ 코드를 작성하기 전에, `PROMPT_SPEC.md`를 타겟 커널(`Rocky Linux 9.8 aarch64`, Kernel `5.14.0-687.10.1.el9_8.0.1.aarch64`) 원본 소스 코드 및 BTF(`vmlinux.h`)와 대조하여 **총 3차례(Phase 1 ~ Phase 3)에 걸쳐 45건의 치명적 설계 결함**을 사전 발굴·제거했습니다.

### 3.1 Phase 1 — 1차 아키텍처 10회 반복 설계 감사 (10 Architectural Flaws Caught)

1. **512바이트 eBPF 스택 한계 초과 (`tid_ctx_t` 432B 지역 변수 선언 시 Verifier 즉시 거부)**:
   - 스택 변수 선언 대신 `BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)` 스크래치 템플릿을 통해 스택 사용량을 `0 Bytes`로 제거.
2. **루프백(`lo`) 환경에서 서버/클라이언트 패킷 혼선 및 0바이트 `ACK` 패킷의 `req_id` 덮어쓰기**:
   - Server-Role Direction Guard(`dport == target_port`, `skc_num == target_port`) 및 Payload-Gated `req_id` Minting(`tcp_payload_len > 0`) 도입.
3. **`sk->__sk_common` 4-Tuple 방향 역전 및 포트 엔디안 불일치 (`skc_num` 호스트 오더 vs `skc_dport` 네트워크 오더)**:
   - 수신/송신 브릿지 조회 키 정규화(`skc_num`에는 `bpf_ntohs` 호출 금지, `skc_dport`에만 `bpf_ntohs` 적용).
4. **SMP 멀티코어 환경에서 `sched_wakeup`의 인터럽트 컨텍스트 불일치**:
   - 100% Waker 컨텍스트가 보장되는 `tracepoint:sched:sched_waking`(`include/trace/events/sched.h:167-180`) 채택.
5. **1바이트 `call_depth` 필드에서 유저 함수 호출 깊이(`0..15`)와 `OSI_L5_SYSCALL_MEM (6)` / `OSI_L6_PRE_COMPUTE (8)` 충돌**:
   - `(layer_type, call_depth)` 직교 분리 원칙 수립.
6. **함수 내부 Off-CPU 대기 시간과 On-CPU 순수 ALU 연산 시간 미분리**:
   - `acc_off_cpu_ns`, `fn_off_cpu_snap[16]`, `inflight_bio_map` 도입으로 On-CPU/Off-CPU 정밀 분리.
7. **C++ 바이너리의 수천 개 STL/런타임 심볼 무차별 `uprobe` 부착으로 인한 `EMFILE` 크래시**:
   - STL/런타임 접두사 필터링 및 `MAX_AUTO_UPROBES = 64` 상한 적용.
8. **`kray_runtime_cfg_t.filter_flags`의 8비트(`u8`) 오버플로우 위험**:
   - 하위 4비트(프로토콜 패밀리 마스크) + 상위 4비트(계층 그룹 마스크)로 4+4 비트 분할.
9. **비동기 SoftIRQ Egress 이벤트(`LAYER_EGRESS_NIC`) 조기 누락**:
   - `50ms` Grace Window 대기 상태 머신 및 `(timestamp, layer_order, is_return)` 정규 정렬 도입.
10. **단일 스레드 REST/MCP 서버의 블로킹 데드락(Hang)**:
    - `ThreadingHTTPServer` + `threading.RLock()` + 내장 루프백 패킷 트리거(`500ms` 이내 무블로킹 응답) 강제.

### 3.2 Phase 2 — 2차 심층 커널 소스·Verifier·ELF·런타임 감사 (25 Deep Kernel/Runtime Flaws Caught)

1. **`kprobe__ip_rcv` 진입 시점의 미초기화 `skb->transport_header` 참조 버그 (`net/ipv4/ip_input.c:552-562`)**:
   - `ip_rcv` 진입 시에는 아직 `skb->transport_header`가 설정되기 전(`0xFFFF`)이므로 `net_off + ((iph.ihl & 0x0f) * 4)`로 L4 오프셋을 직접 계산.
2. **`kprobe____tcp_transmit_skb` 진입 시점의 빈 `skb` 헤더 및 `tracepoint:net:net_dev_xmit`의 Use-After-Free (`net/ipv4/tcp_output.c:1238-1309`)**:
   - 진입 시 `PARM1 = struct sock *sk`에서 4-Tuple을 읽고 `skb_egress_map[(u64)skb]`에 포인터를 선행 바인딩하여 이후 훅에서 `skb->head` 역참조 없이 조회.
3. **`pending_handoff_map[tgid]` 단일 슬롯의 동시 다중 요청 덮어쓰기 레이스 컨디션**:
   - 8-슬롯 원형 FIFO 링 버퍼(`struct handoff_ring_t`) 도입.
4. **`uretprobe` 복귀 시 `PT_REGS_IP(ctx)`가 커널 `[uprobes]` 트램펄린 주소로 치환되는 현상**:
   - `uprobe` 진입 시 `ctx->fn_entry_ip[depth] = PT_REGS_IP(ctx)` 백업 후 `uretprobe`에서 복원.
5. **`uretprobe`에서 `call_depth == 0` 언더플로우(`u8: 0 -> 255`) 및 `parent_tid` 유실**:
   - `if (ctx->call_depth == 0) return 0;` 언더플로우 가드 및 `parent_tid` 전파 강제.
6. **표준 Tracepoint(`sched_waking`, `sched_switch`)의 `TP_STRUCT__entry` 실제 필드명 불일치 (`include/trace/events/sched.h`)**:
   - `args->pid`, `args->prev_pid`, `args->next_pid`, `args->prev_state` 평탄화 필드명 명시.
7. **`sys_exit_write`에서 `active_ctx_map` 삭제 시 일반 로깅 `write(1, ...)`가 컨텍스트를 파괴하는 버그 + `tcp_sendmsg`의 `kretprobe` 교정**:
   - `sys_exit_write`에서 컨텍스트 삭제를 금지하고 `kretprobe__tcp_sendmsg`(`in_target_sendmsg == 1`)에서만 삭제.
8. **중첩 유저 함수(`A() -> B()`)에서 Off-CPU 대기 시간 이중 차감(Double-Subtraction)**:
   - 직접 자식(Direct Child) L5/L6 이벤트 시간만 합산 차감 및 `off_cpu_io_wait_ms` 필드명 단일화.
9. **RingBuf 100% 포화(`ringbuf_reserve() == NULL`) 시 드롭 카운트 누락**:
   - `drop_cnt_map[0]` 커널 배열 직접 조회 공식(`max(max_event_drop_count, bpf_drop_cnt_map[0])`) 강제.
10. **`AF_UNIX` 커널 훅(`unix_stream_recvmsg`/`sendmsg`)의 첫 번째 인자 타입(`struct socket *sock` vs `struct sock *sk`) 불일치 (`net/unix/af_unix.c:2053`)**:
    - `sock->sk` 2단계 커널 포인터 역참조 적용.
11. **`tracepoint:block:block_rq_complete`에 존재하지 않는 `args->bytes` 필드 참조 및 NVMe `blk-mq`의 `block_rq_insert` 생략 (`include/trace/events/block.h:124-169`)**:
    - `block_rq_insert`와 `block_rq_issue` 양쪽 모두에서 등록하고 완료 시 `(u64)args->nr_sector * 512`로 바이트 산출.
12. **`glibc` 유저 공간 Condvar Fastpath(`__wrefs == 0`)로 인한 `sys_enter_futex(FUTEX_WAKE)` 시스콜 생략**:
    - `kprobe__tcp_recvmsg` 시점에 8-슬롯 FIFO에 선행 게시(Pre-Publish)하고 모든 Futex 깨우기 Opcode(`1, 3, 4, 5, 7, 10, 12`)를 포괄.
13. **`mock_server.cpp`를 `-O1`로 컴파일할 때 타겟 함수들이 인라이닝되어 `uprobe`가 증발하는 결함**:
    - `__attribute__((noinline))` 및 `-g -O0 -fno-inline -fno-omit-frame-pointer` 빌드 플래그 강제.
14. **`strip -x` 처리된 `libcrypto_mock.so`에서 `.symtab` 제거 후 내부 정적 함수 오프셋 자동 발굴 불가**:
    - `.eh_frame` FDE(`pc_begin .. pc_end`) 엔트리 및 `.dynsym` 내부 `bl`/`callq` 타겟 오프셋 스캐너 도입.
15. **`kprobe`에서 `skb->head + net_off` 직접 역참조 시 eBPF Verifier 거부(`R1 invalid mem access 'scalar'`)**:
    - `bpf_probe_read_kernel()` 2단계 헬퍼 호출 강제.
16. **`tracepoint:skb:kfree_skb`에서 정상 패킷 소비(`SKB_CONSUMED = 1`)까지 패킷 드롭으로 오탐 (`include/net/dropreason-core.h:129-138`)**:
    - `args->reason > SKB_DROP_REASON_NOT_SPECIFIED (2)` 조건만 실제 드롭으로 필터링.
17. **`tracepoint:tcp:tcp_retransmit_skb`의 포트 이중 `ntohs()` 버그 및 `__u8 saddr[4]` 배열 레이아웃 (`include/trace/events/tcp.h:35-57`)**:
    - 이미 호스트 바이트 오더인 `args->sport`/`dport`에 `bpf_ntohs()` 호출 금지 및 `*(__be32 *)args->saddr` 역참조 적용.
18. **`tracepoint:sched:sched_process_fork`의 필드명(`args->parent_pid`, `args->child_pid`) 명세**:
    - `include/trace/events/sched.h:358-385` 기준 정확한 필드명 고정.
19. **`AF_UNIX` 송수신 소켓 포인터(`sk` vs `unix_sk(sk)->peer`) 비대칭**:
    - 송수신 양측이 동일한 `(client_sk, server_sk)` 쌍을 해시 키로 사용하도록 정규화.
20. **Generic XDP(`XDP_FLAGS_SKB_MODE`) 활성화 시 `xdp_ingress_filter`와 `netif_receive_skb`의 L2 이벤트 중복 방출**:
    - `state->xdp_ts != 0 && state->consumed == 0` 중복 방출 스킵 가드 추가.
21. **`kprobe__handle_mm_fault`에서 매 마이너 페이지 폴트마다 64B RingBuf 이벤트 방출 시 발생하는 링버퍼 폭주**:
    - `ctx->page_faults++` 인플레이스 카운터 누적 후 메모리 복사 완료 시 단일 이벤트로 합산 방출.
22. **`aarch64` PIE/공유 라이브러리에서 ELF 심볼 `st_value`를 파일 오프셋으로 변환하는 `PT_LOAD` 수식 누락**:
    - `uprobe_file_offset = st_value - seg.p_vaddr + seg.p_offset` 공식 명세.
23. **`ai_diagnosis.json` 최상위 8대 필수 키 스키마 고정**:
    - `req_id`, `total_rtt_ms`, `drop_count`, `bottleneck_summary`, `hop_timeline`, `source_code_evidence`, `stripped_assembly_evidence`, `network_layer_diagnostics` 고정.
24. **Graphviz `subgraph cluster_mod_<filename>`에 마침표(`.`) 포함 시 `dot -Tsvg` 문법 에러 발생**:
    - 식별자 정규화(`re.sub(r'[^a-zA-Z0-9_]', '_', ...)`) 강제.
25. **최소 컨테이너 환경에서 `iproute2`(`ss`) 미설치 시 `--discover-ports` 실패**:
    - `/proc/net/{tcp,tcp6,udp,udp6,unix}` + `/proc/<pid>/fd/*` 직접 파서 내장.

### 3.3 Phase 3 — 3차 극한 커널 실행 순서·블로킹 소켓·Per-CPU 오염·다중 프로토콜·CO-RE ABI 감사 (10 Execution-Order & ABI Flaws Caught)

1. **블로킹 소켓 `tcp_recvmsg` 진입 시 패킷 미도착(`sk_wait_data`, `net/ipv4/tcp.c:2638`)으로 인한 `ingress_flow_map` 조회 실패 및 버퍼 크기(`len=4096`) 오기록**:
   - `kprobe__tcp_recvmsg` + `kretprobe__tcp_recvmsg` 이중 바인딩 및 `PT_REGS_RC(ctx)`(`copied`) 실제 수신 바이트 기록.
2. **`tracepoint:net:netif_receive_skb` 실행 시점(line 5606)의 미초기화 `skb->network_header`(line 5610에 리셋) 및 Generic XDP(`do_xdp_generic`, line 5626)와의 실행 순서 역전 (`net/core/dev.c:5606-5626`)**:
   - `skb->data`에서 직접 `struct iphdr`를 읽고 `xdp_ingress_filter`와 `netif_receive_skb` 양방향 중복 방지 가드 적용.
3. **`trace_skb_copy_datagram_iovec`(line 534)가 실제 유저 메모리 복사(`simple_copy_to_iter`, line 535) 및 페이지 폴트보다 먼저 실행되는 순서 결함 (`net/core/datagram.c:531-537`)**:
   - 진입 시 타임스탬프만 기록하고 복사가 완료된 직후(`kretprobe__skb_copy_datagram_iter`)에 페이지 폴트 누적치와 복사 소요 시간을 방출.
4. **유저 함수 실행 중(`call_depth > 0`) Off-CPU Sleep 시 `wakeup_ts`로 인해 슬립 시간(`18ms`)이 증발하고 On-CPU 연산으로 오판되는 결함**:
   - `call_depth == 0`일 때는 런큐 대기 시간(`runq_ns`), `call_depth > 0`일 때는 전체 Off-CPU 시간(`total_off_cpu_ns`)을 방출하고 타임스탬프를 즉시 `0`으로 리셋.
5. **`BPF_PERCPU_ARRAY(zero_ctx_map)`를 In-Place 수정할 때 동일 CPU 코어의 다음 스레드 초기화가 오염되는 결함**:
   - `zero_ctx_map[0]`을 순수 읽기 전용(Strictly Read-Only) 템플릿으로만 사용하도록 강제.
6. **리눅스 커널 헤더(`include/uapi/linux/if_arp.h:144-161`)의 `struct arphdr`에서 `ar_sip`/`ar_tip` 멤버가 `#if 0`으로 비활성화되어 있는 컴파일 결함**:
   - `(u8 *)(arp + 1) + 6` 및 `+ 16` 바이트 오프셋에서 IPv4 주소를 추출하도록 교정.
7. **비연결(Unconnected) UDP 서버 소켓의 `skc_daddr == 0`, `skc_dport == 0` 문제 (`net/ipv4/udp.c:1868-1945`)**:
   - `kretprobe__udp_recvmsg`에서 `msg->msg_name`(`struct sockaddr_in *`)을 읽어 송신자 IP/포트를 복원하고 포트 단위 폴백 키를 병행 지원.
8. **순수 IPv6 소켓(`skc_v6_daddr`) 32비트 XOR 폴딩, Dual-Stack(`::ffff:`) `AF_INET` 정규화 및 `kprobe__ipv6_rcv`의 미초기화 `transport_header` (`net/ipv6/ip6_input.c:260, 302`)**:
   - 128비트 주소 XOR 폴딩, `skc_daddr != 0` 시 `AF_INET` 정규화, `net_off + 40` L4 오프셋 계산 적용.
9. **비동기 `kblockd` `kworker`의 `block_rq_issue` 실행 시 유저 `tid` 덮어쓰기 방지 & `kfree_skb` 3단계 플로우 조회**:
   - `block_rq_insert`가 등록한 원본 유저 `tid`/`req_id` 보존 및 `kfree_skb` 3단계 조회(`skb_egress_map` -> `rx_sk` -> L3/L4 헤더) 명세.
10. **BPF CO-RE(`vmlinux.h:119889`)의 `trace_event_raw_sys_enter`(`ctx->args[1]`) vs BCC(`args->op`) 호환 및 `tcp_retransmit_skb` 양방향 감지**:
    - `#ifdef KRAY_BPF_CORE` 이중 호환 매크로 및 `sport`/`dport` 양방향 재전송 감지 반영.

---

## 4. 설치 및 사용 가이드 (Installation & Usage Guide)

`softwarefactory` 또는 대상 리포지토리의 루트에 본 패키지의 `.agents/`와 `docs/` 디렉토리를 복사하면 즉시 활성화됩니다.

### 4.1 디렉토리 복사
```bash
cp -R archive/softwarefactory-draft/.agents /path/to/target-repo/
cp -R archive/softwarefactory-draft/docs /path/to/target-repo/
chmod +x /path/to/target-repo/.agents/scripts/design_audit_gate.py
```

### 4.2 파이프라인 워크플로우 실행 순서
1. **Step 1**: 프로젝트 요구사항을 바탕으로 루트에 `PROMPT_SPEC.md`(최소 100줄 이상)를 작성합니다.
2. **Step 2**: `.agents/skills/pre-implementation-design-audit/SKILL.md` 런북에 따라 최소 3회차(Phase 1 아키텍처 -> Phase 2 커널/런타임/인터페이스 -> Phase 3 실행 순서/동시성/엣지 케이스) 실증 디자인 어딧을 수행하며 `PROMPT_SPEC.md`를 업데이트합니다.
3. **Step 3**: 발굴 및 교정된 모든 설계 결함을 `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`(최소 100줄 이상, 다회차 Phase 또는 10건 이상의 결함 항목 포함)에 아카이빙합니다.
4. **Step 4**: 게이트 조건이 충족되면 `.agents/scripts/design_audit_gate.py`가 자동으로 구현 파일(`*.c`, `*.py`, `*.cpp`, `*.rs` 등)에 대한 `write_file` 및 `edit_file`을 허용(`"decision": "allow"`)합니다.
