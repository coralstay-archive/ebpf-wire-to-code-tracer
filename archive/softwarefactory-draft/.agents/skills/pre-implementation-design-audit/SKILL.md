---
name: pre-implementation-design-audit
description: >-
  Enforces and guides the 3-step Pre-Implementation Pipeline: (1) Single-Sheet Master
  Specification in PROMPT_SPEC.md, (2) Multi-Pass Ground-Truth Design Audit against
  kernel/runtime/ABI sources, and (3) Design Audit Report generation in
  archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md before writing any production code.
---

# Pre-Implementation Design Audit Runbook (`pre-implementation-design-audit`)

이 스킬은 프로덕션 구현 코드(`*.c`, `*.cpp`, `*.py`, `*.rs`, `*.go`, `*.ts` 등)를 단 한 줄이라도 작성하기 전에 반드시 수행해야 하는 **3단계 사전 설계 감사 파이프라인(3-Step Pre-Implementation Design Audit Pipeline)** 의 실행 절차와 검증 기준을 정의합니다.

---

## Step 1: 1-Sheet Master Specification (`PROMPT_SPEC.md`)

구현 코드를 작성하기 전에 먼저 프로젝트 루트에 단일 마스터 설계 문서인 **`PROMPT_SPEC.md`** (또는 `SPEC.md`, 최소 100줄 이상)를 작성합니다.

### 필수 포함 항목
- **시스템 아키텍처 및 데이터 파이프라인**:
  - 전체 컴포넌트 구조, 계층 간 경계(예: L2~L7, Kernel Space ↔ User Space, IPC/RPC 경계), 스레드/프로세스 핸드오프 규칙을 명시합니다.
- **고정 크기 메모리 및 상태 맵 스키마**:
  - 모든 공유 구조체, 해시 맵/링버퍼 키·벨류 레이아웃, 필드별 바이트 크기, 정렬(Alignment), 바이트 오더(`__be16`/`__be32` vs 호스트 바이트 오더)를 C/타입 정의 수준으로 명시합니다.
- **정확한 수식 및 상태 전이 알고리즘**:
  - 추상적인 자연어 설명 대신 오프셋 산출 수식, 지연 시간(Latency) 분리 수식, 오버플로우/언더플로우 가드 조건을 의사코드 또는 수식으로 고정합니다.
- **출력 스키마 및 E2E 검증 계약**:
  - CLI 인자, REST/MCP API 응답, 최종 출력 JSON의 최상위/하위 필수 키 이름과 E2E 테스트 시나리오(`TEST-01` ~ `TEST-NN`)를 정의합니다.

---

## Step 2: 3-Phase Ground-Truth Design Audit (다회차 실증 설계 감사)

`PROMPT_SPEC.md` 초안이 작성되면, 명세서의 모든 가정을 의심(Zero-Assumption)하고 실제 타겟 환경의 Ground-Truth 레퍼런스(타겟 커널 소스 트리, `vmlinux.h` BTF, ELF/DWARF 규격, 컴파일러 플래그 동작, 공식 문서)와 줄 단위로 대조하여 **최소 3회차(3 Phases)** 의 반복 설계 감사를 수행합니다. 발견된 결함은 즉시 `PROMPT_SPEC.md` 본문에 인플레이스(In-Place)로 교정합니다.

### Phase 1 — 아키텍처 및 데이터 모델 감사 (Architectural & Data Model Audit)
- **스택 및 메모리 한계**:
  - eBPF 512바이트 스택 한계(`MAX_BPF_STACK = 512`), 링버퍼 엔트리 크기, Per-CPU 스크래치 맵 필요 여부를 점검합니다.
- **식별자 및 플로우 키 정규화**:
  - 루프백(`lo`) 반사 패킷 혼선 방지 가드, 송수신 방향별 4-Tuple/소켓 주소 역전, 포트 바이트 오더(`skc_num` vs `skc_dport`) 일치 여부를 검증합니다.
- **인코딩 공간 직교성 및 비트필드 범위**:
  - 단일 `u8`/`u16` 필드 내 상태 코드와 깊이(`call_depth`) 충돌 여부, 비트마스크 오버플로우 여부를 검증합니다.
- **비동기 이벤트 수집 및 동시성 아키텍처**:
  - 비동기 SoftIRQ/백그라운드 이벤트 수집을 위한 Grace Window, 멀티스레드 서버의 락(`RLock`) 및 무블로킹 트리거 구조를 검증합니다.

### Phase 2 — 커널 소스·Verifier·ELF·런타임 인터페이스 감사 (Kernel/Runtime/ABI Deep Audit)
- **함수 진입 시점의 구조체 초기화 상태**:
  - 훅이 걸린 함수 진입 시점(줄 번호 기준)에 참조하려는 헤더 오프셋(`skb->transport_header` 등)이나 버퍼가 실제로 초기화되어 있는지, 혹은 함수 종료 시 이미 해제(Use-After-Free)되었는지 원본 소스로 확인합니다.
- **정적 검증기(Verifier) 및 포인터 안전성**:
  - 비신뢰 커널 포인터 직접 역참조 여부를 확인하고 `bpf_probe_read_kernel()` / `bpf_probe_read_user()` 헬퍼 체인으로 교정합니다.
- **Tracepoint `TP_STRUCT__entry` 실제 필드명 및 타입**:
  - `TP_PROTO` 인자와 실제 `TP_STRUCT__entry` 평탄화 필드명(`args->pid`, `args->prev_pid`, `args->nr_sector` 등), 내부 사전 `ntohs()` 적용 여부를 대조합니다.
- **컴파일러 최적화 및 바이너리 심볼/오프셋**:
  - `-O1` 인라이닝으로 인한 프로브 증발(`__attribute__((noinline))` 필요성), `uretprobe` 트램펄린 IP 치환 현상, `strip -x` 바이너리의 `.eh_frame` FDE 기반 함수 경계 복원, PIE `PT_LOAD` 파일 오프셋 변환 수식(`st_value - p_vaddr + p_offset`)을 검증합니다.

### Phase 3 — 실행 순서·블로킹 대기·Per-CPU 오염·다중 프로토콜 엣지 케이스 감사 (Execution-Order & Edge-Case Audit)
- **커널 내부 훅 간 실행 순서(Execution Ordering)**:
  - 동일 경로 내 복수 훅(예: `trace_netif_receive_skb` vs `skb_reset_network_header` vs `do_xdp_generic`, 또는 `trace_skb_copy_datagram_iovec` vs `simple_copy_to_iter`)의 실제 호출 순서를 줄 번호로 대조합니다.
- **블로킹 I/O 대기 및 반환값 추출**:
  - 소켓이나 디스크 I/O가 함수 진입 시점에 데이터가 없어 블로킹(`sk_wait_data`)되는 경우, 진입(`kprobe`)과 복귀(`kretprobe`) 이중 바인딩 및 실제 처리 바이트(`PT_REGS_RC`) 추출 구조를 검증합니다.
- **Per-CPU 맵 및 타임스탬프 잔류 오염**:
  - `BPF_PERCPU_ARRAY` 제로 템플릿의 읽기 전용(Read-Only) 불변성 유지, Off-CPU/Wakeup 타임스탬프 방출 후 즉시 `0` 리셋 여부를 확인합니다.
- **다중 프로토콜 및 CO-RE / BCC 호환성**:
  - 조건부 컴파일(`#if 0` 처리된 커널 헤더 필드), 비연결 UDP(`msg->msg_name`), 순수 IPv6/Dual-Stack 주소 폴딩, `vmlinux.h`(`trace_event_raw_sys_enter`)와 BCC 간 매크로 호환성을 검증합니다.

---

## Step 3: Design Audit Report (`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`)

3차례의 디자인 어딧과 `PROMPT_SPEC.md` 교정이 완료되면, 발굴하고 해결한 모든 설계 결함을 **`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`** (최소 100줄 이상)에 작성합니다.

### 리포트 작성 규칙
- **가독성 포맷 규칙**:
  - 텍스트가 세로로 좁게 찌그러지는 것을 방지하기 위해 마크다운 표를 사용하지 않고, 전체 가로폭을 활용하는 제목(`##`, `###`, `####`)과 불릿 리스트로 작성합니다.
- **필수 구성 섹션**:
  - **섹션 1**: 검증 대상 명세서(`PROMPT_SPEC.md`) 및 실증 대조 레퍼런스 목록, 명세 단계 설계 감사의 필요성 요약
  - **섹션 2 (`[Phase 1]`)**: 1차 아키텍처 설계 감사에서 발굴·제거한 결함 목록 (각 결함별 메커니즘 + 교정된 명세 해법)
  - **섹션 3 (`[Phase 2]`)**: 2차 심층 커널/런타임/Verifier/ELF 감사에서 발굴·제거한 결함 목록 (근거 소스 파일:줄 번호 + 결함 메커니즘 + 수정된 명세 공식)
  - **섹션 4 (`[Phase 3]`)**: 3차 극한 실행 순서/블로킹/Per-CPU/다중 프로토콜/ABI 감사에서 발굴·제거한 결함 목록 (근거 소스 파일:줄 번호 + 결함 메커니즘 + 수정된 명세 공식)
  - **섹션 5**: 총 발굴 결함 수 요약 및 `PROMPT_SPEC.md` 동기화 완료 선언

---

## 게이트 통과 확인 (Gate Verification)

`.agents/hooks.json`에 등록된 `.agents/scripts/design_audit_gate.py`는 구현 코드(`*.c`, `*.py`, `*.cpp` 등) 생성 시도 시 다음 두 조건을 자동으로 검사합니다.

- `PROMPT_SPEC.md` (또는 `SPEC.md`)가 존재하고 100줄 이상인가?
- `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`가 존재하고 100줄 이상이며 Phase 1~3(또는 10건 이상의 결함 항목)을 포함하는가?

두 조건이 모두 충족되면 하드 게이트가 자동으로 열리고(`"decision": "allow"`), 무결점 명세서를 기반으로 막힘없이 프로덕션 코드를 구현할 수 있습니다.
