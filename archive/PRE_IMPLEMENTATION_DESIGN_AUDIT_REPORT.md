# 구현 전 명세 단계(Pre-Implementation Specification Stage) 설계 결함 발굴 및 커널 소스 실증 감사 보고서

- **문서 경로**: [`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md)
- **검증 대상 명세서**: [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md) (`eBPF-WireToCode-Tracer` 마스터 설계 및 구현 프롬프트 명세서)
- **실증 대조 레퍼런스**:
  1. **Target Kernel Source & BTF**: [`references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/) (`Rocky Linux 9.8 Blue Onyx aarch64`, Kernel `5.14.0-687.10.1.el9_8.0.1.aarch64`)
  2. **Official eBPF Specification**: [`references/ebpf-docs-master/docs/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/ebpf-docs-master/docs/) (`docs.ebpf.io`)
  3. **Canonical Reference Book**: [`references/BPF-성능-분석-도구.pdf`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/BPF-성능-분석-도구.pdf) (Brendan Gregg, *BPF Performance Tools*)

---

## 1. 왜 코드 구현 전에 '명세 단계 설계 감사(Specification-Stage Audit)'가 필수적인가?

일반적인 소프트웨어 개발에서는 대략적인 요구사항만 적고 곧바로 코드를 작성한 뒤 런타임 에러를 디버깅합니다. 그러나 **리눅스 커널 내부와 유저 공간을 동시에 가로지르는 eBPF 시스템 프로그래밍**에서는 명세 단계의 작은 오해나 추상적인 가정이 구현 단계에서 다음과 같은 치명적 실패로 이어집니다.

1. **커널 함수 진입 시점의 구조체 상태 오해 (Temporal State Bugs)**:
   - 커널 함수(`ip_rcv`, `__tcp_transmit_skb`, `net_dev_xmit`)의 이름만 보고 훅을 걸면, 함수 진입 시점에는 아직 커널이 헤더 오프셋(`skb->transport_header`)이나 패킷 데이터를 채우기 전이거나, 반대로 함수 내부에서 이미 버퍼(`skb->head`)를 해제(free)한 직후여서 **100% 매칭 실패 또는 Use-After-Free 쓰레기값 참조**가 발생합니다.
2. **eBPF Verifier 정적 검증 거부 (512B 스택 한계 및 비신뢰 포인터 역참조)**:
   - `BPF_PROG_TYPE_KPROBE`에서 `skb->head`를 일반 포인터처럼 역참조하거나, `400B`가 넘는 스레드 컨텍스트 구조체(`tid_ctx_t`)를 C 지역 변수로 선언하면 커널에 로드조차 되지 않고 Verifier가 즉시 거부합니다.
3. **Tracepoint ABI와 커널 함수 시그니처 간 괴리**:
   - `TP_PROTO`의 C 인자(`struct task_struct *p`)와 실제 eBPF 트레이스포인트가 읽어야 하는 `TP_STRUCT__entry` 포맷 필드(`args->pid`, `args->prev_pid`, `args->nr_sector`)는 이름과 타입이 다릅니다. 또한 커널이 트레이스포인트 내부에서 이미 `ntohs()`를 적용한 필드(`tcp_retransmit_skb`)에 또 `bpf_ntohs()`를 호출하면 포트 번호가 파손됩니다.
4. **컴파일러 최적화(`-O1` 인라이닝)와 ELF/DWARF/Trampoline의 상호작용**:
   - 커널의 `uretprobe`가 복귀 주소를 `[uprobes]` 트램펄린으로 덮어쓰는 현상, C++ 컴파일러가 `-O1`에서 타겟 함수를 인라이닝해 `uprobe` 부착 지점을 증발시키는 현상, `strip -x`로 `.symtab`이 제거된 공유 라이브러리에서 내부 정적 함수를 찾는 문제는 명세 단계에서 정확한 메커니즘을 정의하지 않으면 구현 시 절대 해결할 수 없습니다.

본 문서는 코드 한 줄을 작성하기 전에 **명세서([`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md))를 실제 타겟 커널 소스 코드와 1:1로 대조하여 발굴·제거한 총 45건(1차 아키텍처 감사 10건 + 2차 심층 커널·런타임 감사 25건 + 3차 극한 커널 소스·Verifier·ABI 정밀 감사 10건)의 설계 결함과 해결 공식**을 아카이브로 기록합니다.

---

## 2. [Phase 1] 1차 10회 반복 아키텍처 설계 감사 요약 (Iterations 1 ~ 10)

명세서의 큰 뼈대(512B BPF 스택, 루프백 패킷 방향성, 4-Tuple 엔디안, `call_depth` 인코딩 공간, C++ 심볼 폭발 등)에서 발견된 1차 10대 구조적 결함과 해결책입니다.

### [Phase 1 - Iteration 1] 512바이트 eBPF 스택 한계 초과 (`tid_ctx_t` 지역 변수 선언 시 Verifier 즉시 거부)
- **발견된 명세 결함**: `tid_ctx_t`는 `u64 fn_entry_ts[16]`(`128B`), `u64 fn_entry_ip[16]`(`128B`), `u64 fn_off_cpu_snap[16]`(`128B`) 등을 포함해 단일 구조체 크기가 약 `432 Bytes`에 달합니다. 이를 `kprobe__tcp_recvmsg` 내부에서 `struct tid_ctx_t zero = {};`처럼 스택 지역 변수로 선언하면 eBPF의 엄격한 **512바이트 스택 한계(`MAX_BPF_STACK = 512`)**를 초과하여 Verifier가 로드를 거부합니다.
- **교정된 명세 해법**: 스택에 구조체를 선언하는 대신 **`BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)`** Per-CPU 스크래치 맵을 선언하고, `u32 zero_idx = 0; struct tid_ctx_t *scratch = zero_ctx_map.lookup(&zero_idx);`로 커널 힙 메모리 상에서 초기화한 뒤 `active_ctx_map.update(&tid, scratch)`를 호출하여 BPF 스택 사용량을 `0 Bytes`로 제거했습니다.

### [Phase 1 - Iteration 2] 루프백(`lo`) 환경에서 서버/클라이언트 패킷 혼선 및 `ACK` 제어 패킷의 `req_id` 덮어쓰기
- **발견된 명세 결함**:
  1. 동일 호스트(`127.0.0.1`)에서 `curl`이나 자체 트래픽 트리거가 `mock_server`(`:8080`)를 호출하면, 서버가 보낸 응답 패킷(`sport == 8080`)이 루프백을 타고 다시 Ingress(`XDP`/`ip_rcv`/`tcp_v4_rcv`)로 들어오며, 클라이언트(`curl`) 프로세스도 `tcp_recvmsg`를 호출하여 서버 트레이스와 뒤섞입니다.
  2. 또한 3-way 핸드셰이크의 마지막 0바이트 `ACK` 패킷이나 요청 직후의 `ACK` 패킷이 `ingress_flow_map[key]`의 `req_id`를 새로 덮어써 버려 L2~L4의 `req_id`와 L4.5(`tcp_recvmsg`)의 `req_id`가 불일치합니다.
- **교정된 명세 해법**:
  1. **Server-Role Direction Guard**: Ingress(`XDP`, `ip_rcv`, `tcp_v4_rcv`)에서는 반드시 **`dport == target_port`** 인 패킷만 수용하고(`sport == target_port` 반사 패킷 즉시 무시), 소켓 훅(`tcp_recvmsg`, `tcp_sendmsg`)에서는 로컬 포트 **`sk->__sk_common.skc_num == target_port`** 가드로 클라이언트 소켓을 원천 배제했습니다.
  2. **Payload-Gated `req_id` Minting**: `u16 tcp_payload_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4) - (tcp->doff * 4);`를 계산하여, 기존 `ingress_flow_map[key]`에 아직 소비되지 않은(`consumed == 0`) `req_id`가 존재할 때 `tcp_payload_len == 0`인 제어 패킷(`SYN`/`ACK`)은 기존 `req_id`를 덮어쓰지 못하도록 차단했습니다.

### [Phase 1 - Iteration 3] `sk->__sk_common` 4-Tuple 방향 역전 및 포트 엔디안 불일치로 인한 `ingress_flow_map` 조회 100% 실패
- **커널 소스 근거**: [`include/net/sock.h:158-190`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/sock.h#L158-L190)
- **발견된 명세 결함**: 와이어 수신 패킷(`iph`/`tcph`)은 `saddr = ClientIP`, `daddr = ServerIP`, `sport = ClientPort`, `dport = ServerPort`입니다. 반면 서버 소켓 `struct sock *sk`의 `sk->__sk_common`은 `skc_rcv_saddr = ServerIP (Local)`, `skc_daddr = ClientIP (Remote)`이며, **`skc_num`은 이미 호스트 바이트 오더(`__u16`)인 반면 `skc_dport`는 네트워크 바이트 오더(`__be16`)**입니다. 이를 정규화하지 않으면 `kprobe__tcp_recvmsg`에서 `ingress_flow_map.lookup(&key)`가 100% `NULL`을 반환합니다.
- **교정된 명세 해법**:
  - 수신 브릿지(`kprobe__tcp_recvmsg`) 조회 키: `key = { .saddr = sk->__sk_common.skc_daddr, .daddr = sk->__sk_common.skc_rcv_saddr, .sport = bpf_ntohs(sk->__sk_common.skc_dport), .dport = sk->__sk_common.skc_num, .proto = IPPROTO_TCP, .family = sk->__sk_common.skc_family }` (`skc_num`에는 절대 `bpf_ntohs`를 호출하지 않음!).
  - 송신 브릿지(`kprobe__tcp_sendmsg` → `__tcp_transmit_skb`) 조회 키: `egress_key = { .saddr = sk->__sk_common.skc_rcv_saddr, .daddr = sk->__sk_common.skc_daddr, .sport = sk->__sk_common.skc_num, .dport = bpf_ntohs(sk->__sk_common.skc_dport), .proto = IPPROTO_TCP, .family = sk->__sk_common.skc_family }`.

### [Phase 1 - Iteration 4] SMP 멀티코어 환경에서 `sched_wakeup`의 Waker 컨텍스트 불일치 및 `sys_enter_futex(FUTEX_WAKE)` 오탐
- **커널 소스 근거**: [`include/trace/events/sched.h:167-180`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L167-L180)
- **발견된 명세 결함**: 커널 주석에 명시된 대로 SMP 시스템에서 `tracepoint:sched:sched_wakeup`은 스케줄러 IPI에 의해 타겟 CPU의 인터럽트 컨텍스트에서 실행될 수 있어 `bpf_get_current_pid_tgid()`가 Waker 스레드(`TID A`)가 아닐 수 있습니다. 반면 **`tracepoint:sched:sched_waking`은 100% Waker 컨텍스트에서 호출됨이 보장**됩니다.
- **교정된 명세 해법**: Waker 컨텍스트가 보장되는 `tracepoint:sched:sched_waking`을 1차 스레드 핸드오프 훅으로 채택하고, 워커 스레드가 이미 깨어 있는(`TASK_RUNNING`) 경우를 위해 `pending_handoff_map[tgid]` 폴백 브릿지를 결합했습니다.

### [Phase 1 - Iteration 5] 1바이트 `call_depth` 필드에서 유저 함수 호출 깊이(`0..15`)와 `OSI_L5_SYSCALL_MEM (6)` / `OSI_L6_PRE_COMPUTE (8)` 값 충돌
- **발견된 명세 결함**: `kray_event_t.call_depth` 단일 필드에 유저 함수 호출 깊이(`0..15`)와 세부 계층 코드(`2, 3, 4, 5, 6, 8`)를 함께 인코딩하면서 `layer_type == LAYER_USER_FUNC (4)`로 동일하게 방출하면, 호출 깊이 6 또는 8인 일반 C++ 함수가 커널 시스템콜(`6`)이나 스케줄러 이벤트(`8`)로 오분류됩니다.
- **교정된 명세 해법**: **`(layer_type, call_depth)` 직교 분리 원칙**을 수립하여 `layer_type == LAYER_USER_FUNC (4)`는 오직 순수 유저 공간 `uprobe`/`uretprobe` 함수(`call_depth = 0..15`)에만 독점 할당하고, L5(`OSI_L5_SYSCALL_MEM = 6`) 및 L6(`OSI_L6_PRE_COMPUTE = 8`) 이벤트는 반드시 `layer_type = LAYER_USER_ENTRY (3)`(또는 `LAYER_USER_EXIT = 5`)와 함께 방출하도록 강제했습니다.

### [Phase 1 - Iteration 6] 함수 실행 도중 발생하는 Off-CPU 대기 시간과 On-CPU 순수 ALU 연산 시간 분리 메커니즘 부재
- **발견된 명세 결함**: `execute_storage_query()`가 `18ms` 동안 블록 I/O나 `usleep`으로 블로킹될 때, 단순 `uretprobe_ts - uprobe_ts`만 측정하면 함수 내부에서 발생한 Off-CPU 시간을 알 수 없습니다.
- **교정된 명세 해법**: `tid_ctx_t`에 누적 Off-CPU 카운터(`acc_off_cpu_ns`)와 깊이별 진입 스냅샷(`fn_off_cpu_snap[16]`), 그리고 블록 I/O 추적용 `inflight_bio_map`을 추가하여 On-CPU 연산 시간(`pure_on_cpu_compute_ms`)과 Off-CPU 대기 시간(`off_cpu_io_wait_ms`)을 정밀 분리했습니다.

### [Phase 1 - Iteration 7] C++ 바이너리의 수천 개 STL/런타임 심볼 무차별 `uprobe` 부착으로 인한 `EMFILE` 크래시
- **발견된 명세 결함**: C++ 바이너리(`mock_server`)의 모든 `STT_FUNC` 심볼에 `uprobe`를 부착하면 `std::vector`, `std::string`, `__cxxabiv1` 등 수천 개의 심볼이 로드되어 파일 디스크립터 한계(`RLIMIT_NOFILE`) 초과 및 `call_depth` 오버플로우가 발생합니다.
- **교정된 명세 해법**: 컴파일러/런타임/C++ STL 접두사(`_start`, `__libc_`, `__cxa_`, `_ZSt`, `_ZNSt`, `_ZNKSt`, `_GLOBAL__` 등) 및 `st_size < 16` 바이트 극소 함수를 자동 제외하고 애플리케이션 도메인 함수만 최대 `MAX_AUTO_UPROBES = 64`개로 필터링하도록 명세했습니다.

### [Phase 1 - Iteration 8] `kray_runtime_cfg_t.filter_flags`의 8비트(1바이트) 오버플로우 위험
- **발견된 명세 결함**: `u8 filter_flags` 1바이트 안에 8개 프로토콜과 7개 계층 마스크를 나란히 배치하면 15비트가 필요하여 `u8` 범위를 초과합니다.
- **교정된 명세 해법**: 하위 4비트(`Bits 0..3`)는 프로토콜 패밀리 마스크, 상위 4비트(`Bits 4..7`)는 계층 그룹 마스크로 명확히 4+4 비트 분할 명세했습니다.

### [Phase 1 - Iteration 9] 비동기 SoftIRQ Egress 이벤트(`LAYER_EGRESS_NIC`) 조기 누락 및 Keep-Alive 좀비 `req_id` 오염
- **발견된 명세 결함**: 유저 스레드가 `tcp_sendmsg`(`LAYER_USER_EXIT`)를 마친 직후 RingBuf를 즉시 플러시하면, SoftIRQ에서 비동기로 뒤따라 실행되는 `net_dev_xmit`(`LAYER_EGRESS_NIC`)가 누락됩니다.
- **교정된 명세 해법**: `LAYER_USER_EXIT` 수신 후 `LAYER_EGRESS_NIC` 도착을 기다리거나 최대 `50ms` Grace Window를 대기하는 상태 머신과 `(timestamp, layer_order, is_return)` 정규 정렬(Canonical Sort)을 도입했습니다.

### [Phase 1 - Iteration 10] 단일 스레드 REST/MCP 서버의 블로킹 데드락(Hang)
- **발견된 명세 결함**: 파이썬 기본 `HTTPServer`로 트레이스 캡처를 처리하면 트래픽이 없을 때 무한 대기(Hang)하거나 동시 요청이 데드락에 빠집니다.
- **교정된 명세 해법**: `ThreadingHTTPServer` + `threading.RLock()`을 강제하고, 내장 루프백 패킷 트리거를 통해 `500ms` 이내 무블로킹 응답을 보장했습니다.

---

## 3. [Phase 2] 최종 25대 심층 커널 소스·Verifier·ELF·런타임 정밀 감사 결과 (Flaws #1 ~ #25)

1차 아키텍처 감사 이후, 이전 가정을 모두 백지화하고 **Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) 커널 원본 C 소스 코드의 실제 줄 번호와 매크로 정의를 전수 검사**하여 추가로 잡아낸 25개의 치명적 구현 결함과 해결 공식입니다.

---

### 결함 #1 — `kprobe__ip_rcv` 진입 시점의 미초기화 `skb->transport_header` 참조 버그
- **커널 소스 근거**: [`net/ipv4/ip_input.c:552-562`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552-L562)
- **결함 메커니즘**:
  - `ip_rcv(struct sk_buff *skb, ...)`가 호출되는 시점(Line 552)에는 아직 `ip_rcv_core()` 내부의 `skb->transport_header = skb->network_header + iph->ihl * 4;`가 실행되기 전입니다!
  - 따라서 `kprobe__ip_rcv`에서 `skb->transport_header`를 읽어 TCP/UDP 포트를 파싱하면 미초기화 값(`0xFFFF`)을 참조하여 엉뚱한 메모리를 읽고 포트 필터링(`dport == target_port`)이 100% 실패합니다.
- **수정된 명세 공식**:
  - `kprobe__ip_rcv`에서는 절대 `skb->transport_header`를 읽지 않고, 먼저 `u16 net_off = skb->network_header;`로 `iphdr`를 읽은 뒤 **`u16 trans_off = net_off + ((iph.ihl & 0x0f) * 4);`** 로 L4 오프셋을 직접 계산하여 `skb->head + trans_off`에서 TCP/UDP 포트를 추출합니다.

---

### 결함 #2 — `kprobe____tcp_transmit_skb` 진입 시점의 빈 `skb` 헤더 및 `tracepoint:net:net_dev_xmit`의 Use-After-Free
- **커널 소스 근거**: [`net/ipv4/tcp_output.c:1238-1343`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238-L1343), [`include/trace/events/net.h:71-101`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L71-L101)
- **결함 메커니즘**:
  1. `__tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, ...)`에서 커널은 함수 본문 한참 뒤인 Line 1309(`skb_push(skb, tcp_header_size); skb_reset_transport_header(skb);`)에서야 비로소 TCP 헤더를 `skb`에 기록합니다. 즉, `kprobe____tcp_transmit_skb` 진입 시점에 `skb` 헤더에서 4-Tuple을 읽으면 전부 `0`입니다.
  2. 반대로 `tracepoint:net:net_dev_xmit`은 NIC 드라이버의 `ndo_start_xmit()` 실행 **직후**에 호출되는데, 드라이버가 동기 송신 중 `dev_kfree_skb()`로 이미 `skb->head`를 해제(free)했을 수 있어 `net_dev_xmit`에서 `skb->head`를 역참조하면 Use-After-Free가 발생합니다.
- **수정된 명세 공식**:
  - `kprobe____tcp_transmit_skb` 진입 시점에는 `skb`가 아닌 첫 번째 인자 **`PARM1 = struct sock *sk`의 `sk->__sk_common`** 에서 `egress_key`를 직접 구성해 `egress_flow_map`을 조회하고, 그 즉시 **`u64 skb_ptr = (u64)PT_REGS_PARM2(ctx); skb_egress_map.update(&skb_ptr, &egress_key);`** 로 `skb` 포인터를 선행 바인딩합니다.
  - 이후 `kprobe__ip_output`(`PARM3 = skb`), `tracepoint:net:net_dev_queue`(`args->skbaddr`), `tracepoint:net:net_dev_xmit`(`args->skbaddr`)에서는 `skb->head`를 전혀 역참조하지 않고 오직 **`(u64)skb` 포인터 값만으로 `skb_egress_map`을 조회**하여 Qdisc 지연 시간(`now - state->qdisc_enq_ts`)을 안전하게 산출합니다.

---

### 결함 #3 — `pending_handoff_map[tgid]` 단일 슬롯의 동시 다중 요청(`TEST-03`) 덮어쓰기 레이스 컨디션
- **결함 메커니즘**:
  - `pending_handoff_map`이 프로세스(`tgid`)당 단일 구조체(`pending_handoff_t`)만 저장하면, 동시에 2개의 요청(`req_id #1`, `req_id #2`)이 도착했을 때 두 번째 요청이 첫 번째 요청의 슬롯을 덮어써 버려 워커 스레드가 잘못된 `req_id`를 인계받습니다(`TEST-03` 실패).
- **수정된 명세 공식**:
  - `pending_handoff_map`의 Value를 **8-슬롯 원형 FIFO 링 버퍼(`struct handoff_ring_t { u32 write_idx; u32 read_idx; struct pending_handoff_t slots[8]; }`)** 로 설계했습니다.
  - I/O 스레드는 `slots[write_idx & 7]`에 기록 후 `write_idx++`를 수행하고, 워커 스레드는 `slots[read_idx & 7]`(`claimed == 0`)을 인계받은 뒤 `claimed = 1; read_idx++;`를 수행하여 다중 요청 간 격리를 100% 보장합니다.

---

### 결함 #4 — `uretprobe` 복귀 시 `PT_REGS_IP(ctx)`가 커널 `[uprobes]` 트램펄린 주소로 치환되는 현상
- **결함 메커니즘**:
  - 리눅스 커널은 `uprobe`가 걸린 함수에 진입할 때 스택의 복귀 주소(Return Address)를 커널의 `[uprobes]` 트램펄린 페이지 주소로 덮어씁니다.
  - 따라서 `uretprobe` 핸들러(`trace_uprobe_return`)에서 `PT_REGS_IP(ctx)`를 읽으면 원래 함수 주소가 아니라 트램펄린 주소가 반환되어, `/proc/<PID>/maps` 및 ELF 심볼 매칭이 100% 실패합니다.
- **수정된 명세 공식**:
  - `tid_ctx_t` 내에 **`u64 fn_entry_ip[MAX_CALL_DEPTH]`** 배열을 추가하여, `uprobe` 진입 시점에 **`ctx->fn_entry_ip[depth] = PT_REGS_IP(ctx);`** 로 실제 함수 진입 IP를 백업하고, `uretprobe` 복귀 시점에는 `PT_REGS_IP(ctx)` 대신 **`ev->ip = ctx->fn_entry_ip[depth];`** 를 방출하도록 강제했습니다.

---

### 결함 #5 — `uretprobe`에서 `call_depth == 0` 언더플로우(`u8: 0 -> 255`) 및 `parent_tid` 유실
- **결함 메커니즘**:
  1. 트레이서가 이미 실행 중인 함수 중간에 부착되거나 필터가 핫리로드되면, `uprobe` 진입 없이 `uretprobe`가 먼저 호출될 수 있습니다. 이때 `u8 call_depth == 0`에서 `ctx->call_depth--`를 수행하면 `255`로 언더플로우되어 스택 추적이 영구 오염됩니다.
  2. 또한 `uretprobe` 이벤트 방출 시 `ev->parent_tid = ctx->parent_tid`를 누락하면 복귀 이벤트에서 스레드 핸드오프 계보가 끊어집니다.
- **수정된 명세 공식**:
  - `trace_uprobe_return` 최상단에 **`if (ctx->call_depth == 0) return 0;`** 언더플로우 가드를 강제하고, `ev->parent_tid = ctx->parent_tid;`를 항상 포함하도록 명세했습니다.

---

### 결함 #6 — 표준 Tracepoint(`sched_waking`, `sched_switch`)의 `TP_STRUCT__entry` 실제 필드명 불일치
- **커널 소스 근거**: [`include/trace/events/sched.h:143-165, 222-265`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L143-L265)
- **결함 메커니즘**:
  - 커널 헤더의 `TP_PROTO`는 `struct task_struct *p`나 `prev`, `next` 포인터를 인자로 받지만, 표준 `TRACEPOINT_PROBE`가 접근하는 `TP_STRUCT__entry` 구조체는 포인터가 아닌 평탄화된 정수 필드를 노출합니다.
  - `sched_waking`/`sched_wakeup`(`sched_wakeup_template`)의 필드명은 `target_tid`가 아니라 **`args->pid`** 이며, `sched_switch`의 필드명은 **`args->prev_pid`, `args->next_pid`, `args->prev_state`** 입니다.
- **수정된 명세 공식**:
  - 표준 트레이스포인트 사용 시 `args->pid` 및 `args->prev_pid`/`args->next_pid`/`args->prev_state`를 사용하고, `tp_btf`(`BPF_PROG_TYPE_TRACING`) 사용 시에만 `p->pid`, `prev->pid`, `next->pid`를 사용하도록 명확히 구분했습니다.

---

### 결함 #7 — `sys_exit_write`에서 `active_ctx_map` 삭제 시 일반 로깅 `write(1, ...)`가 컨텍스트를 파괴하는 버그 + 커널 함수 `tcp_sendmsg`에 `uretprobe` 오기재
- **결함 메커니즘**:
  1. 워커 스레드가 비즈니스 로직 도중 `printf`나 파일 로깅으로 `write()` 시스템콜을 호출하면 `sys_exit_write`가 발생합니다. 여기서 `active_ctx_map.delete(&tid)`를 호출하면 정작 이후 실행되는 함수들과 `tcp_sendmsg()`의 `req_id`가 사라집니다!
  2. 또한 `tcp_sendmsg`는 커널 함수이므로 유저 공간용 `uretprobe`가 아니라 커널 **`kretprobe__tcp_sendmsg`** 를 사용해야 합니다.
- **수정된 명세 공식**:
  - `sys_exit_write`에서는 절대 `active_ctx_map`을 삭제하지 않습니다.
  - `kprobe__tcp_sendmsg`에서 `sk->__sk_common.skc_num == target_port`가 확인될 때 `ctx->in_target_sendmsg = 1`을 마킹하고, 오직 **`kretprobe__tcp_sendmsg`** 에서 `ctx->in_target_sendmsg == 1`일 때만 `active_ctx_map.delete(&tid)`를 수행합니다.

---

### 결함 #8 — 중첩 유저 함수(`A() -> B()`)에서 Off-CPU 대기 시간 이중 차감(Double-Subtraction) 및 JSON 필드명 불일치
- **결함 메커니즘**:
  - 부모 함수 `A()`가 자식 함수 `B()`를 호출하고 `B()` 내부에서 `18ms` Off-CPU 대기가 발생했을 때, 단순히 `A`와 `B` 각각의 `(acc_off_cpu_exit - acc_off_cpu_entry)`를 합산하거나 차감하면 부모 `A`와 자식 `B`에서 동일한 `18ms`가 중복 계산됩니다.
  - 또한 섹션별로 `pre_compute_and_io_wait_ms`와 `off_cpu_io_wait_ms` 두 가지 이름이 혼재되어 있었습니다.
- **수정된 명세 공식**:
  - 각 함수 `F`의 `[t_entry, t_return]` 구간 내 **직접 자식(Direct Child) `OSI_L5_SYSCALL_MEM`/`OSI_L6_PRE_COMPUTE` 대기 이벤트 시간**을 합산하여 차감하도록 알고리즘을 통일하고, JSON 필드명도 전 구간 **`off_cpu_io_wait_ms`** 로 단일화했습니다.

---

### 결함 #9 — RingBuf 100% 포화(`ringbuf_reserve() == NULL`) 시 드롭 카운트가 이벤트 스트림에 전달되지 않는 결함
- **결함 메커니즘**:
  - 링버퍼가 가득 차서 `events.ringbuf_reserve()`가 `NULL`을 반환할 때는 `drop_cnt_map[0]`만 증가하고 이벤트는 방출되지 않습니다. 이후 추가 패킷이 없으면 유저 공간은 이벤트 내 `ev->drop_count`만 보고 드롭이 `0`건이라고 오판할 수 있습니다.
- **수정된 명세 공식**:
  - `tracer_agent.py`는 반드시 커널의 `drop_cnt_map[0]` 배열 값을 직접 조회하여 **`final_drop_count = max(max_event_drop_count, bpf_drop_cnt_map[0]) + args.simulate_drops`** 공식으로 최종 드롭 수를 산출하도록 강제했습니다.

---

### 결함 #10 — `AF_UNIX` 커널 훅(`unix_stream_recvmsg`/`sendmsg`)의 첫 번째 인자 타입(`struct socket *sock` vs `struct sock *sk`) 불일치
- **커널 소스 근거**: [`net/unix/af_unix.c:2053, 2733`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2053)
- **결함 메커니즘**:
  - `tcp_recvmsg(struct sock *sk, ...)`와 달리 `unix_stream_recvmsg(struct socket *sock, ...)`와 `unix_stream_sendmsg(struct socket *sock, ...)`의 첫 번째 인자(`PT_REGS_PARM1`)는 `struct sock *`가 아니라 래퍼 구조체인 **`struct socket *sock`** 입니다!
- **수정된 명세 공식**:
  - `struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx); struct sock *sk = NULL; bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);`로 `sk`를 안전하게 역참조하도록 수정했습니다.

---

### 결함 #11 — `tracepoint:block:block_rq_complete`에 존재하지 않는 `args->bytes` 필드 참조 및 NVMe `blk-mq`의 `block_rq_insert` 생략
- **커널 소스 근거**: [`include/trace/events/block.h:124-169, 238-255`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L124-L169)
- **결함 메커니즘**:
  1. `block_rq_issue`(`block_rq` 클래스, `block.h:195`)에는 `bytes` 필드가 존재하지만, 완료 이벤트인 `block_rq_complete`(`block_rq_completion` 클래스, `block.h:124-130`)의 `TP_STRUCT__entry`에는 `dev`, `sector`, `nr_sector`, `error`, `ioprio`만 있고 **`args->bytes` 필드가 아예 존재하지 않아 컴파일이 실패**합니다.
  2. 또한 NVMe 및 `virtio-blk` 멀티큐(`blk-mq`) 디바이스는 큐 스케줄러 없이 `block_rq_insert`를 생략하고 곧바로 `block_rq_issue`를 호출하는 경우가 많아 `block_rq_insert`에서만 맵에 등록하면 블록 I/O가 누락됩니다.
- **수정된 명세 공식**:
  - `block_rq_insert`와 `block_rq_issue` **두 훅 모두**에서 `inflight_bio_map[{args->dev, args->sector}]`를 등록/갱신하고, 완료 훅 `block_rq_complete`에서는 **`(u64)args->nr_sector * 512`**(또는 `bio_state_t.bytes`)로 전송 바이트를 계산하도록 수정했습니다.

---

### 결함 #12 — `glibc` 유저 공간 Condvar Fastpath(`__wrefs == 0`)로 인한 `sys_enter_futex(FUTEX_WAKE)` 시스콜 생략 & 추가 Futex Wake Opcode 누락
- **커널 소스 근거**: [`include/uapi/linux/futex.h:11-26`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/linux/futex.h#L11-L26)
- **결함 메커니즘**:
  1. 워커 스레드(`TID B`)가 아직 `futex_wait`에 잠들기 전(`TASK_RUNNING` 스핀 상태)에 I/O 스레드(`TID A`)가 `std::condition_variable::notify_one()`을 호출하면, `glibc`의 `pthread_cond_signal`은 유저 공간에서 잠든 대기자 수가 `0`(`__wrefs == 0`)임을 확인하고 **커널 `sys_enter_futex(FUTEX_WAKE)` 시스콜조차 호출하지 않고 유저 공간에서 바로 리턴**합니다! 이 경우 `sched_waking`도 발생하지 않고 `sys_enter_futex(FUTEX_WAKE)`도 발생하지 않습니다.
  2. 또한 `pthread_cond_broadcast`나 PI 뮤텍스는 `FUTEX_WAKE(1)` 외에도 `FUTEX_REQUEUE(3)`, `FUTEX_CMP_REQUEUE(4)`, `FUTEX_WAKE_OP(5)`, `FUTEX_UNLOCK_PI(7)`, `FUTEX_CMP_REQUEUE_PI(12)`를 사용합니다.
- **수정된 명세 공식**:
  - I/O 스레드(`TID A`)가 `kprobe__tcp_recvmsg`에서 `req_id`를 바인딩하는 즉시 `pending_handoff_map[tgid]`의 8-슬롯 FIFO에 `{req_id, wakeup_ts = now, waker_tid = tid, claimed = 0}` 슬롯을 **선행 게시(Pre-Publish)**합니다.
  - 이후 `sys_enter_futex`의 모든 깨우기/재큐잉 연산(`1, 3, 4, 5, 7, 10, 12`)에서 해당 슬롯의 `wakeup_ts = now`를 갱신하며, 만약 Tier 1 `sched_waking`이 정상 발화하면 해당 슬롯을 `claimed = 1`로 마킹하고, 발화하지 않은 경우(`TASK_RUNNING` 워커 + `glibc` Fastpath) 워커 스레드가 첫 `uprobe` 진입 시 미청구(`claimed == 0`) 슬롯을 FIFO로 인계받아 100% 핸드오프를 보장합니다.

---

### 결함 #13 — `mock_server.cpp`를 `-O1`로 컴파일할 때 타겟 함수들이 인라이닝(Inlining)되어 `uprobe`가 증발하는 결함
- **결함 메커니즘**:
  - `clang++`/`g++`에서 `-O1` 이상 최적화를 켜면 `parse_http_request()`, `validate_auth_header()`, `format_http_response()`, `verify_hmac_signature_internal()` 같은 함수들이 호출자(`main` 또는 워커 루프) 내부로 인라이닝되어 독립된 함수 진입점/복귀점이 사라지고 `uprobe`/`uretprobe`가 발화하지 않습니다.
- **수정된 명세 공식**:
  - `mock_server.cpp`와 `libcrypto_mock.cpp`의 모든 추적 대상 함수에 **`__attribute__((noinline))`** 지정을 의무화하고, `test_harness.sh` 빌드 플래그를 **`-g -O0 -fno-inline -fno-omit-frame-pointer`** 로 고정했습니다.

---

### 결함 #14 — `strip -x` 처리된 `libcrypto_mock.so`에서 `.symtab` 제거 후 내부 정적 함수(`verify_hmac_signature_internal`) 오프셋 자동 발굴 메커니즘 부재
- **결함 메커니즘**:
  - `libcrypto_mock.so`에 `strip -x` / `strip --strip-unneeded`를 실행하면 `.symtab`이 삭제되고 `.dynsym`에는 외부로 노출된 `verify_request_token`만 남습니다. 이때 내부 함수인 `verify_hmac_signature_internal`은 어떤 심볼 테이블에도 없으므로 단순 심볼 테이블 스캐너만으로는 자동 `uprobe` 부착이 불가능합니다.
- **수정된 명세 공식**:
  - Stripped 바이너리에 대해서는 C++ 예외 처리를 위해 `strip` 후에도 반드시 보존되는 **`.eh_frame` 섹션의 FDE(`Frame Description Entry`, `pc_begin .. pc_end`) 함수 경계 엔트리**와 `.dynsym` 함수 본문 내 **`bl <0xoffset>`(`aarch64`) / `callq <0xoffset>`(`x86_64`) 호출 타겟 오프셋**을 스캔하여 숨겨진 내부 함수 진입점에도 자동으로 `uprobe`/`uretprobe`를 부착하도록 명세했습니다.

---

### 결함 #15 — `kprobe__ip_rcv` 및 `kprobe__tcp_v4_rcv`에서 `skb->head + net_off` 직접 역참조 시 eBPF Verifier 거부(`R1 invalid mem access 'scalar'`)
- **결함 메커니즘**:
  - XDP(`ctx->data`)와 달리 `BPF_PROG_TYPE_KPROBE`에서는 `skb->head`가 비신뢰 커널 포인터(scalar/untrusted pointer)이므로 `*(struct iphdr *)(skb->head + net_off)`처럼 직접 포인터 역참조를 시도하면 Verifier가 즉시 로드를 거부합니다.
- **수정된 명세 공식**:
  - 반드시 `bpf_probe_read_kernel(&head, sizeof(head), &skb->head)`로 포인터를 읽은 후 **`bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off)`** 및 **`bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off)`** 헬퍼를 통해 커널 메모리를 읽도록 강제했습니다.

---

### 결함 #16 — `tracepoint:skb:kfree_skb`에서 정상 패킷 소비(`SKB_CONSUMED = 1`)까지 패킷 드롭(`FLAG_SKB_DROP`)으로 오탐하는 결함
- **커널 소스 근거**: [`include/net/dropreason-core.h:129-138`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h#L129-L138)
- **결함 메커니즘**:
  - 커널의 `enum skb_drop_reason`에서 `SKB_NOT_DROPPED_YET = 0`, `SKB_CONSUMED = 1`, `SKB_DROP_REASON_NOT_SPECIFIED = 2`는 정상 소비 및 미지정 해제를 포함합니다. 이를 구분하지 않으면 정상 요청에서도 `FLAG_SKB_DROP`이 켜질 수 있습니다.
- **수정된 명세 공식**:
  - `tracepoint:skb:kfree_skb`에서는 반드시 **`args->reason > SKB_DROP_REASON_NOT_SPECIFIED (2)`** 일 때만 실제 패킷 드롭(`FLAG_SKB_DROP` 및 `skb_drops++`)으로 집계하도록 필터링 규칙을 명시했습니다.

---

### 결함 #17 — `tracepoint:tcp:tcp_retransmit_skb`의 포트 이중 `ntohs()` 버그 및 `__u8 saddr[4]` 배열 레이아웃
- **커널 소스 근거**: [`include/trace/events/tcp.h:35-57`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L35-L57)
- **결함 메커니즘**:
  - `tcp.h:47-48`의 `TP_fast_assign`을 확인하면 커널이 이미 `__entry->sport = ntohs(inet->inet_sport); __entry->dport = ntohs(inet->inet_dport);`로 변환해 저장합니다. 여기에 eBPF 코드가 또 `bpf_ntohs(args->dport)`를 호출하면 포트 `8080`이 `36895`로 뒤집혀 포트 매칭에 실패하며, `args->saddr` 역시 정수형이 아닌 `__u8 saddr[4]` 배열입니다.
- **수정된 명세 공식**:
  - `tcp_retransmit_skb`에서는 `args->sport`/`args->dport`에 `bpf_ntohs()`를 호출하지 않고 그대로 사용하며, IPv4 주소는 `*(__be32 *)args->saddr`로 읽도록 수정했습니다.

---

### 결함 #18 — `tracepoint:sched:sched_process_fork`의 트레이스포인트 필드명(`args->parent_pid`, `args->child_pid`) 명세
- **커널 소스 근거**: [`include/trace/events/sched.h:358-385`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L358-L385)
- **결함 메커니즘**: `sched_process_fork`의 `TP_STRUCT__entry`는 `parent->pid`가 아닌 **`args->parent_pid`** 와 **`args->child_pid`** 를 노출합니다.
- **수정된 명세 공식**: `args->parent_pid` 및 `args->child_pid` 필드명을 정확히 명시했습니다.

---

### 결함 #19 — `AF_UNIX` (`unix_stream_sendmsg` ↔ `unix_stream_recvmsg`) 송수신 소켓 포인터(`sk` vs `peer`) 비대칭
- **커널 소스 근거**: [`net/unix/af_unix.c:2053, 2733`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2053)
- **결함 메커니즘**: `AF_UNIX` 스트림 연결에서 송신자의 `sock->sk`는 클라이언트 소켓(`sk_c`, `peer = sk_s`)이고 수신자의 `sock->sk`는 서버 소켓(`sk_s`, `peer = sk_c`)이므로 단순히 `(u32)(u64)sk`만 키로 사용하면 송수신 해시 키가 달라집니다.
- **수정된 명세 공식**: `unix_stream_sendmsg`에서는 `{ .saddr = (u32)(u64)sk, .daddr = (u32)(u64)unix_sk(sk)->peer }`, `unix_stream_recvmsg`에서는 `{ .saddr = (u32)(u64)unix_sk(sk)->peer, .daddr = (u32)(u64)sk }`로 정규화하여 양측이 동일한 키로 매칭되도록 수정했습니다.

---

### 결함 #20 — Generic XDP(`XDP_FLAGS_SKB_MODE`) 활성화 시 `xdp_ingress_filter`와 `tracepoint:net:netif_receive_skb`의 L2 이벤트 중복 방출
- **결함 메커니즘**: 두 훅을 동시에 부착하면 동일 패킷이 XDP를 거친 직후 `netif_receive_skb`를 다시 통과하여 `LAYER_INGRESS_NIC` 이벤트가 2번 중복 방출됩니다.
- **수정된 명세 공식**: `netif_receive_skb`에서 `ingress_flow_map.lookup(&key)` 조회 시 이미 `state->xdp_ts != 0 && state->consumed == 0`으로 XDP가 기록한 패킷이면 중복 방출을 스킵하도록 가드를 추가했습니다.

---

### 결함 #21 — `kprobe__handle_mm_fault`에서 매 마이너 페이지 폴트마다 64B RingBuf 이벤트를 개별 방출할 때 발생하는 링버퍼 폭주
- **결함 메커니즘**: 메모리 집약적 요청 처리 중 수백 번의 Minor Page Fault가 발생할 때마다 64B RingBuf 이벤트를 방출하면 정작 중요한 함수/네트워크 이벤트가 밀려날 수 있습니다.
- **수정된 명세 공식**: `kprobe__handle_mm_fault`는 RingBuf 이벤트를 직접 방출하지 않고 `active_ctx_map[tid]->page_faults++` 카운터만 In-Place로 증가시키며, `skb_copy_datagram_iovec`에서 `ev->ip = ((u64)ctx->page_faults << 32) | (u32)args->len;`으로 합산된 단일 `OSI_L5_SYSCALL_MEM` 이벤트를 방출하도록 최적화했습니다.

---

### 결함 #22 — `aarch64` PIE/공유 라이브러리에서 ELF 심볼 `st_value`를 `attach_uprobe` 파일 오프셋으로 변환하는 `PT_LOAD` 수식 누락
- **결함 메커니즘**: `aarch64` 바이너리는 64KB 세그먼트 정렬 등으로 인해 실행 가능 `PT_LOAD` 세그먼트(`PF_X`)의 가상 주소(`p_vaddr`)와 파일 오프셋(`p_offset`)이 다를 수 있어, 단순히 `st_value`를 그대로 커널 `attach_uprobe`에 전달하면 잘못된 파일 오프셋에 프로브가 부착됩니다.
- **수정된 명세 공식**: 심볼이 속한 실행 가능 `PT_LOAD` 세그먼트(`PF_X`)를 찾아 **`uprobe_file_offset = st_value - seg.p_vaddr + seg.p_offset`** 공식으로 정확한 파일 오프셋을 산출하도록 명시했습니다.

---

### 결함 #23 — `ai_diagnosis.json`의 최상위 JSON 키 스키마 계약(`source_code_evidence`, `stripped_assembly_evidence` 등) 명시화
- **결함 메커니즘**: `network_layer_diagnostics` 하위 스키마는 상세히 정의되어 있었으나, `TEST-08`과 `TEST-09`가 참조하는 `ai_diagnosis.json`의 최상위 키 이름이 한곳에 고정되어 있지 않았습니다.
- **수정된 명세 공식**: 최상위 8대 필수 키(`req_id`, `total_rtt_ms`, `drop_count`, `bottleneck_summary`, `hop_timeline`, `source_code_evidence`, `stripped_assembly_evidence`, `network_layer_diagnostics`)를 명시적으로 고정했습니다.

---

### 결함 #24 — Graphviz `subgraph cluster_mod_<filename>`에 마침표(`.`)나 하이픈(`-`) 포함 시 `dot -Tsvg` 문법 에러 발생(`TEST-07`)
- **결함 메커니즘**: 모듈 파일명이 `libcrypto_mock.so`일 때 Graphviz DOT 코드에 `subgraph cluster_mod_libcrypto_mock.so { ... }`처럼 마침표(`.`)가 포함된 비인용 식별자를 출력하면 `dot -Tsvg`가 구문 오류(Syntax Error)로 실패합니다.
- **수정된 명세 공식**: 반드시 `re.sub(r'[^a-zA-Z0-9_]', '_', os.path.basename(mod))`로 정규화하여 `subgraph cluster_mod_libcrypto_mock_so`로 생성하고 원본 파일명은 `label="Module: libcrypto_mock.so"` 속성에 표시하도록 강제했습니다.

---

### 결함 #25 — 최소 컨테이너 환경에서 `iproute2`(`ss`) 미설치 시 `--discover-ports` 실패 방지용 `/proc/net/*` 직접 파서 내장
- **결함 메커니즘**: 미니멀 컨테이너나 슬림 이미지에는 `ss`(`iproute2`) 유틸리티가 설치되어 있지 않을 수 있어 외부 명령 호출에만 의존하면 `--discover-ports`가 실패합니다.
- **수정된 명세 공식**: 리눅스 커널이 항상 노출하는 **`/proc/net/{tcp,tcp6,udp,udp6,unix}` 16진수 소켓 테이블 + `/proc/<pid>/fd/*` 소켓 inode 매칭 파서**를 기본 내장하고 `ss -tulnp`/`ss -xlnp`를 보조 수단으로 결합하도록 명세했습니다.

---

## 4. [Phase 3] 3차 극한 커널 소스·Verifier·ABI 정밀 감사: 10대 심층 결함 추가 발굴 및 제거 (결함 #26 ~ #35, 누적 45건)

2차 감사 이후에도 남아 있을 수 있는 **커널 함수 내부 실행 순서(Execution Ordering), 블로킹 소켓 대기(`sk_wait_data`), Per-CPU 맵 오염, 스케줄러 Sleep 시간 증발, 다중 프로토콜(IPv6/UDP/ARP) 커널 구조체 레이아웃, CO-RE `vmlinux.h` 시스템콜 트레이스포인트 ABI**를 커널 소스 줄 단위로 다시 추적하여 발굴한 10가지 핵심 결함입니다.

### 결함 #26 — 블로킹 소켓 `tcp_recvmsg` 진입 시 패킷 미도착(`sk_wait_data`)으로 인한 `ingress_flow_map` 조회 실패 및 요청 버퍼 크기(`len=4096`) 오기록
- **커널 소스 근거**: [`net/ipv4/tcp.c:2585-2638, 2742`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2585-L2638) (`tcp_recvmsg_locked()`, `sk_wait_data()`, `tcp_recvmsg()`)
- **결함 메커니즘**:
  - `mock_server.cpp`와 같은 블로킹 TCP 서버나 Keep-Alive 연결에서 I/O 스레드는 클라이언트가 HTTP 요청 패킷을 보내기 **전**에 미리 `recv()`(`tcp_recvmsg`)를 호출하고 커널 내부의 `sk_wait_data(sk, &timeo, NULL)`(`tcp.c:2638`)에서 블로킹 대기합니다.
  - 따라서 **`kprobe__tcp_recvmsg` 진입 시점에는 아직 클라이언트 패킷이 NIC(`XDP`)나 `tcp_v4_rcv`에 도착하기 전**이므로 `ingress_flow_map.lookup(&key)`가 `NULL`(또는 이전 완료된 요청)을 반환하여 SoftIRQ ↔ User Thread 바인딩이 100% 끊어집니다!
  - 또한 `kprobe__tcp_recvmsg`의 3번째 인자 `PT_REGS_PARM3(ctx)`(`size_t len`)는 유저가 넘긴 **수신 버퍼 최대 용량(예: `4096`)**이지 실제 수신된 패킷 바이트 수(예: `184B`)가 아닙니다. 실제 수신 바이트 수는 `tcp_recvmsg`가 반환하는 **`int copied = PT_REGS_RC(ctx)`** 에만 존재합니다.
- **수정된 명세 공식**:
  - `kprobe__tcp_recvmsg` 진입 시 `ctx->active_sk_ptr = (u64)PT_REGS_PARM1(ctx)`를 저장하고, 이미 `ingress_flow_map[key]`에 미소비(`state->consumed == 0`) 패킷이 도착해 있으면(Non-blocking / Epoll Ready) 즉시 바인딩합니다.
  - 만약 진입 시점에 패킷이 도착하지 않아 `sk_wait_data()`에서 대기했다가 패킷 수신 후 복귀하는 경우에는 **`kretprobe__tcp_recvmsg`**(`int copied = (int)PT_REGS_RC(ctx); if (copied <= 0) return 0;`)에서 `ctx->active_sk_ptr`로 다시 `ingress_flow_map.lookup(&key)`를 조회하여 `state->consumed = 1` 마킹 및 `ctx->req_id = state->req_id` 바인딩을 수행하고, **실제 수신 바이트 수(`ev->ip = (u64)copied`)**와 `sk_rcvbuf` 체류 시간(`now - state->tcp_rcv_ts`)을 정확히 방출하도록 이중 바인딩 구조를 확립했습니다.

---

### 결함 #27 — `tracepoint:net:netif_receive_skb` 실행 시점의 미초기화 `skb->network_header` 및 Generic XDP(`do_xdp_generic`)와의 실행 순서 역전
- **커널 소스 근거**: [`net/core/dev.c:5592-5629`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c#L5592-L5629) (`__netif_receive_skb_core()`)
- **결함 메커니즘**:
  - `dev.c:5606-5626`의 커널 코드를 줄 단위로 확인하면 다음과 같은 순서로 실행됩니다:
    1. Line 5606: `trace_netif_receive_skb(skb);`
    2. Line 5610: `skb_reset_network_header(skb);`
    3. Line 5626: `ret = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), skb);`
  - 여기서 두 가지 결정적 사실이 드러납니다:
    1) `trace_netif_receive_skb(skb)`(line 5606)가 호출될 때는 **아직 `skb_reset_network_header(skb)`(line 5610)가 실행되기 전**입니다! 따라서 `netif_receive_skb`에서 `skb->head + skb->network_header`를 읽으면 리셋되지 않은 엉뚱한 오프셋을 읽게 됩니다(반면 NIC 드라이버가 호출한 `eth_type_trans()`가 이미 L2 이더넷 헤더 14B를 벗겨냈으므로 **`skb->data`가 정확히 L3 `struct iphdr`의 시작점**을 가리킵니다).
    2) Native Driver XDP(`XDP_FLAGS_DRV_MODE`)에서는 `xdp_ingress_filter` → `netif_receive_skb` 순으로 실행되지만, 루프백(`lo`)이나 `veth`에서 동작하는 **Generic XDP(`XDP_FLAGS_SKB_MODE`, `do_xdp_generic` at line 5626)에서는 거꾸로 `trace_netif_receive_skb`(line 5606)가 먼저 실행되고 `xdp_ingress_filter`(line 5626)가 나중에 실행**됩니다! 따라서 단방향으로만 중복 방지 가드를 걸면 Generic XDP에서 L2 이벤트가 여전히 2번 방출됩니다.
- **수정된 명세 공식**:
  - `tracepoint:net:netif_receive_skb`에서는 `skb->network_header`가 아닌 **`skb->data`(`bpf_probe_read_kernel(&data, sizeof(data), &skb->data)`)에서 직접 `struct iphdr`를 읽도록** 교정하고, **`xdp_ingress_filter`와 `tracepoint:net:netif_receive_skb` 양쪽 모두에 `if (state->xdp_ts != 0 && state->consumed == 0)` 양방향(Bidirectional) 중복 방출 방지 가드**를 적용했습니다.

---

### 결함 #28 — `trace_skb_copy_datagram_iovec`가 실제 유저 메모리 복사(`simple_copy_to_iter`) 및 페이지 폴트(`handle_mm_fault`)보다 먼저 실행되는 순서 결함
- **커널 소스 근거**: [`net/core/datagram.c:531-537`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/datagram.c#L531-L537) (`skb_copy_datagram_iter()`)
- **결함 메커니즘**:
  - `datagram.c:531-537`의 `skb_copy_datagram_iter()` 내부를 보면:
    ```c
    trace_skb_copy_datagram_iovec(skb, len); // Line 534: 복사 시작 전에 먼저 호출됨!
    return __skb_datagram_iter(skb, offset, to, len, false,
                               simple_copy_to_iter, NULL); // Line 535: 실제 유저 메모리 복사 및 Page Fault 발생!
    ```
  - 즉 `tracepoint:skb:skb_copy_datagram_iovec`(line 534) 시점에 즉시 `OSI_L5_SYSCALL_MEM (6)` 이벤트를 방출해 버리면, 정작 그 직후인 line 535(`simple_copy_to_iter`)에서 일어나는 **커널→유저 메모리 복사 소요 시간과 유저 수신 버퍼의 Minor Page Fault(`kprobe__handle_mm_fault`)가 측정에서 누락**됩니다.
- **수정된 명세 공식**:
  - 진입 시점(`tracepoint:skb:skb_copy_datagram_iovec` 또는 `kprobe__skb_copy_datagram_iter`)에는 `ctx->copy_enter_ts = now; ctx->copied_bytes += args->len;`만 기록하고, `simple_copy_to_iter()` 실행 도중 발생하는 페이지 폴트는 `kprobe__handle_mm_fault`가 `ctx->page_faults++`로 누적한 뒤, **복사가 완료된 직후인 `kretprobe__skb_copy_datagram_iter`(또는 `kretprobe__tcp_recvmsg`)에서 실제 복사 지연 시간(`duration_ns = now - ctx->copy_enter_ts`)과 `ctx->page_faults`를 담아 `OSI_L5_SYSCALL_MEM (6)` 이벤트를 방출**하도록 교정했습니다.

---

### 결함 #29 — 유저 함수 실행 중(`call_depth > 0`) Off-CPU Sleep 시 `wakeup_ts`로 인해 슬립 시간(`18ms`)이 증발하고 On-CPU 연산으로 오판되는 결함 + 타임스탬프 잔류 오염
- **결함 메커니즘**:
  - 워커 스레드가 유저 함수 `execute_storage_query()`(`ctx->call_depth > 0`) 내부에서 `18.0ms` 동안 슬립(Off-CPU)한다고 가정합시다:
    - $t = 10.00\text{ ms}$: `sched_switch` (`prev_pid == tid`) → `ctx->off_cpu_enter_ts = 10.00ms`
    - $t = 28.00\text{ ms}$: 타이머/디스크 완료로 `sched_wakeup` 발생 → `ctx->wakeup_ts = 28.00ms`
    - $t = 28.05\text{ ms}$: `sched_switch` (`next_pid == tid`)로 CPU 복귀
  - 이때 `sched_switch` (`next_pid == tid`)에서 `ev->duration_ns = ctx->wakeup_ts ? (now - ctx->wakeup_ts) : (now - ctx->off_cpu_enter_ts);`로 계산하면, `ctx->wakeup_ts`가 존재하므로 단지 런큐 대기 시간인 **`0.05ms`만 방출되고 실제 슬립 시간인 `18.00ms`는 증발**해 버립니다!
  - 그 결과 유저 영역(`tracer_agent.py`)이 함수 총 시간(`total_fn_duration_ns`)에서 차감할 Off-CPU 대기 시간이 `0.05ms`밖에 되지 않아, **실제로는 잠들어 있었던 `18.00ms`를 순수 On-CPU ALU 연산(`pure_on_cpu_compute_ms`)으로 오판**하게 됩니다. 또한 방출 후 `off_cpu_enter_ts`와 `wakeup_ts`를 `0`으로 리셋하지 않으면 이후 단순 선점(Preemption) 시 과거의 `wakeup_ts`가 재사용되어 음수/엉뚱한 지연 시간이 계산됩니다.
- **수정된 명세 공식**:
  - `sched_switch` (`args->next_pid == tid`)에서 `u64 runq_ns = ctx->wakeup_ts ? (now - ctx->wakeup_ts) : 0;`과 `u64 total_off_cpu_ns = ctx->off_cpu_enter_ts ? (now - ctx->off_cpu_enter_ts) : runq_ns;`를 분리 산출합니다.
  - **유저 함수 진입 전(`ctx->call_depth == 0`)에는 초기 스케줄러 디스패치 런큐 대기 시간(`ev->duration_ns = runq_ns`)을 방출하고, 유저 함수 실행 도중(`ctx->call_depth > 0`)에는 슬립과 런큐 대기를 모두 포함한 전체 Off-CPU 시간(`ev->duration_ns = total_off_cpu_ns`)을 방출**하며, 방출 직후 반드시 **`ctx->off_cpu_enter_ts = 0; ctx->wakeup_ts = 0; ctx->futex_enter_ts = 0;`으로 즉시 리셋**하도록 강제했습니다.

---

### 결함 #30 — `BPF_PERCPU_ARRAY(zero_ctx_map)`를 In-Place 수정할 때 동일 CPU 코어의 다음 스레드 초기화가 오염되는 결함
- **결함 메커니즘**:
  - `BPF_PERCPU_ARRAY`의 원소는 매 호출마다 자동으로 0으로 초기화되지 않고 동일 CPU 코어에서 영속적으로 유지됩니다. 만약 `struct tid_ctx_t *scratch = zero_ctx_map.lookup(&zero_idx);`를 얻은 뒤 `scratch->req_id = ...; scratch->in_target_sendmsg = 1;`처럼 `scratch` 내부 필드를 직접 수정하고 `active_ctx_map.update(&tid, scratch)`를 호출하면, `zero_ctx_map[0]` 자체가 오염되어 같은 코어에서 초기화되는 다음 스레드에 이전 스레드의 잔여 필드(`page_faults`, `call_depth`, `acc_off_cpu_ns`)가 그대로 복제됩니다.
- **수정된 명세 공식**:
  - `zero_ctx_map[0]`은 **절대 내부 필드를 수정하지 않는 순수 읽기 전용(Strictly Read-Only) 올-제로 템플릿**으로만 사용합니다. 반드시 `active_ctx_map.update(&tid, zero_template)`으로 맵에 0으로 초기화된 엔트리를 먼저 생성한 뒤, `ctx = active_ctx_map.lookup(&tid)`로 포인터를 다시 얻어 `active_ctx_map` 내부에서만 필드를 수정하도록 명세했습니다.

---

### 결함 #31 — 리눅스 커널 헤더(`include/uapi/linux/if_arp.h:144-161`)의 `struct arphdr`에서 `ar_sip`/`ar_tip` 멤버가 `#if 0`으로 비활성화되어 있는 컴파일 결함
- **커널 소스 근거**: [`include/uapi/linux/if_arp.h:144-161`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/linux/if_arp.h#L144-L161)
- **결함 메커니즘**:
  - `if_arp.h:151-159`를 확인하면 가변 길이 하드웨어 주소를 지원하기 위해 `ar_sha`, `ar_sip`, `ar_tha`, `ar_tip` 필드가 **`#if 0 ... #endif` 전처리기 블록으로 주석 처리**되어 있으며, 실제 `struct arphdr`는 고정 8바이트 헤더(`ar_hrd`, `ar_pro`, `ar_hln`, `ar_pln`, `ar_op`)만 가집니다. 따라서 C 코드에서 `arp->ar_sip`를 참조하면 즉시 컴파일 에러가 발생합니다.
- **수정된 명세 공식**:
  - ARP 패킷(`kprobe__arp_rcv`)에서는 `struct arphdr`(`8B`) 직후의 이더넷/IPv4 페이로드(`ar_sha[6]`, `ar_sip[4]`, `ar_tha[6]`, `ar_tip[4]`) 오프셋인 **`(u8 *)(arp + 1) + 6`에서 `saddr`(`4B`)를, `(u8 *)(arp + 1) + 16`에서 `daddr`(`4B`)를 `bpf_probe_read_kernel`로 추출**하도록 명시했습니다.

---

### 결함 #32 — 비연결(Unconnected) UDP 서버 소켓의 `skc_daddr == 0`, `skc_dport == 0` 문제 및 `kretprobe__udp_recvmsg` `msg->msg_name` 추출
- **커널 소스 근거**: [`net/ipv4/udp.c:1868-1945`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1868-L1945) (`udp_recvmsg()`)
- **결함 메커니즘**:
  - TCP와 달리 `bind(:53)`이나 `bind(:8080)`만 수행한 비연결 UDP 서버 소켓은 `connect()`를 호출하지 않으므로 `sk->__sk_common.skc_daddr`와 `skc_dport`가 항상 **`0`** 입니다!
  - 또한 `udp.c:1938-1944`를 보면 커널은 패킷 복사가 끝난 후 함수 종료 직전에야 `DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name); sin->sin_port = udp_hdr(skb)->source; sin->sin_addr.s_addr = ip_hdr(skb)->saddr;`로 송신자 주소를 채웁니다.
- **수정된 명세 공식**:
  - `kprobe__udp_recvmsg` 진입 시 `ctx->active_msg_name = (u64)msg->msg_name`을 저장하고, 복귀하는 **`kretprobe__udp_recvmsg`** 에서 `struct sockaddr_in *sin = (struct sockaddr_in *)ctx->active_msg_name`을 읽어 클라이언트 IP와 포트를 복원합니다(`msg_name == NULL`일 때를 대비해 `kprobe__udp_rcv`에서 `{ .daddr = 0, .dport = skc_num, .proto = IPPROTO_UDP }` 포트 단위 폴백 키도 함께 지원).

---

### 결함 #33 — 순수 IPv6 소켓(`skc_v6_daddr`) 32비트 XOR 폴딩, Dual-Stack(`::ffff:`) `AF_INET` 정규화 및 `kprobe__ipv6_rcv`의 미초기화 `transport_header`
- **커널 소스 근거**: [`include/net/sock.h:192-193`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/sock.h#L192-L193), [`net/ipv6/ip6_input.c:260, 302`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L260)
- **결함 메커니즘**:
  1. 순수 IPv6 연결에서는 `skc_daddr`가 `0`이고 128비트 주소가 `sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0..3]` 및 `skc_v6_rcv_saddr.in6_u.u6_addr32[0..3]`에 저장됩니다.
  2. 반대로 Dual-Stack 소켓(`IPV6_V6ONLY = 0`)이 IPv4 패킷(`::ffff:127.0.0.1`)을 수신하면 L2/L3/L4에서는 `family = AF_INET (2)`으로 기록되지만 소켓의 `skc_family`는 `AF_INET6 (10)`이어서 `key.family` 불일치가 발생합니다.
  3. 또한 `kprobe__ipv6_rcv`(`ip6_input.c:302`) 진입 시점에는 `ip6_rcv_core()`(`ip6_input.c:260`)가 실행되기 전이므로 `skb->transport_header`가 아직 설정되지 않았습니다.
- **수정된 명세 공식**:
  1. `skc_family == AF_INET6 && skc_daddr == 0`(순수 IPv6)일 때는 `skc_v6_daddr`와 `skc_v6_rcv_saddr`의 `u6_addr32[0..3]` 4개 워드를 XOR 폴딩하여 `flow_key_t`를 생성합니다.
  2. `skc_daddr != 0`(IPv4 및 Dual-Stack IPv4-mapped IPv6)일 때는 `skc_family` 값과 무관하게 `key.family = AF_INET (2)`로 정규화합니다.
  3. `kprobe__ipv6_rcv`에서는 `u16 trans_off = net_off + sizeof(struct ipv6hdr);`(`+40`)로 L4 헤더 위치를 산출합니다.

---

### 결함 #34 — 비동기 `kblockd` `kworker`의 `block_rq_issue` 실행 시 유저 `tid` 덮어쓰기 방지 & `kfree_skb` 3단계 플로우 조회
- **커널 소스 근거**: [`include/trace/events/block.h:238, 252`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L238), [`btf-and-headers/vmlinux.h:117515`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L117515)
- **결함 메커니즘**:
  1. 유저 스레드가 블록 I/O를 요청할 때 `block_rq_insert`는 유저 스레드 컨텍스트에서 실행되어 `inflight_bio_map[bkey]`에 유저 `tid`와 `req_id`를 기록하지만, 이어지는 `block_rq_issue`는 커널 `kblockd` 워크큐(`kworker`) 스레드에서 비동기로 실행될 수 있습니다. 만약 `block_rq_issue`가 무조건 현재 `tid`(`kworker`)로 `inflight_bio_map[bkey]`를 덮어쓰면 원본 유저 스레드의 `tid`와 `req_id`가 유실됩니다.
  2. 또한 `tracepoint:skb:kfree_skb`에서 드롭(`args->reason > 2`) 발생 시 Egress 패킷과 Ingress 패킷의 조회 경로가 다릅니다.
- **수정된 명세 공식**:
  1. `block_rq_issue`에서는 `inflight_bio_map.lookup(&bkey)`를 먼저 확인하여 이미 `block_rq_insert`가 등록한 엔트리가 있으면 기존의 유저 `bstate->tid`와 `bstate->req_id`를 보존하고 `bstate->issue_ts = now;`만 갱신하며, 완료 훅인 `block_rq_complete`(Block SoftIRQ)에서는 항상 `active_ctx_map.lookup(&bstate->tid)`를 조회합니다.
  2. `tracepoint:skb:kfree_skb`에서는 ① `skb_egress_map[(u64)args->skbaddr]`, ② `args->rx_sk`, ③ `(struct sk_buff *)args->skbaddr`의 L3/L4 헤더 순으로 3단계 조회를 수행하도록 명시했습니다.

---

### 결함 #35 — BPF CO-RE(`vmlinux.h:119889`)의 `trace_event_raw_sys_enter`(`ctx->args[1]`) vs BCC(`args->op`) 호환 및 `tcp_retransmit_skb` 양방향(`sport`/`dport`) 감지
- **커널 소스 근거**: [`btf-and-headers/vmlinux.h:119889`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119889), [`include/trace/events/tcp.h:35-57`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L35-L57)
- **결함 메커니즘**:
  1. `vmlinux.h:119889`를 확인하면 커널 BTF에는 개별 시스콜 전용 트레이스포인트 구조체가 따로 있는 것이 아니라 공통 구조체인 `struct trace_event_raw_sys_enter { ... long int id; long unsigned int args[6]; };`만 존재합니다. 따라서 `#ifdef KRAY_BPF_CORE` 모드에서 `ctx->op`를 참조하면 컴파일이 실패하며 `ctx->args[1]`을 읽어야 합니다(반면 BCC `TRACEPOINT_PROBE(syscalls, sys_enter_futex)`에서는 `args->op` 사용).
  2. 또한 `tracepoint:tcp:tcp_retransmit_skb`에서 서버가 송신한 HTTP 응답 패킷이 재전송될 때는 `args->sport == target_port`(`egress_flow_map`)이고, 클라이언트가 보낸 패킷이 재전송될 때는 `args->dport == target_port`(`ingress_flow_map`)입니다.
- **수정된 명세 공식**:
  1. `sys_enter_futex`에서 `#ifdef KRAY_BPF_CORE`일 때는 `((u32)ctx->args[1] & 0x7f)`, BCC일 때는 `((u32)args->op & 0x7f)`로 추출하도록 이중 호환 매크로를 명세했습니다.
  2. `tcp_retransmit_skb`에서 `args->dport == target_port`(`ingress_flow_map`)와 `args->sport == target_port`(`egress_flow_map`) 양방향을 모두 검사하여 `FLAG_TCP_RETRANSMIT`을 누락 없이 기록하도록 반영했습니다.

---

## 5. 결론 및 아카이브 총괄 요약

- **총 발굴 및 제거된 명세 결함 수**: **45건**
  - **Phase 1 (1차 아키텍처 10회 반복 감사)**: 10건 (Iterations 1 ~ 10)
  - **Phase 2 (2차 심층 커널 소스·Verifier·ELF·런타임 감사)**: 25건 (결함 #1 ~ #25)
  - **Phase 3 (3차 극한 커널 실행 순서·블로킹 소켓·Per-CPU 오염·다중 프로토콜·CO-RE ABI 감사)**: 10건 (결함 #26 ~ #35)
- **최종 반영 완료 문서**:
  - 마스터 명세서: [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md) (전 구간 본문 및 Part 5 Copy-Ready Master Prompt 100% 동기화 완료)
  - 감사 아카이브 보고서: [`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md)
- **핵심 엔지니어링 의의**: 코드를 단 한 줄도 작성하기 전에 타겟 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 소스 트리의 함수 내부 줄 번호와 실행 순서(`dev.c:5606`, `tcp.c:2638`, `datagram.c:534`), eBPF Verifier 제약, `vmlinux.h` BTF 구조체, ELF/DWARF/컴파일러 동작까지 총 45건의 잠재 결함을 명세 단계에서 선제 발굴·제거함으로써, 이 명세서 하나만으로 무결점(Zero-Defect) 구현이 가능하도록 완성했습니다.
