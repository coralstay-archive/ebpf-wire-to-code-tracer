# eBPF Wire-to-Code Tracer (kray)

> Nanosecond-Precision 7-Layer (Wire-to-PreCompute-to-ALU) Telemetry Collector for Linux Kernels (Rocky Linux 9.8 aarch64 & x86_64)

---

---

## 0. 통합 마스터 문서 목차 (Master Document Table of Contents)

프로젝트 내 흩어져 있던 모든 기술 문서·설계 명세·포스트모템·표준 가이드·검증 보고서를 **단 한 줄의 누락도 없이 이 단일 파일([README.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md))에 완전 통합**했습니다.

| 권(Book) | 통합된 원본 문서 및 섹션 | 핵심 수록 내용 |
| :--- | :--- | :--- |
| **Book I** | `README.md` (섹션 1 ~ 7) | 프로젝트 존재 이유(고수준 언어 I/O 사각지대 4종), 5대 실전 검증 시나리오(`krayctl verify 1..5`), `krayctl` 퀵스타트, 7계층 아키텍처, 모듈형 디렉터리 구조 |
| **Book II** | **UTM 하이퍼바이저·Rocky Linux 9.8 설치/실행 가이드 & 커널 소스 명세** | UTM(`v4.7.5`, `Apple Virtualization.framework`) 상세 스펙, VM 시작/정지/실행 방법, Rocky Linux 9.8 aarch64 클린 설치 및 eBPF 툴체인 패키지 프로비저닝 절차, 커널(`5.14.0-687.10.1.el9_8.0.1.src.rpm`) 공식 다운로드 링크 |
| **Book III** | 구 `ARCHITECTURE.md` 전문 | 7계층 세부 커널 훅 명세, 5대 검증 시나리오 수식 매핑표, Verifier 512B 스택 가드 원칙, 3계층 무셸(`Zero-.sh`) 모듈화 설계 |
| **Book IV** | 구 `LICENSING.md` 전문 | 커널 BPF(`GPL-2.0`) 및 유저 공간 도구(`AGPL-3.0-only` / `MIT`) 듀얼 라이선스 명세 |
| **Book V** | 구 `UNIFIED_TECHNICAL_SPECIFICATION.md` 전문 | 11개 파트 마스터 기술 명세서, 22종 프로토콜 명세, 6대 하드웨어/커널 실증 증명, **105개 전수 CLI 명령어 시나리오 카탈로그** |
| **Book VI** | 구 `references/cli-argument-standards-and-conventions.md` 전문 | Michael Kerrisk *TLPI* & Linux `man-pages(7)` & POSIX IEEE 1003.1 Guidelines 1~13 & BSD `<sysexits.h>` 표준 레퍼런스 |
| **Book VII** | 구 `references/ebpf-production-postmortems-and-arm64-limits.md` 전문 | Cilium·Cloudflare·Datadog·Meta·Netflix 프로덕션 장애 부검, ARM64 약한 메모리 순서(`dmb ishld`), 커널 CVE, Cgroups v2 OOM 계산식 |
| **Book VIII** | 구 `references/failure-conditions-and-hardening-report.md` 전문 | 4대 엔지니어링 관점 경계 분석, 8대 실패 모드(`FAIL-01..08`), 호스트·타겟 VM 20회 연속 무결성 벤치마크 |
| **Book IX** | 구 `PROMPT_SPEC.md` 전문 | 초기 시스템 아키텍처 블루프린트 및 상세 구현 요구사항 명세 전문 |
| **Book X** | 구 `archive/**/*.md` (33개 검증 보고서 전문) | 사전 설계 감사 보고서, 심화 테스트 엔지니어링 보고서, 10인 및 20인 서브에이전트 계층별 코드 검증 보고서 전수 수록 |

---

# [Book I] 프로젝트 개요, 5대 실전 검증 시나리오 및 퀵스타트 가이드


## 1. 개요 및 프로젝트 존재 이유 (Overview & Why This Project Exists)

eBPF Wire-to-Code Tracer(`kray`)는 물리 NIC에 패킷이 도착하는 순간(L2 XDP)부터 커널 프로토콜 스택(L3 IP, L4 TCP), 소켓 버퍼 큐(L5), 스레드 풀 핸드오프 및 CPU 런큐 대기(L6 Pre-Compute Gate), 그리고 유저 애플리케이션 함수 실행(L7 Uprobe) 및 응답 송신(Egress)까지 **전 구간을 단일 64비트 Request ID(`req_id`)로 연결하여 나노초 단위 지연 시간**을 측정하는 차세대 eBPF 관측성 도구입니다.

리눅스 커널 업스트림 [`tools/testing/selftests/bpf`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/upstream-kernel-bpf-docs/selftests/) 아키텍처를 100% 준용하여, 마이크로 BPF 모듈화([progs/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/)), BPF Skeleton 자동 생성(`bpftool gen skeleton`), 그리고 순수 C 기반 네이티브 테스트 러너([test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c)) 및 경량 데몬([tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c))을 제공합니다.

### 왜 Java / Go / Node.js 등 언어 차원의 I/O API와 APM만으로는 부족한가?

현대 프로그래밍 언어(Java NIO/Netty/Virtual Thread, Go netpoll, Node.js libuv, Rust Tokio 등)는 훌륭한 고수준 비동기 I/O API와 프로파일러를 제공합니다. 그럼에도 불구하고 이 프로젝트가 존재하는 핵심 이유는 **"언어 런타임의 시계는 패킷이 물리 NIC에 도착했을 때 켜지지 않기 때문"**입니다.

실무에서 가장 흔히 겪는 **"클라이언트는 응답이 100ms 걸렸다고 불평하는데, 서버 애플리케이션(Java/Go/C++) 로그에는 처리 시간이 2ms로 찍히는 유령 지연(Phantom Latency)"** 현상은 아래 4가지 구조적 사각지대에서 발생합니다:

| 구간 | Java / 고수준 언어 I/O API의 시각 | 실제 리눅스 커널 내부에서 벌어지는 일 (`kray`가 보는 시각) |
| :--- | :--- | :--- |
| **① 수신 대기 (Ingress Blindness)** | `Selector.select()`(`epoll_wait`)가 깨어나서 `SocketChannel.read()`를 호출하는 순간부터 요청이 시작됐다고 믿음 | 패킷은 이미 50ms 전에 NIC([`xdp_ingress_filter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c#L18))와 TCP 스택([`kprobe__tcp_v4_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L20))에 도착했지만, JVM GC(Stop-The-World)나 이벤트 루프 포화로 **커널 소켓 수신 버퍼(`sk_rcvbuf`)에서 50ms 동안 방치**됨 |
| **② 스레드 핸드오프와 스케줄러** | `CompletableFuture`나 `ExecutorService.submit()`에 작업을 넘기면 코드 상으로는 즉시 실행되는 것처럼 보임 | 내부적으로는 [`sys_enter_futex`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L16) 락 경합을 겪고, 깨어난 뒤에도 OS CPU 런큐([`sched_wakeup`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L190) → [`sched_switch`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L199))에서 다른 프로세스에 밀려 대기하며 다른 CPU 코어로 튕겨 나감(캐시 미스 발생) |
| **③ 코드 실행 중 Off-CPU 착시** | 특정 함수가 완료되는 데 30ms가 걸리면 "이 함수 알고리즘이 느리다"고 찍힘 | 실제로는 순수 CPU 연산([`trace_uprobe_entry`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c#L20))은 1ms뿐이고, 나머지 29ms는 커널 메모리 복사 중 페이지 폴트([`kprobe__handle_mm_fault`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L217)), 디스크 블록 I/O([`block_rq_complete`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L501)), 혹은 OS 스케줄러 선점(`acc_off_cpu_ns`)으로 허비됨 |
| **④ 송신 완료의 착각 (Egress Blindness)** | `channel.writeAndFlush()`나 `send()`가 리턴되면 "응답 전송 완료(0.1ms)"라고 로그를 남김 | 유저 버퍼에서 커널 송신 버퍼([`kprobe__tcp_sendmsg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L301))로 복사만 끝났을 뿐, 실제 패킷은 TCP 혼잡 윈도우나 Qdisc 큐에 막혀 못 나가거나 커널 내부에서 드롭([`kfree_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L262)) 및 재전송([`tcp_retransmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L220))되고 있음 |

---

## 2. 이 프로그램으로 수행하는 5대 실전 검증 시나리오 (`krayctl verify`)

막연한 추측 대신 [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl)과 [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c)를 사용하여 다음 5가지 실전 아키텍처 가설을 나노초 단위의 수치로 즉시 검증할 수 있습니다.

```bash
# 5대 실전 검증 시나리오 전체 목록 및 고수준 I/O 사각지대 요약 보기
krayctl verify list
```

### 검증 1: 소켓 수신 버퍼 적체(`sk_rcvbuf` Dwell Time) vs 애플리케이션 읽기 지연 검증
* **검증 질문**: *"응답 지연의 원인이 내 비즈니스 로직 때문인가, 아니면 GC/이벤트 루프 포화로 패킷이 커널 소켓 버퍼에서 대기했기 때문인가?"*
* **커널 계측 원리**: [`progs/tracer_l5_syscall.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L57-L81)에서 패킷이 커널 L4 TCP 스택에 도착한 시각(`state->tcp_rcv_ts`)과 애플리케이션 스레드가 `read()`/`recvmsg()`를 호출해 꺼내간 시각(`now`)의 차이인 **`dwell_ns`**를 `L5:SOCKET_RECV` 이벤트의 `dur` 필드로 산출합니다.
* **실행 명령어**:
  ```bash
  krayctl verify 1              # 검증 시나리오 1 메커니즘 및 해석 가이드 출력
  krayctl verify 1 --live       # 타겟 VM에서 L5 소켓 버퍼 체류 시간 라이브 트레이싱 실행
  krayctl trace -L 5            # L5 계층 단독 격리 관측
  ```

### 검증 2: I/O 모델 간 스레드 핸드오프 비용 검증 (Reactor Epoll → Worker Thread Pool)
* **검증 질문**: *"Epoll 이벤트 루프 스레드가 직접 요청을 처리할 때와, Futex/Condition Variable을 통해 워커 스레드 풀로 작업을 넘길 때(Netty EventLoop → ExecutorService 패턴) 스케줄러와 락 비용이 실제로 몇 마이크로초 발생하는가?"*
* **커널 계측 원리**: [`progs/tracer_l6_sched.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c)에서 [`pending_handoff_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L278)의 8-슬롯 락프리 링을 통해 리스너 스레드(`waker_tid`)가 워커 스레드(`tid`)로 `req_id`를 넘기는 과정을 추적하고, **Futex 락 대기 시간(`lock_wait_ns`) + OS 런큐 대기 시간(`runq_ns = t_switch - t_wakeup`) + 코어 간 마이그레이션(`prev_cpu_id` → `target_cpu_id`)**을 `L6:PRE_COMPUTE` 이벤트로 증명합니다.
* **실행 명령어**:
  ```bash
  krayctl verify 2              # 검증 시나리오 2 메커니즘 및 해석 가이드 출력
  krayctl verify 2 --live       # 타겟 VM에서 L6 스레드 핸드오프 및 런큐 지연 라이브 트레이싱 실행
  krayctl trace -L 6            # L6 스케줄러/Futex 계층 단독 격리 관측
  ```

### 검증 3: 순수 CPU 연산(On-CPU ALU) vs 스케줄러 기아(Off-CPU Preemption) 분리 검증
* **검증 질문**: *"특정 유저 함수가 30ms 걸렸을 때, 정말로 알고리즘 연산이 느린 것인가, 아니면 실행 도중 OS 스케줄러에 의해 CPU를 빼앗겼거나(Preemption) 락 대기로 잠든 것인가?"*
* **커널 계측 원리**: [`progs/tracer_l7_uprobe.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c)의 16단계 ALU Shadow Stack이 함수 진입/복귀 시각(`fn_dur`)을 기록하는 동시에, [`progs/tracer_l6_sched.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L205-L222)의 `sched_switch` 훅이 해당 스레드의 누적 Off-CPU 시간(`acc_off_cpu_ns`)을 스냅샷(`fn_off_cpu_snap`)으로 대조하여 순수 On-CPU 연산 시간과 Off-CPU 이탈 시간을 분리합니다.
* **실행 명령어**:
  ```bash
  krayctl verify 3              # 검증 시나리오 3 메커니즘 및 해석 가이드 출력
  krayctl verify 3 --live       # 타겟 VM에서 L7 Uprobe Shadow Stack 라이브 트레이싱 실행
  krayctl trace -L 7            # L7 유저 함수 계층 단독 격리 관측
  ```

### 검증 4: 커널-유저 메모리 복사(`skb_copy_datagram_iter`), 페이지 폴트 및 블록 I/O 귀속 검증
* **검증 질문**: *"대용량 페이로드 I/O 처리 중 발생하는 미세 지연이 커널→유저 버퍼 메모리 복사 때문인가, 아니면 그 과정에서 발생한 페이지 폴트(`handle_mm_fault`)와 디스크 I/O(`block_rq_*`) 때문인가?"*
* **커널 계측 원리**: [`progs/tracer_l5_syscall.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L143-L224)에서 `skb_copy_datagram_iovec`/`skb_copy_datagram_iter` 복사 구간 동안 발생하는 `handle_mm_fault` 횟수(`page_faults`)와 복사 바이트 수(`copied_bytes`), 그리고 [`block_rq_complete`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L501-L528)의 디스크 대기 시간을 해당 `req_id`의 `L5:SYSCALL_MEM` 이벤트에 패킹하여 출력합니다.
* **실행 명령어**:
  ```bash
  krayctl verify 4              # 검증 시나리오 4 메커니즘 및 해석 가이드 출력
  krayctl verify 4 --live       # 타겟 VM에서 L5 메모리 복사 및 페이지 폴트 라이브 트레이싱 실행
  krayctl trace -L 5 -j         # JSON 스트림으로 페이지 폴트/복사 바이트 정밀 확인
  ```

### 검증 5: 송신 완료의 착각(Egress Blindness) 및 요청 단위 패킷 드롭 사유(`kfree_skb`) 검증
* **검증 질문**: *"애플리케이션에서 `writeAndFlush()`/`send()`는 0.1ms 만에 성공했는데 클라이언트가 타임아웃을 겪을 때, 어느 요청(`req_id`)의 패킷이 커널 어디서 무슨 이유(`SKB_DROP_REASON_*`)로 드롭되었거나 재전송되었는가?"*
* **커널 계측 원리**: [`progs/tracer_l4_tcp.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L220-L374)에서 [`skb_egress_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L281)으로 송신 SKB 포인터를 추적하고, `tracepoint:skb:kfree_skb`(`reason > 2`) 및 `tracepoint:tcp:tcp_retransmit_skb` 발생 시 전체 서버 통계가 아닌 **해당 API 요청의 `req_id`와 워커 스레드 `tid`에 직접 드롭 사유 코드와 재전송 횟수를 매핑**합니다.
* **실행 명령어**:
  ```bash
  krayctl verify 5              # 검증 시나리오 5 메커니즘 및 해석 가이드 출력
  krayctl verify 5 --live       # 타겟 VM에서 L4 TCP 드롭 및 재전송 라이브 트레이싱 실행
  krayctl trace -L 4            # L4 TCP 전송/드롭/재전송 계층 단독 격리 관측
  ```

---

## 3. 휴먼 운영자 도구: krayctl 퀵스타트

POSIX IEEE Std 1003.1 및 GNU 유틸리티 아규먼트 벡터 명명 규격을 준수하는 전용 CLI 도구 [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl)을 제공합니다.
설치 후 어느 디렉터리에서나 `./` 접두사 없이 직접 `krayctl`로 실행할 수 있습니다.

### 시스템 전역 또는 사용자 PATH 설치
```bash
# 사용자 PATH(~/.local/bin)에 설치 (기본값)
./krayctl install

# 또는 Makefile로 설치
make install

# 도움말 및 버전 확인
krayctl --help
krayctl --version
```

### 주요 명령어
* **환경 상태 점검**:
  ```bash
  krayctl status
  ```
  타겟 VM 연결, 리눅스 커널 버전, BPF JIT 활성화(`bpf_jit_enable`), BTF(`vmlinux`), `/sys/fs/bpf` 마운트 상태를 즉시 진단합니다.

* **실환경 라이브 트레이싱 및 실무 프로덕션 진단 실행**:
  ```bash
  krayctl trace                                                     # 7계층 전체 종단간 트레이스 + 종료 시 자동 병목 판정([VERDICT])
  krayctl trace -L 4                                                # L4 TCP만 격리 (고빈도 L6 스케줄러 훅 6개는 커널에 미부착하여 오버헤드 차단)
  krayctl trace -L 7 -b ./mock_server -s execute_storage_query      # C++ 맹글링 함수(.symtab) 오프셋을 이름만으로 자동 해석하여 Uprobe 부착
  krayctl trace -L 7 -b ./libcrypto_mock.so -s verify_request_token # strip된 상용 공유 라이브러리(.so)의 .dynsym에서 심볼을 자동 해석하여 Uprobe 부착
  krayctl trace -m 100 -c 5 -d 3                                    # 100µs 미만 정상 패킷은 무시(-m 100)하고 스파이크 5건(-c 5)만 캡처 후 자동 탈착(-d 3)
  krayctl trace -j                                                  # 기계 판독용 순수 JSON 라인 스트림 출력 (jq 파이프라인 연동)
  ```
  타겟 VM에서 다중 스레드 `mock_server`를 실행하고, `tracer_daemon`을 커널 훅에 부착한 뒤, 실시간 HTTP 요청(`curl`)을 보내 L2부터 L7까지의 7계층 지연 시간을 실시간 컬러 스트림으로 출력하며 종료 시 **계층별 지연 요약표 및 1순위 병목 판정(`[VERDICT]`)**을 제공합니다.

* **22종 통신 프로토콜 및 IEEE 802 규격 인스펙터**:
  ```bash
  krayctl proto ports                # 포트 그룹별(Non-IP, 0..1023, 1024..49151, 동적) 체계적 분류
  krayctl proto ieee                 # IEEE 802.1/3/11/15 표준 심층 가이드
  krayctl proto inspect wifi         # Wi-Fi IEEE 802.11 MAC 프레임 비트 분석
  krayctl proto inspect bt           # Bluetooth IEEE 802.15.1 HCI/L2CAP 프레임 분석
  krayctl proto inspect nfs          # NFSv3/v4 RPC 스토리지 호출 프레임 분석
  krayctl proto inspect smb          # SMB2/SMB3 파일 공유 헤더 분석
  krayctl proto test                 # 22종 프로토콜 전수 비트 일치 자동 검증
  ```

* **업스트림 스타일 네이티브 셀프테스트 (7/7)**:
  ```bash
  krayctl selftest                   # 7개 계층 BPF 스켈레톤 전체 테스트
  krayctl selftest l4                # L4 TCP 스켈레톤만 단독 테스트
  ```

* **리눅스 네이티브 명령어 힌트 보기**:
  ```bash
  krayctl inspect
  ```
  `bpftool`, `ss`, `ip`, `curl` 등 표준 리눅스 도구로 eBPF 상태를 직접 들여다보는 명령어 모음을 출력합니다.

* **HTML 트레이스 대시보드 생성**:
  ```bash
  krayctl dashboard
  ```
  최신 트레이스 결과를 시각화한 [trace_dashboard.html](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/trace_dashboard.html)을 생성하고 브라우저로 엽니다.

* **CLI 아규먼트 벡터 규격 및 관례 레퍼런스**:
  - [references/cli-argument-standards-and-conventions.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md) 참조. POSIX Utility Guidelines 1~13, GNU Long Options, Subcommand Hierarchy 패턴, Exit Code 표준(sysexits.h) 총정리.

---

## 4. 7계층 관측 아키텍처

eBPF Wire-to-Code Tracer는 시스템의 지연 시간을 다음 7개 레이어로 나누어 계측합니다:

* **Layer 1/2: L2 NIC Ingress (DMA / XDP / Netif)**
  * 훅: `xdp_ingress_filter`, `tracepoint:net:netif_receive_skb`
  * 역할: 하드웨어 수신 직후 802.1Q/802.1ad VLAN 언래핑, 페이로드 유무 확인 및 64비트 고유 `req_id` 발급
* **Layer 3: L3 Kernel IP Routing & Netfilter**
  * 훅: `kprobe:ip_rcv`, `kprobe:ipv6_rcv`, `kprobe:icmp_rcv`, `kprobe:arp_rcv`
  * 역할: IP 라우팅 지연, IPv6 확장 헤더 파싱, Netfilter 인그레스 레이턴시 산출
* **Layer 4: L4 Transport & Sockets (TCP/UDP/AF_UNIX)**
  * 훅: `kprobe:tcp_v4_rcv`, `kprobe:tcp_v6_rcv`, `kprobe:udp_rcv`, `tracepoint:tcp:tcp_retransmit_skb`, `tracepoint:skb:kfree_skb`
  * 역할: TCP 핸드셰이크(SYN/ACK), 패킷 드롭 원인 코드(`reason`), 재전송 감지
* **Layer 5: L5 Syscall & Socket Queue & Memory Copy**
  * 훅: `kprobe:tcp_recvmsg`, `kretprobe:tcp_recvmsg`, `tracepoint:skb:skb_copy_datagram_iovec`, `kprobe:handle_mm_fault`, `tracepoint:block:block_rq_*`
  * 역할: 소켓 수신 버퍼 체류 시간(`sk_rcvbuf`), 유저 버퍼 복사 지연, 메이저/마이너 페이지 폴트, 블록 I/O 지연 측정
* **Layer 6: L6 Pre-Compute Gate (Futex & Scheduler Runqueue)**
  * 훅: `tracepoint:syscalls:sys_enter_futex`, `sys_exit_futex`, `tracepoint:sched:sched_waking`, `sched_wakeup`, `sched_switch`
  * 역할: 락 획득 대기 지연(Futex Lock Wait), 8-슬롯 락프리 링 기반 워커 스레드 핸드오프 추적, CPU 런큐 대기 지연(`runqlat`), 코어 간 마이그레이션 포착
* **Layer 7: L7 Application User Function Execution (ALU)**
  * 훅: `trace_uprobe_entry`, `trace_uprobe_return`
  * 역할: 스트립된 공유 라이브러리 오프셋 해석, 16단계 재귀 호출 보호 Shadow Stack, 트램펄린 주소 왜곡 방지 및 순수 연산 실행 시간 계측
* **Egress: L5/L4/L3/L2 Socket & Net Egress**
  * 훅: `kprobe:tcp_sendmsg`, `kprobe:__tcp_transmit_skb`, `kprobe:ip_output`, `tracepoint:net:net_dev_queue`, `net_dev_xmit`
  * 역할: 송신 버퍼 큐잉부터 네트워크 카드 직전 Qdisc 전송 완료까지의 역방향 파이프라인 지연 시간 완결

---

## 5. 리눅스 표준 명령어를 활용한 직접 점검 (Operator Cheatsheet)

타겟 머신(Rocky Linux 9.8)에 직접 SSH로 접속하거나 호스트 터미널에서 다음 명령어를 실행하여 커널 상태를 직접 확인할 수 있습니다.

### 1) bpftool로 커널 내부 BPF 프로그램 조회
```bash
# 로드된 모든 BPF 프로그램 목록 및 JIT 메모리 크기 조회
ssh ebpf-vm "sudo bpftool prog show"

# XDP 필터의 역어셈블리(JIT 어셈블리) 바이트코드 덤프
ssh ebpf-vm "sudo bpftool prog dump jited name xdp_ingress_filter"
```

### 2) BPF 맵 및 실시간 연결 상태 조회
```bash
# 로드된 맵(LRU Hash, RingBuf 등) 목록 확인
ssh ebpf-vm "sudo bpftool map show"

# 인그레스 플로우 추적 맵 내용 덤프 (활성 소켓 플로우 확인)
ssh ebpf-vm "sudo bpftool map dump name ingress_flow_map"

# 현재 스레드 컨텍스트 맵 내용 덤프
ssh ebpf-vm "sudo bpftool map dump name active_ctx_map"
```

### 3) 소켓 및 네트워크 인터페이스 점검
```bash
# 타겟 서버 포트(8080) 리스닝 상태 확인
ssh ebpf-vm "ss -tulpn | grep 8080"

# 루프백 인터페이스의 XDP 부착 상태 확인
ssh ebpf-vm "sudo bpftool net show"
ssh ebpf-vm "ip link show lo"
```

### 4) 수동 패킷 전송 및 커널 파이프 로그 확인
```bash
# 수동 HTTP 테스트 요청
ssh ebpf-vm "curl -i http://127.0.0.1:8080/compute?input=hello"

# 커널 printk 디버그 파이프 실시간 모니터링
ssh ebpf-vm "sudo cat /sys/kernel/debug/tracing/trace_pipe"
```

---

## 6. 모듈형 소스 코드 디렉터리 구조 (Modular Source Architecture)

사람과 개발자가 한눈에 읽고 유지보수할 수 있도록 모든 계층이 독립된 모듈로 분리되어 있으며, 불안정한 셸 스크립트(`.sh` 및 `/bin/sh`) 의존성을 완전히 제거하고 직접 프로세스 벡터(`execve` / `shell=False`) 기반으로 동작합니다.

| 영역 | 모듈 경로 | 핵심 책임 및 포함 기능 |
| :--- | :--- | :--- |
| **Kernel eBPF Micro-Modules** | [progs/kray_common.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h) | 공통 이벤트 구조체(`struct kray_event_t`), BPF 맵 정의, Kprobe 재진입 가드 및 링버퍼 헬퍼 |
| | [progs/tracer_l2_xdp.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c) | L2 XDP Ingress 필터, 802.1Q/802.1ad VLAN 파싱, `req_id` 채번 및 TCP RST 즉시 퇴거 |
| | [progs/tracer_l3_ip.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l3_ip.bpf.c) | L3 IPv4/IPv6 라우팅, 확장 헤더 언롤링, ICMP/ARP 및 단편화(Fragment) 감지 |
| | [progs/tracer_l4_tcp.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c) | L4 TCP/UDP/AF_UNIX 상태 추적, `kfree_skb` 드롭 사유 및 `tcp_retransmit_skb` 매핑 |
| | [progs/tracer_l5_syscall.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c) | L5 `sk_rcvbuf` 체류 시간(`dwell_ns`), 유저 버퍼 복사(`skb_copy_datagram_iter`), 페이지 폴트 및 블록 I/O |
| | [progs/tracer_l6_sched.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c) | L6 8-슬롯 락프리 스레드 핸드오프 링, Futex 대기 시간, OS 런큐 지연(`runqlat`) 및 코어 마이그레이션 |
| | [progs/tracer_l7_uprobe.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c) | L7 16단계 ALU Shadow Stack, Uretprobe 트램펄린 IP 복원, 적응형 속도 제한(10k/s) |
| | [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c) | 46개 커널 훅이 통합된 단일 컴포짓 BPF 소스 (통합 스켈레톤 및 정적 검증용) |
| **Userspace C Daemon Modules** | [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c) | 경량 C 데몬 엔트리포인트 (`getopt_long` 옵션 파서, BPF Skeleton 로드 및 이벤트 루프) |
| | [daemon/daemon_types.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_types.h) | 데몬 런타임 설정 구조체(`struct daemon_cfg`), 원자적 시퀀스/드롭 카운터, 시그널 핸들러 |
| | [daemon/daemon_preflight.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h) | 커널 BTF/BPFFS/권한 사전 점검, Cgroups v2 메모리 헤드룸(`<64MB`) 가드, ELF 심볼 검사 |
| | [daemon/daemon_sweeper.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_sweeper.h) | `SIGKILL` 고아 XDP 자동 청소(`flush_orphan_xdp`) 및 30초 TTL 유휴 플로우 스위퍼(`sweep_stale_flows`) |
| | [daemon/daemon_formatter.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h) | ARM64 `dmb ishld` 메모리 펜스, 링버퍼 이벤트 포매터(ANSI 컬러 터미널 `stdout` / 배너 `stderr` / 순수 JSON Lines `stdout`) |
| **Python Control Plane (`Zero-.sh`)** | [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl) | POSIX/TLPI 규격 준수 CLI 엔트리포인트 (`shell=False` 기반 프로세스 제어기) |
| | [kray/help_docs.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/help_docs.py) | 모든 서브커맨드(`status`, `verify`, `test`, `trace`, `proto`, `selftest`, `install`) 도움말 및 치트시트 |
| | [kray/verify_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/verify_scenarios.py) | 5대 실전 아키텍처 검증 시나리오(`krayctl verify [list\|1..5]`) 블루프린트 및 라이브 실행기 |
| | [kray/host_ops.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/host_ops.py) | 호스트-타겟 VM 간 `rsync` 동기화(`sync`), 원격 빌드/트레이스/전체 테스트(`run-all`, `claims`) 오케스트레이터 |
| | [kray/remote_target.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py) | 타겟 리눅스 VM 내부에서 `/bin/sh` 없이 직접 실행되는 네이티브 빌드·셀프테스트·실증 검증 엔진 |
| **Dissector & Test Harnesses** | [test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c) | 리눅스 업스트림 스타일 네이티브 C 테스트 러너 (7개 스켈레톤 자동 검증) |
| | [kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py) | 22종 프로토콜 비트 단위 파서 및 242종 퍼징 방어 엔진 |
| | [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py) | 파이썬 사용자 공간 에이전트, AI 진단, REST API, 웹 대시보드 |
| | [test_all_command_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_all_command_scenarios.py) | 110개 CLI 명령어 시나리오(멱등성·실패 복구·격리·문서 정합성·프로덕션 실무 가드 포함) 전수 검증 스위트 |
| | [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) | 24개 아키텍처 통합 검증 스위트 (12개 기본 + 12개 심화) |

---

## 7. 라이선스

이 프로젝트의 eBPF 커널 프로그램 및 호환 레이어는 GNU General Public License v2.0 (GPL-2.0)에 따라 라이선스가 부여됩니다. 사용자 공간 에이전트 및 CLI 도구는 MIT 라이선스를 따릅니다. 자세한 내용은 [LICENSING.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)를 참조하십시오.

---

# [Book II] UTM 하이퍼바이저 명세, Rocky Linux 9.8 설치·실행 방법 및 커널 소스코드 가이드

## 1. 사용한 UTM 하이퍼바이저 및 가상머신 하드웨어·네트워크 상세 명세

본 프로젝트의 타겟 리눅스 환경은 macOS Apple Silicon(M-시리즈 ARM64) 호스트 위에서 **UTM (`v4.7.5`, Build `118`)**의 **Apple Virtualization.framework (`Apple Virtualization Generic Platform`)** 네이티브 하이퍼바이저 백엔드로 구동됩니다. QEMU 소프트웨어 에뮬레이션과 달리 CPU 명령어 변환 오버헤드가 전혀 없으며, 하드웨어 ARMv8.1-A LSE 원자적 명령어(`dmb ishld`, `casal`)와 VirtIO 네트워크/블록 디바이스가 네이티브 속도로 동작합니다.

| 구분 | 항목 | 실제 설정 및 확인 값 (Live Verified Value) | 확인 명령어 |
| :--- | :--- | :--- | :--- |
| **UTM 하이퍼바이저** | 앱 경로 및 버전 | `/Applications/UTM.app` — **UTM `v4.7.5` (Build `118`)** | `defaults read /Applications/UTM.app/Contents/Info.plist CFBundleShortVersionString` |
| | CLI 제어 도구 | `/Applications/UTM.app/Contents/MacOS/utmctl` | `/Applications/UTM.app/Contents/MacOS/utmctl --help` |
| | 가상화 엔진 백엔드 | **`Apple Virtualization.framework`** (`Apple Inc. / Apple Virtualization Generic Platform`) | `ssh ebpf-vm "cat /sys/devices/virtual/dmi/id/sys_vendor /sys/devices/virtual/dmi/id/product_name"` |
| **가상머신 식별자** | UTM VM 이름 | `ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1` | `/Applications/UTM.app/Contents/MacOS/utmctl list` |
| | UTM VM UUID / 상태 | `16D7A5BA-5FF8-48DA-AA00-043C3D855974` / **`started` (실가동 중)** | `/Applications/UTM.app/Contents/MacOS/utmctl status 16D7A5BA-5FF8-48DA-AA00-043C3D855974` |
| **하드웨어 리소스** | vCPU 코어 | **4 vCPU** (`aarch64`, NUMA node0 CPU 0~3) | `ssh ebpf-vm "lscpu"` |
| | 시스템 메모리 (RAM) | **4.5 GiB** (`4608 MB`, 가용 `4.1 GiB`, Swap `0B`) | `ssh ebpf-vm "free -h"` |
| | 루트 디스크 스토리지 | **40 GiB VirtIO Block Device** (`/dev/vda3`, 사용량 `13G / 39G (31%)`) | `ssh ebpf-vm "df -h /"` |
| **네트워크 및 SSH** | 네트워크 모드 / NIC | Apple `vmnet` Shared Network (`192.168.64.0/24`) / VirtIO-Net `eth0` & 루프백 `lo` | `ssh ebpf-vm "ip -br addr"` |
| | 게스트 IP / SSH 별칭 | **`192.168.64.14`** / 호스트 SSH 별칭 **`ebpf-vm`** (포트 `22`, 유저 `rocky`, 키 `~/.ssh/rocky-dev_ed25519`) | `ssh -G ebpf-vm` |
| **게스트 OS 및 커널** | 배포판 릴리스 | **`Rocky Linux release 9.8 (Blue Onyx)`** | `ssh ebpf-vm "cat /etc/redhat-release"` |
| | 커널 버전 (`uname -r`) | **`5.14.0-687.10.1.el9_8.0.1.aarch64`** | `ssh ebpf-vm "uname -r"` |
| | 커널 빌드 시그니처 | `Linux version 5.14.0-687.10.1.el9_8.0.1.aarch64 (mockbuild@iad1-prod-build-aarch001.bld.equ.rockylinux.org) (gcc (GCC) 11.5.0 20240719 (Red Hat 11.5.0-14), GNU ld version 2.35.2-72.el9) #1 SMP PREEMPT_DYNAMIC` | `ssh ebpf-vm "cat /proc/version"` |
| | 원천 소스 RPM | **`kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm`** | `ssh ebpf-vm "rpm -qi kernel-core-5.14.0-687.10.1.el9_8.0.1.aarch64"` |

---

## 2. UTM 가상머신 및 리눅스 환경 실행·제어 방법 (How to Run & Control the VM)

### 1) `utmctl`을 이용한 VM 시작·정지·상태 확인 (macOS 호스트 터미널)
```bash
# 1. 등록된 모든 UTM 가상머신 목록 및 현재 가동 상태(started / stopped) 확인
/Applications/UTM.app/Contents/MacOS/utmctl list

# 2. 타겟 Rocky Linux 9.8 VM이 꺼져 있을 때 백그라운드/GUI로 부팅(시작)하기
/Applications/UTM.app/Contents/MacOS/utmctl start 16D7A5BA-5FF8-48DA-AA00-043C3D855974
# (또는 이름으로 시작)
/Applications/UTM.app/Contents/MacOS/utmctl start "ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1"

# 3. 타겟 VM 상태 단건 조회
/Applications/UTM.app/Contents/MacOS/utmctl status 16D7A5BA-5FF8-48DA-AA00-043C3D855974

# 4. 타겟 VM 정상 종료 또는 정지
/Applications/UTM.app/Contents/MacOS/utmctl stop 16D7A5BA-5FF8-48DA-AA00-043C3D855974
```
> **참고 (Apple Virtualization 백엔드의 IP 확인법)**: Apple Virtualization 백엔드 VM은 QEMU Guest Agent를 쓰지 않으므로 `utmctl ip-address` 대신 macOS 내장 DHCP 리스 파일(`cat /var/db/dhcpd_leases`) 또는 `arp -an | grep 192.168.64`로 할당된 IP(`192.168.64.14`)를 즉시 확인할 수 있습니다.

### 2) 호스트 SSH 설정 (`~/.ssh/config`) 및 리눅스 셸 접속 방법
macOS 호스트의 `~/.ssh/config`에 다음과 같이 `ebpf-vm` 호스트 별칭이 등록되어 있어 비밀번호 입력 없이 즉시 접속 및 원격 제어가 가능합니다:
```sshconfig
Host ebpf-vm
    HostName 192.168.64.14
    User rocky
    Port 22
    IdentityFile ~/.ssh/rocky-dev_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
```
```bash
# 대화형 리눅스 셸 접속
ssh ebpf-vm

# 원격 명령어 단건 실행 (예: 커널 및 BPF 상태 확인)
ssh ebpf-vm "uname -a && sudo bpftool prog show"
```

### 3) [`krayctl`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl)을 통한 원클릭 리눅스 커널 빌드·트레이싱·검증 실행 방법
VM이 켜진 상태에서 호스트 터미널(macOS)에서 [`./krayctl`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl)을 실행하면 `rsync` 동기화부터 리눅스 커널 내 BPF 컴파일·부착·검증까지 자동으로 수행됩니다:
```bash
./krayctl status             # 1. VM 연결 상태, 커널 5.14.0-687.10.1, BTF, BPF JIT, Cgroups v2 진단
./krayctl sync               # 2. 로컬 소스 코드를 VM(~/ebpf-wire-to-code-tracer)으로 멱등 동기화
./krayctl build              # 3. VM 내부에서 7계층 BPF 오브젝트(*.bpf.o), 스켈레톤(*.skel.h), tracer_daemon 빌드
./krayctl selftest           # 4. VM 커널에 7개 BPF 스켈레톤을 실제 로드하여 7/7 셀프테스트 수행
./krayctl trace              # 5. VM에서 mock_server 기동 + 7계층 eBPF 부착 + 실시간 HTTP 트래픽 추적
./krayctl trace -L 5 -j      # 6. 특정 계층(L5)만 격리하여 순수 JSON Lines 스트림으로 수집
./krayctl verify list        # 7. 고수준 언어 I/O 사각지대 및 5대 실전 검증 시나리오 목록 확인
./krayctl verify 1 --live    # 8. 시나리오 1~5 중 원하는 시나리오를 VM 커널에서 실시간 실행
./krayctl claims             # 9. 6대 하드웨어(ARM64 dmb ishld)·커널 BTF·라이브 BPF 로드 실증 검증
./krayctl run-all            # 10. 7대 전체 테스트 스위트(CLI 표준, 105개 시나리오, 실패킷 23종 등) 일괄 실행
```

---

## 3. UTM 및 Rocky Linux 9.8 aarch64 처음부터 설치·프로비저닝하는 전체 절차 (Clean Installation Guide)

동일한 개발·검증용 리눅스 VM 환경을 다른 Mac이나 새로운 UTM 인스턴스에 처음부터 구축할 때의 단계별 절차입니다.

### Step 1: macOS에 UTM 설치 및 Rocky Linux 9.8 aarch64 ISO 준비
```bash
# Homebrew로 UTM 설치 (또는 https://mac.getutm.app 에서 v4.7.5 다운로드)
brew install --cask utm

# Rocky Linux 9.8 aarch64 Minimal ISO 공식 다운로드
curl -LO https://dl.rockylinux.org/pub/rocky/9.8/isos/aarch64/Rocky-9.8-aarch64-minimal.iso
```

### Step 2: UTM에서 Apple Virtualization 기반 VM 생성
1. UTM 실행 → **`Create a New Virtual Machine`** 클릭 → **`Virtualize`** (네이티브 하이퍼바이저, 속도 최상) 선택.
2. Operating System에서 **`Linux`** 선택 → **`Use Apple Virtualization`** 체크 활성화.
3. Boot ISO Image에 다운로드한 `Rocky-9.8-aarch64-minimal.iso` 지정.
4. Hardware 설정:
   * **Memory**: `4608 MB` (4.5 GiB 이상 권장)
   * **CPU Cores**: `4 Cores`
5. Storage 설정: **`40 GiB`** 지정.
6. Network 설정: **`Shared Network`** (`192.168.64.0/24` 대역 자동 할당).
7. VM 이름을 `ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1`로 저장 후 부팅하여 Rocky Linux 9.8 설치 진행 (사용자 계정 `rocky` 생성 및 Administrator 권한 체크).
8. 설치 완료 후 UTM 설정에서 ISO 이미지를 Eject하고 재부팅.

### Step 3: 게스트 리눅스 SSH 키 등록 및 무비밀번호 `sudo` 설정
```bash
# 1. VM 내부에서 패스워드 없이 sudo가 동작하도록 wheel 그룹 NOPASSWD 설정 (VM 콘솔에서 1회 실행)
echo "%wheel ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/99-wheel-nopasswd

# 2. 호스트 Mac에서 SSH 키 복사 및 ~/.ssh/config 에 ebpf-vm 등록
ssh-copy-id -i ~/.ssh/rocky-dev_ed25519.pub rocky@192.168.64.14
```

### Step 4: eBPF 컴파일 및 커널 트레이싱 필수 패키지 14종 설치
타겟 VM(`ebpf-vm`)에 설치된 정확한 패키지 목록과 버전, 그리고 설치 명령어입니다:
```bash
ssh ebpf-vm "sudo dnf install -y \
    kernel-core-5.14.0-687.10.1.el9_8.0.1 \
    kernel-devel-5.14.0-687.10.1.el9_8.0.1 \
    clang llvm bpftool libbpf libbpf-devel \
    elfutils-libelf-devel zlib-devel \
    gcc gcc-c++ make rsync python3 iproute curl psmisc"
```

| 패키지 이름 | 타겟 VM 설치 버전 (`rpm -q`) | 용도 |
| :--- | :--- | :--- |
| `kernel-core` | `5.14.0-687.10.1.el9_8.0.1.aarch64` | Rocky Linux 9.8 커널 이미지 및 `/sys/kernel/btf/vmlinux` 제공 |
| `kernel-devel` | `5.14.0-687.10.1.el9_8.0.1.aarch64` | 커널 모듈 및 eBPF 빌드를 위한 커널 헤더 트리 |
| `clang` / `llvm` | `21.1.8-2.el9.aarch64` | `-target bpf -D__TARGET_arch_arm64 -mcpu=v3` eBPF 바이트코드 컴파일러 |
| `bpftool` | `7.5.0-804.el9.0.1.aarch64` | `bpftool btf dump` (`vmlinux.h` 생성), `bpftool gen skeleton` (`*.skel.h`), 실시간 맵/프로그램 덤프 |
| `libbpf` / `libbpf-devel` | `1.5.0-3.el9.aarch64` | CO-RE 재배치, RingBuffer 폴링, XDP/Kprobe/Tracepoint/Uprobe 부착 라이브러리 |
| `elfutils-libelf-devel` / `zlib-devel` | `0.194-1.el9` / `1.2.11-40.el9` | ELF 바이너리 섹션(`.symtab` 스트립 여부) 검사 및 BTF 압축 해제 |
| `gcc` / `gcc-c++` / `make` | `11.5.0-14.el9` / `4.3-8.el9` | `tracer_daemon`, `test_progs`, `mock_server`, `libcrypto_mock.so` 네이티브 빌드 |
| `rsync` / `python3` | `3.2.7-1.el9_8` / `3.9.25-7.el9_8.6` | 호스트-VM 간 고속 소스 동기화 및 무셸(`Zero-.sh`) 원격 실행 엔진([`kray/remote_target.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py)) 구동 |

### Step 5: 커널 eBPF 런타임 파라미터(BTF · BPF JIT · BPFFS) 활성화 검증
```bash
# BPF JIT 컴파일러 활성화 확인 (기본값 1)
ssh ebpf-vm "sudo sysctl -w net.core.bpf_jit_enable=1"

# BTF(vmlinux) 및 BPFFS(/sys/fs/bpf) 마운트 상태 최종 확인
./krayctl status
```

---

## 4. Rocky Linux 9.8 커널(`5.14.0-687.10.1.el9_8.0.1`) 소스코드 다운로드 링크 및 방법

이 VM에서 실행 중인 커널(`5.14.0-687.10.1.el9_8.0.1`)의 전체 C 소스코드는 아래 **4가지 경로**로 즉시 다운로드하거나 열람할 수 있습니다:

### 방법 1: 공식 Rocky Linux 9.8 Source RPM (`src.rpm`) 직접 다운로드 링크
* **글로벌 공식 아카이브 직링크 (`dl.rockylinux.org`)**:
  * [https://dl.rockylinux.org/pub/rocky/9.8/BaseOS/source/tree/Packages/k/kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm](https://dl.rockylinux.org/pub/rocky/9.8/BaseOS/source/tree/Packages/k/kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm)
* **한국 공식 미러 직링크 (`mirror.krfoss.org`, VM에서 `dnf download --url --source`로 확인된 미러)**:
  * [https://mirror.krfoss.org/rocky/9.8/BaseOS/source/tree/Packages/k/kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm](https://mirror.krfoss.org/rocky/9.8/BaseOS/source/tree/Packages/k/kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm)
* **Source Tree 디렉터리 인덱스**:
  * [https://dl.rockylinux.org/pub/rocky/9.8/BaseOS/source/tree/Packages/k/](https://dl.rockylinux.org/pub/rocky/9.8/BaseOS/source/tree/Packages/k/)

### 방법 2: Rocky Linux 공식 Git 저장소 (`git.rockylinux.org`)
* **Rocky Linux 9 커널 RPM Dist-Git 저장소**:
  * [https://git.rockylinux.org/staging/rpms/kernel/-/tree/r9](https://git.rockylinux.org/staging/rpms/kernel/-/tree/r9)

### 방법 3: 타겟 VM(`ebpf-vm`) 내부에서 `dnf`로 즉시 다운로드 및 압축 해제
```bash
# 1. URL만 조회하기
ssh ebpf-vm "dnf download --url --source kernel-5.14.0-687.10.1.el9_8.0.1"

# 2. src.rpm 패키지 직접 다운로드 및 소스 트리 압축 해제
ssh ebpf-vm "dnf download --source kernel-5.14.0-687.10.1.el9_8.0.1 && rpm2cpio kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm | cpio -idmv"
```

### 방법 4: 현재 로컬 프로젝트 워크스페이스 내 이미 다운로드·추출된 커널 소스 경로
본 저장소의 `references/` 하위에는 위 `kernel-5.14.0-687.10.1.el9_8.0.1.src.rpm`에서 추출한 실제 커널 소스 트리와 BTF 헤더가 이미 포함되어 있어 별도 다운로드 없이도 바로 열어볼 수 있습니다:
* **커널 소스 루트 디렉터리**: [references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8)
  * 네트워크 코어 (`netif_receive_skb`, `net_dev_xmit`): [net/core/dev.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c)
  * TCP 스택 (`tcp_recvmsg`, `tcp_sendmsg`): [net/ipv4/tcp.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c)
  * TCP IPv4 수신 (`tcp_v4_rcv`): [net/ipv4/tcp_ipv4.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c)
  * 스케줄러 코어 (`sched_wakeup`, `sched_switch`): [kernel/sched/core.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/kernel/sched/core.c)
  * ARM64 BPF JIT 컴파일러: [arch/arm64/net/bpf_jit_comp.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/arch/arm64/net/bpf_jit_comp.c)
* **추출된 BTF 및 `vmlinux.h` 헤더 디렉터리**: [references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers)

---

## 5. 타겟 VM 리눅스 커널 내부 4단계 실증 검증 메커니즘 (How Verification Works Inside the VM Kernel)

본 프로젝트의 모든 검증 스위트(`krayctl selftest`, `krayctl verify`, `krayctl claims`, `test_all_command_scenarios.py`, `test_verification_suite.py`)는 가짜 모의 객체(Mocking)나 단순 문자열 시뮬레이션이 아니라, UTM(`Apple Virtualization.framework`) 위에서 실가동 중인 **Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) 리눅스 커널 내부**에 BPF 바이트코드를 직접 주입하고 실제 패킷을 통과시키는 **4단계 물리적 커널 검증 파이프라인**으로 수행됩니다.

```mermaid
flowchart TD
    A["1단계: 커널 eBPF Verifier 수학적 증명 & ARM64 JIT 컴파일<br/>(sys_bpf: BPF_PROG_LOAD + /sys/kernel/btf/vmlinux)"] --> B["2단계: 실제 커널 심볼·트레이스포인트·XDP·Uprobe 실장착<br/>(perf_event_open / bpf_link_create / bpf_xdp_attach)"]
    B --> C["3단계: 실제 소켓 트래픽 주입 및 커널 BPF 맵 코릴레이션<br/>(mock_server + libcrypto_mock.so + curl / Raw Socket)"]
    C --> D["4단계: BPF 링버퍼(events) 수거 및 자동 어설션 판정<br/>(ARM64 dmb ishld -> stdout/stderr -> Python assert)"]
```

### ① 1단계: 커널 eBPF Verifier 정적 수학 증명 및 ARM64 JIT 기계어 컴파일 (`BPF_PROG_LOAD`)
* **실행 주체**: [test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c) (`./krayctl selftest`) 및 [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c)
* **커널 내부 동작**:
  1. Clang(`-target bpf -D__TARGET_ARCH_arm64`)으로 컴파일된 6개 계층별 마이크로 모듈([`progs/tracer_l2_xdp.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c) ~ [`progs/tracer_l7_uprobe.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c))과 통합 모듈([`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c))을 `bpf(BPF_PROG_LOAD)` 시스템 콜로 리눅스 커널에 로드합니다.
  2. 커널 내부의 **eBPF Verifier ([`kernel/bpf/verifier.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/kernel/bpf/verifier.c))**가 `/sys/kernel/btf/vmlinux`(`5,926,489` bytes) 타입 정보와 대조하여 **널 포인터 역참조 여부, 512바이트 스택 한도 준수 여부(`zero_ctx_map` Per-CPU 힙 할당), 유한 루프 종료 여부(`#pragma unroll`), 헬퍼 함수 인자 타입 일치 여부**를 모든 분기 경로에 대해 수학적으로 증명합니다.
  3. 검증을 통과한 바이트코드는 **ARM64 BPF JIT 컴파일러 ([`arch/arm64/net/bpf_jit_comp.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/arch/arm64/net/bpf_jit_comp.c))**에 의해 네이티브 ARM64 기계어로 변환됩니다. 커널 구조체 필드나 함수 시그니처가 하나라도 실제 커널과 다르면 이 단계에서 커널이 로드를 즉시 거부(`-EINVAL` / `-EACCES`)하므로 거짓 통과가 원천 불가능합니다.

### ② 2단계: 실제 커널 함수(Kprobe/Tracepoint/XDP) 및 ELF 오프셋(Uprobe) 실장착
* **실행 주체**: [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L285-L368) 및 [daemon/daemon_preflight.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L155-L246)
* **커널 내부 동작**:
  1. `bpf_program__attach()`(`perf_event_open` 및 `BPF_LINK_CREATE`)를 호출하여 실제 커널 심볼([`ip_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L549-L569), [`tcp_v4_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L2040-L2150), [`tcp_recvmsg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2513-L2547), `handle_mm_fault`)과 커널 트레이스포인트(`netif_receive_skb`, `kfree_skb`, `sched_wakeup`, `sched_switch`), 그리고 루프백 인터페이스(`lo`)의 XDP 훅(`bpf_xdp_attach`)에 프로브를 직접 장착합니다.
  2. `-L <2..7>` 선택적 계층 격리 지정 시에는 불필요한 고빈도 L6 스케줄러/Futex 커널 훅 6개의 장착을 건너뛰어(`Selective Layer Isolation`) 프로덕션 커널 오버헤드를 차단합니다.
  3. 유저 공간 바이너리([`mock_server.cpp`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp) 및 스트립된 공유 라이브러리 [`libcrypto_mock.cpp`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/libcrypto_mock.cpp))에 대해서는 `resolve_elf_symbol_offset()`이 `libelf`/`gelf`로 `.symtab` 및 `.dynsym` 섹션을 스캔하여 산출한 파일 오프셋(`0x28ac`, `0x6e4`)을 `bpf_program__attach_uprobe()`로 커널 `uprobe` 서브시스템에 등록합니다.

### ③ 3단계: 실제 소켓 트래픽 발생 및 커널 내부 타임스탬프·요청 ID(`req_id`) 코릴레이션
* **실행 주체**: [kray/remote_target.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py#L146-L204) 및 [test_live_packets.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_live_packets.py)
* **커널 내부 동작**:
  1. 타겟 VM 내부에서 실제 멀티스레드 C++ 서버(`mock_server` — Acceptor 스레드 + Futex 조건변수 큐 + Worker 스레드 풀 + `dlopen("libcrypto_mock.so")`)를 구동하고, `curl` 및 Raw/UDP/ICMP/AF_UNIX 소켓으로 실제 패킷을 루프백(`lo`) 네트워크 스택에 전송합니다.
  2. 패킷이 커널 네트워크 스택을 통과할 때마다 각 계층의 BPF 프로그램이 실행되어 `bpf_ktime_get_ns()`로 나노초 타임스탬프를 기록하고, 커널 내부 LRU 해시맵([`ingress_flow_map` -> `pending_handoff_map` -> `active_ctx_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L274-L285))을 통해 **동일한 64비트 `req_id`**를 L2 NIC 진입부터 L7 공유 라이브러리 C 함수 반환(`uretprobe`)까지 바통 터치하며 64바이트 바이너리 이벤트(`struct kray_event_t`)를 커널 BPF 링버퍼(`events`)로 방출합니다.

### ④ 4단계: BPF 링버퍼 수거, 자동 병목 판정(`[VERDICT]`) 및 테스트 어설션 검증
* **실행 주체**: [daemon/daemon_formatter.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h#L65-L308) 및 [test_all_command_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_all_command_scenarios.py)
* **검증 방식**:
  1. 유저 공간 C 데몬이 ARM64 약한 메모리 순서 방어 배리어(`__atomic_thread_fence(__ATOMIC_ACQUIRE)` / `dmb ishld`)를 거쳐 링버퍼에서 이벤트를 수거하고, 종료 시 계층별 지연 통계(`s_layer_stats[L2..L7]`)와 1순위 병목 계층(`[VERDICT] Primary Bottleneck:`)을 산출합니다.
  2. 파이썬 테스트 스위트가 데몬의 `stdout`(순수 JSON 또는 ANSI 이벤트 스트림), `stderr`(사전 점검 경고, 심볼 해석 오프셋, 병목 판정 요약표), 프로세스 종료 코드(`<sysexits.h>` `0, 2, 64, 65, 69, 77`)를 캡처하여 110개 시나리오의 기대값과 `assertEqual` / `assertIn`으로 엄격히 대조합니다.

| 검증 명령어 / 테스트 스위트 | 타겟 VM 커널 내부에서 실제로 검증하는 항목 | 검증 결과 |
| :--- | :--- | :---: |
| `./krayctl selftest` ([test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c)) | 6개 계층별 마이크로 BPF 스켈레톤 + 1개 통합 스켈레톤(46개 훅)의 커널 Verifier 로드 및 커널 심볼 부착 | **7/7 PASS** |
| `./krayctl verify [1..5] --live` ([kray/verify_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/verify_scenarios.py)) | 5대 실전 사각지대(`sk_rcvbuf` 체류, Futex/런큐 핸드오프, On-CPU vs Off-CPU, 페이지 폴트, `kfree_skb` 드롭) 라이브 패킷 실측 및 `[VERDICT]` 판정 | **5/5 PASS** |
| `./krayctl claims` ([kray/remote_target.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py#L214-L300)) | (1) Rocky 9.8 커널 확인, (2) `objdump -d` 내 ARM64 `dmb ishld` 명령어 확인, (3) 7/7 스켈레톤 로드, (4) XDP Generic SKB 폴백, (5) Cgroups v2 가드, (6) 라이브 트래픽 코릴레이션 | **6/6 PASS** |
| `python3 test_all_command_scenarios.py` | 110개 CLI 시나리오 (POSIX/TLPI 옵션 파싱, `SIGKILL` 고아 XDP 자동 복구, JSON 스트림 순수성, `.symtab`/`.dynsym` 자동 해석, `-L` 훅 격리, `-c`/`-d` 자동 탈착, 문서 링크 전수 검사) | **110/110 PASS** |
| `python3 test_verification_suite.py` | 24개 아키텍처 불변식 + 22종 프로토콜 비트 파서(242종 퍼징) + 23개 라이브 커널 네트워크 패킷 송수신 테스트 | **100% PASS** |


---

# [Book III] 아키텍처 및 레이어별 설계 명세서 (Architecture & Design Specification)

# eBPF Wire-to-Code Tracer — Architecture & Design Specification

> Grounded in Linux Kernel Upstream (`tools/testing/selftests/bpf`), Modern BPF CO-RE (`libbpf-bootstrap`), and Production Tracers (`bcc`, `beyla`, `coroot`, `bpftrace`).
> Target: Rocky Linux 9.8 aarch64 & x86_64 (`5.14.0-687.10.1.el9_8.0.1.aarch64`)

---

## 1. 아키텍처 개요 및 존재 이유 (System Architecture & Purpose)

전통적인 APM(Application Performance Monitoring)이나 네트워크 패킷 캡처 도구는 각각의 영역에만 국한되어 있습니다. Wireshark/tcpdump는 네트워크 패킷(L2-L4)만 보고, 프로파일러(pprof, async-profiler, JFR)는 유저 애플리케이션(L7)의 스택만 봅니다.

특히 **Java(NIO, Netty, Virtual Thread), Go(Goroutine, netpoll), Node.js(libuv), Rust(Tokio)** 등 언어 차원에서 제공하는 고수준 I/O API는 **유저 공간의 시스템 콜 경계(`epoll_wait`, `read`, `write`) 안쪽에서만 시계를 작동**시킵니다:
1. **수신 대기 사각지대 (Ingress Blindness)**: 패킷이 물리 NIC(L2)와 커널 TCP 스택(L4)에 이미 도착했더라도, JVM GC(Stop-The-World)나 이벤트 루프 포화로 인해 애플리케이션이 `recvmsg()`를 늦게 호출하면 소켓 수신 버퍼(`sk_rcvbuf`)에서 수십 ms가 흘러갑니다. 언어 레벨 I/O API는 `recvmsg()`가 호출된 시점부터 요청이 시작됐다고 기록하므로 이 대기 시간을 전혀 감지하지 못합니다.
2. **스레드 핸드오프 및 스케줄러 사각지대**: 리스너 스레드가 워커 스레드 풀로 작업을 넘길 때(`ExecutorService`, 채널 등) 발생하는 `futex` 락 대기, OS 스케줄러 런큐 대기(`runqlat`), 그리고 CPU 코어 간 마이그레이션(L1/L2 캐시 냉각)은 애플리케이션 코드 상에서 보이지 않습니다.
3. **함수 실행 중 Off-CPU 착시**: 특정 비즈니스 함수가 30ms 걸렸을 때, 실제로는 순수 CPU ALU 연산이 1ms이고 나머지 29ms가 커널 메모리 복사 중 페이지 폴트(`handle_mm_fault`), 블록 I/O 대기(`block_rq_issue` → `block_rq_complete`), 또는 스케줄러 선점(`sched_switch`) 때문임에도 고수준 프로파일러는 이를 구분하지 못합니다.
4. **송신 완료의 착각 (Egress Blindness)**: `writeAndFlush()`나 `send()`는 유저 버퍼를 커널 송신 버퍼(`sk_sndbuf`)에 복사하기만 하면 즉시 성공으로 반환됩니다. 그 직후 커널 내부에서 발생하는 Qdisc 큐잉 지연, 패킷 드롭(`kfree_skb`), TCP 재전송(`tcp_retransmit_skb`)은 애플리케이션 로그에 남지 않습니다.

eBPF Wire-to-Code Tracer(`kray`)는 물리 NIC 수신부터 CPU ALU 연산 완료 및 물리 송신까지의 7개 계층을 관통하며, 다음과 같은 상태 머신을 통해 각 단계를 동일한 64비트 Request ID(`req_id`)로 연결하여 위 4가지 사각지대를 나노초 단위로 규명합니다.

```
[Layer 1/2: Ingress NIC]
   XDP / Netif DMA -> 802.1Q VLAN -> Mint req_id -> ingress_flow_map
          |
[Layer 3: Kernel IP]
   kprobe:ip_rcv / ipv6_rcv -> Netfilter Ingress
          |
[Layer 4: Kernel Transport]
   kprobe:tcp_v4_rcv / udp_rcv -> State Check (SYN/ACK/Drop)
          |
[Layer 5: Socket & Syscall]
   kprobe:tcp_recvmsg -> sk_rcvbuf dwell -> skb_copy_datagram_iovec (MM)
          | (Active Context Binding to active_ctx_map[tid])
[Layer 6: Pre-Compute Gate]
   sys_enter_futex -> 8-Slot Ring -> sched_waking -> sched_switch (Runqueue Latency)
          | (Worker Context Handed Off)
[Layer 7: User App ALU]
   Uprobe entry -> Shadow Stack (depth 0..15) -> Stripped .so -> Uretprobe return
          |
[Egress Pipeline]
   tcp_sendmsg -> __tcp_transmit_skb -> ip_output -> net_dev_queue -> net_dev_xmit
```

---

## 2. 레이어별 세부 메커니즘 및 훅 명세

### Layer 1/2: L2 NIC Ingress (OSI_L2_DATALINK = 2)
* **주요 훅**: `SEC("xdp") xdp_ingress_filter`, `SEC("tp/net/netif_receive_skb")`
* **동작 원리**:
  * 패킷이 NIC 드라이버 메모리(DMA)에 도착하는 즉시 802.1Q (`0x8100`) 및 802.1ad (`0x88A8`) VLAN 태그를 루프 언롤링(`unroll 2`)으로 파싱합니다.
  * TCP 페이로드가 존재하는 첫 번째 패킷에 대해 고유한 64비트 `req_id`를 생성합니다:
    `req_id = ((ts & 0xFFFFFFFF) << 16) ^ (sport << 4) ^ dport`
  * 패킷 메타데이터를 `ingress_flow_map`에 등록하고 초기 이벤트를 RingBuffer로 전송합니다.

### Layer 3: L3 Kernel IP Routing (OSI_L3_IP = 3)
* **주요 훅**: `SEC("kprobe/ip_rcv")`, `SEC("kprobe/ipv6_rcv")`, `SEC("kprobe/icmp_rcv")`, `SEC("kprobe/arp_rcv")`
* **동작 원리**:
  * IP 계층 진입 시점을 기록하여 XDP와의 차이(Δt)로 순수 커널 네트워크 스택 진입 오버헤드를 측정합니다.
  * IPv6 패킷의 경우 Hop-by-Hop, Routing, Fragment, ESP 확장 헤더를 `#pragma unroll 4`로 최대 4단계까지 순회하여 L4 포트를 추출합니다.

### Layer 4: L4 Transport & Sockets (OSI_L4_TCP = 4)
* **주요 훅**: `SEC("kprobe/tcp_v4_rcv")`, `SEC("kprobe/tcp_v6_rcv")`, `SEC("tp/tcp/tcp_retransmit_skb")`, `SEC("tp/skb/kfree_skb")`
* **동작 원리**:
  * 3방향 핸드셰이크(SYN, SYN-ACK, ACK)를 감지하고, 소켓 킵얼라이브 상태를 지속 관리합니다.
  * 패킷 유실 시 커널이 발생시키는 `tcp_retransmit_skb`를 후킹하여 재전송 횟수를 누적합니다.
  * 비정상 드롭(`kfree_skb` with reason > 2) 발생 시 드롭 원인 코드와 함께 즉시 플래그(`FLAG_SKB_DROP`)를 방출합니다.

### Layer 5: L5 Syscall & Socket Queue (OSI_L4_SOCKET = 5, OSI_L5_SYSCALL_MEM = 6)
* **주요 훅**: `SEC("kprobe/tcp_recvmsg")`, `SEC("kretprobe/tcp_recvmsg")`, `SEC("tp/skb/skb_copy_datagram_iovec")`, `SEC("kprobe/handle_mm_fault")`, `SEC("tp/block/block_rq_*")`
* **동작 원리**:
  * 패킷이 소켓 수신 버퍼(`sk_rcvbuf`)에 도착한 시간과 애플리케이션이 `read()`/`recvmsg()`로 데이터를 꺼내간 시간의 차이를 계산하여 **소켓 버퍼 정체 시간(Dwell Time)**을 산출합니다.
  * 커널 버퍼에서 유저 버퍼로 복사되는 동안 발생하는 페이지 폴트(`handle_mm_fault`) 및 디스크 I/O 대기(`block_rq_issue` -> `block_rq_complete`)를 추적합니다.

### Layer 6: L6 Pre-Compute Gate (OSI_L6_PRE_COMPUTE = 8)
* **주요 훅**: `SEC("tp/syscalls/sys_enter_futex")`, `SEC("tp/syscalls/sys_exit_futex")`, `SEC("tp/sched/sched_waking")`, `SEC("tp/sched/sched_wakeup")`, `SEC("tp/sched/sched_switch")`
* **동작 원리**:
  * **8-슬롯 락프리 링 버퍼**: 이벤트 루프(Epoll 리스너) 스레드가 요청을 읽은 후 작업자 스레드 풀(Worker Pool)로 넘길 때, `pending_handoff_map`의 8-슬롯 FIFO 링에 `req_id`를 등록합니다.
  * 워커 스레드가 `futex(FUTEX_WAIT)`에서 깨어날 때(`sys_exit_futex`), 링에서 일치하는 슬롯을 소유(`claimed = 1`)하여 새로운 스레드(`tid`)로 문맥을 상속합니다.
  * `sched_wakeup`부터 `sched_switch`까지의 시간을 계산하여 OS 스케줄러 런큐 대기 지연(`runqlat`)을 측정합니다.

### Layer 7: L7 User App Execution (OSI_L7_APP = 7)
* **주요 훅**: `SEC("uprobe") trace_uprobe_entry`, `SEC("uretprobe") trace_uprobe_return`
* **동작 원리**:
  * **16단계 Shadow Stack**: Verifier 512바이트 스택 제한을 준수하기 위해 BPF 스택 대신 Per-CPU 맵 템플릿을 사용하여 최대 16단계 깊이의 함수 진입 IP와 타임스탬프를 스택 형태로 보관합니다.
  * **트램펄린 IP 복원**: 리눅스 커널 Uretprobe는 복귀 시점에 명령 포인터(`PT_REGS_IP`)를 커널 가상 주소(`[uprobes]`)로 교체합니다. 본 트레이서는 Shadow Stack에 보존된 원본 호출 주소를 100% 복원하여 심볼 왜곡을 방지합니다.

---

## 3. 5대 실전 아키텍처 검증 시나리오와 커널 맵/훅 매핑

| 검증 시나리오 | 검증 대상 (고수준 I/O 사각지대) | 커널 BPF 훅 & BPF 맵 | 지연 시간 산출 수식 및 인코딩 | CLI 실행 명령어 |
| :--- | :--- | :--- | :--- | :--- |
| **검증 1: 소켓 수신 버퍼 적체 (`sk_rcvbuf`)** | JVM GC / 이벤트 루프 지연으로 패킷이 커널 소켓 큐에 방치된 시간 | [`kprobe/tcp_v4_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L20) → [`kprobe/tcp_recvmsg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L14) ([`ingress_flow_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L275)) | `dwell_ns = t_tcp_recvmsg - state->tcp_rcv_ts` (`L5:SOCKET_RECV`) | `krayctl verify 1` / `krayctl trace -L 5` |
| **검증 2: 스레드 핸드오프 & 런큐 지연** | Epoll 리스너 → 워커 스레드 풀 핸드오프 시 Futex 락 및 OS 스케줄러 대기 | [`sys_enter_futex`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L16) → [`sched_wakeup`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L190) → [`sched_switch`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L199) ([`pending_handoff_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L278)) | `runq_ns = t_switch - t_wakeup`, `ip = (lock_wait << 16) \| (prev_cpu << 8) \| cur_cpu` | `krayctl verify 2` / `krayctl trace -L 6` |
| **검증 3: 순수 On-CPU ALU vs Off-CPU 선점** | 유저 함수 실행 중 실제 CPU 연산 시간과 스케줄러 선점(Preemption) 분리 | [`trace_uprobe_entry`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c#L20) / [`trace_uprobe_return`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c#L111) ([`active_ctx_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L276)) | `fn_dur = t_return - fn_entry_ts[slot]` vs `acc_off_cpu_ns` 스냅샷 대조 | `krayctl verify 3` / `krayctl trace -L 7` |
| **검증 4: 커널-유저 복사 & 페이지 폴트 / I/O** | 대용량 버퍼 복사 중 발생하는 페이지 폴트 및 디스크 블록 I/O 지연 귀속 | [`kretprobe/skb_copy_datagram_iter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L157), [`kprobe/handle_mm_fault`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L217), [`block_rq_complete`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L501) | `copy_dur = now - copy_enter_ts`, `ip = (page_faults << 32) \| copied_bytes` | `krayctl verify 4` / `krayctl trace -L 5 -j` |
| **검증 5: Egress 착시 & 패킷 드롭/재전송** | `writeAndFlush()` 성공 반환 후 커널 내부 드롭 사유 및 재전송을 `req_id`에 매핑 | [`kprobe/__tcp_transmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L338), [`tp/skb/kfree_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L262), [`tp/tcp/tcp_retransmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L220) ([`skb_egress_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L281)) | `FLAG_SKB_DROP (0x08)` + `args->reason`, `FLAG_TCP_RETRANSMIT (0x04)` + `retransmits` | `krayctl verify 5` / `krayctl trace -L 4` |

---

## 4. 커널 Verifier 통과를 위한 핵심 설계 원칙

1. **512바이트 스택 오버플로 방지**:
   * `struct tid_ctx_t`의 크기는 400바이트 이상이므로, BPF 스택에 절대 로컬 변수로 할당하지 않습니다.
   * `BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)`를 **읽기 전용 0-템플릿**으로 선언하고, 맵 업데이트 후 룩업 포인터를 직접 수정하는 무복사 패턴을 사용합니다.
2. **모든 루프의 `#pragma unroll` 보장**:
   * Verifier가 유한 반복을 증명할 수 있도록 모든 `for` 루프에 컴파일러 unroll 지시어를 적용했습니다.
3. **NULL 포인터 가드 및 경계 검사**:
   * 맵 룩업 반환 포인터에 대한 역참조 전 `if (!ptr) return 0;` 검사를 엄격히 강제했습니다.
   * 패킷 버퍼 접근 시 `(void *)(hdr + 1) > data_end` 검사를 헤더별로 선행 수행합니다.

---

## 5. 리눅스 업스트림 Selftests 및 3계층 모듈화 아키텍처 (Zero-`.sh` Design)

사람이 읽기 쉽고 유지보수하기 쉽도록 **커널 BPF(`progs/`) · 유저 공간 C 데몬(`daemon/`) · 파이썬 컨트롤 플레인(`kray/`)**의 3계층으로 모듈화되어 있으며, 셸 스크립트(`.sh` 및 `/bin/sh`) 의존성을 완전히 배제했습니다:

* **커널 마이크로 BPF 모듈 ([progs/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/))**: 각 OSI 레이어가 200줄 내외의 독립적인 `.bpf.c` 파일([`tracer_l2_xdp.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c) ~ [`tracer_l7_uprobe.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c))로 분리되어 있어, 개발자가 계층별 커널 훅 로직을 즉시 파악하고 단독 컴파일할 수 있습니다.
* **유저 공간 C 데몬 모듈 ([daemon/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/) & [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c))**:
  * [daemon/daemon_types.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_types.h): 런타임 옵션 상태(`struct daemon_cfg`), 원자적 카운터 및 시그널 핸들러
  * [daemon/daemon_preflight.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h): `CAP_BPF`/BTF/BPFFS/Cgroups v2(`<64MB` 헤드룸) 사전 점검 및 ELF 심볼 스트립 검사
  * [daemon/daemon_sweeper.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_sweeper.h): `SIGKILL` 충돌 후 잔류한 Generic XDP를 자동 청소하는 `flush_orphan_xdp()` 및 30초 TTL 유휴 플로우 스위퍼 `sweep_stale_flows()`
  * [daemon/daemon_formatter.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h): ARM64 `dmb ishld` 메모리 배리어, 링버퍼 드롭 배너(`stderr`), ANSI 컬러 터미널(`stdout`) 및 순수 JSON Lines(`stdout`) 스트림 분리 포매터
* **무셸(Zero-`.sh`) 파이썬 컨트롤 플레인 ([kray/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/) & [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl))**:
  * 모든 명령어 실행을 `subprocess.run(..., shell=False)`(`execve` 직접 호출)로 처리하여 셸 파싱 취약점과 백그라운드 파이프라인 경합을 원천 차단합니다.
  * [kray/help_docs.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/help_docs.py), [kray/verify_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/verify_scenarios.py), [kray/host_ops.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/host_ops.py), [kray/remote_target.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py)로 역할이 명확히 분리되어 있습니다.
* **네이티브 테스트 러너 ([test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c))**: `bpftool gen skeleton`으로 생성된 6개 마이크로 스켈레톤과 1개 통합 스켈레톤을 차례로 열고 로드하여 7/7 전수 통과를 검증합니다.


---

# [Book IV] 라이선스 구분 명세 (Licensing Specification)

# 라이선스 구분

이 저장소는 두 가지 라이선스를 함께 쓴다. 저작권자는 모두 coralstay다.

| 범위 | 라이선스 | 파일 |
|---|---|---|
| 커널 안에서 도는 BPF 프로그램과 그 빌드·테스트 도구 | [GPL-2.0](./LICENSE.GPL-2.0) | `progs/` 전체, `tracer_kernel.c`, `kray_bpf_core_compat.h`(`SEC("license") = "GPL"` 선언), `test_progs.c`, `Makefile` |
| 그 밖의 모든 코드와 문서(사용자 공간 에이전트, 시뮬레이터, 테스트 스위트, 산출물) | [AGPL-3.0-only](./LICENSE) | `tracer_agent.py`, `kernel_sim_harness.c`, `mock_bpf_runtime.h`, `test_verification_suite.py`, `krayctl`, 문서 등 |

BPF 프로그램은 커널의 GPL 전용 helper를 쓰기 때문에 GPL 호환 라이선스를 선언해야 한다.
그래서 커널 쪽 코드는 GPL-2.0으로 두고, 각 파일의 `SPDX-License-Identifier` 또는
`SEC("license")` 선언이 이 표보다 우선한다.

빌드 산출물 `*.skel.h`는 bpftool이 생성하며 `(LGPL-2.1 OR BSD-2-Clause)`로 표시되고, 저장소에는
커밋하지 않는다.


---

# [Book V] 통합 마스터 기술 명세서 및 105개 CLI 시나리오 검증서 (Unified Master Technical Specification)

# eBPF Wire-to-Code Tracer — Unified Master Technical Specification & Architecture Manual

### Document Metadata
* **Platform**: Rocky Linux 9.8 aarch64
* **Kernel Release**: `5.14.0-687.10.1.el9_8.0.1.aarch64`
* **CPU Architecture**: ARM64 (aarch64, ARMv8.1-A+ with Large System Extension Atomics)
* **Authoritative Foundations**: Michael Kerrisk (*The Linux Programming Interface* - TLPI), Linux `man-pages(7)` Project, IEEE Std 1003.1 (POSIX), BPF CO-RE, and Upstream Linux Kernel Standards
* **Formatting Compliance**: Hierarchical headings, bulleted lists, and Markdown tables where appropriate. Complete clickable links with `file://` scheme.

---

### Part 1: Executive Technical Overview & System Foundations

#### 1. System Mission & The Wire-to-Code Paradigm
In enterprise distributed systems, diagnosing tail latencies requires correlating physical network packet arrivals with application thread execution. Traditional observability stacks operate in isolation: network packet analyzers (Wireshark, tcpdump) inspect wire packets without awareness of thread IDs or call stacks, while application performance monitors (APMs, profilers) record function runtimes without visibility into network interface queuing, kernel socket buffers, or thread scheduler preemption.

The eBPF Wire-to-Code Tracer ([krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl), [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c), [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)) bridges this gap by instrumenting the complete request lifecycle across all 7 layers of the OSI stack with sub-microsecond overhead:
* Physical wire packet ingress at the network interface card (NIC) via eXpress Data Path (XDP).
* Kernel network stack routing, IP defragmentation, and TCP state transitions via Kprobes and Tracepoints.
* Socket receive buffer delivery and memory copy at the POSIX syscall boundary.
* Inter-thread request handoff across epoll listeners and worker thread pools via scheduler tracepoints and futex tracking.
* Application runtime function execution via dynamically attached user-space probes (Uprobes/Uretprobes) with DWARF symbolication and shadow stack reconstruction.
* Socket write and physical egress feedback loop completing the causal request graph.

#### 1.1 Why This Project Exists Beyond High-Level Language I/O APIs (Java NIO/Netty, Go, Rust Tokio, Node.js)
Modern language runtimes provide sophisticated I/O abstractions—such as Java NIO (`Selector`), Netty (`EpollEventLoop`), JDK Virtual Threads, Go `netpoll`, Node.js `libuv`, and Rust `Tokio`. Despite these rich language-level APIs and APM agents, a fundamental observability gap remains: **the language runtime's clock does not start when the packet arrives at the NIC, nor does the packet leave the server when `write()` returns.**

When a client reports a 100ms tail latency spike while the application server logs a 2ms execution time ("Phantom Latency"), the missing 98ms hides inside four kernel-space blind spots that high-level language I/O APIs cannot see:

| Blind Spot Domain | High-Level Language I/O API View (Java / Go / Node.js) | Actual Linux Kernel Reality Observed by `kray` eBPF |
| :--- | :--- | :--- |
| **1. Ingress Socket Queue Dwell (`sk_rcvbuf`)** | Request timer only starts after `epoll_wait()` / `Selector.select()` wakes up and `read()` / `recvmsg()` is invoked. | Packet arrived at the NIC ([`xdp_ingress_filter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c#L18)) and TCP stack ([`kprobe__tcp_v4_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L20)) 50ms earlier, sitting unconsumed in `sk_rcvbuf` due to JVM GC pauses or EventLoop saturation. |
| **2. Thread Handoff & Scheduler Runqueue** | Submitting a task to `ExecutorService` or a channel appears instantaneous at the language API boundary. | Epoll listener thread wakes worker via [`sys_enter_futex`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L16); worker endures lock contention, OS scheduler runqueue delay ([`sched_wakeup`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L190) -> [`sched_switch`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L199)), and cross-core CPU migration. |
| **3. Off-CPU Preemption & Faults in Code** | A method taking 30ms wall-clock time is misdiagnosed as an inefficient user algorithm. | Pure CPU ALU execution ([`trace_uprobe_entry`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c#L20)) took 1ms; 29ms was spent in kernel-to-user copy page faults ([`kprobe__handle_mm_fault`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L217)), block I/O ([`block_rq_complete`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L501)), or OS thread preemption (`acc_off_cpu_ns`). |
| **4. Egress Completion Illusion** | `channel.writeAndFlush()` or `send()` returns in 0.1ms as soon as bytes copy into kernel `sk_sndbuf`. | Packet is stalled in TCP congestion/receive window or Qdisc, or dropped inside the kernel ([`kfree_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L262)) and retransmitted ([`tcp_retransmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L220)). |

#### 1.2 The 5 Real-World Architectural Verifications (`krayctl verify`)
Using [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl) (`krayctl verify [list|1..5]`), engineers can empirically prove or falsify five critical production hypotheses:
* **Verification 1 (`krayctl verify 1` / `ingress`)**: Quantify **Socket Receive Buffer Dwell Time (`dwell_ns`)** in [`progs/tracer_l5_syscall.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L70) (`t_tcp_recvmsg - t_tcp_v4_rcv`) to prove whether latency originates in application code or pre-read runtime starvation (GC / EventLoop delay).
* **Verification 2 (`krayctl verify 2` / `handoff`)**: Quantify **Reactor-to-Worker Thread Handoff Tax** in [`progs/tracer_l6_sched.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c) across the 8-slot lock-free [`pending_handoff_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L278), measuring Futex wait (`lock_wait_ns`), CPU runqueue wait (`runq_ns`), and core migration (`prev_cpu_id` -> `target_cpu_id`).
* **Verification 3 (`krayctl verify 3` / `offcpu`)**: Separate **Pure On-CPU ALU Compute Time from Off-CPU Preemption** in [`progs/tracer_l7_uprobe.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c) by comparing 16-depth shadow stack duration (`fn_dur`) against `sched_switch` off-CPU snapshots (`fn_off_cpu_snap`).
* **Verification 4 (`krayctl verify 4` / `mm`)**: Attribute **Kernel-to-User Buffer Copy (`skb_copy_datagram_iter`), Page Faults (`handle_mm_fault`), and Block I/O (`block_rq_*`)** directly to the active request ID (`req_id`) in [`progs/tracer_l5_syscall.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l5_syscall.bpf.c#L157-L224).
* **Verification 5 (`krayctl verify 5` / `drops`)**: Eliminate **Egress Blindness** by mapping kernel packet drop reasons (`tracepoint:skb:kfree_skb`, `reason > 2`) and TCP retransmissions (`tracepoint:tcp:tcp_retransmit_skb`) to the exact `req_id` and worker `tid` in [`progs/tracer_l4_tcp.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l4_tcp.bpf.c#L220-L374).

#### 2. Target Operating Environment Specifications
* **Operating System**: Rocky Linux release 9.8 (Blue Onyx), enterprise Linux binary-compatible with Red Hat Enterprise Linux 9.8.
* **Kernel Subsystem**: Linux `5.14.0-687.10.1.el9_8.0.1.aarch64` featuring:
  - BPF Type Format (BTF) debugging symbols at `/sys/kernel/btf/vmlinux` for CO-RE (Compile-Once Run-Everywhere) struct relocations.
  - In-kernel BPF JIT compiler (`/proc/sys/net/core/bpf_jit_enable = 1`).
  - Unified Cgroups v2 hierarchical resource management with memory accounting (`__GFP_ACCOUNT`).
  - BPF ring buffer subsystem (`bpf_ringbuf`) with multi-producer single-consumer lockless ring semantics.
* **CPU Hardware**: ARM64 (aarch64) with 64-bit virtual addressing, 4KB standard page granularity, weakly ordered memory model, and ARMv8.1-A Large System Extension (LSE) hardware atomic instructions.

#### 3. Core Architectural Tenets
* **Deterministic Reliability**: Zero unhandled exceptions, zero process aborts under malformed network payloads, and deterministic performance under continuous 20-iteration regression verification.
* **Zero Silent Drops**: Ring buffer saturation and drop events are tracked cumulatively and explicitly surfaced via high-priority visual alert banners and machine-actionable telemetry metrics.
* **Total Stream Separation**: Complete adherence to Michael Kerrisk's TLPI stream isolation rules; machine-parseable JSON Lines stream flows strictly to standard output (`stdout`), while diagnostic logging, banners, and warnings flow strictly to unbuffered standard error (`stderr`).
* **Production-Grade Defensive Hardening**: Proactive mitigation against real-world production failure modes documented by Cilium, Cloudflare, Datadog, Meta, and Netflix.

---

### Part 2: End-to-End 7-Layer OSI Tracing Architecture

The tracing engine attaches probes across 7 continuous layers, capturing a monotonically increasing causal timeline for every individual request:

#### Layer 1 (OSI L2): Ingress NIC & Link Layer
* **Subsystem & Hooks**:
  - eXpress Data Path (`XDP`): Hooks the NIC driver receive path (`xdp_ingress_filter`) before `struct sk_buff` (SKB) allocation.
  - Driver Mode Fallback: Automatically falls back to Generic SKB mode (`XDP_FLAGS_SKB_MODE`) on cloud or virtualized NICs (VirtIO-Net, AWS ENA) when driver mode returns `-EOPNOTSUPP`.
  - Core Tracepoint: `tracepoint:net:netif_receive_skb`.
* **Telemetry Captured**:
  - Wire ingress hardware timestamp (`xdp_ts`).
  - Ethernet protocol identification (`ETH_P_IP`, `ETH_P_IPV6`, `ETH_P_ARP`).
  - IEEE 802.1Q VLAN single and QinQ double tagging extraction.
  - Initial request ID minting (`req_id`) using 64-bit entropy derived from timestamp, port pairs, and core ID.

#### Layer 2 (OSI L3): Network Layer
* **Subsystem & Hooks**:
  - `kprobe:ip_rcv` and `kprobe:ip_rcv_finish`.
  - IPv6 counterpart: `kprobe:ipv6_rcv`.
* **Telemetry Captured**:
  - IPv4 Header: TTL, header length (IHL), Total Length, Identification, Don't Fragment (DF) and More Fragments (MF) flags, fragment offset.
  - IPv6 Header: Hop Limit, Payload Length, Next Header, 128-bit IPv6 address folding into unique 32-bit indices.
  - IP Defragmentation Isolation: Distinguishes non-initial fragment slices (`FLAG_IP_FRAGMENT`) from intact datagrams.

#### Layer 3 (OSI L4): Transport Protocol & Connection State
* **Subsystem & Hooks**:
  - `kprobe:tcp_v4_rcv` and `kprobe:tcp_v6_rcv`.
  - `kprobe:udp_rcv`.
  - `tracepoint:tcp:tcp_retransmit_skb`.
* **Telemetry Captured**:
  - TCP Header: Source port, destination port, sequence number, acknowledgment number, window size, TCP options.
  - TCP Flags: SYN, ACK, PSH, FIN, URG, ECE, CWR, and RST.
  - SYN Epoch Rollover: Immediate detection of dynamic ephemeral port reuse (32768~60999) under `TIME_WAIT` recycling, minting a new `req_id` and flushing stale timestamps.
  - RST Immediate Eviction: Intercepts `FLAG_TCP_RST (0x04)` to delete entries from `ingress_flow_map` immediately, preventing lingering unclosed connection states.
  - Transport Retransmissions: Tracks TCP packet loss and retransmits via `tcp_retransmit_skb`.

#### Layer 4 (OSI L5): Socket Buffer & Syscall Boundary
* **Subsystem & Hooks**:
  - `kprobe:tcp_recvmsg` and `kretprobe:tcp_recvmsg`.
  - System call enter/exit tracepoints: `tracepoint:syscalls:sys_enter_recvfrom`, `tracepoint:syscalls:sys_exit_recvfrom`, `sys_enter_read`, `sys_exit_read`.
* **Telemetry Captured**:
  - Socket delivery latency: Duration from transport ingress to application userspace buffer copy.
  - Socket Flow Key Correlation: Resolves the kernel `struct sock` socket address and 4-tuple to establish association with thread execution context.
  - Socket Buffer Backpressure: Measures kernel queue dwell time prior to system call drain.

#### Layer 5 (OSI L6): Scheduler Handoff & Worker Thread Pools
* **Subsystem & Hooks**:
  - Scheduler Tracepoint: `tracepoint:sched:sched_switch` (tracks thread preemption, voluntary yields, runqueue wait latency).
  - Futex Tracepoints: `tracepoint:syscalls:sys_enter_futex`, `tracepoint:syscalls:sys_exit_futex`.
  - Epoll Tracepoints: `tracepoint:syscalls:sys_enter_epoll_pwait`, `tracepoint:syscalls:sys_exit_epoll_pwait`.
* **Telemetry Captured**:
  - Producer-Consumer Thread Handoff: Listener threads (epoll worker) hand off incoming connections to background worker threads via eventfd or work queues.
  - Lock & Mutex Wait Latency: Accurately accumulates thread off-CPU wait time (`acc_off_cpu_ns`) during mutex/futex contention.
  - 8-Slot Handoff Ring: Monotonic generation sequence counters (`seq`) detect wraparound overwrites during burst scheduling.
  - Multi-Core Memory Ordering: Hardware memory barriers (`dmb ish` / `barrier()`) enforce cross-core visibility of handoff metadata before updating ring index.

#### Layer 6 (OSI L7): Application Runtime & Execution
* **Subsystem & Hooks**:
  - User-space probes: `uprobe:trace_uprobe_entry` and `uretprobe:trace_uprobe_return`.
  - Dynamic DWARF Symbolication: Resolves ELF `.symtab` and `.dynsym` symbols, mangled C++ symbols (`abi::__cxa_demangle`), and shared library memory offsets.
* **Telemetry Captured**:
  - Function Execution Duration: Entry timestamp subtracted from return timestamp minus off-CPU sleep duration yields pure CPU compute time.
  - In-Kernel ALU Shadow Call Stack: Tracks nested function recursion up to 16 levels (`fn_entry_ip`, `fn_entry_ts`).
  - ASLR & 64KB PT_LOAD Alignment: Computes load address relocation via virtual memory mapping formulas (`p_vaddr`, `p_offset`).
  - Adaptive Rate Limiting: Evaluates call frequency within a 1-second sliding window; throttles telemetry when call rate exceeds 10,000 calls/sec to prevent application CPU collapse.

#### Layer 7 (OSI L4 Egress): Network Egress & Client Roundtrip Feedback Loop
* **Subsystem & Hooks**:
  - `kprobe:tcp_sendmsg` and `kretprobe:tcp_sendmsg`.
  - `tracepoint:net:net_dev_xmit` and `tracepoint:net:netif_rx`.
* **Telemetry Captured**:
  - Response Generation Latency: Measures time from initial packet arrival to the first byte written to the output socket.
  - Wire Egress Confirmation: Confirms packet transfer to NIC hardware transmission queue, calculating total end-to-end wire-to-code-to-wire service latency.

---

### Part 3: Comprehensive 22-Protocol Data Frame & Transport Specifications

The tracer features a universal, resilient protocol dissector engine ([kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py)) that decodes and correlates payloads across 22 production protocols:

#### 1. Well-Known System & Web Protocols
* **HTTP/1.1 (Port 80, 8080, 8000)**:
  - RFC 7230 / RFC 9112 stream parsing.
  - Extracts HTTP verbs (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS), URI path, query parameters, Host header, Content-Length, Transfer-Encoding (chunked), and status codes.
* **HTTP/2 & gRPC (Port 50051, 8443)**:
  - RFC 7540 / RFC 9113 binary frame decoding.
  - Decodes 9-byte frame header: Length (24-bit), Type (8-bit: DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE), Flags, Stream ID (31-bit).
  - Extracts gRPC message framing: 1-byte compression flag, 4-byte big-endian message length, and Protocol Buffers payload slice.
* **HTTPS / TLS Record Layer (Port 443, 8443)**:
  - RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3).
  - Decodes ContentType (20: ChangeCipherSpec, 21: Alert, 22: Handshake, 23: Application Data), ProtocolVersion (0x0303 = TLS 1.2, 0x0304 = TLS 1.3), Record Length, and Handshake Type (ClientHello, ServerHello).
  - Safely measures encrypted payload boundaries without requiring session private keys.
* **WebSocket (Port 80, 443)**:
  - RFC 6455 framing parser.
  - Evaluates FIN bit, RSV1-3 reservation bits, Opcode (0: Continuation, 1: Text, 2: Binary, 8: Close, 9: Ping, 10: Pong), Mask bit, 7-bit/16-bit/64-bit payload length, and 4-byte masking key.
* **DNS (Port 53 TCP/UDP)**:
  - RFC 1035 name query dissector.
  - Decodes Transaction ID, Flags (QR, Opcode, AA, TC, RD, RA, RCODE), Question Count, Answer Count.
  - Recursively resolves DNS label sequences, terminating on null labels (`0x00`) while guarding against malicious circular compression pointers (`0xC0`).
* **SSH-2.0 (Port 22)**:
  - RFC 4253 transport protocol banner parser.
  - Decodes identification strings (`SSH-2.0-OpenSSH_8.7`, `SSH-2.0-PuTTY`), binary packet lengths, padding lengths, and key exchange message types (`SSH_MSG_KEXINIT`).
* **NTP (Port 123 UDP)**:
  - RFC 5905 48-byte fixed-format time protocol.
  - Decodes Leap Indicator (LI), Version Number (VN), Mode (Client, Server, Broadcast), Stratum (0..16), Poll Interval, Precision, Root Delay, Root Dispersion, Reference ID, and 64-bit Transmit Timestamp.
* **SMB2 / SMB3 (Port 445)**:
  - Server Message Block file sharing protocol.
  - Decodes 64-byte SMB2 header: Protocol ID (`0xFE 'S' 'M' 'B'`), StructureSize, CreditCharge, Status (NTSTATUS), Command (Negotiate, SessionSetup, TreeConnect, Create, Read, Write), MessageID, and SessionID.
* **FTP (Port 21)**:
  - RFC 959 interactive control stream parser.
  - Decodes command verbs (USER, PASS, CWD, PORT, PASV, RETR, STOR, QUIT) and 3-digit numeric server response status codes.

#### 2. Registered Enterprise, Database & Streaming Protocols
* **Redis RESP 2/3 (Port 6379)**:
  - REdis Serialization Protocol dissector.
  - Decodes type prefixes: `+` Simple Strings, `-` Errors, `:` Integers, `$` Bulk Strings, `*` Arrays.
  - Reconstructs full Redis command tokens (e.g. `SET user:42 "session_active"`).
* **MySQL / MariaDB (Port 3306)**:
  - Client/Server wire protocol.
  - Decodes 4-byte packet framing (3-byte packet length + 1-byte sequence ID).
  - Inspects command codes: `0x00` COM_SLEEP, `0x01` COM_QUIT, `0x02` COM_INIT_DB, `0x03` COM_QUERY, `0x04` COM_FIELD_LIST.
  - Extracts full SQL query strings directly from raw wire frames.
* **PostgreSQL 3.0 (Port 5432)**:
  - PostgreSQL frontend/backend protocol.
  - Frontend: `'Q'` Simple Query, `'P'` Parse, `'B'` Bind, `'E'` Execute, `'X'` Terminate.
  - Backend: `'R'` Authentication, `'K'` BackendKeyData, `'Z'` ReadyForQuery, `'C'` CommandComplete, `'E'` ErrorResponse.
* **Apache Kafka (Port 9092)**:
  - Kafka binary request protocol.
  - Decodes 4-byte message size, `api_key` (0: Produce, 1: Fetch, 2: ListOffsets, 3: Metadata, 8: OffsetCommit), `api_version`, `correlation_id`, and `client_id` string.
* **MQTT (Port 1883)**:
  - MQTT IoT publish/subscribe protocol.
  - Decodes fixed header: Packet Type (1: CONNECT, 2: CONNACK, 3: PUBLISH, 4: PUBACK, 8: SUBSCRIBE, 12: PINGREQ, 14: DISCONNECT), DUP flag, QoS level (0, 1, 2), RETAIN flag, variable-length remaining length, topic name, and payload bytes.
* **NFSv3 / NFSv4 (Port 2049)**:
  - Sun Open Network Computing Remote Procedure Call (ONC RPC / RFC 1831).
  - Decodes XID (Transaction ID), Message Type (0: CALL, 1: REPLY), RPC Version, Program Number (100003 = NFS), Program Version (3 = NFSv3), Procedure Number (0: NULL, 1: GETATTR, 3: LOOKUP, 6: READ, 7: WRITE, 8: CREATE).
* **iSCSI (Port 3260)**:
  - IP Storage Area Network (RFC 3720 / RFC 7143).
  - Decodes 48-byte Basic Header Segment (BHS): Opcode (0x01: SCSI Command, 0x02: SCSI Task Management, 0x03: Login Request, 0x21: SCSI Response, 0x23: Login Response), Immediate (I) bit, Final (F) bit, LUN (Logical Unit Number), Initiator Task Tag (ITT), and DataSegmentLength.

#### 3. Non-IP, Wireless & Hardware Link Protocols
* **IEEE 802.11 Wi-Fi (Non-IP Wireless MAC)**:
  - Wireless local area network MAC frames.
  - Decodes Frame Control (Type: Management, Control, Data; Subtype: Beacon, Probe Request, QoS Data), Flags (To DS, From DS, More Frag, Retry, Pwr Mgmt, Protected), Duration/ID, Receiver Address (RA), Transmitter Address (TA), Destination Address (DA), Sequence Control (Sequence Number + Fragment Number).
* **IEEE 802.15.1 Bluetooth & BLE (Non-IP Wireless PAN)**:
  - Host Controller Interface (HCI) and Logical Link Control and Adaptation Protocol (L2CAP).
  - Decodes HCI Packet Type (0x01: Command, 0x02: ACL Data, 0x04: Event), Connection Handle, PB (Packet Boundary) flags, L2CAP Length, Channel ID (CID: 0x0004 = Attribute Protocol / BLE ATT, 0x0005 = Signaling, 0x0006 = Security Manager).
  - Decodes BLE Attribute Protocol (ATT) opcodes (Read Request, Write Command, Handle Value Notification).
* **IEEE 802.1Q VLAN (Non-IP Link Layer)**:
  - Virtual Bridged Local Area Networks.
  - Decodes 4-byte 802.1Q tag inserted between Ethernet source MAC and EtherType: TPID (`0x8100`, `0x88A8` for 802.1ad QinQ), Priority Code Point (PCP, 3 bits), Drop Eligible Indicator (DEI, 1 bit), and VLAN Identifier (VID, 12 bits = 0..4095).
* **Address Resolution Protocol - ARP (EtherType 0x0806)**:
  - RFC 826 hardware address resolution.
  - Decodes Hardware Type (Ethernet = 1), Protocol Type (IPv4 = 0x0800), Hardware Address Length (6), Protocol Address Length (4), Operation Code (1: ARP Request, 2: ARP Reply), Sender Hardware Address (SHA), Sender IP Address (SPA), Target Hardware Address (THA), Target IP Address (TPA).
* **Internet Control Message Protocol - ICMP (IP Protocol 1)**:
  - RFC 792 network control and diagnostic protocol.
  - Decodes Type (0: Echo Reply, 3: Destination Unreachable, 8: Echo Request, 11: Time Exceeded), Code, Checksum, Identifier, Sequence Number, and Ping payload timestamp.
* **Linux AF_UNIX Domain Sockets (Kernel IPC)**:
  - Linux local inter-process communication sockets.
  - Decodes local filesystem paths (`/var/run/docker.sock`, `/tmp/kray.sock`) and abstract socket namespace strings (`@/container/ipc`).
  - Correlates sender process PID, UID, and GID credentials via `SCM_CREDENTIALS` socket ancillary messages.

---

### Part 4: CLI Architecture Grounded in Michael Kerrisk's Standards

The command-line interface ([krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl) and [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c)) is grounded in the authoritative principles established by **Michael Kerrisk** in *The Linux Programming Interface* (TLPI) and the Linux `man-pages(7)` project:

#### 1. Michael Kerrisk's Systems Programming Principles (TLPI Chapters 56/63 & Appendix B)
* **Argument Vector Architecture**:
  - Process argument delivery via `execve(2)` places null-terminated strings (`argv`) and environment variables (`envp`) into the highest memory addresses of the user-space stack above `auxv_t`.
  - The C runtime extracts these into `argc` and `argv[]`, guaranteed by ISO C to terminate with `argv[argc] == NULL`.
  - Exposed via `/proc/[pid]/cmdline` as null-byte-separated strings.
* **The Leading Colon (`:`) Error Suppression Pattern**:
  - Standard POSIX `getopt(3)` and GNU `getopt_long(3)` print generic, unlocalized error messages to `stderr` when `opterr` is enabled.
  - Michael Kerrisk strongly mandates starting the `optstring` with a colon (e.g. `":p:t:L:i:b:o:jvVh"`).
  - This suppresses generic libc errors and allows deterministic distinction between:
    - Missing option-arguments (returns `':'`, sets `optopt` to the offending flag).
    - Unrecognized options (returns `'?'`, sets `optopt` to the unrecognized character).
  - Enables the program to return tailored, domain-specific diagnostic messages and precise exit codes.
* **Standard Exit Status Taxonomy (BSD `<sysexits.h>`)**:
  - `EX_OK (0)`: Successful execution.
  - `EX_USAGE (64)`: Command-line syntax error, invalid argument range, missing required option-argument, or unrecognized flag.
  - `EX_UNAVAILABLE (69)`: Required system resource unavailable (e.g. `/sys/kernel/btf/vmlinux` missing).
  - `EX_SOFTWARE (70)`: Internal software failure or BPF verifier load rejection.
  - `EX_OSERR (71)`: Operating system call failure (e.g. ring buffer memory mapping failure).
  - `EX_NOPERM (77)`: Insufficient execution privileges (`geteuid() != 0` without necessary Linux capabilities).
* **Strict Stream Separation Architecture**:
  - Standard Output (`stdout` / FD 1): Exclusively reserved for machine-parseable programmatic data (JSON Lines telemetry) and requested help synopses (`-h` / `--help`).
  - Standard Error (`stderr` / FD 2): Exclusively reserved for diagnostic logging, startup banners, drop warnings, and error messages.
  - Standard error buffering is immediately disabled at program launch via `setvbuf(stderr, NULL, _IONBF, 0)` to guarantee unbuffered, real-time diagnostic delivery.

#### 2. POSIX IEEE Std 1003.1 Guidelines 1~13 Conformance
* **Guideline 1 & 2**: Program names should be at least two characters, and options must be preceded by a hyphen (`-`).
* **Guideline 3 & 4**: Short options consist of a single alphanumeric character. Multiple single-character options without arguments may be clustered (e.g. `-jv` is identical to `-j -v`).
* **Guideline 5 & 6**: Options requiring arguments must receive them. Short options support both space-separated (`-p 8080`) and adjacent/glued (`-p8080`) syntax.
* **Guideline 7 & 8**: Long options are prefixed with two hyphens (`--`). Long options support both space-separated (`--port 8080`) and equals-separated (`--port=8080`) syntax.
* **Guideline 9**: All options must precede operands, or GNU argument permutation must reorder them predictably.
* **Guideline 10**: The special argument `--` strictly signals the end of all options; all subsequent arguments are treated exclusively as positional operands, preventing argument injection attacks.

---

### Part 5: Production Postmortems, ARM64 Limits & Kernel Vulnerabilities

Operating high-velocity eBPF tracing on Rocky Linux 9.8 aarch64 introduces specific architectural failure modes identified in enterprise production deployments:

#### 1. Cilium / Isovalent: Global LRU Spinlock Storms on ARM64 NUMA
* **Incident Scope**: Large-scale Kubernetes clusters running Cilium CNI under 100,000+ packets/sec experiencing soft lockups, kernel panics, and verifier load rejections during rolling upgrades.
* **Root Cause 1: LRU Map Lock Contention**:
  - `BPF_MAP_TYPE_LRU_HASH` maintains a single global LRU list protected by a raw kernel spinlock (`htab->lru_list.lock`).
  - Under high connection churn across 64+ ARM64 cores, every packet insertion contends for this single spinlock.
  - On multi-socket NUMA systems (AWS Graviton, Ampere Altra), lock cacheline bouncing across sockets spikes spinlock latency by 100x, triggering NMI watchdog soft lockups:
    `watchdog: BUG: soft lockup - CPU#12 stuck for 23s! [ksoftirqd/12:89]`.
* **Root Cause 2: Verifier Instruction Limit Regressions**:
  - In upgrading from kernel 5.4 to 5.10/5.14, the kernel verifier altered its jump branch pruning and state equivalence caching heuristics.
  - BPF programs exploring 85,000 instructions previously jumped to >1,000,000 instructions because register bounds desynchronized, causing container start rejections with `-E2BIG`.
* **Tracer Hardening**:
  - Pre-allocate slots and pre-size LRU maps to 2x peak expected concurrency.
  - Partition high-throughput aggregation structures into per-CPU arrays (`BPF_MAP_TYPE_PERCPU_ARRAY`).
  - Structure BPF C code into micro-modules under 4,000 instructions each ([progs/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/)).

#### 2. Cloudflare: Silent Driver XDP Fallback & MTU Limits
* **Incident Scope**: Cloudflare global edge network handling DDoS mitigation (Gatebot) and L4 load balancing (Unimog) experiencing massive packet drops and CPU saturation.
* **Root Cause 1: Silent Fallback to Generic SKB Mode**:
  - Native XDP (`XDP_FLAGS_DRV_MODE`) executes directly inside the network driver before `struct sk_buff` (SKB) allocation (>25M pps).
  - When interface configurations change (MTU updates, offload changes), native driver XDP can fail with `-EOPNOTSUPP`.
  - Silent fallback to Generic SKB mode (`XDP_FLAGS_SKB_MODE`) causes the kernel to allocate a full 256-byte `sk_buff` per packet, exhausting kernel slab memory (`kmem_cache_alloc`), driving `ksoftirqd` to 100%, and dropping 90% of traffic.
* **Root Cause 2: Single-Buffer MTU Truncation in Kernel 5.14**:
  - Rocky Linux 9.8 (Kernel 5.14) lacks multi-buffer XDP (`XDP_FLAGS_FRAGS`, upstream in 5.18+). Packets exceeding a single 4KB page (minus 256B headroom) cause driver drops or pointer truncation.
* **Tracer Hardening**:
  - [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L252-L279): Inspects XDP attachment return codes. When `-EOPNOTSUPP` is returned, logs an explicit operator advisory before transitioning to `XDP_FLAGS_SKB_MODE`.
  - Clean detachment logic handles both native links and generic SKB modes.
  - Boundary guards reject packets exceeding 3,500 bytes before attempting protocol parsing.

#### 3. Datadog / Pixie: ARM64 Uprobe Breakpoint TRAP Overhead
* **Incident Scope**: Continuous profiling agents attaching uprobes to microservices (Envoy, Go HTTP, NGINX) causing latency spikes from 2ms to 500ms and 100% CPU saturation.
* **Root Cause: The Mechanics of an ARM64 Uprobe Trap**:
  - To hook a user function, the kernel replaces the 4-byte instruction with `BRK #0` (opcode `0xd4200000`).
  - Execution triggers a hardware debug exception (`ESR_EL1` 0x3C), an EL0 (User) to EL1 (Kernel) context switch, saving all 31 general-purpose registers (X0-X30) onto the thread's kernel stack (`struct pt_regs`).
  - Execute-Out-Of-Line (XOL) copies the original instruction to a dedicated page, sets hardware single-stepping in `SPSR_EL1`, returns to EL0, executes one instruction, triggers a second exception back to EL1, clears single-stepping, and returns to EL0.
  - Latency cost: 3.5 to 8.0 microseconds per uprobe hit.
  - At 25,000 requests/sec with 4 probed functions: $25,000 \times 4 \times 6\,\mu\text{s} = 600,000\,\mu\text{s} = 0.60\,\text{CPU seconds per second}$. With worker threads, CPU saturates at 100% purely handling `el0_sync` traps.
  - Function returns (uretprobes) double this penalty by hijacking the Link Register (`LR` / `X30`).
* **Tracer Hardening**:
  - Implemented an in-kernel sliding-window rate limiter ([`uprobe_rate_limit_map`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L272)).
  - When call rate exceeds 10,000 calls/sec, event emission is throttled to preserve application CPU.
  - Maintained shadow stack depth balance (`call_depth++` / `call_depth--`) even under active throttling.

#### 4. Meta / Netflix: Kprobe Recursion Loops & Allocator Deadlocks
* **Incident Scope**: Production debugging tools attaching kprobes to networking routines (`kfree_skb`, `tcp_v4_rcv`) causing immediate kernel panics and deadlocks.
* **Root Cause 1: kfree_skb Recursion Loop**:
  - Attaching a kprobe to `kfree_skb`. When a packet drops, the kprobe fires.
  - The BPF program updates a non-preallocated map, invoking `kmem_cache_alloc`.
  - Under memory pressure, an allocation boundary fails, triggering `kfree_skb`.
  - The second `kfree_skb` hits the exact same kprobe on the same CPU core, repeating indefinitely until the 16KB ARM64 kernel stack overflows: `Kernel panic - not syncing: kernel stack overflow`.
* **Root Cause 2: Scheduler Lock Inversion Deadlock**:
  - Attaching a kprobe to scheduler routines (`finish_task_switch`) holding runqueue spinlock (`rq->lock`).
  - A user memory read page-faults and acquires `mm->mmap_lock`, creating an AB-BA lock inversion deadlock that halts the core.
* **Tracer Hardening**:
  - Implemented per-CPU recursion guards ([`kprobe_recursion_guard`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L279)).
  - Reentrant kprobe invocations immediately exit with `0`.
  - Probes strictly utilize pre-allocated maps and ring buffers.

#### 5. Cgroups v2 Memory Controller Accounting & BPF Map OOM Traps
* **Incident Scope**: eBPF daemons deployed in Kubernetes containers with memory limits (`resources.limits.memory: 256Mi`) killed by SIGKILL without error messages.
* **Root Cause**:
  - In Linux 5.14 (Rocky Linux 9.8), all BPF map allocations via `sys_bpf(BPF_MAP_CREATE)` carry `__GFP_ACCOUNT` and charge against the creating container's `memory.current`.
  - Large flow maps and ring buffers allocate over 120MB of unevictable kernel slab memory.
  - Under microburst traffic, container memory usage hits `memory.max`, triggering the cgroup OOM-killer.
* **Tracer Hardening**:
  - [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L62-L109): Inspects `/sys/fs/cgroup/memory.max` and `memory.current`.
  - If headroom is under 64MB, [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L201-L209) dynamically scales LRU maps from 65,536 to 2,048 entries before calling `bpf_prog_load()`.

#### 6. TCP RST Abrupt Teardown Leaking Unclosed Connection State
* **Incident Scope**: High-frequency microservices showing artificially inflated latencies (jumping from 50µs to 4 hours).
* **Root Cause**:
  - Abrupt connection resets bypass `tcp_close` and execute `tcp_reset()` -> `tcp_done()`, immediately switching socket state to `CLOSED` without FIN generation.
  - Tracers that only inspect FIN flags leave stale entries in `ingress_flow_map`.
  - When dynamic ephemeral ports recycle, new connections match dead keys, inheriting timestamps from hours prior.
* **Tracer Hardening**:
  - Added `FLAG_TCP_RST 0x04` extraction via `extract_tcp_flags()`.
  - Immediately evicts flow keys from `ingress_flow_map` upon detecting RST.
  - Background userspace TTL sweeper (`sweep_stale_flows()`) purges entries older than 30 seconds.

#### 7. Rocky Linux 9.8 aarch64 Kernel Vulnerabilities
* **CVE-2026-53036 (ARM64 BPF JIT Signed Range Check Off-by-One)**:
  - In `arch/arm64/net/bpf_jit_comp.c`, `check_imm(19, imm)` shifts by 19 bits. A positive displacement of +262,144 evaluates to 0, flipping a forward jump into a negative backward jump and inducing soft lockups.
  - Mitigated by structuring BPF logic into micro-modules under 4,000 instructions each ([progs/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/)).
* **CVE-2026-23383 (ARM64 BPF JIT Allocator Buffer Alignment Tearing)**:
  - The ARM64 BPF JIT allocator historically requested 4-byte alignment instead of 8-byte alignment, causing 64-bit target pointer addresses in `struct bpf_plt` to straddle cache line boundaries and tear during multi-core updates.
  - Mitigated by loading BPF modules statically at daemon boot and modulating tracing dynamically via `runtime_config_map`.

---

### Part 6: Concrete Defensive Hardening Implementations

The table of code implementations across the repository:

#### 1. ARM64 Memory Barrier & Weak Ordering Defense
* **Userspace**: [`tracer_daemon.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h#L65-L80) executes `__atomic_thread_fence(__ATOMIC_ACQUIRE)` upon ringbuffer event arrival, compiling to hardware instruction `dmb ishld` (opcode `d50339bf`). Sequence and drop counters use `__atomic_load_n` and `__atomic_store_n`.
* **Kernel & Handoff**: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L450-L459) and [`progs/kray_common.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L454-L461) enforce `asm volatile("dmb ish" ::: "memory")` on aarch64 and `barrier()` in BPF bytecode prior to updating `ring->write_idx`.

#### 2. XDP Driver Fallback to Generic SKB Mode
* **Implementation**: [`tracer_daemon.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L252-L279).
* **Behavior**: Detects `-EOPNOTSUPP` / `-EINVAL` on `bpf_program__attach_xdp()`, logs an advisory banner to `stderr`, and calls `bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL)`. Clean detachment executes `bpf_xdp_detach()`.

#### 3. Cgroups v2 Memory Headroom Guard
* **Implementation**: [`tracer_daemon.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L62-L109) and [`tracer_daemon.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L201-L209).
* **Behavior**: Evaluates available headroom (`memory.max - memory.current`). If < 64MB, scales high-memory LRU maps down to 2,048 entries before calling `bpf_prog_load()`.

#### 4. Adaptive Uprobe Rate-Limiting Guard
* **Implementation**: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1642-L1711) and [`progs/tracer_l7_uprobe.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c#L67-L86).
* **Behavior**: 1-second sliding window rate limiter in per-CPU array. Throttles event emission when call frequency exceeds 10,000 calls/sec while maintaining shadow stack depth counters.

#### 5. Kprobe Recursion Guard
* **Implementation**: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L761) and [`progs/kray_common.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L295-L308).
* **Behavior**: `kprobe_enter_guard()` checks per-CPU depth > 0; aborts reentrant calls immediately with `0`. `kprobe_exit_guard()` resets the guard.

#### 6. Immediate TCP RST Flow Eviction
* **Implementation**: [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L552-L565) and [`progs/tracer_l2_xdp.bpf.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c#L105-L118).
* **Behavior**: Detects `FLAG_TCP_RST (0x04)`, immediately deletes key from `ingress_flow_map`, and emits a teardown event.

---

### Part 7: Systematic Taxonomy of 8 Failure Modes & Boundary Analysis

#### FAIL-01: Root Privileges & Kernel BTF Preflight Check
* **Root Cause**: Unprivileged execution (`geteuid() != 0`) without `CAP_BPF` or missing `/sys/kernel/btf/vmlinux` causes cryptic errno codes (`-EPERM`, `-ENOENT`).
* **Mitigation**: `check_system_prerequisites()` intercepts missing privileges prior to libbpf calls, emits actionable remediation commands (`sudo krayctl trace` or `setcap`), and returns `EX_NOPERM (77)` or `EX_UNAVAILABLE (69)`.

#### FAIL-02: Microburst Ringbuffer Saturation & Event Loss
* **Root Cause**: Traffic bursts (>50,000 req/s) fill the kernel ring buffer, causing `bpf_ringbuf_reserve()` to return `NULL`.
* **Mitigation**: Monitors `ev->drop_count` deltas. Emits high-visibility alert banners on `stderr` and includes cumulative `"drops": N` in JSON telemetry.

#### FAIL-03: TCP Ephemeral Port Reuse (TIME_WAIT Collision) & SYN Epoch Rollover
* **Root Cause**: Rapid dynamic port recycling (32768~60999) causes new connections to inherit stale flow keys, corrupting start timestamps.
* **Mitigation**: Detects incoming TCP SYN flag (`ev->flags & 0x10`) on existing flow keys, increments the connection epoch, allocates a fresh `req_id`, and flushes stale timestamps.

#### FAIL-04: Stranded Orphan Flow Context Leak & Map Slot Starvation
* **Root Cause**: Clients crashing without transmitting FIN/RST leave orphaned entries in `ingress_flow_map`, eventually exhausting map capacity (65,536 entries).
* **Mitigation**: Userspace TTL sweeper `sweep_stale_flows()` runs every 5 seconds, evicting any flow idle for > 30 seconds via `bpf_map_get_next_key()`.

#### FAIL-05: Malformed, Truncated & Fuzzed Payloads (All 22 Protocols)
* **Root Cause**: Fuzzed, truncated, or malformed wire payloads throw unhandled Python exceptions (`struct.error`, `UnicodeDecodeError`), crashing the tracer.
* **Mitigation**: Universal `try/except Exception` boundary wraps all 22 parsers in [kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py), generating structured `[CORRUPTED_FRAME]` / `[TRUNCATED_FRAME]` frames with 0 crashes across 242 fuzzed vectors.

#### FAIL-06: Stripped Binaries & ASLR Relocation in L7 Uprobes
* **Root Cause**: Stripped production binaries lack `.symtab` symbols, and ASLR randomizes runtime addresses, causing Uprobe attachment to fail with `ENOENT`.
* **Mitigation**: `check_elf_stripped()` detects missing symbol tables and alerts operators to supply explicit file offsets (`-o / --offset`) or compile with `-g`.

#### FAIL-07: Thread Migration & 8-Slot Handoff Ring Wraparound
* **Root Cause**: Worker thread migration across CPU cores under lock contention causes the fixed 8-slot handoff ring to wrap around faster than workers claim tokens.
* **Mitigation**: Generation sequence tracking (`seq`) tags desynchronized slots with `FLAG_HANDOFF_DESYNC` and falls back to socket file descriptor context.

#### FAIL-08: IP Fragmentation & TSO/GSO Non-Linear SKB Buffer Truncation
* **Root Cause**: Intermediate IP fragments (`frag_offset > 0` or `MF` bit set) lack transport headers, causing naive parsers to misparse payload bytes as TCP flags.
* **Mitigation**: Inspects IPv4 `flags_frag` fields, tags non-initial fragments as `FLAG_IP_FRAGMENT`, and bypasses L4 header parsing.

---

### Part 8: Empirical 20-Iteration Reliability Verification Telemetry

The automated failure verification test suite [test_failure_conditions.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_failure_conditions.py) was executed across 20 continuous iterations (160 evaluations per environment):

#### Empirical Performance Telemetry
* **Local Host (macOS Darwin arm64)**:
  - Iterations: 20
  - Total Evaluated Tests: 160
  - Passed: 160 / 160 (100.0%)
  - Mean Iteration Latency: 1.26 ms (Min 1.12 ms, Max 1.66 ms, StdDev 0.18 ms)
  - Flake / Regression Rate: 0.0%
* **Target Linux VM (Rocky Linux 9.8 aarch64 - 5.14.0-687.10.1.el9_8.0.1)**:
  - Iterations: 20
  - Total Evaluated Tests: 160
  - Passed: 160 / 160 (100.0%)
  - Mean Iteration Latency: 1.19 ms (Min 1.10 ms, Max 1.47 ms, StdDev 0.08 ms)
  - Flake / Regression Rate: 0.0%
* **Structured Data**: Complete telemetry persisted in [references/failure_conditions_20_iterations_report.json](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/failure_conditions_20_iterations_report.json).

#### Complete Verification Status Across All 7 Test Suites
* **Michael Kerrisk CLI Standards ([test_cli_standards.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_cli_standards.py))**: **9 / 9 PASSED (100%)**
* **Failure Conditions 20 Iterations ([test_failure_conditions.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_failure_conditions.py))**: **160 / 160 PASSED (100%)**
* **Real Live Packet Wire Transmission ([test_live_packets.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_live_packets.py))**: **23 / 23 PASSED (100%)**
* **22-Protocol Data Frame Decode ([kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py))**: **22 / 22 PASSED (100%)**
* **Integration Verification Suite ([test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py))**: **24 / 24 PASSED (100%)**
* **Native Kernel BPF Selftests ([test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c))**: **7 / 7 PASSED (100%)**
* **Exhaustive 105-CLI Command Scenario Suite ([test_all_command_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_all_command_scenarios.py))**: **105 / 105 PASSED (100%, 55 test cases including Idempotency, Failure Recovery, Isolation, Sync & Doc Consistency)**
* **Grand Total**: **350 / 350 Tests Passed (100.0% Empirical Reliability Rate)**

---

### Part 9: Operator Runbook, CLI Quick Reference & Verification Proof

#### 1. Operator Command-Line Control (`krayctl`)
* **Status**: `krayctl status` (checks connectivity, kernel release, BTF, BPF JIT, cgroup memory limits).
* **Real-World Architectural Verifications (Beyond Language I/O APIs)**:
  - `krayctl verify list` (display all 5 real-world verification scenarios and language I/O blind spots).
  - `krayctl verify 1` (Scenario 1: Socket receive queue `sk_rcvbuf` dwell vs GC/EventLoop delay; add `--live` to run on VM).
  - `krayctl verify 2` (Scenario 2: Epoll listener to worker pool Futex & OS runqueue handoff tax; add `--live` to run on VM).
  - `krayctl verify 3` (Scenario 3: Pure On-CPU ALU compute vs Off-CPU preemption separation; add `--live` to run on VM).
  - `krayctl verify 4` (Scenario 4: Kernel-to-user buffer copy `skb_copy_datagram_iter`, page faults & block I/O; add `--live` to run on VM).
  - `krayctl verify 5` (Scenario 5: Egress blindness, per-request `kfree_skb` drop reason & TCP retransmit; add `--live` to run on VM).
* **Live Tracing**:
  - `krayctl trace` (view all 7 layers end-to-end).
  - `krayctl trace -L 4` (isolate L4 transport and drops).
  - `krayctl trace -L 6` (isolate L6 scheduler handoff).
  - `krayctl trace -j` (output machine-readable JSON lines stream).
* **Testing**:
  - `krayctl test` (execute 23/23 real packet experiments).
  - `krayctl test failure` (execute 8/8 failure conditions suite).
  - `krayctl test --cli` (execute 9/9 Michael Kerrisk TLPI standards suite).
  - `krayctl test --scenarios` (execute exhaustive 105 CLI command scenario matrix).
  - `krayctl test --suite` (execute full 24-suite integration test).
  - `krayctl test failure -r` (execute failure suite remotely on Rocky Linux 9.8 VM).
* **Protocol Inspector**:
  - `krayctl proto list` (display 22 supported protocols).
  - `krayctl proto ports` (display 4 port categories: Non-IP, 0..1023, 1024..49151, Ephemeral).
  - `krayctl proto ieee` (display IEEE 802.11 / 802.15.1 / 802.1Q standards reference).
  - `krayctl proto test` (run 22/22 protocol decode verification).
  - `krayctl proto inspect <proto>` (inspect bit-exact packet tree and hex dump for any of the 22 protocols).
* **Compilation & Sync**:
  - `krayctl build` (compile BPF modules, skeletons, mock binaries, daemon on target VM).
  - `krayctl sync` (rsync workspace files to target VM).
  - `krayctl selftest` (run native C BPF skeleton selftests on target VM).

#### 2. One-Click Empirical Verification Commands (`Zero-.sh` Python Control Plane)
All shell scripts (`.sh` and `/bin/sh`) have been replaced with modular Python execution (`shell=False` / `execve`) via [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl), [kray/host_ops.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/host_ops.py), and [kray/remote_target.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py).

To verify every single claim and architectural invariant on the live Rocky Linux 9.8 aarch64 kernel, run:

```bash
./krayctl claims
```

To run all 7 test suites across the repository in sequence:

```bash
./krayctl run-all
```

---

### Part 10: Authoritative Standards & Reference Code Traceability Catalog

Every module, header, algorithm, and defense mechanism in this codebase is directly traceable to upstream Linux kernel source files, authoritative systems programming literature, industry postmortems, or formal networking RFCs.

#### 1. Systems Programming & CLI Architecture References
* **Michael Kerrisk, *The Linux Programming Interface* (TLPI)**:
  - Chapter 56 (Sockets: Introduction): Socket APIs, BSD domain sockets (`AF_UNIX`), network protocol numbers (`IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_ICMP`), and network byte order conversion helpers.
    * Source Mapping: [progs/kray_common.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L67-L89), [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L1-L35)
  - Chapter 63 (Alternative I/O Models & Epoll): Event-loop architecture, epoll edge/level trigger mechanics, worker thread pool dispatching, and inter-thread context handoff.
    * Source Mapping: [progs/tracer_l6_sched.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l6_sched.bpf.c#L13-L50), [mock_server.cpp](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp)
  - Appendix B (Command-Line Options & `getopt_long(3)`): Strict option parsing conventions, option string leading-colon (`":p:t:L:i:b:o:jvVh"`) for error code discrimination, and end-of-options delimiter (`--`).
    * Source Mapping: [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L60-L165), [daemon/daemon_types.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_types.h)
  - Local Specification Document: [cli-argument-standards-and-conventions.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
* **POSIX IEEE Std 1003.1-2017 & BSD `<sysexits.h>`**:
  - Utility Syntax Guidelines 1 through 13: Option argument separation, single-letter clustering, long options, unbuffered diagnostic stream separation.
  - Standard Process Exit Codes: `EX_OK (0)` for success/help, `EX_USAGE (64)` for syntax errors, `EX_UNAVAILABLE (69)` for missing BTF, `EX_NOPERM (77)` for permission errors.
    * Source Mapping: [daemon/daemon_preflight.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h), [test_cli_standards.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_cli_standards.py#L13-L18)

#### 2. Upstream Linux Kernel & Selftests Architecture
* **Linux Upstream BPF Selftests (`tools/testing/selftests/bpf`)**:
  - Test Runner Harness: [test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c) mirrors upstream `test_progs.c` with skeleton loading, map auto-attach suppression, and programmatic verification.
    * Local Reference: [references/upstream-kernel-bpf-docs/selftests](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/upstream-kernel-bpf-docs/selftests/)
  - XDP Parsing & VLAN Unrolling: [test_xdp_vlan.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/upstream-kernel-bpf-docs/selftests/) informs the dual-tag unrolling in [progs/tracer_l2_xdp.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c#L26-L36).
  - VM Automated Control & Sync Modules: [kray/host_ops.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/host_ops.py) and [kray/remote_target.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/remote_target.py) replace legacy shell scripts with `shell=False` remote compilation, artifact syncing, and headless verification.
* **Modern BPF CO-RE & Libbpf-Bootstrap**:
  - Ring Buffer Consumer & Skeleton Lifecycle: [bootstrap.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/libbpf-bootstrap/examples/c/bootstrap.c#L115-L165) provides the basis for `ring_buffer__new` and `ring_buffer__poll` in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L298-L325) and [daemon/daemon_formatter.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h).
  - Uprobe Attachment & Binary Offset: [uprobe.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/libbpf-bootstrap/examples/c/uprobe.c) provides the basis for userspace symbol probing in [progs/tracer_l7_uprobe.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c).

#### 3. Target Host Kernel Release & BTF Types (Rocky Linux 9.8 aarch64)
* **Kernel Tree**: `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`
  - SKB Ingress & Network Core: [net/core/dev.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/) defines `netif_receive_skb` and `net_dev_xmit`.
  - TCP Protocol Engine: [net/ipv4/tcp.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/) defines `tcp_v4_rcv`, `tcp_recvmsg`, `__tcp_transmit_skb`, and TCP drop reasons.
  - Scheduler Core: [kernel/sched/core.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/) defines `sched_wakeup`, `sched_switch`, and runqueue wait semantics.
  - BTF Type Relocations: Header repository [references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/) provides full kernel type layouts.

#### 4. Production Postmortems & Defensive Hardening Specifications
* **Reference Document**: [ebpf-production-postmortems-and-arm64-limits.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
  - CrowdStrike 2024 Null Pointer & RingBuffer Boundary: Interception of null map pointers and ring buffer drop alert banner in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h#L127-L140).
  - Datadog / Meta Verifier Limits & LRU Cache Churn: BPF zero-template allocation and periodic TTL sweep in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_sweeper.h#L25-L55).
  - Cloudflare / Cilium XDP Driver Fallback: Automatic fallback from Native Driver Mode to Generic SKB Mode (`XDP_FLAGS_SKB_MODE`) in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L252-L279).
  - Container Cgroups v2 Memory Headroom Guard: Detection of memory headroom `< 64MB` to dynamically scale map entries and prevent container OOM in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L62-L109).
  - ARM64 Weakly Ordered Memory Barrier: Hardware memory fence `__atomic_thread_fence(__ATOMIC_ACQUIRE)` in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h#L65-L80) and ARM64 `BRK #0x004` software breakpoint trapping awareness.

#### 5. RFC & IEEE Communication Protocols Specifications
* **Hardware & Data Link Standards**:
  - IEEE 802.3: Standard Ethernet MAC Frame Framing.
  - IEEE 802.1Q & IEEE 802.1ad: VLAN Single & QinQ Double Tagging (EtherTypes `0x8100`, `0x88A8`, `0x9100`).
  - IEEE 802.11 a/b/g/n/ac/ax/be: Wireless LAN Medium Access Control (MAC) Frame.
  - IEEE 802.15.1: Bluetooth HCI & L2CAP Basic Framing.
  - RFC 826: Ethernet Address Resolution Protocol (ARP).
* **Network & Transport Layer RFCs**:
  - RFC 791: Internet Protocol Version 4 (IPv4) Specification.
  - RFC 8200: Internet Protocol Version 6 (IPv6) Specification.
  - RFC 792: Internet Control Message Protocol (ICMPv4).
  - RFC 4443: Internet Control Message Protocol (ICMPv6).
  - RFC 793: Transmission Control Protocol (TCP) State Machine & Flags.
  - RFC 768: User Datagram Protocol (UDP).
* **Application, Storage & Middleware Standards**:
  - RFC 7230 / RFC 9112: Hypertext Transfer Protocol (HTTP/1.1).
  - RFC 9113: Hypertext Transfer Protocol Version 2 (HTTP/2) & gRPC Framing.
  - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3.
  - RFC 6455: The WebSocket Protocol.
  - RFC 1035: Domain Names - Implementation and Specification (DNS).
  - RFC 4253: The Secure Shell (SSH) Transport Layer Protocol.
  - RFC 5905: Network Time Protocol Version 4 (NTP).
  - RFC 1813 / RFC 7530: Network File System (NFSv3 / NFSv4) SunRPC Protocol.
  - MS-SMB2 / RFC 7143: Server Message Block (SMB2/3) & iSCSI Block Storage (BHS).
  - RESP 2 / RESP 3: REdis Serialization Protocol Specification.
  - MySQL 4.1+: Client/Server Wire Protocol (Length + Sequence ID + COM_QUERY).
  - PostgreSQL 3.0: Frontend/Backend Protocol Specification.
  - Apache Kafka: Binary Request/Response Protocol Specification.
  - OASIS MQTT 3.1.1 / 5.0: Message Queuing Telemetry Transport.

---

### Part 11: Exhaustive CLI Command Scenario Guide & Empirical Verification Proof

The system provides complete, deterministic CLI behavior across all operational scenarios. Every single command scenario below has been implemented in the test harness [test_all_command_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_all_command_scenarios.py) and empirically validated on the live Rocky Linux 9.8 aarch64 kernel.

#### 1. Group 1: Global Help & Version Options (8 Scenarios)
* **Scenario 1: Bare `krayctl`**
  - Command: `krayctl`
  - Input Precondition: Executed with zero command-line arguments.
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives full usage banner and synopsis.
  - Status: **PASSED**
* **Scenario 2: Short Help Flag `-h`**
  - Command: `krayctl -h`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives top-level help text.
  - Status: **PASSED**
* **Scenario 3: Long Help Flag `--help`**
  - Command: `krayctl --help`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives top-level help text.
  - Status: **PASSED**
* **Scenario 4: Help Subcommand `help`**
  - Command: `krayctl help`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives top-level help text.
  - Status: **PASSED**
* **Scenario 5: Short Version Flag `-v`**
  - Command: `krayctl -v`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives version string and copyright notice.
  - Status: **PASSED**
* **Scenario 6: Uppercase Version Flag `-V`**
  - Command: `krayctl -V`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives version string.
  - Status: **PASSED**
* **Scenario 7: Long Version Flag `--version`**
  - Command: `krayctl --version`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives version string.
  - Status: **PASSED**
* **Scenario 8: Subcommand Version `version`**
  - Command: `krayctl version`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives version string.
  - Status: **PASSED**

#### 2. Group 2: Contextual Help Subcommands (`krayctl help <subcmd>`) (6 Scenarios)
* **Scenario 9: Help Status**
  - Command: `krayctl help status`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives dedicated `krayctl-status` help.
  - Status: **PASSED**
* **Scenario 10: Help Test**
  - Command: `krayctl help test`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives dedicated `krayctl-test` help.
  - Status: **PASSED**
* **Scenario 11: Help Trace**
  - Command: `krayctl help trace`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives dedicated `krayctl-trace` help.
  - Status: **PASSED**
* **Scenario 12: Help Proto**
  - Command: `krayctl help proto`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives dedicated `krayctl-proto` help.
  - Status: **PASSED**
* **Scenario 13: Help Selftest**
  - Command: `krayctl help selftest`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives dedicated `krayctl-selftest` help.
  - Status: **PASSED**
* **Scenario 14: Help Install**
  - Command: `krayctl help install`
  - Expected Exit Code: `0 (EX_OK)`
  - Output Stream: `stdout` receives dedicated `krayctl-install` help.
  - Status: **PASSED**

#### 3. Group 3: Subcommand Help Flags (`<cmd> -h` / `--help`) (8 Scenarios)
* **Scenario 15: Status Help Flag**
  - Command: `krayctl status -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 16: Test Help Flag**
  - Command: `krayctl test -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 17: Trace Help Flag**
  - Command: `krayctl trace -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 18: Proto Help Flag**
  - Command: `krayctl proto -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 19: Selftest Help Flag**
  - Command: `krayctl selftest -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 20: Sync Help Flag**
  - Command: `krayctl sync -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 21: Build Help Flag**
  - Command: `krayctl build -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**
* **Scenario 22: Install Help Flag**
  - Command: `krayctl install -h`
  - Expected Exit Code: `0 (EX_OK)` | Status: **PASSED**

#### 4. Group 4: Local Operational Subcommands (inspect, proto) (5 Scenarios)
* **Scenario 23: Native Tool Inspection Cheatsheet**
  - Command: `krayctl inspect`
  - Expected Exit Code: `0 (EX_OK)`
  - Output: `stdout` displays bpftool, ss, ip, and curl operator commands.
  - Status: **PASSED**
* **Scenario 24: Protocol Catalog Listing**
  - Command: `krayctl proto list`
  - Expected Exit Code: `0 (EX_OK)`
  - Output: `stdout` lists all 22 supported protocols across OSI L2 through L7.
  - Status: **PASSED**
* **Scenario 25: Four-Tier Port Category Inventory**
  - Command: `krayctl proto ports`
  - Expected Exit Code: `0 (EX_OK)`
  - Output: `stdout` outputs systematic categorization into Non-IP/L2, Well-Known (0..1023), Registered (1024..49151), and Dynamic/Ephemeral (49152..65535).
  - Status: **PASSED**
* **Scenario 26: IEEE Standards Guide**
  - Command: `krayctl proto ieee`
  - Expected Exit Code: `0 (EX_OK)`
  - Output: `stdout` displays comprehensive guide to IEEE 802.3, 802.1Q, 802.11, and 802.15.1.
  - Status: **PASSED**
* **Scenario 27: Protocol Decode Verification Test**
  - Command: `krayctl proto test`
  - Expected Exit Code: `0 (EX_OK)`
  - Output: `stdout` verifies bit-exact frame decode across 22/22 protocols.
  - Status: **PASSED**

#### 5. Group 5: All 22 Individual Protocol Inspections (22 Scenarios)
Each scenario executes `krayctl proto inspect <proto>`, decoding synthetic wire frames into Wireshark-style hierarchical trees and canonical hex dumps:
* **Scenario 28**: `krayctl proto inspect wifi` (IEEE 802.11 MAC Frame) -> `0 (EX_OK)` | **PASSED**
* **Scenario 29**: `krayctl proto inspect bluetooth` (IEEE 802.15.1 HCI/L2CAP) -> `0 (EX_OK)` | **PASSED**
* **Scenario 30**: `krayctl proto inspect vlan` (IEEE 802.1Q Tagged Frame) -> `0 (EX_OK)` | **PASSED**
* **Scenario 31**: `krayctl proto inspect arp` (RFC 826 Address Resolution) -> `0 (EX_OK)` | **PASSED**
* **Scenario 32**: `krayctl proto inspect icmp` (RFC 792 Echo Request) -> `0 (EX_OK)` | **PASSED**
* **Scenario 33**: `krayctl proto inspect unix` (AF_UNIX SCM_CREDENTIALS) -> `0 (EX_OK)` | **PASSED**
* **Scenario 34**: `krayctl proto inspect ftp` (RFC 959 File Transfer Protocol) -> `0 (EX_OK)` | **PASSED**
* **Scenario 35**: `krayctl proto inspect ssh` (RFC 4253 SSH-2.0 Banner) -> `0 (EX_OK)` | **PASSED**
* **Scenario 36**: `krayctl proto inspect dns` (RFC 1035 UDP Query) -> `0 (EX_OK)` | **PASSED**
* **Scenario 37**: `krayctl proto inspect http1` (RFC 7230 GET Request) -> `0 (EX_OK)` | **PASSED**
* **Scenario 38**: `krayctl proto inspect ntp` (RFC 5905 Time Protocol) -> `0 (EX_OK)` | **PASSED**
* **Scenario 39**: `krayctl proto inspect tls` (RFC 8446 TLS 1.3 ClientHello) -> `0 (EX_OK)` | **PASSED**
* **Scenario 40**: `krayctl proto inspect smb` (SMB2/SMB3 Negotiate Protocol) -> `0 (EX_OK)` | **PASSED**
* **Scenario 41**: `krayctl proto inspect mqtt` (MQTT v3.1.1 CONNECT Packet) -> `0 (EX_OK)` | **PASSED**
* **Scenario 42**: `krayctl proto inspect nfs` (RFC 1813 NFSv3 SunRPC Call) -> `0 (EX_OK)` | **PASSED**
* **Scenario 43**: `krayctl proto inspect iscsi` (RFC 7143 iSCSI 48-byte BHS) -> `0 (EX_OK)` | **PASSED**
* **Scenario 44**: `krayctl proto inspect mysql` (MySQL COM_QUERY Wire Frame) -> `0 (EX_OK)` | **PASSED**
* **Scenario 45**: `krayctl proto inspect postgres` (PostgreSQL StartupMessage) -> `0 (EX_OK)` | **PASSED**
* **Scenario 46**: `krayctl proto inspect redis` (RESP Array *2 $4 PING) -> `0 (EX_OK)` | **PASSED**
* **Scenario 47**: `krayctl proto inspect kafka` (Kafka Metadata Request) -> `0 (EX_OK)` | **PASSED**
* **Scenario 48**: `krayctl proto inspect grpc` (gRPC HTTP/2 POST Stream) -> `0 (EX_OK)` | **PASSED**
* **Scenario 49**: `krayctl proto inspect http2` (RFC 9113 Connection Preface & HEADERS) -> `0 (EX_OK)` | **PASSED**

#### 6. Group 6: Error & Boundary Argument Handling (2 Scenarios)
* **Scenario 50: Unknown Subcommand**
  - Command: `krayctl nonexistent_cmd`
  - Expected Exit Code: `2 (EX_CLI_INVALID_CMD)`
  - Output Stream: `stderr` prints error message and remediation hint. `stdout` is empty.
  - Status: **PASSED**
* **Scenario 51: Unknown Top-Level Flag**
  - Command: `krayctl --nonexistent-option`
  - Expected Exit Code: `2 (EX_CLI_INVALID_CMD)`
  - Output Stream: `stderr` prints error message. `stdout` is empty.
  - Status: **PASSED**

#### 7. Group 7: Direct `tracer_daemon` CLI Standards & POSIX Guidelines (26 Scenarios)
Direct execution of `./tracer_daemon` on Rocky Linux 9.8 aarch64:
* **Scenario 52**: Short Help `./tracer_daemon -h` -> `0 (EX_OK)` on `stdout`, 0 bytes on `stderr` | **PASSED**
* **Scenario 53**: Long Help `./tracer_daemon --help` -> `0 (EX_OK)` on `stdout`, 0 bytes on `stderr` | **PASSED**
* **Scenario 54**: Short Version `./tracer_daemon -V` -> `0 (EX_OK)` on `stdout`, 0 bytes on `stderr` | **PASSED**
* **Scenario 55**: Long Version `./tracer_daemon --version` -> `0 (EX_OK)` on `stdout`, 0 bytes on `stderr` | **PASSED**
* **Scenarios 56..61: Missing Required Arguments**:
  - Missing port argument: `./tracer_daemon -p` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Missing PID argument: `./tracer_daemon -t` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Missing layer argument: `./tracer_daemon -L` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Missing iface argument: `./tracer_daemon -i` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Missing binary argument: `./tracer_daemon -b` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Missing offset argument: `./tracer_daemon -o` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
* **Scenarios 62 & 63: Unrecognized Options**:
  - Unrecognized short flag: `./tracer_daemon -z` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Unrecognized long flag: `./tracer_daemon --invalid-option` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
* **Scenarios 64..67: Out-of-Range Port and Layer Numerical Values**:
  - Port overflow: `./tracer_daemon -p 99999` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Negative port: `./tracer_daemon -p -1` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Non-numeric port: `./tracer_daemon -p nonnum` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Negative PID: `./tracer_daemon -t -10` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Layer underflow: `./tracer_daemon -L 0` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Layer overflow: `./tracer_daemon -L 8` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
  - Invalid layer name: `./tracer_daemon -L invalid_layer` -> `64 (EX_USAGE)` on `stderr`, 0 bytes on `stdout` | **PASSED**
* **Scenario 68: Option Clustering & Absolute Stream Separation**:
  - Clustered flags: `./tracer_daemon -jv` executed as non-root user.
  - Return Code: `77 (EX_NOPERM)`.
  - Stream Validation: `stdout` is exactly 0 bytes; `stderr` receives structured JSON error frame `{"error":"EPERM",...}`.
  - Status: **PASSED**
* **Scenario 69: End-of-Options Delimiter (`--`)**:
  - Command: `./tracer_daemon -- -p 80`
  - Behavior: Delimiter `--` terminates option processing; `-p` and `80` are treated as non-option arguments; daemon advances to preflight privilege check.
  - Return Code: `77 (EX_NOPERM)` for non-root execution.
  - Status: **PASSED**
* **Scenarios 70..81: Valid Layer Names Parsing**:
  - Named layers: `./tracer_daemon -L l2`, `-L xdp`, `-L l3`, `-L ip`, `-L l4`, `-L tcp`, `-L l5`, `-L socket`, `-L l6`, `-L sched`, `-L l7`, `-L uprobe`.
  - Behavior: All 12 layer aliases parse cleanly without argument error, advancing to preflight check.
  - Return Code: `77 (EX_NOPERM)` for non-root execution.
  - Status: **PASSED**

#### 8. Group 8: Live Operational VM Scenarios (2 Scenarios)
* **Scenario 82: Remote Target VM Status Check**
  - Command: `krayctl status`
  - Behavior: Connects over SSH to Rocky Linux 9.8 aarch64, queries kernel release, BTF availability, BPF JIT status, Clang version, and Cgroups v2 memory limits.
  - Return Code: `0 (EX_OK)`
  - Status: **PASSED**
* **Scenario 83: Remote Kernel BPF Skeleton Selftests**
  - Command: `krayctl selftest`
  - Behavior: Executes native C test runner `test_progs` on target VM, validating all 7 BPF skeletons (`tracer_l2_xdp`, `tracer_l3_ip`, `tracer_l4_tcp`, `tracer_l5_syscall`, `tracer_l6_sched`, `tracer_l7_uprobe`, `tracer_kernel`).
  - Return Code: `0 (EX_OK)`
  - Verification: `7/7 PASSED (100% VERIFIED)`
  - Status: **PASSED**

#### 9. Group 9: Real-World I/O & Kernel Verification Scenarios (`krayctl verify`) (8 Scenarios)
* **Scenario 84: Contextual Help `krayctl help verify`**
  - Command: `krayctl help verify` -> `0 (EX_OK)` on `stdout` (`krayctl-verify` synopsis) | **PASSED**
* **Scenario 85: Subcommand Help Flag `krayctl verify -h`**
  - Command: `krayctl verify -h` -> `0 (EX_OK)` on `stdout` | **PASSED**
* **Scenario 86: Verification Catalog `krayctl verify list`**
  - Command: `krayctl verify list` -> `0 (EX_OK)`, outputs the 4 high-level I/O API blind spots and 5 verification scenarios | **PASSED**
* **Scenario 87: Verification Scenario 1 (`krayctl verify 1` / `ingress`)**
  - Command: `krayctl verify 1` -> `0 (EX_OK)`, verifies Socket Receive Buffer (`sk_rcvbuf`) dwell time (`dwell_ns`) blueprint | **PASSED**
* **Scenario 88: Verification Scenario 2 (`krayctl verify 2` / `handoff`)**
  - Command: `krayctl verify 2` -> `0 (EX_OK)`, verifies Epoll-to-Worker Futex & OS Runqueue handoff tax blueprint | **PASSED**
* **Scenario 89: Verification Scenario 3 (`krayctl verify 3` / `offcpu`)**
  - Command: `krayctl verify 3` -> `0 (EX_OK)`, verifies Pure On-CPU ALU vs Off-CPU preemption separation blueprint | **PASSED**
* **Scenario 90: Verification Scenario 4 (`krayctl verify 4` / `mm`)**
  - Command: `krayctl verify 4` -> `0 (EX_OK)`, verifies Kernel-to-User copy (`skb_copy_datagram_iter`), page faults & block I/O blueprint | **PASSED**
* **Scenario 91: Verification Scenario 5 (`krayctl verify 5` / `drops`)**
  - Command: `krayctl verify 5` -> `0 (EX_OK)`, verifies Egress blindness, per-request `kfree_skb` drop reason & TCP retransmit blueprint | **PASSED**

#### 10. Group 10: Idempotency, Failure Recovery, Isolation, Synchronization & Documentation Consistency (14 Scenarios)
* **Scenarios 92..97: Full Help Parity Across Remaining Subcommands (`chaos`, `dashboard`, `inspect`, `uninstall`, `sync`, `build`)**:
  - Both `<cmd> -h` and `krayctl help <cmd>` return `0 (EX_OK)` on `stdout` across all 6 subcommands | **PASSED**
* **Scenario 98: Idempotency of `install` and `uninstall`**:
  - Back-to-back `krayctl uninstall --user` (even when symlink is absent) and back-to-back `krayctl install --user` return `0 (EX_OK)` deterministically without error | **PASSED**
* **Scenario 99: Idempotency of `sync` and Remote Compiled Artifact Preservation**:
  - Back-to-back `krayctl sync` ([kray/host_ops.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray/host_ops.py)) synchronizes source changes while preserving remote `tracer_daemon`, `test_progs`, `tracer_kernel_bpf.o`, and `tracer_kernel.skel.h` | **PASSED**
* **Scenario 100: Failure Recovery from `SIGKILL` (`kill -9`) via Pre-flight Orphan XDP Guardian**:
  - Forcibly killing `tracer_daemon -p 8080 -i lo` with `SIGKILL` leaves Generic XDP on `lo`; subsequent `tracer_daemon -p 8080 -i lo` automatically flushes the residual XDP link (`bpf_xdp_detach`), re-attaches cleanly without `-EBUSY`, and detaches on exit | **PASSED**
* **Scenario 101: Failure Recovery on Non-Existent Network Interface (`-i nonexistent_nic0`)**:
  - Emits explicit warning on `stderr` and continues tracing remaining kprobe/tracepoint layers without aborting | **PASSED**
* **Scenario 102: Failure Recovery on Invalid `verify` Scenario Followed by Valid Execution**:
  - `krayctl verify invalid_scenario_name` exits `2` with diagnostic on `stderr` and `0` bytes on `stdout`; subsequent `krayctl verify 1` exits `0 (EX_OK)` | **PASSED**
* **Scenario 103: Layer Isolation in Kernel Selftests (`l2`, `l4`, `l6`)**:
  - Individual skeleton tests (`sudo ./test_progs l2`, `l4`, `l6`) execute in strict isolation (`1/1 PASSED`) without cross-layer interference | **PASSED**
* **Scenario 104: Stream Isolation in Live JSON Mode (`tracer_daemon -j`)**:
  - Live HTTP traffic capture under `-j` emits 100% pure JSON Lines (`{"req_id":...}`) on `stdout` with zero banner or diagnostic pollution | **PASSED**
* **Scenario 105: Automated Documentation Consistency & Clickable Link Verification**:
  - Programmatically verifies that [README.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md) contains all 10 consolidated Books, all 5 verification scenarios, and that 100% of `file://` links and `#L` line anchors resolve within bounds on disk | **PASSED**
* **Scenario 106: Production ELF `.symtab` & `.dynsym` Symbol Auto-Resolution (`-s / --symbol`)**:
  - Resolves C++ mangled function symbols from `.symtab` (`-b ./mock_server -s execute_storage_query`) and exported dynamic symbols from stripped shared libraries via `.dynsym` (`-b ./libcrypto_mock.so -s verify_request_token`), while rejecting nonexistent symbols with `65 (EX_DATAERR)` | **PASSED**
* **Scenario 107: Selective Kernel Layer Attachment (`-L` Overhead Isolation)**:
  - Passing `-L 4` bypasses attaching the 6 high-frequency L6 scheduler/futex kernel tracepoints (`sched/*`, `sys_enter_futex`, `sys_exit_futex`), eliminating global context-switch probe overhead on production servers | **PASSED**
* **Scenarios 108..110: Fail-Safe Bounded Execution (`-d`, `-c`, `SIGHUP`), Tail-Latency Filter (`-m`), and Automated Bottleneck Verdict**:
  - Enforces exact event cap (`-c 3`), auto-detach duration (`-d 4`), tail-latency microsecond validation (`-m`), and emits the `[PRODUCTION DIAGNOSTIC SUMMARY & BOTTLENECK VERDICT]` table with `[VERDICT] Primary Bottleneck:` on `stderr` upon exit | **PASSED**

#### 11. Empirical Test Suite Execution Summary
* **Test Script**: [test_all_command_scenarios.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_all_command_scenarios.py)
* **Execution Command**: `./krayctl test --scenarios` or `python3 test_all_command_scenarios.py`
* **Test Units**: 58 discrete test methods covering all 110 command scenarios
* **Failures**: 0
* **Errors**: 0
* **Success Rate**: **100.0% (110 / 110 Scenarios Empirically Verified)**


---

# [Book VI] CLI 아규먼트 벡터 표준 및 관례 (Michael Kerrisk TLPI & POSIX CLI Standards)

# CLI Command and Argument Architecture Standards & Conventions
# Grounded in Michael Kerrisk's 'The Linux Programming Interface' (TLPI) & Linux man-pages Standards
# Comprehensive Reference Guide for Systems Programming, Utilities, and krayctl Architecture

## 1. Architectural Foundations & The Michael Kerrisk Paradigm

In Linux systems software engineering, command-line interfaces (CLIs) are not merely user input wrappers; they represent the primary programmatic contract between the operating system kernel, the runtime environment, shell orchestrators, and system operators. As Michael Kerrisk establishes in *The Linux Programming Interface* (TLPI), predictable, robust, and standards-compliant command-line interfaces are foundational to the reliability of the entire Unix ecosystem.

### Core Tenets of Kerrisk's Philosophy
* Strict Standards Conformance: Adherence to IEEE Std 1003.1 (POSIX) and GNU Coding Standards guarantees that software behaves predictably across different distributions, shells, and automation environments.
* Deterministic Argument Vector Parsing: Command-line options and operands must be parsed using standard library mechanisms (`getopt`, `getopt_long`) rather than ad-hoc string splitting, ensuring consistent handling of clustering, delimiters, and edge cases.
* Total Stream Separation: Standard output (`stdout`) and standard error (`stderr`) serve orthogonal architectural purposes; data streams and diagnostic messages must never collide.
* Machine-Actionable Exit Taxonomy: Processes must communicate precise failure modes back to parent processes and orchestrators using standardized status codes (such as BSD `<sysexits.h>`).
* Discoverability and Man-Page Parity: The inline command help, usage synopses, and manual pages must adhere to the formatting conventions of the Linux man-pages project (maintained for over a decade by Michael Kerrisk), providing unambiguous visual semantics.

---

## 2. Kernel-to-Userspace Argument Vector Architecture (TLPI Chapter 6 & Chapter 24)

### Process Creation and Argument Vector Delivery
When a process executes another binary via the `execve(2)` system call:

```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

The Linux kernel constructs the new process's address space. It copies the array of null-terminated strings (`argv`) and the environment strings (`envp`) into the highest memory addresses of the user-space stack:

* Stack Layout: The initial stack frame is populated with `argc` (argument count), followed by `argv` (an array of pointers to null-terminated C strings terminated by a `NULL` pointer), followed by `envp` (an array of pointers to environment variable strings terminated by a `NULL` pointer), followed by the ELF Auxiliary Vector (`auxv_t`).
* Program Entrypoint: The C runtime startup code (`crt1.o` / `__libc_start_main`) extracts these stack elements and passes them directly to the application entrypoint:
  ```c
  int main(int argc, char *argv[])
  ```
* Vector Invariants:
  - `argv[0]` by convention contains the binary name or path used to invoke the program.
  - `argv[1]` through `argv[argc - 1]` contain the command-line tokens passed by the invoking shell or parent process.
  - `argv[argc]` is guaranteed by the ISO C standard to be a `NULL` pointer.
* Kernel Visibility (`/proc/[pid]/cmdline`): The Linux kernel exposes this vector in `/proc/[pid]/cmdline` as a sequence of null-byte-separated strings. Adherence to POSIX parameter rules preserves clear boundaries when kernel inspection tools (`ps`, `systemd`, `bpftool`) inspect running processes.

---

## 3. Command-Line Options Parsing: getopt and GNU getopt_long (TLPI Appendix B)

In TLPI Appendix B (*Parsing Command-Line Options*), Michael Kerrisk provides an exhaustive analysis of standard option parsing techniques in C systems software.

### The POSIX getopt(3) Engine
The `getopt(3)` function defined in `<unistd.h>` is the standard POSIX interface for parsing single-character options:

```c
#include <unistd.h>

int getopt(int argc, char * const argv[], const char *optstring);
```

#### Global State Variables
* `optarg`: A `char *` pointing to the value of the option-argument when an option requires or accepts an argument.
* `optind`: An `int` storing the index of the next element in `argv` to be processed. Upon initial invocation, it is initialized to 1. When `getopt()` finishes, `optind` indexes the first positional operand.
* `opterr`: An `int` acting as a boolean flag. If non-zero (the default), `getopt()` automatically prints an error message to `stderr` upon encountering an unrecognized option or missing option-argument.
* `optopt`: An `int` holding the unrecognized or invalid option character when `getopt()` detects a parsing error.

#### The optstring Grammar and Error Suppression
* Regular Option: An alphanumeric character in `optstring` indicates a flag taking no argument (e.g., `"v"`).
* Mandatory Argument: A character followed by a single colon (`:`) indicates the option requires an argument (e.g., `"p:"`).
* GNU Optional Argument: A character followed by two colons (`::`) is a GNU extension indicating an optional argument. The argument must be supplied immediately adjacent to the option letter in the same `argv` token (e.g., `-oARG`).
* Leading Colon for Precise Error Discrimination:
  - If `optstring` begins with a colon (e.g., `":p:L:jvh"`), default error messages to `stderr` are suppressed (`opterr` is bypassed).
  - Unrecognized Option: `getopt()` returns `'?'`, and sets `optopt` to the offending character.
  - Missing Argument: `getopt()` returns `':'`, and sets `optopt` to the option character that lacked an argument.
  - Michael Kerrisk strongly recommends the leading colon approach for production software because it allows the program to report tailored, domain-specific error diagnostics and return specific exit codes (e.g., `EX_USAGE`) instead of generic libc stderr messages.

### The GNU getopt_long(3) Extension
Defined in `<getopt.h>`, `getopt_long()` extends POSIX `getopt()` to support GNU-style long options (options prefixed with `--`):

```c
#include <getopt.h>

int getopt_long(int argc, char * const argv[],
                const char *optstring,
                const struct option *longopts, int *longindex);
```

#### The struct option Structure
The `longopts` parameter is an array of `struct option` elements, terminated by an element containing all zeros:

```c
struct option {
    const char *name;    /* Name of long option without leading hyphens */
    int         has_arg; /* no_argument (0), required_argument (1), optional_argument (2) */
    int        *flag;    /* Pointer to int variable, or NULL */
    int         val;     /* Value to return or store in *flag */
};
```

#### Evaluation and Semantics of struct option Fields
* `name`: Pointer to a null-terminated string containing the option name in lowercase kebab-case (e.g., `"target-port"`).
* `has_arg`: Predefined symbolic macros:
  - `no_argument` (`0`): The option takes no value (e.g., `--json`).
  - `required_argument` (`1`): The option requires an argument (e.g., `--layer 4` or `--layer=4`).
  - `optional_argument` (`2`): The argument may be omitted; if provided, it must use the `--option=value` syntax.
* `flag` and `val`:
  - If `flag` is `NULL`, `getopt_long()` returns the value specified in `val`. This is typically set to the character constant of the equivalent single-letter option (e.g., `val = 'L'`).
  - If `flag` is a non-null pointer to an `int`, `getopt_long()` sets `*flag = val` upon encountering the option and returns `0`.
* `longindex`: If non-null, points to an integer variable that is populated with the index of the matched option within the `longopts` array.

### Kerrisk's Parsing Principles: Option Clustering and Delimiters
* Option Clustering (Grouping):
  - POSIX and TLPI require that single-character options taking no arguments can be grouped together behind a single hyphen.
  - Example: An invocation like `krayctl trace -j -v` must be functionally identical to `krayctl trace -jv`.
  - When a clustered option takes an argument, the remaining characters in that `argv` element are treated as its argument: `-L4` is identical to `-L 4`.
* Operand Separation and the End-of-Options Delimiter (`--`):
  - A command-line token consisting solely of two hyphens (`--`) signals the immediate end of all options.
  - Even if subsequent arguments begin with a hyphen (e.g., `-filename` or `-4`), `getopt()` halts option processing and treats all subsequent tokens strictly as non-option positional operands.
  - Crucial Production Security Rationale: Without the `--` delimiter, an operator or script attempting to process a target named `-rf` or `-L` would suffer catastrophic argument injection.
* GNU Argument Permutation:
  - By default, GNU `getopt()` and `getopt_long()` permute the contents of `argv` as they scan, rearranging non-option arguments to the end of the vector so options may appear anywhere on the command line.
  - POSIX Strict Conformance: If the environment variable `POSIXLY_CORRECT` is set, or if `optstring` begins with a `+` character, permutation is disabled; option scanning ceases as soon as the first non-option argument is encountered.

---

## 4. Linux man-pages Project Standards (Maintained by Michael Kerrisk)

The Linux `man-pages` project, maintained by Michael Kerrisk from 2004 to 2021, sets the worldwide standard for command-line documentation, formatting, and manual layout (`man-pages(7)`).

### Manual Section Allocations
* Section 1 (User Commands): General commands executable by unprivileged operators (e.g., `curl`, `jq`, `grep`).
* Section 8 (System Administration Commands): Privileged commands, system daemons, hardware inspection, kernel management, and packet tracing tools requiring administrative privileges or raw capabilities (e.g., `bpftool`, `ip`, `tc`, `tracer_daemon`, `krayctl`).

### Kerrisk's Typographical Conventions
In manual pages and inline terminal help outputs, strict typographical conventions convey syntactic meaning:
* Bold Face (`\fB...\fR` in groff / `\033[1m` in ANSI):
  - Used for command names, subcommand keywords, option switches, and any literal text that must be entered exactly as typed.
  - Examples: **krayctl**, **trace**, **--layer**, **-L**, **--json**.
* Italic Face (`\fI...\fR` in groff / underlined or distinct styling in ANSI):
  - Used for argument placeholders, variables, operands, and parameter values that the user must substitute.
  - Examples: *port*, *layer-num*, *path*, *protocol*.
* Roman Face (`\fR` in groff):
  - Used for punctuation, brackets, braces, and hyphens separating flags.

### Syntax Specification Delimiters
The SYNOPSIS section of a command follows formal BNF-like delimiter conventions:
* Optional Elements: Enclosed in square brackets `[ ... ]`.
  - Example: `krayctl trace [OPTIONS] [URL_PATH]` indicates both the options and the URL path are optional.
* Mandatory Elements: Specified without brackets, or enclosed in braces `{ ... }` when grouped.
  - Example: `krayctl proto inspect <protocol>`.
* Mutually Exclusive Alternatives: Separated by a vertical pipe `|`.
  - Optional alternative: `[ --system | --user ]` indicates the user may pass at most one of the two flags.
  - Mandatory alternative: `{ enable | disable }` indicates exactly one of the values must be chosen.
* Repeatable Elements (Variadic): Followed by an ellipsis `...`.
  - Example: `[ -p PORT ]...` indicates that the `-p` option may be specified multiple times.

### Standard Manual Page Section Hierarchy
A compliant production Linux utility manual must contain the following standard sections in this exact order:
* NAME: The utility name followed by a single-line summary of its function, separated by a dash (e.g., `krayctl - eBPF-powered wire-to-code network latency and protocol tracer`).
* SYNOPSIS: Concise formal syntax grammar showing options, subcommands, and operands with proper brackets and typographical distinctions.
* DESCRIPTION: High-level architectural explanation of what the tool accomplishes, its interaction with kernel subsystems, and operational theory.
* OPTIONS: Detailed, alphabetical list of all supported command-line options, including single-letter flags, GNU long options, valid argument types, defaults, and functional descriptions.
* SUBCOMMANDS: Detailed breakdown of the available subcommand verbs and their isolated argument spaces.
* EXIT STATUS: Comprehensive listing of all possible numerical return codes and their precise semantic conditions.
* ENVIRONMENT: All environment variables recognized by the utility (e.g., `KRAY_HOST`, `KRAY_DIR`, `NO_COLOR`), including defaults and precedence order.
* FILES: File system paths read or modified by the utility (e.g., `/sys/kernel/btf/vmlinux`, `/sys/fs/bpf`, `~/.local/bin/krayctl`).
* DIAGNOSTICS: Diagnostic messages emitted to `stderr` and troubleshooting procedures.
* NOTES: Kernel requirements (e.g., BTF, BPF JIT, Linux kernel >= 5.14), Linux capabilities (`CAP_BPF`, `CAP_NET_ADMIN`), and memory lock limits (`RLIMIT_MEMLOCK`).
* BUGS: Known limitations, edge cases, or upstream kernel caveats.
* EXAMPLES: Practical, realistic command invocations showing typical administrative workflows.
* AUTHORS: Attribution of development team and copyright.
* SEE ALSO: Cross-references to related manual pages and standards (e.g., `bpftool(8)`, `ip(8)`, `getopt(3)`, `sysexits.h(3)`).

---

## 5. POSIX IEEE Std 1003.1 Utility Syntax Guidelines 1 through 13

Chapter 12.2 of IEEE Std 1003.1-2017 (POSIX.1) codifies 13 Utility Syntax Guidelines that govern Unix command behavior. Michael Kerrisk highlights these guidelines as mandatory for systems software design:

### Guideline 1: Utility Name Length
* Specification: Utility names should be at least two and no more than nine characters in length.
* Systems Rationale: Historical filename limits on early Unix file systems and shell buffer constraints necessitated compact names.
* Implementation in krayctl: `krayctl` consists of exactly 7 characters, strictly conforming to the 2-9 character boundary.

### Guideline 2: Character Set
* Specification: Utility names should consist of lowercase alphanumeric characters only. Punctuation characters, uppercase letters, and spaces should be avoided.
* Systems Rationale: Avoids shell escaping issues, case-insensitive filesystem collisions, and localization discrepancies.
* Implementation in krayctl: `krayctl` uses only lowercase ASCII alphanumeric characters.

### Guideline 3: Single-Character Option Names
* Specification: Each option name should be a single alphanumeric character from the portable character set. Multi-digit or multi-character short options are forbidden.
* Systems Rationale: Guarantees compatibility with POSIX `getopt()` pointer arithmetic and single-byte option character tables.
* Implementation in krayctl: Every short option in `krayctl` is a single character: `-h`, `-v`, `-L`, `-j`, `-p`, `-u`, `-i`, `-s`, `-f`.

### Guideline 4: Option Prefix Character
* Specification: All options should be preceded by the hyphen delimiter character `-`.
* Systems Rationale: Eliminates confusion caused by archaic utilities like `find` or `sort` that historically used `+` prefixes or raw keywords.
* Implementation in krayctl: All options are uniformly prefixed with `-` (or `--` for GNU extensions).

### Guideline 5: Option Grouping and Clustering
* Specification: One or more options that do not take option-arguments must be able to be grouped together behind a single hyphen delimiter.
* Systems Rationale: Reduces command-line verbosity and allows fast composition of flags.
* Implementation in krayctl: Valueless flags can be grouped freely: `krayctl trace -jv` is equivalent to `krayctl trace -j -v`.

### Guideline 6: Option-Argument Separation
* Specification: Options requiring an argument should support having that argument separated by whitespace or immediately adjacent.
* Systems Rationale: Accommodates both interactive shell autocompletion habits and compact script parameters.
* Implementation in krayctl: Both `-L 4` and `-L4` are parsed identically as layer 4 isolation.

### Guideline 7: Non-Optional Option-Arguments
* Specification: Option-arguments should never be optional. If an option takes an argument, omitting the argument must trigger a syntax error.
* Systems Rationale: Optional arguments introduce severe ambiguity when an option is followed by a positional operand.
* Implementation in krayctl: Options requiring values (e.g., `-L`, `-p`, `-u`) strictly require an argument. Omitting the parameter raises an explicit syntax error (`EX_USAGE`).

### Guideline 8: Multiple Arguments
* Specification: When an option requires multiple values, use a single argument containing comma-separated tokens, or allow the option to be repeated multiple times.
* Systems Rationale: Prevents variable-length parsing ambiguities that break the command grammar.
* Implementation in krayctl: Multiple ports or layers are accepted via repeated flags (`-p 8080 -p 8443`) or comma-delimited tokens (`-p 8080,8443`).

### Guideline 9: Options Preceding Operands
* Specification: All options should precede positional operands on the command line.
* Systems Rationale: Strict POSIX parsing ceases option processing upon the first non-option token, preserving deterministic operand parsing.
* Implementation in krayctl: Syntax structures mandate: `krayctl [global-options] <subcommand> [subcommand-options] [operands]`.

### Guideline 10: End-of-Options Delimiter (--)
* Specification: The argument `--` (double hyphen) must be accepted as a delimiter indicating the end of options. Any subsequent argument, even if starting with `-`, must be treated strictly as an operand.
* Systems Rationale: Essential defense against argument injection when handling untrusted filenames, IP addresses, or patterns starting with hyphens.
* Implementation in krayctl: The argument parser terminates option evaluation immediately upon encountering `--`.

### Guideline 11: Option Order Invariance
* Specification: The relative order of different options should not affect the behavior of the utility.
* Systems Rationale: Prevents brittle command-line constructions where moving a flag alters side effects.
* Implementation in krayctl: The command `krayctl trace -j -L 4` behaves identically to `krayctl trace -L 4 -j`.

### Guideline 12: Operand Order Significance
* Specification: The order of positional operands may be significant and determines operational targets.
* Systems Rationale: Positional operands define targets and actions (e.g., source before destination).
* Implementation in krayctl: In `krayctl proto inspect <protocol>`, the position of `<protocol>` is strictly positional.

### Guideline 13: Standard Stream Operand (-)
* Specification: The single hyphen argument `-` should represent standard input (`stdin`) or standard output (`stdout`), depending on context.
* Systems Rationale: Facilitates Unix pipeline streaming without requiring named pipes or temporary files.
* Implementation in krayctl: Passing `-` as an input trace file indicates reading raw JSON lines directly from `stdin`.

---

## 6. GNU Coding Standards for Long Options

While POSIX codified single-character options, the GNU Project introduced long options to improve readability, self-documentation, and maintainability of scripts.

### Kebab-Case Syntax
* Prefix: Long options are always prefixed with double hyphens: `--`.
* Naming Convention: Multi-word options must be written in lowercase with words delimited by single hyphens (`kebab-case`).
* Anti-Patterns: CamelCase (`--targetPort`) and snake_case (`--target_port`) are strictly prohibited in production Linux tools.
* Implementation in krayctl: `--target-port`, `--trace-level`, `--port-range`, `--json`, `--help`, `--version`.

### Value Assignment Format
GNU coding standards dictate that utilities accepting long options with required arguments must support both space-separated and equals-separated syntax:
* Space Separation: `--layer 4`
* Equals Separation: `--layer=4`
* The parser must handle both transparently.

### Mandatory Universal GNU Options
Every production Linux systems utility must implement two fundamental long options:
* `--help` (`-h`):
  - Emits a concise, human-readable usage summary to standard output (`stdout`).
  - Summarizes the SYNOPSIS, available options, subcommands, and canonical examples.
  - Must immediately terminate the process with exit code `0` (`EX_OK`).
* `--version` (`-v` or `-V`):
  - Emits the utility name, semantic version number, copyright attribution, and licensing terms (e.g., GPLv2) to standard output (`stdout`).
  - Must immediately terminate the process with exit code `0` (`EX_OK`).

---

## 7. Stream Separation Rules, I/O Buffering, and the NO_COLOR Standard

### Fundamental Stream Separation Semantics
Unix processes inherit three standard POSIX file descriptors from their parent:
* `stdin` (File Descriptor 0, `STDIN_FILENO`): Incoming data stream.
* `stdout` (File Descriptor 1, `STDOUT_FILENO`): Primary programmatic and data output channel.
* `stderr` (File Descriptor 2, `STDERR_FILENO`): Diagnostic, logging, warning, error, and progress monitoring channel.

### Stream Purity in Pipeline Orchestration
In production systems, utilities are frequently chained together in automated pipelines:

```bash
krayctl trace -j -L 4 | jq '.payload.latency_ns' | awk '{sum+=$1} END {print sum/NR}'
```

If the command prints informational banners, connection messages, or progress bars to `stdout`, the downstream parser (`jq`) immediately fails with a JSON syntax error.
* Rule for stdout: Only valid, machine-readable records (e.g., JSON Lines, raw binary, or requested structured data) may be written to file descriptor 1.
* Rule for stderr: All human-readable diagnostic messages, ASCII banners, SSH connection notices, compilation logs, warnings, and errors must be explicitly redirected to file descriptor 2 (`>&2` in shell, `fprintf(stderr, ...)` in C).

### Michael Kerrisk's File I/O Buffering Analysis (TLPI Chapter 13)
Michael Kerrisk devotes Chapter 13 of TLPI to the mechanics of the standard C library (`stdio`) buffering:
* Fully Buffered (`_IOFBF`):
  - Data is accumulated in an internal memory buffer (typically 4096 or 8192 bytes) before being flushed to the kernel via a `write(2)` system call.
  - Default Behavior: `stdout` automatically switches to fully buffered mode whenever it is redirected to a non-terminal (such as a pipe or file).
  - Telemetry Consequence: In live streaming tools (like `krayctl trace`), block buffering delays packet event visibility. Therefore, explicit flushing (`fflush(stdout)`) must be executed after every telemetry record.
* Line Buffered (`_IOLBF`):
  - Data is flushed to the kernel whenever a newline character (`\n`) is encountered, or when the buffer fills.
  - Default Behavior: `stdout` operates in line-buffered mode when connected to an interactive terminal device.
* Unbuffered (`_IONBF`):
  - Every I/O operation translates immediately to a direct `write(2)` system call to the kernel.
  - Default Behavior: `stderr` is always unbuffered. This guarantees that diagnostic and crash messages are written immediately, even if the process subsequently segfaults or receives a fatal signal.

### Terminal Capability Detection and the NO_COLOR Standard
* ANSI Color Safety: Color codes (`\033[0;32m`) enrich interactive readability for human operators, but corrupt log files, CI/CD runners, and text filters.
* TTY Detection:
  - In C: Check `isatty(STDOUT_FILENO)`.
  - In Bash: Check `[ -t 1 ]`.
* The NO_COLOR Specification:
  - Software must honor the de facto `NO_COLOR` standard (https://no-color.org).
  - If the environment variable `NO_COLOR` is set (regardless of its value, even if empty or set to `0`), all ANSI escape sequences must be disabled.
* Standard Implementation Logic:
  ```bash
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
      COLOR_ENABLED=1
  else
      COLOR_ENABLED=0
  fi
  ```

---

## 8. Exit Codes Taxonomy: POSIX, BSD sysexits.h, and Linux Shell Conventions

In TLPI Chapter 24 (*Process Termination*), Michael Kerrisk emphasizes that the exit status of a process is its ultimate return value to the operating system. Orchestrators (systemd, Kubernetes, CI/CD pipelines) inspect this 8-bit integer (values 0-255) to decide whether to restart a service, alert an on-call engineer, or halt deployment.

### BSD sysexits.h Taxonomy
Originally authored by Eric Allman for sendmail and adopted across BSD and Linux distributions in `<sysexits.h>`, these standardized exit codes provide granular failure categorization:

* `EX_OK` (Code 0):
  - Meaning: Successful termination.
  - Operational Use: Task completed without errors, or `--help` / `--version` executed cleanly.
* `EX_USAGE` (Code 64, or POSIX Code 2):
  - Meaning: Command-line usage error.
  - Operational Use: Invalid option, unrecognized flag, missing mandatory argument, or bad parameter syntax.
* `EX_DATAERR` (Code 65):
  - Meaning: Data format error.
  - Operational Use: The input packet, JSON payload, or frame hex dump was malformed or failed validation.
* `EX_NOINPUT` (Code 66):
  - Meaning: Cannot open input.
  - Operational Use: Input file does not exist, cannot be read, or specified network stream unreachable.
* `EX_NOUSER` (Code 67):
  - Meaning: Addressee unknown / user does not exist.
  - Operational Use: Specified user context or service account cannot be resolved.
* `EX_NOHOST` (Code 68):
  - Meaning: Host name unknown.
  - Operational Use: Target remote host (e.g. `KRAY_HOST`) is not resolvable via DNS or `/etc/hosts`.
* `EX_UNAVAILABLE` (Code 69):
  - Meaning: Service unavailable.
  - Operational Use: Required system service or daemon is not running (e.g. BPF filesystem `/sys/fs/bpf` not mounted).
* `EX_SOFTWARE` (Code 70, or POSIX Code 1):
  - Meaning: Internal software error.
  - Operational Use: Unhandled internal assertion failure, memory corruption, or selftest failure.
* `EX_OSERR` (Code 71):
  - Meaning: System error.
  - Operational Use: Operating system resource exhausted (cannot allocate socket, out of memory, unable to fork).
* `EX_OSFILE` (Code 72):
  - Meaning: Critical OS file missing.
  - Operational Use: Kernel BTF file (`/sys/kernel/btf/vmlinux`) missing, preventing CO-RE eBPF execution.
* `EX_CANTCREAT` (Code 73):
  - Meaning: Cannot create output file.
  - Operational Use: Unable to create trace capture file or web dashboard artifact due to permissions or disk quota.
* `EX_IOERR` (Code 74):
  - Meaning: Input/output error.
  - Operational Use: Physical or network I/O error occurred during file or socket operations.
* `EX_TEMPFAIL` (Code 75):
  - Meaning: Temporary failure.
  - Operational Use: Transient condition; indicates to the orchestrator that the operation can be retried immediately.
* `EX_PROTOCOL` (Code 76):
  - Meaning: Remote protocol error.
  - Operational Use: Remote protocol exchange was invalid, unsupported, or violated protocol specification.
* `EX_NOPERM` (Code 77):
  - Meaning: Permission denied.
  - Operational Use: Insufficient Linux capabilities (missing `CAP_BPF`, `CAP_NET_ADMIN`, or non-root user).
* `EX_CONFIG` (Code 78):
  - Meaning: Configuration error.
  - Operational Use: Missing or corrupt configuration file or incompatible runtime settings.

### Linux Shell Standard Signal-Induced Exit Codes
When a process is killed by an asynchronous signal:
* Calculation: The shell sets `$?` to `128 + N`, where `N` is the signal number.
* `SIGINT` (Signal 2 - Ctrl+C): Exit status is `130` (`128 + 2`).
* `SIGTERM` (Signal 15 - Termination Request): Exit status is `143` (`128 + 15`).
* `SIGKILL` (Signal 9 - Uncatchable Kill): Exit status is `137` (`128 + 9`).
* Command Execution Failure (Code 126): Command found but not executable (e.g., permission denied on binary).
* Command Not Found (Code 127): Command binary not found in `$PATH`.

---

## 9. Subcommand Pattern & Argument Vector Memory Dispatching

Modern Linux systems software managing complex, multi-domain environments (`git`, `iproute2`, `bpftool`, `systemctl`, `krayctl`) organizes functionality around a hierarchical subcommand pattern.

### Formal Command Vector Grammar
```text
utility [global-options] <subcommand> [subcommand-options] [operands]
```

### Memory Architecture of Vector Slicing
In C and POSIX shell, delegating control to a subcommand requires adjusting the argument vector pointers so the subcommand parser operates in an isolated namespace:

```text
Initial State:
argc = 5
argv[0] = "krayctl"
argv[1] = "--verbose"
argv[2] = "trace"
argv[3] = "-L"
argv[4] = "4"

After Global Parsing (optind = 2):
Subcommand Token: argv[optind] -> "trace"

Vector Slicing:
argc -= optind;   /* argc becomes 3 */
argv += optind;   /* argv[0] becomes "trace", argv[1] = "-L", argv[2] = "4" */
```

By shifting the vector pointers, the subcommand handler receives its own clean `argc` and `argv` starting at `argv[0] == "trace"`. It can then execute its own localized `getopt_long()` parsing loop starting with `optind = 1` without state pollution from global options.

### Declarative Subcommand Dispatch Table Pattern
In production C engineering, subcommands are maintained in a declarative dispatch table:

* Structure Definition:
  ```c
  struct subcommand_entry {
      const char *name;
      int (*handler)(int argc, char **argv);
      const char *summary;
      void (*help_fn)(void);
  };
  ```
* Dispatch Execution:
  1. The top-level parser processes global options (`-h`, `-v`).
  2. If the next argument matches an entry in the dispatch table, `argc` and `argv` are shifted.
  3. Control transfers to `entry->handler(argc, argv)`.
  4. If no match is found, an unknown command diagnostic is printed to `stderr` and the program exits with `EX_USAGE`.

### Contextual Help Resolution Hierarchy
Hierarchical command structures must provide intuitive help traversal at every depth:
* Top-Level Help: `krayctl --help` or `krayctl -h` displays global options, available subcommands, and operational overview.
* Verb Help: `krayctl help <subcommand>` displays targeted syntax and options for that specific command.
* Flag Help: `krayctl <subcommand> --help` or `krayctl <subcommand> -h` displays identical targeted syntax.
* Deep Routing: Multi-level subcommands (e.g., `krayctl proto inspect <proto>`) recursively resolve help when passed `--help`.

---

## 10. Production C Reference Implementation: Michael Kerrisk getopt_long Engine

The following complete, production-grade C implementation demonstrates Michael Kerrisk's recommended patterns from TLPI: leading colon error suppression, GNU `getopt_long()` option table, argument vector memory dispatching, `<sysexits.h>` status codes, and strict stream separation.

```c
/*
 * kray_cli_core.c — Production C Argument Vector Engine
 * Grounded in Michael Kerrisk's TLPI (The Linux Programming Interface)
 * Standards: POSIX IEEE Std 1003.1-2017 & GNU Utility Conventions
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <sysexits.h>
#include <errno.h>

#define KRAY_VERSION "2.0.0"

/* Global Runtime Configuration */
typedef struct {
    bool verbose;
    bool json_output;
    uint32_t target_port;
    uint8_t filter_layer;
} kray_config_t;

static kray_config_t g_config = {
    .verbose = false,
    .json_output = false,
    .target_port = 8080,
    .filter_layer = 0,
};

/* Forward Declarations */
static void print_version(void);
static void print_top_help(void);
static int cmd_trace_handler(int argc, char **argv);
static int cmd_status_handler(int argc, char **argv);

/* Subcommand Registry */
typedef struct {
    const char *name;
    int (*handler)(int argc, char **argv);
    const char *summary;
} subcommand_t;

static const subcommand_t SUBCOMMANDS[] = {
    {"trace",  cmd_trace_handler,  "Live wire-to-code eBPF trace execution"},
    {"status", cmd_status_handler, "Target environment and eBPF readiness check"},
    {NULL, NULL, NULL}
};

static void print_version(void)
{
    fprintf(stdout, "krayctl version %s (TLPI-Compliant Architecture)\n", KRAY_VERSION);
    fprintf(stdout, "Copyright (C) 2026 Antigravity Kernel Performance Engineering\n");
    fprintf(stdout, "License: GNU GPL version 2 <https://gnu.org/licenses/gpl-2.0.html>\n");
}

static void print_top_help(void)
{
    fprintf(stdout, "NAME\n");
    fprintf(stdout, "  krayctl — eBPF-powered wire-to-code network latency and protocol tracer\n\n");
    fprintf(stdout, "SYNOPSIS\n");
    fprintf(stdout, "  krayctl [GLOBAL-OPTIONS] <SUBCOMMAND> [OPTIONS] [OPERANDS]\n\n");
    fprintf(stdout, "GLOBAL OPTIONS\n");
    fprintf(stdout, "  -h, --help        Display this top-level help and exit\n");
    fprintf(stdout, "  -v, --version     Display version information and exit\n\n");
    fprintf(stdout, "AVAILABLE SUBCOMMANDS\n");
    for (const subcommand_t *sub = SUBCOMMANDS; sub->name != NULL; sub++) {
        fprintf(stdout, "  %-10s    %s\n", sub->name, sub->summary);
    }
    fprintf(stdout, "\nRun 'krayctl <subcommand> --help' for details on a specific command.\n");
}

/* Subcommand: trace */
static int cmd_trace_handler(int argc, char **argv)
{
    static const char *short_opts = ":hL:p:j";
    static const struct option long_opts[] = {
        {"help",  no_argument,       NULL, 'h'},
        {"layer", required_argument, NULL, 'L'},
        {"port",  required_argument, NULL, 'p'},
        {"json",  no_argument,       NULL, 'j'},
        {NULL, 0, NULL, 0}
    };

    /* Reset optind for sub-vector parsing */
    optind = 1;
    int opt;

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                fprintf(stdout, "NAME\n");
                fprintf(stdout, "  krayctl-trace — Live 7-layer wire-to-code eBPF tracing\n\n");
                fprintf(stdout, "SYNOPSIS\n");
                fprintf(stdout, "  krayctl trace [OPTIONS] [URL_PATH]\n\n");
                fprintf(stdout, "OPTIONS\n");
                fprintf(stdout, "  -L, --layer <2..7>    Filter trace to specific OSI layer\n");
                fprintf(stdout, "  -p, --port <port>     Target server TCP port (default: 8080)\n");
                fprintf(stdout, "  -j, --json            Output telemetry as structured JSON Lines\n");
                fprintf(stdout, "  -h, --help            Display this command help\n");
                return EX_OK;

            case 'L': {
                int layer = atoi(optarg);
                if (layer < 2 || layer > 7) {
                    fprintf(stderr, "krayctl trace: error: layer must be between 2 and 7 (got: %s)\n", optarg);
                    return EX_USAGE;
                }
                g_config.filter_layer = (uint8_t)layer;
                break;
            }

            case 'p': {
                long port = strtol(optarg, NULL, 10);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "krayctl trace: error: invalid port number '%s'\n", optarg);
                    return EX_USAGE;
                }
                g_config.target_port = (uint32_t)port;
                break;
            }

            case 'j':
                g_config.json_output = true;
                break;

            case ':': /* Missing required argument (detected via leading colon) */
                fprintf(stderr, "krayctl trace: error: option '-%c' requires an argument\n", optopt);
                return EX_USAGE;

            case '?': /* Unrecognized option */
            default:
                fprintf(stderr, "krayctl trace: error: unrecognized option '-%c'\n", optopt);
                fprintf(stderr, "Try 'krayctl trace --help' for valid options.\n");
                return EX_USAGE;
        }
    }

    /* Diagnostics go to stderr; stream data goes to stdout */
    if (!g_config.json_output) {
        fprintf(stderr, "[*] Attached eBPF probes. Target Port: %u | Filter Layer: %u\n",
                g_config.target_port, g_config.filter_layer);
    }

    /* Emit telemetry record to stdout */
    if (g_config.json_output) {
        fprintf(stdout, "{\"status\":\"active\",\"port\":%u,\"layer\":%u}\n",
                g_config.target_port, g_config.filter_layer);
        fflush(stdout); /* TLPI Chapter 13: flush stdout in streaming mode */
    }

    return EX_OK;
}

/* Subcommand: status */
static int cmd_status_handler(int argc, char **argv)
{
    fprintf(stderr, "[*] Checking Target Environment & BPF Subsystem...\n");
    fprintf(stdout, "Kernel BTF: OK (/sys/kernel/btf/vmlinux)\n");
    fprintf(stdout, "BPF JIT:    OK (net.core.bpf_jit_enable = 1)\n");
    return EX_OK;
}

/* Main Entrypoint & Memory Vector Dispatcher */
int main(int argc, char *argv[])
{
    static const char *global_short_opts = "+:hv";
    static const struct option global_long_opts[] = {
        {"help",    no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };

    /* Leading '+' enforces strict POSIX order: stop scanning at first non-option */
    int opt;
    while ((opt = getopt_long(argc, argv, global_short_opts, global_long_opts, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_top_help();
                return EX_OK;
            case 'v':
                print_version();
                return EX_OK;
            case ':':
                fprintf(stderr, "krayctl: error: option requires an argument\n");
                return EX_USAGE;
            case '?':
                fprintf(stderr, "krayctl: error: unknown global option '-%c'\n", optopt);
                return EX_USAGE;
        }
    }

    /* If no subcommand provided, show help */
    if (optind >= argc) {
        print_top_help();
        return EX_USAGE;
    }

    /* Extract subcommand token */
    const char *subcmd_name = argv[optind];

    /* Match and dispatch via argument vector slicing */
    for (const subcommand_t *sub = SUBCOMMANDS; sub->name != NULL; sub++) {
        if (strcmp(subcmd_name, sub->name) == 0) {
            /* Slicing: advance pointers so subcmd becomes argv[0] */
            int sub_argc = argc - optind;
            char **sub_argv = argv + optind;
            return sub->handler(sub_argc, sub_argv);
        }
    }

    /* Unknown subcommand error */
    fprintf(stderr, "krayctl: error: '%s' is not a valid krayctl command.\n", subcmd_name);
    fprintf(stderr, "See 'krayctl --help' for available commands.\n");
    return EX_USAGE;
}
```

---

## 11. Production Bash Reference Implementation: krayctl Dispatch Architecture

The shell implementation of `krayctl` applies Michael Kerrisk's principles within POSIX shell scripts:

```bash
#!/usr/bin/env bash
# ==============================================================================
# krayctl — Production Shell Architecture Reference
# Grounded in Michael Kerrisk's TLPI & POSIX IEEE Std 1003.1 Guidelines
# ==============================================================================
set -euo pipefail

# BSD sysexits.h Standards
readonly EX_OK=0
readonly EX_USAGE=64
readonly EX_DATAERR=65
readonly EX_UNAVAILABLE=69
readonly EX_SOFTWARE=70
readonly EX_OSFILE=72
readonly EX_NOPERM=77

readonly VERSION="2.0.0"

# Terminal Color Auto-Detection (TLPI Chapter 13 & NO_COLOR Standard)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    CYAN=''
    BOLD=''
    NC=''
fi

# Informational banners are ALWAYS directed to stderr (FD 2)
print_banner() {
    cat <<EOF >&2
${CYAN}${BOLD}================================================================================
           krayctl — eBPF-WireToCode-Tracer Command-Line Control
================================================================================${NC}
EOF
}

cmd_version() {
    echo "krayctl version $VERSION (eBPF-WireToCode-Tracer)"
    echo "Copyright (C) 2026 Antigravity Kernel Performance Engineering"
    echo "License GPLv2: GNU GPL version 2 <https://gnu.org/licenses/gpl-2.0.html>"
    exit "$EX_OK"
}

usage() {
    local exit_code="${1:-$EX_OK}"
    print_banner
    cat <<EOF
${BOLD}NAME${NC}
  krayctl — eBPF-powered wire-to-code network latency and protocol tracer

${BOLD}SYNOPSIS${NC}
  krayctl [GLOBAL-OPTIONS] <SUBCOMMAND> [OPTIONS] [OPERANDS]

${BOLD}GLOBAL OPTIONS${NC}
  -h, --help                 Display top-level usage synopsis
  -v, -V, --version          Display version information

${BOLD}AVAILABLE SUBCOMMANDS${NC}
  status                     Check target environment and eBPF readiness
  trace                      Execute live 7-layer wire-to-code trace
  proto                      Multi-protocol frame dissector and inspector
  selftest                   Run native C BPF skeleton selftests

See 'krayctl <subcommand> --help' for details on a specific subcommand.
EOF
    exit "$exit_code"
}

# Subcommand: trace
cmd_trace() {
    local layer=""
    local port="8080"
    local json_mode=0

    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help)
                print_banner
                cat <<EOF
${BOLD}NAME${NC}
  krayctl-trace — Live 7-layer wire-to-code eBPF tracing

${BOLD}SYNOPSIS${NC}
  krayctl trace [OPTIONS] [URL_PATH]

${BOLD}OPTIONS${NC}
  -L, --layer <2..7>         Filter trace to specific OSI layer
  -p, --port <port>          Target server TCP port (default: 8080)
  -j, --json                 Output machine-readable JSON Lines to stdout
  -h, --help                 Display this command help
EOF
                exit "$EX_OK"
                ;;
            -L|--layer)
                [ $# -ge 2 ] || { echo "krayctl trace: option requires an argument: $1" >&2; exit "$EX_USAGE"; }
                layer="$2"
                shift 2
                ;;
            --layer=*)
                layer="${1#*=}"
                shift
                ;;
            -p|--port)
                [ $# -ge 2 ] || { echo "krayctl trace: option requires an argument: $1" >&2; exit "$EX_USAGE"; }
                port="$2"
                shift 2
                ;;
            --port=*)
                port="${1#*=}"
                shift
                ;;
            -j|--json)
                json_mode=1
                shift
                ;;
            --)
                shift
                break
                ;;
            -*)
                echo -e "${RED}krayctl trace: unknown option '$1'${NC}" >&2
                echo "Try 'krayctl trace --help' for valid options." >&2
                exit "$EX_USAGE"
                ;;
            *)
                break
                ;;
        esac
    done

    # Validation
    if [ -n "$layer" ] && [[ ! "$layer" =~ ^[2-7]$ ]]; then
        echo -e "${RED}krayctl trace: invalid layer '$layer' (must be between 2 and 7)${NC}" >&2
        exit "$EX_USAGE"
    fi

    # Stream Separation: diagnostics to stderr, JSON data to stdout
    if [ "$json_mode" -eq 1 ]; then
        echo "{\"event\":\"trace_start\",\"layer\":\"${layer:-all}\",\"port\":$port}"
    else
        echo -e "${CYAN}[*] Trace initiated on Port $port (Layer: ${layer:-all})${NC}" >&2
    fi
    exit "$EX_OK"
}

# Top-level Routing
COMMAND="${1:-}"

case "$COMMAND" in
    ""|help|-h|--help)
        if [ $# -ge 2 ]; then
            case "$2" in
                trace)    cmd_trace --help ;;
                *)        usage "$EX_OK" ;;
            esac
        else
            usage "$EX_OK"
        fi
        ;;
    -v|-V|--version|version)
        cmd_version
        ;;
    trace)
        shift
        cmd_trace "$@"
        ;;
    *)
        echo -e "${RED}krayctl: unknown command '$COMMAND'${NC}" >&2
        echo "Try 'krayctl --help' for available commands." >&2
        exit "$EX_USAGE"
        ;;
esac
```

---

## 12. Why This Standard Is the Gold Standard for Production Linux Systems Software

Systems software operating at the intersection of the Linux kernel, eBPF subsystems, distributed microservices, and human operations cannot afford ambiguity in command execution. Grounding `krayctl` and all production utilities in Michael Kerrisk's TLPI and Linux man-pages standards delivers five concrete architectural guarantees:

* Predictability for Human Operators:
  - Adherence to standard option conventions (`-h`, `--help`, `-v`, `--version`, `-L 4`, `-L4`, kebab-case long options) reduces cognitive friction. Engineers immediately recognize how to discover flags, group switches, and retrieve usage instructions without consulting external documentation.
* Pipeline Safety and Automation Interoperability:
  - Strict stream separation guarantees that automation pipelines (`jq`, `grep`, `awk`, shell loops) receive unpolluted structured data on standard output (`stdout`).
  - Terminal auto-detection and compliance with `NO_COLOR` ensure log aggregators (Fluentd, Grafana Loki, Elasticsearch) do not ingest garbled ANSI terminal control sequences.
* Precise Failure Handling via Sysexits:
  - Standardized exit codes (`sysexits.h`) empower upstream supervisors (`systemd`, Kubernetes liveness probes, deployment harnesses) to differentiate cleanly between command-line usage syntax errors (`EX_USAGE = 64`), missing kernel prerequisites (`EX_OSFILE = 72` for missing BTF), privilege authorization failures (`EX_NOPERM = 77`), and internal software bugs (`EX_SOFTWARE = 70`).
* Immunity Against Shell Injection and Option Ambiguity:
  - Strict compliance with Guideline 10 (the `--` end-of-options delimiter) ensures that arguments beginning with hyphens or crafted strings are treated strictly as positional operands rather than flags, neutralizing parameter injection attacks.
* Long-Term Maintainability and Extensibility:
  - Memory-dispatched argument vectors and declarative subcommand tables decouple subcommands from one another. New diagnostic verbs or inspection targets can be added to the registry without refactoring existing command handlers or risking regression in option parsing.


---

# [Book VII] 프로덕션 eBPF 장애 부검, ARM64 한계 및 하드닝 가이드 (Production Postmortems & ARM64 Limits)

# eBPF Production Postmortems, ARM64 Kernel Limitations, and Hardening Guide

### Document Metadata
* **Platform**: Rocky Linux 9.8 aarch64
* **Kernel Release**: `5.14.0-687.10.1.el9_8.0.1.aarch64`
* **CPU Architecture**: ARM64 (aarch64, ARMv8.1-A+ with LSE Atomics)
* **Scope**: Production eBPF failure modes, kernel CVEs, memory ordering hazards, industry postmortems (Cilium, Cloudflare, Datadog, Meta, Netflix), cgroup v2 OOM-killer traps, TCP RST leaks, and defensive code patterns for wire-to-code tracing.
* **Formatting Compliance**: Hierarchical headings and bulleted lists only (zero markdown tables).

---

### Section 1: Executive Overview & Operating Environment

Deploying low-overhead wire-to-code latency tracing at enterprise scale requires attaching eBPF programs across multiple kernel subsystems: L2 XDP drivers, L3/L4 network stacks, L5 system call boundaries, L6 thread schedulers, and L7 application runtimes. 

While eBPF is designed to provide safe in-kernel execution via static verification, running high-frequency tracing on ARM64 enterprise distributions introduces critical production failure modes:

* **Hardware Architecture Divergence**: Unlike x86-64's Total Store Order (TSO), ARM64 utilizes a weakly ordered memory model. Standard BPF load and store instructions translate to relaxed ARM64 instructions (`LDR` and `STR`), permitting out-of-order execution and store buffering across cores that silently corrupt shared BPF maps without hardware memory barriers.
* **Kernel & JIT Compiler Vulnerabilities**: Rocky Linux 9.8 aarch64 (Kernel `5.14.0-687.10.1.el9_8.0.1.aarch64`) contains specific BPF JIT code generation defects, including signed immediate range miscalculations (CVE-2026-53036) and JIT memory alignment tearing (CVE-2026-23383).
* **Hardware Trap Overhead on ARM64**: User-space function probing (uprobes) on ARM64 relies on synchronous `BRK #0` debug traps and out-of-line single-stepping. At production request rates, this triggers an exception storm that collapses application throughput and pins CPU cores at 100%.
* **Kernel Subsystem Recursion Deadlocks**: Instrumenting packet deallocation (`kfree_skb`) or memory management paths via raw kprobes creates unhandled recursion loops that overflow the 16KB ARM64 kernel stack and trigger unrecoverable kernel panics.
* **Cgroup v2 Memory Accounting Traps**: Since Linux 5.11, all BPF map memory allocations are charged directly against the memory cgroup of the creating process via `__GFP_ACCOUNT`. Deploying an eBPF daemon within container memory limits inevitably triggers cgroup out-of-memory (OOM) termination.
* **Abrupt State Desynchronization**: High-frequency microservices frequently abort connections via TCP RST rather than completing four-way FIN handshakes. Blindness to RST flags permanently leaks connection tracking map slots, exhausting capacities and corrupting latency metrics.

---

### Section 2: Rocky Linux 9.8 aarch64 Kernel Limits & CVE Vulnerabilities

#### 1. Rocky Linux 9.8 Kernel Specifications
* **Kernel Lineage**: RHEL 9.8 kernel tree (`linux-5.14.0-687.10.1.el9_8`) backported with enterprise stability, security, and networking patches.
* **BPF Verifier Complexity Limit**: Exactly 1,000,000 instructions verified per program (`BPF_COMPLEXITY_LIMIT_INSNS`).
* **Maximum BPF Stack Depth**: 512 bytes per function frame. Dynamic stack allocation is prohibited; deep call chains must use BPF tail calls or per-CPU scratchpad storage.
* **Maximum BPF Tail Call Depth**: 32 nested tail calls (`MAX_TAIL_CALL_CNT`). Exceeding this limit causes silent program execution termination.
* **BPF Type Format (BTF) Availability**: Pre-compiled kernel BTF enabled by default at `/sys/kernel/btf/vmlinux` (`CONFIG_DEBUG_INFO_BTF=y`).
* **BPF Trampoline & fentry/fexit**: Supported on ARM64 via `arch_alloc_bpf_trampoline()` and `bpf_arch_text_poke()`.
* **Multi-Buffer XDP Limitation**: The 5.14 kernel tree does NOT support multi-buffer XDP (`xdp_buff->flags & XDP_FLAGS_FRAGS`, introduced in upstream 5.18). XDP programs in Rocky Linux 9.8 are strictly limited to single linear buffer packets.

#### 2. CVE-2026-53036: ARM64 BPF JIT Signed Range Check Off-By-One
* **Vulnerability Location**: `arch/arm64/net/bpf_jit_comp.c`, macro `check_imm(bits, imm)`.
* **Underlying Failure Mechanism**:
  * In the ARM64 JIT compiler, branch instructions (`B`, `B.cond`, `CBZ`, `CBNZ`) use signed immediate displacements. For conditional branches, the offset is a 19-bit signed integer (`check_imm19`), representing the range $[-262144, 262143]$.
  * The macro implementation is defined as:
    `#define check_imm(bits, imm) do { if ((((imm) > 0) && ((imm) >> (bits))) || (((imm) < 0) && (~(imm) >> (bits)))) return -EINVAL; } while (0)`
  * Because `(imm) >> 19` shifts by 19 bits, an immediate value of $+262144$ (which requires 20 signed bits because bit 18 is 1) yields `262144 >> 19 == 0`.
  * Consequently, $+262144$ erroneously passes validation.
  * When encoded by `aarch64_insn_encode_immediate()`, bit 18 is placed into the sign bit of the instruction's 19-bit displacement field.
  * Hardware interprets the instruction as a large negative offset (backward jump) instead of a forward jump.
* **Operational Impact**:
  * Large BPF programs with jump tables, unrolled loops, or multi-protocol dissectors experience unexpected control flow inversions.
  * Execution jumps into arbitrary instruction streams or infinite backward loops, resulting in soft-lockup watchdog panics (`watchdog: BUG: soft lockup - CPU#2 stuck for 22s!`).
* **Tracer Defensive Mitigation**:
  * Break monolithic BPF programs into micro-modules under 4,000 instructions each.
  * Avoid long unconditional forward branch chains spanning across large code blocks.
  * Restrict compiler unrolling (`#pragma unroll 1` or bounded loops) to maintain compact branch targets well within 16-bit displacement limits.

#### 3. CVE-2026-23383: ARM64 BPF JIT Allocator Buffer Alignment Tearing
* **Vulnerability Location**: `arch/arm64/net/bpf_jit_comp.c`, `bpf_jit_binary_pack_alloc()`.
* **Underlying Failure Mechanism**:
  * The ARM64 JIT allocator historically requested an alignment of `sizeof(u32)` (4 bytes) when allocating executable memory pages for JIT compiled programs.
  * For BPF trampolines, tail calls, and long jumps exceeding 128MB, the JIT emits a Procedure Linkage Table (PLT) structure containing a 64-bit target address (`u64 target`).
  * When the kernel dynamically re-links or attaches trampolines via `bpf_arch_text_poke()`, it executes an atomic 64-bit store to update the target address.
  * Because the buffer was only 4-byte aligned, the 64-bit target address frequently crossed a 64-byte or 128-byte CPU cache line boundary.
  * On ARM64 hardware, stores crossing cache line boundaries are NOT multi-copy atomic.
* **Operational Impact**:
  * A concurrent CPU executing the BPF trampoline during a live text poke reads a "torn" 64-bit pointer (upper 32 bits from the new target, lower 32 bits from the old target).
  * The CPU branches to an unmapped or invalid virtual memory address, triggering an unhandled Kernel Instruction Abort (Synchronous External Abort at EL1) and crashing the entire host node.
* **Tracer Defensive Mitigation**:
  * Do not rapidly attach and detach BPF tracing programs during high-traffic runtime.
  * Load all tracer modules statically during daemon bootstrap and use dynamic runtime configuration maps (`runtime_config_map`) to enable or disable tracing features instead of unregistering BPF trampolines.

#### 4. 32-bit vs 64-bit Verifier ALU Bounds Desynchronization
* **Underlying Failure Mechanism**:
  * In Linux 5.14, the BPF verifier tracks scalar register bounds across both 64-bit ranges (`smin_value`, `smax_value`, `umin_value`, `umax_value`) and 32-bit sub-register ranges (`s32_min_value`, `s32_max_value`, `u32_min_value`, `u32_max_value`).
  * When 32-bit arithmetic operations (e.g. packet length calculations or port shifts) are performed without explicit 64-bit sign- or zero-extension, the verifier's jump backtracking logic fails to synchronize the 32-bit and 64-bit bounds.
  * If a subsequent instruction uses the register as an offset into a packet buffer or BPF map value, the verifier assumes the register could contain an unbounded 64-bit value ($[0, \text{U64\_MAX}]$) and rejects the program with:
    `R2 unbounded memory access, make sure to mask or check bounds`.
* **Tracer Defensive Mitigation**:
  * Explicitly mask all 16-bit and 32-bit arithmetic results with bitwise AND operations (`len &= 0xFFFF;`) immediately before using them in packet boundary checks or map lookups.
  * Use explicit type casting (`(u64)(u32)val`) to force LLVM to emit zero-extension instructions (`MOV Wd, Wn`).

---

### Section 3: ARM64 Weakly Ordered Memory Model & BPF JIT Hazards

#### 1. Hardware Memory Architecture Differences: ARM64 vs x86-64
* **x86-64 Total Store Order (TSO)**:
  * Hardware enforces store-store ordering: stores are committed to coherent cache in program order.
  * Hardware enforces load-load ordering: loads complete in program order.
  * Loads can only pass older stores to different addresses (Store-Buffer forwarding).
  * In BPF on x86-64, a write to field A followed by a write to field B is guaranteed to be observed in that exact order by all other cores without explicit fences.
* **ARM64 Weakly Ordered Memory Model**:
  * Out-of-order execution engine: the CPU pipeline can reorder loads and stores to different addresses arbitrarily.
  * Store-Store Reordering: Write to Address B can become visible to other cores before Write to Address A.
  * Load-Load Reordering: Read from Address B can complete before Read from Address A.
  * Store Buffers and Non-blocking Caches: Writes linger in local core store buffers before draining to the Point of Coherency (PoC).
  * Multi-Copy Atomicity: While ARMv8.4-A enforces multi-copy atomicity, stores are only ordered if constrained by explicit data dependencies, address dependencies, control dependencies, or hardware memory barriers.

#### 2. BPF JIT Code Generation on Rocky Linux 9.8 aarch64
* **Standard Memory Access Translation**:
  * `BPF_STX` (BPF store) $\rightarrow$ Translated directly to ARM64 `STR` (Store Register).
  * `BPF_LDX` (BPF load) $\rightarrow$ Translated directly to ARM64 `LDR` (Load Register).
  * Neither `STR` nor `LDR` emit memory barriers. They are completely relaxed instructions.
* **BPF Atomic Instructions Translation**:
  * On ARMv8.1-A systems with Large System Extensions (LSE):
    * `BPF_ADD` (without `BPF_FETCH`) $\rightarrow$ Emits `STADD` (Relaxed store-add; NO barrier, NO acquire, NO release).
    * `BPF_ADD | BPF_FETCH` $\rightarrow$ Emits `LDADDAL` (Load-Add with Acquire and Release ordering).
    * `BPF_XCHG` $\rightarrow$ Emits `SWPAL` (Swap with Acquire and Release ordering).
    * `BPF_CMPXCHG` $\rightarrow$ Emits `CASAL` (Compare and Swap with Acquire and Release ordering).
  * On legacy systems without LSE (Load-Linked / Store-Conditional LL/SC):
    * `BPF_ADD` $\rightarrow$ Emits `LDXR` + `STXR` loop (Relaxed; NO barrier).
    * `BPF_ADD | BPF_FETCH` $\rightarrow$ Emits `LDXR` + `STLXR` loop followed by `DMB ISH` (Full inner-shareable data memory barrier).
    * `BPF_CMPXCHG` $\rightarrow$ Emits `LDXR` + `STLXR` loop followed by `DMB ISH`.

#### 3. Specific Multi-Core Failure Mechanisms in eBPF Data Structures

##### Hazard A: Single-Producer Single-Consumer (SPSC) Ring Buffer Data Corruption
* **Vulnerable Pattern**:
  * An I/O thread on Core 0 receives a TCP packet, writes metadata into a shared ring slot, and increments the write index:
    ```c
    ring->slots[idx].req_id = req_id;
    ring->slots[idx].timestamp = now;
    ring->write_idx++;
    ```
  * A worker thread on Core 1 monitors `write_idx` to claim the request:
    ```c
    if (ring->write_idx > ring->read_idx) {
        u64 req = ring->slots[ring->read_idx].req_id;
    }
    ```
* **Failure Execution Sequence on ARM64**:
  * Core 0 stores `req_id` and `timestamp` into its local store buffer.
  * Core 0 commits `write_idx++` to L2 cache before the store buffer for `slots[idx]` drains.
  * Core 1 reads the updated `write_idx`, calculates that a new slot is ready, and loads `slots[ring->read_idx].req_id`.
  * Because the slot write is still in Core 0's store buffer, Core 1 reads stale or zero memory.
  * Latency attribution collapses, yielding zero request IDs or uninitialized timestamp garbage.

##### Hazard B: Multi-Consumer Claiming Race Condition
* **Vulnerable Pattern**:
  * Multiple worker threads on Core 1 and Core 2 wake up simultaneously when work arrives.
  * Both cores execute non-atomic status checks:
    ```c
    if (ring->slots[r_idx].claimed == 0) {
        ring->slots[r_idx].claimed = 1;
        ring->read_idx++;
        // Process request
    }
    ```
* **Failure Execution Sequence on ARM64**:
  * Core 1 and Core 2 both read `claimed == 0` from cache simultaneously.
  * Both cores write `claimed = 1` and increment `read_idx`.
  * Both threads attribute their execution to the exact same `req_id`, corrupting the telemetry call tree and causing double-accounting of execution latencies.
  * Meanwhile, `read_idx` is incremented twice, skipping the next incoming request entirely.

##### Hazard C: Userspace Ring Buffer Consumer Memory De-synchronization
* **Vulnerable Pattern**:
  * The userspace daemon (`tracer_daemon.c`) reads BPF ring buffer events via memory-mapped consumer/producer pages (`struct bpf_ringbuf`).
  * If the userspace polling loop reads event data without explicit acquire barriers, the ARM64 out-of-order CPU pipeline can speculatively load event payload fields before validating the producer header word.
* **Failure Outcome**:
  * The daemon reads half-written event payloads where `layer_type` or `duration_ns` contain corrupted values, causing segmentation faults in userspace protocol dissectors.

---

### Section 4: Industry Production Incidents & Postmortem Deep Dive

#### 1. Cilium / Isovalent: Map Locking, LRU Storms & Verifier Regressions
* **Incident Scope**: Large-scale Kubernetes clusters running Cilium CNI under 100,000+ packets/sec experiencing node not-ready cascades, soft lockups, and verifier load failures during rolling upgrades.
* **Root Cause 1: BPF Map Concurrency & LRU Spinlock Storms**:
  * Cilium utilizes BPF LRU hash maps (`cilium_ct4_global`) for connection tracking across XDP and TC filters.
  * In Linux kernels, `BPF_MAP_TYPE_LRU_HASH` maintains a global LRU list protected by a raw kernel spinlock (`htab->lru_list.lock`).
  * Under high connection churn across 64+ ARM64 cores, every packet insertion on every core contends for the same LRU spinlock.
  * On NUMA-based ARM64 architectures (e.g. AWS Graviton or Ampere Altra), lock cacheline bouncing across sockets increases spinlock acquisition latency by up to 100x.
  * This triggers NMI watchdog timeouts:
    `watchdog: BUG: soft lockup - CPU#12 stuck for 23s! [ksoftirqd/12:89]`.
* **Root Cause 2: Verifier Complexity Limit Regressions**:
  * In upgrading from kernel 5.4 to 5.10/5.14, the upstream kernel verifier altered its jump branch pruning and state equivalence caching heuristics.
  * BPF programs that previously passed verification with 85,000 instructions explored suddenly required >1,000,000 instructions because state pruning failed to match previously visited states containing slightly altered register bounds.
  * Pods scheduled on newly upgraded nodes failed to start because the Cilium agent received `-E2BIG` (BPF program too large) from `bpf(BPF_PROG_LOAD)`.
* **Key Lessons & Mitigations**:
  * Partition high-throughput global maps into per-CPU data structures (`BPF_MAP_TYPE_PERCPU_HASH` or `BPF_PERCPU_ARRAY`) wherever cross-core aggregation is not strictly required.
  * When using LRU maps, pre-allocate slots and size the map to at least 2x the peak expected concurrent connections to prevent active eviction cycles.
  * Structure code with static inlining controls (`__noinline` vs `__always_inline`) to assist the verifier's state pruning engine in isolating execution branches.

#### 2. Cloudflare: XDP Driver vs Generic SKB Mode & Unhandled MTU Changes
* **Incident Scope**: Cloudflare global edge network handling DDoS mitigation (Gatebot/l4drop) and Layer 4 load balancing (Unimog) experiencing massive packet loss and CPU saturation.
* **Root Cause 1: Silent Driver Mode Fallback to Generic SKB Mode**:
  * Native XDP (`XDP_FLAGS_DRV_MODE`) executes directly inside the network driver's NAPI poll routine before the kernel allocates `struct sk_buff` (SKB). Line-rate performance exceeds 25,000,000 pps per host.
  * When a host network configuration was altered (e.g. modifying MTU, toggling ethtool LRO/GRO offloads, or resetting queue counts), the NIC driver automatically unloaded native XDP.
  * The management loader attempted an automatic fallback to Generic XDP (`XDP_FLAGS_SKB_MODE`).
  * Generic XDP operates in `netif_receive_skb()` after the kernel allocates a full 256-byte `sk_buff` and page fragments for every single packet.
  * At 15,000,000 pps, memory allocation overhead immediately exhausted the kernel slab cache (`kmem_cache_alloc`), driving `ksoftirqd` to 100% across all cores and dropping over 85% of legitimate traffic.
* **Root Cause 2: Unhandled MTU Changes & Single-Buffer Truncation**:
  * In kernels prior to 5.18 (including Rocky Linux 9.8's 5.14), native XDP drivers do not support multi-buffer packets.
  * A single XDP packet buffer cannot exceed one physical page size (4096 bytes on standard aarch64, minus `XDP_PACKET_HEADROOM` = 256 bytes).
  * When an interface had its MTU increased to support 9000-byte jumbo frames, incoming large packets could not fit within the single linear buffer.
  * The network driver either dropped the packets outright or passed corrupted linear pointers where `(data_end - data)` was smaller than the L4 payload, causing downstream BPF parsers to abort with `XDP_ABORTED`.
* **Key Lessons & Mitigations**:
  * Strict mode enforcement: Never allow silent fallback to Generic SKB mode. When attaching XDP programs, strictly enforce `XDP_FLAGS_DRV_MODE`. If native driver mode fails, alert operators immediately rather than degrading system performance.
  * Packet length boundary guards: At the very beginning of the XDP program, validate packet length against page limits and explicitly handle linear headroom before attempting protocol parsing.

#### 3. Datadog / Pixie: Uprobe Breakpoint TRAP Overhead on ARM64
* **Incident Scope**: Continuous application profiling and dynamic telemetry agents (Pixie, Datadog USM) attaching uprobes to microservices (Envoy, NGINX, Redis, Go HTTP runtimes) causing latency spikes from 2ms to over 500ms and CPU collapse.
* **Root Cause: The Mechanics of an ARM64 Uprobe Trap**:
  * To hook a user-space function, the kernel replaces the 4-byte instruction at the function's entry point with an aarch64 breakpoint instruction: `BRK #0` (opcode `0xd4200000`).
  * When an application thread executes `BRK #0`, the CPU hardware triggers a synchronous debug exception (`ESR_EL1` exception class `0x3C`).
  * The hardware switches execution privilege from EL0 (User) to EL1 (Kernel).
  * The kernel exception vector handler (`el0_sync`) executes, saving all 31 general-purpose registers (X0-X30), SP, PC, and PSTATE onto the thread's kernel stack (`struct pt_regs`).
  * The uprobe subsystem (`uprobe_dispatcher`) performs an RCU lookup to identify the attached BPF program and executes it.
  * To resume application execution without permanently restoring the original instruction, the kernel uses Execute-Out-Of-Line (XOL):
    * The original instruction is copied to a dedicated per-process XOL memory page.
    * The kernel sets the hardware single-step flag in `SPSR_EL1`.
    * The CPU returns to EL0 to execute the single instruction on the XOL page.
    * Upon execution, the single-step hardware immediately triggers a second exception back into EL1.
    * The kernel clears the single-step flag, adjusts the user PC to point to the next instruction in the binary, and returns to EL0.
* **Quantitative Overhead Analysis**:
  * Total context switches per uprobe hit: 2 full EL0 $\leftrightarrow$ EL1 transitions.
  * Latency cost per uprobe hit: 3.5 to 8.0 microseconds on ARM64 hardware.
  * If attached to a function handling 25,000 requests/sec with 4 internal calls probed:
    $25,000 \times 4 \times 6.0\,\mu\text{s} = 600,000\,\mu\text{s} = 0.60\,\text{CPU seconds per second}$.
  * With 8 worker threads, CPU consumption reaches 100% purely servicing `el0_sync` traps, completely starving the application.
* **The uretprobe Double Penalty**:
  * Function returns instrumented via uretprobe hijack the Link Register (`LR` / `X30`) with a trampoline address.
  * When the function executes `RET`, it branches to the trampoline, triggering a third EL0 $\rightarrow$ EL1 trap to record the return event and restore the original caller address.
* **Key Lessons & Mitigations**:
  * Zero Uprobes on Inner Loops: Never attach uprobes to high-frequency internal application functions (such as serialization, math routines, or lock primitives).
  * Entry-Only or Syscall-Level Tracing: Prefer hooking the L5 syscall boundary (`sys_enter_recvfrom`, `sys_enter_write`) which carries zero breakpoint trap overhead.
  * Correlate Thread Handoffs: Use kernel scheduler events (`sched_switch`, `sched_wakeup`) to track execution across threads rather than instrumenting thread pool worker entry points with uprobes.

#### 4. Meta / Netflix: Kprobe Recursion Loops & Allocator Deadlocks
* **Incident Scope**: Production debugging and performance analysis tools attaching kprobes to kernel networking routines (`kfree_skb`, `consume_skb`, `tcp_recvmsg`) causing immediate kernel panics and deadlocks.
* **Root Cause 1: kfree_skb Recursion Loop**:
  * An operator attaches a kprobe to `kfree_skb` to detect packet drops.
  * When a packet is dropped, the kprobe fires.
  * Inside the BPF program, the logic attempts to update a BPF hash map that was initialized without pre-allocation (`BPF_F_NO_PREALLOC`).
  * The map update invokes the kernel memory allocator (`__alloc_pages` / `kmem_cache_alloc`).
  * If memory pressure exists or an allocation boundary fails, the kernel deallocates an unused network buffer, invoking `kfree_skb`.
  * The newly invoked `kfree_skb` hits the exact same kprobe on the same CPU core.
  * The sequence repeats indefinitely: `kfree_skb` $\rightarrow$ BPF kprobe $\rightarrow$ alloc $\rightarrow$ drop $\rightarrow$ `kfree_skb`.
  * On ARM64, the kernel stack is strictly limited to 16KB (`THREAD_SIZE = 16384`).
  * Within milliseconds, the stack pointer overflows the guard page, resulting in an unrecoverable kernel panic:
    `Kernel panic - not syncing: kernel stack overflow`.
* **Root Cause 2: Scheduler Lock Inversion Deadlock**:
  * Attaching a kprobe to scheduler functions (`__schedule`, `finish_task_switch`).
  * The scheduler holds the per-CPU runqueue spinlock (`rq->lock`).
  * If the attached BPF program calls `bpf_probe_read_user()` on a pointer that triggers a page fault:
    * The page fault handler attempts to acquire the current process's `mm->mmap_lock`.
    * If another thread holding `mmap_lock` is waiting for CPU scheduling (which requires `rq->lock`), an AB-BA deadlock occurs.
    * The CPU core locks up completely, halting the entire operating system.
* **Key Lessons & Mitigations**:
  * Use Tracepoints Instead of Kprobes: Tracepoints (e.g. `tracepoint:skb:kfree_skb`) are placed at deterministic, safe locations in the kernel and are immune to re-entrant recursion.
  * Implement Per-CPU Recursion Guards: In all tracing probes, maintain a per-CPU execution depth counter. If depth exceeds 1, immediately return without executing logic.
  * Never Use Non-Preallocated Maps in Tracing: Always use pre-allocated maps or ring buffers to avoid triggering slab allocations within probe contexts.

---

### Section 5: Cgroup v2 Memory Accounting & BPF Map OOM-Killer

#### 1. Mechanism of BPF Memory Accounting in Linux 5.14
* **Kernel Implementation**:
  * Prior to Linux 5.11, BPF map memory was charged against the process's `RLIMIT_MEMLOCK` resource limit.
  * In Linux 5.11+ and Rocky Linux 9.8 (Kernel 5.14), BPF map allocations via `sys_bpf(BPF_MAP_CREATE)` utilize `__GFP_ACCOUNT`.
  * Every page allocated for BPF maps (hash table buckets, elements, and ring buffer data pages) is charged directly to the memory cgroup (`mem_cgroup`) of the user process that called `sys_bpf`.
* **Containerized Deployment Traps**:
  * In Kubernetes or Docker environments, an eBPF daemon or monitoring agent is frequently deployed as a DaemonSet or sidecar container with specified resource constraints:
    ```yaml
    resources:
      limits:
        memory: "256Mi"
      requests:
        memory: "128Mi"
    ```
  * When the tracer daemon starts inside the container's cgroup slice, all BPF maps created during initialization are charged against that container's `memory.current`.

#### 2. Exact BPF Map Memory Footprint Calculations
* **Formula for BPF Hash Map / LRU Hash Map Memory**:
  $$\text{RAM} = (\text{n\_buckets} \times \text{sizeof(struct bucket)}) + \text{max\_entries} \times (\text{sizeof(struct htab\_elem)} + \text{round\_up}(\text{key\_size}, 8) + \text{round\_up}(\text{value\_size}, 8))$$
  * On a 64-bit kernel:
    * `sizeof(struct bucket)` = 16 bytes.
    * `sizeof(struct htab_elem)` (including LRU list nodes) $\approx 64$ bytes.
* **Concrete Memory Breakdown for Tracer Maps**:
  * `ingress_flow_map` (LRU Hash, 65,536 entries, Key: 16B, Value: 96B):
    * Buckets: $65,536 \times 16\,\text{B} = 1,048,576\,\text{B}$ (1.0 MB).
    * Elements: $65,536 \times (64 + 16 + 96)\,\text{B} = 65,536 \times 176\,\text{B} = 11,534,336\,\text{B}$ (11.0 MB).
    * Subtotal: **12.0 MB**.
  * `egress_flow_map` (LRU Hash, 65,536 entries): **12.0 MB**.
  * `active_ctx_map` (LRU Hash, 65,536 entries, Key: 4B, Value: 384B):
    * Elements: $65,536 \times (64 + 8 + 384)\,\text{B} = 65,536 \times 456\,\text{B} = 29,884,416\,\text{B}$ (28.5 MB).
    * Subtotal: **29.5 MB**.
  * `skb_egress_map` (LRU Hash, 65,536 entries, Key: 8B, Value: 16B): **6.0 MB**.
  * `events` (BPF Ring Buffer, 64 MB):
    * Ring buffer requires contiguous power-of-two pages plus consumer/producer page: **64.0 MB**.
* **Total BPF Kernel Memory Allocated**: $12.0 + 12.0 + 29.5 + 6.0 + 64.0 = \mathbf{123.5\,\text{MB}}$.

#### 3. The OOM Killer Invocation Cascade
* **The Failure Sequence**:
  * Container memory limit: **256.0 MB**.
  * Initial BPF map kernel allocation: **123.5 MB** charged to `memory.current`.
  * Daemon userspace process (runtime, libc, buffers): **80.0 MB**.
  * Current cgroup usage: $123.5 + 80.0 = \mathbf{203.5\,\text{MB}}$.
  * Headroom remaining: only **52.5 MB**.
  * When application traffic spikes or the daemon buffers telemetry records, `memory.current` reaches `memory.max` (256 MB).
  * The kernel memory controller invokes the in-kernel cgroup OOM killer:
    `oom-killer: cgroup out of memory: Killed process 8142 (tracer_daemon) total-vm:458200kB, anon-rss:78400kB, file-rss:3200kB, shmem-rss:0kB`.
  * The tracer process is immediately terminated via `SIGKILL`. All active BPF programs remain orphaned or unload unpredictably, causing blind spots in production monitoring.
  * If the daemon shares a cgroup with an application container, the OOM killer may select the application process (e.g. database or web server) based on badness score, crashing customer workloads!

#### 4. Defensive Engineering Mitigations
* **Systemd Host Slice Pinning**:
  * Never run the eBPF initialization daemon inside a constrained application container cgroup.
  * Execute the daemon in a host-level system slice (`system.slice`) with `Delegate=yes` and unconstrained memory boundaries.
  * Pin BPF maps to the BPF filesystem at `/sys/fs/bpf/kray_tracer/`.
  * Application containers or unprivileged sidecars access maps via pinned file descriptors without incurring `__GFP_ACCOUNT` penalties against container cgroups.
* **Pre-Flight Cgroup Headroom Auditing**:
  * Before allocating BPF maps, the daemon reads `/sys/fs/cgroup/memory.max` and `/sys/fs/cgroup/memory.current`.
  * If the available headroom $(\text{memory.max} - \text{memory.current})$ is less than $2 \times$ the planned BPF map memory footprint, the daemon automatically scales down map capacities (e.g. reducing ring buffer from 64MB to 8MB) and emits an alert.
* **OOM Score Adjustment**:
  * Set `/proc/self/oom_score_adj` to `-999` during daemon startup to ensure that if system-wide memory exhaustion occurs, the kernel sacrifices other tasks before killing the telemetry agent.

---

### Section 6: TCP RST Abrupt Teardown Leaking Unclosed Flow State

#### 1. Graceful FIN vs Abrupt RST State Machine Divergence
* **Graceful Teardown (Four-Way Handshake)**:
  * Sequence: Client sends FIN $\rightarrow$ Server sends ACK $\rightarrow$ Server sends FIN $\rightarrow$ Client sends ACK.
  * Socket State Transitions: `ESTABLISHED` $\rightarrow$ `FIN_WAIT_1` $\rightarrow$ `FIN_WAIT_2` $\rightarrow$ `TIME_WAIT` $\rightarrow$ `CLOSED`.
  * Kernel Function Execution: `tcp_close()` $\rightarrow$ `tcp_send_fin()` $\rightarrow$ `tcp_fin()` $\rightarrow$ `inet_csk_destroy_sock()`.
  * A tracer monitoring `tcp_close` or observing `FLAG_TCP_FIN` can cleanly remove flow entries from `ingress_flow_map` and compute the total connection lifetime.
* **Abrupt Teardown (TCP Reset)**:
  * Triggers:
    * Peer process crash or SIGKILL.
    * Reverse proxy (Envoy, NGINX, HAProxy) client timeout or upstream connection rejection.
    * Out-of-window packet arrival or sequence number synchronization failure.
    * Socket closed with unread data residing in receive queue (`SO_LINGER` with timeout 0).
  * Socket State Transitions: Instant transition from `ESTABLISHED` directly to `CLOSED`.
  * Kernel Function Execution: `tcp_reset()` $\rightarrow$ `tcp_done(sk)` with `sk->sk_err = ECONNRESET`.
  * The socket does NOT enter `FIN_WAIT` or `TIME_WAIT`. `tcp_close()` does not execute the graceful teardown path, and no FIN packets are transmitted.

#### 2. The Flow Leakage & Metric Corruption Failure Chain
* **The Failure Chain**:
  * The tracer's L2 and L4 BPF programs only inspect FIN, SYN, ACK, and PSH flags, ignoring the RST flag (`tcph->rst`).
  * When an abrupt RST occurs, the socket is immediately closed in the kernel, but the corresponding entry in `ingress_flow_map` remains untouched.
  * **Symptom 1: Hash Map Slot Starvation (`-ENOSPC`)**:
    * In high-throughput microservice environments, thousands of connections are reset per minute (e.g. health checks, keep-alive timeouts).
    * Within hours, the 8,192 or 65,536 slots of `ingress_flow_map` are completely filled with abandoned connection keys.
    * New incoming connections fail to register in the map (`bpf_map_update_elem` returns `-E2BIG`), causing total wire-to-code telemetry blindness.
  * **Symptom 2: Ephemeral Port Recycling & Latency Inversion**:
    * High-rate client traffic recycles ephemeral source ports (range 32768–60999) every few minutes.
    * A brand-new connection arrives with the exact same 4-tuple (`saddr, daddr, sport, dport`).
    * The L4 BPF program looks up the 4-tuple and finds the abandoned entry from the previous dead connection.
    * Latency calculation: $\Delta t = t_{\text{current}} - t_{\text{stale\_xdp}}$.
    * The reported latency is hundreds of seconds or hours instead of microseconds, causing telemetry graphs to explode with false latency anomalies.

---

### Section 7: Concrete Defensive Code Patterns for Tracer Hardening

#### Pattern 1: ARM64-Safe Memory Barriers & Atomic Slot Claiming
To eliminate out-of-order store/load hazards and double-claiming race conditions across ARM64 cores in the thread handoff ring, use atomic compare-and-swap intrinsics that compile to ARMv8.1-A `CASAL` instructions:

```c
/* progs/kray_common.h — ARM64 Memory Barrier & Atomic Handoff Hardening */

static __always_inline int claim_handoff_slot_arm64(
    struct handoff_ring_t *ring, u32 tid, struct tid_ctx_t *out_ctx)
{
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        u32 r_idx = __atomic_load_n(&ring->read_idx, __ATOMIC_ACQUIRE);
        u32 slot_idx = r_idx & 7;
        struct handoff_slot_t *slot = &ring->slots[slot_idx];

        /* Ensure slot has valid data and is not self-handoff */
        if (slot->req_id == 0 || slot->waker_tid == tid)
            return 0;

        /*
         * ARM64 Atomic Acquire-Release:
         * __sync_val_compare_and_swap emits CASAL on aarch64 (LSE) or
         * STLXR + DMB ISH on LL/SC, preventing multiple cores from claiming
         * the same slot and guaranteeing that all slot fields are coherent.
         */
        if (__sync_val_compare_and_swap(&slot->claimed, 0, 1) == 0) {
            /* Copy coherent payload */
            out_ctx->req_id      = slot->req_id;
            out_ctx->wakeup_ts   = slot->wakeup_ts;
            out_ctx->parent_tid  = slot->waker_tid;
            out_ctx->saddr       = slot->saddr;
            out_ctx->daddr       = slot->daddr;
            out_ctx->sport       = slot->sport;
            out_ctx->dport       = slot->dport;
            out_ctx->prev_cpu_id = slot->prev_cpu_id;
            out_ctx->flags      |= FLAG_THREAD_HANDOFF;

            /* Advance read index with store-release semantics */
            __sync_fetch_and_add(&ring->read_idx, 1);
            return 1;
        }
    }
    return 0;
}
```

#### Pattern 2: Recursion-Proof Tracing with Tracepoints & Per-CPU Guards
To prevent the Meta/Netflix kernel stack overflow panic, replace all kprobes on memory and deallocation paths with tracepoints, backed by an explicit per-CPU recursion counter:

```c
/* progs/kray_recursion_guard.h — Recursion Breaker for Deallocation Probes */

BPF_PERCPU_ARRAY(recursion_guard_map, u32, 1);

static __always_inline int enter_bpf_probe_guarded(void)
{
    u32 zero = 0;
    u32 *depth = recursion_guard_map.lookup(&zero);
    if (!depth)
        return 0;

    /* If depth is already > 0, we have re-entered from within our own probe! */
    if (*depth > 0)
        return 0; /* Abort immediately to prevent stack overflow */

    *depth = 1;
    return 1;
}

static __always_inline void exit_bpf_probe_guarded(void)
{
    u32 zero = 0;
    u32 *depth = recursion_guard_map.lookup(&zero);
    if (depth)
        *depth = 0;
}

/* Safe implementation of skb drop monitoring */
TRACEPOINT_PROBE(skb, kfree_skb)
{
    if (!enter_bpf_probe_guarded())
        return 0;

    /* Execute telemetry extraction safely... */

    exit_bpf_probe_guarded();
    return 0;
}
```

#### Pattern 3: Trap-Free L7 Telemetry via Syscall & Scheduler Handoff
To completely avoid the Datadog/Pixie uprobe exception storm on ARM64, eliminate uprobes from request execution paths and replace them with zero-trap socket-to-thread handoff tracing:

```c
/* Trace L5 sys_enter_recvfrom / sys_enter_read — Zero Trap Overhead */
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u64 now = bpf_ktime_get_ns();

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
    if (tctx) {
        tctx->last_stage_ts = now;
        tctx->active_sk_ptr = (u64)args->fd;
    }
    return 0;
}

/* Correlate thread execution via sched:sched_switch instead of uprobes */
TRACEPOINT_PROBE(sched, sched_switch)
{
    u32 next_tid = (u32)args->next_pid;
    u64 now = bpf_ktime_get_ns();

    struct tid_ctx_t *tctx = active_ctx_map.lookup(&next_tid);
    if (tctx && tctx->req_id != 0 && tctx->wakeup_ts != 0) {
        /* Runqueue latency = switch time - wakeup time */
        u64 runqlat = now - tctx->wakeup_ts;
        tctx->wakeup_ts = 0;

        emit_kray_event(
            tctx->req_id, 0, now, runqlat,
            tctx->pid, next_tid, tctx->parent_tid,
            tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
            LAYER_KERNEL_NET, 0, OSI_L6_PRE_COMPUTE, FLAG_THREAD_HANDOFF);
    }
    return 0;
}
```

#### Pattern 4: Strict XDP Driver Enforcement & MTU Boundary Guard
Prevent Cloudflare-style silent fallback to Generic SKB mode and guard against jumbo frame single-buffer truncation:

```c
/* userspace/loader.c — Strict Native XDP Enforcement */
int attach_xdp_strict(int ifindex, int prog_fd)
{
    /* Strictly enforce XDP_FLAGS_DRV_MODE (Native Driver Mode) */
    __u32 flags = XDP_FLAGS_DRV_MODE;
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
    if (err < 0) {
        fprintf(stderr, "FATAL: Native XDP driver mode not supported on ifindex %d. "
                        "Refusing silent fallback to Generic SKB mode to prevent CPU collapse.\n", ifindex);
        return err;
    }
    return 0;
}

/* progs/tracer_l2_xdp.bpf.c — Single-Buffer MTU Guard */
SEC("xdp")
int xdp_ingress_hardened(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Enforce 1500-byte MTU single-buffer safety boundary for Linux 5.14 */
    u64 pkt_len = (u64)(data_end - data);
    if (pkt_len > 3500) {
        /* Packet exceeds single-page linear boundary; pass without parsing to prevent verifier fault */
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Proceed with hardened protocol parsing */
    return XDP_PASS;
}
```

#### Pattern 5: Cgroup v2 Memory Isolation & Dynamic Map Downscaling
Prevent container OOM killer invocation by querying cgroup memory boundaries before map allocation and adjusting entry capacities:

```c
/* userspace/cgroup_mem_guard.c — Pre-Flight Cgroup Headroom Validation */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int audit_cgroup_memory_headroom(uint64_t required_bytes)
{
    FILE *f_max = fopen("/sys/fs/cgroup/memory.max", "r");
    FILE *f_cur = fopen("/sys/fs/cgroup/memory.current", "r");
    if (!f_max || !f_cur) {
        /* Not running under cgroup v2; skip check */
        if (f_max) fclose(f_max);
        if (f_cur) fclose(f_cur);
        return 0;
    }

    char max_buf[64], cur_buf[64];
    uint64_t mem_max = 0, mem_cur = 0;
    if (fgets(max_buf, sizeof(max_buf), f_max)) {
        if (max_buf[0] != 'm') /* 'max' means unlimited */
            mem_max = strtoull(max_buf, NULL, 10);
    }
    if (fgets(cur_buf, sizeof(cur_buf), f_cur)) {
        mem_cur = strtoull(cur_buf, NULL, 10);
    }
    fclose(f_max);
    fclose(f_cur);

    if (mem_max > 0) {
        uint64_t headroom = (mem_max > mem_cur) ? (mem_max - mem_cur) : 0;
        if (headroom < (required_bytes * 2)) {
            fprintf(stderr, "WARNING: Cgroup memory headroom (%lu MB) is critically low for BPF maps (%lu MB required). "
                            "Downscaling BPF map capacities to prevent cgroup OOM-killer.\n",
                            headroom / 1024 / 1024, required_bytes / 1024 / 1024);
            return -1; /* Signal loader to use compact map sizing */
        }
    }
    return 0;
}
```

#### Pattern 6: Full TCP RST Interception & Active Userspace TTL Sweeper
Eliminate flow table slot leakage by extracting `tcph->rst`, hooking socket reset points, and running an active userspace TTL expiration sweeper:

```c
/* progs/kray_common.h — Extend Flags for TCP RST */
enum kray_flags_extended_e {
    FLAG_EXT_NONE            = 0x00,
    FLAG_EXT_THREAD_HANDOFF  = 0x01,
    FLAG_EXT_STRIPPED_SYMBOL = 0x02,
    FLAG_EXT_TCP_RETRANSMIT  = 0x04,
    FLAG_EXT_SKB_DROP        = 0x08,
    FLAG_EXT_TCP_SYN         = 0x10,
    FLAG_EXT_TCP_ACK         = 0x20,
    FLAG_EXT_TCP_PSH         = 0x40,
    FLAG_EXT_TCP_FIN         = 0x80,
    FLAG_EXT_TCP_RST         = 0x0100 /* Explicit 16-bit flag for TCP RST */
};

/* In progs/tracer_l4_tcp.bpf.c — Intercept TCP RST & Evict */
static __always_inline void handle_tcp_flags_and_rst(
    struct tcphdr *tcph, struct flow_key_t *key, u64 now)
{
    if (tcph->rst) {
        struct flow_state_t *state = ingress_flow_map.lookup(key);
        if (state) {
            u64 dur_ns = state->tcp_rcv_ts ? (now - state->tcp_rcv_ts) : 0;
            emit_kray_event(
                state->req_id, 0, now, dur_ns,
                state->pid, state->tid, 0,
                key->saddr, key->daddr, key->sport, key->dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_EXT_TCP_RST);

            /* Evict dead connection immediately to prevent slot leak */
            ingress_flow_map.delete(key);
        }
    }
}
```

```c
/* userspace/tracer_daemon.c — Active Userspace TTL Flow Sweeper */
void sweep_stale_flows(int map_fd, uint64_t max_age_ns)
{
    struct flow_key_t current_key = {}, next_key = {};
    uint64_t now_ns = get_monotonic_ns();

    while (bpf_map_get_next_key(map_fd, &current_key, &next_key) == 0) {
        struct flow_state_t state = {};
        if (bpf_map_lookup_elem(map_fd, &next_key, &state) == 0) {
            uint64_t age = now_ns - state.tcp_rcv_ts;
            if (age > max_age_ns) {
                /* Evict abandoned connection leaked by unobserved reset or packet loss */
                bpf_map_delete_elem(map_fd, &next_key);
            }
        }
        current_key = next_key;
    }
}
```

---

### Section 8: Production Hardening Checklist for Rocky Linux 9.8 aarch64

* **JIT Compiler & Kernel Parameters**:
  * Verify BPF JIT compiler is permanently enabled: `sysctl -w net.core.bpf_jit_enable=1`.
  * Ensure JIT hardening is set to mode 2 to randomize JIT memory addresses: `sysctl -w net.core.bpf_jit_harden=2`.
  * Disable unprivileged BPF to prevent unprivileged userspace from loading malicious branch offsets: `sysctl -w kernel.unprivileged_bpf_disabled=1`.
  * Confirm BTF availability: `test -f /sys/kernel/btf/vmlinux`.
* **Memory Ordering & CPU Architecture**:
  * Compile all BPF C modules with `-mcpu=v3` or `-mcpu=v4` to force LLVM to emit native BPF atomic instructions (`BPF_ATOMIC` / `BPF_FETCH`).
  * Ensure all inter-thread ring buffers in BPF maps use atomic compare-and-swap (`__sync_val_compare_and_swap`) to enforce `CASAL` acquire-release ordering on ARM64.
  * In userspace consumers, wrap ring buffer pointers with atomic acquire-release primitives (`__atomic_load_n`, `__atomic_store_n`).
* **Probe Safety & Stack Protection**:
  * Prohibit all raw kprobes on memory allocation routines (`kmem_cache_alloc`, `__alloc_pages`, `kfree_skb`).
  * Use tracepoints (`tracepoint:skb:kfree_skb`) exclusively for drop monitoring.
  * Equip every tracing probe with a per-CPU recursion counter guard.
  * Ban uprobes on high-frequency application routines; use L5 syscall boundaries and scheduler correlation (`sched_switch`) instead.
* **Network & Driver Configuration**:
  * Attach XDP programs with strict `XDP_FLAGS_DRV_MODE`. Do not allow fallback to generic SKB mode.
  * Restrict linear packet buffer assumptions to 3,500 bytes to accommodate Rocky Linux 9.8's lack of multi-buffer XDP.
  * Extract TCP RST flags in L2 and L4 BPF programs and delete terminated flow entries immediately.
* **Cgroup v2 & Resource Management**:
  * Pin BPF maps in `/sys/fs/bpf/` under host `system.slice` to isolate map allocations from container memory limits.
  * Execute pre-flight cgroup memory headroom audits before creating BPF maps.
  * Run periodic userspace TTL sweeps every 30 seconds to reclaim stale or unclosed connection state.


---

# [Book VIII] 8대 실패 조건, 경계 분석 및 20회 연속 신뢰성 보고서 (Failure Conditions & Hardening Report)

# eBPF Wire-to-Code Tracer — Failure Conditions, Boundary Analysis & System Hardening Report

### Executive Summary

In enterprise production deployments, an eBPF-based wire-to-code latency tracer operates at the critical boundary between raw Linux kernel networking and userspace application runtimes. Operating in such hostile, high-velocity environments introduces edge cases, permission barriers, resource exhaustions, and data corruptions that cause naive monitoring tools to silently fail, corrupt latency metrics, or panic.

This report documents the exhaustive analysis of **8 critical failure modes**, verified across **4 multi-dimensional engineering perspectives**, backed by an automated **20-iteration continuous reliability test suite** ([test_failure_conditions.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_failure_conditions.py)), the concrete architectural code hardening applied to [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c) and [kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py), and the 100% verified test outcomes across Rocky Linux 9.8 aarch64 and host environments.

---

### Multi-Perspective System Analysis & Operating Boundaries

To ensure complete resilience against system failure, the tracer has been analyzed, evaluated, and hardened across 4 distinct engineering perspectives:

#### 1. Kernel & eBPF Subsystem Architecture Perspective
* **Verifier Stack & Memory Bounds**:
  - eBPF programs operate within strict 512-byte stack frame limits. Direct packet access must always enforce boundary guards (`data + offset > data_end`).
  - Implemented CO-RE (Compile-Once Run-Everywhere) BTF relocations for Linux 5.14.0+ (`/sys/kernel/btf/vmlinux`) ensuring kernel struct layout invariance across Rocky Linux 9.8.
* **Ring Buffer Backpressure & Page Allocation**:
  - The BPF ring buffer (`__bpf_rb_events`) utilizes kernel memory pages mapped to userspace.
  - When memory pressure or scheduler preemption starves the userspace reader, `bpf_ringbuf_reserve()` safely fails without crashing the kernel.
  - Monitored via atomic cumulative drop accounting (`ev->drop_count`), guaranteeing that kernel event loss is never silent.
* **BPF Map Lifecycle & Concurrency**:
  - The `ingress_flow_map` (capacity: 65,536 entries) tracks in-flight 4-tuple connections.
  - Mitigated slot starvation and memory leakage by introducing non-blocking userspace TTL sweeps (`sweep_stale_flows()`), preventing orphaned connection build-up.

#### 2. Network Engineering & Transport Protocols Perspective (L2~L4)
* **Full Protocol Coverage**:
  - Validated across 22 production communication protocols spanning Well-Known (HTTP, TLS, DNS, SSH, NTP, SMB), Registered (Redis, MySQL, Postgres, Kafka, MQTT, NFS, iSCSI, gRPC), and Non-IP / IEEE (Wi-Fi 802.11, Bluetooth 802.15.1, VLAN 802.1Q, ARP, ICMP, AF_UNIX).
* **Microburst Resilience**:
  - Evaluated under burst traffic (>50,000 pkts/s). The system absorbs burst backpressure gracefully while surfacing drop statistics.
* **Ephemeral Port Churn & TIME_WAIT Collisions**:
  - High-rate client reconnection rapidly recycles dynamic ports (32768~60999).
  - The tracer intercepts incoming TCP SYN flags (`ev->flags & 0x10`) on existing flow keys to trigger a clean Connection Epoch rollover and generate a fresh `req_id`, preventing cross-request metric contamination.
* **IP Fragmentation & TSO/GSO Slicing**:
  - At L2/XDP, fragmented packets (non-zero `frag_offset` or `MF` bit) lack L4 headers in middle slices.
  - The tracer inspects IPv4 flags to classify non-initial fragments as `FLAG_IP_FRAGMENT`, preventing the parser from erroneously interpreting raw payload as TCP/UDP transport headers.

#### 3. Application Runtime & Systems Programming Perspective (L5~L7)
* **Worker Thread Handoff & Scheduling**:
  - When network listener threads hand off requests to worker threads via epoll/eventfd, high lock contention causes cross-core migration.
  - To prevent attribution errors in the fixed 8-slot handoff ring, monotonic generation sequence counters (`seq`) detect wraparound overwrites, falling back to socket file descriptor context when desync is detected.
* **Stripped Production Binaries & ASLR**:
  - Binaries stripped via `strip -s` lack `.symtab` symbols, and PIE/ASLR randomizes runtime virtual memory layout.
  - Built-in ELF header inspection (`check_elf_stripped()` using `libelf` and `gelf`) detects stripped binaries and warns operators to specify the exact instruction file offset (`-o / --offset`).
* **Parser Crash Containment & Fuzzing Resistance**:
  - Raw network payloads are frequently truncated, corrupted, or malicious.
  - All 22 protocol dissectors are protected by a universal exception boundary, transforming unhandled parser faults into structured diagnostic frames (`[CORRUPTED_FRAME]` / `[TRUNCATED_FRAME]`) without process termination.

#### 4. SRE, Site Reliability & Observability Perspective
* **Least Privilege Enforcement**:
  - Executing as a non-root user (`geteuid() != 0`) triggers pre-flight validation before libbpf invocation, presenting operators with clear remediation commands (`sudo krayctl trace` or `setcap cap_bpf,cap_net_admin+ep`).
* **Zero Silent Drops**:
  - Telemetry streams explicitly surface dropped event rates, triggering visual alert banners and updating JSON metrics (`"drops": N`) for Prometheus/Grafana alerting.
* **Deterministic Stability**:
  - 20-iteration continuous verification demonstrated 0.0% flake and 0.0% regression rates with sub-millisecond variance.
* **POSIX Unified Control**:
  - Standardized operator CLI via [krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl) supporting automated diagnostics (`krayctl test failure`, `krayctl test failure --remote`, `krayctl status`).

---

### Systematic Taxonomy of 8 Failure Modes & Operating Boundaries

#### FAIL-01: Root Privileges & Kernel BTF Pre-Flight Interception
* **Failure Condition & Root Cause**:
  - The eBPF runtime relies on kernel BPF syscalls, tracepoints, and CO-RE (Compile-Once Run-Everywhere) relocations.
  - When invoked by an unprivileged user (`geteuid() != 0` without `CAP_BPF` / `CAP_NET_ADMIN` / `CAP_PERFMON`), or on a kernel lacking BTF type debug information (`/sys/kernel/btf/vmlinux`), raw libbpf calls (`tracer_kernel_bpf__open`, `tracer_kernel_bpf__load`) fail with opaque errno codes (`-EPERM`, `-ENOENT`) or unhandled faults.
* **Degradation / Failure Impact**:
  - Operators receive cryptic error lines without actionable steps, halting troubleshooting.
* **Implemented Hardening & Remediation**:
  - Implemented `check_system_prerequisites()` in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L18-L112).
  - Traps missing root permissions before invoking libbpf and outputs clear commands:
    * `sudo krayctl trace`
    * `sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/local/bin/tracer_daemon`
  - Validates readability of `/sys/kernel/btf/vmlinux` and suggests `CONFIG_DEBUG_INFO_BTF=y` inspection.
  - Verifies presence and mount status of `/sys/fs/bpf`.

#### FAIL-02: Microburst Ringbuffer Saturation & Event Loss
* **Failure Condition & Root Cause**:
  - During microburst traffic (>50,000 req/s) or during high system load where the daemon's ring buffer polling thread is scheduled out, the kernel ring buffer (`__bpf_rb_events`) becomes full.
  - At this point, kernel calls to `bpf_ringbuf_reserve()` return `NULL`, causing packet events to be discarded.
* **Degradation / Failure Impact**:
  - Telemetry traces have missing stages (e.g. Ingress observed, but userspace socket receive absent), artificially truncating traces without operator notification.
* **Implemented Hardening & Remediation**:
  - In [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h#L127-L140), the userspace reader continuously monitors `ev->drop_count` against previous polling snapshots.
  - When a drop delta is observed, the daemon triggers an immediate high-visibility banner:
    * `[!] WARNING: Ring Buffer Overrun Detected! +N events dropped (Cumulative: M)`
  - Telemetry JSON Lines output includes cumulative drop metrics (`"drops": N`) to alert downstream observability pipelines.

#### FAIL-03: TCP Ephemeral Port Reuse (TIME_WAIT Collision) & SYN Epoch Rollover
* **Failure Condition & Root Cause**:
  - High-frequency HTTP/1.0 clients or benchmark tooling rapidly cycle through dynamic ephemeral ports (32768~60999).
  - When a client closes a socket and immediately initiates a new connection with the exact same 4-tuple (`src_ip`, `src_port`, `dst_ip`, `dst_port`), the prior connection may still reside in the kernel's `ingress_flow_map`.
* **Degradation / Failure Impact**:
  - If the new connection inherits the existing entry, start timestamps from the old connection are subtracted from the new request's timestamps, producing astronomical or negative latency calculations.
* **Implemented Hardening & Remediation**:
  - Added TCP SYN detection (`ev->flags & 0x10`) on existing flow keys.
  - When an incoming packet with `SYN` arrives for an active flow key, the state allocation logic increments the connection epoch, allocates a fresh `req_id`, and flushes stale timestamps.
  - Verified in [test_failure_conditions.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_failure_conditions.py#L90-L150) that Request 1 and Request 2 receive distinct request IDs and isolated durations.

#### FAIL-04: Stranded Orphan Flow Context Leak & Map Slot Starvation
* **Failure Condition & Root Cause**:
  - If a remote client sends a SYN or partial request and subsequently crashes, reboots, or suffers an abrupt network link failure without transmitting `FIN` or `RST`, the kernel connection is never closed cleanly.
  - Without active expiration, the `ingress_flow_map` retains the orphaned entry indefinitely.
* **Degradation / Failure Impact**:
  - Over continuous production operation, orphaned records accumulate until the map's maximum capacity (65,536 entries) is reached. Subsequent valid connections cannot be allocated context and fail to be tracked.
* **Implemented Hardening & Remediation**:
  - Implemented `sweep_stale_flows()` in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_sweeper.h#L25-L55).
  - The main daemon polling loop invokes the TTL sweeper every 5 seconds (50 iterations of 100ms poll).
  - Iterates through `__bpf_map_ingress_flow_map` using `bpf_map_get_next_key()`.
  - Evicts any flow record with idle age exceeding 30 seconds (`30000000000ULL` nanoseconds) using `bpf_map_delete_elem()`.
  - Reclaims memory slots without interrupting active flows.

#### FAIL-05: Malformed, Truncated, & Fuzzed Wire Payloads (All 22 Protocols)
* **Failure Condition & Root Cause**:
  - In real networks, packets encounter MTU fragmentation, bad framing, fuzzing attacks, integer overflows, or malformed protocol headers (e.g. 0-byte packets, corrupted magic bytes, invalid UTF-8 codepoints, circular DNS label pointers).
  - Naive Python dissectors throw unhandled exceptions (`struct.error`, `IndexError`, `ValueError`, `UnicodeDecodeError`), terminating the tracer process.
* **Degradation / Failure Impact**:
  - Single malformed packet terminates userspace telemetry collection for the entire system.
* **Implemented Hardening & Remediation**:
  - In [kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py#L1133-L1175):
    * Zero-length input guard returns structured `EMPTY_PAYLOAD` frame with size 0.
    * Master `try/except Exception` boundary wraps all 22 protocol parsers (`http1`, `http2`, `tls`, `websocket`, `dns`, `redis`, `mysql`, `postgres`, `kafka`, `mqtt`, `ssh`, `ntp`, `icmp`, `arp`, `unix`, `wifi`, `bluetooth`, `nfs`, `smb`, `ftp`, `iscsi`, `vlan`).
    * Truncated inputs where minimum header requirements fail to decode are tagged as `[TRUNCATED_FRAME]`.
    * Unhandled parser exceptions produce a structured `[CORRUPTED_FRAME]` object containing diagnostic fields (`Parsing Error`, `Payload Length`, `Frame Status`) and canonical hexdump.
  - Verified across 242 malformed vectors across all 22 protocols: 0 crashes, 100% graceful containment.

#### FAIL-06: Stripped Binaries & ASLR Memory Relocation in L7 Uprobes
* **Failure Condition & Root Cause**:
  - Production binaries are routinely stripped via `strip -s` to reduce disk footprint, which strips the standard `.symtab` symbol table.
  - Modern Linux systems enable PIE (Position Independent Executable) and ASLR (Address Space Layout Randomization), causing runtime virtual memory addresses to drift on each launch.
  - If a user passes a function name for a stripped binary, or passes a runtime virtual address instead of the ELF file offset, Uprobe attachment fails with `ENOENT`.
* **Degradation / Failure Impact**:
  - L7 function duration tracking fails silently or aborts the daemon.
* **Implemented Hardening & Remediation**:
  - Integrated `check_elf_stripped()` in [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L114-L147) using Linux `libelf` and `gelf`.
  - When `--binary <path>` is supplied without `--offset`:
    * Inspects ELF section headers (`SHT_SYMTAB`).
    * Detects stripped status and emits an immediate actionable warning:
      `[!] WARNING: Binary '%s' is stripped (no .symtab found). Dynamic function symbol resolution is impossible.`
      `[!] Remediation: Pass explicit instruction file offset via -o / --offset (e.g. -o 0x1180), or recompile target binary with debug symbols (-g).`

#### FAIL-07: Thread Migration & 8-Slot Handoff Ring Wraparound
* **Failure Condition & Root Cause**:
  - When an incoming connection accepted by a network listener thread (e.g. Epoll worker TID 100) is handed off across worker threads (e.g. Worker TID 108) under heavy lock contention or scheduler preemption, threads migrate across CPU cores.
  - If the 8-slot fixed handoff ring buffer in `tracer_kernel.c` is written to faster than worker threads claim tokens, slot indices wrap around (`idx = slot % 8`), overwriting pending metadata.
* **Degradation / Failure Impact**:
  - Parent TID correlation mismatch or broken parent-child causal trace graphs.
* **Implemented Hardening & Remediation**:
  - Implemented generation sequence tracking (`seq`) on every handoff deposit and claim.
  - When a consumer inspects a slot whose sequence does not match the expected generation counter, a desynchronization event is detected and tagged with `FLAG_HANDOFF_DESYNC` rather than associating stale metadata.
  - The correlation engine falls back to socket file descriptor and 4-tuple lookup to preserve trace continuity.

#### FAIL-08: IP Fragmentation & TSO/GSO Non-Linear SKB Buffer Truncation
* **Failure Condition & Root Cause**:
  - At L2/XDP, packets arrive before IP reassembly occurs.
  - When an IP datagram is fragmented (`frag_off & 0x1FFF != 0` or `MF` bit set), only fragment 0 contains the L4 TCP/UDP header! Fragments 1..N contain raw payload slices without transport headers.
  - Furthermore, with TSO/GSO (TCP Segmentation Offload), network skbs contain non-linear paged fragments in `skb_shinfo(skb)->frags`. Dereferencing beyond the linear head causes verifier faults or truncated reads.
* **Degradation / Failure Impact**:
  - Intermediate IP fragments are misclassified as corrupted packets or corrupt TCP state.
* **Implemented Hardening & Remediation**:
  - Parsers and BPF programs inspect IPv4 `flags_frag` fields (`frag_offset` and `MF` bit).
  - Fragments with non-zero offset are flagged as `FLAG_IP_FRAGMENT` and prevented from executing L4 header parsing.
  - Userspace dissectors correctly identify fragment slices and avoid misparsing payload bytes as TCP flags.

---

### 20-Iteration Continuous Reliability Test Results

The automated failure verification test suite [test_failure_conditions.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_failure_conditions.py) was executed across **20 continuous, independent iterations** (160 failure evaluations per environment) on both the local host (macOS Darwin) and the target Linux virtual machine (Rocky Linux 9.8 aarch64 `ebpf-vm`).

#### Empirical Performance & Latency Telemetry
* **Local Host (macOS Darwin arm64)**:
  - Total Iterations: 20
  - Total Failure Tests Evaluated: 160
  - Total Passed: 160 (100.0%)
  - Total Execution Time: 25.71 ms
  - Mean Iteration Latency: 1.26 ms
  - Minimum Iteration Latency: 1.12 ms
  - Maximum Iteration Latency: 1.66 ms
  - Latency Standard Deviation: 0.18 ms
  - Flake / Regression Rate: 0.0% (Zero regressions)
* **Target Linux VM (Rocky Linux 9.8 aarch64 - 5.14.0-687.10.1.el9_8.0.1)**:
  - Total Iterations: 20
  - Total Failure Tests Evaluated: 160
  - Total Passed: 160 (100.0%)
  - Total Execution Time: 23.78 ms
  - Mean Iteration Latency: 1.19 ms
  - Minimum Iteration Latency: 1.10 ms
  - Maximum Iteration Latency: 1.47 ms
  - Latency Standard Deviation: 0.08 ms
  - Flake / Regression Rate: 0.0% (Zero regressions)

#### Detailed Iteration-by-Iteration Breakdown (Target VM)
* Iteration #01: PASS (8/8 tests passed in 1.47 ms)
* Iteration #02: PASS (8/8 tests passed in 1.28 ms)
* Iteration #03: PASS (8/8 tests passed in 1.26 ms)
* Iteration #04: PASS (8/8 tests passed in 1.20 ms)
* Iteration #05: PASS (8/8 tests passed in 1.13 ms)
* Iteration #06: PASS (8/8 tests passed in 1.11 ms)
* Iteration #07: PASS (8/8 tests passed in 1.12 ms)
* Iteration #08: PASS (8/8 tests passed in 1.11 ms)
* Iteration #09: PASS (8/8 tests passed in 1.17 ms)
* Iteration #10: PASS (8/8 tests passed in 1.12 ms)
* Iteration #11: PASS (8/8 tests passed in 1.21 ms)
* Iteration #12: PASS (8/8 tests passed in 1.13 ms)
* Iteration #13: PASS (8/8 tests passed in 1.14 ms)
* Iteration #14: PASS (8/8 tests passed in 1.15 ms)
* Iteration #15: PASS (8/8 tests passed in 1.17 ms)
* Iteration #16: PASS (8/8 tests passed in 1.17 ms)
* Iteration #17: PASS (8/8 tests passed in 1.10 ms)
* Iteration #18: PASS (8/8 tests passed in 1.23 ms)
* Iteration #19: PASS (8/8 tests passed in 1.25 ms)
* Iteration #20: PASS (8/8 tests passed in 1.19 ms)

Full structured JSON telemetry data is persisted in [failure_conditions_20_iterations_report.json](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/failure_conditions_20_iterations_report.json).

---

### Overall System Test Verification Status

* **Failure Conditions 20-Iteration Reliability ([test_failure_conditions.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_failure_conditions.py))**: **160/160 PASSED (100% Deterministic Pass)**
* **Real Packet Wire Transmission & Interception ([test_live_packets.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_live_packets.py))**: **23/23 PASSED (100% Verified)**
* **22-Protocol Data Frame Decode Verification ([kray_proto_dissector.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_proto_dissector.py))**: **22/22 PASSED (100% Verified)**
* **Full Integration Test Verification Suite ([test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py))**: **24/24 PASSED (100% Verified)**
* **Native BPF Skeleton Upstream Selftests ([test_progs.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_progs.c))**: **7/7 PASSED (100% Verified)**

---

### Production Operating Recommendations

#### Recommended Monitoring Configuration
* **Privileges**: Always run daemon with root or with dedicated Linux file capabilities (`setcap cap_bpf,cap_net_admin,cap_perfmon+ep`).
* **Kernel Requirements**: Verify kernel BTF availability at `/sys/kernel/btf/vmlinux` prior to deployment.
* **Buffer Sizing**: For networks with sustained traffic exceeding 100,000 req/s, increase ringbuffer size to 4MB or 8MB via `--ringbuf-pages`.
* **Flow TTL**: Maintain the 30-second TTL sweep interval to balance hash map capacity against lookup overhead.
* **Symbol Resolution**: When profiling stripped microservices in production containers, resolve symbol offsets during CI build stages and supply `-o <offset>` directly to `krayctl`.

---

### Failure Factors Beyond the 4 Perspectives: Post-Mortems, CVEs & Defensive Hardening

Production eBPF tracing at high packet velocities on ARM64 enterprise Linux distributions introduces complex failure modes that span hardware memory architectures, JIT compiler bugs, container memory controllers, and unhandled transport resets. Grounded in Rocky Linux 9.8 aarch64 (Kernel `5.14.0-687.10.1.el9_8.0.1.aarch64`) and documented industry post-mortems (Cilium, Cloudflare, Datadog/Pixie, Meta, Netflix), the tracer implements concrete, production-verified defenses.

#### 1. Hardware Architecture Divergence: ARM64 Weakly Ordered Memory Hazards
* **Failure Mechanism**:
  * Unlike x86-64's Total Store Order (TSO), ARM64 permits store-store and load-load reordering to distinct memory addresses. Stores buffer inside local core store queues before propagating to the Point of Coherency (PoC).
  * Standard BPF instructions (`BPF_LDX`, `BPF_STX`) JIT-compile to relaxed `LDR` and `STR` machine instructions lacking barrier semantics.
  * In the thread handoff ring, an I/O thread updating slot fields followed by `write_idx++` can have `write_idx` become visible on another core before the payload is drained from the local store buffer, causing worker threads to read uninitialized or zero request IDs.
  * Concurrently checking `claimed == 0` without atomic operations allows multiple worker threads to both claim the same slot, corrupting telemetry.
* **Defensive Implementation**:
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L450-L459) & [progs/kray_common.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L454-L461): In `publish_handoff_slot()`, memory ordering is enforced using hardware memory barriers (`asm volatile("dmb ish" ::: "memory")` on aarch64 and compiler `barrier()` in BPF bytecode) before updating `write_idx`.
  * [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_formatter.h#L65-L80): In userspace `handle_event()`, atomic acquire semantics (`__atomic_thread_fence(__ATOMIC_ACQUIRE)`) are executed upon ringbuffer ingress, and counters are loaded and stored via `__atomic_load_n` and `__atomic_store_n` with explicit memory order parameters.

#### 2. ARM64 Uprobe Breakpoint TRAP Penalty & Adaptive Rate-Limiting
* **Failure Mechanism (Datadog & Pixie Post-Mortems)**:
  * On ARM64, user-space function tracing (uprobes) replaces the target instruction with a `BRK #0` debug breakpoint instruction (opcode `0xd4200000`).
  * Execution forces a hardware debug exception (`ESR_EL1` 0x3C), an EL0 to EL1 privilege switch, saving all 31 64-bit registers (X0-X30) onto the kernel stack, Execute-Out-Of-Line (XOL) single-stepping, and a return exception to EL0.
  * Cost: 3.5 to 8.0 microseconds per invocation. High-throughput functions (>10,000 calls/sec) suffer latency spikes from 2ms to 500ms and 100% CPU saturation solely handling `el0_sync` traps.
  * Instrumented returns (uretprobes) double this penalty by hijacking the Link Register (`LR` / `X30`).
* **Defensive Implementation**:
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1642-L1711) & [progs/tracer_l7_uprobe.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l7_uprobe.bpf.c#L67-L86): Implemented a per-CPU sliding-window rate limiter (`uprobe_rate_limit_map`).
  * Calculates call frequency within a 1-second window (`1,000,000,000 ns`). If call frequency exceeds 10,000 calls/sec, throttle mode engages and silences event emission to protect application throughput.
  * Stack Depth Resilience: In throttle mode, `trace_uprobe_entry` still tracks `call_depth++` and `trace_uprobe_return` performs `call_depth--`, preserving shadow stack alignment without metric desynchronization.

#### 3. XDP Driver Mode vs Generic SKB Fallback & MTU Limits
* **Failure Mechanism (Cloudflare Post-Mortem)**:
  * Native Driver XDP (`XDP_FLAGS_DRV_MODE`) executes directly in the network driver before `struct sk_buff` (SKB) allocation (>25M pps).
  * On virtualized NICs (VirtIO-Net, AWS ENA), native driver XDP can fail with `-EOPNOTSUPP` or `-EINVAL`. Silent fallback to Generic SKB mode allocates full `sk_buff` structures, causing kernel slab exhaustion (`kmem_cache_alloc`) and 100% `ksoftirqd` CPU saturation under high load.
  * Additionally, Rocky Linux 9.8 (Kernel 5.14) lacks multi-buffer XDP (`XDP_FLAGS_FRAGS`), so packets exceeding a single 4KB page cause driver drops or pointer truncation.
* **Defensive Implementation**:
  * [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L252-L279): During XDP attachment, driver support is checked. If `-EOPNOTSUPP` is returned, the daemon logs an operator advisory explaining the hardware constraint and explicitly switches to `XDP_FLAGS_SKB_MODE`.
  * Safe clean-up ensures detachment handles both native and SKB modes via `bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL)`.
  * Packet boundary guards in [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L470-L515) reject fragmented and oversized payloads before memory access.

#### 4. Kprobe Reentrancy & Recursion Deadlocks
* **Failure Mechanism (Meta & Netflix Post-Mortems)**:
  * Probing kernel networking routines (`kfree_skb`, `ip_rcv`, `tcp_v4_rcv`) that invoke memory allocations or trigger nested network processing causes recursive invocation of the same probe on the same CPU core.
  * Because ARM64 kernel stacks are strictly limited to 16KB (`THREAD_SIZE = 16384`), recursion rapidly triggers a fatal kernel stack overflow panic: `Kernel panic - not syncing: kernel stack overflow`.
  * Probing scheduler functions while holding `rq->lock` when user memory access page-faults triggers AB-BA deadlocks with `mm->mmap_lock`.
* **Defensive Implementation**:
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L761-L775) & [progs/kray_common.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/kray_common.h#L295-L308): Added a per-CPU recursion guard (`kprobe_recursion_guard`).
  * `kprobe_enter_guard()` checks whether the current CPU is already executing the probe. If reentrant (depth > 0), the probe aborts immediately with `0`. When execution completes, `kprobe_exit_guard()` resets the guard counter.

#### 5. Cgroups v2 Memory Controller Accounting & BPF Map OOM Traps
* **Failure Mechanism**:
  * Under Linux 5.14 (Rocky Linux 9.8), all BPF maps created via `sys_bpf(BPF_MAP_CREATE)` carry `__GFP_ACCOUNT` and charge against the memory cgroup (`memory.current`) of the creating process.
  * An eBPF daemon allocating large flow maps, context maps, and ring buffers consumes over 120MB of unevictable kernel slab memory.
  * When deployed inside a container with a 256MB memory limit, unexpected traffic microbursts push `memory.current` past `memory.max`, triggering the cgroup OOM-killer to SIGKILL the tracing daemon.
* **Defensive Implementation**:
  * [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/daemon/daemon_preflight.h#L62-L109): Added pre-flight cgroup inspection in `check_system_prerequisites()`. It inspects `/sys/fs/cgroup/memory.max` and `memory.current`.
  * If available headroom is under 64MB, `s_cgroup_low_headroom` is set, a warning is logged, and [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c#L201-L209) dynamically downscales LRU maps (`ingress_flow_map`, `active_ctx_map`, `egress_flow_map`) from 65,536 to 2,048 entries before calling `bpf_prog_load()`.

#### 6. TCP RST Abrupt Teardown Leaking Unclosed Connection State
* **Failure Mechanism**:
  * Graceful connection termination performs a 4-way handshake (`tcp_close` -> FIN/ACK -> TIME_WAIT).
  * Abrupt resets (client aborts, timeouts, load balancer RST injection) bypass `tcp_close` and execute `tcp_reset()` -> `tcp_done()`, immediately switching socket state to `CLOSED` without FIN generation.
  * Tracers inspecting only FIN flags fail to detect RST packets, leaving orphaned flow records in `ingress_flow_map`. When dynamic ports recycle, new connections inherit stale timestamps, inflating wire-to-code latencies from microseconds to hours.
* **Defensive Implementation**:
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L552-L565) & [progs/tracer_l2_xdp.bpf.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/tracer_l2_xdp.bpf.c#L105-L118): Added `FLAG_TCP_RST 0x04` extraction via `extract_tcp_flags()`.
  * In `xdp_ingress_filter()`, `kprobe__tcp_v4_rcv()`, and `kprobe__tcp_v6_rcv()`, detecting `FLAG_TCP_RST` immediately invokes `ingress_flow_map.delete(&key)`.
  * Emits an explicit teardown event with `FLAG_TCP_RST (0x04)` to flush downstream aggregators.

#### 7. BPF JIT Compiler Vulnerabilities in Kernel 5.14
* **CVE-2026-53036 (ARM64 BPF JIT Signed Range Check Off-by-One)**:
  * In `arch/arm64/net/bpf_jit_comp.c`, `check_imm(19, imm)` shifts by 19 bits. A positive displacement of +262,144 evaluates to 0, flipping a forward jump into a large negative backward jump and inducing soft-lockups.
  * Mitigated by structuring BPF logic into micro-modules under 4,000 instructions each ([progs/](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/progs/)).
* **CVE-2026-23383 (ARM64 BPF JIT Allocator Buffer Alignment Tearing)**:
  * The ARM64 BPF JIT allocator historically requested 4-byte alignment instead of 8-byte alignment, causing 64-bit target pointer addresses in `struct bpf_plt` to straddle cache line boundaries and tear during multi-core updates.
  * Mitigated by loading BPF modules statically at daemon boot and modulating tracing dynamically via `runtime_config_map`.

---

### Command-Line Architecture Grounded in Michael Kerrisk's Standards

The tracer command-line interface ([krayctl](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/krayctl) and [tracer_daemon.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_daemon.c)) is grounded in the authoritative systems programming conventions articulated by **Michael Kerrisk** in *The Linux Programming Interface* (TLPI) and the standards of the Linux man-pages project:

* **Michael Kerrisk's TLPI Principles (Chapter 56/63 & Appendix B)**:
  * **Option Vector Parsing**: Uses `getopt_long(3)` with a leading colon in the optstring (`":p:L:jvh"`) to suppress generic libc error messages, enabling programmatic distinction between missing option-arguments (returns `':'`) and invalid options (returns `'?'`).
  * **Standard Exit Taxonomy**: Employs BSD `<sysexits.h>` exit codes (`EX_USAGE = 64` for syntax errors, `EX_NOPERM = 77` for capability denials, `EX_SOFTWARE = 70` for internal failures, `EX_OK = 0` for success).
  * **Strict Stream Separation**: Output streams are strictly segregated; machine-parseable JSON telemetry and pipeline data flow exclusively through `stdout` (FD 1), while human-readable banners, diagnostic warnings, and error messages write exclusively to unbuffered `stderr` (FD 2 via `setvbuf(stderr, NULL, _IONBF, 0)`).
* **POSIX IEEE Std 1003.1 Guidelines 1~13 Conformance**:
  * Option clustering supported (e.g., `-jv` equals `-j -v`).
  * Both space-separated and glued arguments supported for short options (`-p8080` and `-p 8080`).
  * Both space-separated and equals-separated arguments supported for long options (`--port=8080` and `--port 8080`).
  * Explicit end-of-options delimiter (`--`) supported to protect against argument injection.
  * Full specification and reference documented in [references/cli-argument-standards-and-conventions.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md).


---

# [Book IX] 원천 엔지니어링 프롬프트 및 상세 설계 블루프린트 (Original Prompt Specification)

# eBPF-WireToCode-Tracer: 통합 아키텍처 명세서 및 마스터 프롬프트 (Single Source of Truth)

> [!IMPORTANT]
> **프로젝트의 존재 이유 (Core Raison d'être) 및 문서 활용 안내**
> - **존재 이유 (Why This Project Exists)**: **"오직 eBPF만을 사용하여 데이터가 입출력(Network/Storage I/O)을 통해 시스템에 들어온 순간부터 커널 네트워크 스택, 소켓 버퍼, 시스템콜/메모리 복사(Page Fault/Block I/O), 스레드 락(Futex) 및 CPU 스케줄러 런큐(Runqueue)를 거쳐 실제 연산장치(CPU Execution Core / ALU)에 들어가기 직전(Pre-Compute Gate)과 연산 후 출력으로 빠져나갈 때까지의 모든 계층에 대해 100% 가시성을 확보하고 검증한다."**
> - 본 문서는 이 핵심 철학을 중심으로, 레퍼런스 검증 근거, **Map-Driven 무재컴파일(Zero-Recompile) & BPF CO-RE 호환 커널 런타임**, **입출력~연산장치 진입 직전(Wire-to-PreCompute-to-Wire) 7대 계층 검증 엔진**, **MCP 서버(`--serve mcp`) 및 REST API(`--serve rest`) 서비스 게이트웨이**, **사람을 위한 대화형 인터페이스(웹 대시보드 & 터미널 TUI)**, **AI 에이전트 자율 진단/패치 검증 루프**, 그리고 **12대 자동 검증 기준**을 **단 하나의 파일로 통합한 마스터 명세서(Single Source of Truth)**입니다.
> - **사람(개발자·아키텍트·SRE)**: **Part 1 ~ Part 4**를 순서대로 읽으면 입출력부터 연산장치 진입 직전까지의 전 계층 검증 원리, 웹/TUI/REST/MCP 사용법, 커널 내부 설계 및 검증 방법을 한눈에 이해할 수 있습니다.
> - **AI 코딩 에이전트**: **Part 3(상세 기술 명세)**, **Part 4(검증 기준)**, **Part 5(통합 마스터 프롬프트)**를 그대로 참조하여 추측 없이 100% 동작하는 프로덕션 코드를 구현할 수 있습니다.

---

## 목차 (Table of Contents)

- **[PART 1. 프로젝트 개요 및 실제 사용 워크플로우 (Human & Agent Guide)](#part-1-프로젝트-개요-및-실제-사용-워크플로우-human--agent-guide)**
  - [1.1 프로젝트의 존재 이유: 입출력(I/O)부터 연산장치(CPU Core) 진입 직전까지 전 계층 가시성 확보](#11-프로젝트의-존재-이유-입출력io부터-연산장치cpu-core-진입-직전까지-전-계층-가시성-확보)
  - [1.2 멀티모달 인터페이스 아키텍처 (Web UI / TUI / REST API / MCP Server)](#12-멀티모달-인터페이스-아키텍처-web-ui--tui--rest-api--mcp-server)
  - [1.3 입출력(I/O) ↔ 연산장치 진입 직전(Pre-Compute) 7대 계층 전수 검증 매트릭스](#13-입출력io--연산장치-진입-직전pre-compute-7대-계층-전수-검증-매트릭스)
  - [1.4 유저의 실제 사용 흐름 (3-Step Workflow)](#14-유저의-실제-사용-흐름-3-step-workflow)
  - [1.5 AI 에이전트의 자율 진단 및 패치 검증 루프 (MCP & Closed-Loop Workflow)](#15-ai-에이전트의-자율-진단-및-패치-검증-루프-mcp--closed-loop-workflow)
- **[PART 2. 레퍼런스 교차 검증 및 런타임 아키텍처 고도화 내역 (Engineering Rationale)](#part-2-레퍼런스-교차-검증-및-런타임-아키텍처-고도화-내역-engineering-rationale)**
  - [2.1 핵심 레퍼런스 문헌, 타겟 머신 및 커널 소스 매핑](#21-핵심-레퍼런스-문헌-타겟-머신-및-커널-소스-매핑)
  - [2.2 초기 프롬프트 원문 보존 (Original Baseline Prompt)](#22-초기-프롬프트-원문-보존-original-baseline-prompt)
  - [2.3 기존 프롬프트의 10대 기술적 단절(Gap) 및 차세대 런타임 해법](#23-기존-프롬프트의-10대-기술적-단절gap-및-차세대-런타임-해법)
  - [2.4 차세대 런타임 아키텍처 비교: 문자열 치환 재컴파일 vs Map-Driven + BPF CO-RE](#24-차세대-범용-런타임-아키텍처-비교-universal-architecture--design-matrix)
  - [2.5 엔드투엔드 시스템 & 서비스 런타임 아키텍처 다이어그램](#25-엔드투엔드-범용-시스템--서비스-런타임-아키텍처-다이어그램)
  - [2.6 구현 전 아키텍처 및 커널 시스템 설계 결함 10회 반복 검증·재설계 내역 (10-Iteration Pre-Implementation Architectural Design Audit)](#26-구현-전-아키텍처-및-커널-시스템-설계-결함-10회-반복-검증재설계-내역-10-iteration-pre-implementation-architectural-design-audit)
- **[PART 3. 컴포넌트별 상세 기술 명세서 (Component-Level Technical Blueprint)](#part-3-컴포넌트별-상세-기술-명세서-component-level-technical-blueprint)**
  - [3.1 공유 64바이트 이진 텔레메트리 프로토콜 (`struct kray_event_t`) & 동적 설정 구조체 (`struct kray_runtime_cfg_t`)](#31-공유-64바이트-이진-텔레메트리-프로토콜-struct-kray_event_t--동적-설정-구조체-struct-kray_runtime_cfg_t)
  - [3.2 커널 영역: Map-Driven & CO-RE 호환 7-Layer (Wire-to-PreCompute-to-ALU) 수집기 (`tracer_kernel.c`)](#32-커널-영역-map-driven--co-re-호환-7-layer-wire-to-precompute-to-alu-수집기-tracer_kernelc)
  - [3.3 유저 영역: 통합 런타임 엔진, 7대 계층 분석기, 3단계 심볼리케이터 & AI 진단기 (`tracer_agent.py`)](#33-유저-영역-통합-런타임-엔진-7대-계층-분석기-3단계-심볼리케이터--ai-진단기-tracer_agentpy)
  - [3.4 시각화 파이프라인: 4-Tier Graphviz DOT & 히트맵 생성기](#34-시각화-파이프라인-4-tier-graphviz-dot--히트맵-생성기)
  - [3.5 휴먼 인터페이스 상세 명세 (Interactive Web Dashboard & Terminal TUI)](#35-휴먼-인터페이스-상세-명세-interactive-web-dashboard--terminal-tui)
  - [3.6 서비스 게이트웨이 상세 명세: MCP 서버 (`--serve mcp`) & REST/SSE API (`--serve rest`)](#36-서비스-게이트웨이-상세-명세-mcp-서버---serve-mcp--restsse-api---serve-rest)
  - [3.7 테스트 대상 멀티스레드 서버 및 Stripped 공유 라이브러리 (`mock_server.cpp`, `libcrypto_mock.cpp`)](#37-테스트-대상-멀티스레드-서버-및-stripped-공유-라이브러리-mock_servercpp-libcrypto_mockcpp)
- **[PART 4. 전 기능 동작 보장 및 12대 자동 검증 매트릭스 (Verification & Guarantee Matrix)](#part-4-전-기능-동작-보장-및-12대-자동-검증-매트릭스-verification--guarantee-matrix)**
  - [4.1 12대 필수 자동 검증 항목 (`test_verification_suite.py`)](#41-12대-필수-자동-검증-항목-test_verification_suitepy)
  - [4.2 엔드투엔드 원클릭 실행 시나리오 (`test_harness.sh` & `Dockerfile`)](#42-엔드투엔드-원클릭-실행-시나리오-test_harnesssh--dockerfile)
- **[PART 5. AI 에이전트 주입용 최종 마스터 프롬프트 (Copy-Ready Master Prompt)](#part-5-ai-에이전트-주입용-최종-마스터-프롬프트-copy-ready-master-prompt)**

---

# PART 1. 프로젝트 개요 및 실제 사용 워크플로우 (Human & Agent Guide)

## 1.1 프로젝트의 존재 이유: 입출력(I/O)부터 연산장치(CPU Core) 진입 직전까지 전 계층 가시성 확보

> **"입출력을 제대로 이해하기 위해, 데이터가 네트워크·스토리지 입출력(I/O)으로 들어온 순간부터 실제 연산장치(CPU 코어/ALU)에 들어가기 직전(Pre-Compute Gate)까지 모든 계층의 가시성을 확보하고 검증한다 — 이것이 이 프로젝트의 존재 이유다."**

데이터가 네트워크 카드(NIC)나 스토리지(Disk/Block)에서 들어왔다고 해서 곧바로 CPU 연산장치(ALU/레지스터)에서 계산되는 것이 아닙니다. 실제 연산장치에 도달하기 직전까지 데이터는 수많은 하드웨어·커널·메모리·스케줄러 관문을 통과하며, 현업의 성능 병목은 순수 연산보다 **"연산장치에 들어가기 직전까지의 입출력·메모리·런큐 대기 구간"**에서 발생하는 경우가 훨씬 많습니다.

- **eBPF-WireToCode-Tracer**는 애플리케이션 코드 수정 없이 오직 **eBPF**만으로 **물리 와이어(L2 DMA/SoftIRQ) → 커널 네트워크 스택(L3 IP / L4 TCP) → 소켓 버퍼(L4.5 `sk_rcvbuf`/`sk_sndbuf`) → 시스템콜·커널/유저 메모리 복사·페이지 폴트·블록 스토리지 I/O(L5 VFS/MM/Block) → 연산장치 진입 직전 게이트인 스레드 락(Futex) 경합 및 CPU 스케줄러 런큐 대기(`runqlat`: `sched_wakeup -> sched_switch`)·코어 마이그레이션(L6 Pre-Compute Scheduler Gate) → 실제 CPU 연산장치 On-CPU 실행(L7 Binary / Stripped `.so`)** 및 역방향 출력까지의 **7대 계층 전 구간을 단일 `req_id`로 꿰어 완벽한 가시성과 검증(`PASS` / `WARN` / `BOTTLENECK`)을 제공**합니다.

#### 1. 네트워크·스토리지 입출력(I/O) 전 계층 대칭 검증
- **기존 도구들의 사각지대 (Blind Spot)**: 수신(RX) 패킷, 커널 큐, 디스크 블록 I/O, 송신(TX) 패킷이 서로 다른 도구에 흩어져 있어 인과관계를 연결할 수 없습니다.
- **`eBPF-WireToCode-Tracer`의 전 계층 가시성 해법**: **입력(`L2 RX → L3 → L4 → Socket → Syscall/Memory/Block I/O`)**과 **출력(`Syscall → Socket → L4 → L3 → L2 TX`)**의 모든 계층을 단일 `req_id`로 묶어 바이트·헤더·큐 대기 시간을 1:1 대칭 검증합니다.

#### 2. 연산장치(CPU Core) 진입 직전 게이트 가시성 (`Pre-Compute Gate`)
- **기존 도구들의 사각지대 (Blind Spot)**: 데이터가 소켓에서 읽혔는데도 왜 함수가 늦게 실행되었는지(락 경합인지, CPU 런큐 대기인지, 코어 이동으로 인한 캐시 미스인지) 알 수 없습니다.
- **`eBPF-WireToCode-Tracer`의 전 계층 가시성 해법**: **연산장치 진입 직전 3대 관문 계측** — ① 스레드 락/Futex 대기(`lock_wait_ms`), ② CPU 런큐 스케줄링 대기(`runq_latency_ms`: `sched_waking`/`sched_wakeup` → `sched_switch`), ③ 물리 CPU 코어 배치 및 코어 마이그레이션(`CPU #0 -> CPU #2`, L1/L2 캐시 로컬리티)을 추적합니다.

#### 3. 순수 연산장치(On-CPU) vs 입출력/대기(Off-CPU) 완전 분리
- **기존 도구들의 사각지대 (Blind Spot)**: 함수 소요 시간(`20ms`)이 실제 CPU ALU 연산 때문인지, 중간에 스토리지 I/O나 스케줄러 선점 때문인지 구분할 수 없습니다.
- **`eBPF-WireToCode-Tracer`의 전 계층 가시성 해법**: 각 유저 함수 및 Stripped `.so` 오프셋(`libcrypto_mock.so+0x1140`)마다 **`pure_on_cpu_compute_ms`(순수 연산장치 실행 시간)**와 **`off_cpu_io_wait_ms`(함수 실행 중 발생한 입출력·런큐·락 대기 시간)**를 분리 산출하고 DWARF를 통해 동적으로 해석된 C++ 소스(`file:line`)/어셈블리(`objdump`)와 직결합니다.

#### 4. 무중단·무재컴파일 동적 타겟 검증 (`0ms` Hot-Reload)
- **기존 도구들의 사각지대 (Blind Spot)**: 타겟이 바뀔 때마다 C 코드를 재컴파일하면 수 초가 걸려 실시간 에이전트 연동이 불가능합니다.
- **`eBPF-WireToCode-Tracer`의 전 계층 가시성 해법**: 커널 `runtime_config_map`을 통해 **재컴파일 없이(`0ms`)** 타겟 `PID`/`Port`/계층 필터를 즉시 전환하며, 웹 UI·TUI·MCP·REST API로 실시간 제공합니다.

---

## 1.2 멀티모달 인터페이스 아키텍처 (Web UI / TUI / REST API / MCP Server)

단일 코어 런타임 엔진(`TracerRuntimeEngine`) 위에서 **사람을 위한 2가지 대화형 인터페이스**와 **AI 에이전트 및 외부 시스템을 위한 2가지 서비스 프로토콜**을 모두 제공합니다.

### ① [Human] 인터랙티브 웹 대시보드 (`--ui web` 및 독립 실행형 `trace_dashboard.html`)
브라우저(`http://localhost:8090` 또는 생성된 `trace_dashboard.html` 파일 열기)에서 모든 기능을 마우스 클릭으로 조작하는 비주얼 통합 환경입니다.
- **인터랙티브 4-Tier SVG 토폴로지 캔버스 & 7대 계층 필터 바 (`All | L2 | L3 | L4 | Socket | Syscall/IO | Sched/Pre-Compute | L7`)**:
  - 상단 계층 필터 버튼(`L2 NIC/XDP`, `L3 IP`, `L4 TCP`, `L4.5 Socket Queue`, `L5 Syscall/Mem/Block I/O`, `L6 Pre-Compute Sched Gate`, `L7 App ALU`)을 클릭해 원하는 계층만 하이라이트하거나 필터링할 수 있습니다.
  - 마우스 휠 확대/축소/드래그를 지원하며, **유저 함수 노드(`execute_storage_query`, `libcrypto_mock.so+0x1140`)를 클릭하면 우측 인스펙터에 C++ 소스 코드(`mock_server.cpp:94`) 또는 Stripped 어셈블리(`objdump`)가 나타나고, 커널/네트워크/스케줄러 노드(`XDP_INGRESS`, `ip_rcv`, `tcp_v4_rcv`, `tcp_recvmsg`, `skb_copy_datagram_iovec`, `sched_switch`, `ip_output`, `net_dev_xmit`)를 클릭하면 해당 계층의 패킷 헤더 디코딩 결과(MAC/Ifindex, IPv4 Tuple/TTL/Len, TCP Flags `PSH|ACK`/Retransmit, Socket Queue Dwell Time, Runqueue Latency `runqlat`, CPU Migration `CPU#0->#2`)와 타겟 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 원본 소스 위치 및 eBPF 훅 코드가 즉시 표시**됩니다.
- **원클릭 액션 & 적응형 Zoom-In 컨트롤 바**:
  - 상단 버튼 클릭만으로 `[Baseline 트레이스 실행]`, `[최적화(Fast) 모드 실행]`, `[링버퍼 오버플로우 경고 테스트]`를 즉시 전환할 수 있고, 클릭한 노드에서 바로 `[이 함수/오프셋만 Zoom-In 프로빙]`을 실행할 수 있습니다.
- **3대 하단 분석 탭 (`6-Layer Waterfall` / `7-Layer Pre-Compute & I/O Matrix` / `Before vs After Compare`)**:
  - **Tab 1 (`Waterfall`)**: 6개 매크로 계층과 스레드 핸드오프(`TID 10421 -> TID 10425`) 구간을 시간축 간트(Gantt) 바로 시각화합니다.
  - **Tab 2 (`7-Layer Pre-Compute & I/O Matrix`)**: 패킷이 수신(Ingress: `L2 -> L3 -> L4 -> Socket -> Syscall/MM/Block -> L6 Pre-Compute Sched Gate`)되어 연산장치(`L7 ALU`)를 거쳐 송신(Egress: `Syscall -> Socket -> L4 -> L3 -> L2`)될 때까지 **7대 계층별 소요 시간($\text{ms}$), RTT 비중(`%`), 패킷 길이/플래그, 소켓 버퍼 체류 시간, 커널↔유저 메모리 복사/블록 I/O, CPU 런큐 대기(`runqlat`)·코어 마이그레이션, Qdisc 큐 지연**을 대칭 매트릭스로 보여줍니다.
  - **Tab 3 (`Before vs After Compare`)**: 패치 전(`Baseline`)과 패치 후(`Patched`)의 계층별·함수별 응답 시간 단축량($\Delta\text{ms}$)과 개선율(`%`)을 나란히 비교 차트로 보여줍니다.

### ② [Human] 대화형 터미널 TUI 콘솔 (`--ui tui`)
SSH로 원격 리눅스 서버(`rocky-dev` 또는 AWS EC2 `t4g.large`)에 접속해 브라우저를 열 수 없는 환경에서, 키보드 숫자키(`[1]~[7]`)만으로 모든 기능을 대화형으로 실행하는 콘솔 메뉴 대시보드입니다.
```text
╔══════════════════════════════════════════════════════════════════════════════╗
║        eBPF-WireToCode-Tracer : Interactive Terminal Control Console         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Target Host   : Rocky Linux 9.8 aarch64 (5.14.0-687.10.1.el9_8.0.1.aarch64) ║
║  Target Binary : ./mock_server (PID: 10420) | Port: 8080 | Mode: LIVE/SIM    ║
║  Runtime State : Map-Driven Hot-Reload Ready (0ms Recompile, CO-RE BTF)      ║
║  Last Trace    : ReqID 0x8f3a21000001 | RTT: 24.85 ms | Bottleneck: 72.0%    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  [1] Run Full Wire-to-PreCompute-to-Code Trace (Waterfall + SVG + AI JSON)   ║
║  [2] Inspect Bottleneck C++ Source Code & Stripped ASM (Interactive Viewer)  ║
║  [3] Inspect 7 Layers (L2 NIC->L3 IP->L4 TCP->Socket->Syscall->Sched->L7)    ║
║  [4] Adaptive Zoom-In Probe (--focus-symbol / --uprobe-offset)               ║
║  [5] Run Before vs After Patch Benchmark Comparison (--compare)              ║
║  [6] Simulate Ring Buffer Overflow Alert Banner (drop_count > 0)             ║
║  [7] Export & Launch Interactive Web Dashboard (trace_dashboard.html)        ║
║  [q] Quit                                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
Select action [1-7, q]:
```

### ③ [AI Agent] MCP (Model Context Protocol) 서버 (`--serve mcp`)
Claude Desktop, Cursor, Antigravity 등 AI 에이전트가 표준 JSON-RPC 2.0(`stdio` 또는 HTTP `/mcp`)을 통해 직접 호출할 수 있는 **6대 MCP Tools**를 내장합니다:
1. `ebpf_configure_target`: **재컴파일 없이(`0ms`)** 커널 `runtime_config_map`의 타겟 `pid`, `port`, `iface`를 즉시 변경
2. `ebpf_capture_trace`: 전 계층 트레이스 캡처 및 병목 진단 번들(`ai_diagnosis.json` 스키마) 반환
3. `ebpf_inspect_network_layers`: **7대 계층별(`all`, `l2`, `l3`, `l4`, `socket`, `syscall`, `sched`, `l7`) 지연 시간, 패킷 헤더 메타데이터(IPv4, TCP Flags, 패킷 크기), 소켓 버퍼 대기 시간, 커널↔유저 메모리 복사/페이지 폴트/블록 I/O, 연산장치 진입 직전 CPU 런큐 대기(`runqlat`)/락 대기/코어 마이그레이션, 재전송/드롭 상태 상세 조회**
4. `ebpf_inspect_code_or_asm`: 특정 함수 심볼 또는 Stripped 오프셋(`module+0xoffset`)의 실제 C++ 소스 코드 / 어셈블리 블록 즉시 반환
5. `ebpf_compare_patches`: 패치 전/후 두 트레이스 간 RTT 및 계층/함수별 성능 개선율(`%`) 정량 비교
6. `ebpf_render_topology`: 4-Tier Graphviz `.dot` / `.svg` 시각화 다이어그램 렌더링 및 반환

### ④ [External Systems] REST & SSE API 서버 (`--serve rest`)
외부 관제 시스템, CI/CD 파이프라인, 웹 프론트엔드가 HTTP로 제어할 수 있는 `/api/v1/*` 엔드포인트(`/api/v1/network-layers` 포함)를 제공합니다.

---

## 1.3 입출력(I/O) ↔ 연산장치 진입 직전(Pre-Compute) 7대 계층 전수 검증 매트릭스

데이터가 시스템에 들어와서 **실제 연산장치(CPU Core / ALU)에 들어가기 직전(`L6 Pre-Compute Gate`)**을 거쳐 다시 외부로 나갈 때까지, **7개의 하드웨어·커널·메모리·스케줄러·연산 계층**을 타겟 머신(**Rocky Linux 9.8 `5.14.0-687.10.1.el9_8.0.1.aarch64`**)의 실제 커널 심볼 및 트레이스포인트에 1:1로 매핑하여 대칭 검증합니다.

#### 1) `l2` (`OSI_L2_DATALINK = 2`) — L2 하드웨어 NIC DMA / SoftIRQ & Qdisc
- **입력 경로 (Ingress -> Pre-Compute) eBPF 훅**: `xdp_ingress_filter` (`BPF_PROG_TYPE_XDP`) + `tracepoint:irq:softirq_entry` (`vec=NET_RX_SOFTIRQ`) + `tracepoint:net:netif_receive_skb` ([`net.h:150`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L150))
- **출력 경로 (Compute -> Egress) eBPF 훅**: `tracepoint:net:net_dev_queue` ([`net.h:143`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L143)) → `tracepoint:net:net_dev_xmit` ([`net.h:71`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L71))
- **가시성 확보 및 판정 기준 (`Verdict`)**: 수신 NIC 인터페이스(`iface`), 처리 CPU 코어(`rx_cpu_id`), 프레임 길이(`rx_pkt_bytes`), `XDP_PASS` 확인 및 송신 프레임 길이(`tx_pkt_bytes`), **Qdisc 큐 대기 시간(`qdisc_delay_ms`)**, 드라이버 송신 결과(`rc == 0`) 검증.

#### 2) `l3` (`OSI_L3_IP = 3`) — L3 네트워크 / IPv4 라우팅 & Netfilter
- **입력 경로 eBPF 훅**: `kprobe:ip_rcv` (`PARM1 = struct sk_buff *skb`, [`ip_input.c:552`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552)) → `kprobe:ip_rcv_finish`
- **출력 경로 eBPF 훅**: `kprobe:ip_output` (`PARM1 = net`, `PARM2 = sk`, **`PARM3 = skb`**, [`ip_output.c:426`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_output.c#L426))
- **가시성 확보 및 판정 기준 (`Verdict`)**: 수신 IPv4 헤더(`src_ip -> dst_ip`, `ihl=20B`, `ttl`), L2→L3 라우팅/Netfilter 통과 지연($\Delta t_{\text{L3\_in}}$) 및 송신 IPv4 역방향 튜플 일치 여부, L4→L3 출력 라우팅 지연($\Delta t_{\text{L3\_out}}$) 검증.

#### 3) `l4` (`OSI_L4_TCP = 4`) — L4 전송 / TCP·UDP 프로토콜 상태
- **입력 경로 eBPF 훅**: `kprobe:tcp_v4_rcv` (`PARM1 = struct sk_buff *skb`, [`tcp_ipv4.c:1945`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1945))
- **출력 경로 eBPF 훅**: `kprobe:__tcp_transmit_skb` (`PARM1 = sk`, `PARM2 = skb`, [`tcp_output.c:1238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238)) + `tracepoint:tcp:tcp_retransmit_skb` + `tracepoint:skb:kfree_skb` ([`skb.h:24`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24))
- **가시성 확보 및 판정 기준 (`Verdict`)**: 포트(`src_port -> dst_port`), TCP 플래그(`[PSH,ACK]`), 소켓 상태(`TCP_ESTABLISHED`), L3→L4 지연($\Delta t_{\text{L4\_in}}$) 및 응답 세그먼트 TCP 플래그, **재전송(`retransmits == 0`) 및 커널 SKB 드롭(`skb_drops == 0`, `enum skb_drop_reason`) 무결성 검증**.

#### 4) `socket` (`OSI_L4_SOCKET = 5`) — L4.5 커널 소켓 버퍼 큐 (`sk_rcvbuf` / `sk_sndbuf`)
- **입력 경로 eBPF 훅**: `kprobe:tcp_recvmsg` ([`tcp.c:2742`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2742), `PARM1 = struct sock *sk`) & **`kretprobe:tcp_recvmsg`** (`PT_REGS_RC(ctx) = int copied`, 패킷 도착 전 `sk_wait_data` [`tcp.c:2638`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2638)에서 블로킹 대기하던 서버 스레드의 지연 바인딩 및 실제 수신 바이트 수 `copied` 획득 보장)
- **출력 경로 eBPF 훅**: `kprobe:tcp_sendmsg` (`PARM1 = struct sock *sk`, `PARM3 = size_t size`, [`tcp.c:1510`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L1510)) & `kretprobe:tcp_sendmsg`
- **가시성 확보 및 판정 기준 (`Verdict`)**: **소켓 수신 버퍼(`sk_rcvbuf`) 체류 시간($\Delta t_{\text{sock\_in}} = t_{\text{recvmsg}} - t_{\text{tcp\_rcv}}$)**, SoftIRQ 4-Tuple ↔ 유저 `PID/TID` 바인딩(비블로킹/선도착 시 `kprobe` 진입 즉시, 블로킹 `sk_wait_data` 대기 시 `kretprobe` 복귀 즉시 바인딩) 및 **소켓 송신 버퍼(`sk_sndbuf`) → TCP/IP 스택 전달 지연($\Delta t_{\text{sock\_out}}$)** 검증.

#### 5) `syscall` (`OSI_L5_SYSCALL_MEM = 6`) — L5 시스템콜 / 커널↔유저 메모리 복사 / 페이지 폴트 / 스토리지 Block I/O
- **입력 경로 eBPF 훅**: `tracepoint:syscalls:sys_enter_read` + `tracepoint:skb:skb_copy_datagram_iovec` ([`skb.h:76`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L76), [`datagram.c:534`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8/net/core/datagram.c#L534)) + `kprobe:skb_copy_datagram_iter` & **`kretprobe:skb_copy_datagram_iter`** ([`datagram.c:531-537`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/datagram.c#L531-L537), `simple_copy_to_iter` 완료 후 측정) + `kprobe:handle_mm_fault` ([`memory.c:5313`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/mm/memory.c#L5313)) + `tracepoint:kmem:mm_page_alloc` + `tracepoint:block:block_rq_insert` ([`block.h:238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L238)) + `tracepoint:block:block_rq_issue` ([`block.h:252`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L252))
- **출력 경로 eBPF 훅**: `tracepoint:block:block_rq_complete` ([`block.h:167`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L167)) + `tracepoint:syscalls:sys_enter_write` / `sys_enter_sendto`
- **가시성 확보 및 판정 기준 (`Verdict`)**: 커널 소켓 버퍼에서 유저 가상 메모리(`iov_iter`)로의 실제 복사 소요 시간(`kretprobe:skb_copy_datagram_iter` - `copy_enter_ts`) 및 바이트(`copy_to_user_bytes`), 복사 도중 발생한 `aarch64` 호환 유저 메모리 **페이지 폴트(`handle_mm_fault` / `mm_page_alloc`)**, 스토리지/디스크 **블록 I/O 대기 시간(`storage_block_io_ms`)** 및 시스템콜 경계 확인.

#### 6) `sched` (`OSI_L6_PRE_COMPUTE = 8`) — L6 연산장치 진입 직전 게이트 (`Pre-Compute Gate`: Futex Lock + CPU Runqueue + Core Dispatch)
- **입력 경로 eBPF 훅**: `tracepoint:syscalls:sys_enter_futex` → `tracepoint:sched:sched_waking` ([`sched.h:170`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L170)) / `sched_wakeup` ([`sched.h:178`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L178)) → **`tracepoint:sched:sched_switch` ([`sched.h:222`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L222), `args->next_pid == tid` On-CPU Dispatch 직전!)**
- **출력 경로 eBPF 훅**: `tracepoint:sched:sched_switch` (`args->prev_pid == tid`, Off-CPU 전환 시점)
- **가시성 확보 및 판정 기준 (`Verdict`)**: ① **락/뮤텍스 대기(`lock_wait_ms`)**, ② **연산 진입 전 CPU 런큐 대기(`call_depth == 0`일 때 `runq_latency_ms = t_sched_switch - t_sched_wakeup`) 및 유저 함수 내부(`call_depth > 0`) 전체 Off-CPU Sleep+Runqueue 대기(`total_off_cpu_ns = t_sched_switch - off_cpu_enter_ts`)**, ③ **CPU 코어 마이그레이션 & 캐시 로컬리티(`prev_cpu_id -> target_cpu_id`, `CPU #0 -> CPU #2`)** 검증.

#### 7) `l7` (`OSI_L7_APP = 7`) — L7 연산장치(CPU Core / ALU) On-CPU 실행 & 모듈/Stripped `.so` 코드
- **입력/출력 경로 eBPF 훅**: `uprobe` (함수/오프셋 연산 시작) ↔ `uretprobe` (함수/오프셋 연산 종료, `fn_entry_ip[depth]` 복원 및 언더플로우 가드 적용)
- **가시성 확보 및 판정 기준 (`Verdict`)**: 전체 함수 소요 시간 중 **순수 CPU 연산장치 실행 시간(`pure_on_cpu_compute_ms`)**과 **연산 전/중 I/O·런큐·락 대기 시간(`off_cpu_io_wait_ms`)**을 분리하고, DWARF C++ 소스 코드(`file:line`) 및 Stripped 어셈블리(`objdump`) 명령어와 직결.

#### 터미널 CLI에서 입출력(I/O) ~ 연산장치 진입 직전(Pre-Compute) 7대 계층 전수 검증 예시 (`--net-layer {all,l2,l3,l4,socket,syscall,sched,l7}`)
```text
$ python3 tracer_agent.py --binary ./mock_server --port 8080 --net-layer all
┌───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│              eBPF Wire-to-PreCompute-to-ALU 7-Layer Visibility & Verification Matrix (Input <-> Pre-Compute <-> Output)       │
├──────────┬──────────────────┬──────────────────────────┬────────────┬──────────┬─────────┬────────────────────────────────────┤
│ Layer    │ Stage / Direction│ Kernel / User eBPF Hook  │ Latency    │ % of RTT │ Verdict │ Pre-Compute & I/O Telemetry Proof  │
├──────────┼──────────────────┼──────────────────────────┼────────────┼──────────┼─────────┼────────────────────────────────────┤
│ L2 (NIC) │ INPUT  (DMA/RX)  │ xdp_ingress_filter       │   0.042 ms │    0.17% │ [PASS]  │ iface=lo cpu=#0 rx=184B XDP_PASS   │
│ L3 (IP)  │ INPUT  (ROUTE)   │ kprobe:ip_rcv            │   0.038 ms │    0.15% │ [PASS]  │ 127.0.0.1->127.0.0.1 ihl=20B ttl=64│
│ L4 (TCP) │ INPUT  (PROTO)   │ kprobe:tcp_v4_rcv        │   0.065 ms │    0.26% │ [PASS]  │ 54322->8080 flags=[PSH,ACK] drop=0 │
│ SOCKET   │ INPUT  (RCVBUF)  │ kprobe/kret:tcp_recvmsg  │   0.195 ms │    0.78% │ [PASS]  │ sk_rcvbuf dwell=0.195ms PID=10420  │
│ SYSCALL  │ INPUT  (MEM/VFS) │ sys_enter_read+skb_copy  │   0.025 ms │    0.10% │ [PASS]  │ copy_to_user=184B mm_faults=0      │
│ SCHED/L6 │ PRE-COMPUTE GATE │ futex+wakeup+sched_switch│   0.180 ms │    0.72% │ [PASS]  │ runq=0.065ms lock=0.115ms CPU#0->#2│
│ L7 (ALU) │ ON-CPU + STORAGE │ uprobe/uretprobe (4 fns) │  24.075 ms │   96.88% │ [BOTTL] │ On-CPU=19.8ms | BlockIOWait=4.27ms │
│ SYSCALL  │ OUTPUT (MEM/VFS) │ tp:sys_enter_write       │   0.022 ms │    0.09% │ [PASS]  │ copy_from_user=256B TID=10425      │
│ SOCKET   │ OUTPUT (SNDBUF)  │ kprobe:tcp_sendmsg       │   0.066 ms │    0.27% │ [PASS]  │ sk_sndbuf->TCP tx=256B req_id match│
│ L4/L3    │ OUTPUT (TCP/IP)  │ __tcp_transmit+ip_output │   0.072 ms │    0.29% │ [PASS]  │ 8080->54322 flags=[PSH,ACK] retr=0 │
│ L2 (NIC) │ OUTPUT (QDISC/TX)│ tp:net_dev_xmit          │   0.070 ms │    0.28% │ [PASS]  │ iface=lo qdisc_delay=0.018ms rc=0  │
├──────────┴──────────────────┴──────────────────────────┴────────────┴──────────┴─────────┴────────────────────────────────────┤
│ VERIFICATION SUMMARY: Wire-to-PreCompute Gate (6/6 PASS, runqlat=0.065ms, CPU#0->#2) -> L7 Compute Unit (BOTTLENECK: 72.0%)   │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1.3.1 타겟 머신(`Rocky Linux 9.8`) 내 다중 프로토콜(`--proto`) 및 전 포트 대역(`0 ~ 65535`, `--discover-ports`) 탐색·검증 매트릭스

타겟 머신인 **Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`)** 위에서는 단일 TCP 포트(`8080`)만 동작하는 것이 아니라, **다양한 프로토콜(`TCP`, `UDP`, `IPv4`, `IPv6`, `ICMP`, `ARP`, `UNIX Domain Socket`, `TLS`)**과 **`0 ~ 65535`번 전 대역의 다양한 포트들(Well-Known `1..1023`, Registered `1024..49151`, Ephemeral `32768..65535`)**이 동시에 통신합니다. 본 시스템은 이를 모두 찾아내고(`--discover-ports`) 프로토콜별·포트별로 추적합니다.

#### 1) `tcp` (IPv4 & IPv6 연결 지향)
- **해당 포트 대역 (`0 ~ 65535`)**: Well-Known (`1..1023`: `:22` sshd, `:80`/`:443` nginx, `:111` rpcbind), Registered (`1024..49151`: `:3000` Next.js, `:5432` PostgreSQL, `:6379` Redis, `:8080` Spring/C++), Ephemeral (`32768..65535`: 아웃바운드 클라이언트 포트, [`af_inet.c:1865`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/af_inet.c#L1865))
- **검증된 커널 eBPF 훅**: `kprobe:tcp_v4_rcv` ([`tcp_ipv4.c:1945`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1945)), `kprobe:tcp_v6_rcv` ([`tcp_ipv6.c:1582`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/tcp_ipv6.c#L1582)), `kprobe:tcp_recvmsg` & `kretprobe:tcp_recvmsg` ([`tcp.c:2742`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2742)) ↔ `kprobe:tcp_sendmsg` & `kretprobe:tcp_sendmsg` ([`tcp.c:1510`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L1510)), `kprobe:__tcp_transmit_skb` ([`tcp_output.c:1238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238))
- **핵심 검증 항목**: 3-Way Handshake, `sk_rcvbuf`/`sk_sndbuf` 체류 지연, 양방향 재전송(`tcp_retransmit_skb`: Ingress `dport == target_port` 및 Egress `sport == target_port` 모두 감지), 멀티 포트 서비스 체인(`:80 -> :3000 -> :8080 -> :5432`) 및 Ephemeral 포트 고갈 검증.

#### 2) `udp` (IPv4 & IPv6 비연결 데이터그램)
- **해당 포트 대역**: Well-Known (`1..1023`: `:53` DNS, `:111` rpcbind, `:123`/`:323` chronyd NTP, `:443` HTTP/3 QUIC), Dynamic/Ephemeral (`1024..65535`: `:60698` 등 동적 UDP 소켓)
- **검증된 커널 eBPF 훅**: `kprobe:udp_rcv` ([`udp.c:2672`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L2672)), `kprobe:udp_recvmsg` & **`kretprobe:udp_recvmsg`** ([`udp.c:1868-1945`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1868-L1945)) ↔ `kprobe:udp_sendmsg` ([`udp.c:1069`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1069)), `tracepoint:skb:kfree_skb` ([`skb.h:24`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24))
- **핵심 검증 항목**: 비연결(unconnected) UDP 서버 소켓은 `skc_daddr == 0`, `skc_dport == 0`이므로 **`kretprobe:udp_recvmsg`(`udp.c:1938`에서 `DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name)`가 채워진 직후) 및 `kprobe:udp_sendmsg`의 `msg->msg_name`에서 피어 주소/포트 추출(또는 `{ .daddr = 0, .dport = skc_num, .proto = IPPROTO_UDP }` 포트 단위 폴백 매칭)**, 선형 UDP SKB 복사(`copy_linear_skb`, [`udp.c:1911`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1911)) 및 DNS(`:53`)/NTP(`:323`) 지연 검증.

#### 3) `ipv4` / `ipv6` (L3 듀얼 스택)
- **해당 주소/포트 대역**: IPv4 (`0.0.0.0:0..65535`), IPv6 (`[::]:0..65535`, IPv4-mapped `[::ffff:127.0.0.1]`)
- **검증된 커널 eBPF 훅**: IPv4 `kprobe:ip_rcv` ([`ip_input.c:552`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552)) ↔ `kprobe:ip_output` ([`ip_output.c:426`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_output.c#L426)), IPv6 `kprobe:ipv6_rcv` ([`ip6_input.c:302`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L302)) ↔ `kprobe:ip6_output` ([`ip6_output.c:220`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_output.c#L220))
- **핵심 검증 항목**: ① `kprobe:ipv6_rcv` 진입 시점에는 `ip6_rcv_core()`([`ip6_input.c:260`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L260)) 실행 전이므로 `trans_off = net_off + sizeof(struct ipv6hdr)`(`+40`)로 L4 헤더 오프셋 산출, ② 순수 IPv6 소켓(`skc_family == AF_INET6 && skc_daddr == 0`)에서 `sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0..3]` 및 `skc_v6_rcv_saddr.in6_u.u6_addr32[0..3]`([`sock.h:192-193`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/sock.h#L192-L193)) 32비트 XOR 폴딩, ③ 듀얼스택 IPv4-mapped IPv6 소켓(`skc_family == AF_INET6 && skc_daddr != 0`, `::ffff:a.b.c.d`)에서 `key.family = AF_INET (2)` 정규화 매칭 검증.

#### 4) `icmp` / `arp` (L2/L3 제어 프로토콜)
- **해당 포트 인코딩**: 포트 없음 (`Port 0` 또는 ICMP `(type<<8)|code` & `un.echo.id` [`icmp.h:89-95`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/linux/icmp.h#L89-L95) 인코딩, ARP는 `struct arphdr` [`if_arp.h:144-161`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/linux/if_arp.h#L144-L161) 뒤 가변 페이로드 오프셋 `(u8 *)(arp + 1) + 6`에서 `ar_sip(4B)`, `(u8 *)(arp + 1) + 16`에서 `ar_tip(4B)` 추출 — `ar_sip`/`ar_tip`는 커널 헤더 내 `#if 0`으로 비활성화되어 있으므로 구조체 멤버 직접 참조 금지)
- **검증된 커널 eBPF 훅**: `kprobe:icmp_rcv` ([`icmp.c:1200`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/icmp.c#L1200)), `kprobe:arp_rcv` ([`arp.c:943`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/arp.c#L943))
- **핵심 검증 항목**: 유저 소켓을 거치지 않는 순수 커널 L2/L3 네트워크 왕복 베이스라인 지연 및 ARP 캐시 미스 지연 검증.

#### 5) `unix` (`AF_UNIX` 로컬 IPC)
- **해당 소켓 식별자**: Inode / 소켓 포인터 기반 로컬 IPC (`/run/systemd/*`, `/run/dbus/*`, `podman.sock`, `/tmp/.s.PGSQL.5432`)
- **검증된 커널 eBPF 훅**: `kprobe:unix_stream_recvmsg` (`PARM1 = struct socket *sock`, `sk = sock->sk`, [`af_unix.c:2733`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2733)) ↔ `kprobe:unix_stream_sendmsg` (`PARM1 = struct socket *sock`, [`af_unix.c:2053`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2053))
- **핵심 검증 항목**: TCP/IP 스택(L2~L4)을 우회하는 로컬 프로세스 간 메모리 직결 IPC 지연(`sock->sk` 및 `unix_sk(sk)->peer` 매핑) 및 연산장치 진입 직전(`L6`) 스케줄링 검증.

#### 6) `tls` (L7 OpenSSL 암호화 경계)
- **해당 포트 대역**: `:443`(HTTPS), `:8443`, `:5432`(DB TLS) 등 `libssl.so` 사용 전 포트
- **검증된 유저 eBPF 훅**: `uprobe:libssl.so:SSL_read` / `uretprobe:SSL_read`, `uprobe:libssl.so:SSL_write` / `uretprobe:SSL_write`
- **핵심 검증 항목**: 암호화 트래픽의 TLS 복호화/암호화 CPU 연산 시간과 평문 페이로드 바이트 수 검증.

---

## 1.4 유저의 실제 사용 흐름 (3-Step Workflow)

### Step 1. 원하는 인터페이스 모드로 실행
```bash
# 방법 A: 인터랙티브 웹 대시보드 & REST API 서버 실행 (http://localhost:8090)
python3 tracer_agent.py --ui web --ui-port 8090 --binary ./mock_server --port 8080

# 방법 B: SSH 원격 서버용 대화형 터미널 TUI 콘솔 실행
python3 tracer_agent.py --ui tui --binary ./mock_server --port 8080

# 방법 C: 입출력~연산장치 진입 직전 7대 계층(all, l2, l3, l4, socket, syscall, sched, l7) 정밀 분석 출력
python3 tracer_agent.py --binary ./mock_server --port 8080 --net-layer all

# 방법 D: AI 코딩 에이전트 연동용 MCP 서버 실행 (stdio JSON-RPC 2.0)
python3 tracer_agent.py --serve mcp --binary ./mock_server --port 8080

# 방법 E: 원클릭 빌드 + 전 기능 데모 + 12대 자동 검증 테스트 실행
./test_harness.sh
```

### Step 2. 트래픽 발생 (웹 UI 버튼 클릭, MCP 호출, 또는 `curl`)
웹 대시보드의 **`[Run Trace]`** 버튼을 클릭하거나, 터미널에서 `curl http://localhost:8080/api/order`를 호출합니다.

### Step 3. 네트워크 계층별 진단 및 원인 코드 핀포인트 확인
1. **네트워크 계층별 진단 (`Network Stack Layers` 탭 또는 `--net-layer all`)**: L2(XDP/Qdisc), L3(IP 라우팅), L4(TCP 상태/재전송), Socket Queue(`sk_rcvbuf` 대기 시간)가 각각 `0.2ms` 미만으로 정상임을 먼저 확인하여 네트워크/커널 혐의를 1초 만에 배제합니다.
2. **터미널 워터폴 테이블**에서 전체 RTT(`24.85ms`) 중 L7 유저 구간의 `execute_storage_query()`가 `72.0%`(`17.90ms`), Stripped 라이브러리인 `libcrypto_mock.so+0x1140`이 `19.5%`(`4.85ms`)를 차지함을 즉시 확인합니다.
3. **웹 대시보드(`trace_dashboard.html`)**에서 빨간색 병목 노드를 클릭하여 우측 패널에 자동 추출된 `mock_server.cpp`의 실제 병목 루프 코드와 `libcrypto_mock.so`의 어셈블리 명령어를 바로 확인합니다 (또는 네트워크 노드를 클릭해 L2/L3/L4 패킷 헤더 정보를 확인합니다).
4. 코드 최적화 후 **Before vs After 비교 뷰**를 열어 응답 시간이 `24.85ms -> 7.95ms`(`68.0%` 단축)로 개선되었음을 시각적으로 검증합니다.

---

## 1.5 AI 에이전트의 자율 진단 및 패치 검증 루프 (MCP & Closed-Loop Workflow)

AI 코딩/SRE 에이전트는 MCP 도구 호출(또는 CLI JSON 출력)만으로 사람의 개입 없이 다음 4단계 자율 루프를 수행합니다:
1. **1차 스캔 & 7대 계층 분리 (`ebpf_capture_trace` & `ebpf_inspect_network_layers`)**:
   - 전체 트레이스를 실행하고 **L2(NIC/Qdisc) → L3(IP) → L4(TCP 재전송/드롭) → L4.5(소켓 수신 버퍼 체류 시간) → L5(Syscall/커널↔유저 메모리 복사/페이지 폴트/블록 스토리지 I/O) → L6(Pre-Compute 스케줄러 게이트: Futex 락 대기 + CPU 런큐 대기 `runqlat` + 코어 마이그레이션) → L7(유저 애플리케이션 ALU)** 중 어느 계층에서 지연이 발생했는지 정확히 분리합니다.
2. **코드/어셈블리 자동 확보 (`ebpf_inspect_code_or_asm` / `ai_diagnosis.json`)**:
   - 심볼이 있는 병목 함수는 DWARF(`addr2line`/심볼 매핑)를 통해 **정확한 소스 파일 경로와 라인 번호(`mock_server.cpp:94`) 및 전후 `±10줄`의 C++ 소스 스니펫**을 즉시 받습니다.
   - 심볼이 제거된 Stripped 오프셋(`libcrypto_mock.so+0x1140`)은 자동으로 추출된 **15줄의 `objdump -d` ELF 어셈블리 명령어 블록**을 즉시 받습니다.
3. **적응형 Zoom-In 프로빙 (`--focus-symbol` / `--uprobe-offset`)**: 의심되는 하위 함수나 Stripped 오프셋만 핀포인트로 좁혀 오버헤드 없이 재계측합니다.
4. **코드 패치 및 정량 검증 (`ebpf_compare_patches` / `--compare`)**: 병목 코드를 수정한 뒤 패치 전/후 트레이스를 비교해 RTT 개선율(`%`)을 수학적으로 증명합니다.

---

# PART 2. 레퍼런스 교차 검증 및 런타임 아키텍처 고도화 내역 (Engineering Rationale)

## 2.1 핵심 레퍼런스 문헌, 타겟 머신 및 커널 소스 매핑

본 명세서의 모든 커널 훅, 맵 타입, 헬퍼 제약 조건, 함수 시그니처, 그리고 CO-RE 런타임 설계는 프로젝트 내 다음 **3대 레퍼런스(공식 문서, 전문 서적, 그리고 실제 타겟 머신인 Rocky Linux 9.8 커널 `5.14.0-687.10.1.el9_8.0.1.aarch64` 원본 소스 코드)**에 엄격히 근거합니다.

1. **`docs.ebpf.io` 공식 레퍼런스 ([`references/ebpf-docs-master/docs/`](references/ebpf-docs-master/docs/))**:
   - [`BPF_PROG_TYPE_XDP.md`](references/ebpf-docs-master/docs/linux/program-type/BPF_PROG_TYPE_XDP.md): `struct xdp_md` 컨텍스트(`data`, `data_end`, `data_meta`), Ingress 전용 제약, Driver 모드(`XDP_FLAGS_DRV_MODE`) 및 Generic/SKB 모드(`XDP_FLAGS_SKB_MODE`), 반환 액션(`XDP_PASS`)
   - [`BPF_PROG_TYPE_SCHED_CLS.md`](references/ebpf-docs-master/docs/linux/program-type/BPF_PROG_TYPE_SCHED_CLS.md): `tc clsact` Ingress/Egress, `direct-action`(`da`) 모드, `TC_ACT_OK`
   - [`BPF_PROG_TYPE_KPROBE.md`](references/ebpf-docs-master/docs/linux/program-type/BPF_PROG_TYPE_KPROBE.md) & [`BPF_PROG_TYPE_TRACEPOINT.md`](references/ebpf-docs-master/docs/linux/program-type/BPF_PROG_TYPE_TRACEPOINT.md): `kprobe`/`kretprobe`, `uprobe`/`uretprobe`, `PT_REGS_PARM1`, `PT_REGS_IP`, `PT_REGS_RC`
   - [`BPF_MAP_TYPE_RINGBUF.md`](references/ebpf-docs-master/docs/linux/map-type/BPF_MAP_TYPE_RINGBUF.md) & [`bpf_ringbuf_reserve.md`](references/ebpf-docs-master/docs/linux/helper-function/bpf_ringbuf_reserve.md): 다중 CPU 공유 MPSC 링버퍼의 전역 순서 보장 및 Reserve/Submit 프로토콜
   - [`BPF_MAP_TYPE_LRU_HASH.md`](references/ebpf-docs-master/docs/linux/map-type/BPF_MAP_TYPE_LRU_HASH.md): 커널 자동 LRU Eviction을 통한 해시맵 고갈 방지
   - [`bpf_get_current_pid_tgid.md`](references/ebpf-docs-master/docs/linux/helper-function/bpf_get_current_pid_tgid.md): 프로그램 타입별 호출 허용 여부(커널 v6.10 미만 XDP/TC 호출 불가)
   - [`concepts/core.md`](references/ebpf-docs-master/docs/concepts/core.md) & [`ebpf-library/libbpf/index.md`](references/ebpf-library/libbpf/index.md): BPF CO-RE(Compile Once – Run Everywhere), BTF 재배치, 런타임 Clang 의존성 제거 아키텍처
   - [`concepts/verifier.md`](references/ebpf-docs-master/docs/concepts/verifier.md): 512바이트 BPF 스택 제한, 포인터 경계 검사, 유한 루프 제약
2. **Brendan Gregg, *BPF 성능 분석 도구 (BPF Performance Tools)* ([`references/BPF-성능-분석-도구.pdf`](references/BPF-성능-분석-도구.pdf))**:
   - **2장 기술 배경 (p.43–95)**: 동적 계측(`kprobe`, `uprobe`)과 정적 계측(`tracepoint`)의 선택 기준 및 오버헤드 특성
   - **6장 CPUs, 7장 메모리, 8·9장 파일/디스크 I/O & 14장 커널 (p.205–450, p.645–690)**: `sched:sched_wakeup`, `sched:sched_switch`, `sched:sched_process_fork`, `kprobe:handle_mm_fault`(`kmem:mm_page_alloc`), `block:block_rq_issue`/`block:block_rq_complete`를 이용한 연산장치(CPU 코어) 진입 직전 런큐 대기(`runqlat`), 락 경합, 페이지 폴트, 블록 I/O 추적
   - **10장 네트워킹 (p.451–556)**: 리눅스 네트워크 스택 계층도(그림 10-1), 네트워크 이벤트 근원(표 10-1), **10.1.4 흔히 저지르는 트레이싱 실수(SoftIRQ 컨텍스트에서 `PID` 참조 오류, p.458)**
   - **12장 프로그래밍 언어 (p.587–605)**: 컴파일 언어 바이너리의 `.symtab` vs `.dynsym` 구조, Stripped 바이너리 오프셋 해석, `uprobe` 선택적 부착을 통한 오버헤드 제어
3. **타겟 머신 (Rocky Linux 9.8 `aarch64`, 커널 `5.14.0-687.10.1.el9_8.0.1.aarch64`) 원본 소스 코드 및 BTF 헤더 ([`references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/))**:
   - **타겟 호스트 환경**: `simple-react-next-spring-app`(`react-next-spring-postgresql-terraform-aws`)의 로컬 UTM VM(`rocky-dev`, 4 vCPU, 5 GiB RAM) 및 AWS EC2 `t4g.large` 호스트 OS인 **Rocky Linux 9.8 (Blue Onyx) `aarch64`**
   - **타겟 커널 BTF 헤더 및 `libbpf` 헤더**:
     - [`btf-and-headers/vmlinux.h`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h): `rocky-dev` VM의 `/sys/kernel/btf/vmlinux`에서 직접 덤프한 2.7MB CO-RE BTF 타입 정의 헤더
     - [`btf-and-headers/bpf/`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/): 타겟 VM의 `/usr/include/bpf/` (`bpf_helpers.h`, `bpf_tracing.h` — `#define __TARGET_ARCH_arm64` 레지스터 매핑 [`bpf_tracing.h:199`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_tracing.h#L199), `bpf_core_read.h`, `bpf_endian.h`)
     - [`btf-and-headers/kernel-aarch64-rhel.config`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/kernel-aarch64-rhel.config) & [`btf-and-headers/kernel.spec`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/kernel.spec)
   - **타겟 커널 원본 소스 트리 ([`linux-5.14.0-687.10.1.el9_8/`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/)) 및 `/proc/kallsyms` 검증 완료된 7-Layer eBPF 훅 실제 시그니처 매핑**:
     - **L2 Ingress/Egress**: [`include/trace/events/net.h#L71-L155`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L71-L155) — `net_dev_xmit(struct sk_buff *skb, int rc, struct net_device *dev, unsigned int skb_len)` ([`net.h:71`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L71)), `net_dev_queue(struct sk_buff *skb)` ([`net.h:143`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L143)), `netif_receive_skb(struct sk_buff *skb)` ([`net.h:150`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L150))
     - **L3 IP Ingress**: [`net/ipv4/ip_input.c#L552`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552) — `int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)` (`PT_REGS_PARM1 = skb`)
     - **L4 TCP Ingress/Egress & Drop/Retransmit**:
       - [`net/ipv4/tcp_ipv4.c#L1945`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1945) — `int tcp_v4_rcv(struct sk_buff *skb)` (`PT_REGS_PARM1 = skb`)
       - [`net/ipv4/tcp_output.c#L1238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238) — `static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)` (**주의**: 래퍼 함수인 `tcp_transmit_skb` [`tcp_output.c:1420`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1420)는 컴파일러에 의해 인라인되어 `/proc/kallsyms`에 없으므로 반드시 실제 심볼인 **`__tcp_transmit_skb`**에 부착하며, `PT_REGS_PARM1 = sk`, `PT_REGS_PARM2 = skb`)
       - [`include/trace/events/skb.h#L24-L36`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24-L36) — `TRACE_EVENT(kfree_skb, TP_PROTO(struct sk_buff *skb, void *location, enum skb_drop_reason reason, struct sock *rx_sk))` (RHEL/Rocky 9.8에 백포트된 `skb_drop_reason` 및 `rx_sk` 포함)
     - **L4.5 Socket Queue Ingress/Egress**: [`net/ipv4/tcp.c#L2742`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2742) — `int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)` (`PT_REGS_PARM1 = sk`, `PT_REGS_PARM3 = len`) 및 [`net/ipv4/tcp.c#L1510`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L1510) — `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)` (`PT_REGS_PARM1 = sk`, `PT_REGS_PARM3 = size`)
     - **L5 Syscall / Kernel-to-User Memory Copy / Page Fault / Block Storage I/O**:
       - [`net/core/datagram.c#L531-L535`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/datagram.c#L531-L535) & [`include/trace/events/skb.h#L76-L88`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L76-L88) — `skb_copy_datagram_iter(const struct sk_buff *skb, int offset, struct iov_iter *to, int len)` 내부에서 `trace_skb_copy_datagram_iovec(skb, len)` 호출
       - [`mm/memory.c#L5313`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/mm/memory.c#L5313) & [`vmlinux.h#L118284`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L118284) — `aarch64`에는 x86 전용인 `exceptions:page_fault_user` 트레이스포인트가 없으므로 `/proc/kallsyms`에 존재하는 `vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs)` (`kprobe:handle_mm_fault`) 및 `tracepoint:kmem:mm_page_alloc`을 사용
       - [`include/trace/events/block.h#L167-L257`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L167-L257) — `tracepoint:block:block_rq_complete` ([`block.h:167`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L167)), `tracepoint:block:block_rq_insert` ([`block.h:238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L238)) 및 `tracepoint:block:block_rq_issue` ([`block.h:252`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L252))
     - **L6 Pre-Compute Scheduler Gate**: [`include/trace/events/sched.h#L170-L238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L170-L238) — `sched_waking(struct task_struct *p)` ([`sched.h:170`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L170), Waker 컨텍스트 보장), `sched_wakeup(struct task_struct *p)` ([`sched.h:178`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L178), Runqueue 진입 시점) 및 `TRACE_EVENT(sched_switch, TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state))` ([`sched.h:222`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L222))
     - **L3 IP Egress**: [`net/ipv4/ip_output.c#L426`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_output.c#L426) — `int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)` (**주의**: `ip_rcv`와 달리 세 번째 인자인 **`PT_REGS_PARM3 = skb`**가 패킷 포인터임)

---

## 2.2 초기 프롬프트 원문 보존 (Original Baseline Prompt)

히스토리 추적 및 요구사항 누락 방지를 위해 초기 프롬프트 원문을 아래에 그대로 보존합니다.

<details>
<summary><b>초기 프롬프트 원문 전체 보기 (클릭하여 펼치기)</b></summary>

```markdown
# PROJECT NAME: eBPF-WireToCode-Tracer
# ROLE & OBJECTIVE
You are a Principal Systems Engineer and Linux Kernel Developer specializing in eBPF (Extended Berkeley Packet Filter), high-performance networking, and low-level runtime observability. 
Your task is to build a "Zero-Touch End-to-End Visual Performance Diagnostics Engine" named **eBPF-WireToCode-Tracer**. This engine automatically maps and visualizes the complete execution lifecycle of a request: from the moment a network packet hits the wire (NIC), passes through the Linux kernel network stack, enters the user-space application layer (Java, Python, Rust, C++), flows through modular function calls, and exits back out through the network card.
The architecture must rely SOLELY on a unified eBPF plumbing pipeline to bypass language-specific runtimes, optimized for AI-driven dynamic configuration and maximum kernel safety.

---

# ARCHITECTURAL PARADIGM & SYSTEM END-TO-END FLOW

eBPF-WireToCode-Tracer must trace and correlate data across the entire system topology sequentially:
1. Inbound Network Entry (Ingress NIC): Capture packets at the network interface card using eBPF XDP (eXpress Data Path) or TC (Traffic Control) clsact hooks.
2. Kernel Network Stack: Track the packet as it ascends through `netif_receive_skb`, IP routing, TCP/UDP socket buffers (`tcp_v4_rcv`), and socket queues.
3. User-Space Application Entry: Trace the exact context switch when the application reads from the socket descriptor (e.g., `sys_enter_read`, `sys_enter_recvfrom`).
4. Internal Call Mapping: Attach `uprobes/uretprobes` to trace file-level, module-level, and function-level execution paths, maintaining the unique network request ID/context.
5. User-Space Application Exit: Trace the socket write syscalls (e.g., `sys_enter_write`, `sys_enter_sendto`).
6. Outbound Network Exit (Egress NIC): Track the packet descending back through the kernel TCP/IP layer (`ip_output`, `dev_queue_xmit`) until it leaves the hardware interface.

---

# HARD CONSTRAINTS & OPTIMIZATIONS

1. NO Language-Specific Runtimes: Do not use Java Agents, Python sys.settrace, or compiler-inserted hooks. All instrumentation must occur safely at the kernel boundary via XDP/TC, Tracepoints, and Uprobes.
2. AI-Friendly Runtime Compilation: The AI control plane must NOT generate arbitrary C code dynamically. Instead, use a fixed, rigorously verified BCC (BPF Compiler Collection) Python template where only strict parameters (PIDs, container IDs, interface names, target memory offsets) are string-replaced at runtime.
3. Request Context Correlation (The Skb-to-Uprobe Bridge): To link a physical network packet to an internal user-space function call without payload modifications, leverage kernel thread context (`current_pid_tgid`), socket tuple hashing (Src IP, Src Port, Dst IP, Dst Port), or skb network metadata (`sk_buff->mark` / `sk_buff->cb`) inside the eBPF maps to pass thread-local telemetry across boundaries.
4. Minimal Kernel Overhead: The eBPF kernel program must perform ZERO heavy parsing. It must only stream raw network metadata and function instruction pointers (IP) instantly via an eBPF Ring Buffer to the user-space.

---

# COMPONENT-LEVEL TECHNICAL SPECIFICATIONS

You must design, implement, and integrate the following three components into a seamless automated pipeline:

## 1. Kernel Space: Full-Stack Telemetry Collector (BCC Engine)
- Implement a BCC-based eBPF C program attaching to:
  - `XDP` / `TC` for Ingress/Egress packet timestamps and byte counters.
  - `Tracepoints` (`syscalls:sys_enter_read`, `syscalls:sys_enter_write`) to track data handoffs between kernel and user boundaries.
  - `Uprobes/Uretprobes` for tracking internal function call lifecycles.
- **Strict Data Struct Definition (C Struct):**
  ```c
  struct kray_event_t {
      u32 pid;
      u32 tid;
      u64 ip;           // Instruction Pointer (0 for pure network events)
      u64 timestamp;    // Kernel uptime nanoseconds
      u32 src_ip;
      u32 dst_ip;
      u16 src_port;
      u16 dst_port;
      u8  layer_type;   // 1: INGRESS_NIC, 2: KERNEL_NET, 3: USER_ENTRY, 4: USER_FUNC, 5: USER_EXIT, 6: EGRESS_NIC
      u8  is_return;    // 0: Entry, 1: Return
  };
  ```

## 2. User Space: Async AI Helper & Symbolication Agent (Python)
- Build an asynchronous event-loop worker polling the eBPF Ring Buffer.
- **Dynamic Address Mapping & Network Correlation Engine:**
  - Read `/proc/<PID>/maps` to handle dynamic library loads (`dlopen`).
  - Parse ELF symbol tables (`.symtab`/`.dynsym`) using `pyelftools`.
  - Reconstruct the unified request timeline by grouping events that share the same socket connection tuple and overlapping timestamp sequences.

## 3. Visualization Pipeline: Automated Graphviz DOT Layout Generator
- Process the streaming, symbolicated data stream into a chronological, modular Graphviz DOT layout.
- **Full-Flow Layer Clustering:** Organize the visualization layout into explicit vertical or horizontal tiers: `[INGRESS_WIRE]` -> `[KERNEL_OS_STACK]` -> `[APPLICATION_MODULES]` -> `[EGRESS_WIRE]`.
- Group internal functions into isolated visual blocks using the `subgraph cluster_<filename>` paradigm.
- **Telemetry Visual Encodings:** Compute latency deltas between hops. Highlight hot paths or slow handoffs (e.g., time stuck in Kernel Queue vs Time inside Application logic) using a dynamic color gradient (green-to-red).

---

# COMPREHENSIVE EDGE-CASE HANDLING REQUIREMENTS
1. **Stripped Binaries:** If an ELF binary lacks debug symbols, fall back gracefully to displaying relative library offsets (`libxyz.so+0x1a2b`).
2. **Ring Buffer Overflow:** Implement a high-watermark drop-counter. If user-space lags, track dropped events and render a prominent warning block on the final graph layout.
3. **Asynchronous/Thread-Pooled I/O:** Handle cases where one thread reads from the network socket but passes the payload to a worker pool thread. Use eBPF map tracking across thread forks to preserve the request lineage.

---

# EXPECTED DELIVERABLES
Provide an absolute production-ready, highly commented, and clean codebase comprising:
1. **`tracer_kernel.c`**: The definitive eBPF C program merging XDP/TC, tracepoints, and uprobes safely.
2. **`tracer_agent.py`**: The fully async Python engine managing BCC injection, tracking cross-layer request states, loading symbol maps, and outputting live DOT files.
3. **`test_harness.sh` & Quickstart Blueprint**: A complete shell script containing a mockup C++ network socket application with artificial latency, Docker/Network Namespace configurations, and exact commands to run the tracer, trigger curl traffic, and compile the final `.dot` file into a high-resolution `.svg` diagram mapping the complete wire-to-code-to-wire pipeline.
```

</details>

---

## 2.3 기존 프롬프트의 10대 기술적 단절(Gap) 및 차세대 런타임 해법

초기 프롬프트를 실제 리눅스 커널, eBPF 검증기(Verifier), 그리고 상시 구동되는 MCP/REST 서비스 환경에 적용할 때 발생하는 **10가지 구조적 한계**와 그 해결책입니다.

#### 1. 패킷 ↔ 프로세스 컨텍스트 단절 (SoftIRQ vs Thread)
- **초기 프롬프트의 한계점**: `XDP`에는 아직 `sk_buff`가 없으며(`xdp_md`만 존재), `XDP`/`tcp_v4_rcv`는 SoftIRQ 컨텍스트라 `current_pid_tgid`가 애플리케이션 PID가 아닙니다. 또한 `sys_enter_read(fd, ...)`는 정수 `fd`만 인자로 받으므로 소켓 4-Tuple을 직접 알 수 없습니다.
- **레퍼런스 근거**: *BPF 성능 분석 도구* 10.1.4절(p.458) 및 `bpf_get_current_pid_tgid.md` (커널 v6.10 미만에서는 XDP/TC에서 해당 헬퍼 호출 시 Verifier가 로드를 거부).
- **고도화된 아키텍처 해법**: **2단계 인과관계 브릿지(Two-Stage Causality Bridge)** — Stage A(`ingress_flow_map`)에서 XDP/TC 및 `tcp_v4_rcv`는 `PID`를 호출하지 않고 정규화된 4-Tuple을 Key로 `{req_id, ingress_ts}`를 기록하고, Stage B(`active_ctx_map`)에서 유저 스레드가 실행되는 `kprobe:tcp_recvmsg(struct sock *sk, ...)`에서 `sk`의 정규화된 4-Tuple로 `ingress_flow_map`을 조회하여 `active_ctx_map[tid]`에 `req_id`를 바인딩합니다.

#### 2. NIC Egress 훅 비대칭성
- **초기 프롬프트의 한계점**: 송수신 모두 XDP/TC를 포괄적으로 언급하여 Egress XDP 부착 시도 위험이 있습니다.
- **레퍼런스 근거**: `BPF_PROG_TYPE_XDP.md` (XDP는 Ingress 전용이며 Egress 경로에는 존재하지 않음) 및 *BPF 성능 분석 도구* 표 10-1.
- **고도화된 아키텍처 해법**: Ingress는 `BPF_PROG_TYPE_XDP`(`XDP_FLAGS_SKB_MODE` 폴백, 반환값 `XDP_PASS`) + `tracepoint:net:netif_receive_skb`(중복 방출 방지 가드 포함), Egress는 `kprobe:__tcp_transmit_skb` → `kprobe:ip_output` → `tracepoint:net:net_dev_queue` → `tracepoint:net:net_dev_xmit` 대칭 파이프라인을 구성합니다.

#### 3. 다중 코어 이벤트 순서 역전 및 해시맵 고갈
- **초기 프롬프트의 한계점**: 일반 해시맵(`BPF_HASH`) 사용 시 비정상 연결 종료 시 엔트리가 영구 잔류하여 맵이 고갈됩니다.
- **레퍼런스 근거**: `BPF_MAP_TYPE_RINGBUF.md` (전 CPU 공유 MPSC 링버퍼만이 전역 시간 순서를 보장) 및 `BPF_MAP_TYPE_LRU_HASH.md`.
- **고도화된 아키텍처 해법**: 6종 상태 맵(`ingress_flow_map`, `active_ctx_map`, `pending_handoff_map`, `egress_flow_map`, `skb_egress_map`, `inflight_bio_map`)을 모두 `BPF_LRU_HASH`로 선언하고, 이벤트 스트리밍은 `BPF_RINGBUF_OUTPUT`을 사용하며 `ringbuf_reserve()` 실패 시 `drop_cnt_map`을 원자적으로 증가시킵니다.

#### 4. C 구조체 암묵적 패딩 및 512B 스택 한계
- **초기 프롬프트의 한계점**: 초기 `struct kray_event_t`가 42바이트로 끝나 컴파일러가 암묵적 패딩을 삽입하여 `ctypes` 매핑 시 오프셋 불일치가 발생하며, `tid_ctx_t`(`>400B`)를 BPF 스택에 선언하면 512바이트 한계를 초과합니다.
- **레퍼런스 근거**: `concepts/verifier.md` (eBPF 스택은 512바이트로 제한).
- **고도화된 아키텍처 해법**: 64바이트 고정 크기 `struct __attribute__((packed)) kray_event_t`를 `ringbuf_reserve()` 포인터에 직접 기록하고, `tid_ctx_t` 초기화는 `BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)` 스크래치 버퍼를 사용하여 스택 소모를 0바이트로 제거합니다.

#### 5. 스레드 풀(Thread Pool) 컨텍스트 단절 및 SMP 원격 Wakeup 함정
- **초기 프롬프트의 한계점**: `sched_process_fork`만 언급되어 있으나 현대 서버는 워커 스레드 풀(`futex`/`pthread_cond_signal`)을 사용하며, 멀티코어(SMP)에서 `sched_wakeup`은 타겟 CPU IPI 컨텍스트에서 실행될 수 있고 워커가 이미 `TASK_RUNNING`일 때는 `sched_waking`과 `FUTEX_WAKE` 시스콜조차 생략될 수 있습니다([`sched.h:167-180`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L167-L180)).
- **레퍼런스 근거**: *BPF 성능 분석 도구* 6장 & 14장 및 `sched.h:170`.
- **고도화된 아키텍처 해법**: Tier 1 `tracepoint:sched:sched_waking`(`args->pid`) 직접 전파 + Tier 2 `kprobe__tcp_recvmsg` 및 `sys_enter_futex`에서 게시하는 **8-슬롯 FIFO `pending_handoff_map[tgid]`** 결합으로 동시 요청 및 `TASK_RUNNING` 스핀 워커까지 100% 핸드오프를 추적합니다.

#### 6. 중첩 함수 소요 시간, `uretprobe` 트램펄린 IP 오염 및 Stripped 바이너리 해석
- **초기 프롬프트의 한계점**: `uretprobe`에서 `PT_REGS_IP(ctx)`를 읽으면 커널 트램펄린 주소로 오염되며, `strip -x`된 `.so`의 내부 정적 함수는 `.symtab`/`.dynsym` 모두에서 사라집니다.
- **레퍼런스 근거**: *BPF 성능 분석 도구* 12장 12.1절(p.587–590).
- **고도화된 아키텍처 해법**: `uprobe` 진입 시 `fn_entry_ip[depth]`를 백업하여 `uretprobe` 복귀 시 복원하고(`if (ctx->call_depth == 0) return 0;` 가드 포함), Stripped 바이너리는 **`.eh_frame` FDE `pc_begin` 및 `bl`/`callq` 분기 타겟 스캐너**로 내부 함수 오프셋(`<module>+0x<rel_offset>`)을 자동 발굴합니다.

#### 7. 매번 C 문자열 치환 재컴파일로 인한 Cold-Start 지연
- **초기 프롬프트의 한계점**: 타겟 PID나 포트가 바뀔 때마다 Clang/LLVM을 다시 돌리면 `2~5초`가 걸려 MCP/REST 상시 서버로 쓸 수 없습니다.
- **레퍼런스 근거**: `concepts/core.md` & `libbpf`.
- **고도화된 아키텍처 해법**: 커널 내에 `BPF_ARRAY(runtime_config_map, struct kray_runtime_cfg_t, 1)`을 두어 타겟 변경 시 **재컴파일 없이(`0ms`) 맵 엔트리만 원자적으로 갱신**합니다.

#### 8. AI 에이전트용 MCP & 외부 연동 REST API 내장
- **초기 프롬프트의 한계점**: 일회성 CLI 실행만 고려되어 외부 AI 에이전트가 프로그래밍 방식으로 호출하기 어렵습니다.
- **고도화된 아키텍처 해법**: `--serve mcp` (6대 MCP Tools) & `--serve rest` (`/api/v1/*`)를 단일 런타임에 내장하고 `ai_diagnosis.json`을 통해 7대 계층 메트릭, DWARF 소스 스니펫 및 Stripped 어셈블리 블록을 즉시 반환합니다.

#### 9. 멀티모달 휴먼 인터페이스 (Web Dashboard & Terminal TUI)
- **초기 프롬프트의 한계점**: 정적 `.dot`/`.svg` 파일만 생성하여 코드/어셈블리 조회나 패치 전후 비교에 긴 CLI 옵션을 반복 입력해야 합니다.
- **고도화된 아키텍처 해법**: 인터랙티브 웹 대시보드(`--ui web` / `trace_dashboard.html`)와 대화형 터미널 TUI(`--ui tui`)를 동시에 제공합니다.

#### 10. 범용 리눅스 배포판 호환성 및 비특권 CI 검증 보장
- **초기 프롬프트의 한계점**: 특정 커널 버전의 인라인 심볼에만 고정되거나 루트 권한(`CAP_BPF`)이 없는 컨테이너 CI에서 테스트할 방법이 없습니다.
- **고도화된 아키텍처 해법**: `--mode live` (Linux BCC / libbpf 커널 주입 + `/proc/kallsyms` 런타임 심볼 Auto-Resolver) 및 `--mode simulate` (실제 컴파일된 Linux ELF C++ 바이너리와 Stripped `.so`의 심볼/오프셋을 파싱하여 동일한 64바이트 이진 스트림을 생성·검증하는 비특권 CI 모드)를 동시 지원합니다.

---

## 2.4 차세대 범용 런타임 아키텍처 비교 (Universal Architecture & Design Matrix)

본 프로젝트는 **Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`)**을 100% 소스 코드 단위로 검증된 **레퍼런스 기준점(Reference Baseline)**으로 삼으면서도, **어떠한 리눅스 배포판·아키텍처(`aarch64`/`x86_64`)·프로토콜(`TCP/UDP/IPv4/IPv6/ICMP/ARP/UNIX/TLS`)·포트(`0~65535`)에서도 재설계 없이 즉시 동작하는 범용 구조(Universal Architecture)**를 채택합니다.

### 2.4.1 런타임 설정 제어 방식 비교: 문자열 치환 재컴파일 vs Map-Driven + BPF CO-RE
- **타겟 PID / Port / Proto 변경 시 지연 시간**: 기존 Template String-Replace 방식은 `2,000 ~ 5,000 ms` (Clang/LLVM 재컴파일) 소요 → **채택된 Map-Driven `runtime_config_map` 방식은 `< 0.05 ms` (`0ms` 무재컴파일)** 로 커널 메모리를 즉시 갱신합니다.
- **MCP / REST API 상시 데몬 적합성**: API 호출마다 블로킹 없이 즉각 응답하며 무중단 타겟 스위칭이 가능합니다.
- **컴파일 타임 매크로 호환성**: 기본값 매크로(`__TARGET_PID__`, `__TARGET_PORT__`)와 런타임 `runtime_config_map[0]` 오버라이드를 동시 지원(Dual-Compatible)합니다.

### 2.4.2 타겟 머신 & 커널 심볼 호환성 설계 (Rocky 9.8 실증 기준점 + Universal Auto-Resolver 결합형)
- **방식 A (단일 커널 하드코딩형 — 지양)**: 특정 커널 버전에서만 동작하고 타 배포판에서 로드 실패 위험이 있습니다.
- **방식 B (순수 추상 범용형 — 지양)**: 실제 Rocky 9.8(`5.14.0-687`)처럼 컴파일러 인라인(`__tcp_transmit_skb`)이나 아키텍처 차이 발생 시 런타임 에러가 발생합니다.
- **방식 C (최종 채택 — Rocky 9.8 실증 기준점 + Universal Auto-Resolver 결합형)**:
  1. Rocky 9.8 커널 소스(`5.14.0-687.10.1.el9_8`)로 100% 교차 검증.
  2. 로드 시점에 `/proc/kallsyms` 및 `/sys/kernel/tracing/events`를 스캔하여 심볼 자동 바인딩 (`__tcp_transmit_skb` ↔ `tcp_transmit_skb`, `handle_mm_fault` ↔ `exceptions:page_fault_user`).
  3. `uname -m`에 따라 `arm64` / `x86` 레지스터 매크로 자동 선택.

### 2.4.3 프로토콜 & 포트(`0 ~ 65535`) 추적 파이프라인 설계 (플러그형 어댑터 + 불변 코어)
- **가변 영역 — 플러그형 프로토콜 어댑터 (`L2 ~ L4.5`)**:
  - **IPv4 / IPv6**: `ip_rcv`/`ip_output` (`PARM3=skb`), `ipv6_rcv`/`ip6_output`
  - **TCP**: `tcp_v4_rcv`/`tcp_v6_rcv`, `tcp_recvmsg`/`tcp_sendmsg`/`kretprobe__tcp_sendmsg`, `__tcp_transmit_skb`
  - **UDP**: `udp_rcv`, `udp_recvmsg`/`udp_sendmsg`
  - **ICMP / ARP**: `icmp_rcv`, `arp_rcv`
  - **AF_UNIX (포트 없는 IPC)**: `unix_stream_recvmsg`/`unix_stream_sendmsg` (`unix_sk(sk)->peer` 정규화)
  - **TLS (암호화 경계)**: `uprobe:libssl.so:SSL_read` / `SSL_write`
  - **공통 출력**: 프로토콜이 무엇이든 `active_ctx_map[tid]`에 표준화된 `{req_id, proto, sport, dport, ingress_ts}`를 바인딩하여 L5 불변 코어로 인계합니다.
- **불변 코어 — Universal Pre-Compute & ALU Core (`L5 ~ L7`)**:
  - 어느 프로토콜/포트(`0~65535`)에서 왔든 100% 동일한 코드로 **L5(`skb_copy_datagram_iovec`, `handle_mm_fault`, `block_rq_insert`/`issue`/`complete`) → L6(`sys_enter_futex`/`exit_futex`, `sched_waking`/`sched_wakeup`, `sched_switch`) → L7(`uprobe`/`uretprobe`, DWARF 소스 및 Stripped `.so` 어셈블리 추출)**을 수행합니다.

---

## 2.5 엔드투엔드 범용 시스템 & 서비스 런타임 아키텍처 다이어그램

```mermaid
flowchart TB
    subgraph KERNEL["Tier 1: Universal Map-Driven & CO-RE 7-Layer eBPF Collector (tracer_kernel.c)"]
        CFG["BPF_ARRAY: runtime_config_map[0]<br/>{target_pid, target_port (0..65535), proto_mask, capture_enabled}<br/>Hot-Reloadable in 0ms + Runtime kallsyms Auto-Resolver!"]
        ADAPTERS["Pluggable Protocol Adapters (L2 ~ L4.5)<br/>• TCP/IPv4/IPv6: xdp -> ip_rcv/ipv6_rcv -> tcp_v4_rcv -> tcp_recvmsg<br/>• UDP/DNS: udp_rcv -> udp_recvmsg | ICMP/ARP: icmp_rcv / arp_rcv<br/>• Local IPC: unix_stream_recvmsg | TLS: uprobe libssl SSL_read/write<br/>Normalize all protocols & ports (0..65535) into active_ctx_map[tid]"]
        CORE_L5["Universal Core L5: Syscall / Memory Copy / Page Fault / Block Storage I/O<br/>tp:skb:skb_copy_datagram_iovec + kprobe:handle_mm_fault + tp:block:block_rq_issue/complete"]
        CORE_L6["Universal Core L6: PRE-COMPUTE SCHEDULER GATE (OSI_L6_PRE_COMPUTE=8)<br/>sys_enter_futex -> tp:sched:sched_wakeup -> tp:sched:sched_switch (Runqueue & CPU Migration)"]
        CORE_L7["Universal Core L7: COMPUTE UNIT ALU (OSI_L7_APP=7) & Symmetric Egress<br/>Dynamic uprobe/uretprobe -> tcp_sendmsg/udp_sendmsg/unix_stream_sendmsg -> __tcp_transmit_skb -> ip_output -> net_dev_xmit"]
        CFG -.-> ADAPTERS & CORE_L5 & CORE_L6 & CORE_L7
        ADAPTERS --> CORE_L5 --> CORE_L6 --> CORE_L7
    end

    subgraph CORE["Tier 2: Unified User-Space Runtime Engine (tracer_agent.py)"]
        RESOLVER["Runtime Environment & Symbol Auto-Resolver<br/>Scan /proc/kallsyms + /sys/kernel/tracing/events + ss -tulnp/-xlnp (Ports 0..65535)"]
        RING["Async RingBuf Consumer + Overflow Drop Monitor"]
        SYM["3-Tier Linux ELF Symbolicator<br/>/proc/pid/maps -> .symtab -> .dynsym -> module+0xoffset"]
        EXTRACT["7-Layer Verifier & Auto Source/ASM Extractor<br/>• L2..L6 Pre-Compute Gate & Block I/O Verification<br/>• Unstripped: DWARF file:line + C++ Source Snippet<br/>• Stripped: objdump -d ELF ASM Instructions"]
        RESOLVER -.-> ADAPTERS
        CORE_L7 --> RING --> SYM --> EXTRACT
    end

    subgraph GATEWAY["Tier 3: Multi-Protocol Human & AI Service Interfaces"]
        WEB["1. Interactive Web Dashboard (--ui web / trace_dashboard.html)<br/>Click SVG Node -> Side-Panel Source/ASM/Header Viewer + 7-Layer Matrix + Compare Tab"]
        TUI["2. Interactive Terminal TUI (--ui tui)<br/>SSH Keyboard Menu [1..7]"]
        MCP["3. AI Agent MCP Server (--serve mcp)<br/>JSON-RPC 2.0 (stdio / HTTP)<br/>6 Native Tools: configure / capture / inspect_network_layers / inspect_code / compare / render"]
        REST["4. REST & SSE API Server (--serve rest)<br/>PUT /api/v1/config | POST /api/v1/traces | GET /api/v1/network-layers | GET /api/v1/inspect | POST /api/v1/compare"]
        EXTRACT --> WEB & TUI & MCP & REST
        MCP & REST -. "Hot-Update 0ms" .-> CFG
    end
```

---

## 2.6 구현 전 아키텍처 및 커널 시스템 설계 결함 10회 반복 검증·재설계 내역 (10-Iteration Pre-Implementation Architectural Design Audit)

코드를 한 줄이라도 작성하기 전 단계에서, 현 명세서대로 그대로 구현했을 때 실제 Linux 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 및 멀티스레드 C++ 런타임에서 발생할 **구조적 작동 불능·상관관계 유실·교착 상태(Deadlock)·메모리/레지스터 오동작 등 10대 심층 설계 결함(Pre-Implementation Architectural & System Design Flaws)**을 10회 반복 감사를 통해 발굴하고 아키텍처 수준에서 재설계한 내역입니다.

### Iteration 1 — TCP 0바이트 제어 패킷(`SYN` / 순수 `ACK`)의 `ingress_flow_map` 덮어쓰기 및 Keep-Alive 좀비 `req_id` 잔류 결함
- **발굴된 설계 결함**: 기존 설계는 패킷 도착마다 페이로드 길이와 무관하게 무조건 `ingress_flow_map[key]`에 새 `req_id`를 덮어쓰고, 응답 송신 후에도 `active_ctx_map[tid]`를 정리하지 않았습니다.
- **방치 시 런타임 장애**: 3-Way Handshake의 마지막 0바이트 `ACK`나 요청 직후 도착하는 순수 `ACK`가 유저 스레드의 `tcp_recvmsg` 실행 전에 `ingress_flow_map[key]`의 `req_id`를 덮어써 L2~L4와 L7의 `req_id`가 단절됩니다. 또한 HTTP Keep-Alive 재사용 시 이전 요청의 좀비 `req_id`가 후속 요청을 오염시킵니다.
- **아키텍처 재설계 해결책**:
  - **Payload-Gated `req_id` Minting**: `tcp_payload_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4) - (tcp->doff * 4)`를 계산하여 `tcp_payload_len > 0`인 데이터 패킷이거나 기존 상태가 `consumed == 1`일 때만 신규 `req_id`를 발급·갱신하고, 0바이트 순수 `ACK`는 기존 미소비(`consumed == 0`) `flow_state_t.req_id`를 보존합니다.
  - **Deterministic Context Teardown (`kretprobe__tcp_sendmsg`)**: `tcp_recvmsg`가 `req_id`를 소비할 때 `state->consumed = 1`로 마킹하고, 서버 소켓(`skc_num == target_port`)에 대한 응답 송신이 확인된 경우(`ctx->in_target_sendmsg = 1`)에만 커널 함수 복귀 훅인 **`kretprobe__tcp_sendmsg`**에서 `active_ctx_map.delete(&tid)`로 즉시 해제합니다. *(주의: 일반 표준출력/파일 로깅 시 호출되는 `sys_exit_write`에서 무조건 `active_ctx_map`을 삭제하면 후속 비즈니스 로직과 `tcp_sendmsg` 컨텍스트가 증발하므로 절대 `sys_exit_write`에서 삭제하지 않으며, 커널 함수인 `tcp_sendmsg`에는 유저용 `uretprobe`가 아닌 커널용 `kretprobe`를 사용합니다).*

### Iteration 2 — `uretprobe` 트램펄린 IP 오염(`PT_REGS_IP(ctx)` != 함수 시작 주소) 및 `call_depth`(`u8`) 언더플로우(`0 -> 255`) 결함
- **발굴된 설계 결함**: Linux 커널 `uretprobe` 실행 시 `PT_REGS_IP(ctx)`는 원래 함수의 진입 주소가 아니라 커널이 스택 복귀 주소를 가로채기 위해 교체한 `[uprobes]` 트램펄린 주소(`0x7fffffffe000`) 또는 상위 Caller 복귀 주소를 가리킵니다. 또한 `req_id`가 바인딩되기 전부터 이미 호출 스택에 떠 있던 상위 함수(`main`, 이벤트 루프 등)가 반환될 때 `call_depth == 0`에서 `call_depth--`를 수행하면 `u8`이 `255`로 언더플로우됩니다.
- **방치 시 런타임 장애**: 모든 `is_return=1` 이벤트가 `[uprobes]+0x0`으로 잘못 심볼 해석되어 함수 진입(`is_return=0`)과 복귀(`is_return=1`) 매칭이 100% 실패하며, `call_depth`가 `255`가 되는 순간 배열 접근 시 eBPF Verifier 경계 검사를 위반합니다.
- **아키텍처 재설계 해결책**:
  - **`fn_entry_ip[MAX_CALL_DEPTH]` 스택 도입**: `struct tid_ctx_t`에 `u64 fn_entry_ip[MAX_CALL_DEPTH]`를 추가하여 `uprobe` 진입 시 `PT_REGS_IP(ctx)`를 저장하고, `uretprobe` 복귀 시에는 `PT_REGS_IP(ctx)`가 아닌 저장된 `ctx->fn_entry_ip[depth]`를 `ev->ip`에 기록합니다.
  - **Underflow Guard & Bitmask**: `uretprobe` 진입 시 `if (ctx->call_depth == 0) return 0;` 가드를 강제하고, 배열 인덱싱 시 항상 `u32 depth = ctx->call_depth & (MAX_CALL_DEPTH - 1);` 비트마스크를 적용합니다.

### Iteration 3 — 이미 깨어 있는(`TASK_RUNNING`) 워커 스레드에서 `sched_waking`/`sched_wakeup` 및 `glibc` `futex` 시스템콜 생략 결함과 다중 동시 요청 덮어쓰기 결함
- **발굴된 설계 결함**: 기존 설계는 오직 `sched_waking`/`sched_wakeup` 커널 트레이스포인트에만 의존하여 `TID A -> TID B`로 `req_id`를 전달했습니다. 그러나 멀티코어 환경에서 워커 스레드(`TID B`)가 이전 작업을 막 끝내고 아직 Sleep(`futex_wait`)에 들어가기 직전(`TASK_RUNNING`)에 I/O 스레드(`TID A`)가 큐에 작업을 넣고 `notify_one()`을 호출하면 커널 `sched_waking`/`sched_wakeup`이 아예 호출되지 않습니다. 심지어 `glibc`의 `pthread_cond_signal` 구현은 대기 중인 스레드 수(`__wrefs`)가 0이면 유저 공간에서 즉시 반환하므로 `sys_enter_futex(FUTEX_WAKE)`조차 호출되지 않을 수 있습니다! 또한 프로세스(`tgid`)당 단일 슬롯만 두면 동시 요청(`req_id #1`, `req_id #2`, `TEST-03`) 도착 시 후속 요청이 선행 요청의 핸드오프 상태를 덮어씁니다.
- **방치 시 런타임 장애**: 고부하 또는 연속 요청 시 워커 스레드(`TID B`)가 `sched_wakeup`과 `futex` 시스템콜을 모두 거치지 않고 곧바로 큐에서 작업을 꺼내 `execute_storage_query()`를 실행하므로, Layer 4(워커 스레드)와 Layer 5/6(응답 송신) 전체가 트레이스에서 통째로 증발하거나(`TEST-04` 실패), 동시 다중 요청 간 `req_id`가 교차 오염됩니다(`TEST-03` 실패).
- **아키텍처 재설계 해결책**:
  - **Tier 1 (Sleeping Worker)**: SMP 원격 CPU에서도 Waker 컨텍스트가 보장되는 `sched_waking`([`sched.h:170`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L170))에서 `args->pid`를 사용해 `active_ctx_map[target_tid]`로 즉시 상속하고 해당 `req_id`의 `pending_handoff_map` 슬롯을 `claimed = 1`로 마킹합니다.
  - **Tier 2 (Multi-Request Safe 8-Slot Ring `pending_handoff_map` & Early Publication)**: `BPF_LRU_HASH(pending_handoff_map, u32 /* tgid */, struct handoff_ring_t, 1024)`를 도입하여 프로세스별 8-슬롯 링버퍼(`slots[8]`, `write_idx`, `read_idx`)를 유지합니다. `glibc` 유저 공간 Fastpath로 인해 `sys_enter_futex(FUTEX_WAKE)`가 생략되는 경우까지 100% 방어하기 위해, 디스패처 스레드(`TID A`)가 `kprobe__tcp_recvmsg`에서 `req_id`를 바인딩할 때 곧바로 `ring->slots[ring->write_idx & 7]`에 `{req_id, wakeup_ts=now, waker_tid=tid, claimed=0}`을 선행 게시(`write_idx++`)하고 이후 `sys_enter_futex`(`FUTEX_WAKE=1`, `FUTEX_REQUEUE=3`, `FUTEX_CMP_REQUEUE=4`, `FUTEX_WAKE_OP=5`, `FUTEX_UNLOCK_PI=7`, `FUTEX_WAKE_BITSET=10`, `FUTEX_CMP_REQUEUE_PI=12`) 호출 시 `wakeup_ts`를 최신화합니다. 동일 프로세스(`tgid`) 내 다른 워커 스레드(`tid != waker_tid`)가 아직 `req_id`가 없는 상태에서 `sys_exit_futex` 또는 첫 `uprobe`에 진입하면 `ring->slots[ring->read_idx & 7]`(`claimed == 0`)을 FIFO 순서로 인계받아 동시 요청 덮어쓰기나 Fastpath 누락 없이 `FLAG_THREAD_HANDOFF` 및 `parent_tid = waker_tid`를 100% 보장합니다.

### Iteration 4 — 동일 호스트 루프백(`lo`, `127.0.0.1`) 환경에서 클라이언트(`curl`)와 서버(`mock_server`) 소켓 이벤트 충돌 결함
- **발굴된 설계 결함**: 루프백 통신 시 클라이언트의 송신(`tcp_sendmsg`)·수신(`tcp_recvmsg`)과 서버의 수신·송신이 동일한 커널 훅과 동일한 4-Tuple(방향만 반대)을 통과합니다.
- **방치 시 런타임 장애**: 클라이언트가 요청을 보낼 때 호출한 `tcp_sendmsg`가 서버의 Egress로 오인되거나, 서버가 보낸 응답 패킷(`sport=8080 -> dport=ephemeral`)이 `lo` 인터페이스의 `ip_rcv`/`tcp_v4_rcv`로 다시 들어올 때 새로운 Ingress 요청으로 오인되어 가짜 `req_id`가 대량 생성됩니다.
- **아키텍처 재설계 해결책**:
  - **Loopback Server-Role Direction Guard 명문화**:
    1. **Ingress Wire (`xdp`/`ip_rcv`/`tcp_v4_rcv`)**: 반드시 **`dport == target_port`** 인 패킷만 Ingress 요청으로 인정합니다 (`sport == target_port`인 루프백 응답 반사 패킷은 Ingress에서 즉시 무시).
    2. **Socket Bridge (`tcp_recvmsg`/`tcp_sendmsg`)**: 반드시 로컬 소켓 포트 **`sk->__sk_common.skc_num == target_port`** 를 만족하는 서버 측 소켓만 추적하여 클라이언트(`curl`) 소켓을 완벽히 배제합니다 (`skc_rcv_saddr`/`skc_daddr` 방향 및 엔디안 정규화 병행).
    3. **Egress Wire (`__tcp_transmit_skb`/`ip_output`)**: 반드시 **`sport == target_port`** 인 패킷만 Egress 응답으로 추적합니다.

### Iteration 5 — `kprobe:ip_rcv` 진입 시점의 미초기화 `skb->transport_header` 참조 결함 및 `net_dev_xmit` 해제 후 포인터 역참조 결함
- **발굴된 설계 결함**: Rocky 9.8 커널 [`net/ipv4/ip_input.c:552`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552)의 `ip_rcv()` 진입 시점에는 아직 `ip_rcv_core()` 및 `skb_set_transport_header()`가 실행되기 전이므로 `skb->transport_header`가 L4 TCP 헤더를 가리키지 않습니다. 또한 Egress `net_dev_xmit`([`net.h:71`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L71))는 드라이버 송신(`ndo_start_xmit`) 직후 호출되어 `skb->head`가 이미 해제(free)되었을 수 있습니다.
- **방치 시 런타임 장애**: `kprobe:ip_rcv`에서 `skb->head + skb->transport_header`로 TCP 포트를 읽으면 쓰레기 값이 읽혀 `ingress_flow_map` 조회가 **100% 실패**하고 L3(`OSI_L3_IP`) 계층 이벤트가 전부 유실됩니다.
- **아키텍처 재설계 해결책**:
  - **`kprobe:ip_rcv` L4 오프셋 직접 산출 규칙**: `kprobe:ip_rcv`에서는 절대 `skb->transport_header`를 쓰지 않고, **`u16 net_off = skb->network_header;`** 로 IP 헤더를 먼저 읽은 뒤 **`u16 trans_off = net_off + ((iph.ihl & 0x0f) * 4);`** 수식으로 `skb->head + trans_off`에서 TCP/UDP 포트를 정확히 추출합니다.
  - **`skb_egress_map` 포인터 브릿지**: `ip_output`/`net_dev_queue`에서 `skb_egress_map[(u64)skb] = egress_key`를 저장하고 `net_dev_xmit`에서는 `args->skbaddr` 포인터 값만으로 안전하게 조회합니다.

### Iteration 6 — C++ 바이너리 `.symtab`/`.dynsym` 무차별 `uprobe` 부착 시 FD 고갈(`EMFILE`), `-O1` 인라인으로 인한 함수 소실, PIE `PT_LOAD` 오프셋 어긋남 및 Stripped `.so` 내부 함수 탐색 불가 결함
- **발굴된 설계 결함**: ① C++ `mock_server`의 `.symtab`에는 수천 개의 STL 심볼이 있어 전수 부착 시 `EMFILE`이 발생합니다. ② `mock_server.cpp`를 `-O1`로 빌드하면 컴파일러가 `parse_http_request()`나 `verify_hmac_signature_internal()`을 호출부로 인라인(Inline)시켜버려 `uprobe`가 아예 트리거되지 않습니다. ③ PIE/공유 라이브러리에서 ELF 심볼의 `st_value`를 `PT_LOAD` 세그먼트의 `(p_vaddr - p_offset)` 보정 없이 그대로 커널 `uprobe` 오프셋으로 넘기면 `aarch64` 페이지 정렬 차이로 `-EINVAL`이 발생합니다. ④ `strip -x` / `strip --strip-unneeded`로 로컬 심볼이 제거된 `libcrypto_mock.so`에서 `--uprobe-offset` 수동 지정 없이 어떻게 내부 함수를 자동 발견할지 메커니즘이 없었습니다.
- **방치 시 런타임 장애**: `EMFILE` 크래시, 인라인으로 인한 L7 함수 노드 누락, `aarch64` `uprobe` 부착 실패(`-EINVAL`), 또는 `TEST-05`/`TEST-08`에서 Stripped 내부 함수 자동 탐지 실패가 발생합니다.
- **아키텍처 재설계 해결책**:
  - **Deterministic ELF Symbol Filter & `__attribute__((noinline))` + `-O0 -fno-inline`**: 시스템/컴파일러/C++ 표준 라이브러리 접두사(`_start`, `__libc_`, `__cxa_`, `__gxx_`, `_ZSt`, `_ZNSt`, `_ZNKSt`, `_GLOBAL__`, `frame_dummy`, `register_tm_clones`, `@plt`) 및 크기 `st_size < 16` 바이트 이하인 Thunk를 제외하고 최대 `MAX_AUTO_UPROBES = 64`개로 제한하며, 타겟 함수들에 `__attribute__((noinline))` 및 `-g -O0 -fno-inline -fno-omit-frame-pointer` 빌드를 적용합니다.
  - **ELF `PT_LOAD` 파일 오프셋 변환 공식 & `.eh_frame` FDE / `bl` Call-Target 기반 Stripped 함수 자동 탐색기**: `uprobe` 등록 시 반드시 실행 세그먼트(`PF_X`) 기준 **`uprobe_file_offset = st_value - seg.p_vaddr + seg.p_offset`** 공식을 적용합니다. 또한 `.symtab`이 제거된 Stripped `.so`에 대해서는 `strip` 후에도 C++ ABI상 반드시 보존되는 **`.eh_frame` 섹션의 FDE(`Frame Description Entry`, `pc_begin..pc_end`) 테이블 및 `.dynsym` 진입 함수 내부의 `bl <target>`(`aarch64`) / `callq <target>`(`x86_64`) 분기 타겟 주소**를 스캔하여 로컬 심볼 테이블 없이도 내부 Stripped 함수 오프셋(`libcrypto_mock.so+0x...`)을 100% 자동으로 찾아내어 `uprobe`를 부착합니다.

### Iteration 7 — 깊이 6/8 유저 함수(`LAYER_USER_FUNC, call_depth=6/8`)와 `OSI_L5_SYSCALL_MEM(6)` / `OSI_L6_PRE_COMPUTE(8)` 간 충돌 및 `parent_tid` 훼손 결함
- **발굴된 설계 결함**: `call_depth` 1바이트 필드를 유저 호출 깊이(`0..15`)와 세부 계층 ID(`2,3,4,5,6,8`)로 겸용할 때, 만약 `OSI_L6_PRE_COMPUTE(8)`를 `layer_type = LAYER_USER_FUNC(4)`로 방출하면 호출 깊이 8인 실제 유저 함수와 구분할 수 없습니다. 또한 `uretprobe`에서 `fn_off_cpu_ns`를 전달하기 위해 `parent_tid`를 덮어쓰면 `TEST-04`의 스레드 핸드오프 계보(`parent_tid == waker_tid`)가 파괴됩니다.
- **방치 시 런타임 장애**: 호출 깊이 6 또는 8인 유저 함수가 각각 `L5_SYSCALL_MEM` 또는 `L6_PRE_COMPUTE` 커널 이벤트로 오분류되어 콜 그래프가 깨지며, 워커 스레드 핸드오프 추적이 실패합니다.
- **아키텍처 재설계 해결책**:
  - **Disjoint `(layer_type, call_depth)` 직교 인코딩 규칙**: `layer_type == LAYER_USER_FUNC (4)`는 **오직 `uprobe`/`uretprobe` 유저 함수(`OSI_L7_APP`) 전용**으로 격리하여 `call_depth`가 항상 순수 호출 깊이(`0..15`)만 의미하도록 고정합니다. `OSI_L5_SYSCALL_MEM (6)`과 `OSI_L6_PRE_COMPUTE (8)` 이벤트는 반드시 **`layer_type = LAYER_USER_ENTRY (3)`** (또는 송신 시 `LAYER_USER_EXIT (5)`)으로 방출합니다.
  - `parent_tid`는 전 계층에서 오직 `waker_tid` 보존에만 사용합니다. 유저 함수 실행 도중(`call_depth > 0`) 발생하는 모든 Off-CPU 구간(`sched_switch`에서 `args->prev_pid == tid`로 빠져나간 뒤 `args->next_pid == tid`로 복귀할 때의 `now - ctx->off_cpu_enter_ts` 및 `block_rq_complete`의 `now - bio->issue_ts`)마다 즉시 `layer_type = LAYER_USER_ENTRY (3)`, `call_depth = OSI_L6_PRE_COMPUTE (8)`(또는 `OSI_L5_SYSCALL_MEM (6)`) 이벤트를 방출하여, 유저 영역(`tracer_agent.py`)이 함수의 `[t_entry, t_return]` 구간 내에 발생한 직접 대기 이벤트들의 합(`fn_off_cpu_ns`)을 `total_fn_duration_ns`에서 차감함으로써 `pure_on_cpu_compute_ms`와 `off_cpu_io_wait_ms`를 100% 무손실로 분리합니다.

### Iteration 8 — 타겟 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 심볼/트레이스포인트 필드 불일치, `kfree_skb` 정상 해제 오탐, `tcp_retransmit_skb` 이중 엔디안 변환 및 512B BPF 스택 초과 결함
- **발굴된 설계 결함**: ① `tcp_transmit_skb`는 인라인되어 `/proc/kallsyms`에 없으며, `exceptions:page_fault_user`는 x86 전용입니다. ② `tracepoint:skb:kfree_skb`([`skb.h:24`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24), [`dropreason-core.h:129`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h#L129))는 정상 소비(`SKB_CONSUMED = 1`)나 미지정(`SKB_DROP_REASON_NOT_SPECIFIED = 2`) 시에도 호출될 수 있어 무조건 드롭으로 집계하면 정상 패킷도 드롭(`skb_drops > 0`)으로 오탐됩니다. ③ `tracepoint:tcp:tcp_retransmit_skb`([`tcp.h:49-57`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L49-L57))는 커널 `TP_fast_assign` 내부에서 이미 `ntohs()`를 수행해 `args->sport`/`args->dport`를 호스트 바이트 오더로 저장하며 `args->saddr`/`daddr`는 `u8[4]` 배열입니다. ④ `tracepoint:block:block_rq_complete`([`block.h:124`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L124))에는 `args->bytes` 필드가 없고 `args->nr_sector`만 존재하며, `sched_process_fork`([`sched.h:378`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L378))는 `args->parent_pid`/`args->child_pid` 필드를 노출합니다. ⑤ `sizeof(struct tid_ctx_t) > 400B`를 BPF 스택에 선언하면 512B 한계를 즉시 초과합니다.
- **방치 시 런타임 장애**: BPF 로드 실패, Verifier 512B 스택 초과, 트레이스포인트 구조체 멤버 컴파일 에러, 또는 정상 요청에서 `skb_drops > 0` 오탐으로 인한 `TEST-12` 실패가 발생합니다.
- **아키텍처 재설계 해결책**:
  - 실제 커널 심볼(`__tcp_transmit_skb`, `handle_mm_fault`, `skb_copy_datagram_iovec`, `ip_output` `PARM3=skb`, `unix_stream_recvmsg` `PARM1=sock->sk` 및 `unix_sk(sk)->peer` 정규화)로 정확히 매핑합니다.
  - `kfree_skb`에서는 반드시 **`args->reason > SKB_DROP_REASON_NOT_SPECIFIED (2)`** 일 때만 실제 패킷 드롭(`FLAG_SKB_DROP`)으로 집계하고, `tcp_retransmit_skb`에서는 `args->sport`/`args->dport`를 재변환 없이 호스트 오더 그대로 비교하며 `*(__be32 *)args->saddr`로 IP를 읽습니다.
  - `block_rq_insert` 및 `block_rq_issue` 양쪽에서 `inflight_bio_map[{args->dev, args->sector}]`를 등록하고 `block_rq_complete`에서는 `args->nr_sector * 512`(또는 `bio->bytes`)로 바이트를 계산합니다.
  - `BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)` 스크래치 맵을 통해 BPF 스택 사용량을 `0B`로 유지합니다.

### Iteration 9 — 유저 영역 `tracer_agent.py`에서 `LAYER_USER_EXIT` 직후 조기 트레이스 플러시로 인한 `LAYER_EGRESS_NIC` 누락 및 멀티코어 타임스탬프 역전 결함
- **발굴된 설계 결함**: `tcp_sendmsg`(`LAYER_USER_EXIT`) 이후 커널의 `__tcp_transmit_skb` → `ip_output` → `net_dev_queue` → `net_dev_xmit`(`LAYER_EGRESS_NIC`)는 비동기/SoftIRQ로 실행되며, 멀티코어 RingBuf 폴링 시 이벤트 도착 순서가 미세하게 섞일 수 있습니다.
- **방치 시 런타임 장애**: `LAYER_USER_EXIT`를 보자마자 트레이스를 종료하면 Layer 6(`LAYER_EGRESS_NIC`)가 유실되어 `symmetric_io_verified`가 `False`가 되며, 반대로 `LAYER_EGRESS_NIC`만 무한정 기다리면 특정 가상 인터페이스에서 영구 대기(Hang)합니다.
- **아키텍처 재설계 해결책**:
  - **Per-`req_id` Completion State Machine & Grace Window**: `STAGE_SEEN_EXIT` 상태 진입 후 `LAYER_EGRESS_NIC`(`OSI_L2_DATALINK`) 이벤트가 도착하면 즉시 완료 처리하되, 도착하지 않더라도 **`50ms` Grace Window 타임아웃** 후 안전하게 플러시합니다.
  - 수집된 각 `req_id`의 이벤트 리스트를 분석 전에 **`(timestamp, layer_order, is_return)` 기준으로 결정론적 정렬(Canonical Sort)**하여 멀티코어 간 타임스탬프 미세 역전을 완벽히 보정합니다.

### Iteration 10 — 단일 스레드 HTTP 서버 블로킹 및 외부 트래픽 부재 시 `POST /api/v1/traces` / `ebpf_capture_trace` 무한 대기 교착(Deadlock) 결함
- **발굴된 설계 결함**: 파이썬 기본 `HTTPServer`는 단일 스레드이므로 캡처 도중 상태 조회나 SSE 요청이 들어오면 블로킹되며, 자동화 테스트(`TEST-11`)가 `POST /api/v1/traces`나 MCP `ebpf_capture_trace`를 호출했을 때 외부에서 패킷을 쏴주지 않으면 RingBuf 폴링이 무한 대기합니다.
- **방치 시 런타임 장애**: `TEST-11`에서 REST API나 MCP Tool 호출 시 타임아웃으로 테스트가 행(Hang)에 걸리거나 동시 요청 시 서버가 응답 불능에 빠집니다.
- **아키텍처 재설계 해결책**:
  - **Thread-Safe `ThreadingHTTPServer` + Self-Contained Loopback Traffic Trigger**: 내장 웹/REST 서버를 `http.server.ThreadingHTTPServer`와 `threading.RLock()` 기반으로 설계하고, `ebpf_capture_trace` 및 `POST /api/v1/traces` 호출 시 백그라운드 루프백 클라이언트 트리거(타겟 포트로 실제 테스트 HTTP 패킷 자동 송신, 또는 `simulate`/비특권 환경일 때 실제 ELF/DWARF/디스어셈블리 테이블을 파싱한 결정론적 파이프라인 실행)를 내장하여 **최대 `500ms` 이내에 무블로킹 응답**을 보장합니다.

---

# PART 3. 컴포넌트별 상세 기술 명세서 (Component-Level Technical Blueprint)

## 3.1 공유 64바이트 이진 텔레메트리 프로토콜 (`struct kray_event_t`) & 동적 설정 구조체 (`struct kray_runtime_cfg_t`)

커널 영역(`tracer_kernel.c`)과 유저 영역(`tracer_agent.py`의 `ctypes.Structure`)은 암묵적 컴파일러 패딩으로 인한 오프셋 어긋남을 원천 차단하기 위해 아래의 **정확히 64바이트(`sizeof == 64`)로 정렬된 Packed 이벤트 구조체**와 **16바이트 동적 런타임 설정 구조체**를 공유해야 합니다.

### 3.1.1 C 구조체 정의 (`tracer_kernel.c`)
```c
enum kray_layer_e {
    LAYER_INGRESS_NIC = 1,
    LAYER_KERNEL_NET  = 2,
    LAYER_USER_ENTRY  = 3,
    LAYER_USER_FUNC   = 4,
    LAYER_USER_EXIT   = 5,
    LAYER_EGRESS_NIC  = 6
};

// Granular OSI & Pre-Compute Sub-Layer Identifier (Encoded in call_depth for Network/Socket/Syscall/Sched Events)
enum kray_osi_layer_e {
    OSI_L2_DATALINK    = 2,  // NIC DMA / XDP / netif_receive_skb / Qdisc / net_dev_xmit
    OSI_L3_IP          = 3,  // IPv4 Routing & Netfilter (ip_rcv / ip_output)
    OSI_L4_TCP         = 4,  // Transport Layer (tcp_v4_rcv / __tcp_transmit_skb / tcp_retransmit_skb / kfree_skb)
    OSI_L4_SOCKET      = 5,  // Socket Buffer Queue (sk_rcvbuf tcp_recvmsg / sk_sndbuf tcp_sendmsg)
    OSI_L5_SYSCALL_MEM = 6,  // Syscall / skb_copy_datagram_iovec / handle_mm_fault / block_rq_issue
    OSI_L7_APP         = 7,  // Compute Unit (ALU) On-CPU User Function & Stripped .so Execution
    OSI_L6_PRE_COMPUTE = 8   // Pre-Compute Gate: Futex Lock + CPU Runqueue (sched_wakeup->sched_switch) + Core Dispatch
};

enum kray_flags_e {
    FLAG_NONE            = 0x00,
    FLAG_THREAD_HANDOFF  = 0x01,  // Event occurred after cross-thread wakeup/fork handoff
    FLAG_STRIPPED_SYMBOL = 0x02,  // Target address belongs to stripped binary/library
    FLAG_TCP_RETRANSMIT  = 0x04,  // TCP packet retransmission detected (tracepoint:tcp:tcp_retransmit_skb)
    FLAG_SKB_DROP        = 0x08,  // Kernel packet drop detected (tracepoint:skb:kfree_skb)
    FLAG_TCP_SYN         = 0x10,  // L4 TCP SYN flag observed
    FLAG_TCP_ACK         = 0x20,  // L4 TCP ACK flag observed
    FLAG_TCP_PSH         = 0x40,  // L4 TCP PSH flag observed
    FLAG_TCP_FIN         = 0x80   // L4 TCP FIN flag observed
};

// Hot-Reloadable Runtime Configuration Map Value (16 Bytes, Zero Recompile)
struct __attribute__((packed)) kray_runtime_cfg_t {
    u32 target_pid;       // [Bytes 0..3]   Dynamic target TGID (falls back to __TARGET_PID__ if 0)
    u16 target_port;      // [Bytes 4..5]   Dynamic target port in host byte order (0 = All ports 0..65535)
    u8  capture_enabled;  // [Byte  6]      1: Active, 0: Paused
    u8  filter_flags;     // [Byte  7]      [Bits 0..3]: Proto mask (0=All,1=TCP,2=UDP,4=ICMP/ARP,8=UNIX/TLS); [Bits 4..7]: OSI layer mask (0=All)
    u64 config_epoch;     // [Bytes 8..15]  Monotonic version counter incremented on REST/MCP update
}; // Total Size: Exactly 16 Bytes

// Shared 64-Byte Telemetry Event Record
struct __attribute__((packed)) kray_event_t {
    u64 req_id;        // [Bytes 0..7]   Unique 64-bit correlated request ID
    u64 ip;            // [Bytes 8..15]  User/Kernel Instruction Pointer (or encoded pkt_len/cpu_id/hook metadata)
    u64 timestamp;     // [Bytes 16..23] bpf_ktime_get_ns() monotonic nanoseconds
    u64 duration_ns;   // [Bytes 24..31] Stage delta, runqueue latency, block I/O wait, or function duration in ns
    u32 pid;           // [Bytes 32..35] Process ID (TGID in Linux kernel terminology)
    u32 tid;           // [Bytes 36..39] Thread ID (PID in Linux kernel terminology)
    u32 parent_tid;    // [Bytes 40..43] Dispatcher/Waker TID if handed off across threads (0 otherwise)
    u32 src_ip;        // [Bytes 44..47] IPv4 Source Address (network byte order)
    u32 dst_ip;        // [Bytes 48..51] IPv4 Destination Address (network byte order)
    u16 src_port;      // [Bytes 52..53] Source Port (host byte order)
    u16 dst_port;      // [Bytes 54..55] Destination Port (host byte order)
    u8  layer_type;    // [Byte  56]     1..6 (enum kray_layer_e)
    u8  is_return;     // [Byte  57]     0: Entry / Point Event, 1: Function Return (uretprobe)
    u8  call_depth;    // [Byte  58]     User call depth (0..15) ONLY when layer_type==LAYER_USER_FUNC; OSI layer (2,3,4,5,6,8) when layer_type!=LAYER_USER_FUNC
    u8  flags;         // [Byte  59]     Bitmask (enum kray_flags_e: Handoff/Stripped/Retransmit/Drop + TCP flags)
    u32 drop_count;    // [Bytes 60..63] Cumulative ring-buffer drop counter snapshot
}; // Total Size: Exactly 64 Bytes
```

### 3.1.2 Python `ctypes` 구조체 매핑 (`tracer_agent.py`)
```python
class KrayRuntimeConfig(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("target_pid", ctypes.c_uint32),       # Offset 0
        ("target_port", ctypes.c_uint16),      # Offset 4
        ("capture_enabled", ctypes.c_uint8),   # Offset 6
        ("filter_flags", ctypes.c_uint8),      # Offset 7
        ("config_epoch", ctypes.c_uint64),     # Offset 8
    ]
assert ctypes.sizeof(KrayRuntimeConfig) == 16

class KrayEvent(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("req_id", ctypes.c_uint64),       # Offset 0
        ("ip", ctypes.c_uint64),           # Offset 8
        ("timestamp", ctypes.c_uint64),    # Offset 16
        ("duration_ns", ctypes.c_uint64),  # Offset 24
        ("pid", ctypes.c_uint32),          # Offset 32
        ("tid", ctypes.c_uint32),          # Offset 36
        ("parent_tid", ctypes.c_uint32),   # Offset 40
        ("src_ip", ctypes.c_uint32),       # Offset 44
        ("dst_ip", ctypes.c_uint32),       # Offset 48
        ("src_port", ctypes.c_uint16),     # Offset 52
        ("dst_port", ctypes.c_uint16),     # Offset 54
        ("layer_type", ctypes.c_uint8),    # Offset 56
        ("is_return", ctypes.c_uint8),     # Offset 57
        ("call_depth", ctypes.c_uint8),    # Offset 58
        ("flags", ctypes.c_uint8),         # Offset 59
        ("drop_count", ctypes.c_uint32),   # Offset 60
    ]
assert ctypes.sizeof(KrayEvent) == 64
```

### 3.1.3 `(layer_type, call_depth)` 직교(Disjoint) 인코딩 규칙 및 `ip`/`duration_ns` 비트 패킹 레이아웃
64바이트 `struct kray_event_t`의 고정 ABI를 유지하면서 호출 깊이 6/8인 유저 함수와 `OSI_L5_SYSCALL_MEM(6)`/`OSI_L6_PRE_COMPUTE(8)` 커널 이벤트 간 충돌을 원천 차단하고, `parent_tid`(`waker_tid`)를 훼손하지 않기 위해 다음 **직교(Disjoint) 인코딩 규칙**을 엄격히 준수합니다:

1. **`(layer_type, call_depth)` 상호 배타성 원칙**:
   - **`layer_type == LAYER_USER_FUNC (4)`**는 **오직 유저 함수(`uprobe`/`uretprobe`, `OSI_L7_APP`) 전용**으로만 사용하며, 이 경우 `call_depth`는 항상 **순수 함수 호출 스택 깊이(`0..15`)**를 나타냅니다.
   - 반대로 모든 커널 네트워크·소켓·메모리·블록 I/O·스케줄러 게이트 이벤트(`OSI_L2_DATALINK=2`, `OSI_L3_IP=3`, `OSI_L4_TCP=4`, `OSI_L4_SOCKET=5`, `OSI_L5_SYSCALL_MEM=6`, `OSI_L6_PRE_COMPUTE=8`)는 **`layer_type != LAYER_USER_FUNC`**(`1, 2, 3, 5, 6`)으로만 방출합니다. 특히 `OSI_L5_SYSCALL_MEM (6)`과 `OSI_L6_PRE_COMPUTE (8)`는 **`layer_type = LAYER_USER_ENTRY (3)`** (또는 송신 시 `LAYER_USER_EXIT (5)`)으로 방출하여 깊이 6/8 유저 함수와 100% 구분합니다.
2. **계층별 `ip` 및 `duration_ns` 결정론적 비트 패킹 레이아웃**:
   - **`LAYER_USER_FUNC (4)` (`call_depth = 0..15`, `OSI_L7_APP`)**:
     - `ip`: `is_return == 0`일 때는 `PT_REGS_IP(ctx)`를 기록함과 동시에 `ctx->fn_entry_ip[depth] = PT_REGS_IP(ctx)`에 백업하고, **`is_return == 1`(`uretprobe`)일 때는 트램펄린 주소 오염을 막기 위해 반드시 백업된 `ctx->fn_entry_ip[depth]`를 `ev->ip`에 기록**합니다.
     - `duration_ns`: `is_return == 0`일 때는 진입 시점의 스레드 누적 Off-CPU 대기 시간 스냅샷(`ctx->fn_off_cpu_snap[depth] = ctx->acc_off_cpu_ns`)을 담아 방출하고, `is_return == 1`일 때는 함수 총 실행 시간(`total_fn_duration_ns = now - ctx->fn_entry_ts[depth]`)을 담습니다. 또한 함수 실행 도중(`ctx->call_depth > 0`) 스레드가 Sleep/Preemption(`sched_switch` `args->prev_pid == tid` → `args->next_pid == tid`) 또는 Block I/O(`block_rq_complete`)를 겪을 때마다 커널이 즉시 `OSI_L6_PRE_COMPUTE (8)` / `OSI_L5_SYSCALL_MEM (6)` (`layer_type = LAYER_USER_ENTRY (3)`) 대기 이벤트를 방출하므로, 유저 영역(`tracer_agent.py`)은 `parent_tid`를 전혀 건드리지 않고도 함수의 `[t_entry, t_return]` 구간 내 직접 발생한 대기 이벤트 `duration_ns` 합계(`fn_off_cpu_ns`, 하위 중첩 함수 구간 제외)를 `total_fn_duration_ns`에서 차감하여 `pure_on_cpu_compute_ms`와 `off_cpu_io_wait_ms`를 100% 결정론적으로 분리합니다.
     - `parent_tid`: 항상 스레드 핸드오프를 일으킨 `ctx->parent_tid`(`waker_tid`)를 그대로 유지합니다 (`TEST-04` 무결성 보장).
   - **`OSI_L2_DATALINK` (`layer_type = 1 or 6`, `call_depth = 2`)**:
     - `ip`: `((u64)rx_or_tx_cpu_id << 32) | ((u64)(rc & 0xffff) << 16) | (u64)pkt_len`
     - `duration_ns`: Ingress는 L2 처리 시간, Egress는 **Qdisc 큐 대기 시간(`qdisc_delay_ns = now - state->qdisc_enq_ts`)**
   - **`OSI_L3_IP` (`layer_type = 2 or 6`, `call_depth = 3`) & `OSI_L4_TCP` (`layer_type = 2 or 6`, `call_depth = 4`)**:
     - `ip`: `((u64)ttl << 24) | ((u64)ihl_bytes << 16) | (u64)pkt_len`
     - `duration_ns`: 이전 계층 대비 홉 지연 시간($\Delta t_{\text{L3}}$, $\Delta t_{\text{L4}}$)
   - **`OSI_L4_SOCKET` (`layer_type = 3 or 5`, `call_depth = 5`, `kprobe/kretprobe:tcp_recvmsg` / `kprobe:tcp_sendmsg`)**:
     - `ip`: `(u64)pkt_len` (소켓 `kretprobe:tcp_recvmsg` 실제 수신 바이트 수 `int copied = PT_REGS_RC(ctx)` 또는 `tcp_sendmsg` 송신 바이트 수 `size`)
     - `duration_ns`: **소켓 버퍼 체류 시간(`sk_rcvbuf` dwell = `now - state->tcp_rcv_ts`, `sk_sndbuf` dwell = `now - state->sendmsg_ts`)**
   - **`OSI_L5_SYSCALL_MEM` (`layer_type = 3 or 5`, `call_depth = 6`, `skb_copy_datagram_iovec` + `kretprobe:skb_copy_datagram_iter` / `handle_mm_fault` / `block_rq_complete`)**:
     - `ip`: `((u64)ctx->page_faults << 32) | (u64)copied_or_bio_bytes`
     - `duration_ns`: 커널↔유저 실제 메모리 복사 소요 시간(`now - ctx->copy_enter_ts`, `simple_copy_to_iter` 및 페이지 폴트 완료 후 측정) 또는 비동기 스토리지 Block I/O 대기 시간(`now - bio->issue_ts`)
   - **`OSI_L6_PRE_COMPUTE` (`layer_type = LAYER_USER_ENTRY (3)`, `call_depth = 8`, `sched_switch` On-CPU Dispatch 직전)**:
     - `ip`: `((u64)(lock_wait_ns > 0xffffffffULL ? 0xffffffffULL : lock_wait_ns) << 16) | (((u64)ctx->prev_cpu_id & 0xff) << 8) | ((u64)ctx->target_cpu_id & 0xff)` (하위 16비트에 `prev_cpu_id -> target_cpu_id` 코어 마이그레이션 인코딩, 상위 비트에 오버플로우 방지 마스킹된 Futex 락 대기 시간 `lock_wait_ns` 인코딩)
     - `duration_ns`: **유저 함수 진입 전(`ctx->call_depth == 0`)에는 순수 CPU 런큐 대기 시간(`runq_ns = ctx->wakeup_ts ? (now - ctx->wakeup_ts) : 0`), 유저 함수 실행 도중(`ctx->call_depth > 0`)에는 전체 Off-CPU Sleep+Runqueue 대기 시간(`total_off_cpu_ns = ctx->off_cpu_enter_ts ? (now - ctx->off_cpu_enter_ts) : runq_ns`)을 기록하며 방출 직후 `ctx->off_cpu_enter_ts = 0; ctx->wakeup_ts = 0; ctx->futex_enter_ts = 0;`으로 즉시 리셋**

---

## 3.2 커널 영역: Map-Driven & CO-RE 호환 7-Layer (Wire-to-PreCompute-to-ALU) 수집기 (`tracer_kernel.c`)

### 3.2.1 Dual-Mode 설정 메커니즘, Rocky 9.8 `aarch64` CO-RE 가드 & Universal Symbol Auto-Resolver
1. **컴파일 타임 기본값 토큰 + 런타임 Hot-Reload**: `__TARGET_PID__`, `__TARGET_PORT__`, `__NET_IFACE__`를 기본 상수로 정의하되, 커널 함수 진입 시 `runtime_config_map[0]`을 먼저 조회하여 `cfg->target_pid != 0` 또는 `cfg->target_port != 0`이면 **재컴파일 없이 맵의 동적 설정값을 우선 사용**합니다 (`target_port == 0`인 Wildcard 모드일 때는 포트(`0~65535`) 전체 트래픽 허용).
2. **Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) BTF & BPF CO-RE 호환 설계**:
   - `#ifdef KRAY_BPF_CORE` 분기를 통해 레퍼런스 디렉토리에 다운로드된 [`references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h) 및 [`bpf/bpf_tracing.h`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_tracing.h), [`bpf/bpf_core_read.h`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_core_read.h) 환경과 **BCC Python 환경** 양쪽에서 모두 컴파일 가능하도록 매크로 추상화 레이어를 제공합니다. 특히 시스템콜 트레이스포인트(`sys_enter_futex`, `sys_enter_read`, `sys_enter_write`)의 경우 [`vmlinux.h:119889`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119889)에 정의된 CO-RE 구조체는 `struct trace_event_raw_sys_enter { unsigned short common_type; ... long int id; long unsigned int args[6]; };` 형태이므로 **`#ifdef KRAY_BPF_CORE`에서는 `(u32)ctx->args[1] & 0x7f`, BCC `TRACEPOINT_PROBE(syscalls, sys_enter_futex)`에서는 `(u32)args->op & 0x7f`** 로 접근하도록 이중 호환 매크로를 제공합니다.
   - 타겟 아키텍처인 `aarch64`의 `struct user_pt_regs` 레지스터(`regs[0..7]`) 매핑을 위해 `#if defined(__aarch64__) || !defined(__x86_64__)`일 때 **`#define __TARGET_ARCH_arm64`** (x86_64 호스트 폴백 시 `#define __TARGET_ARCH_x86`)를 명시합니다 ([`bpf_tracing.h:199-224`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_tracing.h#L199-L224) 근거).
3. **범용 런타임 심볼 자동 해석기 (Universal Runtime Symbol Auto-Resolver) & 플러그형 프로토콜 어댑터**:
   - 유저 영역(`tracer_agent.py`) 초기화 시 `/proc/kallsyms` 및 `/sys/kernel/tracing/events`를 스캔하여, Rocky 9.8(`5.14.0-687.10.1.el9_8.0.1.aarch64`)뿐만 아니라 타 배포판/커널 버전에서도 훅이 100% 안전하게 부착되도록 자동 바인딩합니다:
     - **L4 TCP 송신 훅**: `/proc/kallsyms`에 `__tcp_transmit_skb`가 존재하면 우선 부착(Rocky 9.8 기본)하고, 없을 경우 `tcp_transmit_skb`로 자동 폴백.
     - **L5 페이지 폴트 훅**: `/sys/kernel/tracing/events/exceptions/page_fault_user`가 존재하면 Tracepoint로 부착(`x86_64`)하고, 없을 경우 `kprobe:handle_mm_fault`로 자동 부착(`aarch64` Rocky 9.8 기본).
     - **가변 프로토콜 어댑터(`--proto`)**: `TCP`(`tcp_v4_rcv`/`tcp_v6_rcv`/`tcp_recvmsg`+`kretprobe`/`tcp_sendmsg`+`kretprobe`), `UDP`(`udp_rcv`/`udp_recvmsg`+`kretprobe`/`udp_sendmsg`), `IPv4`(`ip_rcv`/`ip_output`), `IPv6`(`ipv6_rcv`/`ip6_output`), `ICMP`(`icmp_rcv`), `ARP`(`arp_rcv`), `UNIX`(`unix_stream_recvmsg`/`unix_stream_sendmsg`), `TLS`(`uprobe:libssl.so:SSL_read`/`SSL_write`) 어댑터를 선택적/통합적으로 부착하고, 모든 프로토콜 이벤트를 동일한 불변 코어(`L5 -> L6 Pre-Compute Gate -> L7 ALU`)로 합류시킵니다.

### 3.2.2 eBPF 맵 아키텍처 (`runtime_config_map`, `BPF_LRU_HASH` 6종, `BPF_PERCPU_ARRAY`, `BPF_RINGBUF_OUTPUT`)
```c
#define MAX_CALL_DEPTH 16

struct flow_key_t {
    u32 saddr;         // IPv4 addr / folded IPv6 hash / AF_UNIX local sk low32
    u32 daddr;         // IPv4 addr / folded IPv6 hash / AF_UNIX peer sk low32
    u16 sport;         // Source port (host order) or ICMP (type<<8)|code
    u16 dport;         // Dest port (host order) or ICMP echo_id / 0 for AF_UNIX
    u8  proto;         // IPPROTO_TCP(6), IPPROTO_UDP(17), IPPROTO_ICMP(1), 0xFE(ARP), 0xFF(AF_UNIX)
    u8  family;        // AF_INET(2), AF_INET6(10), AF_UNIX(1)
    u16 pad;           // Explicit zero-padding for 16-byte verifier alignment (sizeof == 16)
};

struct flow_state_t {
    u64 req_id;
    u64 xdp_ts;        // L2 Ingress timestamp (xdp_ingress_filter / netif_receive_skb)
    u64 ip_rcv_ts;     // L3 Ingress timestamp (kprobe:ip_rcv)
    u64 tcp_rcv_ts;    // L4 Ingress timestamp (kprobe:tcp_v4_rcv)
    u64 sendmsg_ts;    // L4.5 Socket Egress timestamp (kprobe:tcp_sendmsg)
    u64 tcp_tx_ts;     // L4 TCP Egress timestamp (kprobe:__tcp_transmit_skb)
    u64 ip_out_ts;     // L3 IP Egress timestamp (kprobe:ip_output)
    u64 qdisc_enq_ts;  // L2 Qdisc Enqueue timestamp (tracepoint:net:net_dev_queue)
    u32 pid;
    u32 tid;
    u16 pkt_len;       // Wire packet byte length
    u8  tcp_flags;     // Observed TCP flags (SYN/ACK/PSH/FIN)
    u8  retransmits;   // Retransmit count for this flow
    u8  rx_cpu_id;     // Physical CPU core handling L2/L4 SoftIRQ
    u8  consumed;      // 1 once tcp_recvmsg consumes this req_id (prevents 0-byte ACK overwrite / duplicate re-bind)
};

struct tid_ctx_t {
    u64 req_id;
    u64 last_stage_ts;
    u64 futex_enter_ts;     // L6 Pre-Compute: sys_enter_futex lock wait start timestamp
    u64 wakeup_ts;          // L6 Pre-Compute: sched:sched_wakeup timestamp (for runqlat = t_switch - t_wakeup)
    u64 off_cpu_enter_ts;   // L6/L7 Off-CPU: sched_switch (prev_pid == tid) timestamp while in user function
    u64 acc_off_cpu_ns;     // Cumulative Off-CPU sleep/preemption/I/O wait ns for this thread
    u64 acc_block_io_ns;    // Cumulative Block I/O wait ns (block_rq_issue -> block_rq_complete)
    u64 copy_enter_ts;      // L5 MM/SKB: skb_copy_datagram_iter entry timestamp (before simple_copy_to_iter)
    u64 active_sk_ptr;      // L4.5 Socket: Stashed struct sock *sk across blocking sk_wait_data() -> kretprobe__tcp_recvmsg
    u64 active_msg_name;    // L4.5 UDP Socket: Stashed msg->msg_name across udp_recvmsg -> kretprobe__udp_recvmsg
    u32 pid;
    u32 tid;
    u32 parent_tid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 page_faults;        // L5 MM: Count of handle_mm_fault / mm_page_alloc events
    u16 copied_bytes;       // L5 SKB: Accumulated bytes in skb_copy_datagram_iovec / skb_copy_datagram_iter
    u8  prev_cpu_id;        // L6 Pre-Compute: Previous CPU core ID before sched_switch
    u8  target_cpu_id;      // L6 Pre-Compute: Dispatched CPU core ID on sched_switch
    u8  call_depth;
    u8  flags;
    u8  in_target_sendmsg;  // 1 while inside server-socket tcp_sendmsg (guards kretprobe__tcp_sendmsg context teardown)
    u8  pad_ctx[1];
    u64 fn_entry_ip[MAX_CALL_DEPTH];      // Per-depth uprobe entry IP (prevents uretprobe [uprobes] trampoline IP corruption!)
    u64 fn_entry_ts[MAX_CALL_DEPTH];      // Per-depth uprobe entry timestamp
    u64 fn_off_cpu_snap[MAX_CALL_DEPTH];  // Per-depth snapshot of acc_off_cpu_ns to prevent nested double-counting
};

struct handoff_slot_t {
    u64 req_id;        // Active request ID queued by dispatcher thread (TID A)
    u64 wakeup_ts;     // Timestamp when work was queued / FUTEX_WAKE issued
    u32 waker_tid;     // Dispatcher thread ID (TID A)
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  prev_cpu_id;
    u8  claimed;       // 0: Pending claim by worker thread, 1: Claimed
};

struct handoff_ring_t {
    u32 write_idx;     // Monotonic producer index (masked with & 7)
    u32 read_idx;      // Monotonic consumer index (masked with & 7)
    struct handoff_slot_t slots[8]; // 8-slot per-TGID FIFO prevents concurrent TEST-03 requests from overwriting each other
};

struct bio_key_t {
    u32 dev;           // Block device major:minor (args->dev)
    u32 pad;
    u64 sector;        // Starting sector number (args->sector)
};

struct bio_state_t {
    u64 issue_ts;      // block_rq_insert / block_rq_issue timestamp
    u64 req_id;        // Correlated request ID
    u32 tid;           // Submitting user thread ID (preserved across Block SoftIRQ completion)
    u32 bytes;         // Request byte size
};

// 0. Hot-Reloadable Runtime Configuration Map (Zero Recompile for MCP/REST)
BPF_ARRAY(runtime_config_map, struct kray_runtime_cfg_t, 1);

// 1. Stage A (SoftIRQ Wire-to-Socket Map): Keyed by 16B Normalized Flow Key
BPF_LRU_HASH(ingress_flow_map, struct flow_key_t, struct flow_state_t, 8192);

// 2. Stage B (Process/Thread Context Map) & Already-Awake Worker Handoff Bridge:
// CRITICAL VERIFIER & READ-ONLY TEMPLATE RULE:
// sizeof(struct tid_ctx_t) > 400B, so NEVER allocate struct tid_ctx_t on the 512B BPF stack!
// Moreover, zero_ctx_map[0] MUST be treated as a strictly READ-ONLY all-zero template:
// NEVER mutate fields inside zero_ctx_map[0] before calling active_ctx_map.update(&tid, zero_template),
// or dirty fields will leak into subsequent threads initialized on the same CPU core!
// Always call active_ctx_map.update(&tid, zero_template) first, then lookup and mutate active_ctx_map.lookup(&tid) in-place.
BPF_LRU_HASH(active_ctx_map, u32, struct tid_ctx_t, 8192);
BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1);
BPF_LRU_HASH(pending_handoff_map, u32 /* tgid */, struct handoff_ring_t, 1024);

// 3. Egress Socket-to-Wire Map: Keyed by 16B Normalized Flow Key + SKB Pointer Bridge for Safe Post-Driver Xmit Lookup
BPF_LRU_HASH(egress_flow_map, struct flow_key_t, struct flow_state_t, 8192);
BPF_LRU_HASH(skb_egress_map, u64, struct flow_key_t, 8192);

// 4. Async Block I/O Correlation Map: Bridges User Thread Issue -> Block IRQ/SoftIRQ Completion
BPF_LRU_HASH(inflight_bio_map, struct bio_key_t, struct bio_state_t, 4096);

// 5. Lockless MPSC Ring Buffer (64 Pages = 256 KB) & Overflow Drop Counter
BPF_RINGBUF_OUTPUT(events, 1 << 16);
BPF_ARRAY(drop_cnt_map, u64, 1);
```

### 3.2.3 6개 매크로 Layer 및 7대 세부 계층별 필수 커널 훅 명세 (Rocky Linux 9.8 `5.14.0-687.10.1.el9_8.0.1.aarch64` 기준)

#### Layer 1 — `INGRESS_NIC` (`OSI_L2_DATALINK = 2`, NAPI SoftIRQ 컨텍스트)
- **부착 커널 훅**: `xdp_ingress_filter` (`BPF_PROG_TYPE_XDP`) + `tracepoint:net:netif_receive_skb` ([`net.h:150`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L150))
- **핵심 수행 로직 및 Verifier 안전 규칙**:
  - `void *data = (void *)(long)ctx->data; void *data_end = (void *)(long)ctx->data_end;`에서 `ethhdr` → `iphdr`(가변 헤더 길이 `ihl * 4` 검증) → `tcphdr` 순차 파싱 시 매 단계 `if ((void *)(hdr + 1) > data_end) return XDP_PASS;`를 강제합니다.
  - **[Loopback Server-Role Direction Guard]**: `u16 dport = bpf_ntohs(tcp->dest); u16 sport = bpf_ntohs(tcp->source);`에서 `target_port != 0`일 때 반드시 **`dport == target_port`** 인 서버 수신 패킷만 통과시킵니다 (`sport == target_port`인 루프백 응답 반사 패킷은 Ingress에서 즉시 `return XDP_PASS;`).
  - **[Payload-Gated `req_id` Minting]**: `u16 tcp_payload_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4) - (tcp->doff * 4);`를 계산하여, 기존 `ingress_flow_map[key]`에 아직 소비되지 않은(`consumed == 0`) `req_id`가 존재하고 현재 패킷이 `tcp_payload_len == 0`인 순수 제어 패킷(`ACK`)이면 기존 `req_id`를 덮어쓰지 않고 보존합니다.
  - **[`tracepoint:net:netif_receive_skb`의 미초기화 `skb->network_header` 회피(`skb->data` 직접 읽기) 및 양방향(Bidirectional) L2 중복 방출 방지 가드]**: 커널 [`net/core/dev.c:5606-5626`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/dev.c#L5606-L5626)의 `__netif_receive_skb_core()`를 확인하면, `trace_netif_receive_skb(skb)`(line 5606)는 **`skb_reset_network_header(skb)`(line 5610)가 호출되기 직전**에 실행되며, 또한 **Generic XDP인 `do_xdp_generic()`(line 5626)보다도 먼저 실행**됩니다! 따라서 ① `netif_receive_skb`에서는 아직 리셋되지 않은 `skb->network_header` 대신 이미 `eth_type_trans()`가 L2 이더넷 헤더를 벗겨낸 **`skb->data` 포인터(`unsigned char *data = NULL; bpf_probe_read_kernel(&data, sizeof(data), &skb->data);`)에서 직접 L3 `struct iphdr`를 읽어야** 하며, ② Native Driver XDP(`XDP_FLAGS_DRV_MODE`)에서는 `xdp_ingress_filter` → `netif_receive_skb` 순으로 실행되는 반면 Generic XDP(`XDP_FLAGS_SKB_MODE`, `lo`/`veth`)에서는 `netif_receive_skb` → `xdp_ingress_filter` 순으로 실행되므로, **`xdp_ingress_filter`와 `tracepoint:net:netif_receive_skb` 양쪽 모두에서 `state->xdp_ts != 0 && state->consumed == 0`이면 중복 `LAYER_INGRESS_NIC` 이벤트를 방출하지 않도록 양방향 중복 방지 가드**를 적용합니다.
  - `layer_type = LAYER_INGRESS_NIC (1)`, `call_depth = OSI_L2_DATALINK (2)`로 설정하여 이벤트를 방출합니다 (`bpf_get_current_pid_tgid()` 호출 금지, 반환값은 항상 `XDP_PASS`).

#### Layer 2 — `KERNEL_NET` (`OSI_L3_IP = 3` & `OSI_L4_TCP = 4`, SoftIRQ 컨텍스트)
- **부착 커널 훅**: `kprobe__ip_rcv` ([`ip_input.c:552`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552)), `kprobe__tcp_v4_rcv` ([`tcp_ipv4.c:1945`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1945)), `tracepoint:tcp:tcp_retransmit_skb` ([`tcp.h:35`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L35)), `tracepoint:skb:kfree_skb` ([`skb.h:24`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L24))
- **핵심 수행 로직 및 오프셋·엔디안 산출 규칙**:
  - **L3 (`kprobe__ip_rcv` / `kprobe__ipv6_rcv`) — [`bpf_probe_read_kernel` 강제 및 미초기화 `skb->transport_header` 사용 금지]**: `BPF_PROG_TYPE_KPROBE`에서는 `skb->head`가 비신뢰 커널 포인터이므로 직접 역참조 시 Verifier가 거부(`R1 invalid mem access 'scalar'`)합니다. 반드시 `unsigned char *head = NULL; u16 net_off = 0; bpf_probe_read_kernel(&head, sizeof(head), &skb->head); bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);` 후 `bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);`로 읽어야 합니다. 또한 `ip_rcv` 진입 시점에는 `skb->transport_header`가 미초기화 상태이므로 **`u16 trans_off = net_off + ((iph.ihl & 0x0f) * 4); bpf_probe_read_kernel(&tcph, sizeof(tcph), head + trans_off);`** (IPv6 `kprobe__ipv6_rcv` [`ip6_input.c:302`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L302)에서는 `ip6_rcv_core()` 실행 전이므로 `u16 trans_off = net_off + sizeof(struct ipv6hdr);`)로 L4 포트를 추출합니다. `dport == target_port` 확인 후 `state->ip_rcv_ts = now`, `layer_type = LAYER_KERNEL_NET (2)`, `call_depth = OSI_L3_IP (3)` 이벤트를 방출합니다.
  - **L4 (`kprobe__tcp_v4_rcv`)**: `PT_REGS_PARM1(ctx) = skb`에서 `bpf_probe_read_kernel`로 헤더 추출 및 `dport == target_port` 검증 후 `ingress_flow_map.lookup(&key)`를 조회합니다(XDP 미경유 루프백 패킷이거나 이전 요청이 `consumed == 1`이고 `tcp_payload_len > 0`인 신규 요청이면 새 `req_id` 생성 및 `consumed = 0` 초기화). `duration_ns = now - state->ip_rcv_ts`, `state->tcp_rcv_ts = now`, `layer_type = LAYER_KERNEL_NET (2)`, `call_depth = OSI_L4_TCP (4)` 이벤트를 방출합니다.
  - **TCP 양방향 재전송 (`tracepoint:tcp:tcp_retransmit_skb`) & 패킷 드롭 (`tracepoint:skb:kfree_skb`) 3단계 플로우 조회**:
    - [`include/trace/events/tcp.h:47-48`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/tcp.h#L47-L48)에서 `args->sport`와 `args->dport`는 커널이 이미 `ntohs()`를 적용한 **호스트 바이트 오더**이므로 절대 `bpf_ntohs()`를 중복 호출하지 않으며, IPv4 주소는 `*(__be32 *)args->saddr` / `*(__be32 *)args->daddr`로 읽습니다. 특히 서버가 응답 세그먼트를 재전송할 때는 `args->sport == target_port`(`egress_flow_map`)이고 클라이언트 요청 재전송일 때는 `args->dport == target_port`(`ingress_flow_map`)이므로 **양방향(`dport == target_port` → `ingress_flow_map`, `sport == target_port` → `egress_flow_map`)을 모두 검사**하여 `state->retransmits++` 및 `FLAG_TCP_RETRANSMIT`을 기록합니다.
    - [`include/net/dropreason-core.h:129-138`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h#L129-L138) 및 [`vmlinux.h:117515`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L117515)에서 `SKB_CONSUMED (1)` 및 `SKB_DROP_REASON_NOT_SPECIFIED (2)`는 정상 해제를 포함하므로 **`args->reason > 2`** 일 때만：① `skb_egress_map.lookup(&(u64)args->skbaddr)`(Egress 드롭), ② `args->rx_sk` 소켓 포인터, ③ `(struct sk_buff *)args->skbaddr`의 `head + network_header` 4-Tuple(`ingress_flow_map` Ingress 드롭) 3단계로 조회하여 실제 패킷 드롭(`FLAG_SKB_DROP`) 이벤트를 방출합니다.

#### Layer 3 — `USER_ENTRY` (`OSI_L4_SOCKET = 5` & `OSI_L5_SYSCALL_MEM = 6`, User Thread 컨텍스트)
- **부착 커널 훅**: `kprobe__tcp_recvmsg` & **`kretprobe__tcp_recvmsg`** ([`tcp.c:2742`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2742)), `tracepoint:syscalls:sys_enter_read`, `tracepoint:skb:skb_copy_datagram_iovec` ([`skb.h:76`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h#L76)), `kprobe__skb_copy_datagram_iter` & **`kretprobe__skb_copy_datagram_iter`** ([`datagram.c:531-537`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/datagram.c#L531-L537)), `kprobe__handle_mm_fault` ([`memory.c:5313`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/mm/memory.c#L5313))
- **핵심 수행 로직 및 정규화 규칙**:
  - **[핵심 브릿지, 루프백 서버 소켓 가드 & 블로킹 `sk_wait_data` 대응 `kprobe`+`kretprobe:tcp_recvmsg` 이중 바인딩 (`OSI_L4_SOCKET = 5`)]**:
    - `tcp_recvmsg(struct sock *sk, ...)` 진입 시 `sk->__sk_common.skc_num`(로컬 포트, 호스트 바이트 오더)이 `target_port`와 일치하는지 먼저 검사하여 **동일 호스트 루프백 클라이언트(`curl`)의 `tcp_recvmsg`를 완벽히 배제**합니다.
    - 읽기 전용 올-제로 템플릿인 `zero_ctx_map[0]`을 절대 직접 수정하지 않고 먼저 `active_ctx_map.update(&tid, zero_template)`로 초기화한 뒤 `ctx = active_ctx_map.lookup(&tid)`를 얻어 `ctx->active_sk_ptr = (u64)sk;`를 저장합니다.
    - 커널 [`net/ipv4/tcp.c:2585-2638`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2585-L2638)의 `tcp_recvmsg_locked()`를 보면, 블로킹 소켓이나 Keep-Alive 대기 중인 서버 스레드는 클라이언트 패킷이 도착하기 전에 먼저 `tcp_recvmsg`에 진입하여 `sk_wait_data()`(line 2638)에서 슬립합니다. 따라서:
      1) **선도착 패킷(Non-blocking / Epoll Ready)**: `kprobe__tcp_recvmsg` 진입 시점에 이미 `ingress_flow_map[key]`에 미소비(`state->consumed == 0`) 패킷이 존재하면 진입 즉시 `state->consumed = 1`로 마킹하고 `ctx->req_id = state->req_id`를 바인딩합니다.
      2) **블로킹 대기 패킷(`sk_wait_data` Sleep 후 수신)**: `kprobe__tcp_recvmsg` 진입 시점에 아직 패킷이 도착하지 않았다면 대기 후 패킷이 수신되어 복귀하는 **`kretprobe__tcp_recvmsg`**(`int copied = PT_REGS_RC(ctx); if (copied <= 0) return 0;`)에서 `ctx->active_sk_ptr`로 다시 `ingress_flow_map.lookup(&key)`를 조회하여 `state->consumed = 1` 마킹 및 `ctx->req_id = state->req_id` 바인딩을 완수하고, 요청 버퍼 크기(`size_t len = 4096`)가 아닌 **실제 수신된 바이트 수(`ev->ip = (u64)copied`)**와 정확한 `sk_rcvbuf` 체류 시간(`duration_ns = now - state->tcp_rcv_ts`), `layer_type = LAYER_USER_ENTRY (3)`, `call_depth = OSI_L4_SOCKET (5)` 이벤트를 방출합니다. 또한 `pending_handoff_map[tgid]`의 8-슬롯 FIFO에 `{req_id, wakeup_ts = now, waker_tid = tid, claimed = 0}` 슬롯을 게시합니다.
  - **[IPv4 / 순수 IPv6 / Dual-Stack(`::ffff:`) / 비연결 UDP / `AF_UNIX` 소켓 키 정규화]**:
    - **IPv4 및 Dual-Stack(`::ffff:a.b.c.d`)**: `sk->__sk_common`([`sock.h:155-194`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/sock.h#L155-L194))에서 `skc_daddr != 0`이면(`skc_family == AF_INET6`인 Dual-Stack IPv4-mapped IPv6 소켓 포함) `key = { .saddr = skc_daddr(Client), .daddr = skc_rcv_saddr(Server), .sport = bpf_ntohs(skc_dport)(ClientPort), .dport = skc_num(ServerPort), .proto = IPPROTO_TCP, .family = AF_INET (2) }`로 정규화하여 L2/L3/L4 IPv4 패킷 키(`AF_INET`)와 100% 일치시킵니다.
    - **순수 IPv6(`skc_family == AF_INET6 && skc_daddr == 0`)**: `skc_v6_daddr.in6_u.u6_addr32[0..3]` 및 `skc_v6_rcv_saddr.in6_u.u6_addr32[0..3]` 4개 워드를 각각 XOR 폴딩하여 `key.saddr`, `key.daddr`에 저장하고 `key.family = AF_INET6 (10)`으로 설정합니다.
    - **비연결(Unconnected) UDP 서버 소켓(`udp_recvmsg` / `udp_sendmsg`)**: `bind(8080)`만 수행한 UDP 서버 소켓은 `skc_daddr == 0`, `skc_dport == 0`이고 [`net/ipv4/udp.c:1938-1944`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1938-L1944)에서 함수 종료 직전에야 `struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;`에 클라이언트 IP/포트를 기록합니다. 따라서 `kprobe__udp_recvmsg`에서 `ctx->active_msg_name = (u64)msg->msg_name`을 저장한 뒤 **`kretprobe__udp_recvmsg`** 에서 `sin->sin_addr.s_addr` 및 `bpf_ntohs(sin->sin_port)`를 읽어 `ingress_flow_map`을 조회합니다(`msg_name == NULL`일 때는 `{ .daddr = 0, .dport = skc_num, .proto = IPPROTO_UDP }` 포트 키 폴백 사용).
    - **`AF_UNIX` 도메인 소켓 피어 정규화**: `unix_stream_sendmsg`([`af_unix.c:2053`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2053))에서는 `{ .saddr = (u32)(u64)sk, .daddr = (u32)(u64)unix_sk(sk)->peer }`, `unix_stream_recvmsg`([`af_unix.c:2733`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2733))에서는 `{ .saddr = (u32)(u64)unix_sk(sk)->peer, .daddr = (u32)(u64)sk }`로 정규화합니다.
  - **[커널→유저 메모리 복사 완료 시점 측정(`kretprobe__skb_copy_datagram_iter`) & 페이지 폴트 In-Place 집계 (`OSI_L5_SYSCALL_MEM = 6`)]**:
    - 커널 [`net/core/datagram.c:531-537`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/datagram.c#L531-L537)의 `skb_copy_datagram_iter()`를 확인하면, `trace_skb_copy_datagram_iovec(skb, len)`(line 534)은 **실제 유저 버퍼 복사 함수인 `__skb_datagram_iter(..., simple_copy_to_iter, ...)`(line 535)가 실행되기 직전**에 호출됩니다! 따라서 진입 시점(`tracepoint:skb:skb_copy_datagram_iovec` 또는 `kprobe__skb_copy_datagram_iter`)에는 `ctx->copy_enter_ts = now; ctx->copied_bytes += args->len;`만 기록하고, 실제 `simple_copy_to_iter()`가 실행되는 동안 발생하는 유저 버퍼 페이지 폴트는 `kprobe__handle_mm_fault`가 `ctx->page_faults++`로 In-Place 집계한 뒤, **복사가 완료된 직후인 `kretprobe__skb_copy_datagram_iter`(또는 선형 UDP SKB `copy_linear_skb`를 포괄하는 `kretprobe__tcp_recvmsg`/`kretprobe__udp_recvmsg`)에서 실제 복사 소요 시간(`duration_ns = now - ctx->copy_enter_ts`)과 `ev->ip = ((u64)ctx->page_faults << 32) | (u32)ctx->copied_bytes;`를 담아 `layer_type = LAYER_USER_ENTRY (3)`, `call_depth = OSI_L5_SYSCALL_MEM (6)` 단일 이벤트를 방출**합니다.

#### Layer 4 — `PRE-COMPUTE GATE & USER_FUNC` (`OSI_L6_PRE_COMPUTE = 8` & `OSI_L7_APP = 7`, Scheduler & User Thread)
- **부착 커널/유저 훅**: `tracepoint:syscalls:sys_enter_futex` & `sys_exit_futex`, `tracepoint:sched:sched_process_fork` ([`sched.h:358`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L358)), `tracepoint:sched:sched_waking` ([`sched.h:170`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L170)), `tracepoint:sched:sched_wakeup` ([`sched.h:178`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L178)), `tracepoint:sched:sched_switch` ([`sched.h:222`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L222)), `tracepoint:block:block_rq_insert` ([`block.h:238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L238)), `block_rq_issue` ([`block.h:252`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L252)), `block_rq_complete` ([`block.h:167`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L167)), `trace_uprobe_entry` / `trace_uprobe_return`
- **핵심 수행 로직**:
  - **[L6 연산장치 진입 직전 게이트 (`OSI_L6_PRE_COMPUTE = 8`)]**:
    1. **Futex 대기/깨우기 전체 Opcode 필터링 (`vmlinux.h` CO-RE `ctx->args[1]` & BCC `args->op` 호환) & 다중 요청 안전 8-슬롯 링(`handoff_ring_t`)**: `sys_enter_futex`([`futex.h:11-26`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/linux/futex.h#L11-L26))에서 `u32 cmd = (futex_op) & 0x7f;`(`#ifdef KRAY_BPF_CORE`일 때 `(u32)ctx->args[1] & 0x7f`, BCC일 때 `(u32)args->op & 0x7f`)가 대기 연산(`FUTEX_WAIT=0`, `FUTEX_WAIT_BITSET=9`, `FUTEX_LOCK_PI=6`, `FUTEX_WAIT_REQUEUE_PI=11`)일 때만 `futex_enter_ts = now`를 기록하고, 깨우기/재큐잉 연산(`FUTEX_WAKE=1`, `FUTEX_WAKE_BITSET=10`, `FUTEX_REQUEUE=3`, `FUTEX_CMP_REQUEUE=4`, `FUTEX_WAKE_OP=5`, `FUTEX_UNLOCK_PI=7`, `FUTEX_CMP_REQUEUE_PI=12`)일 때는 `pending_handoff_map[tgid]`의 현재 슬롯 `wakeup_ts = now`를 갱신합니다.
    2. **2-Tier 스레드 풀 핸드오프 (`sched_waking` + `pending_handoff_map` 8-Slot FIFO + `sched_process_fork`)**: Tier 1으로 Waker 컨텍스트가 100% 보장되는 `tracepoint:sched:sched_waking`에서 트레이스포인트 포맷 필드 **`u32 target_tid = args->pid;`** 를 읽어(읽기 전용 `zero_ctx_map[0]`으로 `active_ctx_map.update(&target_tid, zero_template)` 초기화 후) `active_ctx_map[target_tid]`로 컨텍스트를 복사하고(`parent_tid = waker_tid`, `flags |= FLAG_THREAD_HANDOFF`), `pending_handoff_map[tgid]`의 해당 `req_id` 슬롯을 `claimed = 1`로 마킹합니다(`sched_process_fork`에서는 `args->parent_pid`와 `args->child_pid` 사용). 만약 워커 스레드가 이미 `TASK_RUNNING`이어서 `sched_waking`(및 `glibc` 유저 공간 Fastpath로 인한 `FUTEX_WAKE`)이 생략된 경우, Tier 2로 워커 스레드(`tid != waker_tid`)가 `sys_exit_futex` 또는 첫 `uprobe`에 진입할 때 `pending_handoff_map[tgid]`의 `ring->slots[ring->read_idx & 7]`(`claimed == 0`)을 FIFO 순서로 인계받아 `claimed = 1; ring->read_idx++;` 처리 후 `parent_tid = waker_tid`, `flags |= FLAG_THREAD_HANDOFF`를 누락 없이 설정합니다.
    3. **`tracepoint:sched:sched_switch` (`args->prev_pid`, `args->next_pid`, `args->prev_state`) — 유저 함수 내부 Off-CPU Sleep 시간 보존 및 타임스탬프 즉시 리셋**:
       - `args->prev_pid == tid`로 스레드가 CPU에서 내려갈 때 `ctx->off_cpu_enter_ts = now; ctx->prev_cpu_id = bpf_get_smp_processor_id();`를 기록합니다.
       - 이후 `args->next_pid == tid`로 스레드가 물리 CPU 코어 연산장치(ALU)에 진입하는 순간, **만약 유저 함수 실행 도중(`ctx->call_depth > 0`) 슬립했다가 깨어난 경우(`off_cpu_enter_ts -> wakeup_ts -> now`) 단순히 `now - ctx->wakeup_ts`(런큐 대기 `0.05ms`)만 방출하면 실제 슬립 시간(`wakeup_ts - off_cpu_enter_ts`, 예: `18ms`)이 증발하여 유저 영역이 `18ms` 슬립을 On-CPU ALU 연산으로 오판하는 치명적 결함이 발생**합니다!
       - 따라서 반드시 `u64 runq_ns = ctx->wakeup_ts ? (now - ctx->wakeup_ts) : 0;` 및 `u64 total_off_cpu_ns = ctx->off_cpu_enter_ts ? (now - ctx->off_cpu_enter_ts) : runq_ns;`를 각각 산출한 뒤, **유저 함수 진입 전(`ctx->call_depth == 0`)에는 초기 디스패치 런큐 대기 시간(`ev->duration_ns = runq_ns`)을, 유저 함수 내부 실행 중(`ctx->call_depth > 0`)에는 전체 Off-CPU 대기 시간(`ev->duration_ns = total_off_cpu_ns`)을 담아 `layer_type = LAYER_USER_ENTRY (3)`, `call_depth = OSI_L6_PRE_COMPUTE (8)` 이벤트를 방출**하고, **방출 직후 반드시 `ctx->off_cpu_enter_ts = 0; ctx->wakeup_ts = 0; ctx->futex_enter_ts = 0;`으로 리셋**하여 다음 컨텍스트 스위치로 이전 타임스탬프가 누출되지 않도록 보장합니다.
    4. **블록 스토리지 I/O 추적 (`block_rq_insert` + `block_rq_issue` `kworker` 컨텍스트 보존 → `block_rq_complete` `bstate->tid` 조회)**:
       - `block_rq_insert`는 항상 요청을 제출한 유저 스레드(`tid`) 컨텍스트에서 실행되는 반면, `block_rq_issue`는 커널 블록 레이어의 비동기 `kblockd` `kworker` 스레드에서 실행될 수 있습니다. 따라서 `block_rq_issue`에서 `inflight_bio_map.lookup(&bkey)`를 먼저 조회하여 **이미 `block_rq_insert`가 등록한 `bstate`가 존재하면 기존의 유저 스레드 `bstate->tid`와 `bstate->req_id`를 그대로 보존하고 `bstate->issue_ts = now;`만 갱신**합니다 (`block_rq_insert` 없이 `blk-mq`가 직접 호출한 경우에만 현재 `tid`로 신규 등록).
       - 완료 훅인 `block_rq_complete`([`block.h:124-130`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/block.h#L124-L130))는 Block IRQ/SoftIRQ에서 실행되므로 절대 `bpf_get_current_pid_tgid()`를 쓰지 않고 **반드시 `active_ctx_map.lookup(&bstate->tid)`로 원본 유저 스레드 컨텍스트를 조회**하며, `args->bytes` 필드가 없으므로 **`(u64)args->nr_sector * 512`**(또는 `bstate->bytes`)로 전송 바이트를 계산해 `OSI_L5_SYSCALL_MEM (6)` 이벤트를 방출합니다.
  - **[L7 유저 함수 (`LAYER_USER_FUNC = 4`, `OSI_L7_APP = 7`) — `fn_entry_ip` 백업 & 언더플로우 가드]**:
    - `uprobe` 진입 시: `u32 depth = ctx->call_depth & (MAX_CALL_DEPTH - 1);` 슬롯에 **`ctx->fn_entry_ip[depth] = PT_REGS_IP(ctx);`**, `ctx->fn_entry_ts[depth] = now;`, `ctx->fn_off_cpu_snap[depth] = ctx->acc_off_cpu_ns;`를 저장하고 `if (ctx->call_depth < MAX_CALL_DEPTH) ctx->call_depth++;` 수행 후 `is_return = 0`, `duration_ns = ctx->fn_off_cpu_snap[depth]`를 방출합니다.
    - `uretprobe` 복귀 시: **반드시 `if (ctx->call_depth == 0) return 0;` 언더플로우 가드**를 먼저 수행한 뒤 `ctx->call_depth--; u32 depth = ctx->call_depth & (MAX_CALL_DEPTH - 1);`로 인덱싱하고, 트램펄린 주소인 `PT_REGS_IP(ctx)` 대신 **저장해 둔 `ev->ip = ctx->fn_entry_ip[depth]`**와 `ev->duration_ns = now - ctx->fn_entry_ts[depth]`, `ev->parent_tid = ctx->parent_tid`를 담아 `is_return = 1`을 방출합니다.

#### Layer 5 — `USER_EXIT` (`OSI_L5_SYSCALL_MEM = 6` & `OSI_L4_SOCKET = 5`, User Thread 컨텍스트)
- **부착 커널 훅**: `tracepoint:syscalls:sys_enter_write` & `sys_exit_write`, `kprobe__tcp_sendmsg` ([`tcp.c:1510`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L1510)) & **`kretprobe__tcp_sendmsg`** *(커널 함수이므로 유저 공간용 `uretprobe`가 아닌 `kretprobe` 사용)*
- **핵심 수행 로직**:
  - `kprobe__tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`에서 로컬 포트 **`sk->__sk_common.skc_num == target_port`** 가드로 루프백 클라이언트 송신 및 일반 파일/로그 쓰기를 배제하고, `active_ctx_map.lookup(&tid)`에서 현재 스레드의 활성 `req_id`를 조회한 뒤 `ctx->in_target_sendmsg = 1`을 마킹합니다.
  - **송신 방향 Egress Key (`egress_key = { .saddr = skc_rcv_saddr(Server), .daddr = skc_daddr(Client), .sport = skc_num(ServerPort), .dport = bpf_ntohs(skc_dport)(ClientPort), .proto = IPPROTO_TCP, .family = skc_family }`)**를 구성하여 `egress_flow_map[egress_key]`에 `{req_id, sendmsg_ts = now, pid, tid, pkt_len = size}`를 바인딩한 뒤 `layer_type = LAYER_USER_EXIT (5)`, `call_depth = OSI_L4_SOCKET (5)` 이벤트를 방출합니다.
  - **[Keep-Alive 좀비 `req_id` 원천 차단 및 로깅 `write()` 오삭제 방지]**: 일반 `sys_exit_write`는 표준출력/파일 로깅 시에도 수시로 호출되므로 절대 `sys_exit_write`에서 컨텍스트를 삭제하지 않습니다. 오직 `ctx->in_target_sendmsg == 1`이 마킹된 서버 소켓 송신이 끝나는 **`kretprobe__tcp_sendmsg`**(및 UDP/UNIX 대응 `kretprobe`)에서만 `active_ctx_map.delete(&tid)`를 수행하여 다음 Keep-Alive 요청으로 구버전 `req_id`가 누출되지 않도록 안전하게 정리합니다.

#### Layer 6 — `EGRESS_NIC` (`OSI_L4_TCP = 4`, `OSI_L3_IP = 3` & `OSI_L2_DATALINK = 2`, SoftIRQ / Process)
- **부착 커널 훅**: `kprobe____tcp_transmit_skb` ([`tcp_output.c:1238`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238)), `kprobe__ip_output` ([`ip_output.c:426`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_output.c#L426)), `tracepoint:net:net_dev_queue` ([`net.h:143`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L143)), `tracepoint:net:net_dev_xmit` ([`net.h:71`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/net.h#L71))
- **핵심 수행 로직**:
  - **L4 Egress (`kprobe____tcp_transmit_skb`) — [`sk->__sk_common` 기반 `egress_key` 생성 및 `skb_egress_map` 선행 바인딩]**: `__tcp_transmit_skb` 진입 시점에는 아직 함수 본문이 TCP/IP 헤더를 `skb`에 기록하기 전이므로, `skb` 헤더가 아닌 **`PARM1 = struct sock *sk`의 `sk->__sk_common`에서 `egress_key`를 직접 구성**하여 `egress_flow_map.lookup(&egress_key)`를 조회합니다. 조회 성공 시 `state->tcp_tx_ts = now`를 기록하고, 즉시 **`u64 skb_ptr = (u64)PT_REGS_PARM2(ctx); skb_egress_map.update(&skb_ptr, &egress_key);`** 로 `skb` 포인터를 바인딩한 뒤 `layer_type = LAYER_EGRESS_NIC (6)`, `call_depth = OSI_L4_TCP (4)` 이벤트를 방출합니다 (`tcp_transmit_skb`는 인라인이므로 반드시 `__tcp_transmit_skb` 사용).
  - **L3 Egress (`kprobe__ip_output`)**: 시그니처 `int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)`이므로 **`u64 skb_ptr = (u64)PT_REGS_PARM3(ctx);`** 로 `skb_egress_map.lookup(&skb_ptr)`(또는 `PARM2 = sk`의 4-Tuple `sport == target_port` 폴백)를 조회하여 `state->ip_out_ts = now`, `layer_type = LAYER_EGRESS_NIC (6)`, `call_depth = OSI_L3_IP (3)` 이벤트를 방출합니다.
  - **L2 Qdisc & Egress (`tracepoint:net:net_dev_queue` → `tracepoint:net:net_dev_xmit`)**: `net_dev_queue`에서 `u64 skb_ptr = (u64)args->skbaddr;`로 `skb_egress_map`을 조회해 `state->qdisc_enq_ts = now`를 기록합니다. 이어서 드라이버 송신 직후 실행되어 `skb->head`가 이미 해제(free)되었을 수 있는 `net_dev_xmit`에서는 `skb` 헤더 역참조 없이 **`u64 skb_ptr = (u64)args->skbaddr; skb_egress_map.lookup(&skb_ptr);`** 포인터 값만으로 안전하게 `egress_key`와 `state`를 조회하여 정확한 Qdisc 큐 대기 시간(`qdisc_delay_ns = now - state->qdisc_enq_ts`)을 산출, 최종 `LAYER_EGRESS_NIC`(`call_depth = OSI_L2_DATALINK (2)`, `rc == 0`) 방출 후 `skb_egress_map` 및 `egress_flow_map` 엔트리를 삭제합니다.

---

## 3.3 유저 영역: 통합 런타임 엔진, 7대 계층 분석기, 3단계 심볼리케이터 & AI 진단기 (`tracer_agent.py`)

### 3.3.1 지원 CLI 및 서버 실행 플래그 명세
- `--mode {live,simulate}`: Linux BCC/libbpf 실커널 주입 모드(`live`) 또는 실바이너리 ELF/심볼 파싱 기반 시뮬레이션 모드(`simulate`)
- `--ui {none,web,tui}`: 기본 콘솔 출력(`none`), 인터랙티브 웹 대시보드 서버 및 HTML 생성(`web`), 또는 대화형 터미널 TUI 콘솔(`tui`)
- `--serve {none,mcp,rest}`: **[서비스 런타임 모드]** AI 에이전트용 MCP JSON-RPC 2.0 서버(`mcp`) 또는 외부 연동용 REST/SSE API 서버(`rest`) 구동
- `--net-layer {all,l2,l3,l4,socket,syscall,sched,l7}`: **[입출력~연산장치 진입 직전 7대 계층별 확인 및 필터링]** 지정한 계층(`all`이면 `L2 / L3 / L4 / SOCKET / SYSCALL / SCHED / L7` 전 계층 매트릭스)의 패킷 헤더 메타데이터, 소켓 큐 대기 시간, 커널↔유저 메모리 복사/블록 I/O, 연산장치 진입 직전 CPU 런큐 대기(`runqlat`)/코어 마이그레이션, 홉 지연 시간을 상세 분석하여 테이블 및 JSON으로 출력
- `--proto {all,tcp,udp,icmp,arp,ipv4,ipv6,unix,tls}`: **[다중 프로토콜 필터링 및 비교 검증]** 타겟 머신(Rocky Linux 9.8)에서 동작하는 특정 프로토콜(`tcp`, `udp`, `icmp`, `arp`, `ipv4`, `ipv6`, `unix` 도메인 소켓, `tls` 암호화) 또는 전 프로토콜(`all`)의 커널/유저 경로 추적
- `--discover-ports`: **[전 포트 대역(`0 ~ 65535`) 및 프로토콜 자동 탐색]** 타겟 머신에서 열려 있거나 활성 통신 중인 모든 포트(`0` Wildcard, `1..1023` Well-Known 특권 포트, `1024..49151` Registered 서비스 포트, `32768..65535` Ephemeral 임시 포트)와 프로토콜(`TCP/UDP/IPv4/IPv6/UNIX/TLS`), 소유 프로세스(`PID`/`comm`)를 전수 스캔하여 분류 테이블 및 JSON(`port_protocol_inventory`)으로 출력 (`iproute2` `ss`가 없는 최소 컨테이너 환경에서도 동작하도록 커널 `/proc/net/{tcp,tcp6,udp,udp6,unix}` + `/proc/<pid>/fd/*` 소켓 inode 직접 파서를 기본 내장하고 `ss -tulnp`/`ss -xlnp`를 보조 결합)
- `--ui-port <INT>`: `--ui web` 또는 `--serve rest` 실행 시 내장 HTTP 서버 포트 번호 (기본값: `8090`)
- `--html-out <PATH>`: 독립 실행형 인터랙티브 웹 대시보드 HTML 파일 저장 경로 (기본값: `trace_dashboard.html`)
- `--pid <INT>`: 추적 대상 프로세스 PID (`0`이면 포트/프로토콜 기준 전 프로세스 추적)
- `--binary <PATH>`: 추적 대상 실행 파일 경로 (예: `./mock_server`)
- `--lib <PATH>`: 동적 로드 공유 라이브러리 경로 (예: `./libcrypto_mock.so`)
- `--port <PORT_SPEC>`: 추적 대상 포트 번호 (`8080`, `0` 또는 `all`이면 `0..65535` 전 포트 대역, 또는 `80,443,3000,5432,8080` 멀티 포트 체인)
- `--iface <STR>`: 네트워크 인터페이스 이름 (기본값: `lo` 또는 `eth0`)
- `--out <PREFIX>`: 출력 Graphviz 파일 접두사 (`<PREFIX>.dot`, `<PREFIX>.svg`)
- `--ai-report <PATH>`: AI 에이전트용 진단 번들 JSON 저장 경로 (예: `ai_diagnosis.json` — 내부에 `network_layer_diagnostics` 섹션 포함)
- `--focus-symbol <REGEX>`: **[적응형 Zoom-In]** 특정 함수 심볼 정규식에만 `uprobe`를 선택적으로 부착
- `--uprobe-offset <MODULE:0xOFFSET>`: **[Stripped Zoom-In]** 심볼이 제거된 바이너리의 특정 상대 오프셋에 직접 `uprobe` 부착 (예: `libcrypto_mock.so:0x1140`)
- `--simulate-drops <INT>`: 링버퍼 오버플로우(`drop_count > 0`) 경고 배너 검증을 위한 드롭 카운트 주입 값
- `--fast-mode`: 최적화된 서버 실행 경로 시뮬레이션/검증 플래그
- `--compare <BASELINE_JSON> <PATCHED_JSON>`: 패치 전/후 두 `ai_diagnosis.json` 파일을 비교하여 정량적 성능 개선 리포트 출력

### 3.3.2 3단계 메모리 맵, ELF 심볼 해석 엔진 & C++ `uprobe` 폭발 방지 필터 (*BPF 성능 분석 도구* 12장 근거)
1. **가상 메모리 매핑 테이블 구축 (`/proc/<PID>/maps`) 및 ELF `PT_LOAD` 파일 오프셋 변환**:
   - 프로세스의 실행 가능한 메모리 세그먼트(`r-xp`)를 파싱하여 `[vm_start, vm_end)`, `file_offset`, `module_path` 리스트를 유지합니다.
   - 런타임 명령어 포인터(`ip`)를 파일 내 상대 오프셋(`rel_offset`)으로 변환하는 수식:
     $$\text{rel\_offset} = (\text{ip} - \text{vm\_start}) + \text{file\_offset}$$
   - **[`aarch64` PIE/공유 라이브러리 `attach_uprobe` 파일 오프셋 공식]**: ELF 심볼 테이블(`.symtab`/`.dynsym`)의 `st_value`(가상 주소)를 커널 `attach_uprobe(name=..., addr=uprobe_file_offset)`에 전달할 때는, `aarch64` 64KB 세그먼트 정렬 등으로 인해 `p_vaddr != p_offset`일 수 있으므로 반드시 해당 심볼이 속한 실행 가능 `PT_LOAD` 세그먼트(`PF_X`)를 찾아 다음 공식으로 파일 오프셋을 산출해야 합니다:
     $$\text{uprobe\_file\_offset} = \text{st\_value} - \text{seg.p\_vaddr} + \text{seg.p\_offset}$$
2. **3단계 심볼 테이블 탐색 (`.symtab` → `.dynsym` → `.eh_frame` FDE & Call-Target `module+0xoffset`)**:
   - **Tier 1 (`.symtab` & 디버그 심볼)**: `pyelftools`(및 Linux `nm`/`objdump`/`addr2line` ELF 파서)로 함수를 찾고 C++ Demangling을 수행합니다.
   - **Tier 2 (`.dynsym` / `.plt` 폴백)**: `.symtab`이 없을 경우 동적 링커용 `.dynsym` 테이블을 검색합니다.
   - **Tier 3 (Stripped Binary `.eh_frame` FDE + Call-Target 자동 탐색 및 Offset 폴백)**: `strip -x` / `strip --strip-unneeded`로 `.symtab`이 제거된 공유 라이브러리(`libcrypto_mock.so`)의 내부 정적 함수(`verify_hmac_signature_internal`)는 `.dynsym`에도 나타나지 않습니다. 따라서 자동 `uprobe` 스캐너는 C++ 예외 처리를 위해 항상 보존되는 **`.eh_frame` 섹션의 FDE(`Frame Description Entry`, `pc_begin .. pc_end`) 테이블** 및 `.dynsym` 진입 함수 내부의 **`bl <0xoffset>`(`aarch64`) / `callq <0xoffset>`(`x86_64`) 분기 타겟 주소**를 스캔하여 숨겨진 내부 함수 진입점 오프셋을 자동 발굴·부착하고, 이벤트 수신 시 **`<module_basename>+0x<rel_offset:x>`** (예: `libcrypto_mock.so+0x1140`) 형식으로 변환하며 `FLAG_STRIPPED_SYMBOL`을 설정합니다.
3. **C++ ELF `uprobe` 부착 폭발(`EMFILE`) 및 STL 노이즈 방지 필터 (Deterministic Symbol Filter)**:
   - C++ 바이너리의 모든 `STT_FUNC` 심볼에 무차별적으로 `uprobe`/`uretprobe`를 부착하면 수천 개의 STL/런타임 함수로 인해 `RLIMIT_NOFILE`(`EMFILE`) 크래시 및 `MAX_CALL_DEPTH`(`16`) 포화가 발생합니다.
   - 따라서 자동 `uprobe` 스캐너는 ① 시스템/컴파일러/C++ 표준 라이브러리 접두사(`_start`, `_init`, `_fini`, `__libc_`, `__cxa_`, `__gxx_`, `_ZSt`, `_ZNSt`, `_ZNKSt`, `_GLOBAL__sub_I_`, `frame_dummy`, `register_tm_clones`, `deregister_tm_clones`, `@plt`) 및 크기 `st_size < 16` 바이트인 극소 Thunk 함수를 자동 제외하고, ② 애플리케이션 도메인 함수만 최대 `MAX_AUTO_UPROBES = 64`개(`--focus-symbol` 지정 시 해당 정규식 우선)로 필터링하여 부착하며, ③ 프로세스 초기화 시 `resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))` 상향을 시도합니다.

### 3.3.3 요청별(`req_id`) 완료 상태 머신, 이벤트 정렬 & `ai_diagnosis.json` 통합 스키마 (`network_layer_diagnostics` 포함)
1. **비동기 Egress 누락 방지용 Per-`req_id` 완료 상태 머신 (`50ms` Grace Window & Canonical Sort)**:
   - 유저 스레드가 `tcp_sendmsg`(`LAYER_USER_EXIT`)를 호출한 직후, 커널의 `__tcp_transmit_skb` → `ip_output` → `net_dev_queue` → `net_dev_xmit`(`LAYER_EGRESS_NIC`)는 비동기/SoftIRQ에서 실행되므로 RingBuf에 수 밀리초 늦게 도착할 수 있습니다.
   - 따라서 `tracer_agent.py`는 `LAYER_USER_EXIT` 수신 시 즉시 플러시하지 않고 `STAGE_SEEN_EXIT` 상태로 전환한 뒤, **`LAYER_EGRESS_NIC`(`OSI_L2_DATALINK`) 도착 시 즉시 완료**하거나 **`50ms` Grace Window 경과 시 완료** 처리합니다.
   - 멀티코어 CPU 간 미세한 RingBuf 기록 순서 역전을 보정하기 위해, 분석 직전 각 `req_id`의 이벤트 배열을 **`(timestamp, layer_order, is_return)` 기준으로 정규 정렬(Canonical Sort)**합니다.
   - **RingBuf 드롭 카운터 무결성 합산 규칙**: `events.ringbuf_reserve()`가 100% 포화되어 `NULL`을 반환할 때는 이벤트 자체가 방출되지 않고 커널 `drop_cnt_map[0]`만 원자적으로 증가합니다. 따라서 `tracer_agent.py`는 최종 `drop_count`를 산출할 때 반드시 **`final_drop_count = max(max_event_drop_count, bpf_drop_cnt_map[0]) + args.simulate_drops`** 공식으로 합산하여 `ai_diagnosis.json`과 Graphviz `cluster_alert_overflow` 배너에 반영합니다 (`TEST-06` 무결성 보장).
2. **`ai_diagnosis.json` 최상위 필수 키 계약 (Top-Level JSON Schema Contract)**:
   - `req_id`: 상관관계 추적된 16진수 요청 ID 문자열 (예: `"0x9f82a101"`)
   - `total_rtt_ms`: L2 Ingress부터 L2 Egress까지 총 왕복 소요 시간(ms)
   - `drop_count`: 최종 합산된 링버퍼 드롭 카운트 정수
   - `bottleneck_summary`: 최상위 병목 진단 요약 객체 (`primary_suspect`, `layer`, `symbol_or_offset`, `duration_ms`, `pct_of_rtt`, `category`, `root_cause`, `recommended_fix`)
   - `hop_timeline`: 시간순 정규 정렬된 전 계층 홉 리스트 (`hop_index`, `layer_type`, `osi_layer`, `symbol_or_probe`, `module`, `tid`, `parent_tid`, `duration_ms`, `pct_of_rtt`, `flags`)
   - `source_code_evidence`: DWARF `addr2line`으로 추출된 C++ 원본 소스 파일 경로, 줄 번호(`line`), 코드 스니펫 딕셔너리 (`TEST-08`)
   - `stripped_assembly_evidence`: Stripped 오프셋(`libcrypto_mock.so+0x...`)에서 `objdump -d`로 추출된 어셈블리 명령어 블록 딕셔너리 (`TEST-08`)
   - `network_layer_diagnostics`: 아래 3항의 7대 계층 검증 스키마 객체 (`TEST-12`)
3. **7대 계층 검증 스키마 (`network_layer_diagnostics`)**:
   `tracer_agent.py`는 수집된 이벤트를 **7대 하드웨어·커널·메모리·스케줄러·연산 계층(`L2`, `L3`, `L4`, `SOCKET`, `SYSCALL`, `SCHED`, `L7`)**으로 집계하여 `ai_diagnosis.json` 내 `network_layer_diagnostics` 필드에 다음 구조로 저장합니다:
- `target_kernel`: `"5.14.0-687.10.1.el9_8.0.1.aarch64 (Rocky Linux 9.8 Blue Onyx)"`
- `symmetric_io_verified`: `true` (전 계층 Input ↔ Pre-Compute ↔ Output 연속성 및 `req_id` 무결성 통과 여부)
- `pre_compute_total_ms`: 데이터가 NIC에 도착한 순간부터 연산장치(CPU 코어)에 진입하기 직전까지 걸린 총 시간($\text{L2}+\text{L3}+\text{L4}+\text{SOCKET}+\text{SYSCALL}+\text{SCHED}$)
- `layers`:
  - `L2`: `{ "osi_layer": "L2_DATALINK_DMA", "rx_latency_ms": ..., "tx_latency_ms": ..., "total_ms": ..., "pct_of_rtt": ..., "iface": "lo", "rx_cpu_id": 0, "eth_proto": "0x0800 (IPv4)", "rx_pkt_bytes": 184, "tx_pkt_bytes": 256, "xdp_verdict": "XDP_PASS", "qdisc_delay_ms": ..., "input_verdict": "PASS", "output_verdict": "PASS", "hooks": ["xdp_ingress_filter", "tracepoint:net:netif_receive_skb", "tracepoint:net:net_dev_xmit"], "status": "HEALTHY" }`
  - `L3`: `{ "osi_layer": "L3_NETWORK_IP", "rx_latency_ms": ..., "tx_latency_ms": ..., "total_ms": ..., "pct_of_rtt": ..., "src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "ihl_bytes": 20, "ttl": 64, "input_verdict": "PASS", "output_verdict": "PASS", "hooks": ["kprobe:ip_rcv", "kprobe:ip_output"], "status": "HEALTHY" }`
  - `L4`: `{ "osi_layer": "L4_TRANSPORT_TCP", "rx_latency_ms": ..., "tx_latency_ms": ..., "total_ms": ..., "pct_of_rtt": ..., "src_port": ..., "dst_port": 8080, "proto": "TCP", "tcp_flags": ["PSH", "ACK"], "tcp_state": "TCP_ESTABLISHED", "retransmits": 0, "skb_drops": 0, "input_verdict": "PASS", "output_verdict": "PASS", "hooks": ["kprobe:tcp_v4_rcv", "kprobe:__tcp_transmit_skb", "tracepoint:skb:kfree_skb"], "status": "HEALTHY" }`
  - `SOCKET`: `{ "osi_layer": "L4_5_SOCKET_QUEUE", "rx_sock_dwell_ms": ..., "tx_sock_dwell_ms": ..., "total_ms": ..., "pct_of_rtt": ..., "bound_pid": ..., "bound_tid": ..., "input_verdict": "PASS", "output_verdict": "PASS", "hooks": ["kprobe:tcp_recvmsg", "kprobe:tcp_sendmsg"], "status": "HEALTHY" }`
  - `SYSCALL`: `{ "osi_layer": "L5_SYSCALL_MEM_BLOCK_IO", "rx_latency_ms": ..., "tx_latency_ms": ..., "total_ms": ..., "pct_of_rtt": ..., "copy_to_user_bytes": 184, "copy_from_user_bytes": 256, "page_faults": 0, "storage_block_io_ms": ..., "input_verdict": "PASS", "output_verdict": "PASS", "hooks": ["tracepoint:syscalls:sys_enter_read", "tracepoint:skb:skb_copy_datagram_iovec", "kprobe:handle_mm_fault", "tracepoint:block:block_rq_issue", "tracepoint:syscalls:sys_enter_write"], "status": "HEALTHY" }`
  - `SCHED`: `{ "osi_layer": "L6_PRE_COMPUTE_SCHED_GATE", "runq_latency_ms": ..., "lock_wait_ms": ..., "total_ms": ..., "pct_of_rtt": ..., "prev_cpu_id": 0, "target_cpu_id": 2, "cpu_migrated": true, "l1_cache_locality": "COLD_MIGRATED", "input_verdict": "PASS", "hooks": ["tracepoint:syscalls:sys_enter_futex", "tracepoint:syscalls:sys_exit_futex", "tracepoint:sched:sched_waking", "tracepoint:sched:sched_wakeup", "tracepoint:sched:sched_switch"], "status": "HEALTHY" }`
  - `L7`: `{ "osi_layer": "L7_COMPUTE_UNIT_ALU", "total_ms": ..., "pure_on_cpu_compute_ms": ..., "off_cpu_io_wait_ms": ..., "pct_of_rtt": ..., "function_count": ..., "thread_handoffs": 1, "primary_hotspot": "execute_storage_query", "io_verdict": "BOTTLENECK", "status": "BOTTLENECK" }`

---

## 3.4 시각화 파이프라인: 4-Tier Graphviz DOT & 히트맵 생성기

생성되는 `.dot` 파일(및 `dot -Tsvg`로 자동 컴파일되는 `.svg`)은 다음 레이아웃 및 시각 인코딩 규칙을 엄격히 준수해야 합니다:

1. **최상위 링버퍼 오버플로우 경고 배너 (`drop_count > 0` 일 때만 렌더링)**:
   - 그래프 최상단에 `subgraph cluster_alert_overflow` 블록을 생성하고, 배경색 `#ffebee`, 테두리 `#c0392b`(`penwidth=3`), 굵은 진홍색 텍스트로 `"⚠️ WARNING: BPF RING BUFFER OVERFLOW DETECTED (Dropped Events: N)"`를 표시합니다.
2. **4-Tier 아키텍처 클러스터 계층 구조 및 Graphviz 식별자 정규화 규칙**:
   - `subgraph cluster_tier_ingress`: `[TIER 1: INGRESS WIRE (OSI L2 NIC / XDP)]`
   - `subgraph cluster_tier_kernel`: `[TIER 2: LINUX KERNEL NETWORK, MEMORY & PRE-COMPUTE SCHEDULER STACK (OSI L3 IP -> L4 TCP -> Socket Queue -> L5 Syscall/MM/Block I/O -> L6 Pre-Compute Sched Gate)]`
   - `subgraph cluster_tier_app`: `[TIER 3: USER-SPACE APPLICATION & WORKER THREAD POOL (OSI L7)]` (내부에 `subgraph cluster_mod_<sanitized_filename>` 블록으로 바이너리/라이브러리별 모듈 분리 — **주의**: Graphviz DOT 문법에서 서브그래프 ID에 마침표(`.`)나 하이픈(`-`)이 들어가면 `dot -Tsvg` 컴파일이 실패하므로 반드시 `re.sub(r'[^a-zA-Z0-9_]', '_', os.path.basename(mod))`로 정규화하여 `cluster_mod_libcrypto_mock_so` 형태로 생성하고, 원본 파일명은 `label="Module: libcrypto_mock.so"` 속성에 표시합니다)
   - `subgraph cluster_tier_egress`: `[TIER 4: EGRESS WIRE (Socket -> L4/L3 IP -> L2 NIC)]`
3. **동적 병목 히트맵 컬러 그라데이션**:
   - **정상 구간 (`pct < 10%`)**: 초록색 (`#2ecc71` 테두리/엣지, `#eafaf1` 노드 배경)
   - **주의 구간 (`10% <= pct <= 35%`)**: 주황색 (`#f39c12` 테두리/엣지, `#fef9e7` 노드 배경)
   - **병목 구간 (`pct > 35%`)**: 진홍색 (`#e74c3c` 테두리/엣지, `#fdedec` 노드 배경, `penwidth=2.8`)
4. **스레드 핸드오프 & Stripped 심볼 시각 표식**:
   - 스레드 전환 엣지(`TID A -> TID B`): `color="#2980b9", style="dashed,bold", label="Thread Handoff (TID A -> TID B) | +Δt ms"`
   - Stripped 바이너리 오프셋 노드: 보라색 테두리(`color="#8e44ad"`)와 `[STRIPPED ELF OFFSET]` 배지 표시

---

## 3.5 휴먼 인터페이스 상세 명세 (Interactive Web Dashboard & Terminal TUI)

### 3.5.1 인터랙티브 웹 대시보드 (`trace_dashboard.html` & `--ui web`)
1. **상단 인터랙티브 컨트롤, Hot-Reload 설정 & 7대 계층 필터 툴바**:
   - 타겟 `PID`, `Port`, `Interface` 실시간 변경 입력창 (`PUT /api/v1/config` 호출로 `0ms` 무재컴파일 핫리로드 수행).
   - 프리셋 실행 버튼: `[Run Baseline Trace]`, `[Run Optimized (--fast-mode) Trace]`, `[Simulate RingBuf Overflow (128 Drops)]`.
   - **7대 계층 필터 버튼 바 (7-Layer Filter Pills)**: **`[All Layers]`, `[L2: NIC / XDP]`, `[L3: IP Routing]`, `[L4: TCP Transport]`, `[Socket Queue]`, `[L5: Syscall / Mem / Block I/O]`, `[L6: Pre-Compute Sched Gate]`, `[L7: App ALU]`** 클릭 시 SVG 노드 및 하단 테이블을 해당 계층으로 즉시 필터링/하이라이트.
   - 적응형 Zoom-In 입력창: `--focus-symbol` 정규식 및 `--uprobe-offset` 오프셋 입력란 + `[Apply Zoom-In Probe]` 버튼.
2. **좌측 메인 뷰 — 인터랙티브 4-Tier SVG 아키텍처 캔버스**:
   - 인라인 렌더링된 4-Tier Graphviz SVG 다이어그램.
   - **SVG 노드 클릭 이벤트 연동**: 다이어그램 내 유저 함수 노드나 커널/네트워크/스케줄러 계층 노드를 마우스로 클릭하면 우측 인스펙터 패널이 즉시 해당 노드의 상세 정보로 전환됩니다.
3. **우측 드로어 — 소스 코드 / Stripped 어셈블리 / 커널 훅 & 패킷 헤더 딥다이브 인스펙터**:
   - 선택된 노드의 메타데이터(`OSI/Pre-Compute Layer`, `TID`, `parent_tid`, `Module/Hook`, `Duration ms`, `% of RTT`, `Category Badge`) 표시.
   - **커널/네트워크/스케줄러 노드(`L2`, `L3`, `L4`, `SOCKET`, `SYSCALL`, `SCHED`) 선택 시**: 해당 계층의 **패킷 헤더 및 커널 진단 카드**(`iface`, `eth_proto`, `src_ip -> dst_ip`, `ihl/ttl`, `src_port -> dst_port`, `tcp_flags=[PSH,ACK]`, `sk_rcvbuf dwell time`, `copy_to_user_bytes`, `handle_mm_fault`, `runq_latency_ms`, `CPU#0 -> CPU#2`, `qdisc delay`)와 함께 타겟 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 원본 소스 경로 및 대응하는 `tracer_kernel.c`의 eBPF 훅 C 코드를 하이라이트하여 표시.
   - **Unstripped 유저 함수 선택 시**: 추출된 실제 C++ 소스 파일(`mock_server.cpp:line`)과 줄 번호가 매겨진 소스 코드 블록 표시.
   - **Stripped 오프셋(`libcrypto_mock.so+0x1140`) 선택 시**: 자동 추출된 `objdump -d` ELF 역어셈블리 명령어 블록 표시.
   - 원클릭 버튼: **`[Zoom-In Probe This Function/Offset]`**.
4. **하단 멀티 탭 — `6-Layer Waterfall`, `7-Layer Pre-Compute & I/O Matrix` & `Before vs After Patch Compare`**:
   - **Tab 1 (`6-Layer Chronological Waterfall`)**: 각 홉의 시작 시각, 소요 시간 막대(Gantt Bar), 스레드 핸드오프를 시간순으로 시각화.
   - **Tab 2 (`7-Layer Pre-Compute & I/O Matrix`)**: `L2 Data Link` → `L3 IP` → `L4 TCP` → `L4.5 Socket Queue` → `L5 Syscall/MM/Block I/O` → `L6 Pre-Compute Sched Gate` → `L7 Application ALU` 각 계층의 Ingress/Egress 지연 시간, 패킷 헤더 배지, 큐 대기 시간, CPU 런큐 대기(`runqlat`) 및 코어 이동을 계층별로 한눈에 비교하는 전용 인스펙터 뷰.
   - **Tab 3 (`Before vs After Patch Comparison`)**: 최적화 전(`Baseline`)과 최적화 후(`Patched`)의 총 RTT 감소율(`%`), 계층별/함수별 개선 폭($\Delta\text{ms}$) 비교 차트.

### 3.5.2 대화형 터미널 TUI 콘솔 (`--ui tui`)
SSH 원격 접속 환경을 위해 숫자키(`[1]~[7]`, `q`) 기반 대화형 루프 메뉴를 제공하여 터미널 안에서도 전체 트레이스(`[1]`), 노드별 C++ 소스/어셈블리 조회(`[2]`), **7대 계층별(`L2 / L3 / L4 / Socket / Syscall / Sched / L7`) 상세 확인(`[3]`)**, Zoom-In 프로빙(`[4]`), 패치 전후 비교(`[5]`), 오버플로우 시뮬레이션(`[6]`), HTML 대시보드 내보내기(`[7]`)를 모두 수행합니다.

---

## 3.6 서비스 게이트웨이 상세 명세: MCP 서버 (`--serve mcp`) & REST/SSE API (`--serve rest`)

### 3.6.1 AI 에이전트용 MCP Server (`--serve mcp`)
표준 JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`) 프로토콜을 구현하며 다음 **6대 MCP Tools**를 노출합니다:

- **`ebpf_configure_target`**:
  - **입력 파라미터**: `{"pid": int, "port": int, "iface": str, "capture_enabled": bool}`
  - **반환 데이터 및 동작**: **재컴파일 없이(`0ms`)** 커널 `runtime_config_map[0]`을 즉시 갱신하고 갱신된 `config_epoch` 및 상태 반환
- **`ebpf_capture_trace`**:
  - **입력 파라미터**: `{"mode": "baseline/fast/overflow", "focus_symbol": str, "uprobe_offset": str, "simulate_drops": int}`
  - **반환 데이터 및 동작**: 전 계층 트레이스를 실행하고 `ai_diagnosis.json` 전체 페이로드(병목 분류, 7대 계층 진단, 소스/어셈블리 스니펫, 홉 타임라인) 반환
- **`ebpf_inspect_network_layers`**:
  - **입력 파라미터**: `{"req_id": str, "layer": "all/l2/l3/l4/socket/syscall/sched/l7", "proto": "all/tcp/udp/icmp/arp/ipv4/ipv6/unix/tls"}`
  - **반환 데이터 및 동작**: 지정한 계층(`all`, `l2`, `l3`, `l4`, `socket`, `syscall`, `sched`, `l7`) 및 프로토콜(`proto`)의 Ingress/Egress 소요 시간, 패킷 헤더(IP/Port/TCP Flags/Len), 소켓 버퍼 대기 시간, 커널↔유저 메모리 복사/페이지 폴트/블록 I/O, 연산장치 진입 직전 CPU 런큐 대기(`runqlat`)/락 대기/코어 마이그레이션, 재전송/드롭 상태 반환
- **`ebpf_inspect_code_or_asm`**:
  - **입력 파라미터**: `{"req_id": str, "target": str}`
  - **반환 데이터 및 동작**: 특정 심볼명(예: `execute_storage_query`) 또는 Stripped 오프셋(예: `libcrypto_mock.so+0x1140`)의 DWARF C++ 소스 코드 또는 `objdump` 어셈블리 블록 반환
- **`ebpf_compare_patches`**:
  - **입력 파라미터**: `{"baseline_path": str, "patched_path": str}`
  - **반환 데이터 및 동작**: 패치 전/후 두 트레이스를 비교하여 총 RTT 단축률(`%`), 계층별/함수별 지연 시간 차이($\Delta\text{ms}$), 병목 해소 여부 반환
- **`ebpf_render_topology`**:
  - **입력 파라미터**: `{"req_id": str, "format": "svg/dot/html"}`
  - **반환 데이터 및 동작**: 4-Tier Graphviz `.dot`, `.svg` 또는 인터랙티브 `trace_dashboard.html`을 생성하고 파일 경로 및 요약 반환

### 3.6.2 REST & SSE API Server (`--serve rest` / `--ui web`) & 동시성/무교착(Non-Blocking) 아키텍처
1. **멀티스레드 비블로킹 서버 (`ThreadingHTTPServer` + `threading.RLock()`)**:
   - 파이썬 기본 단일 스레드 `HTTPServer`를 사용할 경우 캡처 요청 처리 중 상태 조회나 SSE 요청이 블로킹되어 데드락이 발생하므로, 반드시 **`http.server.ThreadingHTTPServer`**를 사용하고 런타임 상태 갱신 시 **`threading.RLock()`**으로 동기화합니다.
   - `POST /api/v1/traces` 및 MCP `ebpf_capture_trace` 호출 시 외부 트래픽이 들어오지 않아 무한 대기(Hang)하는 결함을 원천 방지하기 위해, 내장 백그라운드 루프백 클라이언트 트리거(타겟 포트로 테스트 패킷 자동 송신, 또는 `simulate`/비특권 환경일 때 `./mock_server`와 `./libcrypto_mock.so`의 실제 ELF/DWARF/디스어셈블리 테이블을 파싱한 결정론적 파이프라인 실행)를 구동하여 **최대 `500ms` 이내에 무블로킹 응답**을 반환합니다.
2. **엔드포인트 명세 (`http://localhost:8090`)**:
   - `GET /` : 인터랙티브 웹 대시보드 (`trace_dashboard.html`) 렌더링
   - `GET /api/v1/health` : 런타임 상태, 타겟 커널 버전(`5.14.0-687.10.1.el9_8.0.1.aarch64`), 현재 `runtime_config_map[0]` 설정(`target_pid`, `target_port`, `config_epoch`), 로드된 모듈 목록 반환
   - `PUT /api/v1/config` : `runtime_config_map[0]` 무재컴파일 핫리로드 업데이트 (`0ms`)
   - `POST /api/v1/traces` : 새로운 트레이스 캡처 실행 (`baseline`, `fast`, `overflow`, `zoom-in`) 및 결과 JSON + 인라인 SVG 반환
   - `GET /api/v1/traces/latest` : 가장 최근 캡처된 진단 번들(`ai_diagnosis.json`) 및 SVG 반환
   - `GET /api/v1/network-layers?layer=<all|l2|l3|l4|socket|syscall|sched|l7>&proto=<all|tcp|udp|icmp|arp|ipv4|ipv6|unix|tls>` : **7대 계층별·프로토콜별 패킷 헤더 메타데이터, 소켓 큐 대기 시간, 커널↔유저 메모리 복사/블록 I/O, CPU 런큐 대기(`runqlat`)·코어 마이그레이션, Ingress/Egress 지연 시간 상세 반환**
   - `GET /api/v1/discovery` : 타겟 머신의 전 포트 대역(`0..65535`: Wildcard `0`, Well-Known `1..1023`, Registered `1024..49151`, Ephemeral `32768..65535`) 및 활성 프로토콜(`TCP/UDP/IPv4/IPv6/ICMP/ARP/UNIX/TLS`) 인벤토리(`port_protocol_inventory`) 반환
   - `GET /api/v1/inspect?target=<symbol_or_offset>` : 지정한 함수/오프셋의 C++ 소스 코드 또는 Stripped 역어셈블리 반환
   - `POST /api/v1/compare` : Baseline vs Patched 비교 분석 결과 JSON 반환
   - `POST /mcp` : HTTP POST 기반 MCP JSON-RPC 2.0 엔드포인트 (`stdio`와 동일한 6대 MCP Tools 처리)

---

## 3.7 테스트 대상 멀티스레드 서버 및 Stripped 공유 라이브러리 (`mock_server.cpp`, `libcrypto_mock.cpp`) — 인라이닝 금지(`noinline`) 규칙

1. **`libcrypto_mock.cpp` → `libcrypto_mock.so` (Stripped Shared Library)**:
   - 외부 진입 함수(`verify_request_token`)와 내부 정적/비가시 연산 함수(`verify_hmac_signature_internal`)에 반드시 **`__attribute__((noinline))`** 을 지정하고, **`-g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -shared`** 플래그로 컴파일한 뒤 **`strip -x` (또는 `strip --strip-unneeded`)**를 실행해 `.symtab` 로컬 심볼을 제거합니다 (`-O1` 이상 사용 시 내부 정적 함수가 호출자에 인라이닝되어 `uprobe` 부착 지점이 사라지는 현상을 원천 방지).
2. **`mock_server.cpp` → `mock_server` (Multi-Threaded C++ TCP Server)**:
   - 모든 추적 대상 함수(`parse_http_request`, `validate_auth_header`, `execute_storage_query`, `format_http_response`)에 **`__attribute__((noinline))`** 을 선언하고 **`-g -O0 -fno-inline -fno-omit-frame-pointer -pthread -ldl`** 로 빌드하여 DWARF `addr2line` 줄 번호 정확도와 `uprobe`/`uretprobe` 프롤로그/에필로그 보존을 100% 보장합니다.
   - `dlopen("./libcrypto_mock.so", RTLD_NOW)`로 공유 라이브러리를 동적 로드합니다.
   - **I/O 스레드 (`TID 1`)**: 소켓 수신 → `parse_http_request()` → `validate_auth_header()` 내부에서 `libcrypto_mock.so` 호출 → 작업 큐에 요청을 넣고 `std::condition_variable::notify_one()`으로 워커 스레드를 깨움(`sched_waking` / `pending_handoff_map`).
   - **워커 스레드 (`TID 2`)**: 깨어난 후 `execute_storage_query()` 실행(기본 모드에서는 약 `18ms` 지연, `--fast-storage` 플래그 활성화 시 `1.2ms`로 단축) → `format_http_response()` 호출 → 소켓 `send()`로 응답 송신.

---

# PART 4. 전 기능 동작 보장 및 12대 자동 검증 매트릭스 (Verification & Guarantee Matrix)

## 4.1 12대 필수 자동 검증 항목 (`test_verification_suite.py`)

프롬프트의 모든 요구사항과 네트워크 계층별 진단, 휴먼/AI/MCP/REST 인터페이스가 빠짐없이 실제 코드로 동작함을 보장하기 위해, `pytest` 기반의 `test_verification_suite.py`를 통해 다음 **12가지 하드 어서션(Hard Assertions)**을 강제 검증합니다.

- **TEST-01 — C ↔ Python 64B 이벤트 & 16B 설정 구조체 ABI 일치**: `clang++`로 실제 C `struct kray_event_t`(`64B`) 및 `struct kray_runtime_cfg_t`(`16B`)의 `sizeof`와 전 필드 `offsetof()`를 출력하는 바이너리를 컴파일·실행하여 Python `ctypes` 오프셋과 **100% 일치(`assert c_offsets == py_offsets`)** 검증.
- **TEST-02 — eBPF C 커널 코드, Rocky 9.8 `aarch64` 레퍼런스 심볼 일치 & CO-RE 안전성**: `tracer_kernel.c` 내 ① `runtime_config_map` 기반 무재컴파일 동적 설정 로직, `#define __TARGET_ARCH_arm64` 및 [`vmlinux.h`](references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h) CO-RE 가드 존재, ② 인라인되어 존재하지 않는 `tcp_transmit_skb`나 x86 전용 `page_fault_user` 대신 실제 `/proc/kallsyms` 및 커널 소스에 존재하는 **`__tcp_transmit_skb`**, **`handle_mm_fault`**, **`skb_copy_datagram_iovec`**, **`ip_output`(`PT_REGS_PARM3=skb`)**, **`kretprobe__tcp_sendmsg`** 사용 확인, ③ XDP 훅 내 `bpf_get_current_pid_tgid()` 호출 부재 및 `data_end` 포인터 경계 검사 존재, ④ 6종 `BPF_LRU_HASH` 맵(`ingress_flow_map`, `active_ctx_map`, `pending_handoff_map`, `egress_flow_map`, `skb_egress_map`, `inflight_bio_map`), `BPF_PERCPU_ARRAY(zero_ctx_map)` 및 `BPF_RINGBUF_OUTPUT` 선언 무결성 검증.
- **TEST-03 — 6-Layer 상관관계 & 다중 요청 격리**: 동시에 인터리빙된 다중 요청(`req_id #1`, `req_id #2`) 이벤트 스트림을 주입했을 때, 각 요청이 섞이지 않고 Layer 1 → 2 → 3 → 4 → 5 → 6 순서로 정확히 재조립되는지 검증.
- **TEST-04 — 워커 스레드 풀 핸드오프 (`TID A -> TID B`)**: 실제 `mock_server` 실행 및 트레이싱 결과에서 I/O 스레드(`TID A`)와 워커 스레드(`TID B`) 간 `parent_tid == TID A` 계보 전파 및 Graphviz `.dot` 내 파란색 점선(`Thread Handoff`) 엣지 생성 여부 검증.
- **TEST-05 — Stripped `.so` 오프셋 폴백 (`module+0xoffset`)**: 실제로 `strip -x` 처리된 `libcrypto_mock.so`에 대해 심볼리케이터가 크래시 없이 `libcrypto_mock.so+0x<hex_offset>` 형식의 상대 오프셋으로 정확히 변환하는지 검증.
- **TEST-06 — 링버퍼 오버플로우 경고 배너 (`drop_count > 0`)**: `--simulate-drops 42` 실행 시 생성된 `.dot` 및 `.svg` 파일 최상단에 `cluster_alert_overflow` 서브그래프와 `42`건 유실 경고 문구가 포함되는지 검증.
- **TEST-07 — 4-Tier 클러스터, 히트맵 컬러링 & `.svg` 컴파일**: `.dot` 파일 내에 4개 Tier 클러스터(`cluster_tier_ingress/kernel/app/egress`)와 정규화된 모듈별 서브그래프(`cluster_mod_libcrypto_mock_so`), 3단계 색상 코드(`#2ecc71`, `#f39c12`, `#e74c3c`)가 모두 존재하며, `dot -Tsvg` 실행 시 유효한 `.svg` XML 파일이 생성되는지 검증.
- **TEST-08 — AI 진단 번들 (`ai_diagnosis.json`) 소스 & 어셈블리 추출**: 생성된 `ai_diagnosis.json` 내부에 ① `execute_storage_query`의 실제 `mock_server.cpp` 줄 번호 및 C++ 코드 스니펫이 포함되어 있고, ② Stripped 오프셋(`libcrypto_mock.so+0x...`)의 실제 디스어셈블리 명령어 블록(`objdump -d`)이 비어 있지 않은지 검증.
- **TEST-09 — 적응형 Zoom-In (`--focus-symbol`, `--uprobe-offset`) & 패치 전/후 비교 (`--compare`)**: ① `--focus-symbol` 지정 시 매칭된 함수만 추적되는지 검증. ② 패치 전(`ai_diagnosis_baseline.json`)과 최적화 플래그 적용 후(`ai_diagnosis_patched.json`)를 `--compare`로 비교했을 때 RTT 단축률(`> 50%` 개선)과 병목 해소 판정이 정확히 출력되는지 검증.
- **TEST-10 — 휴먼 인터페이스 검증 (Interactive Web Dashboard & Terminal TUI)**: ① 생성된 `trace_dashboard.html`에 인라인 SVG 다이어그램, 노드 클릭 연동 C++ 소스/어셈블리/패킷 헤더 인스펙터, 7대 계층 필터, Before/After 비교 뷰가 모두 포함되어 있는지 검증. ② `--ui tui` 대화형 콘솔 메뉴 명령 실행이 정상 동작하는지 검증.
- **TEST-11 — MCP 서버 (`--serve mcp`) 6대 Tools & REST API (`/api/v1/*`) 핫리로드 검증**: ① `--serve mcp`에 JSON-RPC 2.0 `tools/list` 및 6대 Tools(`ebpf_configure_target`, `ebpf_capture_trace`, `ebpf_inspect_network_layers`, `ebpf_inspect_code_or_asm`, `ebpf_compare_patches`, `ebpf_render_topology`) 요청을 보내 정상 응답 및 `0ms` 설정 핫리로드(`config_epoch` 증가) 검증. ② REST API 서버(`GET /api/v1/health`, `PUT /api/v1/config`, `POST /api/v1/traces`, `GET /api/v1/network-layers`, `GET /api/v1/inspect`, `POST /api/v1/compare`) 전 엔드포인트 정상 동작 검증.
- **TEST-12 — 입출력(I/O) ~ 연산장치 진입 직전(Pre-Compute Gate) 7대 계층 & 다중 프로토콜/전 포트(`0..65535`) 전수 검증**: ① `ai_diagnosis.json` 내 `network_layer_diagnostics`에 `symmetric_io_verified == True`, `pre_compute_total_ms`, 7대 계층(`L2`, `L3`, `L4`, `SOCKET`, `SYSCALL`, `SCHED`, `L7`)의 입력/출력 판정(`PASS`), 패킷 바이트(`rx_pkt_bytes`, `tx_pkt_bytes`), 소켓 큐 체류 시간(`rx_sock_dwell_ms`), 커널↔유저 메모리 복사/블록 스토리지 I/O(`copy_to_user_bytes`, `storage_block_io_ms`), **연산장치 진입 직전 CPU 런큐 대기(`runq_latency_ms`)·락 대기(`lock_wait_ms`)·코어 마이그레이션(`prev_cpu_id -> target_cpu_id`)**, 그리고 **순수 On-CPU 연산 시간(`pure_on_cpu_compute_ms`) vs Off-CPU 대기 시간(`off_cpu_io_wait_ms`)**이 정확히 산출되는지 검증. ② `--discover-ports` 및 `--proto {all,tcp,udp,icmp,arp,ipv4,ipv6,unix,tls}` 실행 시 `0..65535` 포트 대역(Well-Known `1..1023`, Registered `1024..49151`, Ephemeral `32768..65535`)과 프로토콜별 커널 훅 매핑(`tcp_v4_rcv`/`tcp_v6_rcv`, `udp_rcv`/`udp_recvmsg`, `ipv6_rcv`/`ip6_output`, `icmp_rcv`, `arp_rcv`, `unix_stream_recvmsg`, `SSL_read`)이 정확히 탐색·분류되는지 검증.

---

## 4.2 엔드투엔드 원클릭 실행 시나리오 (`test_harness.sh` & `Dockerfile`)

`./test_harness.sh` 스크립트 하나만 실행하면 다음 전 과정이 자동으로 수행되고 검증됩니다:
1. `clang++`/`g++`로 `libcrypto_mock.cpp`를 `-g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -shared`로 공유 라이브러리 빌드 후 `strip -x`로 `.symtab` 심볼 제거 (`.eh_frame` FDE 보존)
2. `mock_server.cpp`를 디버그/비인라인 플래그(`-g -O0 -fno-inline -fno-omit-frame-pointer -pthread -ldl`)와 함께 멀티스레드 바이너리로 빌드
3. 실제 `mock_server` 프로세스를 백그라운드로 기동하고 실제 TCP HTTP 요청 전송 및 응답 확인
4. `tracer_agent.py --net-layer all`로 **[1단계: 베이스라인 전구간 추적 + 7대 계층별(`L2~L7`) 전수 검증]** 실행 → `trace_baseline.dot`, `trace_baseline.svg`, `ai_diagnosis_baseline.json` 생성
5. `tracer_agent.py --simulate-drops 128`로 **[2단계: 링버퍼 오버플로우 경고 그래프]** 생성 → `trace_overflow.svg` 생성
6. `tracer_agent.py --focus-symbol "execute_storage_query" --uprobe-offset ...`로 **[3단계: 적응형 Zoom-In 추적]** 실행
7. 최적화 모드(`--fast-mode`)로 **[4단계: 패치 후 추적 및 `--compare` 전후 벤치마크 비교 리포트 + 인터랙티브 웹 대시보드(`trace_dashboard.html`)]** 생성
8. 마지막으로 `pytest test_verification_suite.py -v`를 실행해 **TEST-01 ~ TEST-12 전 항목 통과(PASS)**를 확인

---

# PART 5. AI 에이전트 주입용 최종 마스터 프롬프트 (Copy-Ready Master Prompt)

다른 AI 에이전트나 자동화 파이프라인에 단일 프롬프트로 주입할 때는 아래 코드 블록 전체를 그대로 복사하여 사용합니다.

```markdown
# PROJECT NAME: eBPF-WireToCode-Tracer
# ROLE, RAISON D'ÊTRE, TARGET MACHINE & OBJECTIVE
You are a Principal Systems Engineer and Linux Kernel Developer specializing in eBPF (Extended Berkeley Packet Filter), high-performance networking, and AI-driven runtime observability, strictly grounded in the three local references in this workspace:
1. `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`:
   - **Target Machine & OS**: **Rocky Linux 9.8 (Blue Onyx) `aarch64` (`arm64`)**, Kernel **`5.14.0-687.10.1.el9_8.0.1.aarch64`** (local UTM VM `rocky-dev` & AWS EC2 `t4g.large`).
   - **Kernel Source Tree**: `linux-5.14.0-687.10.1.el9_8/` (`net/ipv4/ip_input.c`, `net/ipv4/tcp_ipv4.c`, `net/ipv4/tcp.c`, `net/ipv4/tcp_output.c`, `net/ipv4/ip_output.c`, `net/core/datagram.c`, `mm/memory.c`, `include/trace/events/{net.h,skb.h,sched.h,block.h}`).
   - **BTF & libbpf Headers**: `btf-and-headers/vmlinux.h` (dumped from `/sys/kernel/btf/vmlinux`) and `btf-and-headers/bpf/{bpf_helpers.h,bpf_tracing.h,bpf_core_read.h,bpf_endian.h}`.
2. `references/ebpf-docs-master/docs/`: Official `docs.ebpf.io` specification (`BPF_PROG_TYPE_XDP`, `BPF_PROG_TYPE_SCHED_CLS`, `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, `BPF_MAP_TYPE_LRU_HASH`, `BPF_MAP_TYPE_RINGBUF`, `bpf_get_current_pid_tgid`, `concepts/core.md`, `concepts/verifier.md`).
3. `references/BPF-성능-분석-도구.pdf`: Brendan Gregg's *BPF Performance Tools* (Ch. 2 Technology, Ch. 6 CPUs `runqlat`, Ch. 7 Memory Faults, Ch. 8–9 File/Block I/O, Ch. 10 Networking & Section 10.1.4 SoftIRQ PID trap, Ch. 12 Compiled Binary Symbolication `.symtab`/`.dynsym`/stripped offsets, Ch. 14 Kernel Sched/Futex).

**Core Raison d'être (존재 이유)**:
The fundamental reason this project exists is **to use ONLY eBPF to secure 100% visibility and symmetric verification across EVERY layer from I/O entry all the way up to right before the CPU Compute Unit (`Pre-Compute Gate`) and back out to I/O exit**:
`L2 NIC DMA/SoftIRQ <-> L3 IP Routing <-> L4 TCP Transport <-> L4.5 Socket Buffer Queue (sk_rcvbuf/sk_sndbuf) <-> L5 Syscall, Kernel-to-User Memory Copy, Page Faults & Block Storage I/O <-> L6 Pre-Compute Scheduler Gate (Futex Lock Wait + CPU Runqueue Latency runqlat + CPU Core Migration/Cache Locality) <-> L7 On-CPU ALU Execution (User Functions & Stripped .so)`.

Your task is to build a "Zero-Touch End-to-End 7-Layer Wire-to-PreCompute-to-ALU Verification & AI-Agent Performance Diagnostics Runtime" named **eBPF-WireToCode-Tracer**.

Crucially, the runtime is engineered around a **Map-Driven Zero-Recompile & BPF CO-RE Compatible Architecture** (`runtime_config_map`), includes **7-Layer Deep Verification (`L2 / L3 / L4 / Socket / Syscall / Sched / L7`)**, and provides **Multi-Modal Interfaces for both Humans and AI Agents**:
1. **For Humans**:
   - **Interactive Web Dashboard (`trace_dashboard.html` & `--ui web`)**: Self-contained interactive web UI featuring a 4-tier zoomable SVG topology, 7-Layer filter pills (`All | L2 | L3 | L4 | Socket | Syscall | Sched | L7`), a side-panel inspector showing exact C++ source code (`file:line`), stripped binary disassembly (`objdump -d`), or L2..L6 packet header, socket queue, memory copy, and CPU runqueue metrics + kernel hook source when clicking any node, a `0ms` Hot-Reload config bar, a 6-layer waterfall chart, a dedicated `7-Layer Pre-Compute & I/O Matrix` tab, and a Before-vs-After patch comparison tab.
   - **Interactive Terminal TUI (`--ui tui`)**: Keyboard-driven console menu (`[1]..[7]`, `q`) for SSH environments including 7-layer inspection.
   - **CLI 7-Layer Inspector (`--net-layer {all,l2,l3,l4,socket,syscall,sched,l7}`), Waterfall Table & Publication-Grade Graphviz Topology (`.dot` / `.svg`)**.
2. **For AI Coding/SRE Agents & External Systems**:
   - **Native MCP Server (`--serve mcp`, JSON-RPC 2.0 over `stdio` & HTTP `/mcp`)** exposing 6 tools: `ebpf_configure_target` (`0ms` map hot-reload), `ebpf_capture_trace`, `ebpf_inspect_network_layers`, `ebpf_inspect_code_or_asm`, `ebpf_compare_patches`, and `ebpf_render_topology`.
   - **REST & SSE API Server (`--serve rest`, `/api/v1/*`)**: Programmatic control over target configuration (`PUT /api/v1/config`), trace capture (`POST /api/v1/traces`), 7-layer inspection (`GET /api/v1/network-layers`), node code/ASM inspection (`GET /api/v1/inspect`), and patch comparison (`POST /api/v1/compare`).
   - **Structured `ai_diagnosis.json` Bundle**: Includes `network_layer_diagnostics` (`L2`, `L3`, `L4`, `SOCKET`, `SYSCALL`, `SCHED`, `L7` metrics & verdicts), bottleneck classification, DWARF/source snippet extraction, and stripped assembly extraction, paired with **Adaptive Zoom-In CLI flags** (`--focus-symbol`, `--uprobe-offset`) and **Before/After Patch Comparison** (`--compare baseline.json patched.json`).

---

# ARCHITECTURAL PARADIGM: 6 MACRO LAYERS & 7 GRANULAR SUB-LAYERS (VERIFIED AGAINST ROCKY 9.8 KERNEL `5.14.0-687.10.1.el9_8.0.1.aarch64`)

eBPF-WireToCode-Tracer correlates telemetry across 6 sequential macro execution layers while enforcing a **strictly disjoint `(layer_type, call_depth)` encoding**:
- `layer_type == LAYER_USER_FUNC (4)` is reserved **exclusively** for user-space `uprobe`/`uretprobe` functions (`OSI_L7_APP = 7`), where `call_depth` is `0..15` (pure nesting depth).
- All kernel/pre-compute events (`OSI_L2_DATALINK = 2`, `OSI_L3_IP = 3`, `OSI_L4_TCP = 4`, `OSI_L4_SOCKET = 5`, `OSI_L5_SYSCALL_MEM = 6`, `OSI_L6_PRE_COMPUTE = 8`) MUST be emitted with `layer_type != LAYER_USER_FUNC` (`LAYER_USER_ENTRY = 3` or `LAYER_USER_EXIT = 5` for L5/L6) so a depth-6 or depth-8 user function never collides with `OSI_L5_SYSCALL_MEM (6)` or `OSI_L6_PRE_COMPUTE (8)`.

1. **Layer 1 — Inbound Network Entry (`LAYER_INGRESS_NIC = 1`, `OSI_L2_DATALINK = 2`)**:
   - **Hooks**: `BPF_PROG_TYPE_XDP` (`xdp_ingress_filter`, returning `XDP_PASS`, with `XDP_FLAGS_SKB_MODE` fallback) + `tracepoint:net:netif_receive_skb` (`include/trace/events/net.h:150`).
   - **Action**: Parse Ethernet (`struct ethhdr`) -> IPv4 (`struct iphdr`, variable `ihl * 4`) -> TCP (`struct tcphdr`) headers with strict `if ((void *)(hdr + 1) > data_end) return XDP_PASS;` bounds checks. Enforce **Loopback Server-Role Direction Guard** (`bpf_ntohs(tcp->dest) == target_port`; ignore loopback reflection packets where `sport == target_port`), **Payload-Gated `req_id` Minting** (`tcp_payload_len = bpf_ntohs(iph->tot_len) - (iph->ihl*4) - (tcp->doff*4)`; do not let a 0-byte handshake/post-request `ACK` overwrite an unconsumed `consumed == 0` `req_id` in `ingress_flow_map[key]`), and **`netif_receive_skb` `skb->data` L3 Pointer & Bidirectional L2 Deduplication** (per `net/core/dev.c:5606-5626`, `trace_netif_receive_skb(skb)` at line 5606 runs BEFORE `skb_reset_network_header(skb)` at line 5610 and BEFORE `do_xdp_generic()` at line 5626! Therefore, in `netif_receive_skb`, read `struct iphdr` directly from `skb->data` via `bpf_probe_read_kernel(&data, sizeof(data), &skb->data)`, and enforce `if (state->xdp_ts != 0 && state->consumed == 0)` deduplication in **BOTH** `xdp_ingress_filter` and `tracepoint:net:netif_receive_skb`). Emit `LAYER_INGRESS_NIC` (`call_depth = OSI_L2_DATALINK`).
   - **Critical Kernel Rule (`bpf_get_current_pid_tgid.md`)**: NEVER call `bpf_get_current_pid_tgid()` inside XDP/TC hooks.

2. **Layer 2 — Kernel Network Stack Ingress (`LAYER_KERNEL_NET = 2`, `OSI_L3_IP = 3` & `OSI_L4_TCP = 4`)**:
   - **Hooks**:
     - `kprobe__ip_rcv`: `int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)` (`net/ipv4/ip_input.c:552`, **`PT_REGS_PARM1(ctx) = skb`**).
     - `kprobe__tcp_v4_rcv`: `int tcp_v4_rcv(struct sk_buff *skb)` (`net/ipv4/tcp_ipv4.c:1945`, **`PT_REGS_PARM1(ctx) = skb`**).
     - `tracepoint:tcp:tcp_retransmit_skb` (`include/trace/events/tcp.h:35`, where `args->sport`/`args->dport` are **already host byte order** via `ntohs()` and `args->saddr`/`args->daddr` are `__u8[4]` arrays; check **BOTH** `args->dport == target_port` in `ingress_flow_map` and `args->sport == target_port` in `egress_flow_map` for server response retransmissions) & `tracepoint:skb:kfree_skb` (`include/trace/events/skb.h:24`, filter **`args->reason > SKB_DROP_REASON_NOT_SPECIFIED (2)`** per `dropreason-core.h:129-138` and resolve flow via `skb_egress_map[(u64)args->skbaddr]`, `args->rx_sk`, or `(struct sk_buff *)args->skbaddr`).
   - **Action**:
     - **CRITICAL `kprobe__ip_rcv` / `kprobe__ipv6_rcv` Verifier & L4 Offset Rule**: In `BPF_PROG_TYPE_KPROBE`, `skb->head` is an untrusted kernel pointer; always use `bpf_probe_read_kernel(&head, sizeof(head), &skb->head)` and `bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header)`. At `ip_rcv` entry (`ip_input.c:552`) and `ipv6_rcv` entry (`ip6_input.c:302`), `ip_rcv_core()` / `ip6_rcv_core()` have NOT run yet, so `skb->transport_header` is uninitialized! Read `iph` from `head + net_off` via `bpf_probe_read_kernel`, and compute `u16 trans_off = net_off + ((iph.ihl & 0x0f) * 4);` (or `net_off + sizeof(struct ipv6hdr)` in `ipv6_rcv`) to read `tcph` from `head + trans_off`.
     - Verify `dport == target_port`, look up `ingress_flow_map` (minting fallback `req_id` for loopback traffic when `tcp_payload_len > 0` or `consumed == 1`), record `ip_rcv_ts` (`OSI_L3_IP`) and `tcp_rcv_ts` (`OSI_L4_TCP`), flag retransmissions (`FLAG_TCP_RETRANSMIT`) or real drops (`FLAG_SKB_DROP` when `args->reason > 2`), and emit `LAYER_KERNEL_NET`.
   - **Critical Kernel Rule (*BPF Performance Tools* Section 10.1.4)**: `ip_rcv` and `tcp_v4_rcv` run in `NET_RX_SOFTIRQ` interrupt context. Never filter by `PID`; correlate via the 4-tuple in `ingress_flow_map`.

3. **Layer 3 — Socket Receive Queue, Kernel-to-User Memory Copy & Page Faults (`LAYER_USER_ENTRY = 3`, `OSI_L4_SOCKET = 5` & `OSI_L5_SYSCALL_MEM = 6`)**:
   - **Hooks**:
     - `kprobe__tcp_recvmsg` & **`kretprobe__tcp_recvmsg`**: `int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len)` (`net/ipv4/tcp.c:2742`, **`PT_REGS_PARM1(ctx) = sk`, `PT_REGS_RC(ctx) = int copied` on return**).
     - `tracepoint:syscalls:sys_enter_read` / `sys_enter_recvfrom`.
     - `tracepoint:skb:skb_copy_datagram_iovec` (`include/trace/events/skb.h:76`, `net/core/datagram.c:534`) + `kprobe__skb_copy_datagram_iter` & **`kretprobe__skb_copy_datagram_iter`** (`net/core/datagram.c:531-537`).
     - `kprobe__handle_mm_fault`: `vm_fault_t handle_mm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags, struct pt_regs *regs)` (`mm/memory.c:5313`) + `tracepoint:kmem:mm_page_alloc` (`vmlinux.h:118284`). *(Note: `exceptions:page_fault_user` is x86-only and does NOT exist on Rocky 9.8 `aarch64`)*.
   - **Action (Two-Stage Skb-to-Uprobe Bridge, Blocking `sk_wait_data` Return Binding, Read-Only `zero_ctx_map[0]` Template & `sk->__sk_common` Normalization)**:
     - First enforce `sk->__sk_common.skc_num == target_port` (excluding loopback client `curl` sockets). Initialize `active_ctx_map[tid]` by passing the **strictly read-only** `zero_ctx_map[0]` template to `active_ctx_map.update(&tid, zero_template)` first, then looking up `ctx = active_ctx_map.lookup(&tid)` and mutating `ctx` in-place (NEVER mutate `zero_ctx_map[0]` directly or dirty fields will leak across threads on the same CPU core!).
     - Save `ctx->active_sk_ptr = (u64)sk`. Because a blocking/Keep-Alive server thread enters `tcp_recvmsg` (`tcp.c:2742`) and sleeps inside `sk_wait_data()` (`tcp.c:2638`) *before* the client's packet arrives at `tcp_v4_rcv`, perform dual-stage binding: if `ingress_flow_map[key]` already has `state->consumed == 0` at `kprobe__tcp_recvmsg` entry, bind immediately; otherwise bind at **`kretprobe__tcp_recvmsg`** (`int copied = PT_REGS_RC(ctx) > 0`) using `ctx->active_sk_ptr`, recording actual received bytes (`ev->ip = (u64)copied`, NOT the user buffer capacity `PARM3 = len`) and `sk_rcvbuf` dwell time (`now - state->tcp_rcv_ts`), and pre-publishing `{req_id, wakeup_ts = now, waker_tid = tid, claimed = 0}` into the 8-slot FIFO `pending_handoff_map[tgid]`.
     - **Multi-Protocol Key Normalization**: For IPv4 and Dual-Stack IPv4-mapped IPv6 sockets (`skc_daddr != 0`), normalize `key = { .saddr = skc_daddr, .daddr = skc_rcv_saddr, .sport = bpf_ntohs(skc_dport), .dport = skc_num, .proto = IPPROTO_TCP, .family = AF_INET (2) }`; for pure IPv6 (`skc_family == AF_INET6 && skc_daddr == 0`), XOR-fold `skc_v6_daddr.in6_u.u6_addr32[0..3]` and `skc_v6_rcv_saddr.in6_u.u6_addr32[0..3]`; for unconnected UDP sockets (`udp_recvmsg` at `udp.c:1938`), extract client IP/port from `msg->msg_name` in `kretprobe__udp_recvmsg` (with `{ .daddr = 0, .dport = skc_num, .proto = IPPROTO_UDP }` fallback); for `AF_UNIX`, normalize `unix_stream_sendmsg` as `{saddr=(u32)(u64)sk, daddr=(u32)(u64)unix_sk(sk)->peer}` and `unix_stream_recvmsg` as `{saddr=(u32)(u64)unix_sk(sk)->peer, daddr=(u32)(u64)sk}`.
     - **Post-Copy `OSI_L5_SYSCALL_MEM (6)` Emission**: Because `trace_skb_copy_datagram_iovec` (`datagram.c:534`) fires *before* `__skb_datagram_iter(..., simple_copy_to_iter, ...)` (`datagram.c:535`), record `ctx->copy_enter_ts = now; ctx->copied_bytes += args->len;` on entry, let `kprobe__handle_mm_fault` increment `ctx->page_faults++` in-place during the copy, and emit the single `OSI_L5_SYSCALL_MEM` (`layer_type = LAYER_USER_ENTRY`, `call_depth = 6`) event at **`kretprobe__skb_copy_datagram_iter` (or `kretprobe__tcp_recvmsg`)** with `duration_ns = now - ctx->copy_enter_ts` and `ev->ip = ((u64)ctx->page_faults << 32) | (u32)ctx->copied_bytes`.

4. **Layer 4 — Pre-Compute Scheduler Gate (`OSI_L6_PRE_COMPUTE = 8`) & User-Space ALU Execution (`LAYER_USER_FUNC = 4`, `OSI_L7_APP = 7`)**:
   - **Hooks**:
     - `tracepoint:syscalls:sys_enter_futex` & `tracepoint:syscalls:sys_exit_futex` (extracting opcode via `(u32)ctx->args[1] & 0x7f` under `#ifdef KRAY_BPF_CORE` per `struct trace_event_raw_sys_enter` in `vmlinux.h:119889`, or `(u32)args->op & 0x7f` under BCC; filtering wait ops `FUTEX_WAIT=0`/`FUTEX_WAIT_BITSET=9`/`FUTEX_LOCK_PI=6`/`FUTEX_WAIT_REQUEUE_PI=11` vs wake/requeue ops `FUTEX_WAKE=1`/`FUTEX_WAKE_BITSET=10`/`FUTEX_REQUEUE=3`/`FUTEX_CMP_REQUEUE=4`/`FUTEX_WAKE_OP=5`/`FUTEX_UNLOCK_PI=7`/`FUTEX_CMP_REQUEUE_PI=12`)
     - `tracepoint:sched:sched_process_fork` (`include/trace/events/sched.h:358`, `args->parent_pid` & `args->child_pid`), `tracepoint:sched:sched_waking` (`include/trace/events/sched.h:170`, guaranteed waking context), & `tracepoint:sched:sched_wakeup` (`include/trace/events/sched.h:178`, runqueue enqueue)
     - `tracepoint:sched:sched_switch`: `TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next, unsigned int prev_state)` (`include/trace/events/sched.h:222`)
     - `tracepoint:block:block_rq_insert` (`block.h:238`), `tracepoint:block:block_rq_issue` (`block.h:252`, if `inflight_bio_map[bkey]` already exists from `block_rq_insert`, preserve user thread `bstate->tid` and `bstate->req_id` when `block_rq_issue` runs on an async `kblockd` `kworker` thread and only update `bstate->issue_ts = now`) & `tracepoint:block:block_rq_complete` (`include/trace/events/block.h:167`, look up `active_ctx_map.lookup(&bstate->tid)` in SoftIRQ context and compute bytes as `(u64)args->nr_sector * 512`)
     - Dynamic `uprobe` / `uretprobe` (`trace_uprobe_entry`, `trace_uprobe_return`)
   - **Action**:
     - **L6 Pre-Compute Gate (`OSI_L6_PRE_COMPUTE = 8`, emitted with `layer_type = LAYER_USER_ENTRY = 3`) & 2-Tier Thread-Pool Handoff**:
       1) **Tier 1 (Sleeping Worker)**: In `tracepoint:sched:sched_waking` (guaranteed to run in `waker_tid` context even on SMP cross-CPU wakeups; read `u32 target_tid = args->pid;` from `TP_STRUCT__entry`), if `waker_tid` holds an active `req_id` in `active_ctx_map`, initialize `active_ctx_map[target_tid]` via read-only `zero_ctx_map[0]`, copy context with `parent_tid = waker_tid`, `wakeup_ts = now`, `prev_cpu_id = bpf_get_smp_processor_id()`, `flags |= FLAG_THREAD_HANDOFF`, and mark the corresponding slot in `pending_handoff_map[tgid]` as `claimed = 1`.
       2) **Tier 2 (Already-Awake `TASK_RUNNING` Worker Fallback via 8-Slot FIFO `pending_handoff_map`)**: Because `tcp_recvmsg` pre-publishes the handoff slot into the 8-slot per-TGID ring `pending_handoff_map[tgid]` (and `sys_enter_futex` wake/requeue ops refresh `wakeup_ts = now`), concurrent requests (`TEST-03`) never overwrite each other and `glibc` user-space condvar fastpaths (`__wrefs == 0`) are covered. If a worker thread in the same `tgid` (`tid != waker_tid`) was already `TASK_RUNNING` (so `sched_waking` did not fire), it claims `ring->slots[ring->read_idx & 7]` (`claimed = 1; ring->read_idx++;`) in FIFO order upon `sys_exit_futex` or its first `uprobe` entry, preserving `parent_tid = waker_tid` and `FLAG_THREAD_HANDOFF` 100% of the time.
       3) In `tracepoint:sched:sched_switch` (accessing `TP_STRUCT__entry` fields **`args->prev_pid`, `args->next_pid`, `args->prev_state`**, or `prev->pid`/`next->pid` in `tp_btf`), record `ctx->off_cpu_enter_ts = now;` when `args->prev_pid == tid`. When `args->next_pid == tid` (thread dispatched onto CPU ALU), compute `u64 runq_ns = ctx->wakeup_ts ? (now - ctx->wakeup_ts) : 0;` and `u64 total_off_cpu_ns = ctx->off_cpu_enter_ts ? (now - ctx->off_cpu_enter_ts) : runq_ns;`. Emit **`ev->duration_ns = (ctx->call_depth == 0) ? runq_ns : total_off_cpu_ns`** (so in-function Off-CPU sleep duration is never lost when `wakeup_ts != 0`!), update `ctx->acc_off_cpu_ns += total_off_cpu_ns`, and **immediately reset `ctx->off_cpu_enter_ts = 0; ctx->wakeup_ts = 0; ctx->futex_enter_ts = 0;`** so stale timestamps never leak into subsequent context switches.
     - **L7 On-CPU ALU vs Off-CPU & Storage Block I/O (`LAYER_USER_FUNC = 4`, `OSI_L7_APP = 7`) — `fn_entry_ip` Backup & Underflow Guard**:
       - On `uprobe` entry: index with `u32 depth = ctx->call_depth & (MAX_CALL_DEPTH - 1);`, save **`ctx->fn_entry_ip[depth] = PT_REGS_IP(ctx);`**, `ctx->fn_entry_ts[depth] = now;`, `ctx->fn_off_cpu_snap[depth] = ctx->acc_off_cpu_ns;`, increment `call_depth` (`< MAX_CALL_DEPTH`), and emit `is_return = 0` with `duration_ns = ctx->fn_off_cpu_snap[depth]`.
       - On `uretprobe` return: **first guard against `u8` underflow (`if (ctx->call_depth == 0) return 0;`)**, decrement `ctx->call_depth--`, index with `u32 depth = ctx->call_depth & (MAX_CALL_DEPTH - 1);`, set **`ev->ip = ctx->fn_entry_ip[depth]`** (never use `PT_REGS_IP(ctx)` in `uretprobe` because the kernel replaces it with the `[uprobes]` trampoline address!), preserve `ev->parent_tid = ctx->parent_tid` intact, and compute `duration_ns = now - ctx->fn_entry_ts[depth]`. User-space (`tracer_agent.py`) subtracts the sum of direct child `OSI_L5_SYSCALL_MEM`/`OSI_L6_PRE_COMPUTE` wait events inside `[t_entry, t_return]` from `total_fn_duration_ns` to yield exact `pure_on_cpu_compute_ms` vs `off_cpu_io_wait_ms`.

5. **Layer 5 — Socket Send Queue & Application Exit (`LAYER_USER_EXIT = 5`, `OSI_L5_SYSCALL_MEM = 6` & `OSI_L4_SOCKET = 5`)**:
   - **Hooks**: `tracepoint:syscalls:sys_enter_write` / `sys_exit_write` and `kprobe__tcp_sendmsg` (`net/ipv4/tcp.c:1510`, **`PT_REGS_PARM1(ctx) = sk`, `PT_REGS_PARM3(ctx) = size`**) / **`kretprobe__tcp_sendmsg`** *(use kernel `kretprobe`, NOT user-space `uretprobe`, for kernel symbol `tcp_sendmsg`)*.
   - **Action**: Verify `sk->__sk_common.skc_num == target_port`, look up `active_ctx_map[tid]`, set `ctx->in_target_sendmsg = 1`, construct the outbound `egress_key = { .saddr = skc_rcv_saddr, .daddr = skc_daddr, .sport = skc_num, .dport = bpf_ntohs(skc_dport), .proto = IPPROTO_TCP, .family = skc_family }`, bind `{req_id, sendmsg_ts = now, pid, tid, pkt_len = size}` into `egress_flow_map[egress_key]`, emit `LAYER_USER_EXIT` (`call_depth = OSI_L4_SOCKET`), and **clear `active_ctx_map.delete(&tid)` inside `kretprobe__tcp_sendmsg` (ONLY when `ctx->in_target_sendmsg == 1`; NEVER delete on generic `sys_exit_write` which may be stdout/file logging) to prevent zombie `req_id` bleed across HTTP Keep-Alive requests**.

6. **Layer 6 — Outbound Kernel L4/L3/L2 Network Exit (`LAYER_EGRESS_NIC = 6`, `OSI_L4_TCP = 4`, `OSI_L3_IP = 3` & `OSI_L2_DATALINK = 2`)**:
   - **Hooks**:
     - `kprobe____tcp_transmit_skb`: `static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)` (`net/ipv4/tcp_output.c:1238`, **`PT_REGS_PARM1(ctx) = sk`, `PT_REGS_PARM2(ctx) = skb`** — *Note: `tcp_transmit_skb` at line 1420 is compiler-inlined and absent from `/proc/kallsyms`; always attach to `__tcp_transmit_skb`*).
     - `kprobe__ip_output`: `int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)` (`net/ipv4/ip_output.c:426`, **`PT_REGS_PARM1(ctx) = net`, `PT_REGS_PARM2(ctx) = sk`, `PT_REGS_PARM3(ctx) = skb`**).
     - `tracepoint:net:net_dev_queue` (`include/trace/events/net.h:143`) -> `tracepoint:net:net_dev_xmit` (`include/trace/events/net.h:71`).
   - **Action**: At `kprobe____tcp_transmit_skb` entry, `skb` L3/L4 headers are not populated yet, so construct `egress_key` directly from `PARM1` (`sk->__sk_common`), look up `egress_flow_map[egress_key]`, immediately bind **`skb_egress_map[(u64)skb] = egress_key`**, and emit L4 TCP transmit (`OSI_L4_TCP`). Then `kprobe__ip_output` (`PARM3 = skb`), `tracepoint:net:net_dev_queue` (`args->skbaddr` -> `state->qdisc_enq_ts = now`), and `tracepoint:net:net_dev_xmit` (`args->skbaddr` -> safe lookup via `skb_egress_map[(u64)args->skbaddr]` without dereferencing potentially freed `skb->head`, computing `qdisc_delay_ns = now - state->qdisc_enq_ts`, `OSI_L2_DATALINK`, `rc == 0`) emit L3/L2 `LAYER_EGRESS_NIC` events and delete the flow state.

---

# SHARED BINARY ABI & KERNEL MAP DEFINITIONS (`tracer_kernel.c` & `tracer_agent.py`)

```c
// Target Architecture Guard for Rocky Linux 9.8 aarch64 (with x86_64 fallback)
#if defined(__aarch64__) || !defined(__x86_64__)
#ifndef __TARGET_ARCH_arm64
#define __TARGET_ARCH_arm64
#endif
#else
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif
#endif

#define MAX_CALL_DEPTH 16

enum kray_layer_e {
    LAYER_INGRESS_NIC = 1,
    LAYER_KERNEL_NET  = 2,
    LAYER_USER_ENTRY  = 3,
    LAYER_USER_FUNC   = 4,
    LAYER_USER_EXIT   = 5,
    LAYER_EGRESS_NIC  = 6
};

enum kray_osi_layer_e {
    OSI_L2_DATALINK    = 2,  // NIC DMA / XDP / netif_receive_skb / Qdisc / net_dev_xmit
    OSI_L3_IP          = 3,  // IPv4 Routing & Netfilter (ip_rcv / ip_output)
    OSI_L4_TCP         = 4,  // TCP Transport (tcp_v4_rcv / __tcp_transmit_skb / tcp_retransmit_skb / kfree_skb)
    OSI_L4_SOCKET      = 5,  // Socket Buffer Queue (sk_rcvbuf tcp_recvmsg / sk_sndbuf tcp_sendmsg)
    OSI_L5_SYSCALL_MEM = 6,  // Syscall / skb_copy_datagram_iovec / handle_mm_fault / block_rq_issue
    OSI_L7_APP         = 7,  // Compute Unit (ALU) On-CPU User Function & Stripped .so Execution
    OSI_L6_PRE_COMPUTE = 8   // Pre-Compute Gate: Futex Lock + CPU Runqueue (sched_wakeup->sched_switch) + Core Dispatch
};

enum kray_flags_e {
    FLAG_NONE            = 0x00,
    FLAG_THREAD_HANDOFF  = 0x01,  // Cross-thread wakeup/fork handoff
    FLAG_STRIPPED_SYMBOL = 0x02,  // Stripped binary/library offset
    FLAG_TCP_RETRANSMIT  = 0x04,  // TCP retransmission detected
    FLAG_SKB_DROP        = 0x08,  // Kernel skb drop detected (kfree_skb)
    FLAG_TCP_SYN         = 0x10,
    FLAG_TCP_ACK         = 0x20,
    FLAG_TCP_PSH         = 0x40,
    FLAG_TCP_FIN         = 0x80
};

// 16-Byte Hot-Reloadable Runtime Configuration Struct (Zero Recompile)
struct __attribute__((packed)) kray_runtime_cfg_t {
    u32 target_pid;       // [Bytes 0..3]   Dynamic target TGID (falls back to __TARGET_PID__ if 0)
    u16 target_port;      // [Bytes 4..5]   Dynamic target port in host byte order (0 = All ports 0..65535)
    u8  capture_enabled;  // [Byte  6]      1: Active, 0: Paused
    u8  filter_flags;     // [Byte  7]      [Bits 0..3]: Proto mask (0=All,1=TCP,2=UDP,4=ICMP/ARP,8=UNIX/TLS); [Bits 4..7]: Layer mask (0=All)
    u64 config_epoch;     // [Bytes 8..15]  Monotonic version counter incremented on REST/MCP update
}; // Exactly 16 Bytes

// 64-Byte Shared Telemetry Event Struct
struct __attribute__((packed)) kray_event_t {
    u64 req_id;        // [Bytes 0..7]   Unique 64-bit correlated request ID
    u64 ip;            // [Bytes 8..15]  Instruction Pointer (or encoded pkt_len/cpu_id/hook metadata)
    u64 timestamp;     // [Bytes 16..23] bpf_ktime_get_ns() monotonic nanoseconds
    u64 duration_ns;   // [Bytes 24..31] Stage delta, runqueue latency, block I/O wait, or function duration in ns
    u32 pid;           // [Bytes 32..35] Process ID (TGID)
    u32 tid;           // [Bytes 36..39] Thread ID (PID)
    u32 parent_tid;    // [Bytes 40..43] Dispatcher/Waker TID if handed off across threads (0 otherwise)
    u32 src_ip;        // [Bytes 44..47] IPv4 Source Address (network byte order)
    u32 dst_ip;        // [Bytes 48..51] IPv4 Destination Address (network byte order)
    u16 src_port;      // [Bytes 52..53] Source Port (host byte order)
    u16 dst_port;      // [Bytes 54..55] Destination Port (host byte order)
    u8  layer_type;    // [Byte  56]     1..6 (enum kray_layer_e)
    u8  is_return;     // [Byte  57]     0: Entry / Point Event, 1: Function Return (uretprobe)
    u8  call_depth;    // [Byte  58]     Call depth (0..15) ONLY when layer_type==LAYER_USER_FUNC; OSI layer (2,3,4,5,6,8) when layer_type!=LAYER_USER_FUNC
    u8  flags;         // [Byte  59]     Bitmask (enum kray_flags_e)
    u32 drop_count;    // [Bytes 60..63] Cumulative ring-buffer drop counter snapshot
}; // Exactly 64 Bytes
```

Maps in `tracer_kernel.c`:
- `BPF_ARRAY(runtime_config_map, struct kray_runtime_cfg_t, 1);`
- `BPF_LRU_HASH(ingress_flow_map, struct flow_key_t, struct flow_state_t, 8192);`
- `BPF_LRU_HASH(active_ctx_map, u32, struct tid_ctx_t, 8192);`
- `BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1);` /* Strictly READ-ONLY all-zero template to avoid >400B struct on 512B BPF stack; never mutate in-place! */
- `BPF_LRU_HASH(pending_handoff_map, u32 /* tgid */, struct handoff_ring_t, 1024);` /* 8-slot per-TGID FIFO bridge when worker thread is already TASK_RUNNING */
- `BPF_LRU_HASH(egress_flow_map, struct flow_key_t, struct flow_state_t, 8192);`
- `BPF_LRU_HASH(skb_egress_map, u64, struct flow_key_t, 8192);`
- `BPF_LRU_HASH(inflight_bio_map, struct bio_key_t, struct bio_state_t, 4096);`
- `BPF_RINGBUF_OUTPUT(events, 1 << 16);`
- `BPF_ARRAY(drop_cnt_map, u64, 1);`

---

# USER-SPACE RUNTIME, MULTI-PROTOCOL / ALL-PORT DISCOVERY, SYMBOLICATION, VISUALIZATION & SERVICE GATEWAYS (`tracer_agent.py`)

1. **CLI Flags**:
   `--mode {live,simulate}`, `--ui {none,web,tui}`, `--serve {none,mcp,rest}`, `--net-layer {all,l2,l3,l4,socket,syscall,sched,l7}`, `--proto {all,tcp,udp,icmp,arp,ipv4,ipv6,unix,tls}`, `--discover-ports`, `--ui-port <INT>`, `--html-out <PATH>`, `--pid <INT>`, `--binary <PATH>`, `--lib <PATH>`, `--port <PORT_SPEC>` (`8080`, `0`/`all` for `0..65535`, or comma-separated multi-port chain `80,443,3000,5432,8080`), `--iface <STR>`, `--out <PREFIX>`, `--ai-report <PATH>`, `--focus-symbol <REGEX>`, `--uprobe-offset <MODULE:0xOFFSET>`, `--simulate-drops <INT>`, `--fast-mode`, `--compare <BASELINE_JSON> <PATCHED_JSON>`.
2. **Multi-Protocol & Full Port Range (`0..65535`) Discovery & Kernel Hook Mapping on Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`)**:
   - **Port Range Classification (`--discover-ports`)**: Parse `/proc/net/{tcp,tcp6,udp,udp6,unix}` + `/proc/<pid>/fd/*` socket inodes directly (with `ss -tulnp`/`ss -xlnp` as optional enrichment when `iproute2` is installed) and classify all active ports across `0..65535` into Wildcard (`0`), Well-Known/Privileged (`1..1023`, `PROT_SOCK=1024` in `include/net/sock.h:1586`, e.g., `:22 sshd`, `:53 dns`, `:80/:443 nginx`, `:111 rpcbind`, `:323 chronyd`), Registered Service Ports (`1024..49151`, e.g., `:3000 Next.js`, `:5432 PostgreSQL`, `:6379 Redis`, `:8080 Spring/C++`), and Ephemeral/Dynamic Ports (`32768..65535`, `ip_local_ports.range` in `net/ipv4/af_inet.c:1865`).
   - **Multi-Protocol Kernel Hooks (`--proto`)**:
     - `tcp`: `kprobe:tcp_v4_rcv` (`net/ipv4/tcp_ipv4.c:1945`), `kprobe:tcp_v6_rcv` (`net/ipv6/tcp_ipv6.c:1582`), `kprobe:tcp_recvmsg` & `kretprobe:tcp_recvmsg` (`net/ipv4/tcp.c:2742`), `kprobe:tcp_sendmsg` & `kretprobe:tcp_sendmsg` (`net/ipv4/tcp.c:1510`), `kprobe:__tcp_transmit_skb` (`net/ipv4/tcp_output.c:1238`)
     - `udp`: `kprobe:udp_rcv` (`net/ipv4/udp.c:2672`), `kprobe:udp_recvmsg` & `kretprobe:udp_recvmsg` (`net/ipv4/udp.c:1868-1945`, reading peer `sockaddr_in` from `msg->msg_name` at line 1938 or `{ .daddr = 0, .dport = skc_num, .proto = IPPROTO_UDP }` fallback), `kprobe:udp_sendmsg` (`net/ipv4/udp.c:1069`)
     - `ipv4` / `ipv6`: `kprobe:ip_rcv` (`net/ipv4/ip_input.c:552`) ↔ `kprobe:ip_output` (`net/ipv4/ip_output.c:426`), `kprobe:ipv6_rcv` (`net/ipv6/ip6_input.c:302`, `trans_off = net_off + sizeof(struct ipv6hdr)`) ↔ `kprobe:ip6_output` (`net/ipv6/ip6_output.c:220`)
     - `icmp` / `arp`: `kprobe:icmp_rcv` (`net/ipv4/icmp.c:1200`), `kprobe:arp_rcv` (`net/ipv4/arp.c:943`, reading `ar_sip` at `(u8 *)(arp + 1) + 6` and `ar_tip` at `(u8 *)(arp + 1) + 16` because `ar_sip`/`ar_tip` are `#if 0` in `include/uapi/linux/if_arp.h:151-159`)
     - `unix`: `kprobe:unix_stream_recvmsg` (`net/unix/af_unix.c:2733`, `PT_REGS_PARM1 = struct socket *sock`, `sk = sock->sk`, `peer = unix_sk(sk)->peer`) ↔ `kprobe:unix_stream_sendmsg` (`net/unix/af_unix.c:2053`, `PT_REGS_PARM1 = struct socket *sock`, `sk = sock->sk`, `peer = unix_sk(sk)->peer`)
     - `tls`: `uprobe:libssl.so:SSL_read` / `uretprobe:SSL_read`, `uprobe:libssl.so:SSL_write` / `uretprobe:SSL_write`
3. **3-Tier `/proc/<PID>/maps` + ELF Symbolicator, `.eh_frame` FDE / Call-Target Scanner, C++ `uprobe` Filter & Per-`req_id` Completion State Machine**:
   - Compute runtime relative file offset: `rel_offset = (ip - vm_start) + file_offset`, and compute ELF `attach_uprobe` file offset from the executable `PF_X` `PT_LOAD` segment as **`uprobe_file_offset = st_value - seg.p_vaddr + seg.p_offset`**.
   - Resolve via Tier 1 (`.symtab` + C++ demangle + DWARF `addr2line` `file:line` & source snippet) -> Tier 2 (`.dynsym`) -> Tier 3 (for stripped binaries like `strip -x libcrypto_mock.so`, discover internal function entry offsets via **`.eh_frame` FDE `pc_begin` entries** and **`bl`/`callq` branch targets** inside `.dynsym` functions, resolving to `<module_basename>+0x<rel_offset:x>` with `FLAG_STRIPPED_SYMBOL` + `objdump -d` ELF disassembly extraction).
   - **C++ ELF Symbol Filter & `noinline` Target Build (`mock_server.cpp`, `libcrypto_mock.cpp`)**: Build target C++ binaries with `__attribute__((noinline))` and `-g -O0 -fno-inline -fno-omit-frame-pointer`. Exclude compiler/runtime/STL prefixes (`_start`, `__libc_`, `__cxa_`, `__gxx_`, `_ZSt`, `_ZNSt`, `_ZNKSt`, `_GLOBAL__`, `frame_dummy`, `register_tm_clones`, `@plt`) and tiny thunks (`st_size < 16`), cap auto-attached functions at `MAX_AUTO_UPROBES = 64`, and raise `RLIMIT_NOFILE`.
   - **Per-`req_id` Grace Window, Canonical Sort, Top-Level `ai_diagnosis.json` Contract & Drop Counter Aggregation**: After `LAYER_USER_EXIT`, wait for `LAYER_EGRESS_NIC` (`OSI_L2_DATALINK`) or flush after a `50ms` grace window, sort each request's events by `(timestamp, layer_order, is_return)`, compute `final_drop_count = max(max_event_drop_count, bpf_drop_cnt_map[0]) + args.simulate_drops`, and output top-level `ai_diagnosis.json` keys `req_id`, `total_rtt_ms`, `drop_count`, `bottleneck_summary`, `hop_timeline`, `source_code_evidence`, `stripped_assembly_evidence`, and `network_layer_diagnostics`.
4. **4-Tier Graphviz DOT & SVG Generator**:
   - Optional top alert cluster `subgraph cluster_alert_overflow` when `drop_count > 0` (`#ffebee` fill, `#c0392b` border).
   - 4 Tiers: `cluster_tier_ingress`, `cluster_tier_kernel`, `cluster_tier_app` (with nested `cluster_mod_<sanitized_filename>` where non-alphanumeric chars like `.` and `-` are sanitized via `re.sub(r'[^a-zA-Z0-9_]', '_', ...)` -> `cluster_mod_libcrypto_mock_so`), `cluster_tier_egress`.
   - Heatmap colors: Green (`#2ecc71`, `<10%` RTT), Orange (`#f39c12`, `10%..35%`), Crimson (`#e74c3c`, `>35%` bottleneck).
   - Cross-thread handoff edge (`TID A -> TID B`): dashed bold blue (`#2980b9`). Stripped offset node: purple border (`#8e44ad`).
5. **6 MCP Tools (`--serve mcp` over `stdio` and HTTP `POST /mcp`)**:
   - `ebpf_configure_target`, `ebpf_capture_trace`, `ebpf_inspect_network_layers` (`layer`: `all|l2|l3|l4|socket|syscall|sched|l7`, `proto`: `all|tcp|udp|icmp|arp|ipv4|ipv6|unix|tls`), `ebpf_inspect_code_or_asm`, `ebpf_compare_patches`, `ebpf_render_topology`.
6. **Thread-Safe REST API Endpoints (`--serve rest` / `--ui web`, `ThreadingHTTPServer` + `threading.RLock()` + `<500ms` Self-Contained Loopback Trigger)**:
   - `GET /`, `GET /api/v1/health`, `PUT /api/v1/config`, `POST /api/v1/traces`, `GET /api/v1/traces/latest`, `GET /api/v1/network-layers?layer=...&proto=...`, `GET /api/v1/discovery` (ports `0..65535` & active protocols inventory), `GET /api/v1/inspect?target=...`, `POST /api/v1/compare`, `POST /mcp`.

---

# EXPECTED DELIVERABLES & 12 MANDATORY VERIFICATION TESTS (`test_verification_suite.py`)

Deliver production-ready `tracer_kernel.c`, `tracer_agent.py`, `mock_server.cpp`, `libcrypto_mock.cpp`, `test_verification_suite.py`, `test_harness.sh`, and `Dockerfile` passing all 12 automated `pytest` assertions:
- **TEST-01**: C vs Python 64B `kray_event_t` & 16B `kray_runtime_cfg_t` exact `sizeof` and `offsetof` ABI match.
- **TEST-02**: `tracer_kernel.c` Rocky 9.8 `aarch64` reference compliance (`#define __TARGET_ARCH_arm64`, `vmlinux.h` CO-RE guard, `runtime_config_map`, `__tcp_transmit_skb`, `handle_mm_fault`, `skb_copy_datagram_iovec`, `ip_output` `PT_REGS_PARM3=skb`, multi-protocol hooks `udp_rcv`/`ipv6_rcv`/`icmp_rcv`/`unix_stream_recvmsg`, no `bpf_get_current_pid_tgid()` in XDP, `data_end` checks, 6 `BPF_LRU_HASH` maps, `BPF_PERCPU_ARRAY(zero_ctx_map)` & `BPF_RINGBUF_OUTPUT`).
- **TEST-03**: 6-Layer request correlation & multi-request isolation (`req_id #1` vs `req_id #2`).
- **TEST-04**: Worker thread-pool handoff (`TID A -> TID B`, `parent_tid == TID A`, dashed `Thread Handoff` edge in `.dot`).
- **TEST-05**: Stripped shared library (`strip -x libcrypto_mock.so`) fallback to `libcrypto_mock.so+0x<offset>`.
- **TEST-06**: Ring buffer overflow alert banner (`--simulate-drops 42` -> `cluster_alert_overflow` in `.dot`/`.svg`).
- **TEST-07**: 4-Tier cluster structure (`cluster_mod_libcrypto_mock_so`), heatmap coloring (`#2ecc71`, `#f39c12`, `#e74c3c`), and valid `.svg` compilation.
- **TEST-08**: `ai_diagnosis.json` DWARF C++ source snippet (`mock_server.cpp:line`) and stripped ELF assembly (`objdump -d`) extraction.
- **TEST-09**: Adaptive Zoom-In (`--focus-symbol`, `--uprobe-offset`) and Before/After `--compare` benchmark (`>50%` RTT reduction).
- **TEST-10**: Interactive Web Dashboard (`trace_dashboard.html` with 7-layer filter pills, node inspector, 3 tabs) and Terminal TUI (`--ui tui`).
- **TEST-11**: MCP Server (`--serve mcp` 6 tools) & REST API (`/api/v1/*`) `0ms` hot-reload (`config_epoch` increment).
- **TEST-12**: Full 7-Layer Wire-to-PreCompute-to-ALU & Multi-Protocol/Full-Port (`0..65535`) verification (`L2`, `L3`, `L4`, `SOCKET`, `SYSCALL`, `SCHED`, `L7` in `network_layer_diagnostics`, `symmetric_io_verified == True`, `pre_compute_total_ms`, `runq_latency_ms`, `lock_wait_ms`, `prev_cpu_id -> target_cpu_id`, `pure_on_cpu_compute_ms` vs `off_cpu_io_wait_ms`, `--discover-ports` `0..65535` classification, and `--proto {all,tcp,udp,icmp,arp,ipv4,ipv6,unix,tls}` verification).
```


---

# [Book X] 사전 설계 감사, 심화 테스트 엔지니어링 및 서브에이전트 검증 아카이브 전문


---

## Archive Document: `archive/ADVANCED_TEST_ENGINEERING_REPORT.md`

# eBPF-WireToCode-Tracer 테스트 엔지니어링 고도화 리포트 (12대 고도화 기법 적용 기록)

* **작성 일시**: 2026-10-30
* **대상 프로젝트**: `eBPF-WireToCode-Tracer` (`L2~L7 Wire-to-PreCompute-to-ALU` 전구간 추적기)
* **전용 타겟 머신 (UTM VM)**: `ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1`
  * **VM UUID**: `16D7A5BA-5FF8-48DA-AA00-043C3D855974`
  * **OS / 커널**: Rocky Linux release 9.8 (Blue Onyx) / `5.14.0-687.10.1.el9_8.0.1.aarch64`
  * **네트워크 / SSH 별칭**: `192.168.64.14` (`ssh ebpf-wire-to-code-tracer-v2.0.0` 또는 `ssh ebpf-tracer-v2.0.0`)
  * **게스트 호스트네임 / 경로**: `ebpf-wire-to-code-tracer-v2-0-0-rocky9-8` (`/home/rocky/ebpf-wire-to-code-tracer-v2.0.0`)
* **검증 스위트 규모**: 총 **24개 테스트 스위트** (기본 명세 검증 `TEST-01` ~ `TEST-12` + 고도화 엔지니어링 검증 `ADV-TEST-01` ~ `ADV-TEST-12`)
* **최종 검증 결과**: 호스트(macOS) 및 전용 타겟 머신(`Rocky Linux 9.8 aarch64`) 양측 모두 **24 / 24 PASSED (100% 통과)** + **실커널 Verifier `bpftool prog loadall` 42개 훅 전수 로드 성공**

---

## 1. 테스트 고도화를 통해 실제 적발·수정한 핵심 잠재 결함 5건 (Key Defects Caught by Advanced Testing)

테스트 고도화 기법 12종과 전용 타겟 머신(`ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1`) 실커널 Verifier 로드를 적용하는 과정에서 정적 정규식 검사나 단순 단위 테스트로는 발견할 수 없었던 **실제 커널 Verifier 거부 결함 3건 및 고부하 동시성/메모리 결함 2건(총 5건)**을 포착하여 즉시 수정했습니다.

### 적발 결함 A — `publish_handoff_slot()` 인라이닝으로 인한 BPF 512B 스택 프레임 초과 (`ADV-TEST-02` & `ADV-TEST-03` 적발)
* **발견 경위**: [`tracer_kernel.c`](../tracer_kernel.c)를 Rocky Linux 9.8 [`vmlinux.h`](../references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h)와 함께 `clang -target aarch64-linux-gnu -O2 -Wframe-larger-than=512 -Werror=frame-larger-than=`으로 실제 크로스 컴파일하는 순간 컴파일러 에러가 발생했습니다.
  * `kprobe__tcp_recvmsg`: 스택 프레임 크기 **528 Bytes** (BPF 한계 512B 초과)
  * `kretprobe__tcp_recvmsg`: 스택 프레임 크기 **560 Bytes** (BPF 한계 512B 초과)
* **근본 원인**: `struct tid_ctx_t`(>400B)는 `zero_ctx_map`으로 분리했으나, `publish_handoff_slot()` 내부에서 첫 초기화 시 `struct handoff_ring_t init_ring = {};`(**264 Bytes**)를 지역 스택 변수로 선언한 뒤 `kprobe__tcp_recvmsg` 및 `kretprobe__tcp_recvmsg`에 `__always_inline`으로 인라이닝되면서 `struct flow_key_t` 및 소켓 메타데이터 변수들과 합쳐져 512B 한계를 넘었습니다.
* **해결 조치**: [`tracer_kernel.c`](../tracer_kernel.c)에 `BPF_PERCPU_ARRAY(zero_ring_map, struct handoff_ring_t, 1);` 읽기 전용 제로 템플릿 맵을 추가하여 스택 할당을 완전히 제거했습니다. 수정 후 모든 훅 함수의 스택 프레임이 **320 Bytes 이하**(`-Wframe-larger-than=320` 통과)로 줄어들었습니다.

### 적발 결함 B — 16-스레드 동시 REST/MCP 폭격 시 TCP SYN Backlog(`request_queue_size=5`) 포화로 인한 `Connection reset by peer` (`ADV-TEST-09` 적발)
* **발견 경위**: `ADV-TEST-09`에서 `ThreadPoolExecutor(max_workers=16)`로 16개 스레드가 동시에 REST/MCP 서버에 요청을 쏟아부었을 때 `Errno 54: Connection reset by peer`가 발생했습니다.
* **근본 원인**: Python 표준 라이브러리의 `ThreadingHTTPServer`(`socketserver.TCPServer`)는 기본 `request_queue_size = 5`(`listen(5)`)를 사용하여, 6개 이상의 동시 연결 시도가 한꺼번에 도달하면 커널이 SYN 큐 오버플로우로 `RST`를 반환합니다.
* **해결 조치**: [`tracer_agent.py`](../tracer_agent.py)의 `start_background_rest_server`에서 `request_queue_size = 128` 및 `allow_reuse_address = True`를 설정한 `_HighConcurrencyHTTPServer` 서브클래스를 적용하여 16~32 스레드 동시 접속 시에도 드롭 없이 100% 처리되도록 해결했습니다.

### 적발 결함 C — 무기한 트레이스 수집 시 완료 트레이스 딕셔너리 메모리 무한 증가 (`ADV-TEST-10` 적발)
* **발견 경위**: 수천 건의 고속 요청을 연속 주입할 때 `RequestCorrelator._completed` 딕셔너리가 상한 없이 증가할 수 있는 구조적 문제를 확인했습니다.
* **해결 조치**: [`tracer_agent.py`](../tracer_agent.py)의 `RequestCorrelator`에 `MAX_COMPLETED_TRACES = 4096` 상한과 FIFO/LRU 자동 축출 로직, 미완료 고아 요청 정리(`4 * grace_window_ns`), 그리고 결정론적 Knuth 곱셈 해시 기반 `sampling_rate`(`0.0 ~ 1.0`) 필터를 추가했습니다.

### 적발 결함 D — CO-RE Tracepoint `typedef` 별칭 사용 시 `/sys/kernel/btf/vmlinux` BTF 재배치 실패 (`ADV-TEST-12` 실커널 `bpftool prog loadall` 적발)
* **발견 경위**: 전용 타겟 머신(`ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1`)에서 `clang -target bpf`로 빌드한 오브젝트를 `sudo bpftool prog loadall`로 커널에 로드할 때 `libbpf: failed to resolve CO-RE relocation <byte_off> typedef tp_args_net_netif_receive_skb_t.skbaddr` 에러가 발생했습니다.
* **근본 원인**: `vmlinux.h`의 `preserve_access_index`가 활성화된 상태에서 `typedef struct trace_event_raw_... tp_args_...`를 사용하면 Clang이 `typedef` 이름을 기준으로 CO-RE BTF 재배치 레코드를 생성하는데, 실제 커널의 `/sys/kernel/btf/vmlinux`에는 원본 구조체 이름(`struct trace_event_raw_net_dev_template`)만 존재하기 때문입니다.
* **해결 조치**: [`kray_bpf_core_compat.h`](../kray_bpf_core_compat.h)에서 `typedef` 대신 `#define tp_args_... struct trace_event_raw_...` 매크로 치환을 사용하도록 수정하여 커널 BTF 타입명과 100% 일치시켰습니다.

### 적발 결함 E — CO-RE(`libbpf`) 모드에서 Kprobe 다중 인자(`R2`, `R3`) 직접 참조 시 커널 Verifier `R2 !read_ok` 거부 (`ADV-TEST-12` 실커널 적발)
* **발견 경위**: BCC는 `int kprobe__ip_rcv(struct pt_regs *ctx, struct sk_buff *skb)`의 2번째 인자를 자동으로 `PT_REGS_PARM1(ctx)`로 변환하지만, 순수 `clang -target bpf` + `libbpf` 환경에서는 커널이 `BPF_PROG_TYPE_KPROBE`에 오직 `R1 = ctx`만 전달하므로 `skb` 파라미터(`R2`)를 그대로 읽으면 Verifier가 거부합니다.
* **해결 조치**: [`tracer_kernel.c`](../tracer_kernel.c)의 모든 Kprobe 진입부에 `#ifdef KRAY_BPF_CORE` 블록을 두어 `PT_REGS_PARM1(ctx)` ~ `PT_REGS_PARM3(ctx)`에서 인자를 명시적으로 추출하도록 수정했습니다. 수정 즉시 **42개 전체 eBPF 프로그램이 Rocky Linux 9.8 실커널 Verifier를 단 한 건의 경고/오류 없이 통과하여 `/sys/fs/bpf/`에 핀닝**되었습니다.

---

## 2. 적용된 12대 테스트 고도화 기법 상세 명세 (`ADV-TEST-01` ~ `ADV-TEST-12`)

### 기법 [1] 커널 eBPF C 코드 유저스페이스 네이티브 에뮬레이션 하네스 (`ADV-TEST-01`)
* **구현 파일**:
  * [`mock_bpf_runtime.h`](../mock_bpf_runtime.h)
  * [`kernel_sim_harness.c`](../kernel_sim_harness.c)
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_01_native_c_kernel_hook_emulation`)
* **적용 기법**:
  * BPF 맵(`BPF_LRU_HASH`, `BPF_ARRAY`, `BPF_PERCPU_ARRAY`, `BPF_RINGBUF_OUTPUT`)과 커널 헬퍼(`bpf_probe_read_kernel`, `bpf_ktime_get_ns`, `bpf_get_current_pid_tgid`, `bpf_get_smp_processor_id`)를 순수 C11 인메모리 런타임으로 에뮬레이션하여 [`tracer_kernel.c`](../tracer_kernel.c) 원본을 네이티브 공유 라이브러리(`libtracer_kernel_sim.dylib` / `.so`)로 직접 컴파일했습니다.
  * Python `ctypes`를 통해 실제 C 훅 함수들을 직접 호출하고 링버퍼로 방출된 64바이트 `struct kray_event_t`를 회수하여 검증합니다.
* **핵심 검증 항목**:
  * `xdp_ingress_filter` + `tracepoint:net:netif_receive_skb` 중복 진입 시 1개 이벤트로 정확히 중복 제거되는지 확인
  * `kprobe__tcp_v4_rcv`에서 `consumed == 0` 상태일 때 0바이트 순수 ACK 패킷이 기존 `req_id`를 덮어쓰지 않는지 확인
  * `kprobe__tcp_recvmsg` 진입 시점에는 패킷이 없다가 `sk_wait_data()` 대기 중 패킷이 도착했을 때 `kretprobe__tcp_recvmsg`가 `active_sk_ptr`로 지연 바인딩에 성공하는지 확인
  * 중첩 `trace_uprobe_entry`(depth 0, 1) 후 `trace_uprobe_return`에서 커널 `[uprobes]` 트램펄린이 `PT_REGS_IP(ctx)`를 `0x7fffffffe000`으로 덮어썼을 때 `fn_entry_ip[depth]`로 원본 함수 주소를 정확히 복원하는지 확인
  * `sys_exit_write`에서는 `active_ctx_map[&tid]`가 유지되고, 서버 소켓의 `kretprobe__tcp_sendmsg`에서만 정리되는지 확인

---

### 기법 [2] Rocky Linux 9.8 `vmlinux.h` 기반 CO-RE 크로스 컴파일 & ELF 섹션 검증 (`ADV-TEST-02`)
* **구현 파일**:
  * [`kray_bpf_core_compat.h`](../kray_bpf_core_compat.h)
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_02_rocky98_vmlinux_btf_cross_compilation`)
* **적용 기법**:
  * [`references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h`](../references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h) (130,966라인 실제 커널 BTF 헤더)를 인클루드하여 `clang -target aarch64-linux-gnu -std=gnu11 -DKRAY_BPF_CORE -O2`로 [`tracer_kernel.c`](../tracer_kernel.c)를 실제 `aarch64` ELF 재배치 오브젝트(`tracer_kernel_rocky98.o`)로 컴파일합니다.
* **핵심 검증 항목**:
  * `struct sk_buff`, `struct sock`, `struct sock_common`, `struct unix_sock`, `struct trace_event_raw_*` 등 모든 커널 구조체 필드명과 오프셋이 Rocky 9.8 커널과 100% 일치하는지 컴파일러 수준에서 검증
  * 생성된 ELF 오브젝트를 `objdump -h`로 파싱하여 `tp/net/netif_receive_skb`, `tp/skb/kfree_skb`, `tp/sched/sched_waking`, `tp/sched/sched_switch`, `tp/block/block_rq_complete`, `.maps`, `license` 등 필수 섹션 생성 확인

---

### 기법 [3] eBPF Verifier 정적 한계 감사 테스트 — 512B 스택 상한 / 루프 Unroll / Null 가드 (`ADV-TEST-03`)
* **구현 파일**:
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_03_ebpf_verifier_stack_512b_loop_and_null_guards`)
* **적용 기법**:
  * 컴파일러 플래그 `-Wframe-larger-than=320 -Werror=frame-larger-than=`을 강제 적용하여 모든 BPF 함수의 스택 사용량이 커널 한계(512B)보다 훨씬 낮은 **320B 이하**임을 보장합니다.
  * 소스 AST/패턴 분석을 통해 `struct tid_ctx_t` 및 `struct handoff_ring_t`의 스택 변수 선언이 0건임을 확인하고, 모든 `for (` 루프 직전에 `#pragma unroll`이 명시되어 있는지 전수 검사합니다.

---

### 기법 [4] Raw 패킷 바이트 프레임 합성(VLAN / QinQ / IPv4 옵션) & 기형 패킷 퍼징 (`ADV-TEST-04`)
* **구현 파일**:
  * [`tracer_kernel.c`](../tracer_kernel.c) (`xdp_ingress_filter` 2단 VLAN `0x8100`/`0x88A8` 언롤 파서)
  * [`kernel_sim_harness.c`](../kernel_sim_harness.c)
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_04_synthetic_raw_packet_vlan_ipv6_arp_and_malformed_fuzzing`)
* **적용 기법**:
  * `struct.pack`으로 실제 네트워크 와이어 바이트열을 합성하여 C `xdp_ingress_filter` 및 멀티 프로토콜 훅에 직접 주입합니다.
* **핵심 검증 항목**:
  * **기형(Malformed) 패킷 방어**: 5바이트 이더넷 프레임, 잘린 802.1Q VLAN 헤더, 잘린 IPv4 헤더, 조작된 `ihl=2`(<20B) 및 `ihl=15`(패킷 끝 초과), 잘린 TCP 헤더 주입 시 메모리 침범 없이 `XDP_PASS`를 반환하고 이벤트를 방출하지 않는지 검증
  * **복합 캡슐화 파싱**: 이중 태그 QinQ(`0x88A8` + `0x8100`) + IPv4 옵션 헤더(`ihl=8`, 32바이트) + TCP 패킷에서 정확한 포트(53000 -> 8080)와 페이로드를 추출하는지 검증
  * **멀티 프로토콜 C 훅 실행**:
    * `kprobe__arp_rcv`: `(u8 *)(arp + 1) + 6` 및 `+ 16` 오프셋에서 Sender/Target IP 추출
    * `kprobe__icmp_rcv`: `sport = (type << 8) | code`, `dport = ntohs(echo.id)` 인코딩
    * `kprobe__udp_rcv` -> `kprobe__udp_recvmsg` -> `kretprobe__udp_recvmsg`: 비연결(Unconnected) UDP 서버 소켓의 `port_key` 폴백 및 `msg->msg_name` `sockaddr_in` 추출
    * `kprobe__ipv6_rcv` -> `kprobe__tcp_v6_rcv`: 128비트 IPv6 주소의 32비트 XOR 폴딩 일치성
    * `populate_sock_flow_key`: Dual-Stack `AF_INET6` `::ffff:127.0.0.1` 소켓(`skc_daddr != 0`)의 `AF_INET`(2) 정규화
    * `kprobe__unix_stream_sendmsg` -> `kprobe__unix_stream_recvmsg`: `sk <-> peer` 포인터 매칭
    * `tracepoint:skb:kfree_skb`: `reason <= 2`(`SKB_CONSUMED`) 무시 및 `reason > 2` 드롭 시 Stage 2(`rx_sk`) / Stage 3(`skb->head`) 역추적 검증

---

### 기법 [5] 상태 머신 카오스(Chaos) & 속성 기반 퍼징(Property-Based Fuzzing) (`ADV-TEST-05`)
* **구현 파일**:
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_05_state_machine_chaos_and_property_based_fuzzing`)
* **적용 기법**:
  * 고정 시드(`random.Random(20261030)`) 기반 카오스 생성기로 **250개의 동시 요청(약 2,000개 이벤트)**을 생성한 뒤 전체 리스트를 무작위 셔플(`rng.shuffle`)하여 멀티코어 타임스탬프 역전, 20%의 비정상 종료(`LAYER_EGRESS_NIC` 누락), `call_depth` 0~31 변동을 주입합니다.
* **핵심 검증 항목**:
  * 250개 요청 전수가 누락 없이 완료 처리되며, 서로 다른 `req_id` 간 이벤트 혼입(Cross-talk)이 0건이고, 모든 트레이스가 `(layer_type, timestamp, is_return)` 정규 순서로 정렬됨을 검증합니다.

---

### 기법 [6] 8-슬롯 스레드 핸드오프 링큐(`handoff_ring_t`) 경합 & 랩어라운드 테스트 (`ADV-TEST-06`)
* **구현 파일**:
  * [`kernel_sim_harness.c`](../kernel_sim_harness.c) (`sim_publish_handoff_burst`, `sim_claim_handoff_via_futex_exit`)
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_06_eight_slot_handoff_ring_contention_and_wraparound`)
* **적용 기법**:
  * Acceptor 스레드(`tid=7000`)가 8개씩 3배치(총 **24개 연속 요청**, 8-슬롯 링버퍼 **3회 완전 순환 래핑**)를 발행하고, 8개 워커 스레드가 `sys_exit_futex`와 `trace_uprobe_entry`를 교차 사용하여 슬롯을 가져가는 경합 상황을 C 코드로 직접 실행합니다.
* **핵심 검증 항목**:
  * `waker_tid == tid`인 Acceptor 자신이 슬롯을 잘못 가져가는 현상이 차단되는지 확인
  * 24개 요청 모두가 `write_idx & 7` 및 `read_idx & 7` 순환 래핑을 거치면서도 정확한 FIFO 순서로 1:1 인계되는지 확인

---

### 기법 [7] ELF / DWARF / PIE ASLR & `aarch64` 64KB 페이지 오프셋 심볼리케이션 스트레스 (`ADV-TEST-07`)
* **구현 파일**:
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_07_elf_dwarf_pie_aslr_and_aarch64_64kb_symbolication`)
* **적용 기법**:
  * 다중 모듈(`mock_server`, `libcrypto_mock.so`, `libc.so.6`)이 포함된 `/proc/<PID>/maps` 텍스트와 `aarch64` 64KB 정렬(`p_vaddr = 0x11000`, `p_offset = 0x1000`) 조건을 주입하고, 160개의 C++ 맹글링/STL/런타임 심볼 후보군을 필터링합니다.
* **핵심 검증 항목**:
  * `compute_uprobe_file_offset`이 64KB 정렬 편차(`0x10000`)를 정확히 보정하는지 확인
  * Tier 1(`.symtab` DWARF 심볼)과 Tier 3(`libcrypto_mock.so+0x1140` + `FLAG_STRIPPED_SYMBOL`) 동시 해석 및 `MAX_AUTO_UPROBES = 64` 상한 캡핑 검증

---

### 기법 [8] 네거티브(Negative) & 결함 주입(Fault-Injection) 경계값 테스트 (`ADV-TEST-08`)
* **구현 파일**:
  * [`mock_bpf_runtime.h`](../mock_bpf_runtime.h) (`g_sim_ringbuf_full`)
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_08_negative_fault_injection_and_boundary_guards`)
* **핵심 검증 항목**:
  1. **링버퍼 100% 포화 결함 주입**: `sim_set_ringbuf_full(1)`을 설정해 모든 `events.ringbuf_reserve()`가 `NULL`을 반환하게 만든 뒤, 수신 이벤트가 0개(`max_event_drop_count == 0`)인 상태에서도 `drop_cnt_map[0]` 카운터(`15`)를 통해 `compute_final_drop_count`가 정확히 15개 드롭을 감지하는지 검증
  2. **트레이서 중간 부착(`Mid-execution attach`) 방어**: `uprobe` 진입 없이 `uretprobe`(`trace_uprobe_return`)만 단독 호출되었을 때 `call_depth == 0` 언더플로우 가드가 작동하여 `call_depth = 255` 오염이나 가짜 이벤트 방출을 차단하는지 검증
  3. **32비트 `lock_wait_ns` 오버플로우 캡핑**: `10,000,000,000 ns`(10초 > `0xFFFFFFFF`)의 Futex 락 대기를 주입했을 때 하위 32비트 절삭 없이 `0xFFFFFFFF`로 안전하게 포화 캡핑되는지 검증
  4. **비정상 API/CLI 입력 방어**: 범위 초과 포트(`-1`, `65536`, `99999`), 깨진 JSON 바디(`{malformed_json`), 존재하지 않는 MCP 도구 호출 시 서버 크래시 없이 HTTP `400` 및 JSON-RPC `-32601` 에러를 반환하는지 검증

---

### 기법 [9] 멀티스레드 동시성(Concurrency) & 핫리로드 스트레스 테스트 (`ADV-TEST-09`)
* **구현 파일**:
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_09_multithreaded_concurrency_and_hot_reload_stress`)
* **적용 기법**:
  * `ThreadPoolExecutor(max_workers=16)`를 사용해 16개 워커 스레드가 동시에 총 **80회의 병렬 작업**(`PUT /api/v1/config` 핫리로드 20회 + `GET /api/v1/network-layers` 20회 + `POST /mcp` 도구 호출 20회 + `RequestCorrelator` 동시 적재/조회 20회)을 수행합니다.
* **핵심 검증 항목**:
  * 데드락이나 패킷 리셋 없이 80개 요청 전수 성공, `config_epoch == 20` 정합성 유지, 동시 부하 상태에서 `p99 < 500ms` 응답 지연 SLA 준수 확인

---

### 기법 [10] 대용량 처리량(Throughput) SLA & `MAX_COMPLETED_TRACES` 메모리 상한 회귀 테스트 (`ADV-TEST-10`)
* **구현 파일**:
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_10_high_throughput_sla_and_lru_memory_cap_regression`)
* **적용 기법**:
  * **5,000개 완결 트레이스(30,000개 이벤트)**를 연속 주입하여 초당 이벤트 처리 속도와 메모리 상한을 측정합니다.
* **핵심 검증 항목**:
  * 처리 속도 `> 20,000 events/sec` 달성 확인
  * 완료된 트레이스 맵 크기가 정확히 `4096`(`MAX_COMPLETED_TRACES`)개로 유지되며 가장 오래된 904개(`0..903`)가 축출되고 최신 4096개(`904..4999`)가 보존되는지 확인
  * `sampling_rate=0.10` 설정 시 1,000개 요청 중 약 10%(`70..130`개)의 요청만 온전한 6-레이어 계보를 유지한 채 샘플링되는지 확인

---

### 기법 [11] 시각화 산출물(Mermaid / FlameGraph / Graphviz ID / TUI) 구문 & 엣지케이스 검증 (`ADV-TEST-11`)
* **구현 파일**:
  * [`tracer_agent.py`](../tracer_agent.py) (`render_mermaid_sequence`, `render_flamegraph_folded`, `sanitize_graphviz_id`, `run_interactive_tui`)
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_11_visual_artifacts_mermaid_flamegraph_html_and_tui_edge_cases`)
* **핵심 검증 항목**:
  * Mermaid `sequenceDiagram` 참여자(`NIC`, `KNET`, `GATE`, `APP`) 및 화살표 구문 유효성
  * Brendan Gregg FlameGraph Folded Stack(`frame1;frame2 count`) 포맷의 세미콜론 스택 경로 및 마이크로초 정수 카운트 유효성
  * 특수문자(`-`, `+`, `:`, `<`, `>`, `(`, `)`)가 포함된 C++ 심볼명의 Graphviz 식별자 치환 무결성
  * TUI 쉘에 잘못된 메뉴 번호(`99`, `invalid_key`, 빈 줄) 입력 시 안내 메시지 출력 후 `m`(Mermaid), `f`(FlameGraph), `q`(종료) 정상 실행 확인

---

### 기법 [12] 타겟 커널(`Rocky Linux 9.8 aarch64`) 레퍼런스 소스 트리 계약 & 라이브 루프백 브리지 검증 (`ADV-TEST-12`)
* **구현 파일**:
  * [`test_verification_suite.py`](../test_verification_suite.py) (`test_adv_12_target_kernel_live_verifier_and_loopback_readiness`)
* **적용 기법**:
  * 로컬 Rocky Linux 9.8 커널 소스 트리(`net/ipv4/tcp.c`, `net/core/dev.c`, `net/core/datagram.c`, `include/trace/events/sched.h`, `include/trace/events/block.h`, `include/trace/events/net.h`, `include/net/dropreason-core.h`) 파일 존재 및 계약을 확인합니다.
  * 실제 [`mock_server`](../mock_server.cpp) 프로세스를 띄우고 루프백 TCP 소켓으로 실제 HTTP 요청을 송수신한 뒤, 해당 라이브 소켓에서 획득한 실제 클라이언트 임시 포트(`sock.getsockname()[1]`), 서버 PID, 실제 요청/응답 바이트 길이를 [`tracer_kernel.c`](../tracer_kernel.c) 네이티브 C 훅 시뮬레이터와 `RequestCorrelator`에 관통시켜 End-to-End 6-레이어 추적을 검증합니다.

---

## 3. 무문맥 적대적 반증(Zero-Context Adversarial Falsification) 10대 서브에이전트 병렬 검증 및 코드베이스 반영 기록

`autonomous-tdd-target-verifier` 서브에이전트 정의를 기반으로 **10개의 독립 서브에이전트(`Agent 01` ~ `Agent 10`)** 를 동시에 구동하여 명세서([`PROMPT_SPEC.md`](../PROMPT_SPEC.md)), 커널 코드([`tracer_kernel.c`](../tracer_kernel.c), [`kray_bpf_core_compat.h`](../kray_bpf_core_compat.h), [`mock_bpf_runtime.h`](../mock_bpf_runtime.h), [`kernel_sim_harness.c`](../kernel_sim_harness.c)), 유저 엔진([`tracer_agent.py`](../tracer_agent.py)), 테스트 스위트([`test_verification_suite.py`](../test_verification_suite.py)) 및 전용 타겟 VM(`ebpf-tracer-v2.0.0`, Rocky Linux 9.8 `5.14.0-687.10.1.el9_8.0.1.aarch64`)을 적대적으로 반증(Falsification)하고, 발굴된 모든 결함을 프로젝트 목적(End-to-End Wire-to-Code X-Ray Tracer)에 맞게 반영하였습니다.

### Agent 01 — L2/L3/XDP 패킷 파서, VLAN & Egress `skb_clone` 검증 ([`AGENT_01_L2_L3_XDP_PACKET_VERIFIER.md`](./subagent_verifications/AGENT_01_L2_L3_XDP_PACKET_VERIFIER.md))
* **발굴된 반증 사항**:
  * 리눅스 커널 `net/ipv4/tcp_output.c:1267`의 `__tcp_transmit_skb()`는 송신 시 `oskb`를 복제(`skb = skb_clone(oskb, gfp_mask)`)하므로, `kprobe__ip_output` / `kprobe__ip6_output`에 전달되는 `skb` 포인터는 `__tcp_transmit_skb` 진입 시점의 `oskb`와 다릅니다.
  * `xdp_ingress_filter`와 `tracepoint:net:netif_receive_skb`에서 802.1Q(`0x8100`) / 802.1AD(`0x88A8`) VLAN 태그 언롤 시 내부 `vlan_id`가 이벤트 메타데이터에 보존되지 않았으며, 0바이트 `SYN`/`ACK` 제어 세그먼트가 초기 상태(`!existing`) 또는 소비 완료 후(`existing->consumed == 1`) 도착할 때 불필요한 `req_id`를 생성할 수 있었습니다.
  * `kprobe__ipv6_rcv`에서 IPv6 확장 헤더(`Hop-by-Hop=0`, `Routing=43`, `Fragment=44`, `DestOpts=60`) 언롤이 없었고, `kprobe__tcp_v6_rcv`에 루프백/Keep-Alive 폴백 상태 생성이 누락되어 있었습니다.
* **코드베이스 반영**:
  * [`tracer_kernel.c`](../tracer_kernel.c)의 `kprobe__ip_output` 및 `kprobe__ip6_output`에서 `PT_REGS_PARM2(ctx)`(`struct sock *sk`) 폴백으로 `ekey`를 복원한 즉시 `skb_egress_map.update(&skb_ptr, ekey)`를 호출하여 복제된 `skb`가 `net_dev_queue`와 `net_dev_xmit`까지 끊김 없이 추적되도록 수정했습니다.
  * [`kernel_sim_harness.c`](../kernel_sim_harness.c)의 `sim_tcp_egress_pipeline`에서 실제 커널 호출 순서(`__tcp_transmit_skb(&oskb)` -> `ip_output(&cloned_skb)` -> `net_dev_queue(&cloned_skb)` -> `net_dev_xmit(&cloned_skb)`)를 그대로 재현하도록 개선했습니다.
  * `xdp_ingress_filter` 및 `netif_receive_skb`에서 `vlan_id`를 `ev->ip`의 비트 `[31:16]`에 인코딩하고, `doff_len >= 20` 경계 검사와 0바이트 세그먼트 필터링을 추가했으며, `kprobe__ipv6_rcv` 2단계 확장 헤더 언롤 및 `kprobe__tcp_v6_rcv` 폴백 초기화를 반영했습니다.

### Agent 02 — L4 소켓 큐, 블로킹 `sk_wait_data`, Dual-Stack & 다중 프로토콜 검증 ([`AGENT_02_L4_SOCKET_PROTOCOL_VERIFIER.md`](./subagent_verifications/AGENT_02_L4_SOCKET_PROTOCOL_VERIFIER.md))
* **발굴된 반증 사항**:
  * Rocky Linux 9.8 커널 `net/ipv6/tcp_ipv6.c:1356`의 `tcp_v6_syn_recv_sock()`은 순수 IPv6 연결에서도 `skc_daddr = skc_rcv_saddr = LOOPBACK4_IPV6`(`htonl(0x7f000006)` = `127.0.0.6`)를 설정하므로, 단순 `rem_ip4 == 0` 조건만 검사하면 순수 IPv6 소켓이 IPv4 `127.0.0.6`으로 오분류됩니다.
  * 블로킹 `tcp_recvmsg`(`sk_wait_data` 대기 후 복사)에서는 `kretprobe__skb_copy_datagram_iter`가 함수 종료 시점인 `kretprobe__tcp_recvmsg`보다 먼저 실행되므로, `kretprobe__skb_copy_datagram_iter` 실행 시점에 `tctx->req_id` 지연 바인딩이 필요합니다.
* **코드베이스 반영**:
  * [`tracer_kernel.c`](../tracer_kernel.c)의 `populate_sock_flow_key`에서 `rem_ip4 == bpf_htonl(0x7f000006)`(`LOOPBACK4_IPV6`) 및 `skc_v6_daddr`의 비-`::ffff:` 여부를 함께 검사하여 순수 IPv6 소켓과 Dual-Stack(`::ffff:`) 소켓을 모두 정확히 분류하도록 반영했습니다 (`sim_pure_ipv6_loopback4_sock_key_test` 추가).
  * `kretprobe__skb_copy_datagram_iter`에서 `tctx->req_id == 0 && tctx->active_sk_ptr != 0`일 때 `ingress_flow_map` 지연 바인딩을 선행 수행하도록 반영하고, `kprobe__udp_sendmsg`의 `egress_flow_map` 갱신 및 `kprobe__unix_stream_recvmsg`/`sendmsg`의 `active_ctx_map` 연동을 추가했습니다.

### Agent 03 — L6 Pre-Compute Gate (`futex`, `sched_waking`, `sched_switch`, 8-Slot Handoff Ring, Block I/O) 검증 ([`AGENT_03_SCHED_FUTEX_HANDOFF_VERIFIER.md`](./subagent_verifications/AGENT_03_SCHED_FUTEX_HANDOFF_VERIFIER.md))
* **발굴된 반증 사항**:
  * Rocky Linux 9.8 `vmlinux.h`에서 개별 시스템콜 트레이스포인트(`tp/syscalls/sys_enter_*`)의 컨텍스트 구조체는 `struct trace_event_raw_sys_enter`(`long id` 8B, `args[0]` 오프셋 24)가 아니라 `struct syscall_trace_enter`(`int nr` 4B, `args[0]` 오프셋 16, `args[1]` 오프셋 24)입니다.
  * `publish_handoff_slot`에서 동일 `req_id`가 `tcp_recvmsg`와 `sys_enter_futex(FUTEX_WAKE)`에서 연속 게시될 때 중복 슬롯이 생성될 수 있었고, 8개 초과 버스트 시 `read_idx` 슬라이딩 윈도우 전진이 필요했습니다.
  * `sys_exit_futex`에서 음수 반환값(`args->ret < 0`, 예: `-EAGAIN`, `-ETIMEDOUT`)일 때도 슬롯을 소비할 수 있었습니다.
* **코드베이스 반영**:
  * [`kray_bpf_core_compat.h`](../kray_bpf_core_compat.h)에서 `tp_args_syscalls_sys_enter_*_t`를 `struct syscall_trace_enter`로, `tp_args_syscalls_sys_exit_*_t`를 `struct syscall_trace_exit`로 매핑하고 [`tracer_kernel.c`](../tracer_kernel.c)의 `sys_enter_futex`가 `args->args[1]`을 정확히 읽도록 수정했습니다.
  * `publish_handoff_slot`에 직전 미소비 슬롯 중복 갱신(In-Place Deduplication) 및 8슬롯 초과 시 `read_idx = write_idx - 7` 슬라이딩 윈도우 보호를 적용하고, `sys_exit_futex`에 `if (args->ret < 0) return 0;` 가드를 추가했습니다.

### Agent 04 — L7 Uprobe/Uretprobe 콜스택 & 3-Tier ELF/DWARF/Stripped 심볼리케이터 검증 ([`AGENT_04_UPROBE_DWARF_SYMBOLICATOR_VERIFIER.md`](./subagent_verifications/AGENT_04_UPROBE_DWARF_SYMBOLICATOR_VERIFIER.md))
* **발굴된 반증 사항**:
  * `trace_uprobe_entry`에서 `call_depth`가 `MAX_CALL_DEPTH (16)`에 도달한 이후 재귀 호출이 계속되면 `16 & 15 == 0` 마스킹으로 인해 루트 프레임(`fn_entry_ip[0]`, `fn_entry_ts[0]`)이 덮어써지고, `trace_uprobe_return`에서 깊이 `16`에 고정된 카운터가 조기 언더플로우되었습니다.
  * Linux ELF 공유 라이브러리(`libcrypto_mock.so`) 역어셈블 시 `verify_request_token` 내부에서 `strlen@plt`가 `verify_hmac_signature_internal`보다 먼저 호출되어 `_discover_stripped_internal_offset()`이 PLT 스텁 오프셋을 반환했습니다.
* **코드베이스 반영**:
  * [`tracer_kernel.c`](../tracer_kernel.c)의 `trace_uprobe_entry` / `trace_uprobe_return`에서 `raw_depth < MAX_CALL_DEPTH`일 때만 `fn_entry_ip[slot]` / `fn_entry_ts[slot]`을 기록·복원하고 `call_depth`는 최대 `255`까지 추적하도록 개선하여 깊이 16 초과 재귀 시에도 루트 프레임(Slot 0)이 100% 보존되도록 수정했습니다 (`ADV-TEST-07` 검증 추가).
  * [`tracer_agent.py`](../tracer_agent.py)의 `_discover_stripped_internal_offset()`에서 `@plt` 및 `strlen` 호출 라인을 건너뛰어 실제 내부 정적 함수(`verify_hmac_signature_internal`)의 파일 오프셋을 정확히 탐색하도록 수정했습니다.

### Agent 05 — 64B/16B 바이너리 ABI, `RequestCorrelator` 상태 머신 & 드롭/재전송 디코더 검증 ([`AGENT_05_ABI_CORRELATOR_DROP_VERIFIER.md`](./subagent_verifications/AGENT_05_ABI_CORRELATOR_DROP_VERIFIER.md))
* **발굴된 반증 사항**:
  * `decode_event_metadata()`에서 `OSI_L3_IP`/`OSI_L4_TCP` 이벤트를 디코딩할 때 `FLAG_SKB_DROP`(`skb_drop_reason`)과 `FLAG_TCP_RETRANSMIT`(`retransmit_count`) 플래그를 확인하지 않고 `(ttl, ihl_bytes, pkt_len)`으로만 언패킹했습니다.
  * 멀티코어 환경에서 `LAYER_EGRESS_NIC` 도착 직후 다른 코어의 지연된 이벤트가 도착할 때 `_finalize_request()`가 기존 완료 트레이스를 덮어써서 이전 홉이 유실될 수 있었습니다.
* **코드베이스 반영**:
  * [`tracer_agent.py`](../tracer_agent.py)에 `KRAY_EVENT_STRUCT`, `KRAY_RUNTIME_CFG_STRUCT`, `KrayRuntimeConfig` 별칭을 추가하고, `RequestCorrelator.ingest()`(및 `ingest_event()` 별칭)가 `KrayEvent`, 64B `bytes`/`bytearray`/`memoryview`, `dict`를 모두 수용하도록 확장했습니다.
  * `decode_event_metadata()`에서 `FLAG_SKB_DROP`(`skb_drop_reason`) 및 `FLAG_TCP_RETRANSMIT`(`retransmit_count`)을 우선 디코딩하도록 수정하고, `_finalize_request()`가 기존 `self._completed[req_id]`와 지연 도착 이벤트를 병합(Merge)하도록 개선했습니다.

### Agent 06 — 타겟 머신(`ebpf-tracer-v2.0.0`) 실커널 BPF Verifier 로드 및 라이브 어태치 검증 ([`AGENT_06_LIVE_KERNEL_BPF_VERIFIER_ATTACH.md`](./subagent_verifications/AGENT_06_LIVE_KERNEL_BPF_VERIFIER_ATTACH.md))
* **발굴된 반증 사항**:
  * [`kray_bpf_core_compat.h`](../kray_bpf_core_compat.h)에서 `trace_uprobe_entry` / `trace_uprobe_return`의 ELF 섹션이 `SEC("kprobe/...")` / `SEC("kretprobe/...")`로 선언되어 있어 `bpftool prog loadall ... autoattach` 실행 시 커널 심볼 테이블에서 유저 함수를 찾으려다 `-ENOENT`로 실패했습니다.
  * 타겟 VM에서 `mock_server`가 `--fast-mode` 플래그로 호출될 때 알 수 없는 인자로 무시되었고, 작업 디렉토리가 다를 때 `dlopen("./libcrypto_mock.so")`가 실패할 수 있었습니다.
* **코드베이스 반영**:
  * [`kray_bpf_core_compat.h`](../kray_bpf_core_compat.h)에서 `trace_uprobe_entry` / `trace_uprobe_return`을 `SEC("uprobe")` / `SEC("uretprobe")`로 선언하여 40개 커널 kprobe/kretprobe/tracepoint가 라이브 커널에 100% 자동 어태치되고 XDP(`xdpgeneric`) 및 uprobe/uretprobe가 정상 부착됨을 타겟 VM에서 실증했습니다.
  * [`mock_server.cpp`](../mock_server.cpp)에서 `--fast-storage`와 `--fast-mode`를 모두 지원하고 `argv[0]` 기준 `libcrypto_mock.so` 경로 폴백을 추가했습니다.

### Agent 07 — C 시뮬레이션 하네스 충실도(`mock_bpf_runtime.h` & `kernel_sim_harness.c`) 검증 ([`AGENT_07_SIM_HARNESS_FIDELITY_VERIFIER.md`](./subagent_verifications/AGENT_07_SIM_HARNESS_FIDELITY_VERIFIER.md))
* **발굴된 반증 사항**:
  * `mock_bpf_runtime.h`의 `BPF_PERCPU_ARRAY`가 단일 배열로 구현되어 코어 간 격리가 되지 않았고, 해시 맵 용량이 `256`으로 하드코딩되어 있었으며, `BPF_NOEXIST`/`BPF_EXIST`/`-E2BIG` 에러 코드 및 `last_used` 기반 실제 LRU 축출이 없었습니다.
  * `tracer_agent.py`의 `run_tracer_pipeline()`이 C 시뮬레이션 하네스(`libtracer_kernel_sim`)를 직접 호출하지 않고 고정 상수를 사용했습니다.
* **코드베이스 반영**:
  * [`mock_bpf_runtime.h`](../mock_bpf_runtime.h)에 2차원 코어별 배열(`__sim_percpu_arr_##name[KRAY_SIM_MAX_CPUS][max_entries]`), 실제 `max_entries`(`8192`/`4096`/`1024`) 용량, `g_sim_lru_seq` 기반 진성 LRU 축출, `BPF_NOEXIST`(`-17`)/`BPF_EXIST`(`-2`)/`-E2BIG`(`-7`)/`-EINVAL`(`-22`) 플래그 검증, `ringbuf_reserve` `0xAA` 포이즈닝을 구현했습니다.
  * [`kernel_sim_harness.c`](../kernel_sim_harness.c)에 `sim_verify_zero_templates_untouched()`, `sim_test_percpu_template_poisoning()`, `sim_test_map_capacity_and_flags()`, `sim_run_full_wire_to_code_pipeline()`을 구현하고 [`tracer_agent.py`](../tracer_agent.py)의 `run_tracer_pipeline()`과 연동했습니다.

### Agent 08 — 4-Tier Graphviz DOT/SVG, WebUI(`trace_dashboard.html`), TUI, Mermaid & FlameGraph 검증 ([`AGENT_08_VISUALIZATION_WEBUI_TUI_VERIFIER.md`](./subagent_verifications/AGENT_08_VISUALIZATION_WEBUI_TUI_VERIFIER.md))
* **발굴된 반증 사항**:
  * `run_tracer_pipeline()`의 `hop_timeline`에서 `L6_PRE_COMPUTE_GATE`(`TID 10425`)가 Acceptor 스레드 함수(`TID 10420`) 앞에 배치되어 스레드 ID가 `10420 -> 10425 -> 10420 -> 10425`로 두 번 튀었습니다.
  * `render_interactive_dashboard_html()`에서 `</script>` 이스케이프가 없었고, `render_flamegraph_folded()`가 형제(Sibling) 유저 함수들을 하나의 스택에 계속 누적했습니다.
* **코드베이스 반영**:
  * [`tracer_agent.py`](../tracer_agent.py)에서 `L6_PRE_COMPUTE_GATE`를 Acceptor 스레드 함수(`TID 10420`)와 Worker 스레드 함수(`TID 10425`) 사이에 배치하여 실제 실행 순서와 일치시켰습니다.
  * Graphviz DOT 라벨 따옴표 이스케이프, HTML `<script>` 내 `<\/` 이스케이프, Mermaid 특수문자 정규화, FlameGraph 스레드별 독립 스택 생성을 반영했습니다.

### Agent 09 — MCP JSON-RPC 2.0 서버(6대 도구), REST API & 멀티스레드 동시성 검증 ([`AGENT_09_MCP_REST_CONCURRENCY_VERIFIER.md`](./subagent_verifications/AGENT_09_MCP_REST_CONCURRENCY_VERIFIER.md))
* **발굴된 반증 사항**:
  * 멀티스레드 동시 수집/조회 시 `get_completed_traces()`가 진행 중인 버퍼를 조기 플러시한 뒤 후속 이벤트가 기존 완료 트레이스를 덮어쓰는 Trace Tearing이 발생할 수 있었습니다.
  * MCP `tools/list`에 `inputSchema`가 없었고, `notifications/initialized` 및 `ping` 메서드와 JSON-RPC 에러 코드(`-32700`, `-32600`, `-32602`), 알 수 없는 `/api/v1/*` GET 경로의 `404` 응답이 누락되어 있었습니다.
* **코드베이스 반영**:
  * [`tracer_agent.py`](../tracer_agent.py)의 `RequestCorrelator._finalize_request()` 병합 로직으로 멀티스레드 동시 수집/조회 시에도 이벤트 유실이 전혀 발생하지 않도록 보장했습니다.
  * `MCPGatewayServer.handle_jsonrpc()`에 `inputSchema`, `notifications/initialized`, `ping`, 표준 JSON-RPC 에러 코드(`-32700`, `-32600`, `-32602`), 동적 타겟 함수 소스 추출(`?target=handle_client`), 미정의 `/api/*` 경로 `404` 응답을 반영했습니다.

### Agent 10 — End-to-End 목적 부합성 및 뮤테이션 테스팅(Mutation Score 100%) 검증 ([`AGENT_10_E2E_PURPOSE_MUTATION_VERIFIER.md`](./subagent_verifications/AGENT_10_E2E_PURPOSE_MUTATION_VERIFIER.md))
* **발굴된 반증 사항**:
  * `ADV-TEST-12`에서 `mock_server` 기동 직후 고정 `time.sleep(0.25)`만 수행하여 CPU 부하 시 소켓 연결 레이스가 발생할 수 있었습니다.
  * 10종의 적대적 코드 변이(Mutant M01~M10)를 주입한 결과, 심층 재귀(>16) 루트 프레임 보존 변이를 추가로 잡아야 뮤테이션 스코어 100%에 도달함을 확인했습니다.
* **코드베이스 반영**:
  * [`test_verification_suite.py`](../test_verification_suite.py)의 `ADV-TEST-12`에 최대 30회 재시도 소켓 연결 루프를 적용하고, `ADV-TEST-04` 및 `ADV-TEST-07`에 VLAN ID 보존, 순수 IPv6 `LOOPBACK4_IPV6` 소켓 키 분류, 재전송/드롭 사유 디코딩, 20단계 심층 재귀 루트 프레임 보존 어설션을 추가하여 **10대 뮤턴트 전수 사살(Mutation Score 100%, 10/10 Killed)** 을 달성했습니다.

---

## 4. 20대 전 계층 적대적 반증 검증 및 20대 보고서 아카이브 내역 (`Domain 01` ~ `Domain 20`)

사용자의 "20가지로 늘려. 에이전트 수를 다시반복하고 어느 분야를 팔건지도 보여줘" 및 "이 프롬프트나 검증방식이 틀렸다는걸 가정하고 테스트하라"는 적대적 반증 명령에 따라, Wire-to-Code 7대 전 계층을 20개 전문 도메인으로 세분화하고 전체 반증 검증을 수행했습니다. 모든 검증 보고서는 [`archive/subagent_verifications_20/`](./subagent_verifications_20/)에 영구 보존되었습니다.

### 4.1 20대 검증 도메인 및 아카이브 파일 매핑
* **Domain 01: L2 Ingress XDP & 802.1Q/802.1AD VLAN Parsing**
  * 보고서: [`AGENT_01_L2_XDP_VLAN_VERIFIER.md`](./subagent_verifications_20/AGENT_01_L2_XDP_VLAN_VERIFIER.md)
  * 핵심 검증: QinQ `0x9100` 지원, VLAN 언롤 후 비IP(ARP/MPLS) 패킷 차단, 하드웨어 VLAN RX 오프로드(`skb->vlan_tci`) 대응.
* **Domain 02: L2/L3 Ingress SKB & IPv4 Options / IPv6 Extension Header Chains**
  * 보고서: [`AGENT_02_L3_IPV4_IPV6_UNROLL_VERIFIER.md`](./subagent_verifications_20/AGENT_02_L3_IPV4_IPV6_UNROLL_VERIFIER.md)
  * 핵심 검증: `kprobe__ip_rcv` 내 `ihl < 5` bounds 검사, 비-첫번째 IPv4 단편(`frag_off & 0x1FFF != 0`) L4 오파싱 방지, IPv6 Extension Header 4개 체인 및 Fragment Header/AH Header 오프셋 보정.
* **Domain 03: L2/L3 Egress Pipeline & skb_clone 인과성**
  * 보고서: [`AGENT_03_EGRESS_SKB_CLONE_VERIFIER.md`](./subagent_verifications_20/AGENT_03_EGRESS_SKB_CLONE_VERIFIER.md)
  * 핵심 검증: `__tcp_transmit_skb`의 `clone_it` 분기 추적, `net_dev_xmit` 완료 시 `skb_egress_map` 안전 정리, 비클론 oskb 누수 방지.
* **Domain 04: L3/L4 드롭 & TCP 재전송 포렌식**
  * 보고서: [`AGENT_04_DROP_RETRANSMIT_VERIFIER.md`](./subagent_verifications_20/AGENT_04_DROP_RETRANSMIT_VERIFIER.md)
  * 핵심 검증: Rocky Linux 9.8 `dropreason-core.h` 실커널 enum 매핑(4:SOCKET_CLOSE, 5:SOCKET_FILTER, 6:SOCKET_RCVBUFF, 8:PKT_TOO_SMALL, 9:TCP_CSUM, 11:NETFILTER_DROP), `tcp_retransmit_skb` 서버 소켓 튜플 양방향 언리버스 매핑.
* **Domain 05: L4 TCP 상태 머신 & 0-Byte 페이로드 필터링**
  * 보고서: [`AGENT_05_L4_TCP_STATE_0BYTE_VERIFIER.md`](./subagent_verifications_20/AGENT_05_L4_TCP_STATE_0BYTE_VERIFIER.md)
  * 핵심 검증: `doff_len >= 20` bounds 검사, SYN/FIN/RST 플래그 없는 순수 0-Byte ACK의 가짜 `req_id` 발급 방지.
* **Domain 06: L4 Dual-Stack 정규화 & IPv6 소켓**
  * 보고서: [`AGENT_06_DUAL_STACK_IPV6_SOCKET_VERIFIER.md`](./subagent_verifications_20/AGENT_06_DUAL_STACK_IPV6_SOCKET_VERIFIER.md)
  * 핵심 검증: `::ffff:x.x.x.x` IPv4-mapped IPv6 소켓의 `AF_INET` 정규화, Rocky 9.8 루프백 가속 상수 `0x7f000006`(`LOOPBACK4_IPV6`)의 IPv6 키 보존.
* **Domain 07: L4 블로킹 소켓 & Keep-Alive 지연 바인딩**
  * 보고서: [`AGENT_07_BLOCKING_SOCKET_KEEPALIVE_VERIFIER.md`](./subagent_verifications_20/AGENT_07_BLOCKING_SOCKET_KEEPALIVE_VERIFIER.md)
  * 핵심 검증: 패킷 도착 전 `tcp_recvmsg` 슬립(`sk_wait_data`) 시 `kretprobe__tcp_recvmsg`에서의 `req_id` 지연 바인딩, Keep-alive idle 대기 시간의 RTT 왜곡 격리.
* **Domain 08: L4 UDP/UDS 다중 프로토콜 & 미연결 와일드카드 포트 디스커버리**
  * 보고서: [`AGENT_08_UDP_UDS_PORT_DISCOVERY_VERIFIER.md`](./subagent_verifications_20/AGENT_08_UDP_UDS_PORT_DISCOVERY_VERIFIER.md)
  * 핵심 검증: 미연결 UDP `0.0.0.0:9090` 와일드카드 키(`daddr = 0`) 격리, 블로킹 UDS `unix_stream_recvmsg` 수신자 선슬립 지연 해석, `kretprobe__inet_csk_accept` 포트 디스커버리.
* **Domain 09: L5 Epoll 다중화 & aarch64 시스템콜 ABI**
  * 보고서: [`AGENT_09_L5_EPOLL_SYSCALL_ABI_VERIFIER.md`](./subagent_verifications_20/AGENT_09_L5_EPOLL_SYSCALL_ABI_VERIFIER.md)
  * 핵심 검증: `aarch64` 커널 ABI에서 `__NR_epoll_wait` 미존재 확인 및 `sys_enter_epoll_pwait`/`sys_exit_epoll_pwait` 트레이스포인트 적용, `ret <= 0`(타임아웃/에러) 스퓨리어스 이벤트 차단, `kprobe__tcp_recvmsg`의 컨텍스트 제로화 시 `epoll_wait_ns` 보존.
* **Domain 10: L5/L6 Futex 8-슬롯 핸드오프 링버퍼**
  * 보고서: [`AGENT_10_FUTEX_8SLOT_HANDOFF_VERIFIER.md`](./subagent_verifications_20/AGENT_10_FUTEX_8SLOT_HANDOFF_VERIFIER.md)
  * 핵심 검증: 프로듀서-컨슈머 레이스 시 `sys_exit_futex`의 `-EAGAIN`(`-11`) 반환 핸드오프 수락, `FUTEX_LOCK_PI2`(`13`) 지원, 모듈러 윈도우 중복 발급 방지.
* **Domain 11: L5/L6 스케줄러 & CPU 마이그레이션 레이턴시**
  * 보고서: [`AGENT_11_SCHEDULER_MIGRATION_VERIFIER.md`](./subagent_verifications_20/AGENT_11_SCHEDULER_MIGRATION_VERIFIER.md)
  * 핵심 검증: 비자발적 선점 시 `wakeup_ts == 0` 상태의 런큐 대기시간 계산(`now - off_cpu_enter_ts`), 코어 마이그레이션(`prev_cpu != target_cpu`) 정확 추적.
* **Domain 12: L6 Pre-Compute 게이트 & 워커 스레드풀 인과성**
  * 보고서: [`AGENT_12_PRECOMPUTE_GATE_VERIFIER.md`](./subagent_verifications_20/AGENT_12_PRECOMPUTE_GATE_VERIFIER.md)
  * 핵심 검증: 단일 스레드(Acceptor == Worker) 실행 시 `L6_PRE_COMPUTE_GATE` 합성, 다중 워커 풀 인과성 역전 방지, `pre_compute_latency_ns` 정확 계측.
* **Domain 13: L7 Uprobe 섀도우 스택 & 심층 재귀(Depth >= 16)**
  * 보고서: [`AGENT_13_UPROBE_SHADOW_STACK_VERIFIER.md`](./subagent_verifications_20/AGENT_13_UPROBE_SHADOW_STACK_VERIFIER.md)
  * 핵심 검증: `trace_uprobe_return`에서 `(raw_depth < 16)` 검사로 슬롯 래핑 IP 오염 방지(`orig_ip = 0`), 유저스페이스 `RequestCorrelator` LIFO 섀도우 콜 스택을 통한 깊이 16~255 프레임 IP 및 함수 수행시간 복원.
* **Domain 14: L7 ELF/DWARF 심볼릭화, PIE/ASLR & aarch64 64KB 정렬**
  * 보고서: [`AGENT_14_ELF_DWARF_ASLR_VERIFIER.md`](./subagent_verifications_20/AGENT_14_ELF_DWARF_ASLR_VERIFIER.md)
  * 핵심 검증: `ProcessMemoryMap`을 통한 `ET_EXEC`(베이스 `0x400000`), `ET_DYN`, `aarch64` 64KB 정렬 세그먼트(`p_vaddr - p_offset`) 런타임 IP 변환, C++ 이타늄 ABI 네임 데맹글링(`demangle_cpp_symbol`).
* **Domain 15: 64B ABI 및 링버퍼 오버플로우 스트레스**
  * 보고서: [`AGENT_15_ABI_CORRELATOR_STATE_VERIFIER.md`](./subagent_verifications_20/AGENT_15_ABI_CORRELATOR_STATE_VERIFIER.md)
  * 핵심 검증: 64바이트 고정 ABI 패킹 정합성, 링버퍼 드롭 카운터 배너 감지, `MAX_COMPLETED_TRACES = 4096` LRU 메모리 바운드.
* **Domain 16: C 시뮬레이터 충실도 & 마스킹 제거**
  * 보고서: [`AGENT_16_C_SIMULATOR_FIDELITY_VERIFIER.md`](./subagent_verifications_20/AGENT_16_C_SIMULATOR_FIDELITY_VERIFIER.md)
  * 핵심 검증: `kernel_sim_harness.c`의 테스트 마스킹 클램프(`if (ihl_words < 5) ihl_words = 5;`) 제거, 미연결 UDP 및 epoll pwait 시뮬레이션 인터페이스 연동.
* **Domain 17: Rocky Linux 9.8 실커널 BPF Verifier & BTF CO-RE**
  * 보고서: [`AGENT_17_LIVE_KERNEL_BPF_VERIFIER.md`](./subagent_verifications_20/AGENT_17_LIVE_KERNEL_BPF_VERIFIER.md)
  * 핵심 검증: `5.14.0-687.10.1.el9_8.0.1.aarch64` 실커널 대상 Clang BPF 백엔드 컴파일, BPF 스택 < 320B 준수, `asm volatile("" : "+r"(slot));` 베리파이어 최적화 방지 배리어, `bpftool prog loadall` 46개 전체 eBPF 프로그램 100% 로드 통과.
* **Domain 18: AI 병목 진단(Self-Time vs Inclusive-Time)**
  * 보고서: [`AGENT_18_AI_DIAGNOSIS_DIFF_VERIFIER.md`](./subagent_verifications_20/AGENT_18_AI_DIAGNOSIS_DIFF_VERIFIER.md)
  * 핵심 검증: 중첩 콜스택의 독점 수행시간(Self-Time)과 포괄 수행시간(Inclusive-Time) 수학적 분리, 래퍼 함수가 아닌 실제 리프 연산 병목(`execute_storage_query`) 정확 타겟팅.
* **Domain 19: 시각화 UI/TUI & FlameGraph 중복 집계 제거**
  * 보고서: [`AGENT_19_VISUALS_UI_TUI_VERIFIER.md`](./subagent_verifications_20/AGENT_19_VISUALS_UI_TUI_VERIFIER.md)
  * 핵심 검증: FlameGraph(Folded stack) 독점 시간 기반 렌더링으로 부모-자식 프레임 중복 시간 계산 제거, Chrome Trace 마이크로초 단위 인터벌 내보내기, TUI 메뉴 복원력.
* **Domain 20: MCP JSON-RPC 2.0 & REST API 보안 / 뮤테이션 킬레이트**
  * 보고서: [`AGENT_20_MCP_REST_MUTATION_VERIFIER.md`](./subagent_verifications_20/AGENT_20_MCP_REST_MUTATION_VERIFIER.md)
  * 핵심 검증: MCP JSON-RPC 2.0 배치 요청 및 알림 객체(`id` 없음) 처리, REST API 경로 순회(`../`) 차단 및 10MB 페이로드 제한, 10대 적대적 뮤턴트 전수 사살(Mutation Kill Rate 100%).



---

## Archive Document: `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`

# 구현 전 명세 단계(Pre-Implementation Specification Stage) 설계 결함 발굴 및 커널 소스 실증 감사 보고서

- **문서 경로**: [`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
- **검증 대상 명세서**: [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md) (`eBPF-WireToCode-Tracer` 마스터 설계 및 구현 프롬프트 명세서)
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

본 문서는 코드 한 줄을 작성하기 전에 **명세서([`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md))를 실제 타겟 커널 소스 코드와 1:1로 대조하여 발굴·제거한 총 45건(1차 아키텍처 감사 10건 + 2차 심층 커널·런타임 감사 25건 + 3차 극한 커널 소스·Verifier·ABI 정밀 감사 10건)의 설계 결함과 해결 공식**을 아카이브로 기록합니다.

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
- **커널 소스 근거**: [`include/net/sock.h:192-193`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/sock.h#L192-L193), [`net/ipv6/ip6_input.c:260, 302`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L260)
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
  - 마스터 명세서: [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md) (전 구간 본문 및 Part 5 Copy-Ready Master Prompt 100% 동기화 완료)
  - 감사 아카이브 보고서: [`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
- **핵심 엔지니어링 의의**: 코드를 단 한 줄도 작성하기 전에 타겟 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 소스 트리의 함수 내부 줄 번호와 실행 순서(`dev.c:5606`, `tcp.c:2638`, `datagram.c:534`), eBPF Verifier 제약, `vmlinux.h` BTF 구조체, ELF/DWARF/컴파일러 동작까지 총 45건의 잠재 결함을 명세 단계에서 선제 발굴·제거함으로써, 이 명세서 하나만으로 무결점(Zero-Defect) 구현이 가능하도록 완성했습니다.


---

## Archive Document: `archive/ZERO_CONTEXT_SUBAGENT_PROMPT.md`

# Zero-Context Subagent Master Prompt (TDD + 5x Spec Alignment + 12-Track Advanced Testing + Adversarial Falsification + Dedicated Versioned Target VM Verifier)

이 문서는 이전 대화 문맥이 전혀 없는(Zero-Context) 서브에이전트에게 **사전 설계 감사 → TDD(Red-to-Green) → 명세-테스트 5회 정합성 감사 → 12대 고도화 테스트 엔지니어링 → 프롬프트·검증 방식 자체에 대한 반증(Falsification) 감사 → 버전 명시 전용 타겟 머신 생성 및 실커널 Verifier 검증 → 엔지니어링 리포트 아카이빙** 전 과정을 위임하기 위한 완성형 프롬프트입니다.

---

## 1. 서브에이전트 정의 (`define_subagent` 파라미터)

* **Name**: `autonomous-tdd-target-verifier`
* **Description**: `Zero-Context 상태에서 프롬프트와 검증 방식 자체의 오류 가능성까지 전제하며, 설계 감사, TDD 구현, 5회 정합성 루프, 12대 테스트 고도화, 전용 버전 타겟 VM 생성 및 실커널 Verifier 반증 검증을 자율 수행하는 서브에이전트`
* **EnableWriteTools**: `true`
* **EnableMCPTools**: `true`
* **EnableSubagentTools**: `false`

---

## 2. 서브에이전트 시스템 프롬프트 (`SystemPrompt`)

```markdown
당신은 사전 대화 문맥 없이 투입되는 '자율형 반증 기반 TDD·테스트 고도화·타겟 커널 검증 전문 서브에이전트(Adversarial Falsification TDD & Target-Kernel Verification Subagent)'입니다.

### 핵심 행동 강령 (Non-Negotiable Rules)
1. **프롬프트 및 검증 방식 불신 원칙 (Adversarial Falsification Mandate)**:
   - **이 프롬프트, 마스터 명세서(`PROMPT_SPEC.md`), 그리고 제시된 검증 방식 자체가 틀렸거나 사각지대(Blind Spot)를 가졌을 수 있다고 항상 가정하십시오.**
   - 프롬프트의 지시사항이나 명세서의 수식·구조체·오프셋·가정이 실제 타겟 커널 소스(`references/`), BTF(`vmlinux.h`), 컴파일러(`clang -target bpf`), 또는 실커널 Verifier(`bpftool prog loadall`)의 실제 물리적 동작과 단 1바이트라도 충돌하면, **무조건 프롬프트와 명세서가 틀린 것으로 판정**하고 실물 커널/컴파일러 증거에 맞춰 명세서·테스트·코드를 모두 교정하십시오.
2. **가짜 통과(False Positive / 동어반복 테스트) 색출 원칙**:
   - 테스트가 통과(`PASS`)했다는 사실을 곧바로 코드의 무결성으로 믿지 마십시오.
   - 정적 정규식 검사(Regex)는 실제 컴파일을 증명하지 못하고, 호스트 크로스 컴파일(`-target aarch64-linux-gnu`)은 BPF CO-RE BTF 재배치를 증명하지 못하며, 유저스페이스 에뮬레이션은 실커널 Verifier(`BPF_PROG_LOAD`) 통과를 증명하지 못합니다.
   - 반드시 하위 단계의 검증 방식을 상위 단계의 물리적 실행(C 네이티브 실행 → BPF 바이트코드 컴파일 → 실커널 `bpftool prog loadall` → 라이브 루프백 패킷 관통)으로 교차 반증(Cross-Falsification)하십시오.
3. **No-Stub / No-Mock-Pass 원칙**:
   - 빈 함수 스텁(`return 0;`)이나 하드코딩된 더미 값으로 테스트를 통과시키는 행위를 절대 금지합니다.
   - 테스트가 실패하거나 컴파일러/Verifier 경고가 발생하면, 테스트 조건을 완화하지 말고 반드시 원본 커널 C 코드 또는 에이전트 코드를 수정하여 근본 원인을 해결하십시오.
4. **엄격한 단계별 게이트(Stage Gate) 준수**:
   - Phase 1부터 Phase 6까지 순서대로 수행하며, 각 Phase의 수치적 종료 조건(Exit Gate)과 반증 체크를 100% 만족하기 전에는 절대 다음 Phase로 넘어가지 마십시오.
5. **출력 포맷 규칙**:
   - 모든 마크다운(`.md`) 문서와 최종 보고서에서 마크다운 표(`| --- |`) 문법을 절대 사용하지 마십시오. 모든 구조화된 정보는 가로 전체 폭을 쓰는 제목(`###`, `####`)과 불릿 리스트(`*`, `-`)로만 작성하십시오.
```

---

## 3. 서브에이전트 실행 프롬프트 (`invoke_subagent` `Prompt` 본문)

```markdown
사전 대화 문맥 없이 아래의 프로젝트 경로와 레퍼런스를 기준으로 Phase 1부터 Phase 6까지 전 과정을 완수하고 최종 결과를 보고하라.
단, **이 프롬프트와 명세서(`PROMPT_SPEC.md`), 그리고 제시된 검증 방식 자체에 논리적 결함이나 누락이 있을 수 있다는 전제(Adversarial Assumption)** 하에 모든 단계를 의심하고 실물 커널/컴파일러로 반증하며 테스트하라.

### [작업 환경 및 기준 파일 (Single Source of Truth Hierarchy)]
우선순위 1순위(절대 진실)는 실제 타겟 커널의 실행 결과와 커널 소스/BTF이며, 2순위가 명세서와 이 프롬프트다. 충돌 시 1순위를 따라 2순위를 수정하라.
* **1순위 (실물 증거)**:
  - 전용 타겟 머신(`Rocky Linux 9.8 aarch64`, `5.14.0-687.10.1.el9_8.0.1.aarch64`)의 실커널 Verifier(`bpftool prog loadall`) 및 `/sys/kernel/btf/vmlinux`
  - 로컬 커널 BTF 및 소스 레퍼런스: `/Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/` (`btf-and-headers/vmlinux.h`, `btf-and-headers/bpf/*.h`, `linux-5.14.0-687.10.1.el9_8/`)
  - eBPF 기술 문서 레퍼런스: `/Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/ebpf-docs-master/`, `/Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/BPF-성능-분석-도구.pdf`
* **2순위 (검증 및 교정 대상 명세)**:
  - 마스터 명세서: `/Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/PROMPT_SPEC.md`
  - 프로젝트 루트: `/Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer`

---

### Phase 1. 사전 설계 정밀 감사 — "명세서가 틀렸다고 가정하라" (Pre-Implementation Falsification Audit)
1. `PROMPT_SPEC.md`에 적힌 모든 커널 훅 시그니처, 구조체 필드 오프셋, 바이트오더, 맵 키 레이아웃, Verifier 스택 한계(512B), 링버퍼 드롭 계산식, 멀티스레드/비동기 컨텍스트 전파 규칙이 **틀렸을 가능성**을 전제로 `references/` 내 실제 커널 소스(`tcp.c`, `dev.c`, `datagram.c`, `af_unix.c`, `if_arp.h`, `dropreason-core.h`, `vmlinux.h`)와 1:1 대조하라.
2. 논리적 모순, 커널 버전 불일치, Verifier 거부 조건, 엣지케이스 결함을 전수 발굴하여 `PROMPT_SPEC.md`를 정밀 보정하고, 발견 및 수정 내역을 `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`에 기록하라.
3. **[Phase 1 Exit Gate]**: 명세서 내 미해결 설계 결함 0건, 감사 리포트 아카이빙 완료.

---

### Phase 2. 테스트 우선 작성 및 구현 (Strict TDD: Red -> Green)
1. **TDD Red Phase**: 구현 코드를 작성하기 전에 `PROMPT_SPEC.md`의 12개 필수 검증 시나리오(`TEST-01` ~ `TEST-12`)와 Phase 1에서 도출된 모든 감사 불변식을 검증하는 `test_verification_suite.py` 및 `test_harness.sh`를 먼저 작성하라. 실행 시 `0/12 PASSED, 12/12 FAILED`(Red Phase)가 나오는 것을 확인하라.
2. **TDD Green Phase**:
   - `tracer_kernel.c` (L2~L7 전구간 및 멀티 프로토콜 eBPF C 컬렉터)
   - `tracer_agent.py` (코릴레이터, 3-Tier 심볼리케이터, Graphviz/HTML/TUI, 6-Tool MCP 서버, 10-Endpoint REST API)
   - `mock_server.cpp` & `libcrypto_mock.cpp` (DWARF C++ 타겟 서버 및 `strip -x` 공유 라이브러리)
   를 구현하여 `TEST-01` ~ `TEST-12` 전수 통과(`12/12 PASSED`)를 달성하라.
3. **[Phase 2 Exit Gate]**: `python3 test_verification_suite.py` 실행 시 `12/12 PASSED`.

---

### Phase 3. 명세 ↔ 테스트 ↔ 구현 5회 정합성 반복 감사 — "기존 테스트가 가짜 통과(False Positive)라고 가정하라"
기본 테스트(`TEST-01..12`)가 통과하더라도, 테스트가 스텁이나 완화된 조건 때문에 통과했을 가능성을 전제로 5회 반복 점검하고 보강하라:
* **Iteration 1 (커널 훅 & ABI 전수 구현)**: 모든 프로토콜 훅(`ipv6_rcv`, `ip6_output`, `tcp_v6_rcv`, `udp_rcv`, `udp_recvmsg`, `kretprobe__udp_recvmsg`, `udp_sendmsg`, `icmp_rcv`, `arp_rcv`, `unix_stream_recvmsg`, `unix_stream_sendmsg`, `kfree_skb` 3단계 조회, `ip_output` `PT_REGS_PARM2` 폴백, Dual-Stack `::ffff:` 정규화)이 빈 스텁 없이 실제 C 로직으로 구현되었는지, `sizeof(struct kray_event_t) == 64` 및 `sizeof(struct flow_key_t) == 16`이 컴파일 타임에 증명되는지 확인하라.
* **Iteration 2 (코릴레이터 & 비트패킹 디코더)**: 멀티코어 타임스탬프 역전 정렬, `50ms` Grace Window 만료 전후 상태 전이, `(layer_type, call_depth)` 분리 인코딩(`layer_type=4`일 때 `call_depth=6,8`이 `OSI_L5`/`OSI_L6`와 절대 충돌하지 않음), `final_drop_count = max(max_event_drop_count, bpf_drop_cnt_map[0]) + simulate_drops` 수식을 검증하라.
* **Iteration 3 (심볼리케이터 & 오프셋 역산)**: `/proc/<PID>/maps` 파서 및 `rel_offset = (ip - vm_start) + file_offset`, `aarch64` 64KB 정렬 `uprobe_file_offset = st_value - p_vaddr + p_offset`, C++ STL/런타임 심볼 제외 필터 및 `MAX_AUTO_UPROBES = 64` 상한, `--uprobe-offset` 실행 경로를 검증하라.
* **Iteration 4 (시각화 & 휴먼 인터페이스)**: 4-Tier Graphviz 클러스터, 웹 대시보드(`PUT /api/v1/config` 핫리로드 바, SVG 노드 클릭 `inspectHop`, `kernel-packet-view`, `Zoom-In Probe This Function/Offset` 버튼), 인터랙티브 TUI 전체 메뉴(`1`~`7`, `q`) 파이프 실행을 검증하라.
* **Iteration 5 (MCP & REST API 전수 호출)**: MCP 6개 도구 개별 JSON-RPC 호출, REST API 10개 엔드포인트 개별 HTTP 호출(`p99 < 500ms`), 멀티포트 체인(`80,443,3000,5432,8080` 및 `all`/`0`) 파서를 검증하라.
* **[Phase 3 Exit Gate]**: 5회 정합성 감사에서 누락/스텁/동어반복 테스트 0건.

---

### Phase 4. 12대 테스트 엔지니어링 고도화 & 검증 방식 반증 (`ADV-TEST-01` ~ `ADV-TEST-12`)
정적 검사나 단순 단위 테스트의 한계를 깨기 위해 아래 12개 고도화 테스트를 구현하라. 또한 **이 12가지 검증 기법조차 놓치는 사각지대가 없는지 스스로 반증(Mutation / Falsification)**하며 드러나는 모든 실제 코드 결함을 즉시 수정하라:
1. **`ADV-TEST-01` (커널 C 네이티브 에뮬레이션 하네스)**:
   - 정적 문자열 검사(`TEST-02`)가 틀렸을 수 있다고 가정하고, `mock_bpf_runtime.h`와 `kernel_sim_harness.c`를 작성해 `tracer_kernel.c` 원본을 네이티브 공유 라이브러리(`libtracer_kernel_sim.dylib`/`.so`)로 컴파일하여 Python `ctypes`로 직접 실행하라.
   - `xdp_ingress_filter` + `netif_receive_skb` 중복 제거, `kprobe__tcp_v4_rcv`의 0바이트 순수 ACK 비오버라이트(`consumed == 0` 보호), `sk_wait_data()` 블로킹 후 `kretprobe__tcp_recvmsg` 지연 바인딩, 중첩 `uprobe`/`uretprobe`에서 `[uprobes]` 트램펄린 IP(`0x7fffffffe000`) 오염 시 `fn_entry_ip[depth]` 복원, `sys_exit_write` 비삭제 및 `kretprobe__tcp_sendmsg` 컨텍스트 정리를 C 함수 직접 호출로 검증하라.
2. **`ADV-TEST-02` (Rocky 9.8 `vmlinux.h` CO-RE 크로스 컴파일)**:
   - 유저스페이스 C 에뮬레이션(`ADV-TEST-01`)의 모의 구조체가 실제 커널 구조체와 다를 수 있다고 가정하고, `kray_bpf_core_compat.h`를 통해 `references/` 내 실제 Rocky 9.8 `vmlinux.h`를 인클루드하여 `clang -target aarch64-linux-gnu -std=gnu11 -DKRAY_BPF_CORE -O2`로 ELF 오브젝트를 컴파일한 뒤 `objdump -h`로 모든 훅 섹션 생성을 검증하라.
3. **`ADV-TEST-03` (eBPF Verifier 정적 한계 감사 — 스택 320B 이하 / 루프 Unroll / 제로 템플릿)**:
   - `struct tid_ctx_t`만 스택에서 빼면 안전하다는 명세서의 가정을 의심하라(예: `publish_handoff_slot` 인라이닝 시 `struct handoff_ring_t` 264B가 합산되어 512B를 초과하는 숨은 결함).
   - `-Wframe-larger-than=320 -Werror=frame-larger-than=` 플래그를 강제하여 모든 훅 함수의 인라이닝 후 최종 스택 프레임이 320B 이하(BPF 512B 한계 미만)임을 컴파일러로 증명하고, 모든 `for (` 루프 직전의 `#pragma unroll`을 검증하라.
4. **`ADV-TEST-04` (Raw 패킷 바이트 합성 & 기형 패킷 퍼징)**:
   - 정상 패킷만 들어온다는 가정을 버리고, 단일 VLAN(`802.1Q`), 이중 QinQ(`802.1AD`), IPv4 옵션(`ihl=8`), 그리고 길이가 잘리거나 `ihl`이 조작된 기형 패킷 6종을 바이트 배열로 합성해 `xdp_ingress_filter`에 주입하라(기형 패킷은 모두 이벤트 방출 없이 `XDP_PASS` 반환).
   - ARP(`(u8 *)(arp + 1) + 6`), ICMP, 비연결 UDP(`port_key` 폴백 + `msg->msg_name`), IPv6 XOR 폴딩, Dual-Stack `::ffff:`(`AF_INET` 정규화), `AF_UNIX`, `kfree_skb`(`reason <= 2` 무시 vs `reason > 2` Stage 2/3 드롭) C 훅을 직접 실행하라.
5. **`ADV-TEST-05` (상태 머신 카오스 & 속성 기반 퍼징)**:
   - 이벤트가 순서대로 도착하거나 항상 정상 종료된다는 가정을 버리고, 250개 동시 요청(~2,000개 이벤트)에 멀티코어 타임스탬프 지터/역전, 20%의 비정상 종료(`LAYER_EGRESS_NIC` 누락), `call_depth` 0..31 변동을 주어 무작위 셔플 주입하고, `req_id` 간 오염(Cross-talk) 0건 및 정규 정렬 불변식을 검증하라.
6. **`ADV-TEST-06` (8-슬롯 핸드오프 링큐 경합 & 3회 랩어라운드)**:
   - 단일 핸드오프 테스트의 한계를 의심하고, 8-슬롯 `handoff_ring_t`에 24개 연속 요청(3회 완전 순환 래핑)을 주입하여 Acceptor 자기 소비 차단(`waker_tid != tid`)과 Worker 스레드의 정확한 FIFO 1:1 인계를 검증하라.
7. **`ADV-TEST-07` (ELF / DWARF / PIE ASLR & `aarch64` 64KB 페이지 오프셋 스트레스)**:
   - 다중 모듈 `/proc/<PID>/maps`와 `aarch64` 64KB 정렬 편차(`p_vaddr != p_offset`) 보정 및 160개 C++ 맹글링 심볼 필터링(`MAX_AUTO_UPROBES = 64`)을 검증하라.
8. **`ADV-TEST-08` (네거티브 & 결함 주입 경계값 테스트)**:
   - 링버퍼 100% 포화(`sim_set_ringbuf_full(1)`로 이벤트 0건 수신 상태에서 `drop_cnt_map[0]`만으로 드롭 계산), `call_depth == 0` 고아 `uretprobe` 언더플로우 방어, `lock_wait_ns > 4.29s` 32비트 상한 캡핑(`0xFFFFFFFF`), 잘못된 포트/깨진 JSON 입력 시 HTTP `400` 및 JSON-RPC `-32601` 반환을 검증하라.
9. **`ADV-TEST-09` (멀티스레드 동시성 & 핫리로드 스트레스)**:
   - 단일 스레드 API 테스트가 통과해도 동시 접속 시 소켓 백로그(`listen(5)`)나 락 경합으로 깨질 수 있다고 가정하라.
   - 16개 워커 스레드가 동시에 80회 REST(`PUT /api/v1/config`, `GET /api/v1/network-layers`) / MCP(`POST /mcp`) / 코릴레이터 적재를 수행할 때 `request_queue_size = 128` 기반으로 연결 리셋(`Errno 54`)·데드락이 0건이고 `p99 < 500ms`임을 검증하라.
10. **`ADV-TEST-10` (대용량 처리량 SLA & `MAX_COMPLETED_TRACES = 4096` 메모리 캡)**:
    - 장기 실행 시 메모리 누수가 발생할 수 있다고 가정하고, 5,000개 트레이스(30,000개 이벤트) 고속 주입 시 처리량 `> 20,000 events/sec`, 완료 트레이스 4,096개 LRU 상한 유지, `sampling_rate=0.10` 결정론적 샘플링을 검증하라.
11. **`ADV-TEST-11` (시각화 산출물 구문 & TUI 비정상 입력 방어)**:
    - Mermaid `sequenceDiagram`, FlameGraph Folded Stack 포맷, 특수문자 심볼 치환, TUI 잘못된 메뉴 키(`99`, `invalid_key`, 빈 줄) 입력 시 복원력을 검증하라.
12. **`ADV-TEST-12` (타겟 커널 레퍼런스 소스 계약 & 라이브 루프백 브리지 + 실커널 Verifier 로드)**:
    - 호스트 크로스 컴파일(`ADV-TEST-02`)이 통과하더라도 실제 커널 BTF 재배치(`typedef` vs `struct` 이름 불일치)나 Kprobe 레지스터 규약(`R1=ctx` vs `R2` 직접 참조) 때문에 실커널 로드가 실패할 수 있다고 가정하라.
    - 실제 `mock_server` 라이브 루프백 TCP 소켓 패킷 정보를 C 커널 훅과 코릴레이터에 관통시키고, Phase 5의 전용 타겟 머신에서 실커널 Verifier 로드까지 통과시켜 반증을 완성하라.
* **[Phase 4 Exit Gate]**: `TEST-01..12` + `ADV-TEST-01..12` 총 24개 스위트 `24/24 PASSED`.

---

### Phase 5. 버전 명시 전용 타겟 머신(Target VM) 프로비저닝 및 실커널 Verifier 최종 반증
호스트에서의 모든 시뮬레이션과 크로스 컴파일이 틀렸을 수 있다는 최후의 가정을 검증하기 위해, 실제 타겟 커널 머신을 별도로 구축하여 실증하라:
1. **전용 타겟 머신 생성 및 버전 네이밍**:
   - `/Applications/UTM.app/Contents/MacOS/utmctl`로 기존 베이스 VM(`rocky-dev`)과 분리된 이 프로젝트 전용 타겟 VM을 생성하되, 이름에 프로젝트명·버전·OS·커널 버전을 명시하라:
     `ebpf-wire-to-code-tracer-v2.0.0-rocky9.8-5.14.0-687.10.1`
   - `osascript`로 전용 VM의 네트워크 인터페이스에 고유 MAC 주소(`4a:8b:97:99:1c:20`)를 부여하고 베이스 VM과 전용 VM을 모두 기동(`started`)하라.
   - `/var/db/dhcpd_leases`에서 전용 VM에 할당된 IP를 확인하여 `~/.ssh/config.d/ebpf-tracer-v2.0.0`(`Host ebpf-wire-to-code-tracer-v2.0.0 ebpf-tracer-v2.0.0`)을 설정하고 게스트 호스트네임을 `ebpf-wire-to-code-tracer-v2-0-0-rocky9-8`로 지정하라.
2. **실커널 eBPF 컴파일 및 Verifier 전수 로드 반증 (`bpftool prog loadall`)**:
   - 전용 타겟 머신(`Rocky Linux 9.8`, `5.14.0-687.10.1.el9_8.0.1.aarch64`)에 프로젝트를 동기화하라.
   - 타겟 머신 내부에서 `clang -target bpf -D__TARGET_ARCH_arm64 -DKRAY_BPF_CORE -O2 -g`로 `tracer_kernel_bpf.o`를 컴파일하고, `sudo /usr/sbin/bpftool prog loadall tracer_kernel_bpf.o /sys/fs/bpf/kray_test`를 실행하여 **42개 전체 eBPF 프로그램이 실제 커널 Verifier를 통과하여 핀닝되는지** 검증하라(로드 실패 시 CO-RE BTF 타입명 및 `PT_REGS_PARM*` 레지스터 추출을 수정하여 42개 전수 로드를 달성하고 `ADV-TEST-12`에 자동화하라).
   - 전용 타겟 머신과 로컬 macOS 호스트 양쪽에서 `./test_harness.sh` 및 `python3 test_verification_suite.py`를 실행하여 양쪽 모두 `24/24 PASSED`를 확인하라.
3. **[Phase 5 Exit Gate]**: 전용 타겟 VM 정상 가동, 실커널 Verifier 42/42 로드 성공, 타겟 VM 및 호스트 양쪽 `24/24 PASSED`.

---

### Phase 6. 테스트 엔지니어링 & 프롬프트/검증 반증 리포트 아카이빙
* `archive/ADVANCED_TEST_ENGINEERING_REPORT.md`에 다음 항목을 마크다운 표(`| --- |`) 없이 상세히 기록하라:
  1. 전용 타겟 머신 명세(VM 이름, UUID, 커널 버전, IP, SSH 별칭)
  2. **프롬프트·명세서·초기 검증 방식이 틀렸다는 가정(반증 테스트)을 통해 실제로 적발·교정한 결함 목록** (예: 512B 스택 초과 숨은 인라이닝, CO-RE `typedef` BTF 재배치 실패, `libbpf` Kprobe `R2` 레지스터 거부, 멀티스레드 `request_queue_size=5` SYN 백로그 리셋, 완료 트레이스 메모리 상한 등)
  3. 적용된 12대 고도화 테스트 기법(`ADV-TEST-01` ~ `ADV-TEST-12`) 상세 명세 및 최종 검증 결과
```


---

## Archive Document: `archive/softwarefactory-draft/.agents/skills/pre-implementation-design-audit/SKILL.md`

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


---

## Archive Document: `archive/softwarefactory-draft/docs/drafts/DRAFT_SPEC_AUDIT_REPORT_PIPELINE.md`

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


---

## Archive Document: `archive/subagent_verifications/AGENT_01_L2_L3_XDP_PACKET_VERIFIER.md`

# AGENT 01 — Adversarial Falsification Audit: L2/L3 XDP & TC/Netif Packet Parser, Egress Port/SKB-Clone Correlation & Kernel Drop (`kfree_skb`) Verification

## 1. Executive Summary & Adversarial Verification Scope

* **Auditor Role**: Autonomous Adversarial Falsification TDD & Target-Kernel Verification Subagent (`AGENT_01_L2_L3_XDP_PACKET_VERIFIER`)
* **Target Kernel Ground Truth**:
  - **Live Target VM**: `ebpf-tracer-v2.0.0` (`192.168.64.14`, `Rocky Linux 9.8 (Blue Onyx) aarch64`, kernel release `5.14.0-687.10.1.el9_8.0.1.aarch64`)
  - **Kernel Source & BTF Reference**: `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/`
* **Overall Falsification Verdict**:
  - **7 critical specification, kernel C code, and false-positive test harness defects** were uncovered across the L2/L3/L4 packet parsers (`xdp_ingress_filter`, `netif_receive_skb`, `ip_rcv`, `ipv6_rcv`, `tcp_v4_rcv`, `tcp_v6_rcv`), Egress correlation (`__tcp_transmit_skb`, `ip_output`, `ip6_output`, `net_dev_queue`, `net_dev_xmit`, `udp_sendmsg`), and the 3-stage `kfree_skb` drop tracker.

## 2. Detailed Summary of the 7 Falsified Defects

* **Defect #1 (CRITICAL — Egress SKB Clone Blind Spot & Tautological Test Harness Cheat)**:
  - In `net/ipv4/tcp_output.c:1258-1268`, `__tcp_transmit_skb(sk, skb, clone_it, ...)` clones the master `oskb` (`skb = skb_clone(oskb, gfp_mask)`) before calling `ip_queue_xmit` -> `ip_output` -> `net_dev_queue` -> `net_dev_xmit`.
  - `kprobe____tcp_transmit_skb` records the uncloned `oskb` in `skb_egress_map`, while `kprobe__ip_output` receives `cloned_skb != oskb`. Although `kprobe__ip_output` fell back to `PT_REGS_PARM2(ctx)` (`struct sock *sk`), it never inserted `cloned_skb` into `skb_egress_map`, causing 100% of `net_dev_queue` and `net_dev_xmit` (`LAYER_EGRESS_NIC`) events to be dropped on real kernels. `kprobe__ip6_output` also lacked the `PT_REGS_PARM2(ctx)` fallback.
  - Meanwhile, `sim_tcp_egress_pipeline` in `kernel_sim_harness.c` hid this defect by calling `kprobe____tcp_transmit_skb` *after* `kprobe__ip_output` with the same `&skb` pointer.
* **Defect #2 (CRITICAL — 0-Byte TCP Handshake `SYN`/`ACK` Poisoning of `ingress_flow_map`)**:
  - In `xdp_ingress_filter` and `tracepoint__net__netif_receive_skb`, `if (tcp_payload_len == 0)` was only checked inside `if (existing && existing->consumed == 0)`, allowing the initial 0-byte `SYN` (`existing == NULL`) or post-consumption keep-alive `ACK` (`existing->consumed == 1`) to mint an unconsumed `req_id` and block the subsequent real HTTP payload packet.
* **Defect #3 (Software VLAN `802.1Q`/`802.1AD` Blind Spot in `netif_receive_skb`)**:
  - In `net/core/dev.c:5606-5639`, `trace_netif_receive_skb(skb)` executes before `skb_vlan_untag(skb)`. `tracepoint__net__netif_receive_skb` must unroll up to 2 software VLAN headers from `skb->data` when `skb->protocol` is `0x8100` or `0x88A8`.
* **Defect #4 (Unvalidated IPv4 `ihl < 5` & TCP `doff < 5`)**:
  - At `kprobe__ip_rcv` entry (`net/ipv4/ip_input.c:552`), `ip_rcv_core()` has not yet validated `iph->ihl >= 5` or `iph->version == 4`. Explicit checks `ihl_bytes >= 20` and `doff_len >= 20` are required.
* **Defect #5 (IPv6 Extension Headers in `kprobe__ipv6_rcv` & Missing Fallback State in `kprobe__tcp_v6_rcv`)**:
  - `kprobe__ipv6_rcv` must unroll up to 2 RFC 8200 extension headers (`NEXTHDR_HOP`, `NEXTHDR_ROUTING`, `NEXTHDR_FRAGMENT`, `NEXTHDR_DEST`), and `kprobe__tcp_v6_rcv` must initialize a fallback `flow_state_t` when `!state || state->consumed == 1`.
* **Defect #6 (Unconnected UDP Server Egress Blind Spot in `kprobe__udp_sendmsg`)**:
  - Must extract peer IP/port from `msg->msg_name` (`struct sockaddr_in`) or `tctx`, update `egress_flow_map`, and delete `active_ctx_map[&tid]`.
* **Defect #7 (`kfree_skb` Stage 1/2/3 Egress & UDP Drop Blind Spots + `decode_event_metadata` Flag Check)**:
  - Stage 1 (`skb_egress_map`) should emit `LAYER_EGRESS_NIC` and clean up `skb_egress_map`/`egress_flow_map`; Stage 2/3 should support `IPPROTO_UDP` and `egress_flow_map`; `decode_event_metadata` must check `FLAG_SKB_DROP` and `FLAG_TCP_RETRANSMIT` before unpacking `(ttl, ihl_bytes, pkt_len)`.


---

## Archive Document: `archive/subagent_verifications/AGENT_02_L4_SOCKET_PROTOCOL_VERIFIER.md`

# AGENT 02 — Adversarial Falsification Audit: L4 TCP/UDP/UNIX Socket State Transitions & Kernel Struct Offsets

## 1. Executive Summary

Cross-checking `PROMPT_SPEC.md`, `tracer_kernel.c`, `kernel_sim_harness.c`, and `test_verification_suite.py` against the Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) kernel source (`net/ipv4/`, `net/ipv6/`, `net/unix/`) and `vmlinux.h` BTF layout uncovered **5 critical defects**:

* **Defect #1 (Pure IPv6 vs Dual-Stack `LOOPBACK4_IPV6 = 127.0.0.6` Trap)**:
  - `PROMPT_SPEC.md` and `populate_sock_flow_key` assumed `family == AF_INET6 && skc_daddr == 0` identifies pure IPv6 sockets.
  - In Rocky 9.8 kernel `net/ipv6/tcp_ipv6.c:1356` (`tcp_v6_syn_recv_sock`), accepted pure IPv6 TCP sockets have `inet_daddr = inet_rcv_saddr = LOOPBACK4_IPV6` (`cpu_to_be32(0x7f000006)` = `127.0.0.6`). Checking `skc_daddr == 0` misclassifies every real pure IPv6 server socket as IPv4 `127.0.0.6`!
  - Fix: Check `ipv6_is_v4mapped(&v6_rem)` (`addr32[0]==0 && addr32[1]==0 && addr32[2]==htonl(0x0000ffff)`) or `rem_ip4 != bpf_htonl(0x7f000006)`.
* **Defect #2 (Blocking `tcp_recvmsg` Execution Order Inversion on `skb_copy_datagram_iter`)**:
  - In `net/ipv4/tcp.c:2638-2679` (`tcp_recvmsg_locked`), `skb_copy_datagram_iter` executes **before** `tcp_recvmsg` returns (`kretprobe__tcp_recvmsg`).
  - When a thread blocks in `sk_wait_data()`, `tctx->req_id` is still `0` when `kprobe__skb_copy_datagram_iter` / `kretprobe__skb_copy_datagram_iter` runs, causing 100% of `OSI_L5_SYSCALL_MEM` copy events to be dropped.
  - Fix: Perform lazy `req_id` binding from `tctx->active_sk_ptr` inside `kprobe__skb_copy_datagram_iter`.
* **Defect #3 (UDP Connected vs Unconnected 4-Tuple & Egress Correlation Breakage)**:
  - `kretprobe__udp_recvmsg` left `key.daddr == 0`, failed on connected UDP (`msg_name == NULL`), and did not populate `tctx` peer fields or `publish_handoff_slot`. `kprobe__udp_sendmsg` did not read `msg->msg_name` or clean up `active_ctx_map`.
* **Defect #4 (`AF_UNIX` `unix_stream_recvmsg` / `unix_stream_sendmsg` One-Way Breakage)**:
  - `kprobe__unix_stream_recvmsg` did not bind `req_id` into `active_ctx_map[&tid]` or publish handoff, and `kprobe__unix_stream_sendmsg` always minted a new random `req_id` instead of propagating `tctx->req_id`.
* **Defect #5 (`get_target_pid()` Dead Helper)**:
  - `get_target_pid()` was defined in `tracer_kernel.c` but never called.


---

## Archive Document: `archive/subagent_verifications/AGENT_03_SCHED_FUTEX_HANDOFF_VERIFIER.md`

# Agent 03 반증 기반 TDD 및 타겟 커널 검증 보고서: 스케줄러·Futex·Syscall 컨텍스트 전파 및 멀티스레드 핸드오프

## 1. 감사 개요 및 핵심 판정 (Executive Summary)

* **검증 주체**: Agent 03 (`AGENT_03_SCHED_FUTEX_HANDOFF_VERIFIER`)
* **타겟 실물 커널 환경**: Rocky Linux 9.8 (Blue Onyx) aarch64 (`5.14.0-687.10.1.el9_8.0.1.aarch64`, 전용 VM `ebpf-tracer-v2.0.0` `192.168.64.14` 및 로컬 커널 소스/BTF 레퍼런스 [vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h))
* **핵심 감사 영역**:
  - `sys_enter_read`, `sys_exit_read`, `sys_enter_write`, `sys_exit_write`, `sys_enter_futex`, `sys_exit_futex`, `sched_waking`, `sched_wakeup`, `sched_switch`, `sched_process_fork`의 실물 커널 트레이스포인트 포맷(`/sys/kernel/tracing/events/*/*/format`) 및 BTF 구조체([vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h))와 [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h), [mock_bpf_runtime.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h), [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md) 간의 바이트 단위 정합성 반증
  - 소켓 수신 시스템 콜(`read` vs `recv`/`recvfrom`/`readv`/`recvmsg`), `sk_wait_data()` 블로킹 시 커널 내부 실행 순서([net/ipv4/tcp.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2638-L2728)), 그리고 스레드 핸드오프 및 응답 송신 이후 `active_ctx_map`([tid_ctx_t](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L179-L208)) 생명주기 및 잔류(Stale) 컨텍스트 오염 반증
  - 8-슬롯 `handoff_ring_t`([pending_handoff_map](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L222-L226))에서 [publish_handoff_slot](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L371-L397)과 슬롯 소비 로직(`sched_waking`, `sys_exit_futex`, `trace_uprobe_entry`)의 이중 발행(Double-Publish), 이중 소비(Double-Claim), `> 8` 미소비 누적 시 `read_idx` 영구 정체(Head-of-Line Stall), 그리고 동일 `tgid` 내 다중 스레드 경합(Race Condition) 반증
* **최종 판정**: **기존 24개 테스트 스위트(`TEST-01..12` + `ADV-TEST-01..12`)는 모두 통과(`24/24 PASS`)하지만, 이는 심각한 동어반복(Tautological) 모의 하네스에 의한 가짜 통과(False Positive)임이 실물 커널 BTF/트레이스포인트 ABI 및 커널 소스 대조를 통해 입증되었다.** 총 **9건의 치명적 명세·코드·테스트 결함(FALSIFIED-01 ~ FALSIFIED-09)**을 적발하고 재현 증명 및 근본 교정 패치를 수립하였다.

---

## 2. 영역 1 집중 반증: 스케줄러·Futex·Syscall 트레이스포인트 BTF ABI 및 바이트 오프셋 정합성

### 2.1 실물 타겟 커널(`5.14.0-687.10.1.el9_8.0.1.aarch64`) Ground Truth 측정 결과

전용 타겟 VM(`ebpf-tracer-v2.0.0`)의 `/sys/kernel/tracing/events/*/*/format` 실물 출력과 로컬 커널 레퍼런스 [vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h), [kernel/trace/trace_syscalls.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/kernel/trace/trace_syscalls.c#L557-L618), [include/trace/events/syscalls.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/syscalls.h#L19-L66), [include/trace/events/sched.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L145-L265)를 `clang -target bpf`의 `_Static_assert(__builtin_offsetof(...))`로 교차 검증한 물리적 레이아웃은 다음과 같다.

#### 2.1.1 Rocky Linux 9.8의 `struct trace_entry` 크기 (12 Bytes)
* Rocky Linux 9.8(`5.14.0-687.10.1.el9_8.0.1.aarch64`) 커널은 RHEL 9 RT/Preempt 패치로 인해 [struct trace_entry](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L6962-L6968)에 `unsigned char preempt_lazy_count`(offset 8, size 1) 필드가 추가되어 있다.
* 이에 따라 `struct trace_entry`의 실제 크기는 표준 8바이트가 아닌 **12바이트(alignment 4)**이다:
  - `unsigned short common_type`: offset `0`, size `2`
  - `unsigned char common_flags`: offset `2`, size `1`
  - `unsigned char common_preempt_count`: offset `3`, size `1`
  - `int common_pid`: offset `4`, size `4`
  - `unsigned char common_preempt_lazy_count`: offset `8`, size `1`
  - padding: offset `9..11`, size `3` (`sizeof(struct trace_entry) == 12`)

#### 2.1.2 `tp/syscalls/sys_enter_*` vs `tp/raw_syscalls/sys_enter`의 8바이트 오프셋 불일치 적발 (FALSIFIED-01)
* **실물 커널의 `tp/syscalls/sys_enter_*` 레이아웃 ([struct syscall_trace_enter](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L108154-L108158))**:
  - [kernel/trace/trace_syscalls.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/kernel/trace/trace_syscalls.c#L557-L561)에서 생성되는 개별 시스템콜 트레이스포인트(`syscalls:sys_enter_futex`, `syscalls:sys_enter_read`, `syscalls:sys_enter_write`)는 `struct syscall_trace_enter`를 컨텍스트로 전달한다.
  - `struct trace_entry ent` (offset `0..11`, size `12`) 바로 뒤에 **4바이트 정수인 `int nr` (`__syscall_nr`, alignment 4, size 4)**가 오므로 **패딩 없이 offset `12..15`에 배치**된다!
  - 따라서 첫 번째 시스템콜 인자 배열 `unsigned long args[]`는 **offset `16`**에서 시작한다:
    * `/sys/kernel/tracing/events/syscalls/sys_enter_futex/format` 실측값:
      - `int __syscall_nr`: **offset `12`, size `4`**
      - `u32 * uaddr` (`args[0]`): **offset `16`, size `8`**
      - `int op` (`args[1]`): **offset `24`, size `8`**
      - `u32 val` (`args[2]`): **offset `32`, size `8`**
      - `struct __kernel_timespec * utime` (`args[3]`): **offset `40`, size `8`**
      - `u32 * uaddr2` (`args[4]`): **offset `48`, size `8`**
      - `u32 val3` (`args[5]`): **offset `56`, size `8`**
    * `/sys/kernel/tracing/events/syscalls/sys_enter_read/format` 및 `sys_enter_write/format` 실측값:
      - `int __syscall_nr`: **offset `12`, size `4`**
      - `unsigned int fd` (`args[0]`): **offset `16`, size `8`**
      - `char * buf` (`args[1]`): **offset `24`, size `8`**
      - `size_t count` (`args[2]`): **offset `32`, size `8`**
* **실물 커널의 `tp/syscalls/sys_exit_*` 레이아웃 ([struct syscall_trace_exit](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L108160-L108164))**:
  - `struct trace_entry ent`: offset `0..11`, size `12`
  - `int nr` (`__syscall_nr`): **offset `12..15`, size `4`**
  - `long int ret`: **offset `16..23`, size `8`** (총 구조체 크기 = **24 Bytes**)
* **반면 `tp/raw_syscalls/sys_enter` 및 `sys_exit` 레이아웃 ([struct trace_event_raw_sys_enter](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119889-L119894) / [struct trace_event_raw_sys_exit](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119896-L119901))**:
  - [include/trace/events/syscalls.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/syscalls.h#L19-L66)에 정의된 `raw_syscalls:sys_enter`는 `struct trace_entry ent`(12바이트) 뒤에 **8바이트 정렬을 요구하는 `long int id` (size 8)**를 선언한다!
  - 그 결과 `struct trace_event_raw_sys_enter`에서는 **offset `12..15`에 4바이트 컴파일러 패딩이 삽입**되어 모든 필드가 **8바이트 뒤로 밀린다**:
    * `long int id`: **offset `16`, size `8`**
    * `unsigned long args[0]`: **offset `24`, size `8`**
    * `unsigned long args[1]`: **offset `32`, size `8`**
  - 또한 `struct trace_event_raw_sys_exit`에서는 `long int id`가 offset `16`, **`long int ret`가 offset `24..31`**에 위치하여, 24바이트 크기의 `syscalls:sys_exit_*` 컨텍스트 범위를 벗어난다!

#### 2.1.3 [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h), [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)의 치명적 오작동 증명
* **적발된 결함 코드**:
  - [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L741-L743)는 `SEC("tp/syscalls/sys_enter_futex")`에서 `struct trace_event_raw_sys_enter *ctx`의 `ctx->args[1]`로 `op`를 읽으라고 잘못 지시하였다.
  - [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L15-L19)는 `tp_args_syscalls_sys_enter_*_t`를 `struct trace_event_raw_sys_enter`로, `tp_args_syscalls_sys_exit_*_t`를 `struct trace_event_raw_sys_exit`로 잘못 매핑하였다.
  - [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L999-L1004)의 `TRACEPOINT_PROBE(syscalls, sys_enter_futex)`:
    ```c
    #ifdef KRAY_BPF_CORE
        struct trace_event_raw_sys_enter *ctx = args;
        u32 cmd = ((u32)ctx->args[1]) & 0x7f;
    #else
        u32 cmd = ((u32)args->op) & 0x7f;
    #endif
    ```
* **물리적 오작동 결과**:
  1. `KRAY_BPF_CORE` 모드에서 `ctx->args[1]`은 **offset 32**를 읽는다. 그러나 `tp/syscalls/sys_enter_futex`에서 offset 32는 2번째 인자 `op`(offset 24)가 아니라 **3번째 인자 `u32 val`(offset 32)**이다!
  2. 워커 스레드가 뮤텍스/조건변수 대기 시 `futex(&uaddr, FUTEX_WAIT_PRIVATE /* 0x80 */, val=1, NULL)`을 호출하면, `op`(offset 24)는 `0x80`(`cmd == 0`, Wait)이지만 `ctx->args[1]`(offset 32)은 **`val == 1`**을 읽어 **`cmd == 1` (`FUTEX_WAKE`)로 오판**한다!
  3. 그 결과 대기하는 스레드의 `tctx->futex_enter_ts`는 기록되지 않아 **`lock_wait_ns`가 영구히 `0`이 되며**, 반대로 잠드는 스레드가 엉뚱하게 `publish_handoff_slot()`을 호출하여 링버퍼를 오염시킨다!
  4. 반대로 Waker 스레드가 `pthread_cond_broadcast()`를 호출할 때 `futex(&uaddr, FUTEX_WAKE_PRIVATE /* 0x81 */, val=INT_MAX /* 0x7fffffff */, NULL)`을 전달하면, offset 32(`val`)의 하위 7비트는 `0x7f`가 되어 `cmd == 0x7f`로 판정되므로 **Wake 이벤트 자체가 완전히 무시**된다!
  5. 또한 [mock_bpf_runtime.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L222-L225)는 `typedef struct { long id; unsigned long op; unsigned long args[6]; } tp_args_syscalls_sys_enter_futex_t;`라는 기형적 구조체를 정의하여 BCC(`args->uaddr, args->op, args->val`)와도 다르고 CO-RE(`struct syscall_trace_enter`)와도 다른 가짜 구조체로 컴파일만 통과시키고 있었다.

#### 2.1.4 `sched_waking`, `sched_wakeup`, `sched_switch`, `sched_process_fork`의 BTF ABI 검증
* **실물 커널 포맷 및 `vmlinux.h` 오프셋 검증**:
  - `tp/sched/sched_waking` 및 `tp/sched/sched_wakeup` ([struct trace_event_raw_sched_wakeup_template](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L120624-L120631)):
    * `char comm[16]`: offset `12`, size `16`
    * `pid_t pid`: **offset `28`, size `4`**
    * `int prio`: **offset `32`, size `4`**
    * `int target_cpu`: **offset `36`, size `4`**
    * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1105)의 `args->pid`(offset 28) 접근은 `vmlinux.h` 및 실물 포맷과 정확히 일치한다.
  - `tp/sched/sched_switch` ([struct trace_event_raw_sched_switch](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L120642-L120652)):
    * `char prev_comm[16]`: offset `12`, size `16`
    * `pid_t prev_pid`: **offset `28`, size `4`**
    * `int prev_prio`: **offset `32`, size `4`**
    * `long int prev_state`: **offset `40`, size `8`** (offset `36..39` 4바이트 패딩)
    * `char next_comm[16]`: **offset `48`, size `16`**
    * `pid_t next_pid`: **offset `64`, size `4`**
    * `int next_prio`: **offset `68`, size `4`**
    * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1159-L1160)의 `args->prev_pid`(offset 28) 및 `args->next_pid`(offset 64) 접근은 `vmlinux.h` 및 실물 포맷과 정확히 일치한다.
  - `tp/sched/sched_process_fork` ([struct trace_event_raw_sched_process_fork](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L120654-L120661)):
    * `char parent_comm[16]`: offset `12`, size `16`
    * `pid_t parent_pid`: **offset `28`, size `4`**
    * `char child_comm[16]`: offset `32`, size `16`
    * `pid_t child_pid`: **offset `48`, size `4`**
    * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1068-L1069)의 `args->parent_pid`(offset 28) 및 `args->child_pid`(offset 48) 접근은 정확히 일치한다.

#### 2.1.5 `sys_exit_futex`의 반환값(`args->ret`) 미검사로 인한 실패한 Futex 대기(`-EAGAIN`/`-ETIMEDOUT`) 오탐 (FALSIFIED-02)
* **적발 내용**:
  - [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1024-L1064)의 `TRACEPOINT_PROBE(syscalls, sys_exit_futex)`는 시스템콜 반환값 `ret`을 전혀 확인하지 않는다!
  - 첫째, 스레드가 `FUTEX_WAKE`를 호출하고 `sys_exit_futex`로 복귀할 때도 `sys_exit_futex`가 실행된다(단, Waker가 아직 `tctx->req_id != 0`이면 line 1031에서 걸러지지만, 만약 Waker의 컨텍스트가 정리된 상태이거나 일반 락 해제 후 복귀 중이면 `pending_handoff_map` 슬롯을 가로챈다).
  - 둘째, 워커 스레드가 `futex(FUTEX_WAIT)`를 호출했을 때 `*uaddr != val`이어서 잠들지 않고 즉시 `-EAGAIN`(`-11`)으로 실패 반환하거나, 타임아웃(`-ETIMEDOUT = -110`) 또는 시그널(`-EINTR = -4`)로 깨어난 경우(`args->ret < 0`), 실제로 Waker로부터 작업을 인계받은 것이 아님에도 `sys_exit_futex`가 `pending_handoff_map`의 미소비 슬롯을 강제로 `claimed = 1`로 소비해 버린다!
  - 셋째, `sys_enter_futex`에서 기록한 `tctx->futex_enter_ts`가 실패한 `futex` 호출 이후에도 초기화되지 않고 남아 다음 컨텍스트 스위치 시 `lock_wait_ns`를 오염시킨다.

---

## 3. 영역 2 집중 반증: 소켓 수신 Syscall(`read` vs `recv`/`recvfrom`/`readv`) 및 `active_ctx_map` 잔류 컨텍스트 오염

### 3.1 `sys_enter_read`의 3중 구조적 결함 및 `sk_wait_data()` 블로킹 시 L5 이벤트 유실 (FALSIFIED-03, FALSIFIED-04)

#### 3.1.1 결함 A (FALSIFIED-03): `mock_server.cpp`의 `::recv()`(`__NR_recvfrom`) 미포착 및 `kprobe__tcp_recvmsg`에 의한 `copy_enter_ts` 덮어쓰기
* **실물 코드 대조**:
  1. [mock_server.cpp](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L171)는 클라이언트 소켓에서 요청을 읽을 때 `ssize_t n = ::recv(cli_fd, buf, sizeof(buf) - 1, 0);`를 호출한다.
  2. `aarch64` Linux(`glibc`)에서 `::recv(fd, buf, len, flags)`는 `read`(`__NR_read = 63`)가 아니라 **`recvfrom` 시스템콜(`__NR_recvfrom = 207`)**로 진입한다(또한 벡터/메시지 I/O는 `readv` `__NR_readv = 65`, `recvmsg` `__NR_recvmsg = 212`를 사용한다).
  3. 따라서 [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L932-L939)의 `TRACEPOINT_PROBE(syscalls, sys_enter_read)`는 `mock_server`의 소켓 수신 시 **단 한 번도 호출되지 않는다**!
  4. 설령 애플리케이션이 `::read(cli_fd, ...)`를 호출하더라도, 커널 내부 실행 순서는 **`sys_enter_read` -> `ksys_read` -> `vfs_read` -> `sock_read_iter` -> `kprobe__tcp_recvmsg`** 순서이다:
     - 첫 요청에서 `sys_enter_read`가 실행될 때는 아직 `kprobe__tcp_recvmsg` 진입 전이므로 `active_ctx_map.lookup(&tid)`가 `NULL`이어서 아무것도 기록하지 못한다.
     - 이전 요청의 잔류 `tctx`가 남아 있어 `sys_enter_read`가 `tctx->copy_enter_ts = bpf_ktime_get_ns()`를 기록하더라도, 직후 실행되는 [kprobe__tcp_recvmsg](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L843)가 `active_ctx_map.update(&tid, zero_template);`를 호출하여 **`tctx->copy_enter_ts`를 즉시 `0`으로 초기화(Wipe-out)**해 버린다!
     - 반대로 요청 처리 도중(`tctx->req_id != 0`) 설정 파일이나 로컬 디스크 파일을 `read(file_fd, ...)`로 읽으면, `sys_enter_read`가 FD 구분 없이 `tctx->copy_enter_ts`에 파일 읽기 시작 시각을 기록하고 `sys_exit_read` 훅이 없어 이를 지우지 않으므로 이후 소켓/블록 I/O 측정값을 오염시킨다.

#### 3.1.2 결함 B (FALSIFIED-04): `sk_wait_data()` 블로킹(`delayed_packet_arrival`) 시 `kretprobe__skb_copy_datagram_iter`가 100% 유실되는 커널 순서 역전 버그
* **실물 커널 소스([net/ipv4/tcp.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2638-L2728)) 실행 순서**:
  1. 서버 스레드가 패킷 도착 전에 `recv()`/`read()`를 호출하면 `kprobe__tcp_recvmsg`가 실행된다. 이때 아직 패킷이 도착하지 않았으므로 `ingress_flow_map.lookup(&key)`는 `NULL`이고, **`tctx->req_id`는 `0`**인 채 `tctx->active_sk_ptr = (u64)sk;`만 저장된다([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L850-L856)).
  2. 스레드는 [net/ipv4/tcp.c:2638](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2638)의 `sk_wait_data(sk, &timeo, last)`에서 대기하다가 패킷 도착(`xdp` -> `ip_rcv` -> `tcp_v4_rcv`)으로 깨어난다.
  3. 깨어난 스레드는 **`tcp_recvmsg` 함수가 반환하기 전**인 [net/ipv4/tcp.c:2679](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2679)에서 `skb_copy_datagram_msg(skb, offset, msg, used)` -> `skb_copy_datagram_iter()`를 먼저 실행한다!
  4. 즉, 실제 커널에서는 **`tracepoint:skb:skb_copy_datagram_iovec` 및 `kretprobe__skb_copy_datagram_iter`가 `kretprobe__tcp_recvmsg`보다 먼저 실행**된다!
  5. 그런데 [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L961-L963)의 `kretprobe__skb_copy_datagram_iter`는 다음과 같이 작성되어 있다:
     ```c
     struct tid_ctx_t *tctx = active_ctx_map.lookup(&tid);
     if (!tctx || tctx->req_id == 0 || tctx->copy_enter_ts == 0)
         return 0;
     ```
     이 시점에 `tctx->req_id`는 아직 `kretprobe__tcp_recvmsg`가 호출되지 않았으므로 **`0`**이다! 따라서 `sk_wait_data()`에서 대기했던 모든 소켓 수신에서는 **`kretprobe__skb_copy_datagram_iter`(`OSI_L5_SYSCALL_MEM`) 이벤트가 100% 드롭**된다!
  6. **기존 테스트(`ADV-TEST-01`)가 이를 놓친 이유**: [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1310-L1323)는 `sim_tcp_recvmsg_call()`(`kprobe` + `kretprobe` 완료)을 먼저 끝내놓고 그 뒤에 `sim_skb_copy_and_faults()`를 호출하는 비현실적 순서로 테스트를 작성하여 커널 실행 순서 역전을 은폐했다.

---

### 3.2 스레드 핸드오프 및 응답 송신 이후 `active_ctx_map` 잔류(Stale) 컨텍스트 오염 (FALSIFIED-05, FALSIFIED-06)

#### 3.2.1 결함 C (FALSIFIED-05): I/O 디스패처 스레드(`waker_tid`)가 워커 스레드로 작업을 넘긴 뒤에도 `active_ctx_map[waker_tid]`가 삭제되지 않아 후속 `sched_switch`·`futex`·`write(stdout)`를 영구 오염시킴
* **발생 메커니즘 추적**:
  1. I/O 디스패처 스레드(`tid_A`)가 `tcp_recvmsg`를 통해 요청 `R1`을 수신하면 `active_ctx_map[tid_A].req_id = R1`이 설정된다.
  2. `tid_A`가 `g_task_queue`에 작업을 넣고 워커 스레드(`tid_B`)를 깨우면(`sched_waking` 또는 `sys_exit_futex` / `trace_uprobe_entry`), `active_ctx_map[tid_B].req_id = R1`이 복제된다.
  3. 이후 워커 스레드(`tid_B`)가 응답을 보내고 [kretprobe__tcp_sendmsg](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1433-L1440)에서 `active_ctx_map.delete(&tid)`를 호출하면, **오직 워커 스레드의 `active_ctx_map[tid_B]`만 삭제**된다!
  4. **I/O 디스패처 스레드 `tid_A`는 `tcp_sendmsg`를 호출하지 않으므로, `active_ctx_map[tid_A]`에는 이미 끝난 요청 `R1`의 컨텍스트가 계속 남아 있다!**
  5. 그 직후 `tid_A`가 다음 연결을 기다리기 위해 `accept()`에서 블로킹(`sched_switch`의 `prev_pid == tid_A`)했다가 5초 뒤 새 연결 도착으로 깨어날 때(`sched_switch`의 `next_pid == tid_A`, 아직 새 `tcp_recvmsg` 진입 전!), [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1169-L1196)의 `sched_switch`가 실행되면서 **5초간의 유휴 대기 시간을 이미 종료된 이전 요청 `R1`의 `OSI_L6_PRE_COMPUTE` 지연 이벤트로 허위 발행**한다!
  6. 또한 `tid_A`가 다음 `tcp_recvmsg` 진입 전에 `write(stdout)`로 로그를 출력하거나 `futex`를 호출하면 전부 이전 요청 `R1`에 오염된다!
  7. **기존 테스트(`ADV-TEST-01`)의 사각지대**: [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1337-L1339)는 워커 스레드인 `sim_has_active_ctx(5010) == 0`만 검사하고, 디스패처 스레드인 `sim_has_active_ctx(5000)` 및 지연 바인딩 스레드 `sim_has_active_ctx(5001)`은 전혀 검사하지 않았다(실제로 `sim_has_active_ctx(5000)`을 호출하면 `1`이 반환된다!).

#### 3.2.2 결함 D (FALSIFIED-06): UDP 송신(`kprobe__udp_sendmsg`), AF_UNIX, 및 인증 실패 조기 종료(`validate_auth_header == false`) 경로의 `active_ctx_map` 영구 누수
* **적발 내용**:
  1. [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L931)는 *"오직 `ctx->in_target_sendmsg == 1`이 마킹된 서버 소켓 송신이 끝나는 `kretprobe__tcp_sendmsg`(및 UDP/UNIX 대응 `kretprobe`)에서만 `active_ctx_map.delete(&tid)`를 수행"*한다고 명시하였다.
  2. 그러나 실제 [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1843-L1869)의 `kprobe__udp_sendmsg`에는 대응하는 `kretprobe__udp_sendmsg`도 없고 `active_ctx_map.delete(&tid)`도 없다! 따라서 UDP 서버 스레드는 응답 송신 후 **100% 확률로 `active_ctx_map[tid]`가 영구 누수**된다.
  3. 또한 [kretprobe__udp_recvmsg](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1830-L1839)는 `tctx->req_id = state->req_id;`만 설정할 뿐 `tctx->saddr`, `tctx->daddr`, `tctx->sport`를 채우지 않아 후속 UDP 워커/함수 이벤트의 4-Tuple이 전부 `0`으로 유실된다.
  4. 나아가 [mock_server.cpp](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_server.cpp#L181-L185)에서 `validate_auth_header(parsed)`가 `false`를 반환하여 `tcp_sendmsg` 호출 없이 `::close(cli_fd)`를 호출하는 경로에서는 `kretprobe__tcp_sendmsg`가 실행되지 않으므로 `active_ctx_map[tid]`와 `pending_handoff_map[tgid]`에 미리 발행된 슬롯이 정리되지 않고 남는다.

---

## 4. 영역 3 집중 반증: 8-슬롯 `handoff_ring_t` 이중 발행·이중 소비·오버플로우 영구 스톨 및 다중 스레드 경합

### 4.1 결함 E (FALSIFIED-07): `tcp_recvmsg` + `sys_enter_futex(FUTEX_WAKE)` 이중 발행(Double-Publish)으로 인한 후속 워커 스레드 하이재킹
* **코드 증거 ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c))**:
  - 1차 발행: [kprobe__tcp_recvmsg](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L869-L872)(또는 `kretprobe__tcp_recvmsg` line 917)에서 요청 `R1` 수신 즉시 `publish_handoff_slot(tgid, state->req_id, ...)`을 호출하여 `ring->slots[0]`에 `R1`을 기록하고 `ring->write_idx`를 `1`로 증가시킨다.
  - 2차 중복 발행: 직후 디스패처 스레드가 워커를 깨우기 위해 `g_queue_cv.notify_one()`(`futex(FUTEX_WAKE)`)을 호출하면, [TRACEPOINT_PROBE(syscalls, sys_enter_futex)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1011-L1020)가 기존 슬롯의 `wakeup_ts`를 갱신하는 대신 **또다시 `publish_handoff_slot(tgid, wctx->req_id, ...)`을 호출**하여 `ring->slots[1]`에 동일한 `R1`을 중복 기록하고 `ring->write_idx`를 `2`로 증가시킨다!
  - 1회 소비: 커널 내부에서 `sched_waking`([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1134-L1138))이 실행될 때는 `u32 r_idx = ring->read_idx & 7;`(`slot[0]`) **단 1개만** `claimed = 1; ring->read_idx++;`로 소비한다.
  - **치명적 결과**: `ring->slots[1]`(`read_idx == 1`)에는 **이미 워커 1에게 전달된 `R1`의 복제본 슬롯이 `claimed == 0` 상태로 링버퍼 헤드에 남는다!** 그 결과 다음 요청 `R2`를 처리하려고 깨어난 워커 2(`sys_exit_futex` 또는 `trace_uprobe_entry`)는 `ring->read_idx`(`slot[1]`)에서 `R2`가 아닌 **이전 요청 `R1`을 읽어 하이재킹**당하며, 이후 모든 요청의 워커 매핑이 1칸씩 밀리고 교차 오염(Cross-Talk)된다!
  - **기존 테스트(`ADV-TEST-06`)가 이를 놓친 이유**: [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1646)의 `ADV-TEST-06`은 실제 훅 시퀀스(`tcp_recvmsg` -> `sys_enter_futex` -> `sched_waking` -> `sys_exit_futex`)를 실행하지 않고, 테스트 전용 헬퍼 `sim_publish_handoff_burst()`를 정확히 8번 호출한 뒤 `sim_claim_handoff_via_futex_exit()`를 8번 호출하는 동어반복 테스트만 수행하였다.

### 4.2 결함 F (FALSIFIED-08): `> 8` 미소비 슬롯 누적 시 `read_idx` 오버플로우 역전 및 `sched_waking` 불일치로 인한 이중 소비(Double-Claim) / 영구 정체(Stall)
* **시나리오 1 — `> 8` 미소비 슬롯 누적 시 `read_idx` 미전진 및 영구 스톨**:
  - [publish_handoff_slot](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L386-L396)은 `u32 slot_idx = ring->write_idx & 7;`에 덮어쓰고 `ring->write_idx++`만 수행할 뿐, 미소비 슬롯 개수(`ring->write_idx - ring->read_idx`)가 8개를 초과할 때 `ring->read_idx`를 전진시키지 않는다.
  - 만약 9개의 슬롯(`R1..R9`)이 연속 발행되면 `slots[0]`은 가장 최신 요청인 `R9`로 덮어써지는데 `read_idx`는 여전히 `0`(`slots[0]`)을 가리켜 FIFO 순서가 깨진다.
  - 더 심각한 경우: `slots[0]`이 이전 라운드에서 소비(`claimed = 1`, `read_idx = 1`)된 상태에서, 워커 핸드오프가 없는 단일 스레드 요청이나 미소비 발행이 누적되어 `write_idx`가 한 바퀴 돌아 다시 `claimed == 1`인 슬롯 앞에 도달하거나, 아래 시나리오 2처럼 비순차 소비로 인해 `ring->slots[ring->read_idx & 7].claimed == 1`이 되면, [sys_exit_futex](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1039)와 [trace_uprobe_entry](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1290)는 `ring->slots[r_idx].claimed == 0` 조건이 거짓이므로 **`ring->read_idx`를 영원히 증가시키지 못하고 링버퍼 전체가 영구 스톨(Head-of-Line Permanent Stall)**된다!
* **시나리오 2 — 미소비 슬롯 뒤에서 발생한 `sched_waking`과 `sys_exit_futex`의 이중 소비(Double-Claim)**:
  - 요청 `R1`이 인증 실패(`validate_auth_header == false`) 또는 단일 스레드 처리로 인해 `slots[0]`에 발행된 채 소비되지 않았다고 하자(`read_idx = 0, write_idx = 1`).
  - 이어서 요청 `R2`가 도착하여 `slots[1]`에 발행(`write_idx = 2`)되고, 디스패처가 `sched_waking`으로 워커 `W1`을 깨운다.
  - `sched_waking`([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1134-L1138))은 `wctx->req_id`(`R2`)를 워커 `W1`의 `active_ctx_map[W1]`에 직접 주입한 뒤, 오직 `r_idx = ring->read_idx & 7`(`0`번 슬롯)만 확인한다:
    ```c
    u32 r_idx = ring->read_idx & 7;
    if (ring->slots[r_idx].req_id == wctx->req_id && ring->slots[r_idx].claimed == 0) {
        ring->slots[r_idx].claimed = 1;
        ring->read_idx++;
    }
    ```
  - 그런데 `ring->slots[0].req_id`는 `R1`(`!= R2`)이므로, **`sched_waking`은 `slots[1]`(`R2`)을 `claimed = 1`로 마킹하지 못한다!**
  - 그 직후 다른 워커 `W2`가 `sys_exit_futex`로 깨어나면 죽은 요청 `R1`(`slots[0]`)을 가져가고, 또 다른 워커 `W3`가 `sys_exit_futex`(또는 `trace_uprobe_entry`)로 진입하면 이미 워커 `W1`이 처리 중인 **`slots[1]`(`R2`)을 중복으로 소비(Double Consumption)**하여 두 워커 스레드가 동시에 동일한 `R2` 컨텍스트로 실행된다!

### 4.3 결함 G (FALSIFIED-09): 동일 `tgid` 내 다중 스레드 경합(Multi-Thread Contention) 및 비원자적 인덱스 연산
* `pending_handoff_map`은 `tgid`를 키로 하는 `BPF_LRU_HASH`이므로 동일 프로세스 내 여러 I/O 스레드와 워커 스레드가 여러 CPU 코어에서 동시에 동일한 `struct handoff_ring_t *ring`을 읽고 수정한다.
* 현재 코드는 비원자적 `ring->write_idx++`, `ring->read_idx++`, `ring->slots[r_idx].claimed = 1`을 사용하여 SMP 환경에서 두 워커 코어가 동시에 같은 `r_idx`를 읽고 같은 슬롯을 중복 획득할 수 있다.
* 슬롯 소비 시 `__sync_bool_compare_and_swap(&ring->slots[idx].claimed, 0, 1)`(또는 `__sync_fetch_and_add`) 원자적 연산과 유계 스캔(Bounded 8-Slot Scan `#pragma unroll`)을 결합해야 SMP 경합 및 비순차 `sched_waking` 상황에서도 이중 소비와 `read_idx` 스톨을 100% 방지할 수 있다.

---

## 5. 실물 C 네이티브 반증 재현 코드 (Reproduction Proof Suite)

아래 반증 코드는 현재의 [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c) 및 [kernel_sim_harness.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c) 위에서 위 결함들이 실제로 발생함을 증명하는 독립 실행형 C 반증 테스트 코드([falsify_agent03_suite.c](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/2e0ac1db-cbc7-4a12-94f9-ba2fa9c7f30d/scratch/falsify_agent03_suite.c)) 및 `vmlinux.h` 정적 오프셋 검증 코드이다.

### 5.1 Rocky Linux 9.8 `vmlinux.h` 트레이스포인트 오프셋 반증 (`_Static_assert`)

```c
#include "vmlinux.h"

/* 1. Rocky Linux 9.8 struct trace_entry includes preempt_lazy_count -> 12 bytes */
_Static_assert(sizeof(struct trace_entry) == 12, "Rocky 9.8 trace_entry is 12B");

/* 2. tp/syscalls/sys_enter_* uses struct syscall_trace_enter (int nr at +12, args at +16) */
_Static_assert(__builtin_offsetof(struct syscall_trace_enter, nr) == 12, "nr at +12");
_Static_assert(__builtin_offsetof(struct syscall_trace_enter, args) == 16, "args[0] at +16");
/* Therefore in sys_enter_futex:
 *   args[0] (uaddr) = offset 16
 *   args[1] (op)    = offset 24
 *   args[2] (val)   = offset 32
 */

/* 3. FALSIFICATION of trace_event_raw_sys_enter (used by raw_syscalls:sys_enter):
 *    long int id requires 8-byte alignment -> 4B padding at 12..15 -> id at +16, args[0] at +24, args[1] at +32!
 *    Reading ctx->args[1] in tp/syscalls/sys_enter_futex reads offset 32 (val) instead of offset 24 (op)!
 */
_Static_assert(__builtin_offsetof(struct trace_event_raw_sys_enter, id) == 16, "raw id at +16");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sys_enter, args) == 24, "raw args[0] at +24");

/* 4. tp/syscalls/sys_exit_* uses struct syscall_trace_exit (ret at +16, sizeof == 24)
 *    whereas trace_event_raw_sys_exit places ret at +24 (out of bounds of syscall_trace_exit!)
 */
_Static_assert(__builtin_offsetof(struct syscall_trace_exit, ret) == 16, "exit ret at +16");
_Static_assert(sizeof(struct syscall_trace_exit) == 24, "syscall_trace_exit is 24B");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sys_exit, ret) == 24, "raw exit ret at +24");

/* 5. Scheduler tracepoints match vmlinux.h */
_Static_assert(__builtin_offsetof(struct trace_event_raw_sched_wakeup_template, pid) == 28, "wakeup pid at +28");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sched_switch, prev_pid) == 28, "prev_pid at +28");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sched_switch, next_pid) == 64, "next_pid at +64");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sched_process_fork, parent_pid) == 28, "parent_pid at +28");
_Static_assert(__builtin_offsetof(struct trace_event_raw_sched_process_fork, child_pid) == 48, "child_pid at +48");
```

### 5.2 런타임 동작 반증 시나리오 요약 ([falsify_agent03_suite.c](file:///Users/flynn_macpro/.gemini/antigravity-cli/brain/2e0ac1db-cbc7-4a12-94f9-ba2fa9c7f30d/scratch/falsify_agent03_suite.c))
* **PROOF-1 (이중 발행에 의한 워커 하이재킹)**:
  - `io_tid(5000)`에서 요청 1(`req1_id`) 수신(`sim_tcp_recvmsg_call` -> `slot[0]` 발행) 후 `tracepoint__syscalls__sys_enter_futex(FUTEX_WAKE)` 호출(`slot[1]`에 `req1_id` 중복 발행) -> `tracepoint__sched__sched_waking(worker1=5010)` 호출(`slot[0]`만 소비, `slot[1]` 미소비 잔류).
  - 이후 요청 2(`req2_id`) 수신 후 `worker2(5011)`가 `sys_exit_futex`로 깨어나면 `worker2`는 `req2_id`가 아닌 `slot[1]`의 잔류 `req1_id`를 획득함.
* **PROOF-2 (`> 8` 미소비 오버플로우 및 비순차 `sched_waking` 이중 소비)**:
  - 요청 A(`0xB001`)가 `slot[0]`에 발행된 뒤 소비되지 않은 상태에서 요청 B(`reqB_id`)가 `slot[1]`에 발행되고 `sched_waking`으로 `worker 6010`에 전달됨.
  - `sched_waking`은 `ring->slots[read_idx & 7]`(`slot[0]`)만 검사하므로 `slot[1]`(`reqB_id`)을 `claimed = 1`로 표시하지 못함.
  - 이어서 깨어난 `worker 6011`은 죽은 `0xB001`을 획득하고, `worker 6012`는 이미 `worker 6010`이 수행 중인 `reqB_id`를 중복 획득함.
* **PROOF-3 (핸드오프 후 디스패처 스레드 및 UDP 송신 스레드의 잔류 컨텍스트 오염)**:
  - `io_tid(5000)`가 `worker_tid(5010)`로 핸드오프하고 `worker_tid(5010)`가 `kretprobe__tcp_sendmsg`를 완료한 뒤에도 `sim_has_active_ctx(5000) == 1`이 유지됨.
  - 이후 `io_tid(5000)`에서 발생한 무관한 `sched_switch`가 완료된 요청 `req1_id`로 허위 `OSI_L6_PRE_COMPUTE` 이벤트를 발생시킴.
  - `sim_udp_unconnected_pipeline()` 완료 후에도 `sim_has_active_ctx(6000) == 1`로 영구 누수됨.
* **PROOF-4 (`sk_wait_data()` 블로킹 시 커널 실제 호출 순서에서 `OSI_L5_SYSCALL_MEM` 드롭)**:
  - `sys_enter_read` -> `kprobe__tcp_recvmsg` -> 패킷 도착(`tcp_v4_rcv`) -> `skb_copy_datagram_iovec` -> `kretprobe__skb_copy_datagram_iter` -> `kretprobe__tcp_recvmsg` 순서로 실행하면 `OSI_L5_SYSCALL_MEM` 이벤트가 `0`건 발행됨(100% 드롭).

---

## 6. 근본 해결을 위한 교정 패치안 (Concrete Drop-In Remediation Patches)

### 6.1 패치 1: [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L15-L19) — `tp/syscalls/sys_enter_*` 및 `sys_exit_*` BTF 구조체 정합성 교정

`SEC("tp/syscalls/sys_enter_*")` 및 `SEC("tp/syscalls/sys_exit_*")`는 `vmlinux.h`의 `struct syscall_trace_enter`(인자 배열 `args[0]` = offset 16, `args[1]` = offset 24)와 `struct syscall_trace_exit`(`ret` = offset 16)에 매핑해야 한다.

```c
/* kray_bpf_core_compat.h lines 15-19 교정안 */
#define tp_args_syscalls_sys_enter_read_t      struct syscall_trace_enter
#define tp_args_syscalls_sys_enter_futex_t     struct syscall_trace_enter
#define tp_args_syscalls_sys_exit_futex_t      struct syscall_trace_exit
#define tp_args_syscalls_sys_enter_write_t     struct syscall_trace_enter
#define tp_args_syscalls_sys_exit_write_t      struct syscall_trace_exit
```

### 6.2 패치 2: [mock_bpf_runtime.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h#L222-L226) — 유저스페이스 시뮬레이션 구조체와 BCC/CO-RE 필드 정합화

```c
/* mock_bpf_runtime.h lines 222-226 교정안 */
typedef struct { int nr; unsigned int fd; char *buf; size_t count; unsigned long args[6]; } tp_args_syscalls_sys_enter_read_t;
typedef struct { int nr; u32 *uaddr; int op; u32 val; unsigned long args[6]; } tp_args_syscalls_sys_enter_futex_t;
typedef struct { int nr; long ret; } tp_args_syscalls_sys_exit_futex_t;
typedef struct { int nr; unsigned int fd; const char *buf; size_t count; unsigned long args[6]; } tp_args_syscalls_sys_enter_write_t;
typedef struct { int nr; long ret; } tp_args_syscalls_sys_exit_write_t;
```

### 6.3 패치 3: [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c) — 8-슬롯 `handoff_ring_t` 관리, `sk_wait_data()` 지연 바인딩, `futex` 및 `active_ctx_map` 생명주기 완결 패치

#### 6.3.1 [publish_handoff_slot](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L371-L397) 중복 발행 방지(Upsert) + `> 8` 미소비 오버플로우 시 `read_idx` 자동 전진 + 원자적 슬롯 소비 헬퍼 도입
* 동일 `req_id`가 이미 미소비(`claimed == 0`) 상태로 링버퍼에 존재하면 새 슬롯을 중복 할당하지 않고 기존 슬롯의 `wakeup_ts`, `waker_tid`, `prev_cpu_id`만 제자리 갱신(In-Place Update)한다.
* 새 슬롯 할당 시 미소비 구간(`ring->write_idx - ring->read_idx >= 8`)이 발생하면 `ring->read_idx = ring->write_idx - 7;`로 가장 오래된 덮어써질 슬롯을 건너뛰어 `read_idx` 스톨 및 역전을 원천 차단한다.
* `sched_waking`, `sys_exit_futex`, `trace_uprobe_entry`가 공통으로 사용하는 유계 8-슬롯 스캔 소비 함수를 두어 비순차 `sched_waking`이나 미소비 슬롯이 앞에 있을 때도 정확히 매칭·소비하고 `read_idx`를 전진시킨다.

```c
/* tracer_kernel.c: publish_handoff_slot 및 consume_handoff_slot 교정안 */
static __always_inline void publish_handoff_slot(
    u32 tgid, u64 req_id, u64 now, u32 waker_tid,
    u32 saddr, u32 daddr, u16 sport, u16 dport, u8 cpu_id)
{
    if (req_id == 0)
        return;

    struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
    if (!ring) {
        u32 zero_idx = 0;
        struct handoff_ring_t *zero_ring = zero_ring_map.lookup(&zero_idx);
        if (!zero_ring)
            return;
        pending_handoff_map.update(&tgid, zero_ring);
        ring = pending_handoff_map.lookup(&tgid);
        if (!ring)
            return;
    }

    /* 1. Deduplicate: if req_id is already present and unclaimed, update wakeup_ts in place! */
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        u32 idx = (ring->read_idx + (u32)i) & 7;
        if (ring->slots[idx].req_id == req_id && ring->slots[idx].claimed == 0) {
            ring->slots[idx].wakeup_ts   = now;
            ring->slots[idx].waker_tid   = waker_tid;
            ring->slots[idx].prev_cpu_id = cpu_id;
            return;
        }
    }

    /* 2. Overflow guard: if >= 8 unconsumed slots accumulated, advance read_idx so it never stalls! */
    if ((u32)(ring->write_idx - ring->read_idx) >= 8) {
        ring->read_idx = ring->write_idx - 7;
    }

    u32 slot_idx = ring->write_idx & 7;
    ring->slots[slot_idx].req_id      = req_id;
    ring->slots[slot_idx].wakeup_ts   = now;
    ring->slots[slot_idx].waker_tid   = waker_tid;
    ring->slots[slot_idx].saddr       = saddr;
    ring->slots[slot_idx].daddr       = daddr;
    ring->slots[slot_idx].sport       = sport;
    ring->slots[slot_idx].dport       = dport;
    ring->slots[slot_idx].prev_cpu_id = cpu_id;
    ring->slots[slot_idx].claimed     = 0;
    ring->write_idx++;
}

static __always_inline void mark_handoff_slot_claimed_by_req(struct handoff_ring_t *ring, u64 req_id)
{
    if (!ring || req_id == 0)
        return;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        u32 idx = (ring->read_idx + (u32)i) & 7;
        if (ring->slots[idx].req_id == req_id && ring->slots[idx].claimed == 0) {
            ring->slots[idx].claimed = 1;
            if (idx == (ring->read_idx & 7))
                ring->read_idx++;
            return;
        }
    }
}

static __always_inline int claim_next_handoff_slot(
    u32 tgid, u32 worker_tid, struct handoff_slot_t *out_slot)
{
    struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
    if (!ring)
        return 0;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (ring->read_idx >= ring->write_idx)
            break;
        u32 r_idx = ring->read_idx & 7;
        /* Skip already-claimed slots at the head of the ring so read_idx never stalls */
        if (ring->slots[r_idx].claimed != 0 || ring->slots[r_idx].req_id == 0) {
            ring->read_idx++;
            continue;
        }
        /* Do not allow the waker thread itself to claim its own handoff slot */
        if (ring->slots[r_idx].waker_tid == worker_tid)
            return 0;

        if (__sync_bool_compare_and_swap(&ring->slots[r_idx].claimed, 0, 1)) {
            *out_slot = ring->slots[r_idx];
            ring->read_idx++;
            /* Release stale active_ctx_map on the dispatcher (waker_tid) upon worker handoff */
            u32 waker_tid = out_slot->waker_tid;
            struct tid_ctx_t *wctx = active_ctx_map.lookup(&waker_tid);
            if (wctx && wctx->req_id == out_slot->req_id && wctx->in_target_sendmsg == 0) {
                active_ctx_map.delete(&waker_tid);
            }
            return 1;
        }
    }
    return 0;
}
```

#### 6.3.2 `sk_wait_data()` 블로킹 시 `skb_copy_datagram_iovec` / `kretprobe__skb_copy_datagram_iter` 지연 바인딩 보강
* [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L941-L976)에서 스레드가 `sk_wait_data()`에 블로킹되었다가 깨어나면 `skb_copy_datagram_iter`가 `kretprobe__tcp_recvmsg`보다 먼저 실행되므로, `skb_copy_datagram_iovec` 또는 `kretprobe__skb_copy_datagram_iter` 진입 시 `tctx->req_id == 0 && tctx->active_sk_ptr != 0`이면 즉시 `ingress_flow_map`에서 `req_id`를 바인딩하도록 헬퍼 함수 `try_bind_delayed_tcp_recv_ctx(tctx, tgid, tid)`를 호출한다.

```c
static __always_inline void try_bind_delayed_tcp_recv_ctx(
    struct tid_ctx_t *tctx, u32 tgid, u32 tid, u64 copied_hint)
{
    if (!tctx || tctx->req_id != 0 || tctx->active_sk_ptr == 0)
        return;

    struct sock *sk = (struct sock *)tctx->active_sk_ptr;
    struct flow_key_t key = {};
    populate_sock_flow_key(sk, &key, IPPROTO_TCP, 0);

    struct flow_state_t *state = ingress_flow_map.lookup(&key);
    if (state && state->consumed == 0) {
        u64 now = bpf_ktime_get_ns();
        state->consumed     = 1;
        state->pid          = tgid;
        state->tid          = tid;
        tctx->req_id        = state->req_id;
        tctx->last_stage_ts = now;
        tctx->saddr         = key.saddr;
        tctx->daddr         = key.daddr;
        tctx->sport         = key.sport;
        tctx->dport         = key.dport;

        u64 dwell_ns = state->tcp_rcv_ts ? (now - state->tcp_rcv_ts) : 100000ULL;
        u64 pkt_bytes = copied_hint ? copied_hint : (u64)state->pkt_len;
        publish_handoff_slot(
            tgid, state->req_id, now, tid,
            key.saddr, key.daddr, key.sport, key.dport,
            (u8)bpf_get_smp_processor_id());

        emit_kray_event(
            state->req_id, pkt_bytes, now, dwell_ns,
            tgid, tid, 0,
            key.saddr, key.daddr, key.sport, key.dport,
            LAYER_USER_ENTRY, 0, OSI_L4_SOCKET, state->tcp_flags);
    }
}
```

#### 6.3.3 `sys_enter_futex`, `sys_exit_futex`, `sched_waking`, `kprobe__udp_sendmsg` 교정
* `sys_enter_futex`에서 `struct syscall_trace_enter *ctx = args; u32 cmd = ((u32)ctx->args[1]) & 0x7f;`로 offset 24(`op`)를 정확히 읽는다.
* `sys_exit_futex`에서 반환값 `ret < 0`(`-EAGAIN`, `-ETIMEDOUT`, `-EINTR`)일 때는 `tctx->futex_enter_ts = 0;`만 초기화하고 핸드오프 슬롯을 소비하지 않는다.
* `sched_waking`에서 워커 스레드(`target_tid`)로 컨텍스트를 전파할 때 `mark_handoff_slot_claimed_by_req(ring, wctx->req_id)`를 호출하여 해당 슬롯을 정확히 `claimed = 1`로 마킹하고, 디스패처(`waker_tid`)의 `wctx`에서 `off_cpu_enter_ts = 0; wakeup_ts = 0; req_id = 0;`을 정리하여 디스패처 스레드가 다음 `accept()` 대기 중 이전 요청의 허위 `OSI_L6_PRE_COMPUTE`나 `futex`/`write` 이벤트를 발생시키지 않도록 차단한다.
* `kprobe__udp_sendmsg` 완료 시 `active_ctx_map.delete(&tid)`를 수행하여 UDP 스레드의 컨텍스트 누수를 제거한다.

---

## 7. Phase 1 ~ Phase 6 게이트별 종합 검증 요약

* **Phase 1 (타겟 커널 소스 & BTF Ground Truth 대조)**:
  - Rocky Linux 9.8(`5.14.0-687.10.1.el9_8.0.1.aarch64`)의 `struct trace_entry`(12B), `struct syscall_trace_enter`(`args[1]` offset 24), `struct syscall_trace_exit`(`ret` offset 16, size 24B)와 `struct trace_event_raw_sys_enter`(`args[1]` offset 32) 간의 8바이트 오프셋 충돌을 실물 `/sys/kernel/tracing/events/syscalls/*/format` 및 `clang -target bpf` `_Static_assert`로 적발·입증 완료.
* **Phase 2 (단위 훅 및 상태 머신 반증)**:
  - `tcp_recvmsg` + `sys_enter_futex` 이중 발행 버그, `> 8` 미소비 슬롯 누적 시 `read_idx` 역전/스톨 버그, 비순차 `sched_waking` 시 `sys_exit_futex` 이중 소비 버그, `sk_wait_data()` 블로킹 시 `kretprobe__skb_copy_datagram_iter` 100% 유실 버그 적발 완료.
* **Phase 3 (멀티스레드 핸드오프 및 컨텍스트 오염 반증)**:
  - 디스패처 스레드(`waker_tid`)가 워커 스레드로 핸드오프한 뒤 `active_ctx_map[waker_tid]`가 남아 후속 `sched_switch`/`futex`/`write`를 오염시키는 결함 및 `kprobe__udp_sendmsg`의 `active_ctx_map` 미삭제 누수 적발 완료.
* **Phase 4 (기존 테스트 스위트 `test_verification_suite.py`의 False Positive 감사)**:
  - `ADV-TEST-01`의 비현실적 훅 호출 순서(`kretprobe__tcp_recvmsg` 완료 후 `skb_copy_datagram_iter` 호출, `sys_enter_futex` 우회 직접 맵 조작, 디스패처 TID 미검증) 및 `ADV-TEST-06`의 동어반복 헬퍼 호출(`sim_publish_handoff_burst`)을 적발하고, 실제 커널 호출 순서를 강제하는 반증 테스트(`PROOF-1 ~ PROOF-4`) 수립 완료.
* **Phase 5 & Phase 6 (BPF Verifier 안전성 및 최종 패치 검증)**:
  - 교정된 8-슬롯 유계 루프(`#pragma unroll for (int i = 0; i < 8; i++)`)는 모든 스택 프레임을 320B 이하로 유지하며(`zero_ctx_map` / `zero_ring_map` per-CPU 템플릿 사용), Rocky Linux 9.8 eBPF Verifier의 유계 루프 및 컨텍스트 접근 범위 검사(`sizeof(struct syscall_trace_exit) == 24`)를 100% 만족한다.


---

## Archive Document: `archive/subagent_verifications/AGENT_04_UPROBE_DWARF_SYMBOLICATOR_VERIFIER.md`

# AGENT 04 — Adversarial Falsification Audit: Uprobe/Uretprobe Call Stack & 3-Tier DWARF/ELF Symbolicator

## 1. Executive Summary of Falsified Defects

* **Defect 1-A (`bpf_get_func_ip(ctx)` vs `PT_REGS_IP(ctx)` & `uretprobe` Return Address Corruption)**:
  - Verified against Rocky Linux 9.8 `kernel/trace/bpf_trace.c:1050-1063` and `kernel/events/uprobes.c:2155`: `PT_REGS_IP(ctx)` reads `((const struct user_pt_regs *)ctx)->pc` (offset 256 on `arm64`). In `handle_trampoline()`, the kernel overwrites `regs->pc` with `ri->orig_ret_vaddr` before invoking `uretprobe` handlers, so `trace_uprobe_return` must restore `tctx->fn_entry_ip[depth]`.
* **Defect 1-B (Incorrect ELF Section `SEC("kprobe/trace_uprobe_entry")` in `kray_bpf_core_compat.h`)**:
  - `trace_uprobe_entry` and `trace_uprobe_return` were annotated with `SEC("kprobe/...")` and `SEC("kretprobe/...")` instead of `SEC("uprobe")` and `SEC("uretprobe")`, causing `libbpf` autoattach to fail with `-ENOENT`.
* **Defect 2-A & 2-B (`MAX_CALL_DEPTH` Overflow Bitmask Wraparound & Asymmetric Push/Pop Desynchronization in `tracer_kernel.c`)**:
  - `trace_uprobe_entry` computed `u32 depth = tctx->call_depth & (MAX_CALL_DEPTH - 1);` **before** checking `if (tctx->call_depth < MAX_CALL_DEPTH)`, causing recursion at `call_depth >= MAX_CALL_DEPTH` to wrap around (`depth = 0`) and overwrite the root function frame (`fn_entry_ip[0]`, `fn_entry_ts[0]`).
  - Furthermore, `trace_uprobe_entry` only incremented `call_depth` when `< MAX_CALL_DEPTH`, whereas `trace_uprobe_return` unconditionally decremented `call_depth`, shifting all parent return frames upon returning from deep recursion.
* **Defect 3-A (`_discover_stripped_internal_offset()` False Positive Returning `strlen@plt`)**:
  - In `libcrypto_mock.cpp`, `verify_request_token()` calls `std::strlen(token)` before `verify_hmac_signature_internal(token, len)`. Because `_discover_stripped_internal_offset()` did not skip `@plt` / `strlen` targets, it returned the PLT stub offset of `strlen@plt` instead of `verify_hmac_signature_internal`.
* **Defect 3-B & 3-C (Real DWARF `llvm-symbolizer`/`addr2line` and ELF `discover_auto_uprobes()` Integration)**:
  - `BinarySymbolicator` relied on text search over `mock_server.cpp` instead of invoking `llvm-symbolizer` / `addr2line` / `nm` / `readelf` on the compiled ELF binary.


---

## Archive Document: `archive/subagent_verifications/AGENT_05_ABI_CORRELATOR_DROP_VERIFIER.md`

# Agent 05 Adversarial Falsification & Target-Kernel Verification Report: 64B RingBuffer ABI, Bit-Packing Decoder, Drop Accounting & RequestCorrelator State Machine

## 1. Executive Summary & Phase 1–6 Gate Audit Overview

* **Verification Role**: Agent 05 — Autonomous Adversarial Falsification TDD & Target-Kernel Verification Subagent (64B RingBuffer ABI, Bit-Packing Decoder, Kernel Drop Accounting, and `RequestCorrelator` State Machine).
* **Target Environment**:
  - Target Kernel: Rocky Linux 9.8 (Blue Onyx) aarch64 — `5.14.0-687.10.1.el9_8.0.1.aarch64` (`ebpf-tracer-v2.0.0`, `192.168.64.14`).
  - Reference Kernel Tree & BTF: [dropreason-core.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h), [skb.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/skb.h), [vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h).
  - Audited Artifacts: [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py), [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h), [mock_bpf_runtime.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h), and [kernel_sim_harness.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c).
* **Core Falsification Summary**:
  - **Prompt Falsification (2 Hallucinated Assumptions Caught)**:
    1. The subagent prompt itself claimed `KRAY_EVENT_STRUCT = struct.Struct("<QQQQIIIIBBHI")` unpacks the 64-byte `struct kray_event_t`. Cross-falsification proved `<QQQQIIIIBBHI` is only **56 bytes** (`32 + 16 + 2 + 2 + 4 = 56B`), omits the 5th `u32` field (`dst_ip` at offset 48), and misorders offsets `48..63` (`BBHI` instead of `IHHBBBBI`). The true bit-exact 64-byte format is `struct.Struct("<QQQQIIIIIHHBBBBI")`.
    2. The subagent prompt referenced `PACK_L2_AUX`, `PACK_L3_AUX`, `PACK_APP_AUX`, `decode_aux_metric`, `LAYER_KERNEL_DROP`, `LAYER_WAIT_SCHED`, `LAYER_WAIT_LOCK`, and `(2u << 28) | (reason & 0xFFFF)`. Cross-falsification proved none of these identifiers exist in `PROMPT_SPEC.md`, `tracer_kernel.c`, or `tracer_agent.py`; instead, the codebase multiplexes auxiliary metrics into `ev.ip`, `ev.duration_ns`, `ev.layer_type`, `ev.call_depth`, and `ev.flags`, and decodes them in [`decode_event_metadata`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L194-L279) — where we uncovered real bit-collision and misdecoding bugs!
  - **Code & Spec Defects Discovered (8 Critical / High Findings)**:
    1. **Defect 05-01 (`RequestCorrelator.ingest` Raw 64B `bytes` / `dict` Rejection & Missing `KRAY_EVENT_STRUCT`)**: [`RequestCorrelator.ingest`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L323-L341) only accepts `KrayEvent` instances and raises `AttributeError` when passed raw 64-byte `bytes`/`memoryview` buffers from `BPF_MAP_TYPE_RINGBUF` or `dict` objects. Also, `PROMPT_SPEC.md` Section 3.1.2 specifies `KrayRuntimeConfig`, whereas `tracer_agent.py` defines [`KrayRuntimeCfg`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L78-L86) without an alias.
    2. **Defect 05-02 (`decode_event_metadata` Bit-Collision & Misdecoding of `kfree_skb` Drop Reasons and `tcp_retransmit_skb` Counts)**: In [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L725-L805), both `TRACEPOINT_PROBE(skb, kfree_skb)` (`flags = FLAG_SKB_DROP`) and `TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)` (`flags |= FLAG_TCP_RETRANSMIT`) emit `layer_type = LAYER_KERNEL_NET (2)` and `call_depth = OSI_L4_TCP (4)` with `ev->ip = (u64)args->reason` or `ev->ip = (u64)state->retransmits`. However, [`decode_event_metadata`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L228-L240) ignores `ev.flags` and unconditionally unpacks `ev.ip` as `ttl = (raw_ip >> 24) & 0xFF`, `ihl_bytes = (raw_ip >> 16) & 0xFF`, `pkt_len = raw_ip & 0xFFFF`. Thus, `kfree_skb` drop reason codes (including Rocky 9.8 subsystem drop reasons with `SKB_DROP_REASON_SUBSYS_MASK = 0xffff0000`) and TCP retransmit counts are corrupted into fake `pkt_len` and `ihl_bytes` fields, completely losing `drop_reason` and `retransmits`!
    3. **Defect 05-03 (`decode_event_metadata` Confuses `trace_uprobe_entry` Off-CPU Snapshot with Function `duration_ns`)**: In [`trace_uprobe_entry`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1328-L1332) (`is_return == 0`), `ev->duration_ns` carries `tctx->fn_off_cpu_snap[depth]` (cumulative thread off-CPU ns at function entry), whereas in [`trace_uprobe_return`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1357-L1361) (`is_return == 1`), `ev->duration_ns` carries total wall-clock duration `now - tctx->fn_entry_ts[depth]`. Yet [`decode_event_metadata`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L205-L213) labels both as `"duration_ns"`, misreporting cumulative thread off-CPU time as function execution duration on entry events.
    4. **Defect 05-04 (`tracer_kernel.c` L3/L4 Hooks Omit `(ttl << 24) | (ihl_bytes << 16)` Bit-Packing in `ev->ip`)**: While `kprobe__ip_rcv` and `kprobe__tcp_v4_rcv` pack `((u64)iph.ttl << 24) | ((u64)ihl_bytes << 16) | pkt_len`, 6 other L3/L4 hooks ([`kprobe____tcp_transmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1476), [`kprobe__ip_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1509), [`kprobe__ip6_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1634), [`kprobe__tcp_v6_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1686), [`kprobe__udp_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1743), and [`kprobe__icmp_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1901)) only pass `pkt_len` in `ev->ip`, causing `decode_event_metadata` to decode `ttl = 0` and `ihl_bytes = 0`.
    5. **Defect 05-05 (`tracer_kernel.c` `kfree_skb` Stage 1 Dangling `skb_egress_map` Leak & Stage 3 Missing Egress Drop Fallback)**: In [`TRACEPOINT_PROBE(skb, kfree_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L747-L758), Stage 1 emits `FLAG_SKB_DROP` on an egress drop and returns `0` without deleting `skb_egress_map` or `egress_flow_map`, leaving freed `struct sk_buff *` pointers in `skb_egress_map` vulnerable to slab allocator reuse. In Stage 3 (lines `777–807`), header-parsed drops only query `ingress_flow_map` and never fall back to `egress_flow_map`.
    6. **Defect 05-06 (`RequestCorrelator` Multi-Core Out-of-Order Event Overwrite Destroys Completed Traces)**: In [`RequestCorrelator.ingest`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L340-L350), receiving `LAYER_EGRESS_NIC` (`call_depth == OSI_L2_DATALINK`) immediately pops `self._buffers[req_id]` into `self._completed[req_id]`. If any delayed event for the same `req_id` arrives from another CPU core microseconds later, `ingest` creates a new 1-event buffer in `self._buffers[req_id]`, and `flush_expired()` subsequently **overwrites `self._completed[req_id]` with that single late event**, destroying the entire prior trace!
    7. **Defect 05-07 (`RequestCorrelator` Lacks Terminal State Classification, `total_latency_ns`, `max_blocking_hop`, and Live L7 `[t_entry, t_return]` `pure_on_cpu_ns` vs `off_cpu_wait_ns` Calculation)**: `RequestCorrelator` does not classify trace states (`DROPPED` vs `COMPLETED` vs `PARTIAL_TIMEOUT`), nor does it compute `total_latency_ns`, `max_blocking_hop`, or L7 user function `pure_on_cpu_ns` vs `off_cpu_wait_ns` by subtracting nested `OSI_L5_SYSCALL_MEM` and `OSI_L6_PRE_COMPUTE` waits inside `[t_entry, t_return]` as required by `PROMPT_SPEC.md` Section 3.1.3.
    8. **Defect 05-08 (`test_verification_suite.py` `ADV-TEST-12` Fixed `time.sleep(0.25)` Race & Dead-Comment macOS SSH Verifier Skip)**: In [`test_adv_12_target_kernel_live_verifier_and_loopback_readiness`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2096), a fixed `time.sleep(0.25)` races against `mock_server` startup on macOS (`[Errno 61] Connection refused`), and lines `2076–2077` claim in a comment to run `bpftool prog loadall` via SSH to `ebpf-tracer-v2.0.0` from macOS, but `if sys.platform.startswith("linux"):` completely skips the live kernel verifier check when executed on macOS.

---

## 2. Adversarial Falsification of the Prompt Itself & `PROMPT_SPEC.md`

### 2.1 Falsification of Prompt's `KRAY_EVENT_STRUCT = struct.Struct("<QQQQIIIIBBHI")` (56B vs 64B)

* **Prompt Claim**:
  - The prompt instructed Agent 05 to verify `KRAY_EVENT_STRUCT = struct.Struct("<QQQQIIIIBBHI")` in `tracer_agent.py` against the 64-byte C `struct kray_event_t`.
* **Adversarial Proof of Falsity**:
  - Calculating the byte size of `struct.Struct("<QQQQIIIIBBHI")` in little-endian (`<`) mode:
    - `QQQQ`: 4 unsigned 64-bit integers (`4 * 8 = 32` bytes, offsets `0..31`)
    - `IIII`: 4 unsigned 32-bit integers (`4 * 4 = 16` bytes, offsets `32..47`)
    - `BB`: 2 unsigned 8-bit integers (`2 * 1 = 2` bytes, offsets `48..49`)
    - `H`: 1 unsigned 16-bit integer (`1 * 2 = 2` bytes, offsets `50..51`)
    - `I`: 1 unsigned 32-bit integer (`1 * 4 = 4` bytes, offsets `52..55`)
    - **Total Size of `<QQQQIIIIBBHI` = `56` bytes (8 bytes short of 64 bytes!)**
  - Comparing against the actual C [`struct __attribute__((packed)) kray_event_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L129-L146) and Python [`KrayEvent`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L89-L108):
    - Bytes `0..7` (`Q`, 8B): `req_id` (`u64`)
    - Bytes `8..15` (`Q`, 8B): `ip` (`u64`)
    - Bytes `16..23` (`Q`, 8B): `timestamp` (`u64`)
    - Bytes `24..31` (`Q`, 8B): `duration_ns` (`u64`)
    - Bytes `32..35` (`I`, 4B): `pid` (`u32`)
    - Bytes `36..39` (`I`, 4B): `tid` (`u32`)
    - Bytes `40..43` (`I`, 4B): `parent_tid` (`u32`)
    - Bytes `44..47` (`I`, 4B): `src_ip` (`u32`)
    - Bytes `48..51` (`I`, 4B): `dst_ip` (`u32`) — **Missing from the prompt's `IIII` (which has only four `I`s instead of five `I`s)!**
    - Bytes `52..53` (`H`, 2B): `src_port` (`u16`) — **Misordered in the prompt as `BBH`!**
    - Bytes `54..55` (`H`, 2B): `dst_port` (`u16`)
    - Byte `56` (`B`, 1B): `layer_type` (`u8`)
    - Byte `57` (`B`, 1B): `is_return` (`u8`)
    - Byte `58` (`B`, 1B): `call_depth` (`u8`)
    - Byte `59` (`B`, 1B): `flags` (`u8`)
    - Bytes `60..63` (`I`, 4B): `drop_count` (`u32`)
  - **True 64-Byte `struct.Struct` Format**:
    - `KRAY_EVENT_STRUCT = struct.Struct("<QQQQIIIIIHHBBBBI")` (`32 + 20 + 4 + 4 + 4 = 64` bytes, 16 fields).
  - **True 16-Byte `struct.Struct` Format for `struct __attribute__((packed)) kray_runtime_cfg_t`**:
    - `KRAY_RUNTIME_CFG_STRUCT = struct.Struct("<IHBBQ")` (`target_pid: u32`, `target_port: u16`, `capture_enabled: u8`, `filter_flags: u8`, `config_epoch: u64` = `4 + 2 + 1 + 1 + 8 = 16` bytes, 5 fields).

### 2.2 Falsification of Prompt's `aux_metric`, `PACK_L2_AUX`, `decode_aux_metric`, and `(2u << 28) | (reason & 0xFFFF)`

* **Prompt Claim**:
  - The prompt referred to `aux_metric`, `PACK_L2_AUX`, `PACK_L3_AUX`, `PACK_APP_AUX`, `(2u << 28) | (reason & 0xFFFF)`, `decode_aux_metric`, `LAYER_KERNEL_DROP`, `LAYER_WAIT_SCHED`, and `LAYER_WAIT_LOCK`.
* **Adversarial Proof of Falsity**:
  - None of those symbols exist in [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), or [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py).
  - In the actual architecture (`PROMPT_SPEC.md` Section 2.1.2 & Section 3.1.3), `struct kray_event_t` does not have a 32-bit `aux_metric` field with a 4-bit tag `(tag << 28)`. Instead:
    - `ev.layer_type` (`u8`, `1..6`) encodes the 6 macro pipeline stages (`LAYER_INGRESS_NIC = 1`, `LAYER_KERNEL_NET = 2`, `LAYER_USER_ENTRY = 3`, `LAYER_USER_FUNC = 4`, `LAYER_USER_EXIT = 5`, `LAYER_EGRESS_NIC = 6`).
    - `ev.call_depth` (`u8`) is overloaded: when `layer_type == LAYER_USER_FUNC (4)`, `call_depth` holds the user function recursion depth (`0..15`); when `layer_type != LAYER_USER_FUNC`, `call_depth` holds the OSI sub-layer ID (`OSI_L2_DATALINK = 2`, `OSI_L3_IP = 3`, `OSI_L4_TCP = 4`, `OSI_L4_SOCKET = 5`, `OSI_L5_SYSCALL_MEM = 6`, `OSI_L7_APP = 7`, `OSI_L6_PRE_COMPUTE = 8`).
    - `ev.ip` (`u64`) and `ev.duration_ns` (`u64`) are bit-packed per OSI layer and decoded by [`decode_event_metadata(ev)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L194-L279).
  - **Why the Prompt's Suspicion Was Still Structurally Valid**:
    - Even though the prompt used outdated symbol names (`decode_aux_metric`), its underlying adversarial hypothesis — that **kernel drop events (`kfree_skb`) and wait/retransmit events collide in the bit-packing decoder** — turned out to be **100% true in [`decode_event_metadata`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L228-L240)**!

---

## 3. Detailed Technical Audit of Discovered Code, Spec & Test Defects

### 3.1 Defect 05-01: `RequestCorrelator.ingest` Fails on Raw 64B `bytes` / `memoryview` / `dict` and Missing `KRAY_EVENT_STRUCT`

* **Location**:
  - [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L78-L113) and [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L323-L341)
  - [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L669-L678)
* **Root Cause**:
  - `RequestCorrelator.ingest(self, ev: KrayEvent)` directly accesses `ev.req_id`, `ev.drop_count`, `ev.timestamp`, `ev.layer_type`, and `ev.call_depth` as attributes.
  - When BPF ring-buffer polling (`BPF_MAP_TYPE_RINGBUF`) delivers a 64-byte `bytes`, `bytearray`, or `memoryview` slice, or when JSON/MCP tests pass a `dict` via `ingest()` / `ingest_event()`, Python immediately raises `AttributeError: 'bytes' object has no attribute 'req_id'`.
  - Additionally, `PROMPT_SPEC.md` line 669 names the 16-byte runtime config class `KrayRuntimeConfig`, whereas `tracer_agent.py` line 78 defines `KrayRuntimeCfg` without an alias.

### 3.2 Defect 05-02: Bit-Packing Collision in `decode_event_metadata` Corrupts `kfree_skb` Drop Reasons (`FLAG_SKB_DROP`) and `tcp_retransmit_skb` Counts (`FLAG_TCP_RETRANSMIT`)

* **Location**:
  - [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L725-L805) (`TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)` and `TRACEPOINT_PROBE(skb, kfree_skb)`)
  - [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L228-L240) (`decode_event_metadata`)
  - Ground-Truth Reference: [dropreason-core.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/net/dropreason-core.h#L129-L575)
* **Root Cause**:
  - In `tracer_kernel.c`, `TRACEPOINT_PROBE(skb, kfree_skb)` emits:
    - `layer_type = LAYER_KERNEL_NET (2)`
    - `call_depth = OSI_L4_TCP (4)`
    - `flags = FLAG_SKB_DROP (0x08)`
    - `ip = (u64)args->reason` (where `enum skb_drop_reason` in Rocky Linux 9.8 `include/net/dropreason-core.h` has core values `3..88` and subsystem values masked by `SKB_DROP_REASON_SUBSYS_MASK = 0xffff0000`)
  - Similarly, `TRACEPOINT_PROBE(tcp, tcp_retransmit_skb)` emits:
    - `layer_type = LAYER_KERNEL_NET (2)`
    - `call_depth = OSI_L4_TCP (4)`
    - `flags = state->tcp_flags | FLAG_TCP_RETRANSMIT (0x04)`
    - `ip = (u64)state->retransmits`
  - However, in `tracer_agent.py` (`decode_event_metadata`, lines 228–240):
    ```python
    if cdepth in (OSI_L3_IP, OSI_L4_TCP):
        ttl = (raw_ip >> 24) & 0xFF
        ihl_bytes = (raw_ip >> 16) & 0xFF
        pkt_len = raw_ip & 0xFFFF
    ```
  - Because `decode_event_metadata` fails to inspect `ev.flags & FLAG_SKB_DROP` and `ev.flags & FLAG_TCP_RETRANSMIT` before unpacking `cdepth in (OSI_L3_IP, OSI_L4_TCP)`:
    - A packet drop with `reason = 9` (`SKB_DROP_REASON_TCP_CSUM`) is misdecoded as a 9-byte TCP packet (`pkt_len = 9, ttl = 0, ihl_bytes = 0`), with **no `drop_reason` or `drop_reason_name` field**!
    - A Rocky 9.8 subsystem drop reason such as `(1 << 16) | 9` (`0x00010009`) has its upper 16 subsystem bits sliced into `ihl_bytes = 1` and its lower 16 bits into `pkt_len = 9`!
    - A TCP retransmission with `retransmits = 2` is misdecoded as a 2-byte TCP packet (`pkt_len = 2`) with no `retransmits` field!

### 3.3 Defect 05-03: `decode_event_metadata` Misinterprets `trace_uprobe_entry` Off-CPU Snapshot (`fn_off_cpu_snap`) as Function `duration_ns`

* **Location**:
  - [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1322-L1362) (`trace_uprobe_entry` & `trace_uprobe_return`)
  - [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L204-L213) (`decode_event_metadata`)
* **Root Cause**:
  - In `trace_uprobe_entry` (`is_return == 0`), `tracer_kernel.c` line 1329 passes `tctx->fn_off_cpu_snap[depth]` (the thread's cumulative `acc_off_cpu_ns` snapshot at the moment of function entry) in the `dur_ns` parameter of `emit_kray_event`.
  - In `trace_uprobe_return` (`is_return == 1`), `tracer_kernel.c` line 1358 passes `fn_dur = now - tctx->fn_entry_ts[depth]` (the total wall-clock elapsed time of the function) in `dur_ns`.
  - Yet `decode_event_metadata` returns `"duration_ns": dur_ns` for both `is_return == 0` and `is_return == 1`. If a thread accumulated 45ms of off-CPU sleep before entering a fast 10µs helper function, the entry event (`is_return == 0`) is falsely decoded as having `duration_ns = 45,000,000`!

### 3.4 Defect 05-04: Six L3/L4 Hooks in `tracer_kernel.c` Omit `(ttl << 24) | (ihl_bytes << 16)` When Packing `ev->ip`

* **Location**:
  - [`kprobe____tcp_transmit_skb`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1475-L1479)
  - [`kprobe__ip_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1508-L1512)
  - [`kprobe__ip6_output`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1633-L1637)
  - [`kprobe__tcp_v6_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1685-L1689)
  - [`kprobe__udp_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1742-L1746)
  - [`kprobe__icmp_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1900-L1904)
* **Root Cause**:
  - `PROMPT_SPEC.md` Section 3.1.3 states that for `OSI_L3_IP (3)` and `OSI_L4_TCP (4)`, `ev.ip` is packed as `(ttl << 24) | (ihl_bytes << 16) | pkt_len`.
  - While `kprobe__ip_rcv`, `kprobe__tcp_v4_rcv`, and `kprobe__ipv6_rcv` pack `ttl`/`hop_limit` and `ihl_bytes` (`20` or `40`), the 6 hooks listed above pass raw `(u64)pkt_len` in `ev->ip`, causing `decode_event_metadata` to report `ttl = 0` and `ihl_bytes = 0`.
  - In `kprobe__tcp_v6_rcv`, `kprobe__udp_rcv`, and `kprobe__icmp_rcv`, the L3 header (`ip6h` or `iph`) is already read onto the BPF stack, so packing `((u64)ip6h.hop_limit << 24) | (40ULL << 16) | (u64)state->pkt_len` and `((u64)iph.ttl << 24) | ((u64)((iph.ihl & 0x0f) * 4) << 16) | (u64)pkt_len` costs zero extra `bpf_probe_read_kernel` calls!

### 3.5 Defect 05-05: `kfree_skb` Stage 1 Leaks `skb_egress_map` / `egress_flow_map` Entries and Stage 3 Misses Egress Header Fallback

* **Location**:
  - [`TRACEPOINT_PROBE(skb, kfree_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L733-L809)
* **Root Cause**:
  - In Stage 1 (lines `747–758`), when `skb_egress_map.lookup(&skb_ptr)` finds `ekey` and `egress_flow_map.lookup(ekey)` finds `estate`, the probe emits the `FLAG_SKB_DROP` event and immediately executes `return 0;` **without deleting `skb_egress_map` or `egress_flow_map`**.
  - Because `kfree_skb` frees the `struct sk_buff` back to the kernel slab cache (`skbuff_head_cache`), a dropped egress packet never reaches `net_dev_xmit` (where `skb_egress_map.delete(&skb_ptr)` normally happens at line 1559). If the slab allocator reuses the same `skb_ptr` address for another socket's packet, `net_dev_xmit` or `kfree_skb` will misattribute the new packet to the old dropped request!
  - In Stage 3 (lines `777–807`), when `skb->head + net_off` is parsed into `ikey`, the probe only looks up `ingress_flow_map.lookup(&ikey)`. If an egress packet was dropped before `skb_egress_map` registration (or after `skb_clone` changed `skb_ptr`), Stage 3 misses `egress_flow_map.lookup(&ikey)`.

### 3.6 Defect 05-06: `RequestCorrelator` Late Multi-Core Event Overwrite Destroys Completed Traces

* **Location**:
  - [`RequestCorrelator.ingest` and `RequestCorrelator._finalize_request`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L323-L370)
* **Root Cause & Exact Failure Sequence**:
  1. A request `req_id = 0xCAFEBABE` executes across 8 hooks from `LAYER_INGRESS_NIC (1)` to `LAYER_EGRESS_NIC (6, call_depth=OSI_L2_DATALINK)`.
  2. When `ingest()` receives `LAYER_EGRESS_NIC (call_depth == OSI_L2_DATALINK)` at line 340, it immediately calls `self._finalize_request(req_id)`.
  3. `_finalize_request(req_id)` pops all 8 events from `self._buffers[req_id]` and writes the 8-event list to `self._completed[req_id]`.
  4. On an SMP/multi-core system (or during out-of-order probe delivery), another CPU core delivers a 9th event for the same `req_id` (e.g., `kprobe__ip_output`, `kretprobe__tcp_sendmsg`, `block_rq_complete`, or `trace_uprobe_return`) 50µs later.
  5. `ingest(late_ev)` sees `req_id` is not in `self._buffers`, so `self._buffers.setdefault(req_id, [])` creates a **new 1-element list `[late_ev]`**!
  6. When `get_completed_traces()` calls `flush_expired()`, `_finalize_request(req_id)` runs again:
     ```python
     if req_id in self._completed:
         self._completed.pop(req_id, None)
     self._completed[req_id] = events_list
     ```
  7. **Result**: The 8-event completed trace in `self._completed[req_id]` is **overwritten and replaced by the 1-element list `[late_ev]`**, causing 88% of the request's telemetry to vanish!

### 3.7 Defect 05-07: `RequestCorrelator` Missing Terminal State (`DROPPED` vs `COMPLETED` vs `PARTIAL_TIMEOUT`), `total_latency_ns`, `max_blocking_hop`, and Live L7 `pure_on_cpu_ns` vs `off_cpu_wait_ns` Separation

* **Location**:
  - [`RequestCorrelator`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L284-L370)
  - [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L679-L686)
* **Root Cause**:
  - `PROMPT_SPEC.md` Section 3.1.3 requires `RequestCorrelator` to:
    - Maintain per-`req_id` correlation state across normal completion (`LAYER_EGRESS_NIC`), kernel packet drop (`FLAG_SKB_DROP`), and grace-window timeout (`50ms` after `LAYER_USER_EXIT` or `200ms` orphan timeout).
    - Compute `pure_on_cpu_ns` vs `off_cpu_wait_ns` for every user-space function interval `[t_entry, t_return]` by subtracting nested child `OSI_L5_SYSCALL_MEM` or `OSI_L6_PRE_COMPUTE` wait durations whose timestamps fall inside `[t_entry, t_return]`.
  - Currently, `RequestCorrelator` only stores raw `List[KrayEvent]` in `self._completed` without:
    - Merging late multi-core events into already-finalized `self._completed[req_id]` traces and re-sorting canonically.
    - Classifying trace terminal state as `"DROPPED"` (when any event has `flags & FLAG_SKB_DROP`), `"COMPLETED"` (when `LAYER_EGRESS_NIC` with `OSI_L2_DATALINK` was observed and no drop occurred), or `"PARTIAL_TIMEOUT"` (when finalized via grace-window expiry without `LAYER_EGRESS_NIC` or `FLAG_SKB_DROP`).
    - Computing `total_latency_ns`, `max_blocking_hop`, and the L7 function call chain summary (`pure_on_cpu_ns` vs `off_cpu_wait_ns`).

### 3.8 Defect 05-08: `test_verification_suite.py` `ADV-TEST-12` Loopback Connection Race & Skipped macOS-to-VM Verifier Check

* **Location**:
  - [`test_adv_12_target_kernel_live_verifier_and_loopback_readiness`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2096)
* **Root Cause**:
  - Line 2042 uses a single fixed `time.sleep(0.25)` after spawning `mock_server` before calling `socket.create_connection(("127.0.0.1", port), timeout=2.0)`. When `mock_server` is freshly compiled on macOS, `syspolicyd`/`amfid` binary scanning can delay socket bind past 250ms, causing a spurious `[Errno 61] Connection refused` failure.
  - Lines 2076–2077 state in a comment: `# - Or via SSH to dedicated target VM 'ebpf-tracer-v2.0.0' (192.168.64.14) if reachable from macOS`, but line 2077 only has `if sys.platform.startswith("linux") and Path("/usr/sbin/bpftool").exists():` with no `else:` branch for macOS SSH execution.

---

## 4. Concrete Remediation Patches (Drop-In Verified Code)

### 4.1 Patch 1: `tracer_kernel.c` — `kfree_skb` Map Cleanup, Stage 3 Egress Drop Fallback, and L3/L4 `ttl`/`ihl_bytes` Bit-Packing

* **Target File**: [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)
* **Changes**:
  - In `TRACEPOINT_PROBE(skb, kfree_skb)` Stage 1 (lines `747–758`), delete `egress_flow_map` and `skb_egress_map` after emitting `FLAG_SKB_DROP` so freed `struct sk_buff *` slab addresses cannot cause false positive correlations on reuse.
  - In `TRACEPOINT_PROBE(skb, kfree_skb)` Stage 3 (lines `797–805`), fall back to `egress_flow_map.lookup(&ikey)` if `ingress_flow_map.lookup(&ikey)` returns NULL, and clean up `egress_flow_map` on drop.
  - In `kprobe__tcp_v6_rcv` (line `1686`), `kprobe__udp_rcv` (line `1743`), and `kprobe__icmp_rcv` (line `1901`), pack `((u64)ttl_or_hoplimit << 24) | ((u64)ihl_bytes << 16) | ((u64)pkt_len & 0xffffULL)` into `ev->ip`.
  - In `kprobe____tcp_transmit_skb` (line `1476`), `kprobe__ip_output` (line `1509`), and `kprobe__ip6_output` (line `1634`), pack default L3/L4 header metadata `(64ULL << 24) | (20ULL << 16) | ((u64)estate->pkt_len & 0xffffULL)` (or `40ULL << 16` for IPv6) so `decode_event_metadata` always receives valid `ttl` and `ihl_bytes`.

```c
/* --- Patch for tracer_kernel.c: TRACEPOINT_PROBE(skb, kfree_skb) (lines 746-808) --- */
    /* Stage 1: Egress SKB pointer lookup */
    struct flow_key_t *ekey = skb_egress_map.lookup(&skb_ptr);
    if (ekey) {
        struct flow_state_t *estate = egress_flow_map.lookup(ekey);
        if (estate) {
            emit_kray_event(
                estate->req_id, (u64)args->reason, now, 0,
                estate->pid, estate->tid, 0,
                ekey->saddr, ekey->daddr, ekey->sport, ekey->dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
            egress_flow_map.delete(ekey);
        }
        skb_egress_map.delete(&skb_ptr);
        return 0;
    }

    /* Stage 2: Receiving socket pointer args->rx_sk */
    struct sock *rx_sk = (struct sock *)args->rx_sk;
    if (rx_sk) {
        struct flow_key_t sk_key = {};
        populate_sock_flow_key(rx_sk, &sk_key, IPPROTO_TCP, 0);
        struct flow_state_t *istate = ingress_flow_map.lookup(&sk_key);
        if (istate) {
            emit_kray_event(
                istate->req_id, (u64)args->reason, now, 0,
                istate->pid, istate->tid, 0,
                sk_key.saddr, sk_key.daddr, sk_key.sport, sk_key.dport,
                LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
            return 0;
        }
    }

    /* Stage 3: Parse L3/L4 headers from (struct sk_buff *)args->skbaddr (Ingress + Egress fallback) */
    struct sk_buff *skb = (struct sk_buff *)args->skbaddr;
    if (skb) {
        unsigned char *head = NULL;
        u16 net_off = 0;
        bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
        bpf_probe_read_kernel(&net_off, sizeof(net_off), &skb->network_header);
        if (head) {
            struct iphdr iph = {};
            bpf_probe_read_kernel(&iph, sizeof(iph), head + net_off);
            if (iph.protocol == IPPROTO_TCP) {
                u16 ihl_bytes = (iph.ihl & 0x0f) * 4;
                struct tcphdr tcph = {};
                bpf_probe_read_kernel(&tcph, sizeof(tcph), head + net_off + ihl_bytes);
                struct flow_key_t ikey = {};
                ikey.saddr  = iph.saddr;
                ikey.daddr  = iph.daddr;
                ikey.sport  = bpf_ntohs(tcph.source);
                ikey.dport  = bpf_ntohs(tcph.dest);
                ikey.proto  = IPPROTO_TCP;
                ikey.family = AF_INET;
                struct flow_state_t *istate = ingress_flow_map.lookup(&ikey);
                if (istate) {
                    emit_kray_event(
                        istate->req_id, (u64)args->reason, now, 0,
                        istate->pid, istate->tid, 0,
                        ikey.saddr, ikey.daddr, ikey.sport, ikey.dport,
                        LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
                } else {
                    struct flow_state_t *estate = egress_flow_map.lookup(&ikey);
                    if (estate) {
                        emit_kray_event(
                            estate->req_id, (u64)args->reason, now, 0,
                            estate->pid, estate->tid, 0,
                            ikey.saddr, ikey.daddr, ikey.sport, ikey.dport,
                            LAYER_KERNEL_NET, 0, OSI_L4_TCP, FLAG_SKB_DROP);
                        egress_flow_map.delete(&ikey);
                    }
                }
            }
        }
    }
```

### 4.2 Patch 2: `tracer_agent.py` — Bit-Exact `KRAY_EVENT_STRUCT`, Collision-Free `decode_event_metadata`, Multi-Core Merge & Trace Summary in `RequestCorrelator`

* **Target File**: [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py)
* **Changes**:
  1. Define `KRAY_RUNTIME_CFG_STRUCT = struct.Struct("<IHBBQ")` (16B), `KRAY_EVENT_STRUCT = struct.Struct("<QQQQIIIIIHHBBBBI")` (64B), and alias `KrayRuntimeConfig = KrayRuntimeCfg`.
  2. Add `unpack_raw_event(raw: bytes | bytearray | memoryview) -> KrayEvent` using `KRAY_EVENT_STRUCT.unpack` for fast binary deserialization validated against `ctypes.KrayEvent`.
  3. Fix `decode_event_metadata(ev)` to check:
     - `flags & FLAG_SKB_DROP` first when `cdepth in (OSI_L3_IP, OSI_L4_TCP)`: decode the full 32-bit `drop_reason = raw_ip & 0xFFFFFFFF`, `drop_subsys = (raw_ip >> 16) & 0xFFFF`, `drop_code = raw_ip & 0xFFFF`, and map standard Rocky Linux 9.8 `include/net/dropreason-core.h` enum names (`SKB_DROP_REASON_NO_SOCKET = 3`, `SKB_DROP_REASON_PKT_TOO_SMALL = 8`, `SKB_DROP_REASON_TCP_CSUM = 9`, `SKB_DROP_REASON_NETFILTER_DROP = 11`, `SKB_DROP_REASON_QDISC_DROP = 57`, `SKB_DROP_REASON_NOMEM = 74`, etc.) while keeping `pkt_len = 0` so drop reasons never masquerade as packet lengths.
     - `flags & FLAG_TCP_RETRANSMIT` next when `cdepth in (OSI_L3_IP, OSI_L4_TCP)`: decode `retransmits = raw_ip & 0xFFFFFFFF` and `is_retransmit = True`.
     - `ltype == LAYER_USER_FUNC`: distinguish `is_return == 0` (`off_cpu_snap_ns = dur_ns`, `duration_ns = 0`) vs `is_return == 1` (`duration_ns = dur_ns`).
  4. Fix `RequestCorrelator`:
     - Support `KrayEvent`, raw 64-byte `bytes`/`bytearray`/`memoryview`, and `dict` in `ingest()` and alias `ingest_event = ingest` and `ingest_raw_bytes(raw: bytes)`.
     - Fix the multi-core late-event overwrite bug in `_finalize_request(req_id)` and `ingest()`: if `req_id` already exists in `self._completed`, merge the newly arrived event(s) into the existing trace list and re-sort canonically by `(int(e.layer_type), int(e.timestamp), int(e.is_return))` instead of overwriting `self._completed[req_id]`!
     - Immediately finalize or mark `req_id` when `flags & FLAG_SKB_DROP` is ingested, and track trace terminal status (`"DROPPED"`, `"COMPLETED"`, `"PARTIAL_TIMEOUT"`).
     - Add `summarize_trace(req_id)` and `get_trace_summaries()` to compute:
       - `status`: `"DROPPED"` if any event has `FLAG_SKB_DROP`, `"COMPLETED"` if `LAYER_EGRESS_NIC (OSI_L2_DATALINK)` is present, else `"PARTIAL_TIMEOUT"`.
       - `total_latency_ns`: `max(e.timestamp) - min(e.timestamp)` (or sum of non-overlapping stage durations).
       - `max_blocking_hop`: the hop with the maximum wait/execution duration across the trace.
       - `l7_functions`: pairs `LAYER_USER_FUNC` entry (`is_return == 0`) and return (`is_return == 1`) events per `call_depth` (or uses `[t_return - duration_ns, t_return]`), subtracts any nested `OSI_L5_SYSCALL_MEM` and `OSI_L6_PRE_COMPUTE` wait durations falling within `[t_entry, t_return]`, and outputs exact `wall_duration_ns`, `off_cpu_wait_ns`, and `pure_on_cpu_ns`.

```python
# --- Drop-in Patch for tracer_agent.py (ABI Structs, Decoder & RequestCorrelator) ---
import struct

KRAY_RUNTIME_CFG_STRUCT = struct.Struct("<IHBBQ")
KRAY_EVENT_STRUCT = struct.Struct("<QQQQIIIIIHHBBBBI")
KrayRuntimeConfig = KrayRuntimeCfg

assert KRAY_RUNTIME_CFG_STRUCT.size == 16 == ctypes.sizeof(KrayRuntimeCfg)
assert KRAY_EVENT_STRUCT.size == 64 == ctypes.sizeof(KrayEvent)

ROCKY98_SKB_DROP_REASONS: Dict[int, str] = {
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
    18: "SKB_DROP_REASON_PROTO_MEM",
    22: "SKB_DROP_REASON_SOCKET_BACKLOG",
    23: "SKB_DROP_REASON_TCP_FLAGS",
    25: "SKB_DROP_REASON_TCP_ZEROWINDOW",
    33: "SKB_DROP_REASON_TCP_LISTEN_OVERFLOW",
    37: "SKB_DROP_REASON_TCP_RESET",
    57: "SKB_DROP_REASON_QDISC_DROP",
    64: "SKB_DROP_REASON_CPU_BACKLOG",
    65: "SKB_DROP_REASON_XDP",
    66: "SKB_DROP_REASON_TC_INGRESS",
    74: "SKB_DROP_REASON_NOMEM",
}


def unpack_raw_event(raw: bytes | bytearray | memoryview) -> KrayEvent:
    """Zero-drift 64-byte binary unpacker verified against KRAY_EVENT_STRUCT and ctypes.KrayEvent."""
    if len(raw) != 64:
        raise ValueError(f"Expected 64-byte kray_event_t buffer, got {len(raw)} bytes")
    fields = KRAY_EVENT_STRUCT.unpack(raw)
    return KrayEvent(*fields)


def coerce_kray_event(ev: Any) -> KrayEvent:
    """Coerce KrayEvent, 64-byte raw bytes/bytearray/memoryview, or dict into KrayEvent."""
    if isinstance(ev, KrayEvent):
        return ev
    if isinstance(ev, (bytes, bytearray, memoryview)):
        return unpack_raw_event(ev)
    if isinstance(ev, dict):
        return make_event(
            req_id=int(ev.get("req_id", 0)),
            timestamp=int(ev.get("timestamp", ev.get("ts_ns", 0))),
            duration_ns=int(ev.get("duration_ns", 0)),
            layer_type=int(ev.get("layer_type", LAYER_INGRESS_NIC)),
            call_depth=int(ev.get("call_depth", 0)),
            is_return=int(ev.get("is_return", 0)),
            ip=int(ev.get("ip", 0)),
            pid=int(ev.get("pid", 0)),
            tid=int(ev.get("tid", 0)),
            parent_tid=int(ev.get("parent_tid", 0)),
            src_ip=int(ev.get("src_ip", ev.get("saddr", 0))),
            dst_ip=int(ev.get("dst_ip", ev.get("daddr", 0))),
            src_port=int(ev.get("src_port", ev.get("sport", 0))),
            dst_port=int(ev.get("dst_port", ev.get("dport", 0))),
            flags=int(ev.get("flags", 0)),
            drop_count=int(ev.get("drop_count", 0)),
        )
    return ev


def decode_event_metadata(ev: KrayEvent) -> Dict[str, Any]:
    """
    Collision-free decoder for disjoint (layer_type, call_depth) and bit-packed
    ev.ip / ev.duration_ns / ev.flags across all 7 OSI/compute layers, kfree_skb drops,
    and TCP retransmissions.
    """
    ev = coerce_kray_event(ev)
    ltype = int(ev.layer_type)
    cdepth = int(ev.call_depth)
    raw_ip = int(ev.ip)
    dur_ns = int(ev.duration_ns)
    flags = int(ev.flags)

    # Disjoint rule: layer_type == LAYER_USER_FUNC (4) is EXCLUSIVELY OSI_L7_APP (7)
    if ltype == LAYER_USER_FUNC:
        is_ret = bool(ev.is_return)
        return {
            "osi_layer_id": OSI_L7_APP,
            "osi_layer_name": "L7_COMPUTE_ALU",
            "user_call_depth": cdepth,
            "instruction_pointer": raw_ip,
            "is_return": is_ret,
            "off_cpu_snap_ns": 0 if is_ret else dur_ns,
            "duration_ns": dur_ns if is_ret else 0,
        }

    if cdepth == OSI_L2_DATALINK:
        cpu_id = (raw_ip >> 32) & 0xFFFFFFFF
        rc = (raw_ip >> 16) & 0xFFFF
        pkt_len = raw_ip & 0xFFFF
        return {
            "osi_layer_id": OSI_L2_DATALINK,
            "osi_layer_name": "L2_DATALINK",
            "cpu_id": cpu_id,
            "rc": rc,
            "pkt_len": pkt_len,
            "duration_ns": dur_ns,
        }

    if cdepth in (OSI_L3_IP, OSI_L4_TCP):
        if flags & FLAG_SKB_DROP:
            reason_full = raw_ip & 0xFFFFFFFF
            subsys_id = (reason_full >> 16) & 0xFFFF
            reason_code = reason_full & 0xFFFF
            reason_name = ROCKY98_SKB_DROP_REASONS.get(
                reason_full,
                ROCKY98_SKB_DROP_REASONS.get(reason_code, f"SKB_DROP_REASON_{reason_code}"),
            )
            return {
                "osi_layer_id": cdepth,
                "osi_layer_name": "L4_KERNEL_SKB_DROP",
                "is_skb_drop": True,
                "drop_reason": reason_full,
                "drop_subsys": subsys_id,
                "drop_code": reason_code,
                "drop_reason_name": reason_name,
                "ttl": 0,
                "ihl_bytes": 0,
                "pkt_len": 0,
                "duration_ns": dur_ns,
            }
        if flags & FLAG_TCP_RETRANSMIT:
            retransmits = raw_ip & 0xFFFFFFFF
            return {
                "osi_layer_id": cdepth,
                "osi_layer_name": "L4_TCP_RETRANSMIT",
                "is_retransmit": True,
                "retransmits": retransmits,
                "ttl": 0,
                "ihl_bytes": 0,
                "pkt_len": 0,
                "duration_ns": dur_ns,
            }
        ttl = (raw_ip >> 24) & 0xFF
        ihl_bytes = (raw_ip >> 16) & 0xFF
        pkt_len = raw_ip & 0xFFFF
        return {
            "osi_layer_id": cdepth,
            "osi_layer_name": "L3_NETWORK_IP" if cdepth == OSI_L3_IP else "L4_TRANSPORT_TCP",
            "ttl": ttl,
            "ihl_bytes": ihl_bytes,
            "pkt_len": pkt_len,
            "duration_ns": dur_ns,
        }
```

```python
# --- Drop-in Patch for RequestCorrelator in tracer_agent.py ---
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
        self._status: Dict[int, str] = {}
        self.max_event_drop_count: int = 0
        self.skb_drop_events_count: int = 0

    def ingest_raw_bytes(self, raw: bytes | bytearray | memoryview) -> None:
        self.ingest(unpack_raw_event(raw))

    def ingest_event(self, ev: Any) -> None:
        self.ingest(ev)

    def ingest(self, ev: Any) -> None:
        ev_obj = coerce_kray_event(ev)
        with self._lock:
            req_id = int(ev_obj.req_id)
            if int(ev_obj.drop_count) > self.max_event_drop_count:
                self.max_event_drop_count = int(ev_obj.drop_count)
            if int(ev_obj.flags) & FLAG_SKB_DROP:
                self.skb_drop_events_count += 1

            if not self._should_sample(req_id):
                return

            # If req_id was already finalized into _completed, merge late multi-core events in-place!
            if req_id in self._completed and req_id not in self._buffers:
                merged = self._completed[req_id]
                merged.append(ev_obj)
                merged.sort(key=lambda e: (int(e.layer_type), int(e.timestamp), int(e.is_return)))
                self._status[req_id] = self._classify_trace_status(merged)
                return

            if req_id not in self._first_seen_ts:
                self._first_seen_ts[req_id] = int(ev_obj.timestamp)

            buf = self._buffers.setdefault(req_id, [])
            buf.append(ev_obj)

            if int(ev_obj.flags) & FLAG_SKB_DROP:
                self._finalize_request(req_id)
            elif int(ev_obj.layer_type) == LAYER_USER_EXIT:
                self._exit_seen_ts[req_id] = int(ev_obj.timestamp)
            elif int(ev_obj.layer_type) == LAYER_EGRESS_NIC and int(ev_obj.call_depth) == OSI_L2_DATALINK:
                self._finalize_request(req_id)

    @staticmethod
    def _classify_trace_status(events_list: List[KrayEvent]) -> str:
        if any(int(e.flags) & FLAG_SKB_DROP for e in events_list):
            return "DROPPED"
        if any(
            int(e.layer_type) == LAYER_EGRESS_NIC and int(e.call_depth) == OSI_L2_DATALINK
            for e in events_list
        ):
            return "COMPLETED"
        return "PARTIAL_TIMEOUT"

    def _finalize_request(self, req_id: int) -> None:
        events_list = self._buffers.pop(req_id, [])
        self._first_seen_ts.pop(req_id, None)
        self._exit_seen_ts.pop(req_id, None)
        if req_id in self._completed:
            prior = self._completed.pop(req_id)
            events_list = prior + events_list
        events_list.sort(key=lambda e: (int(e.layer_type), int(e.timestamp), int(e.is_return)))
        self._completed[req_id] = events_list
        self._status[req_id] = self._classify_trace_status(events_list)
        while len(self._completed) > self.max_completed_traces:
            oldest_key = next(iter(self._completed))
            self._completed.pop(oldest_key, None)
            self._status.pop(oldest_key, None)

    def summarize_trace(self, req_id: int) -> Dict[str, Any]:
        """
        Compute end-to-end trace diagnosis summary directly from correlated KrayEvents:
        - status: COMPLETED | DROPPED | PARTIAL_TIMEOUT
        - total_latency_ns: wall-clock span across all hops + first-hop duration
        - max_blocking_hop: stage with largest duration_ns
        - l7_functions: [t_entry, t_return] pure_on_cpu_ns vs off_cpu_wait_ns separation
        """
        with self._lock:
            evs = self._completed.get(req_id) or self._buffers.get(req_id, [])
            if not evs:
                return {"req_id": req_id, "status": "EMPTY", "total_latency_ns": 0}
            status = self._classify_trace_status(evs)
            min_ts = min(int(e.timestamp) for e in evs)
            max_ts = max(int(e.timestamp) for e in evs)
            span_ns = max(0, max_ts - min_ts)

            # Separate L7 user function intervals [t_entry, t_return] from kernel/wait hops
            entry_stack: Dict[int, KrayEvent] = {}
            l7_functions: List[Dict[str, Any]] = []
            wait_events = [
                e for e in evs
                if int(e.layer_type) != LAYER_USER_FUNC
                and int(e.call_depth) in (OSI_L5_SYSCALL_MEM, OSI_L6_PRE_COMPUTE)
            ]

            for e in evs:
                if int(e.layer_type) == LAYER_USER_FUNC:
                    depth = int(e.call_depth)
                    if int(e.is_return) == 0:
                        entry_stack[depth] = e
                    else:
                        entry_ev = entry_stack.pop(depth, None)
                        wall_dur = int(e.duration_ns)
                        t_ret = int(e.timestamp)
                        t_ent = int(entry_ev.timestamp) if entry_ev is not None else max(0, t_ret - wall_dur)
                        if wall_dur == 0 and t_ret >= t_ent:
                            wall_dur = t_ret - t_ent
                        nested_wait_ns = sum(
                            int(w.duration_ns)
                            for w in wait_events
                            if t_ent <= int(w.timestamp) <= t_ret
                        )
                        off_cpu_wait_ns = min(wall_dur, nested_wait_ns)
                        pure_on_cpu_ns = max(0, wall_dur - off_cpu_wait_ns)
                        l7_functions.append({
                            "call_depth": depth,
                            "ip": int(e.ip),
                            "t_entry_ns": t_ent,
                            "t_return_ns": t_ret,
                            "wall_duration_ns": wall_dur,
                            "off_cpu_wait_ns": off_cpu_wait_ns,
                            "pure_on_cpu_ns": pure_on_cpu_ns,
                        })

            non_entry_hops = [
                e for e in evs
                if not (int(e.layer_type) == LAYER_USER_FUNC and int(e.is_return) == 0)
            ]
            max_hop_ev = max(non_entry_hops, key=lambda e: int(e.duration_ns), default=evs[0])
            drop_evs = [decode_event_metadata(e) for e in evs if int(e.flags) & FLAG_SKB_DROP]

            return {
                "req_id": req_id,
                "status": status,
                "event_count": len(evs),
                "total_latency_ns": span_ns if span_ns > 0 else sum(int(e.duration_ns) for e in non_entry_hops),
                "max_blocking_hop": {
                    "layer_type": int(max_hop_ev.layer_type),
                    "call_depth": int(max_hop_ev.call_depth),
                    "duration_ns": int(max_hop_ev.duration_ns),
                    "metadata": decode_event_metadata(max_hop_ev),
                },
                "drop_details": drop_evs[0] if drop_evs else None,
                "l7_functions": l7_functions,
            }
```

### 4.3 Patch 3: `test_verification_suite.py` — Eliminate `ADV-TEST-12` Connection Race & Add Agent 05 Regression Tests

* **Target File**: [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2035-L2096)
* **Changes**:
  - Replace the brittle single `time.sleep(0.25)` before `socket.create_connection(("127.0.0.1", port), timeout=2.0)` in `test_adv_12_target_kernel_live_verifier_and_loopback_readiness` with a bounded connection retry loop (`up to 40 * 50ms = 2.0s`) so `mock_server` startup jitter on macOS never triggers a false `[Errno 61] Connection refused`.
  - Add cross-falsification assertions in `TEST-01`, `TEST-03`, and `ADV-TEST-05` verifying:
    - `KRAY_EVENT_STRUCT` (`<QQQQIIIIIHHBBBBI`, 64B) and `KRAY_RUNTIME_CFG_STRUCT` (`<IHBBQ`, 16B) round-trip unpacking via `RequestCorrelator.ingest(raw_64b_bytes)` and `RequestCorrelator.ingest(dict_event)`.
    - `decode_event_metadata` collision-free decoding when `flags & FLAG_SKB_DROP` (preserving full 32-bit `drop_reason` and `drop_reason_name` with `pkt_len == 0`) and when `flags & FLAG_TCP_RETRANSMIT` (preserving `retransmits` with `pkt_len == 0`).
    - Multi-core late event arrival after `LAYER_EGRESS_NIC (OSI_L2_DATALINK)` merging into `self._completed[req_id]` (`len(completed[req_id]) == 9`) instead of overwriting the completed trace with 1 event.
    - `summarize_trace(req_id)` accurately classifying `"DROPPED"` vs `"COMPLETED"` vs `"PARTIAL_TIMEOUT"` and separating `pure_on_cpu_ns` from `off_cpu_wait_ns` across `[t_entry, t_return]`.


---

## Archive Document: `archive/subagent_verifications/AGENT_06_LIVE_KERNEL_BPF_VERIFIER_ATTACH.md`

# AGENT 06 — Adversarial Falsification Audit: Live Target VM BPF Verifier Load & Real Kernel Attachment (`ebpf-tracer-v2.0.0`)

## 1. Executive Summary of Live Kernel Falsifications on `ebpf-tracer-v2.0.0` (`5.14.0-687.10.1.el9_8.0.1.aarch64`)

* **Falsification #1 (`bpftool prog loadall` != Real Kernel Attachment)**:
  - Running `bpftool prog loadall` without `autoattach` only validates `BPF_PROG_LOAD` in the Verifier.
  - Testing real attachment via `libbpf` `bpf_program__attach()` on `ebpf-tracer-v2.0.0` revealed:
    1. `trace_uprobe_entry` (`SEC("kprobe/trace_uprobe_entry")`) and `trace_uprobe_return` (`SEC("kretprobe/trace_uprobe_return")`) failed with `errno = -2 (ENOENT)` because `kray_bpf_core_compat.h` marked them as kernel probes instead of `SEC("uprobe")` / `SEC("uretprobe")`.
    2. Loopback (`lo`) rejects `xdpdrv` native mode (`EOPNOTSUPP`) and requires `xdpgeneric` (`XDP_FLAGS_SKB_MODE`).
    3. All 39 kernel `kprobe`/`kretprobe`/`tp` hooks in `tracer_kernel_bpf.o` match real symbols in `/proc/kallsyms` (`ipv6_rcv`, `ip6_output`, `tcp_v4_rcv`, `tcp_v6_rcv`, `__tcp_transmit_skb`, etc.) and attach cleanly (`PASS=39`).
* **Falsification #2 (Prompt Hypothesis on 42 Programs Falsified + Empty `sys_exit_write` Stub Caught)**:
  - Inspecting `llvm-objdump -h tracer_kernel_bpf.o` proved there are zero duplicate macro-generated `tracepoint_probe_*` sections; the 42 sections are `1 XDP + 18 Tracepoints + 21 Kprobes/Kretprobes + 2 Uprobes = 42` real functions in `tracer_kernel.c`.
  - Caught an actual 16-byte no-op stub (`r0 = 0; exit;`) in `TRACEPOINT_PROBE(syscalls, sys_exit_write)`.
* **Falsification #3 (Live Kernel Data-Path Bugs)**:
  - `__tcp_transmit_skb` clones `oskb` (`skb = skb_clone(oskb, gfp_mask)`), so `kprobe__ip_output` and `kprobe__ip6_output` must register the post-clone `skb_ptr` into `skb_egress_map` on `PT_REGS_PARM2(ctx)` fallback.
  - 0-byte TCP `SYN` / `ACK` packets must be filtered out before creating entries in `ingress_flow_map`.


---

## Archive Document: `archive/subagent_verifications/AGENT_07_SIM_HARNESS_FIDELITY_VERIFIER.md`

# AGENT 07 — C 에뮬레이션 하네스(`mock_bpf_runtime.h` / `kernel_sim_harness.c`) 현실 왜곡 반증 및 타겟 커널 교차 검증 보고서

## 1. 감사 개요 및 핵심 반증 결론 (Executive Summary)

* **검증 주체**: Agent 07 (`AGENT_07_SIM_HARNESS_FIDELITY_VERIFIER`)
* **검증 대상**:
  - 마스터 명세서: [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)
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
  - [`PROMPT_SPEC.md:197`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L197) (Flaw #35)은 비연결형 UDP 서버 소켓(`0.0.0.0:8080`)의 경우 `sk->sk_daddr == 0`, `sk->sk_dport == 0`이므로 `msg->msg_name` (`struct sockaddr_in *`)에서 피어 주소와 포트를 추출해야 한다고 명시하였다.
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
  - 또한 [`PROMPT_SPEC.md:451`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L451) 및 `tracer_agent.py`의 `decode_event_metadata()`는 `OSI_L3_IP (3)`와 `OSI_L4_TCP (4)` 이벤트의 `ev->ip`가 `((u64)ttl << 24) | ((u64)ihl_bytes << 16) | (u64)pkt_len`으로 비트패킹되어 있다고 정의하나, `kprobe____tcp_transmit_skb`, `kprobe__ip_output`, `kprobe__tcp_v6_rcv`, `kprobe__ip6_output`은 상위 비트를 채우지 않고 `estate->pkt_len`만 대입하여 `decode_event_metadata()` 호출 시 `ttl == 0, ihl_bytes == 0`으로 디코딩되었다.
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


---

## Archive Document: `archive/subagent_verifications/AGENT_08_VISUALIZATION_WEBUI_TUI_VERIFIER.md`

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


---

## Archive Document: `archive/subagent_verifications/AGENT_09_MCP_REST_CONCURRENCY_VERIFIER.md`

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


---

## Archive Document: `archive/subagent_verifications/AGENT_10_E2E_PURPOSE_MUTATION_VERIFIER.md`

# AGENT 10 — Adversarial Falsification Audit: End-to-End Wire-to-Code Purpose Alignment & Mutation Testing (`Mutants M1..M8`)

## 1. Executive Summary

* **Part A — End-to-End Wire-to-Code Purpose Alignment Audit (`E2E-01` .. `E2E-05`)**:
  - **E2E-01 (`run_tracer_pipeline()` Hardcoded Synthesis Bypass)**: `run_tracer_pipeline()` in `tracer_agent.py` was outputting hardcoded constants instead of feeding the 64-byte `KrayEvent` stream from `libtracer_kernel_sim` (or live BPF ringbuf) through `RequestCorrelator`, `decode_event_metadata()`, `compute_final_drop_count()`, and `BinarySymbolicator`.
  - **E2E-02 (DWARF Symbolication Bypass)**: `BinarySymbolicator.extract_cpp_source_evidence()` was searching `mock_server.cpp` text instead of querying `llvm-symbolizer` / `addr2line` / `dwarfdump` / `nm` on the compiled binary.
  - **E2E-03 (Interval Subtraction Engine)**: Needed event-driven calculation of `pure_on_cpu_compute_ms` vs `off_cpu_io_wait_ms` from `uretprobe` `duration_ns`, `off_cpu_delta`, and nested L5/L6 events.
  - **E2E-04 (`RequestCorrelator._finalize_request()` Sort Key Inversion)**: Sorted by `(layer_type, timestamp, is_return)` instead of `(timestamp, layer_type, is_return)`, pulling mid-function L5/L6 events (`block_rq_complete`, `sched_switch`) ahead of the L7 `uprobe` entry.
  - **E2E-05 (`mock_server.cpp` `--fast-mode` Flag & Relative `dlopen` Path)**: `mock_server.cpp` only checked `--fast-storage` (ignoring `--fast-mode`) and called `dlopen("./libcrypto_mock.so", RTLD_NOW)` with a CWD-relative path.

* **Part B — Mutation Testing of the 24 Test Suites (`Mutants M1` .. `M8`)**:
  - **Mutant M1**: `call_depth >= MAX_CALL_DEPTH (16/32)` bitmask wraparound (`16 & 15 == 0`) overwriting root frame slot 0 in `trace_uprobe_entry`.
  - **Mutant M2**: `sched_switch` in-function (`call_depth > 0`) Off-CPU sleep duration never tested through the C kernel simulator.
  - **Mutant M3**: `tcp_retransmit_skb` C tracepoint handler never executed in `kernel_sim_harness.c`.
  - **Mutant M4**: `kprobe__ip6_output` and `sched_process_fork` C handlers never executed in `kernel_sim_harness.c`.
  - **Mutant M5**: Unconnected UDP `kprobe__udp_sendmsg` emitting `dst_ip=0, dst_port=0` and leaking `active_ctx_map[&tid]`.
  - **Mutant M6**: `decode_event_metadata()` L2/L3/L4 bit-unpacking (`cpu_id`, `vlan_id`, `ttl`, `ihl_bytes`, `pkt_len`) not cross-verified against C kernel bit-packing.
  - **Mutant M7**: `RequestCorrelator._finalize_request()` timestamp ordering with mid-function L5/L6 events.
  - **Mutant M8**: `run_tracer_pipeline()` disconnected from `RequestCorrelator` and C kernel events.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_01_L2_XDP_VLAN_VERIFIER.md`

# Agent 01 Adversarial Falsification Report — Domain 01/20: L2 XDP & Ethernet Frame Parsing (802.1Q/802.1AD QinQ VLAN, Truncated Frames, Non-IP EtherTypes)

### 1. Executive Summary of Falsifications

* **Finding 1.1 [CRITICAL] — Missing `h_proto != ETH_P_IP_HOST` Guard After VLAN Unrolling in `TRACEPOINT_PROBE(net, netif_receive_skb)`**:
  * In [`tracer_kernel.c:548-565`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L548-L565), `h_proto` was initialized from `skb->protocol` and updated inside the 2-tag VLAN unroll loop, **but `if (h_proto != ETH_P_IP_HOST) return 0;` was missing after the loop**! Any non-IPv4 frame (ARP `0x0806`, LLDP `0x88CC`, MPLS `0x8847`, or triple-tagged VLAN) whose payload bytes at `nh_ptr` happened to have `(byte[0] & 0x0f) == 4` and `byte[9] == 6` falsely minted a `req_id` in `ingress_flow_map`.
* **Finding 1.2 [HIGH] — Missing `iph->version == 4` in `xdp_ingress_filter`, Missing `doff_len < sizeof(struct tcphdr)` in `netif_receive_skb`, and Unchecked `iph->tot_len` vs. Physical Buffer Length**:
  * In [`xdp_ingress_filter`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L452-L481), `iph->version == 4` and `(u64)tot_len <= (u64)((long)data_end - (long)iph)` must be verified so spoofed `tot_len` on truncated frames never bypasses the 0-byte payload filter.
  * In [`TRACEPOINT_PROBE(net, netif_receive_skb)`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L586-L590), `if (doff_len < sizeof(struct tcphdr)) return 0;` and `if (args->len < pulled_vlan_bytes + (u32)tot_len) return 0;` must be enforced.
* **Finding 1.3 [HIGH] — Shared `parse_eth_vlan_cursor` Helper, Legacy QinQ `0x9100` (`ETH_P_QINQ1`), and Hardware VLAN Offload (`skb->vlan_tci`)**:
  * Added `ETH_P_QINQ1_HOST` (`0x9100`), factored out `parse_eth_vlan_cursor()`, and read `skb->vlan_tci & 0x0FFF` in `netif_receive_skb` when hardware VLAN RX stripping is active.
* **Finding 1.4 [MEDIUM] — `decode_event_metadata` `vlan_id` vs. `rc` Bit-Packing Collision on `LAYER_INGRESS_NIC`**:
  * In [`tracer_agent.py:224-235`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L224-L235), `LAYER_INGRESS_NIC` packs `vlan_id` in `ev->ip` bits `[27:16]`, so `result["rc"]` must be `0` on ingress events instead of reporting `vlan_id` as `rc`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_02_L3_IPV4_IPV6_UNROLL_VERIFIER.md`

## Adversarial Falsification Report — Domain 02/20: L2/L3 Ingress SKB & IP Header Unrolling (`netif_receive_skb`, `ip_rcv`, `ipv6_rcv`, IPv4 Options `IHL`, IPv6 Extension Header Chains & Fragmentation)

### Executive Summary of Falsified Claims & Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against the target Rocky Linux 9.8 kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64` in [`references/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8)) falsified **10 distinct assumptions and implementation claims** across three core areas:

* **Area 1 — IPv4 Variable Header Length (`IHL`), Malformed Header Bounds (`ihl < 5`), and Non-First Fragment Guards**:
  * [`kprobe__ip_rcv`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L622-L685) fires at `ip_rcv()` entry ([`net/ipv4/ip_input.c:552`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L552)) **before** `ip_rcv_core()` validates `iph->ihl < 5 || iph->version != 4` ([`net/ipv4/ip_input.c:488`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L488)). Yet `kprobe__ip_rcv` ([`tracer_kernel.c:646-647`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L646-L647)) and `TRACEPOINT_PROBE(skb, kfree_skb)` ([`tracer_kernel.c:848-849`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L848-L849)) never check `ihl_bytes < 20` or `(iph.version & 0x0f) != 4`!
  * [`kernel_sim_harness.c:284-285`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L284-L285) (`build_ipv4_tcp_buf`) contains a **silent test-masking clamp**: `if (ihl_words < 5) ihl_words = 5;`, making it impossible for simulator tests to expose the missing `ihl < 5` check in `kprobe__ip_rcv` and `kfree_skb`.
  * None of `xdp_ingress_filter`, `tp_netif_receive_skb`, or `kprobe__ip_rcv` check for **non-first IPv4 fragments** (`(bpf_ntohs(iph.frag_off) & 0x1FFF) != 0`), causing raw L7 payload bytes in subsequent fragments to be misinterpreted as `struct tcphdr`.
  * Neither `tp_netif_receive_skb` ([`tracer_kernel.c:588-589`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L588-L589)) nor `kprobe__tcp_v4_rcv` ([`tracer_kernel.c:724-725`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L724-L725)) validates `doff_len >= sizeof(struct tcphdr)` (`20B`), allowing malformed `doff < 5` to inflate `tcp_payload_len > 0` on 0-byte ACKs.
* **Area 2 — IPv6 Extension Header Unrolling (`0`, `43`, `44`, `60`, `51`) & Non-First Fragment Misparse**:
  * [`PROMPT_SPEC.md:202`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L202) and [`PROMPT_SPEC.md:1199`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L1199) falsely specify a fixed `trans_off = net_off + sizeof(struct ipv6hdr)` (`40` bytes), contradicting RFC 8200 and Rocky 9.8 [`net/ipv6/ip6_input.c:230-313`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L230-L313) where `skb->transport_header` is still at the start of the first header after `struct ipv6hdr` upon `ipv6_rcv` entry.
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
  * [`PROMPT_SPEC.md:202`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L202) and [`PROMPT_SPEC.md:1199`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L1199) state:
    > "`ipv6_rcv` 진입 시점에는 `skb->transport_header`가 아직 L4 헤더로 설정되지 않았으므로, 반드시 `net_off + sizeof(struct ipv6hdr)` (`40` 바이트) 오프셋에서 L4 포트(`sport`, `dport`)를 직접 추출하라."
  * This instruction in `PROMPT_SPEC.md` is physically wrong whenever any IPv6 extension header (`0`, `43`, `44`, `51`, `60`) is present, and contradicts Section 3.3 item 7 ([`PROMPT_SPEC.md:280`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L280)) in the same document.

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

#### 1. [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md)

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


---

## Archive Document: `archive/subagent_verifications_20/AGENT_03_EGRESS_SKB_CLONE_VERIFIER.md`

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


---

## Archive Document: `archive/subagent_verifications_20/AGENT_04_DROP_RETRANSMIT_VERIFIER.md`

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
  * Because [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L801) filters `if (args->reason <= 2) return 0;`, every subsystem/driver/qdisc drop in Rocky 9.8 that calls plain `kfree_skb(skb)` (which passes `SKB_DROP_REASON_NOT_SPECIFIED = 2`, [`include/linux/skbuff.h`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/core/skbuff.c#L1060-L1068)) is silently discarded! And if an old kernel or mock passes `reason == 0`, it is also discarded instead of falling back to `SKB_DROP_REASON_NOT_SPECIFIED (2)`.
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


---

## Archive Document: `archive/subagent_verifications_20/AGENT_05_L4_TCP_STATE_0BYTE_VERIFIER.md`

### Agent 05 Adversarial Falsification Report — Domain 05/20: L4 TCP State Machine & 0-Byte Handshake/FIN/RST Filtering (`tcp_v4_rcv`, `tcp_v6_rcv`, `doff` Validation, Piggybacked ACKs)

#### Executive Summary of Falsified Assumptions
* **Target Scope Audited**:
  * [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L426-L756) (`xdp_ingress_filter`, `TRACEPOINT_PROBE(net, netif_receive_skb)`, `kprobe__ip_rcv`, `kprobe__tcp_v4_rcv`) and [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1722-L1890) (`kprobe__ipv6_rcv`, `kprobe__tcp_v6_rcv`)
  * [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L526-L532) (Iteration 1: Payload-Gated `req_id` Minting) & [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L574-L591) (Layer 1 & Layer 2 Hook Specifications)
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
  * [`PROMPT_SPEC.md:587`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L587)
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


---

## Archive Document: `archive/subagent_verifications_20/AGENT_06_DUAL_STACK_IPV6_SOCKET_VERIFIER.md`

# Adversarial Falsification Report — Domain 06/20: L4 Dual-Stack Normalization & IPv6 Sockets (`AF_INET6`, `::ffff:x.x.x.x`, `IPV6_V6ONLY`, `tcp_v6_syn_recv_sock`, `populate_sock_flow_key`)

### Executive Summary of Falsified Claims & Architectural Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against Rocky Linux 9.8 kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64` in [`references/`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8)) falsified core assumptions regarding dual-stack socket flow correlation:

* **Falsification 1 — IPv4-Mapped IPv6 Asymmetric Normalization in `populate_sock_flow_key`**:
  * In Linux kernel `net/ipv6/tcp_ipv6.c:1356`, when a dual-stack socket receives an IPv4 connection, `tcp_v6_syn_recv_sock` initializes the child socket with `skc_family = AF_INET6`, but `skc_v6_daddr` is set to `::ffff:1.2.3.4` (`in6_u.u6_addr32[2] = bpf_htonl(0x0000ffff)` and `in6_u.u6_addr32[3] = ipv4_daddr`).
  * In `tracer_kernel.c:populate_sock_flow_key`, the socket family is checked. If `rem_ip4 != 0` is present, it directly treats it as IPv4. However, if the socket was created via `bind(::)` without `IPV6_V6ONLY`, the local address `skc_v6_rcv_saddr` might be `::` (all zeros) or `::ffff:127.0.0.1`.
  * If `rem_v4_mapped` is true but `loc_v4_mapped` is false (e.g., listening on wildcard `::`), the previous key calculation left `key->daddr = 0` or failed to extract the IPv4 address from the mapped representation, leading to lookup mismatch against wire packets arriving on `netif_receive_skb` which are parsed as pure `AF_INET` (`127.0.0.1`).
* **Falsification 2 — `LOOPBACK4_IPV6` Synthetic Constant Collision**:
  * In Rocky Linux 9.8 `net/ipv6/tcp_ipv6.c:1356`, `LOOPBACK4_IPV6` (`bpf_htonl(0x7f000006)`) is used internally by the kernel for loopback routing acceleration in IPv6 child sockets.
  * In `tracer_kernel.c:populate_sock_flow_key`, reading `skc_rcv_saddr` directly on an `AF_INET6` socket without checking `skc_family` or mapped state can read `0x7f000006` instead of the actual IPv4 loopback address `127.0.0.1` (`0x7f000001`), corrupting the 4-tuple hash key.
* **Falsification 3 — UDP Dual-Stack Recvmsg Flow Association**:
  * In `tracer_kernel.c`, while TCP sockets have `skc_family` and `skc_num` populated, unconnected UDP sockets using `recvfrom()` or `recvmmsg()` on dual-stack wildcards do not set `skc_daddr` prior to reception.
  * Attempting to populate `egress_key` or `ingress_key` from `sock` in `udp_recvmsg` without reading `struct sockaddr_in6` from `struct msghdr` results in all-zero remote IP, breaking causality correlation.

### Root Cause Analysis & Line Citations

* [`tracer_kernel.c:290-340`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L290-L340):
  * `populate_sock_flow_key` handles `AF_INET` and `AF_INET6`.
  * For `AF_INET6`, it checks `ipv6_addr_is_v4_mapped(&rem6)` and `ipv6_addr_is_v4_mapped(&loc6)`.
  * If either is mapped or if `rem_ip4 != 0`, it normalizes to `AF_INET` and sets `key->family = AF_INET`.
  * However, when `rem_v4_mapped` is detected, `key->saddr = is_egress ? eff_loc4 : eff_rem4` must be strictly validated so that `eff_rem4` is taken from `rem6[3]` when `rem_ip4 == 0`.
* [`kernel_sim_harness.c:980-1025`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L980-L1025):
  * `sim_dual_stack_mapped_sock_key_test` and `sim_pure_ipv6_loopback4_sock_key_test` verify this behavior in unit testing.
  * Tested whether `skc_rcv_saddr = bpf_htonl(0x7f000006)` (Rocky 9.8 `LOOPBACK4_IPV6`) gets normalized properly to `AF_INET6` for pure IPv6, while mapped `::ffff:127.0.0.1` correctly normalizes to `AF_INET`.

### Verification & Remediation Invariants

1. Dual-Stack Normalization Invariant: Any socket connection terminating on an IPv4-mapped IPv6 address (`::ffff:x.x.x.x`) MUST produce a `flow_key_t` with `family = AF_INET`, `saddr = client_ipv4`, and `daddr = server_ipv4`.
2. Pure IPv6 Invariant: Sockets using native IPv6 addresses MUST preserve `family = AF_INET6` and store the 32-bit FNV-1a hash of the 128-bit IPv6 addresses in `saddr` and `daddr`.
3. Loopback4 Guard Invariant: In `AF_INET6` mode, `skc_rcv_saddr` containing `0x7f000006` MUST NOT override the 128-bit address `skc_v6_rcv_saddr` unless the 128-bit address is verified to be `::ffff:127.0.0.6`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_07_BLOCKING_SOCKET_KEEPALIVE_VERIFIER.md`

# Adversarial Falsification Report — Domain 07/20: L4 Blocking Sockets & Keep-Alive Filtering (`sk_wait_data`, 0-Byte Probes, TCP Keepalive, Delayed Binding)

### Executive Summary of Falsified Claims & Architectural Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against Rocky Linux 9.8 kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64`) falsified core assumptions regarding blocking sockets and keepalive packet handling:

* **Falsification 1 — Zero-Byte Keepalive Probe False Positives**:
  * TCP keep-alive packets and window probes contain `payload_len == 0` or `1` with ACK flags and sequence numbers set to `rcv_nxt - 1`.
  * If `kprobe__tcp_recvmsg` or `netif_receive_skb` processes these keepalive ACK packets without checking payload length or state changes, it generates false `req_id`s, polluting the trace with synthetic request lifecycles that never correspond to application layer RPCs.
  * In `tracer_kernel.c`, `netif_receive_skb` and `tcp_rcv_established` must strictly ignore 0-byte pure ACKs unless they are part of a valid connection handshake or FIN teardown.
* **Falsification 2 — Delayed Binding in Blocking Sockets (`sk_wait_data`)**:
  * In blocking I/O models, a thread calls `recv()` or `read()` before the network packet arrives at the NIC.
  * In Linux `net/ipv4/tcp.c:2150`, `tcp_recvmsg` enters and sleeps on `sk_wait_data()`.
  * When the packet arrives via NAPI SoftIRQ (`netif_receive_skb` -> `tcp_v4_rcv`), `req_id` is minted at L2/L3 in interrupt context where `current->pid` is the NAPI SoftIRQ kworker (`pid == 0` or idle).
  * If `active_ctx_map` relies on `kprobe__tcp_recvmsg` to bind `req_id` to the calling thread TID, the binding fails because `ingress_flow_map` does not have `req_id` yet at the instant `tcp_recvmsg` entry was hooked.
  * Therefore, `kretprobe__tcp_recvmsg` is REQUIRED to bind `req_id` to the thread upon socket read completion when data has actually been copied into userspace buffers.
* **Falsification 3 — Epoll Wakeup Latency Attribution in Long-Polling / Idle Sockets**:
  * For keepalive/long-polling connections, sockets remain idle inside `epoll_wait` for seconds or minutes.
  * If epoll wait latency is attributed to request processing time, total RTT inflates to 30,000ms+ (the idle timeout).
  * `tracer_kernel.c` and `tracer_agent.py` must isolate idle epoll wait time from active request processing time by tracking `now - epoll_exit_ts` rather than `epoll_enter_ts`.

### Root Cause Analysis & Line Citations

* [`tracer_kernel.c:710-756`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L710-L756):
  * `kprobe__tcp_rcv_established` validates `payload_len == 0`: if `payload_len == 0 && !(tflags & (FLAG_TCP_SYN | FLAG_TCP_FIN | FLAG_TCP_RST))`, packet is filtered out.
* [`tracer_kernel.c:1470-1540`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1470-L1540):
  * `kprobe__tcp_recvmsg` and `kretprobe__tcp_recvmsg`:
  * If `state` is not found at entry (delayed arrival case where thread blocked first), `kretprobe__tcp_recvmsg` checks `ingress_flow_map` at exit when `copied > 0` and binds `state->req_id` to `active_ctx_map[tid]`.
* [`test_verification_suite.py:1370-1378`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1370-L1378):
  * Explicitly tests delayed arrival: `sim_tcp_recvmsg_call` before packet arrival, followed by packet injection and verification that delayed binding succeeds.

### Verification & Remediation Invariants

1. 0-Byte Filter Invariant: Packets with zero TCP payload without SYN/FIN/RST flags MUST NOT create new `flow_state_t` entries or mint `req_id`s.
2. Delayed Binding Invariant: When `tcp_recvmsg` is called prior to packet arrival on the wire, the request ID MUST be resolved and bound to the thread context at `kretprobe__tcp_recvmsg` when bytes are returned (`ret > 0`).
3. Idle Separation Invariant: Epoll wait timeout and idle socket polling MUST NOT be counted towards `total_rtt_ms` or `pre_compute_latency_ns`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_08_UDP_UDS_PORT_DISCOVERY_VERIFIER.md`

# Agent 08 Adversarial Falsification Report — Domain 08/20: L4 Multi-Protocol Discovery & IPC (`UDP`, `UDS`, `inet_csk_accept`)

### 1. Executive Summary of Falsifications

* **Falsification 1 — UDP Wildcard (`0.0.0.0:9090` / `INADDR_ANY`) 4-Tuple Mismatch & Test Cheat**:
  * On an unconnected UDP server bound to `0.0.0.0:9090`, `sk->__sk_common.skc_rcv_saddr` is `0`, whereas `kprobe__udp_rcv` inserts `key.daddr = iph.daddr` (`127.0.0.1`). Updating both the exact 4-tuple `key` and the wildcard-local key `wild_key` (`wild_key.daddr = 0`) in `kprobe__udp_rcv` and checking `wild_key` in `kretprobe__udp_recvmsg` preserves full client `(saddr, sport, dport)` isolation even when `skc_rcv_saddr == 0`.
* **Falsification 2 — Connected UDP Sockets (`skc_daddr != 0, skc_dport != 0`) & Kernel vs. User `msg_name` Reading**:
  * `kprobe__udp_recvmsg` now reads `skc_daddr` and `skc_dport` so connected UDP sockets (`msg_name == NULL`) correlate cleanly, and `kretprobe__udp_recvmsg` tries `bpf_probe_read_kernel` before `bpf_probe_read_user` on `msg->msg_name`.
* **Falsification 3 — Blocking `unix_stream_recvmsg` Race Condition Across Process A and Process B**:
  * When Process B blocks in `unix_stream_recvmsg` (`unix_stream_data_wait`) *before* Process A calls `unix_stream_sendmsg`, `kprobe__unix_stream_recvmsg` runs when `ingress_flow_map` is empty. Saving `sk` and `peer` in `active_ctx_map` at entry and adding `kretprobe__unix_stream_recvmsg` resolves `req_id` upon wakeup/exit, checks `state->consumed == 0`, reads actual `len` (`PT_REGS_PARM3(ctx)`) in `kprobe__unix_stream_sendmsg`, and calls `publish_handoff_slot()`.
* **Falsification 4 — `kretprobe__inet_csk_accept` & `FLAG_PORT_DISCOVERY` / `PROTO_TCP` / `PROTO_UDP` / `PROTO_UDS`**:
  * Added `kretprobe__inet_csk_accept` to `tracer_kernel.c` and protocol/port discovery metadata decoding in `tracer_agent.py`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_09_L5_EPOLL_SYSCALL_ABI_VERIFIER.md`

# Agent 09 Adversarial Falsification Report — Domain 09/20: L5 Event Multiplexing (`epoll_wait`, `epoll_ctl`, Reactor Loop Readiness & Multi-FD Dispatch)

### 1. Executive Summary of Falsifications

* **Falsification 1 — Complete Absence of L5 Epoll Multiplexing Hooks Across the Codebase**:
  * In [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h), and [mock_bpf_runtime.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/mock_bpf_runtime.h), zero `epoll` tracepoints, kprobes, or context fields existed prior to this 20-agent audit.
  * Specifically, [`struct tid_ctx_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L179-L208) had `futex_enter_ts`, `wakeup_ts`, `off_cpu_enter_ts`, `copy_enter_ts`, `active_sk_ptr`, and `active_msg_name`, but no `epoll_enter_ts` or `epoll_wait_ns` field.
  * Syscall tracepoints in [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L873-L1536) were restricted to `sys_enter_read`, `sys_enter_futex`, `sys_exit_futex`, `sys_enter_write`, and `sys_exit_write`.
* **Falsification 2 — Critical `aarch64` Linux Kernel ABI Blind Spot (`__NR_epoll_wait` Does Not Exist on `aarch64`)**:
  * On the target Rocky Linux 9.8 `aarch64` kernel (`5.14.0-687.10.1.el9_8.0.1.aarch64`), [arch/arm64/include/uapi/asm/unistd.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/arch/arm64/include/uapi/asm/unistd.h#L1-L25) delegates directly to [include/uapi/asm-generic/unistd.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/uapi/asm-generic/unistd.h#L77-L82).
  * In `asm-generic/unistd.h`, legacy `epoll_create` and `epoll_wait` are omitted (`__ARCH_WANT_SYSCALL_DEPRECATED` is never defined on `arm64`). Only four epoll syscalls exist in the `aarch64` syscall table:
    * `__NR_epoll_create1` (`20`) -> `sys_epoll_create1`
    * `__NR_epoll_ctl` (`21`) -> `sys_epoll_ctl`
    * `__NR_epoll_pwait` (`22`) -> `sys_epoll_pwait`
    * `__NR_epoll_pwait2` (`441`) -> `sys_epoll_pwait2`
  * On `aarch64`, when C/C++ user-space (`nginx`, `Envoy`, `libuv`, or `mock_server.cpp`) calls glibc's `epoll_wait(epfd, events, maxevents, timeout)`, glibc invokes `syscall(__NR_epoll_pwait, epfd, events, maxevents, timeout, NULL, _NSIG / 8)`.
* **Falsification 3 — Spurious Events & Timestamp Accumulation on `epoll_wait` / `epoll_pwait` Timeout (`ret == 0`) or Error (`ret < 0`, e.g. `-EINTR`)**:
  * In `fs/eventpoll.c`, `do_epoll_wait` returns `0` when the timeout expires with no ready events, or a negative errno (`-EINTR = -4`, `-EBADF = -9`, `-EINVAL = -22`, `-EFAULT = -14`) on signal interruption or invalid parameters.
  * When `ret <= 0`, the exit probe must clear `tctx->epoll_enter_ts = 0`, `tctx->epoll_wait_ns = 0`, and `tctx->epoll_ready_rem = 0` without emitting a spurious `OSI_L6_PRE_COMPUTE` event.
* **Falsification 4 — Reactor Loop Causal Order Inversion (`epoll_pwait` Runs *Before* `tcp_recvmsg` Binds `req_id`) & Context Clobbering by `kprobe__tcp_recvmsg`**:
  * In real event-driven servers, the reactor loop calls `epoll_wait()` / `epoll_pwait()` **before** calling `recv()` / `tcp_recvmsg()`.
  * `kprobe__tcp_recvmsg` previously overwrote `active_ctx_map[&tid]` with `zero_template` on entry, wiping out any `epoll_wait_ns` or `epoll_ready_rem` recorded by `sys_exit_epoll_pwait` moments earlier.
  * Saving `saved_epoll_wait_ns` and `saved_epoll_ready_rem` across `active_ctx_map.update(&tid, zero_template)` in `kprobe__tcp_recvmsg` and emitting the deferred `OSI_L6_PRE_COMPUTE` event as soon as `tctx->req_id` is bound preserves full reactor-loop causality.
* **Falsification 5 — Multi-FD Batch Readiness (`args->ret > 1`) & `mock_server.cpp` Epoll Coverage**:
  * Tracking `epoll_ready_rem` across multi-FD batches and wiring `epoll_create1` / `epoll_ctl` / `epoll_wait` into `mock_server.cpp` ensures both simulation and live loopback tests exercise L5 epoll multiplexing.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_10_FUTEX_8SLOT_HANDOFF_VERIFIER.md`

# Agent 10 Adversarial Falsification Report — Domain 10/20: L5/L6 Futex Synchronization & 8-Slot Handoff Ring Buffer (`sys_enter_futex`, `sys_exit_futex`, `FUTEX_WAIT`/`WAKE`, Contention & Wrap-Around)

### 1. Executive Summary of Falsifications

* **Flaw 1 — `sys_exit_futex` Drops `-EAGAIN` (`-11`) Contended Fast-Path Handoffs & Leaks Stale `futex_enter_ts` Across `-ETIMEDOUT` (`-110`) / `-EINTR` (`-4`)**:
  * In [`tracer_kernel.c:1142-1188`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1188), `sys_exit_futex` previously rejected all `args->ret < 0`. When a producer updates the futex word and calls `FUTEX_WAKE` just before the consumer acquires the kernel futex hash-bucket spinlock in `futex_wait_setup()`, `futex(FUTEX_WAIT)` returns `-EAGAIN` (`-11`) immediately without sleeping (`sched_switch` never fires). Allowing `args->ret == -11` (`-EAGAIN`) to claim a pending handoff slot while clearing `tctx->futex_enter_ts = 0` on genuine errors (`-ETIMEDOUT = -110`, `-EINTR = -4`) closes both the fast-path drop and the stale timestamp leak.
* **Flaw 2 — Futex Opcode Extraction (`cmd = op & 0x7F`) in `sys_enter_futex` & `FUTEX_LOCK_PI2` (`13`) Coverage**:
  * Separates `#ifdef KRAY_BPF_CORE`, `#elif defined(KRAY_USER_SIM)`, and `#else` (BCC) opcode extraction cleanly, and adds `FUTEX_LOCK_PI2` (`13`) to the wait opcode set (`0, 6, 9, 11, 13`).
* **Flaw 3 — 8-Slot Active Window Deduplication & Monotonic `u32` Wrap-Around Safety in `publish_handoff_slot`**:
  * Replaces the single-slot `ring->write_idx > ring->read_idx` check with an unrolled 8-slot active window scan (`u32 depth = (u32)(ring->write_idx - ring->read_idx)`) that prevents duplicate slot allocation even if an earlier slot for the same `req_id` was already claimed by `sched_waking`.
* **Flaw 4 — Unified `mark_handoff_slot_claimed()` and `consume_handoff_slot()` Helpers**:
  * Searches the active 8-slot window in `mark_handoff_slot_claimed()` when `sched_waking` claims a request out-of-order, and advances `read_idx` past any leading already-claimed slots in `consume_handoff_slot()`.
* **Flaw 5 — UDP (`kretprobe__udp_recvmsg`) and `AF_UNIX` (`kprobe__unix_stream_recvmsg`) Handoff Publishing**:
  * Calls `publish_handoff_slot()` in `kretprobe__udp_recvmsg` and `kprobe__unix_stream_recvmsg` so multi-threaded UDP and UDS servers also support Tier-2 worker pool handoff.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_11_SCHEDULER_MIGRATION_VERIFIER.md`

### Domain 11 Adversarial Falsification Report: L5/L6 Scheduler & CPU Migration (`sched_waking`, `sched_wakeup`, `sched_switch`, `sched_process_fork`, `sys_enter_futex`, `sys_exit_futex`, Runqueue Latency, Preemption vs. Voluntary Sleep)

#### 1. Falsification of the Prompt's Premise (`active_ctx_map` Key Width & `swapper/0` Behavior)
* **Prompt Hypothesis Audited**:
  * The prompt hypothesized that `active_ctx_map` is keyed by `u64 pid_tgid` (`(u64)tgid << 32 | tid`) and that `tp_sched_switch` constructs a `u64` key using `bpf_get_current_pid_tgid() & 0xFFFFFFFF00000000ULL`, which would fail when switching from `swapper/N` (`prev_pid == 0`, `tgid == 0`).
* **Physical Code Reality in [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L251-L254)**:
  * In [`tracer_kernel.c:253`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L253), `active_ctx_map` is declared as `BPF_LRU_HASH(active_ctx_map, u32, struct tid_ctx_t, 8192);` (keyed by 32-bit `u32 tid`, NOT `u64 pid_tgid`), whereas `pending_handoff_map` in [`tracer_kernel.c:254`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L254) is keyed by `u32 tgid`.
  * In [`tp_sched_switch` (`tracer_kernel.c:1282-1327`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1282-L1327), `u32 prev_tid = (u32)args->prev_pid;` and `u32 next_tid = (u32)args->next_pid;` are used directly as keys into `active_ctx_map`, and the emitted event uses `nctx->pid` (the cached TGID stored inside [`struct tid_ctx_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L211-L234)), avoiding `bpf_get_current_pid_tgid()` inside `tp_sched_switch`.
* **Actual `swapper/N` (`tid == 0`) Defect Found in [`tracer_kernel.c:1288-1299`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1288-L1299)**:
  * Neither `prev_tid` nor `next_tid` is guarded against `0` (`swapper/N` idle threads on every CPU core). Every idle transition performs unnecessary BPF LRU hash lookups on key `0` (`active_ctx_map.lookup(&prev_tid)` and `active_ctx_map.lookup(&next_tid)`).

---

#### 2. Critical Flaw #1: Involuntary Preemption (`args->prev_state == 0` or `TASK_REPORT_MAX`) Drops Runqueue Wait Latency to `0 ns` at `call_depth == 0` and Fails to Distinguish Preemption from Voluntary Sleep
* **Target Kernel Ground Truth ([`include/trace/events/sched.h:190-265`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L190-L265))**:
  * In Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8`), `__trace_sched_switch_state(bool preempt, unsigned int prev_state, struct task_struct *p)` sets `args->prev_state` to `TASK_REPORT_MAX` (`0x100` / `256`) when `preempt == true`, or `0` (`TASK_RUNNING`) on voluntary yield/preemption, whereas voluntary sleep (`futex`, socket wait, block I/O) sets `args->prev_state` to `TASK_INTERRUPTIBLE` (`1`) or `TASK_UNINTERRUPTIBLE` (`2`).
  * When a task is involuntarily preempted (`prev_state == 0` or `prev_state >= 0x100`), it **remains on the CPU runqueue in `TASK_RUNNING` state** and **never triggers `sched_waking` or `sched_wakeup`** before being scheduled back On-CPU by `sched_switch`.
* **Root Cause in [`tp_sched_switch` (`tracer_kernel.c:1282-1327`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1282-L1327)**:
  * `tp_sched_switch` never reads `args->prev_state`!
  * When a thread with an active `req_id` is involuntarily preempted at `call_depth == 0` (for example, between `skb_copy_datagram_iter` and the first user-space `uprobe`, or after `sched_wakeup` + preemption before `uprobe`):
    1. On switch-out ([`tracer_kernel.c:1292-1296`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1292-L1296)), `pctx->off_cpu_enter_ts = now;` is recorded, while `pctx->wakeup_ts` remains `0` (because `sched_wakeup` never fires for an already-runnable preempted task).
    2. On switch-in ([`tracer_kernel.c:1303-1310`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1303-L1310)):
       * `u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts) : 0;` evaluates to **`0`**!
       * `u64 total_off_cpu_ns = nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : runq_ns;` evaluates to the true preemption runqueue wait (`now - off_cpu_enter_ts`).
       * `u64 emit_dur = (nctx->call_depth == 0) ? runq_ns : total_off_cpu_ns;` selects `runq_ns` (`0`) because `nctx->call_depth == 0`!
    3. Consequently, **100% of involuntary preemption runqueue latency at `call_depth == 0` is emitted with `duration_ns = 0`!**
  * Furthermore, when an involuntarily preempted thread at `call_depth > 0` stays on the runqueue waiting for CPU time, its entire `now - off_cpu_enter_ts` is actually **Runqueue Wait** (since `prev_state == 0` / `TASK_REPORT_MAX`), whereas `tp_sched_switch` does not record whether the switch-out was preemption (`prev_state == 0 || prev_state >= 0x80`) vs. voluntary sleep (`prev_state & 0x7f`).

---

#### 3. Critical Flaw #2: Tier-2 `sys_exit_futex` Handoff Claim Occurs *After* `sched_switch`, Skipping `OSI_L6_PRE_COMPUTE` Emission and Leaving Stale `wakeup_ts` / `futex_enter_ts`
* **Root Cause in [`sys_exit_futex` (`tracer_kernel.c:1142-1188`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1188) and [`kernel_sim_harness.c:1033-1038`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L1033-L1038)**:
  * Consider the physical Linux kernel execution order when a worker thread wakes from `futex(FUTEX_WAIT)` and claims a handoff via Tier 2 (`pending_handoff_map` in `sys_exit_futex`, e.g., when `sched_waking` did not populate `tctx` or in `FUTEX_REQUEUE` / burst handoff):
    1. Worker enters `sys_enter_futex(FUTEX_WAIT)` (`tctx->futex_enter_ts = t_enter`, `tctx->req_id = 0`).
    2. Worker is switched Off-CPU by `tp_sched_switch` (`tctx->req_id == 0`).
    3. Worker is switched **back On-CPU** by `tp_sched_switch` so it can exit the `futex` syscall. If Tier 1 (`tp_sched_waking`) did not assign `tctx->req_id`, then at the moment `tp_sched_switch` runs, `nctx->req_id` is still **`0`**, so `tp_sched_switch` ([`tracer_kernel.c:1299`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1299)) does **nothing**!
    4. Now already On-CPU, the worker executes [`tp_sys_exit_futex` (`tracer_kernel.c:1142-1188`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1188), which claims `ring->slots[r_idx]` and populates `tctx->req_id`, `tctx->futex_enter_ts = saved_futex_ts`, and `tctx->wakeup_ts = ring->slots[r_idx].wakeup_ts`.
    5. The worker immediately returns to user space and enters `trace_uprobe_entry` **without another `sched_switch`**!
  * **Two Severe Consequences**:
    1. **Missing `OSI_L6_PRE_COMPUTE` Event**: `tp_sys_exit_futex` never emits the `OSI_L6_PRE_COMPUTE` event for the Tier-2 handoff (`lock_wait_ns = wakeup_ts - futex_enter_ts`, `runq_ns = now - wakeup_ts`, and CPU migration `prev_cpu_id -> cur_cpu`).
    2. **Timestamp Poisoning on Next Context Switch**: Because `tctx->wakeup_ts` and `tctx->futex_enter_ts` are set in `tp_sys_exit_futex` and **not cleared**, when the worker later blocks inside a user function (`call_depth > 0`, e.g., during Block I/O), the next `tp_sched_switch` computes a corrupted `lock_wait_ns` using the stale `futex_enter_ts` from before the function even started!

---

#### 4. Critical Flaw #3: `tp_sched_waking` Unconditionally Clobbers Active Target Thread Contexts and Fails to Mark Non-Head `pending_handoff_map` Ring Slots as Claimed
* **Root Cause in [`tp_sched_waking` (`tracer_kernel.c:1220-1271`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1220-L1271)**:
  * **Sub-Flaw 3A (Context Clobbering of Active Threads & Cross-Process Kernel Threads)**:
    * At [`tracer_kernel.c:1236-1245`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1236-L1245):
      ```c
      struct tid_ctx_t *existing_tctx = active_ctx_map.lookup(&target_tid);
      u64 saved_futex_ts = existing_tctx ? existing_tctx->futex_enter_ts : 0;
      ...
      active_ctx_map.update(&target_tid, zero_template);
      ```
    * If `existing_tctx && existing_tctx->req_id != 0` (for example, `target_tid` is **already actively executing another traced request** `req_id_1` and was briefly blocked on a mutex/pagefault/I/O that `waker_tid` happened to wake while holding `req_id_2`), `tp_sched_waking` **wipes out `target_tid`'s entire `tid_ctx_t`** (`zero_template`), destroying its in-flight `req_id_1`, `call_depth`, `fn_entry_ts[]`, and `acc_off_cpu_ns`!
    * Even worse: if `existing_tctx && existing_tctx->req_id == wctx->req_id` (a worker thread already handling `wctx->req_id` at `call_depth > 0` is woken up by a helper thread sharing the same `req_id`), `active_ctx_map.update(&target_tid, zero_template)` zeroes out `target_tid`'s `call_depth` and `fn_entry_ts[]` stack mid-function!
    * Furthermore, when an Acceptor thread with `wctx->req_id != 0` wakes a kernel worker thread (`kworker/*`, `ksoftirqd/*`) or an unrelated daemon (`target_tid` not in `tgid`), `tp_sched_waking` injects `wctx->req_id` and `tctx->pid = tgid` into `active_ctx_map[&target_tid]`, causing the kernel thread's subsequent `sched_switch` to emit false `OSI_L6_PRE_COMPUTE` events attributed to the application's `req_id` and `tgid`!
  * **Sub-Flaw 3B (Ring Buffer Slot Leak & Double-Claim on Out-of-Order Wakeups)**:
    * At [`tracer_kernel.c:1261-1268`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1261-L1268):
      ```c
      struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
      if (ring) {
          u32 r_idx = ring->read_idx & 7;
          if (ring->slots[r_idx].req_id == wctx->req_id && ring->slots[r_idx].claimed == 0) {
              ring->slots[r_idx].claimed = 1;
              ring->read_idx++;
          }
      }
      ```
    * If Acceptor A publishes `req_id_1` at `slots[0]` (`read_idx == 0`) via `sys_enter_futex(FUTEX_WAKE)` where no sleeping thread was woken in `sched_waking` (because Worker 1 was spinning in user space and will call `FUTEX_WAIT` / `sys_exit_futex`), and Acceptor B concurrently publishes `req_id_2` at `slots[1]` and wakes Worker 2 via `tp_sched_waking`, then `ring->slots[r_idx].req_id` (`slots[0].req_id == req_id_1`) does **not** match `wctx->req_id` (`req_id_2`). As a result, `slots[1]` (`req_id_2`) is **left unclaimed (`claimed == 0`)** in `pending_handoff_map`, and the next Tier-2 worker in `sys_exit_futex` will claim `req_id_2` a **second time**!

---

#### 5. Critical Flaw #4: `tp_sched_switch` Overwrites `prev_cpu_id` During SMP Wakeup-Before-Switch Race, and `tp_sched_process_fork` Never Initializes `wakeup_ts` or `prev_cpu_id`
* **Root Cause A (`tp_sched_switch` Overwriting Waker's `prev_cpu_id` in [`tracer_kernel.c:1292-1296`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1292-L1296))**:
  * In [`tracer_kernel.c:1292-1296`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1292-L1296):
    ```c
    struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
    if (pctx && pctx->req_id != 0) {
        pctx->off_cpu_enter_ts = now;
        pctx->prev_cpu_id      = (u8)bpf_get_smp_processor_id();
    }
    ```
  * When a worker thread on CPU 2 sets `TASK_INTERRUPTIBLE` inside `futex_wait_queue_me()` and an Acceptor thread on CPU 0 immediately calls `FUTEX_WAKE` -> `try_to_wake_up()` -> `tp_sched_waking` *before* CPU 2 executes `tp_sched_switch` for `prev_tid`, `tp_sched_waking` on CPU 0 sets `tctx->req_id = wctx->req_id`, `tctx->wakeup_ts = now`, and `tctx->prev_cpu_id = 0` (the Acceptor's CPU).
  * Microseconds later, when CPU 2 runs `tp_sched_switch` (`prev_tid = worker`), `pctx->req_id != 0` is now TRUE, so `pctx->prev_cpu_id` is overwritten with `2` (the worker's old CPU), erasing the cross-CPU handoff provenance (`CPU 0 -> CPU 2`)!
* **Root Cause B (`tp_sched_process_fork` Missing `wakeup_ts` and `prev_cpu_id` in [`tracer_kernel.c:1190-1218`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1190-L1218))**:
  * In Linux `kernel/sched/core.c` (`wake_up_new_task`), a newly forked/cloned thread is woken via `trace_sched_wakeup_new(p)` ([`include/trace/events/sched.h:185`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/include/trace/events/sched.h#L185)), **not** `sched_waking` or `sched_wakeup`.
  * Because [`tp_sched_process_fork` (`tracer_kernel.c:1206-1216`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1206-L1216) leaves `cctx->wakeup_ts = 0` and `cctx->prev_cpu_id = 0`, when the forked child thread is scheduled onto a CPU in `tp_sched_switch`, the guard `(nctx->wakeup_ts != 0 || nctx->off_cpu_enter_ts != 0)` at [`tracer_kernel.c:1299`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1299) evaluates to **FALSE**, completely dropping the child thread's initial `OSI_L6_PRE_COMPUTE` runqueue latency and CPU migration event!

---

#### 6. Critical Flaw #5: User-Space `correlate_and_symbolicate_sim_events` (`tracer_agent.py`) Hardcodes `tid == 10425`, Hardcodes `"execute_storage_query"`, Ignores `OSI_L6_PRE_COMPUTE` Off-CPU Events, and Hardcodes `sched_runq_ms` / `sched_lock_ms` in `run_tracer_pipeline`
* **Spec Contract ([`PROMPT_SPEC.md:716`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L716) & [`PROMPT_SPEC.md:925`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L925))**:
  * Requires `tracer_agent.py` to subtract direct child `OSI_L5_SYSCALL_MEM (6)` and `OSI_L6_PRE_COMPUTE (8)` wait events inside `[t_entry, t_return]` (or use the kernel-maintained `acc_off_cpu_ns` snapshot delta exported by `trace_uprobe_entry` / `trace_uprobe_return`) to separate `pure_on_cpu_compute_ms` and `off_cpu_io_wait_ms` for any traced function on any thread.
* **Actual Implementation in [`tracer_agent.py:746-785`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L746-L785)**:
  * At [`tracer_agent.py:747-751`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L747-L751):
    ```python
    worker_bio_ns = 0
    for ev in trace_events:
        meta = decode_event_metadata(ev)
        if int(ev.layer_type) == LAYER_USER_ENTRY and int(ev.call_depth) == OSI_L5_SYSCALL_MEM and int(ev.tid) == 10425:
            worker_bio_ns += int(ev.duration_ns)
    ```
  * And at [`tracer_agent.py:770`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L770):
    ```python
    off_cpu_ns = worker_bio_ns if resolved["symbol"] == "execute_storage_query" else 0
    ```
  * **Three Falsifications in `tracer_agent.py`**:
    1. **Mock-Pass Hardcoding of `tid == 10425` and `symbol == "execute_storage_query"`**: Any other worker thread TID (e.g., `20002`, `30001`, or forked child) or any other user function that sleeps on a mutex/condvar/futex (`OSI_L6_PRE_COMPUTE` at `call_depth > 0`) or performs Block I/O gets `off_cpu_ns = 0`!
    2. **Kernel Already Computes Exact Per-Function Off-CPU Delta via `fn_off_cpu_snap[depth]`**: Look at [`trace_uprobe_entry` (`tracer_kernel.c:1447-1461`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1447-L1461), which stores `tctx->fn_off_cpu_snap[depth] = tctx->acc_off_cpu_ns;` and emits `off_cpu_snap` in `ev.duration_ns` of the `LAYER_USER_ENTRY` event! However, [`trace_uprobe_return` (`tracer_kernel.c:1464-1509`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1464-L1509) never reads `tctx->acc_off_cpu_ns - tctx->fn_off_cpu_snap[depth]`, and `correlate_and_symbolicate_sim_events` completely ignores both `ev.duration_ns` on `LAYER_USER_ENTRY` and `OSI_L6_PRE_COMPUTE` events during `[t_entry, t_return]`!
    3. **Double-Counting Hazard Between `OSI_L5_SYSCALL_MEM` and `OSI_L6_PRE_COMPUTE` Inside `[t_entry, t_return]`**: In [`kernel_sim_harness.c:660-678`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c#L660-L678), while `execute_storage_query` is at `call_depth == 1`, the worker sleeps for `bio_ns` (`18,220,000 ns`). `block_rq_complete` emits `OSI_L5_SYSCALL_MEM` with `duration_ns = 18,220,000`, AND `sched_switch` emits `OSI_L6_PRE_COMPUTE` with `duration_ns = total_off_cpu_ns = 18,220,000`! Because `total_off_cpu_ns` (`now - off_cpu_enter_ts`) encompasses the entire sleep window of the Block I/O + post-wakeup runqueue latency (`runq_ns`), `OSI_L6_PRE_COMPUTE` (`total_off_cpu_ns`) is the **total Off-CPU time** of that function call, whereas `OSI_L5_SYSCALL_MEM` (`bio_ns`) is the Block I/O sub-component of that sleep!
    4. **Hardcoded `sched_runq_ms` and `sched_lock_ms` in [`run_tracer_pipeline` (`tracer_agent.py:1358-1363`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1358-L1363)**:
       * Lines 1359–1360 hardcode `sched_runq_ms = 0.065` and `sched_lock_ms = 0.115` instead of extracting them from the `OSI_L6_PRE_COMPUTE` event decoded in `c_harness_result["events"]` (`meta["lock_wait_ns"] / 1e6` and `ev.duration_ns / 1e6`)!

---

#### 7. Concrete Diff Recommendations

##### A. [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1142-L1327) — Fix `sys_exit_futex`, `sched_process_fork`, `sched_waking`, `sched_wakeup`, and `sched_switch`
```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -1173,16 +1173,30 @@ TRACEPOINT_PROBE(syscalls, sys_exit_futex)
         if (tctx) {
+            u64 now              = bpf_ktime_get_ns();
+            u8  cur_cpu          = (u8)bpf_get_smp_processor_id();
+            u64 wake_ts          = ring->slots[r_idx].wakeup_ts;
+            u64 runq_ns          = (wake_ts && now > wake_ts) ? (now - wake_ts) : 0;
+            u64 lock_wait_ns     = (saved_futex_ts && wake_ts > saved_futex_ts)
+                                       ? (wake_ts - saved_futex_ts)
+                                       : 0;
+            u64 capped_lock      = (lock_wait_ns > 0xFFFFFFFFULL) ? 0xFFFFFFFFULL : lock_wait_ns;
+            u64 encoded_ip       = (capped_lock << 16) |
+                                   (((u64)ring->slots[r_idx].prev_cpu_id & 0xff) << 8) |
+                                   ((u64)cur_cpu & 0xff);
+
             tctx->req_id         = ring->slots[r_idx].req_id;
-            tctx->futex_enter_ts = saved_futex_ts;
-            tctx->wakeup_ts      = ring->slots[r_idx].wakeup_ts;
+            tctx->futex_enter_ts = 0;
+            tctx->wakeup_ts      = 0;
             tctx->pid            = tgid;
             tctx->tid            = tid;
             tctx->parent_tid     = ring->slots[r_idx].waker_tid;
             tctx->saddr          = ring->slots[r_idx].saddr;
             tctx->daddr          = ring->slots[r_idx].daddr;
             tctx->sport          = ring->slots[r_idx].sport;
             tctx->dport          = ring->slots[r_idx].dport;
             tctx->prev_cpu_id    = ring->slots[r_idx].prev_cpu_id;
+            tctx->target_cpu_id  = cur_cpu;
             tctx->flags         |= FLAG_THREAD_HANDOFF;
+
+            emit_kray_event(
+                tctx->req_id, encoded_ip, now, runq_ns,
+                tctx->pid, tid, tctx->parent_tid,
+                tctx->saddr, tctx->daddr, tctx->sport, tctx->dport,
+                LAYER_USER_ENTRY, 0, OSI_L6_PRE_COMPUTE, tctx->flags);
         }
     }
     return 0;
 }
@@ -1206,10 +1220,12 @@ TRACEPOINT_PROBE(sched, sched_process_fork)
     if (cctx) {
         cctx->req_id     = pctx->req_id;
+        cctx->wakeup_ts  = bpf_ktime_get_ns();
         cctx->pid        = pctx->pid;
         cctx->tid        = child_tid;
         cctx->parent_tid = parent_tid;
         cctx->saddr      = pctx->saddr;
         cctx->daddr      = pctx->daddr;
         cctx->sport      = pctx->sport;
         cctx->dport      = pctx->dport;
+        cctx->prev_cpu_id = (u8)bpf_get_smp_processor_id();
         cctx->flags      = pctx->flags | FLAG_THREAD_HANDOFF;
     }
     return 0;
 }
@@ -1235,8 +1251,14 @@ TRACEPOINT_PROBE(sched, sched_waking)
     /* Preserve futex_enter_ts if worker thread already entered sys_enter_futex(FUTEX_WAIT) */
     struct tid_ctx_t *existing_tctx = active_ctx_map.lookup(&target_tid);
+    if (existing_tctx && existing_tctx->req_id != 0) {
+        /* Do not clobber a thread that is already actively tracing a request */
+        if (existing_tctx->req_id == wctx->req_id)
+            existing_tctx->wakeup_ts = bpf_ktime_get_ns();
+        return 0;
+    }
     u64 saved_futex_ts = existing_tctx ? existing_tctx->futex_enter_ts : 0;
@@ -1261,8 +1283,13 @@ TRACEPOINT_PROBE(sched, sched_waking)
         struct handoff_ring_t *ring = pending_handoff_map.lookup(&tgid);
         if (ring) {
-            u32 r_idx = ring->read_idx & 7;
-            if (ring->slots[r_idx].req_id == wctx->req_id && ring->slots[r_idx].claimed == 0) {
-                ring->slots[r_idx].claimed = 1;
-                ring->read_idx++;
+            #pragma unroll
+            for (int i = 0; i < 8; i++) {
+                u32 idx = (ring->read_idx + i) & 7;
+                if (ring->slots[idx].req_id == wctx->req_id && ring->slots[idx].claimed == 0) {
+                    ring->slots[idx].claimed = 1;
+                    if (i == 0)
+                        ring->read_idx++;
+                    break;
+                }
             }
         }
     }
@@ -1291,18 +1318,24 @@ TRACEPOINT_PROBE(sched, sched_switch)
     u32 prev_tid = (u32)args->prev_pid;
     u32 next_tid = (u32)args->next_pid;
     u64 now      = bpf_ktime_get_ns();
 
-    struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
-    if (pctx && pctx->req_id != 0) {
-        pctx->off_cpu_enter_ts = now;
-        pctx->prev_cpu_id      = (u8)bpf_get_smp_processor_id();
+    if (prev_tid > 0) {
+        struct tid_ctx_t *pctx = active_ctx_map.lookup(&prev_tid);
+        if (pctx && pctx->req_id != 0) {
+            pctx->off_cpu_enter_ts = now;
+            /* Preserve waker's prev_cpu_id if sched_waking already fired before switch-out */
+            if (pctx->wakeup_ts == 0)
+                pctx->prev_cpu_id = (u8)bpf_get_smp_processor_id();
+        }
     }
 
+    if (next_tid == 0)
+        return 0;
     struct tid_ctx_t *nctx = active_ctx_map.lookup(&next_tid);
     if (nctx && nctx->req_id != 0 && (nctx->wakeup_ts != 0 || nctx->off_cpu_enter_ts != 0)) {
         u8 cur_cpu = (u8)bpf_get_smp_processor_id();
         nctx->target_cpu_id = cur_cpu;
 
-        u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts) : 0;
+        /* If involuntarily preempted (wakeup_ts == 0, off_cpu_enter_ts != 0), entire wait is runqueue wait */
+        u64 runq_ns = nctx->wakeup_ts ? (now - nctx->wakeup_ts)
+                                      : (nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : 0);
         u64 total_off_cpu_ns = nctx->off_cpu_enter_ts ? (now - nctx->off_cpu_enter_ts) : runq_ns;
```

##### B. [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L745-L785) — Remove Hardcoded `tid == 10425` / `"execute_storage_query"` and Extract Real Scheduler Wait Metrics
```diff
--- a/tracer_agent.py
+++ b/tracer_agent.py
@@ -744,12 +744,6 @@ def correlate_and_symbolicate_sim_events(
     fn_spans: list[dict[str, Any]] = []
     open_entries: dict[tuple[int, int], Any] = {}
 
-    worker_bio_ns = 0
-    for ev in trace_events:
-        meta = decode_event_metadata(ev)
-        if int(ev.layer_type) == LAYER_USER_ENTRY and int(ev.call_depth) == OSI_L5_SYSCALL_MEM and int(ev.tid) == 10425:
-            worker_bio_ns += int(ev.duration_ns)
-
     for ev in trace_events:
         ltype = int(ev.layer_type)
         tid = int(ev.tid)
@@ -767,8 +761,25 @@ def correlate_and_symbolicate_sim_events(
                 base_offset=base_load_offset,
             )
             total_dur_ns = int(ev.duration_ns)
-            off_cpu_ns = worker_bio_ns if resolved["symbol"] == "execute_storage_query" else 0
+            t_return = int(ev.timestamp_ns)
+            t_entry = t_return - total_dur_ns
+            sched_off_cpu_ns = 0
+            bio_off_cpu_ns = 0
+            for child_ev in trace_events:
+                if int(child_ev.tid) != tid or int(child_ev.layer_type) != LAYER_USER_ENTRY:
+                    continue
+                c_ts = int(child_ev.timestamp_ns)
+                if t_entry <= c_ts <= t_return:
+                    if int(child_ev.call_depth) == OSI_L6_PRE_COMPUTE:
+                        sched_off_cpu_ns += int(child_ev.duration_ns)
+                    elif int(child_ev.call_depth) == OSI_L5_SYSCALL_MEM:
+                        bio_off_cpu_ns += int(child_ev.duration_ns)
+            off_cpu_ns = max(sched_off_cpu_ns, bio_off_cpu_ns)
             on_cpu_ns = max(0, total_dur_ns - off_cpu_ns)
```
And in [`run_tracer_pipeline` (`tracer_agent.py:1358-1363`)](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1358-L1363), derive `sched_runq_ms` and `sched_lock_ms` from the pre-compute (`call_depth == OSI_L6_PRE_COMPUTE`) handoff event in `c_harness_result["events"]` when available, falling back to `0.065` / `0.115` only when no handoff event is present.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_12_PRECOMPUTE_GATE_VERIFIER.md`

# Adversarial Falsification Report — Domain 12/20: L6 Pre-Compute Gate & Worker Thread Pool Attribution (`L6_PRE_COMPUTE_GATE`, Acceptor-to-Worker Causality, Multi-Worker Isolation)

### Executive Summary of Falsified Claims & Architectural Blind Spots

Cross-examination of [`PROMPT_SPEC.md`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md), [`tracer_kernel.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c), [`kernel_sim_harness.c`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kernel_sim_harness.c), [`tracer_agent.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py), and [`test_verification_suite.py`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py) against the core project philosophy falsified critical assumptions regarding the `L6_PRE_COMPUTE_GATE`:

* **Falsification 1 — Single-Threaded Event Loop Pre-Compute Gate Missing**:
  * In single-threaded servers (e.g. Node.js, Redis, or non-threaded Python/C++ event loops), there is NO Futex handoff between acceptor and worker threads (`acceptor_tid == worker_tid`).
  * If `L6_PRE_COMPUTE_GATE` (`OSI_L6_PRE_COMPUTE = 8`) is ONLY emitted upon Futex wake or scheduler context switch between distinct threads, single-threaded architectures would show a missing L6 gate in `seven_layer_matrix`.
  * `tracer_kernel.c` and `tracer_agent.py` must ensure that for single-threaded executions, the transition from kernel socket read (`sys_exit_recvmsg` / `skb_copy_datagram_iter`) to userspace execution entry (`uprobe` depth 0) synthesizes or emits `L6_PRE_COMPUTE_GATE` so that `pre_compute_latency_ns` is always accounted for.
* **Falsification 2 — Worker Thread Pool Attribution Inversion**:
  * In multi-threaded thread pools (such as the target server `mock_server.cpp`), the acceptor thread places work into a bounded queue and signals worker threads via `pthread_cond_signal` or `pthread_mutex_unlock` (`sys_futex(FUTEX_WAKE)`).
  * If multiple workers compete for the queue:
    * Worker A (TID 10425) wakes up, claims Request 1.
    * Worker B (TID 10426) wakes up, claims Request 2.
  * If `pending_handoff_map` uses a single global slot per process rather than an 8-slot ringbuffer indexed by modulo head/tail or monotonic sequence, Worker B can overwrite Request 1 before Worker A reads it, leading to request cross-talk and inverted latency attribution.
* **Falsification 3 — Pre-Compute Latency vs Inclusive Compute Boundary**:
  * By formal specification definition, `pre_compute_latency_ns` measures the wall-clock time from the initial wire packet arrival (`STAGE_L2_INGRESS`) to the instant the worker thread enters its first application-level compute function (`STAGE_L7_USERSPACE_COMPUTE`).
  * If userspace runtime initialization overhead (e.g., dynamic linker relocations, memory allocator initialization) is included inside compute time rather than pre-compute overhead, CPU bottleneck diagnosis in `ai_diagnosis.json` produces false leaf attribution.

### Root Cause Analysis & Line Citations

* [`tracer_kernel.c:1340-1420`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1340-L1420):
  * `publish_handoff_slot` records `req_id`, `now`, `waker_tid`, and network 4-tuple in `pending_handoff_map` using an 8-slot ringbuffer.
  * `sys_exit_futex` claims the oldest unconsumed slot for the waking worker thread.
  * If `ret == -EAGAIN` (-11), the worker thread retried without sleeping, which must still claim handoff if available.
* [`tracer_agent.py:1020-1080`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L1020-L1080):
  * `_finalize_request` builds `seven_layer_matrix`:
  * If no explicit futex event occurred because `acceptor_tid == worker_tid`, `L6_PRE_COMPUTE_GATE` is synthesized between `L5_SYSCALL_MEMCPY` and `L7_APP_ALU` with duration computed from `first_uprobe_ts - last_l5_ts`.
* [`test_verification_suite.py:380-420`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L380-L420):
  * `test_04_worker_thread_pool_handoff` verifies handoff from Acceptor thread (TID 10420) to Worker thread (TID 10425) with exact req_id continuity and runqlat latency attribution.

### Verification & Remediation Invariants

1. Pre-Compute Gate Invariant: Every completed request MUST contain an `L6_PRE_COMPUTE_GATE` entry in `seven_layer_matrix`, regardless of whether the execution model is single-threaded or multi-threaded.
2. Thread Isolation Invariant: In concurrent multi-worker environments, no worker thread may claim another worker's assigned `req_id` or corrupt the 8-slot handoff ringbuffer.
3. Strict Pre-Compute Metric Invariant: `pre_compute_latency_ns = first_app_uprobe_ts - wire_ingress_ts`. It MUST equal the exact sum of L2, L3, L4, L4.5, L5, and L6 durations.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_13_UPROBE_SHADOW_STACK_VERIFIER.md`

# Agent 13 Adversarial Falsification Report — Domain 13/20: L7 Uprobe/Uretprobe Shadow Call Stack (`trace_uprobe_entry`, `trace_uprobe_return`, Deep Recursion `> 16`, Unbalanced Stack Resilience)

### 1. Executive Summary of Falsifications

* **Flaw 13-1 [CRITICAL] — `trace_uprobe_return` Slot Wrap-Around IP Aliasing (`orig_ip = tctx->fn_entry_ip[raw_depth & 15]`) and Missing Userspace LIFO Shadow Stack Backfill at Deep Recursion (`raw_depth >= 16`)**:
  * In [`tracer_kernel.c:1494-1508`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1494-L1508), `fn_dur` was guarded by `(raw_depth < MAX_CALL_DEPTH) ? (now - saved_ts) : 0`, **but `orig_ip = tctx->fn_entry_ip[slot]` was NOT guarded by `(raw_depth < MAX_CALL_DEPTH)`**! Returning from depths `19..16` wrapped `slot = raw_depth & 15` to `3..0` and emitted false-alias instruction pointers stolen from outer frames `3..0`.
  * Guarding `orig_ip = (raw_depth < MAX_CALL_DEPTH) ? tctx->fn_entry_ip[slot] : 0`, preserving full `u8 report_depth = raw_depth`, and maintaining a per-`(req_id, tid)` LIFO shadow call stack of `is_return == 0` events in `RequestCorrelator._finalize_request` restores the exact `ev.ip` and `ev.duration_ns` for all recursive return frames at depth `>= 16`.
* **Flaw 13-2 — Spec Alignment in `PROMPT_SPEC.md`**:
  * Updated `PROMPT_SPEC.md` so the L7 shadow stack specification matches the non-wrapping `raw_depth < MAX_CALL_DEPTH` guard and LIFO userspace backfill.
* **Flaw 13-3 — Strengthened `ADV-TEST-07` Deep Recursion Assertions**:
  * Verified every single return frame across depths `19..0` (not just `depth 0`).


---

## Archive Document: `archive/subagent_verifications_20/AGENT_14_ELF_DWARF_ASLR_VERIFIER.md`

# Agent 14 Adversarial Falsification Report — Domain 14/20: ELF/DWARF Symbolicator, PIE/ASLR VMA Math & Stripped Binary Disassembly (`BinarySymbolicator`, `aarch64` 64KB Pages, C++ Demangling)

### 1. Executive Summary of Falsifications

* **Flaw 14-1 — Missing `ProcessMemoryMap` & ELF `PT_LOAD` Virtual Address Bias (`p_vaddr - p_offset`) Across `ET_EXEC`, `ET_DYN`, and `aarch64` 64KB Pages**:
  * Added `ProcessMemoryMap` (`from_proc_maps`, `set_module_vaddr_bias`, `translate_ip`) and `_read_exec_pt_load_bias()` to `BinarySymbolicator` so runtime IPs translate into both physical `file_offset` (`runtime_ip - vm_start + vma_file_offset`) and ELF virtual address `elf_vaddr` (`file_offset + p_vaddr - p_offset`).
* **Flaw 14-2 — C++ Itanium ABI (`_Z...` / `__Z...`) Demangling & `should_attach_uprobe_symbol` Filtering**:
  * Added `demangle_cpp_symbol()` (using `c++filt`/`llvm-cxxfilt` with a deterministic pure-Python Itanium ABI fallback) and `strip_cpp_signature()`, and expanded `EXCLUDED_SYMBOL_PREFIXES` / `DEMANGLED_EXCLUDED_PREFIXES` to filter thunks (`_ZThn*`, `_ZTv*`), RTTI/vtables (`_ZTI*`, `_ZTS*`, `_ZTV*`), `__gnu_cxx`, operators, and macOS `__ZSt*` symbols.
* **Flaw 14-3 — `_discover_stripped_internal_offset` PLT Header & Compiler Instrumentation Filtering**:
  * Anchored `verify_request_token` header matching to `^\s*([0-9a-fA-F]+)\s+<_?verify_request_token>:\s*$` (excluding `@plt`/`$stub`), filtered compiler instrumentation (`__stack_chk_fail`, `__asan_*`, `_Unwind_*`, `memcpy`, `strlen`), and converted the discovered VMA target using `lib_vaddr_bias`.
* **Flaw 14-4 — `extract_stripped_disassembly` & `extract_cpp_source_evidence` Accuracy**:
  * Stopped disassembly capture at the next symbol boundary, capped at 15 lines, and demangled/stripped C++ parameter lists before locating function definitions in `mock_server.cpp`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_15_ABI_CORRELATOR_STATE_VERIFIER.md`

# Agent 15 Adversarial Falsification Report — Domain 15/20: 64-Byte `kray_event_t` ABI, Ringbuf Overflow Accounting & Out-of-Order `RequestCorrelator` State Machine

### 1. Executive Summary of Falsifications

* **Defect 15-1 — `kray_runtime_cfg_t.filter_flags` Dead ABI & `capture_enabled` / `target_pid` Bypass Bugs**:
  * In [`tracer_kernel.c:268-284`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L268-L284), `get_target_pid()` previously checked `if (cfg && cfg->target_pid != 0)` instead of `if (cfg && cfg->config_epoch > 0)`, preventing hot-reloading `target_pid = 0` when `__TARGET_PID__` was non-zero at compile time.
  * When `cfg->capture_enabled == 0 && cfg->config_epoch > 0`, `emit_kray_event()` itself should guard on `capture_enabled` so portless hooks (`icmp_rcv`, `arp_rcv`, `unix_stream_recvmsg`) also respect `capture_enabled == 0`.
* **Defect 15-2 — Unreset `tctx->copied_bytes` and `tctx->page_faults` in `kretprobe__skb_copy_datagram_iter` & 16-Bit `u16 copied_bytes` Truncation**:
  * In [`struct tid_ctx_t`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L197-L198), `page_faults` and `copied_bytes` were `u16` (truncating reads >= 64KB) and were not reset to `0` after `kretprobe__skb_copy_datagram_iter` emitted `OSI_L5_SYSCALL_MEM`. Upgrading both to `u32` and resetting them to `0` upon emission prevents cross-read accumulation.
* **Defect 15-3 — `run_tracer_pipeline` & `run_c_harness_wire_to_code_pipeline` Ignored `ev->drop_count` and `drop_cnt_map[0]`**:
  * [`compute_final_drop_count`](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L188-L199) existed in `tracer_agent.py` but was not called in `run_tracer_pipeline`, which previously hardcoded `final_drop_count = int(simulate_drops)`. Wiring `correlator.max_event_drop_count` and `lib.sim_get_drop_count()` into `compute_final_drop_count()` ensures real C ringbuf drops propagate end-to-end into `ai_diagnosis.json`.
* **Defect 15-4 — Saturating 32-Bit `ev->drop_count` Cast in `emit_kray_event`**:
  * Caps `*cnt` at `0xFFFFFFFFU` before assigning `ev->drop_count` so $2^{32}$ ringbuf drops never wrap around to `0`.
* **Defect 15-5 & 15-6 — Late Out-of-Order Events Arriving After `L2_EGRESS` Finalization & `max_inflight` LRU Bound**:
  * When `req_id` is already in `self._completed` and a delayed event (`L4_EGRESS` or `L7_FUNC_EXIT`) arrives on another CPU, `ingest()` now immediately merges and re-finalizes `self._completed[req_id]`.
  * Added `max_inflight = 4096` LRU eviction on `self._buffers` and updated `_first_seen_ts[req_id]` with `min()` across out-of-order timestamps.
* **Defect 15-7 — Canonical Sub-Layer Sort Order**:
  * Within `LAYER_KERNEL_NET` (`2`) and `LAYER_USER_ENTRY` (`3`), OSI sub-layers ascend (`L3=3 -> L4=4 -> L4.5=5 -> L5=6 -> L6=8`), whereas within `LAYER_USER_EXIT` (`5`) and `LAYER_EGRESS_NIC` (`6`), OSI sub-layers descend (`L4=4 -> L3=3 -> L2=2`). Using `_canonical_sort_key` prevents egress/ingress sub-layer inversions when timestamps tie across CPUs.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_16_C_SIMULATOR_FIDELITY_VERIFIER.md`

# Agent 16 Adversarial Falsification Report — Domain 16/20: Userspace C Simulation Harness Fidelity (`mock_bpf_runtime.h`, `kernel_sim_harness.c`, Per-CPU Maps, True LRU, Poison Memory)

### 1. Executive Summary of Falsifications

* **Flaw 16.1 — Missing Emulated BPF Helpers & Low-Pointer Fault Protection in `mock_bpf_runtime.h`**:
  * Added `bpf_probe_read`, `bpf_probe_read_user`, `bpf_get_current_comm`, `bpf_get_prandom_u32`, `bpf_ringbuf_reserve`, `bpf_ringbuf_submit`, and `bpf_ringbuf_discard`.
  * Updated `bpf_probe_read_kernel` to return `KRAY_ERR_EFAULT (-14)` and zero-fill `dst` on NULL or near-NULL (`(uintptr_t)unsafe_ptr < 4096ULL`) pointers.
* **Flaw 16.2 — Array Map Out-of-Bounds Error Code (`-E2BIG`), `.delete` Operation, and `0xDD` Delete Poisoning**:
  * Fixed `BPF_ARRAY` and `BPF_PERCPU_ARRAY` out-of-bounds updates to return `KRAY_ERR_E2BIG (-7)` (matching Linux `array_map_update_elem`), added `.delete` returning `KRAY_ERR_EINVAL (-22)`, guarded self-overlapping `memmove`, and poisoned deleted hash/LRU entries with `0xDD`.
* **Flaw 16.3 — Configurable RingBuf Capacity (`sim_set_ringbuf_capacity`) & Drop-Budget (`sim_set_ringbuf_drop_limit`)**:
  * Added `g_sim_ringbuf_cap`, `g_sim_ringbuf_drop_budget`, and reservation tracking so C tests can trigger ringbuf exhaustion and verify `ev->drop_count` recovery in `emit_kray_event`.
* **Flaw 16.4 — Blocking `tcp_recvmsg` Lazy Iter Binding & UDP L3/L2 Egress Simulation**:
  * Extended `sim_tcp_recvmsg_call` (`delayed_packet_arrival == 2`) to exercise lazy `req_id` binding inside `kretprobe__skb_copy_datagram_iter`, updated `kprobe__ip_output` to support `IPPROTO_UDP` egress fallback, and added `sim_udp_egress_pipeline`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_17_LIVE_KERNEL_BPF_VERIFIER.md`

### Agent 17 Adversarial Falsification Report (Domain 17/20: Live Kernel BPF Verifier & Rocky Linux 9.8 BTF CO-RE — `vmlinux.h`, `bpftool prog loadall`, 42 Programs, 512B Stack Limit, Live Attach)

#### Executive Summary & Environment Note
* **Target Kernel & Reference Tree**: Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`), verified against the extracted kernel source tree and BTF headers in [vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h), [bpf_tracing.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_tracing.h), [bpf_helpers.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_helpers.h), and `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/`.
* **SSH Execution Boundary Note**: Direct `ssh ebpf-tracer-v2.0.0` invocation was blocked by the execution harness permission gate (`Permission prompt for action 'command' on target 'ssh ebpf-tracer-v2.0.0 ...' was denied`). Per safety guidelines, no circumvention was attempted; instead, exhaustive static/BTF/verifier/kernel-source cross-falsification was performed against the exact `5.14.0-687.10.1.el9_8.0.1.aarch64` kernel tree, BTF dump, and `test_verification_suite.py` / `tracer_kernel.c` / `kray_bpf_core_compat.h` / `tracer_agent.py`.
* **Total Falsifications Found**: 7 critical/high-severity flaws across standalone `-target bpf` compilation, `bpftool prog loadall ... autoattach`, `lo` XDP generic vs native attachment, unimplemented `--mode live` in `tracer_agent.py`, BCC-style multi-arg kprobe/function-pointer CO-RE shims, stack frame hot spots, and missing/inlined kernel hooks.

---

### FALSIFIED-17-01: Standalone `clang -target bpf` Compilation Fails Without `-DKRAY_BPF_CORE` and Explicit BTF Header Search Path
* **Target Files & Lines**:
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L20-L46)
  * [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2218-L2231)
* **Evidence & Falsification**:
  * Running the standard BPF CO-RE compilation command:
    `clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I/home/rocky/ebpf-wire-to-code-tracer-v2.0.0 -c /home/rocky/ebpf-wire-to-code-tracer-v2.0.0/tracer_kernel.c -o /tmp/agent20_17/tracer_kernel.bpf.o`
    immediately fails with fatal preprocessor errors (`'uapi/linux/ptrace.h' file not found` / `'vmlinux.h' file not found`) for two independent reasons:
  * **Defect 1 (Missing Auto-Detection of `__bpf__`)**: In [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L20), the CO-RE header block is guarded solely by `#ifdef KRAY_BPF_CORE`. When `clang -target bpf` is invoked without `-DKRAY_BPF_CORE`, `__bpf__` is predefined by Clang, but `KRAY_BPF_CORE` is not. Execution falls through to the `#elif !defined(KRAY_USER_SIM)` BCC branch at lines 28–45 (`#include <uapi/linux/ptrace.h>`, `#include <bcc/proto.h>`), which fails under standalone `clang -target bpf`.
  * **Defect 2 (`vmlinux.h` and `bpf/*.h` Path Resolution)**: In [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L21-L25), `#include "vmlinux.h"` and `#include <bpf/bpf_helpers.h>` assume `-Ireferences/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers` was passed on the command line. Neither `vmlinux.h` nor `bpf/bpf_helpers.h` exists in the repository root `/home/rocky/ebpf-wire-to-code-tracer-v2.0.0`, and on Rocky Linux 9.8 without `libbpf-devel` installed system-wide in `/usr/include/bpf`, compiling with only `-I/home/rocky/ebpf-wire-to-code-tracer-v2.0.0` fails unless `__has_include` fallbacks into `references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/` are provided.
* **Recommended Fix (Unified Diff)**:
```diff
--- a/tracer_kernel.c
+++ b/tracer_kernel.c
@@ -17,12 +17,29 @@
  * ============================================================================
  */
 
-#ifdef KRAY_BPF_CORE
-#include "vmlinux.h"
-#include <bpf/bpf_helpers.h>
-#include <bpf/bpf_tracing.h>
-#include <bpf/bpf_core_read.h>
-#include <bpf/bpf_endian.h>
+#if defined(KRAY_BPF_CORE) || (defined(__bpf__) && !defined(__BCC__) && !defined(KRAY_USER_SIM))
+#ifndef KRAY_BPF_CORE
+#define KRAY_BPF_CORE 1
+#endif
+#if __has_include("vmlinux.h")
+#include "vmlinux.h"
+#elif __has_include("references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h")
+#include "references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h"
+#endif
+#if __has_include(<bpf/bpf_helpers.h>)
+#include <bpf/bpf_helpers.h>
+#include <bpf/bpf_tracing.h>
+#include <bpf/bpf_core_read.h>
+#include <bpf/bpf_endian.h>
+#elif __has_include("references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_helpers.h")
+#include "references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_helpers.h"
+#include "references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_tracing.h"
+#include "references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_core_read.h"
+#include "references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/bpf/bpf_endian.h"
+#endif
 #include "kray_bpf_core_compat.h"
 #elif !defined(KRAY_USER_SIM)
```

---

### FALSIFIED-17-02: `bpftool prog loadall ... autoattach` Fails on Unqualified `SEC("uprobe")`, `SEC("uretprobe")`, and `SEC("xdp")` Sections, and `lo` Rejects Native XDP (`xdpdrv`)
* **Target Files & Lines**:
  * [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L91-L99)
  * [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2232-L2263)
* **Evidence & Falsification**:
  * **Defect 1 (`SEC("uprobe")` and `SEC("uretprobe")` Auto-Attach Rejection)**:
    In [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L98-L99):
    * `#define trace_uprobe_entry SEC("uprobe") int trace_uprobe_entry`
    * `#define trace_uprobe_return SEC("uretprobe") int trace_uprobe_return`
    While `bpftool prog loadall tracer_kernel.bpf.o /sys/fs/bpf/agent20_17_pin` (without `autoattach`) succeeds because `BPF_PROG_LOAD` only verifies the bytecode (`BPF_PROG_TYPE_KPROBE`), passing `autoattach` invokes `bpf_program__attach()` on every program in the ELF object. In `libbpf` on Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`), `attach_uprobe()` requires the ELF section name to specify `SEC("uprobe/<binary_path>:<func_or_offset>")` (e.g., `SEC("uprobe//usr/lib64/libc.so.6:malloc")`). Bare `SEC("uprobe")` and `SEC("uretprobe")` cause `bpf_program__attach()` to fail with `-EINVAL` (`prog 'trace_uprobe_entry': section 'uprobe' is missing binary path`) or `-EOPNOTSUPP`.
  * **Defect 2 (`SEC("xdp")` Cannot Auto-Attach Without `ifindex`, and `lo` Requires `xdpgeneric`)**:
    In [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L91), `xdp_ingress_filter` has `SEC("xdp")`. `libbpf` does not define an auto-attach handler for `SEC("xdp")` because no network interface index (`ifindex`) is encoded in the section definition. Furthermore, when attaching `xdp_ingress_filter` to the loopback interface (`lo`) via `bpftool net attach`, Rocky Linux 9.8's loopback driver (`drivers/net/loopback.c`) does not implement `.ndo_bpf` (`XDP_FLAGS_DRV_MODE` / `xdpdrv` returns `-EOPNOTSUPP`). Attachment to `lo` **must** explicitly use generic SKB mode:
    `sudo bpftool net attach xdpgeneric pinned /sys/fs/bpf/agent20_17_pin/xdp_ingress_filter dev lo`
    (and detach via `sudo bpftool net detach xdpgeneric dev lo`).
* **Recommended Fix (Unified Diff)**:
```diff
--- a/kray_bpf_core_compat.h
+++ b/kray_bpf_core_compat.h
@@ -95,8 +95,8 @@
 #define kretprobe__tcp_sendmsg SEC("kretprobe/tcp_sendmsg") int kretprobe__tcp_sendmsg
 #define kprobe__tcp_recvmsg SEC("kprobe/tcp_recvmsg") int kprobe__tcp_recvmsg
 #define kretprobe__tcp_recvmsg SEC("kretprobe/tcp_recvmsg") int kretprobe__tcp_recvmsg
-#define trace_uprobe_entry SEC("uprobe") int trace_uprobe_entry
-#define trace_uprobe_return SEC("uretprobe") int trace_uprobe_return
+#define trace_uprobe_entry SEC("uprobe//usr/lib64/libc.so.6:malloc") int trace_uprobe_entry
+#define trace_uprobe_return SEC("uretprobe//usr/lib64/libc.so.6:malloc") int trace_uprobe_return
 #define kprobe__tcp_v4_connect SEC("kprobe/tcp_v4_connect") int kprobe__tcp_v4_connect
 #define kretprobe__tcp_v4_connect SEC("kretprobe/tcp_v4_connect") int kretprobe__tcp_v4_connect
```

---

### FALSIFIED-17-03: `ADV-TEST-12` Performs Verifier Load Only (`bpftool prog loadall`) and Never Tests Kernel Attachment (`autoattach` / Tracepoints / Kprobes / Uprobes / `xdpgeneric` on `lo`)
* **Target Files & Lines**:
  * [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2204-L2263)
* **Evidence & Falsification**:
  * In [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L2232-L2252), `test_adv_12_target_kernel_live_verifier_and_loopback_readiness` runs:
    `bpftool prog loadall <obj_path> /sys/fs/bpf/kray_verify_<pid>`
    checks `len(pinned) == 42`, and immediately runs `rm -rf /sys/fs/bpf/kray_verify_<pid>` in `finally:`.
  * **Why This Is a False Positive (Blind Spot)**:
    In Linux 5.14 (`kernel/bpf/syscall.c`), `BPF_PROG_LOAD` for `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACEPOINT`, and `BPF_PROG_TYPE_XDP` only validates BPF instructions in the Verifier. It does **not**:
    * Look up the kprobe symbol in `/proc/kallsyms` or register a `kprobe` via `perf_event_open()`.
    * Open `/sys/kernel/tracing/events/<category>/<name>/id` to attach tracepoints.
    * Resolve uprobe ELF binary offsets.
    * Attach `xdp_ingress_filter` to `lo` (`xdpgeneric`).
  * Consequently, if a function in `SEC("kprobe/foo")` is completely inlined or absent from `/proc/kallsyms`, or if a tracepoint name is misspelled, `bpftool prog loadall` without `autoattach` still returns exit code `0` and pins all 42 programs!
* **Recommended Fix (Unified Diff)**:
```diff
--- a/test_verification_suite.py
+++ b/test_verification_suite.py
@@ -2238,6 +2238,14 @@ class AdversarialSpecVerificationSuite(unittest.TestCase):
                     os.chmod(pin_dir, 0o755)
                     pinned = os.listdir(pin_dir)
                     self.assertEqual(len(pinned), 42, f"Expected 42 pinned BPF programs in {pin_dir}, found {len(pinned)}: {pinned}")
+
+                    # Verify actual XDP generic attach/detach on loopback ('lo')
+                    xdp_pin = os.path.join(pin_dir, "xdp_ingress_filter")
+                    attach_res = subprocess.run(
+                        ["bpftool", "net", "attach", "xdpgeneric", "pinned", xdp_pin, "dev", "lo"],
+                        capture_output=True, text=True
+                    )
+                    self.assertEqual(attach_res.returncode, 0, f"xdpgeneric attach on lo failed: {attach_res.stderr}")
                 finally:
+                    subprocess.run(["bpftool", "net", "detach", "xdpgeneric", "dev", "lo"], capture_output=True)
                     shutil.rmtree(pin_dir, ignore_errors=True)
```

---

### FALSIFIED-17-04: `--mode live` in `tracer_agent.py` Is a Dead CLI Flag That Silently Runs User-Space Simulation Instead of Live eBPF Attachment
* **Target Files & Lines**:
  * [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L2234-L2274)
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L452)
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L743-L747)
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L945)
* **Evidence & Falsification**:
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L743-L747) states that `tracer_agent.py` supports `--mode live` (converting `TRACEPOINT_PROBE` / `BPF_RINGBUF_OUTPUT`, parsing `/proc/kallsyms` at runtime via a Symbol Auto-Resolver, falling back to `XDP_FLAGS_SKB_MODE` on `lo`, and dynamically attaching uprobes/uretprobes).
  * Inspecting [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L2234-L2274) reveals that `--mode` (`choices=["live", "simulate"]`, default `"simulate"`) is parsed into `args.mode` at line 2234, **and is never read anywhere in the entire file**.
  * Whether the user runs `python3 tracer_agent.py --mode live` or `--mode simulate`, `main()` unconditionally calls `run_tracer_pipeline(...)` without `args.mode`, which executes `KernelSimBridge` (`libtracer_kernel_sim.so` user-space C simulation) and never loads or attaches any BPF program into the kernel.
* **Recommended Fix**:
  * Pass `mode=args.mode` into `run_tracer_pipeline()` in [tracer_agent.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_agent.py#L2260-L2274) and implement a live BPF loader backend (or explicitly raise a clear error if `--mode live` is requested when live BPF attachment is not active, rather than silently spoofing live kernel execution with `KernelSimBridge`).

---

### FALSIFIED-17-05: BCC-Style Multi-Argument Kprobe Signatures & Function-Pointer Map Shims in `kray_bpf_core_compat.h` Risk Verifier Rejection and Emit Misleading BTF Prototypes
* **Target Files & Lines**:
  * [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L39-L114)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L627-L683)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1632-L1638)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1790-L1796)
  * [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1463-L1474)
  * [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1516-L1529)
* **Evidence & Falsification**:
  * **Defect 1 (False-Positive Host Cross-Compile in `ADV-TEST-02` & `ADV-TEST-03`)**:
    [test_verification_suite.py](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/test_verification_suite.py#L1463-L1474) and lines 1516–1529 compile `tracer_kernel.c` with `clang -target aarch64-linux-gnu -Wno-unknown-attributes` instead of `-target bpf -D__TARGET_ARCH_arm64`. That only produces ARM64 ELF machine code (`EM_AARCH64`), completely bypassing Clang's BPF backend (`EM_BPF`), `.BTF` / `.BTF.ext` CO-RE relocation emission, and the 512B BPF stack limit.
  * **Defect 2 (Function-Pointer Struct Shim in `kray_bpf_core_compat.h`)**:
    In [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L39-L86), `KRAY_DEFINE_MAP_OPS` and `BPF_RINGBUF_OUTPUT` instantiate `static const struct __kray_map_ops_##name` containing function pointers (`lookup`, `update`, `delete`, `ringbuf_reserve`, `ringbuf_submit`, `ringbuf_discard`). In the Linux 5.14 BPF Verifier (`kernel/bpf/verifier.c`), indirect function pointer calls (`BPF_JMP | BPF_CALL | BPF_X` / `callx`) are rejected (`indirect call is not supported in bpf`). This only survives at `-O2` because Clang constant-folds the `static const` struct member access; at `-O0` or if address propagation is inhibited, the verifier rejects the program. Marking the helper functions `__attribute__((always_inline))` is necessary to guarantee inlining across optimization levels.
  * **Defect 3 (Extra Uninitialized Parameters `R2..R4` in Kprobe C Signatures)**:
    In BPF kprobe programs (`SEC("kprobe/...")`), the kernel only populates `R1 = struct pt_regs *ctx` on entry; registers `R2` through `R5` have state `NOT_INIT` in the BPF Verifier. However, 16 kprobes in [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c) declare extra C parameters `(struct pt_regs *ctx, struct sk_buff *skb, ...)`. While 14 of them overwrite the parameter via `#ifdef KRAY_BPF_CORE skb = (struct sk_buff *)PT_REGS_PARM1(ctx); #endif`, two functions—`kprobe__ip_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1632)) and `kprobe__ip6_output(struct pt_regs *ctx, struct net *net, struct sock *sk, struct sk_buff *skb)` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1790))—leave `net`, `sk`, and `skb` as dead uninitialized parameters (`R2`, `R3`, `R4`) in the C signature while reading `PT_REGS_PARM2(ctx)` and `PT_REGS_PARM3(ctx)` into local variables `real_sk` and `real_skb`. This emits 4-argument `BTF_KIND_FUNC_PROTO` records into `.BTF` for single-argument `BPF_PROG_TYPE_KPROBE` entry points.
* **Recommended Fix (Unified Diff)**:
```diff
--- a/kray_bpf_core_compat.h
+++ b/kray_bpf_core_compat.h
@@ -39,19 +39,19 @@
 };
 
 #define KRAY_DEFINE_MAP_OPS(name, key_type, val_type) \
-static __inline val_type *__kray_lookup_##name(const key_type *k) { \
+static __always_inline val_type *__kray_lookup_##name(const key_type *k) { \
     return (val_type *)bpf_map_lookup_elem(&name##_def, k); \
 } \
-static __inline int __kray_update_##name(const key_type *k, const val_type *v) { \
+static __always_inline int __kray_update_##name(const key_type *k, const val_type *v) { \
     return (int)bpf_map_update_elem(&name##_def, k, v, BPF_ANY); \
 } \
-static __inline int __kray_delete_##name(const key_type *k) { \
+static __always_inline int __kray_delete_##name(const key_type *k) { \
     return (int)bpf_map_delete_elem(&name##_def, k); \
 } \
```

---

### FALSIFIED-17-06: Per-Program Stack Frame Audit Across All 42 BPF Programs (`<= 512B` Limit)
* **Target Files & Lines**:
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L261-L396) (`struct flow_key_t`, `struct flow_state_t`, `struct tid_ctx_t`, `struct handoff_ring_t`)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1824-L1890) (`kprobe__tcp_v6_rcv`)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1722-L1788) (`kprobe__ipv6_rcv`)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L685-L756) (`kprobe__tcp_v4_rcv`)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1892-L1947) (`kprobe__udp_rcv`)
* **Evidence & Stack Usage Breakdown**:
  * **Why 512B Is Not Exceeded**:
    * `struct tid_ctx_t` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L322-L356)) is **464 bytes** (`10 * 8B + 5 * 4B + 4 * 2B + 6 * 1B + 2B pad + 44 * 8B = 468B/472B`), which would overflow the 512-byte BPF stack if allocated locally alongside `struct flow_key_t`. [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L387) avoids stack allocation by using `BPF_PERCPU_ARRAY(zero_ctx_map, struct tid_ctx_t, 1)` (`get_zero_tid_ctx()`).
    * `struct trace_event_t` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L186-L246)) is **520 bytes** (exceeding the entire 512B BPF stack on its own), and is allocated exclusively in the BPF ring buffer via `events.ringbuf_reserve(sizeof(struct trace_event_t))`.
    * `struct handoff_ring_t` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L371-L374)) is **264 bytes** (`8B + 8 * 32B`), accessed in-place via `handoff_S_to_A.lookup(&fd_key)` and initialized via `BPF_PERCPU_ARRAY(zero_handoff_map, struct handoff_ring_t, 1)`.
  * **Top Stack Frame Consumers Among the 42 BPF Programs (with `emit_event` inlined)**:
    * `kprobe__tcp_v6_rcv` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1824-L1890)): `unsigned char *head = 0` (8B) + `u16 net_off = 0, trans_off = 0` (4B) + `struct ipv6hdr ip6` (40B) + `struct tcphdr tcph` (20B) + `struct flow_key_t key` (16B) + `struct flow_state_t init_state` (72B) + callee-saved register spills (`r6..r9`) ≈ **184–208 bytes** (`<= 512B`).
    * `kprobe__ipv6_rcv` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1722-L1788)): `head` (8B) + `net_off` (2B) + `struct ipv6hdr ip6` (40B) + `ext_hdr`/`frag_hdr` (12B) + `ports` (4B) + `struct flow_key_t key` (16B) + `struct flow_state_t init_state` (72B) + spills ≈ **176–200 bytes** (`<= 512B`).
    * `kprobe__tcp_v4_rcv` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L685-L756)): `head` (8B) + `net_off`/`trans_off` (4B) + `struct iphdr iph` (20B) + `struct tcphdr tcph` (20B) + `struct flow_key_t key` (16B) + `struct flow_state_t init_state` (72B) + spills ≈ **160–184 bytes** (`<= 512B`).
    * `kprobe__udp_rcv` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1892-L1947)): `head` (8B) + `net_off`/`trans_off` (4B) + `struct iphdr iph` (20B) + `struct udphdr udph` (8B) + `struct flow_key_t key, rev_key` (32B) + `struct flow_state_t init_state` (72B) + spills ≈ **160–184 bytes** (`<= 512B`).
    * `tracepoint__net__netif_receive_skb` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L530-L622)): `data` (8B) + `struct iphdr iph` (20B) + `struct tcphdr tcph` (20B) + `struct flow_key_t key` (16B) + `struct flow_state_t init_state` (72B) + spills ≈ **152–176 bytes** (`<= 512B`).
    * `xdp_ingress_filter` ([tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L429-L528)): `struct flow_key_t key` (16B) + `struct flow_state_t init_state` (72B) + spills ≈ **104–128 bytes** (`<= 512B`).
    * All remaining 36 tracepoint/kprobe/kretprobe/uprobe programs consume between **16 bytes and 144 bytes** of stack.

---

### FALSIFIED-17-07: Rocky Linux 9.8 (`5.14.0-687.10.1.el9_8.0.1.aarch64`) Kernel Source & BTF Cross-Check — Inlined `tcp_transmit_skb`, Syscall Tracepoint Flexible-Array Indexing, and Missing UDP/UNIX Cleanup Kretprobes
* **Target Files & Lines**:
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L128-L150)
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L741-L746)
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L893)
  * [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L931)
  * [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L15-L21)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L1949-L2000) (`kprobe__udp_sendmsg`)
  * [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c#L2044-L2077) (`kprobe__unix_stream_sendmsg`)
  * [tcp_output.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238-L1425)
  * [vmlinux.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119889-L119902)
* **Evidence & Falsification**:
  * **Finding 7A (`tcp_transmit_skb` Is Inlined in `5.14.0-687.10.1.el9_8.0.1.aarch64`; Only `__tcp_transmit_skb` Exists in `kallsyms`)**:
    In [tcp_output.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1420-L1425), `static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask)` is a 1-line static wrapper around `static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt)` (line 1238). GCC inlines `tcp_transmit_skb` into all callers on Rocky Linux 9.8, leaving only `__tcp_transmit_skb` in `/proc/kallsyms`. While `tracer_kernel.c:1594` uses `kprobe____tcp_transmit_skb` (`SEC("kprobe/__tcp_transmit_skb")`), all 16 kprobe target symbols in `tracer_kernel.c` were verified against the Rocky Linux 9.8 kernel source tree:
    * `ip_rcv` ([ip_input.c:563](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_input.c#L563)) — non-inline global symbol.
    * `tcp_v4_rcv` ([tcp_ipv4.c:1954](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L1954)) — non-inline global symbol.
    * `tcp_sendmsg` ([tcp.c:1487](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L1487)) — `EXPORT_SYMBOL(tcp_sendmsg)`.
    * `tcp_recvmsg` ([tcp.c:2505](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp.c#L2505)) — `EXPORT_SYMBOL(tcp_recvmsg)`.
    * `tcp_v4_connect` ([tcp_ipv4.c:207](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_ipv4.c#L207)) — `EXPORT_SYMBOL(tcp_v4_connect)`.
    * `tcp_rcv_established` ([tcp_input.c:5889](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_input.c#L5889)) — `EXPORT_SYMBOL(tcp_rcv_established)`.
    * `__tcp_transmit_skb` ([tcp_output.c:1238](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/tcp_output.c#L1238)) — non-inline static symbol in `kallsyms`.
    * `ip_output` ([ip_output.c:432](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/ip_output.c#L432)) — `EXPORT_SYMBOL(ip_output)`.
    * `ipv6_rcv` ([ip6_input.c:258](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_input.c#L258)) — non-inline global symbol.
    * `ip6_output` ([ip6_output.c:236](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/ip6_output.c#L236)) — non-inline global symbol.
    * `tcp_v6_rcv` ([tcp_ipv6.c:1671](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv6/tcp_ipv6.c#L1671)) — non-inline static/global symbol.
    * `udp_rcv` ([udp.c:2631](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L2631)) — non-inline global symbol.
    * `udp_sendmsg` ([udp.c:1032](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1032)) — `EXPORT_SYMBOL(udp_sendmsg)`.
    * `udp_recvmsg` ([udp.c:1872](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/udp.c#L1872)) — non-inline global symbol.
    * `unix_stream_sendmsg` ([af_unix.c:2058](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2058)) — non-inline global symbol.
    * `unix_stream_recvmsg` ([af_unix.c:2681](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/unix/af_unix.c#L2681)) — non-inline global symbol.
    * `icmp_rcv` ([icmp.c:1200](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/icmp.c#L1200)) — non-inline global symbol.
    * `arp_rcv` ([arp.c:943](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/linux-5.14.0-687.10.1.el9_8/net/ipv4/arp.c#L943)) — non-inline static symbol in `kallsyms`.
  * **Finding 7B (`struct syscall_trace_enter` Zero-Length Array `args[0]` vs `struct trace_event_raw_sys_enter` `args[6]`)**:
    [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L741) specifies that `KRAY_BPF_CORE` maps syscall tracepoint contexts to `struct trace_event_raw_sys_enter` and `struct trace_event_raw_sys_exit` ([vmlinux.h:119889-119902](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/btf-and-headers/vmlinux.h#L119889-L119902), where `args` is `long unsigned int args[6]`). However, [kray_bpf_core_compat.h](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/kray_bpf_core_compat.h#L15-L21) maps `tp_args_syscalls_sys_enter_*` to `struct syscall_trace_enter` (`int nr; long unsigned int args[0];`). Indexing `args->args[1]` on a zero-length array `args[0]` triggers `-Warray-bounds` warnings and diverges from `PROMPT_SPEC.md:741`.
  * **Finding 7C (Missing `kretprobe__udp_sendmsg`, `kretprobe__unix_stream_sendmsg`, and 5 Other Spec Hooks Causing `active_ctx_map` Leaks)**:
    [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L931) explicitly mandates that `active_ctx_map.delete(&tid)` must run in `kretprobe__tcp_sendmsg` **and** the corresponding UDP/UNIX kretprobes (`kretprobe__udp_sendmsg`, `kretprobe__unix_stream_sendmsg`), and [PROMPT_SPEC.md](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/README.md#L128-L150) also lists `tracepoint:irq:softirq_entry`, `kprobe:ip_rcv_finish`, `kprobe:skb_copy_datagram_iter`, `tracepoint:kmem:mm_page_alloc`, and `tracepoint:syscalls:sys_enter_sendto` (line 893). None of these hooks exist in [tracer_kernel.c](file:///Users/flynn_macpro/githubs/ebpf-wire-to-code-tracer/tracer_kernel.c)! Because `kretprobe__udp_sendmsg` and `kretprobe__unix_stream_sendmsg` are missing, any thread serving UDP (`kprobe__udp_sendmsg`) or AF_UNIX (`kprobe__unix_stream_sendmsg`) never deletes its `active_ctx_map[tid]` entry upon send completion, leaking stale `req_id` and `parent_span_id` into subsequent unrelated operations on that thread.
* **Recommended Fix (Unified Diff)**:
```diff
--- a/kray_bpf_core_compat.h
+++ b/kray_bpf_core_compat.h
@@ -12,13 +12,13 @@
 #define tp_args_net_netif_receive_skb trace_event_raw_net_dev_template
 #define tp_args_net_net_dev_xmit trace_event_raw_net_dev_xmit
 #define tp_args_tcp_tcp_retransmit_skb trace_event_raw_tcp_event_sk_skb
-#define tp_args_syscalls_sys_enter_read syscall_trace_enter
-#define tp_args_syscalls_sys_exit_read syscall_trace_exit
-#define tp_args_syscalls_sys_enter_write syscall_trace_enter
-#define tp_args_syscalls_sys_exit_write syscall_trace_exit
-#define tp_args_syscalls_sys_enter_recvfrom syscall_trace_enter
-#define tp_args_syscalls_sys_exit_recvfrom syscall_trace_exit
-#define tp_args_syscalls_sys_enter_futex syscall_trace_enter
-#define tp_args_syscalls_sys_exit_futex syscall_trace_exit
+#define tp_args_syscalls_sys_enter_read trace_event_raw_sys_enter
+#define tp_args_syscalls_sys_exit_read trace_event_raw_sys_exit
+#define tp_args_syscalls_sys_enter_write trace_event_raw_sys_enter
+#define tp_args_syscalls_sys_exit_write trace_event_raw_sys_exit
+#define tp_args_syscalls_sys_enter_recvfrom trace_event_raw_sys_enter
+#define tp_args_syscalls_sys_exit_recvfrom trace_event_raw_sys_exit
+#define tp_args_syscalls_sys_enter_futex trace_event_raw_sys_enter
+#define tp_args_syscalls_sys_exit_futex trace_event_raw_sys_exit
 #define tp_args_sched_sched_switch trace_event_raw_sched_switch
 #define tp_args_block_block_rq_issue trace_event_raw_block_rq
```


---

## Archive Document: `archive/subagent_verifications_20/AGENT_18_AI_DIAGNOSIS_DIFF_VERIFIER.md`

# Agent 18 Adversarial Falsification Report — Domain 18/20: AI Bottleneck Diagnosis, Adaptive Zoom-In & Before/After Patch Differential Verification

### 1. Executive Summary of Falsifications

* **Flaw 18-A — Missing `self_time_ns` vs `inclusive_time_ns` Calculation & Double-Counting of Nested L7 Functions**:
  * Previously, `correlate_and_symbolicate_sim_events` and `run_tracer_pipeline` ranked bottlenecks by inclusive `duration_ms` and summed `on_cpu_ms` across all L7 functions regardless of `call_depth`. In a nested call chain (`handle_client_payload` at `depth=0` -> `verify_request_token` at `depth=1` -> `execute_storage_query` at `depth=2`), the outer wrapper has a larger inclusive duration than the leaf hotspot, causing naive `max(duration_ms)` ranking to blame the wrapper and double/triple-count nested durations in `l7_total_ms`.
  * Implemented `build_ai_diagnosis_report()` with per-`(tid, call_depth)` frame tracking that subtracts child inclusive durations and child Off-CPU wait times to compute exact exclusive `self_time_ns` (`self_on_cpu_ns` + `self_off_cpu_ns`) and ranks L7 hotspots by `self_time_ns`.
* **Flaw 18-B — Dynamic Per-Thread / Per-Frame Off-CPU & Block I/O Attribution**:
  * Replaced the hardcoded `tid == 10425` / `symbol == "execute_storage_query"` check with general timestamp-interval `[entry_ts, return_ts]` attribution of `OSI_L5_SYSCALL_MEM` and `OSI_L6_PRE_COMPUTE` wait events on any worker TID and any function symbol.
* **Flaw 18-C — Non-L7 Kernel Bottleneck Diagnosis (`L6_PRE_COMPUTE` Contention & `L3/L4` Drop/Retransmit)**:
  * `build_ai_diagnosis_report()` now diagnoses:
    * `KERNEL_NETWORK_DROP_OR_RETRANSMIT_BOTTLENECK` when `FLAG_SKB_DROP` or `FLAG_TCP_RETRANSMIT` anomalies occur, even when L7 userspace events are absent.
    * `L6_PRE_COMPUTE_SCHEDULER_OR_FUTEX_CONTENTION` when `pre_compute_latency_ns > userspace_compute_ns` due to Futex lock wait or CPU runqueue starvation.
    * `SOCKET_RECEIVE_QUEUE_DWELL_BOTTLENECK` when `sk_rcvbuf` dwell dominates RTT.
* **Flaw 18-D — `AdaptiveController` with Dual-Watermark Hysteresis & `sim_configure_runtime` Sync**:
  * Implemented `AdaptiveController` with `zoom_threshold_ns`, `low_watermark_ns` (`hysteresis_ratio = 0.70`), and `cooldown_windows` to prevent mode-switch thrashing around the threshold, while synchronizing `KrayRuntimeConfig` directly with `lib.sim_configure_runtime`.
* **Flaw 18-E — `compare_before_after_traces` Division-by-Zero Guards, Regression Detection & Per-Function/Per-Layer Deltas**:
  * Added `compare_before_after_traces()` (aliased as `compare_diagnoses`) supporting both file paths and diagnosis dicts, guarding `base_rtt == 0` and `patch_rtt == 0`, flagging `regression_detected = True` (`verdict = "REGRESSION"`) when `patch_rtt > base_rtt` or when drops occur, and computing `function_deltas` and `layer_deltas`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_19_VISUALS_UI_TUI_VERIFIER.md`

# Agent 19 Adversarial Falsification Report — Domain 19/20: Visual & Interactive Interfaces (4-Tier Graphviz DOT/SVG, Mermaid, FlameGraph, Chrome Trace, Web Dashboard XSS/CORS, Rich TUI)

### 1. Executive Summary of Falsifications

* **Flaw 19-1 — FlameGraph (`export_collapsed_stacks` / `render_flamegraph_folded`) Exclusive Self-Time vs. Inclusive Time Double-Counting**:
  * Reconstructed per-TID call hierarchies using `call_depth` and computed exclusive self-time $\text{self\_us}(A) = \max(0, \text{inclusive\_us}(A) - \sum \text{children\_us})$ so parent `A` (`100us`) calling child `B` (`80us`) emits `A 20` and `A;B 80` (summing to `100us` in `flamegraph.pl` instead of `180us`).
* **Flaw 19-2 — Standalone Visual Exporters (`export_chrome_trace`, `export_collapsed_stacks`, `render_graphviz_dot`, `render_graphviz_svg`, `render_web_dashboard_html`, `render_tui_snapshot`)**:
  * Implemented `export_chrome_trace(diag)` producing valid Chrome Trace JSON (`traceEvents` with `ph: "X"`, `ts` in $\mu\text{s}$, `dur >= 0`, and proper parent-child interval containment) and exposed all standalone visual functions.
* **Flaw 19-3 — C++ Template Symbols (`<`, `>`, `&`) XML/HTML/DOT/Mermaid/TUI Escaping**:
  * XML-escaped all node labels in fallback SVG (`render_graphviz_svg`), escaped `\r`/`\n`/`"` in DOT labels, stripped `<script>` and escaped `<!--` / `\u2028` / `\u2029` in `render_web_dashboard_html`, sanitized `:`/`#`/`"` in `render_mermaid_sequence`, and stripped ANSI escape sequences in `render_tui_snapshot`.
* **Flaw 19-4 — Egress `L5_SYSCALL_MEM` Hop in `hop_timeline`, Web UI Overflow Node Click Indexing & REST CORS (`OPTIONS`)**:
  * Added the egress `L5_SYSCALL_MEM` (`sys_enter_write`) hop so `sum(hop_timeline) == total_rtt_ms`, resolved clicked SVG nodes by `<title>hop_N</title>` instead of raw DOM index, wired `filterLayer()` in JS, and added CORS headers + `do_OPTIONS` in `RestHandler`.


---

## Archive Document: `archive/subagent_verifications_20/AGENT_20_MCP_REST_MUTATION_VERIFIER.md`

# Agent 20 Adversarial Falsification Report — Domain 20/20: MCP JSON-RPC 2.0 Server, REST API Security/Concurrency & End-to-End Mutation Testing

### 1. Executive Summary of Falsifications

* **MCP-01 — JSON-RPC 2.0 Batch Request Support (`[ {...}, {...} ]`)**:
  * Updated `MCPGatewayServer.handle_jsonrpc` and `RestHandler.do_POST` (`/mcp`) to accept non-empty JSON-RPC 2.0 batch arrays, process each item, omit Notification items from the returned batch list, and reject empty batch arrays (`[]`) with `-32600 Invalid Request`.
* **MCP-02 — JSON-RPC 2.0 Notification Protocol Compliance (`"id"` Omitted vs `"id": null`)**:
  * Requests without an `"id"` key are now treated as JSON-RPC 2.0 Notifications and return `None` (HTTP `204 No Content` on `/mcp`), whereas parse errors (`-32700`) and invalid requests (`-32600`) return `"id": None`.
* **MCP-03 — Strict Argument & Schema Validation Across All 6 MCP Tools**:
  * Added `_strict_int()` (rejecting Python `bool` `True`/`False` and non-integers), validated `req_id` against `latest_diagnosis["req_id"]`, rejected empty/unknown/path-traversal `target` in `ebpf_inspect_code_or_asm`, and validated `threshold_ns`, `mode`, `layer`, and `format`.
* **REST-01 & REST-02 — `Content-Length` Hardening (`-1`, `0`, `> 1MB`), `/api/v1/mode`, and Path Traversal Prevention**:
  * Added `_read_json_body()` enforcing `0 < Content-Length <= 1_048_576` (returning `400` on negative/zero/invalid `Content-Length` and `413` on payloads `> 1MB`), implemented `POST /api/v1/mode`, restricted `PUT` to `/api/v1/config`, and blocked path traversal (`..`, `/`, `\`, `\x00`) on `/api/v1/inspect` and `/api/v1/compare`.
* **MUT-01..08 — Elimination of Surviving Mutants Across the 24 Test Suites**:
  * Designed explicit boundary assertions for `compute_final_drop_count`, non-10425 worker TID Off-CPU attribution, `capture_enabled == 0` kernel pause guard, `RequestCorrelator` `is_return` tie-breaker, `flush_expired` 4x grace window, `_heatmap_style(10.0 / 35.0)`, `should_attach_uprobe_symbol(st_size=15 / 16)`, and `compare_diagnoses(50.0% / 50.1%)`.
