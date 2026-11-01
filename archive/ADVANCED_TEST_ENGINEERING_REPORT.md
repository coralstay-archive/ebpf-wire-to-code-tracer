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

