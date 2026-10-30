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
