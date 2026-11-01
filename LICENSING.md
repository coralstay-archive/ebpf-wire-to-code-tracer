# 라이선스 구분

이 저장소는 두 가지 라이선스를 함께 쓴다. 저작권자는 모두 coralstay다.

| 범위 | 라이선스 | 파일 |
|---|---|---|
| 커널 안에서 도는 BPF 프로그램과 그 빌드·테스트 도구 | [GPL-2.0](./LICENSE.GPL-2.0) | `progs/` 전체, `tracer_kernel.c`, `kray_bpf_core_compat.h`(`SEC("license") = "GPL"` 선언), `test_progs.c`, `Makefile` |
| 그 밖의 모든 코드와 문서(사용자 공간 에이전트, 시뮬레이터, 테스트 스위트, 산출물) | [AGPL-3.0-only](./LICENSE) | `tracer_agent.py`, `kernel_sim_harness.c`, `mock_bpf_runtime.h`, `test_verification_suite.py`, `vmtest.sh`, 문서 등 |

BPF 프로그램은 커널의 GPL 전용 helper를 쓰기 때문에 GPL 호환 라이선스를 선언해야 한다.
그래서 커널 쪽 코드는 GPL-2.0으로 두고, 각 파일의 `SPDX-License-Identifier` 또는
`SEC("license")` 선언이 이 표보다 우선한다.

빌드 산출물 `*.skel.h`는 bpftool이 생성하며 `(LGPL-2.1 OR BSD-2-Clause)`로 표시되고, 저장소에는
커밋하지 않는다.
