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
