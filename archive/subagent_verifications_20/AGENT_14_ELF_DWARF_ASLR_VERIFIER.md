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
