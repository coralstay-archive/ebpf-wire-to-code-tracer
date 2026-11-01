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
