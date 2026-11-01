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
