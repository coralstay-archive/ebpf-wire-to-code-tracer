#!/usr/bin/env python3
"""
Antigravity Lifecycle Hook: Pre-Implementation Design Audit Gate
Enforces the 3-step pipeline before any implementation code or build file can be created/edited:
  [1] PROMPT_SPEC.md (or SPEC.md) single-sheet master specification (>= 100 lines)
  [2] Multi-pass Ground-Truth Design Audit
  [3] archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md (>= 100 lines, documenting Phases or >= 10 audited items)
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

IMPLEMENTATION_EXTENSIONS = {
    ".c",
    ".cpp",
    ".cc",
    ".h",
    ".hpp",
    ".py",
    ".rs",
    ".go",
    ".ts",
    ".tsx",
    ".js",
    ".java",
    ".sh",
}

IMPLEMENTATION_BASENAMES = {
    "Dockerfile",
    "Makefile",
    "CMakeLists.txt",
}

MIN_SPEC_LINES = 100
MIN_REPORT_LINES = 100
MIN_AUDITED_ITEMS = 10


def read_stdin_payload() -> Dict[str, Any]:
    try:
        raw = sys.stdin.read()
        if not raw or not raw.strip():
            return {}
        return json.loads(raw)
    except Exception:
        return {}


def resolve_workspace_root(payload: Dict[str, Any]) -> Path:
    workspace_paths = payload.get("workspacePaths") or []
    if isinstance(workspace_paths, list) and len(workspace_paths) > 0 and workspace_paths[0]:
        return Path(workspace_paths[0]).resolve()
    return Path.cwd().resolve()


def is_always_allowed_path(target_path: Path, workspace_root: Path, artifact_dir: Optional[str]) -> bool:
    try:
        resolved_target = target_path.resolve()
    except Exception:
        resolved_target = target_path

    if artifact_dir:
        try:
            art_root = Path(artifact_dir).resolve()
            if resolved_target == art_root or art_root in resolved_target.parents:
                return True
        except Exception:
            pass

    target_str = resolved_target.as_posix()
    if "/scratch/" in target_str or "/.gemini/" in target_str:
        return True

    try:
        rel_path = resolved_target.relative_to(workspace_root)
        rel_parts = rel_path.parts
        rel_posix = rel_path.as_posix()
    except ValueError:
        rel_parts = resolved_target.parts
        rel_posix = resolved_target.name

    if rel_posix in {"PROMPT_SPEC.md", "SPEC.md", "README.md"}:
        return True

    if len(rel_parts) > 0 and rel_parts[0] in {"archive", "docs", ".agents", ".agent", "_agents", "_agent"}:
        return True

    return False


def is_implementation_target(target_path: Path) -> bool:
    name = target_path.name
    if name in IMPLEMENTATION_BASENAMES:
        return True
    suffix = target_path.suffix.lower()
    return suffix in IMPLEMENTATION_EXTENSIONS


def check_spec_gate(workspace_root: Path) -> Tuple[bool, str, Optional[Path]]:
    for candidate in ("PROMPT_SPEC.md", "SPEC.md"):
        spec_path = workspace_root / candidate
        if spec_path.is_file():
            try:
                lines = spec_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception as exc:
                return False, f"[Step 1 미충족] `{candidate}` 파일을 읽을 수 없습니다: {exc}", spec_path
            if len(lines) < MIN_SPEC_LINES:
                return (
                    False,
                    f"[Step 1 미충족] `{candidate}` 마스터 설계서의 분량이 부족합니다 "
                    f"(현재 {len(lines)}줄, 최소 {MIN_SPEC_LINES}줄 이상 필요).",
                    spec_path,
                )
            return True, "OK", spec_path

    return (
        False,
        f"[Step 1 미충족] 워크스페이스 루트(`{workspace_root}`)에 1장 마스터 설계서(`PROMPT_SPEC.md` 또는 `SPEC.md`, 최소 {MIN_SPEC_LINES}줄 이상)가 존재하지 않습니다.",
        None,
    )


def check_audit_report_gate(workspace_root: Path) -> Tuple[bool, str]:
    report_path = workspace_root / "archive" / "PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md"
    if not report_path.is_file():
        return (
            False,
            f"[Step 2 & 3 미충족] 다회차 디자인 어딧 리포트(`archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md`)가 존재하지 않습니다.",
        )

    try:
        content = report_path.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
    except Exception as exc:
        return False, f"[Step 2 & 3 미충족] `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md` 읽기 실패: {exc}"

    if len(lines) < MIN_REPORT_LINES:
        return (
            False,
            f"[Step 2 & 3 미충족] `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md` 분량이 부족합니다 "
            f"(현재 {len(lines)}줄, 최소 {MIN_REPORT_LINES}줄 이상 필요).",
        )

    has_multi_phase = all(
        re.search(rf"Phase\s*{idx}", content, re.IGNORECASE) for idx in (1, 2, 3)
    )
    item_matches = re.findall(
        r"(?:^|\n)\s*#{2,4}\s+.*?(?:Iteration\s*\d+|결함\s*#?\d+|Flaw\s*#?\d+|Issue\s*#?\d+|Audit\s*#?\d+)",
        content,
        re.IGNORECASE,
    )

    if not has_multi_phase and len(item_matches) < MIN_AUDITED_ITEMS:
        return (
            False,
            "[Step 2 & 3 미충족] `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md` 내에 다회차 감사 구조(Phase 1 / Phase 2 / Phase 3) "
            f"또는 최소 {MIN_AUDITED_ITEMS}건 이상의 개별 결함 감사 항목(현재 {len(item_matches)}건 감지됨)이 기록되어 있지 않습니다.",
        )

    return True, "OK"


def handle_pre_tool_use(payload: Dict[str, Any]) -> Dict[str, Any]:
    tool_call = payload.get("toolCall") or {}
    tool_name = tool_call.get("name", "")
    tool_args = tool_call.get("args") or {}

    if tool_name not in {"write_file", "edit_file"}:
        return {"decision": "allow"}

    raw_path = tool_args.get("Path") or tool_args.get("TargetFile") or tool_args.get("path") or ""
    if not raw_path:
        return {"decision": "allow"}

    workspace_root = resolve_workspace_root(payload)
    artifact_dir = payload.get("artifactDirectoryPath")

    target_path = Path(raw_path)
    if not target_path.is_absolute():
        target_path = (workspace_root / target_path).resolve()

    if is_always_allowed_path(target_path, workspace_root, artifact_dir):
        return {"decision": "allow"}

    if not is_implementation_target(target_path):
        return {"decision": "allow"}

    spec_ok, spec_msg, _ = check_spec_gate(workspace_root)
    report_ok, report_msg = check_audit_report_gate(workspace_root)

    if spec_ok and report_ok:
        return {"decision": "allow"}

    missing_reasons: List[str] = []
    if not spec_ok:
        missing_reasons.append(spec_msg)
    if not report_ok:
        missing_reasons.append(report_msg)

    reason = (
        "[Design Audit Gate 차단] 프로덕션/구현 코드(`"
        + target_path.name
        + "`)를 작성하기 전에 반드시 아래 3단계 파이프라인을 먼저 완료해야 합니다:\n"
        + "  [1] `PROMPT_SPEC.md` (1장 마스터 설계서 작성, >= 100줄)\n"
        + "  [2] 다회차(Phase 1~3) 실증 Design Audit 수행 및 `PROMPT_SPEC.md` 인플레이스 교정\n"
        + "  [3] `archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md` (디자인 어딧 리포트 작성, >= 100줄)\n"
        + "누락/미충족 항목:\n  - "
        + "\n  - ".join(missing_reasons)
    )
    return {
        "decision": "deny",
        "reason": reason,
    }


def handle_stop(payload: Dict[str, Any]) -> Dict[str, Any]:
    termination_reason = payload.get("terminationReason", "")
    if termination_reason != "NO_TOOL_CALL":
        return {"decision": "allow"}

    workspace_root = resolve_workspace_root(payload)
    spec_exists = (workspace_root / "PROMPT_SPEC.md").is_file() or (workspace_root / "SPEC.md").is_file()
    report_path = workspace_root / "archive" / "PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md"

    if spec_exists and not report_path.is_file():
        return {
            "decision": "continue",
            "reason": (
                "[Design Audit Gate] 1장 마스터 설계서(PROMPT_SPEC.md)는 작성되었으나 "
                "디자인 어딧 및 archive/PRE_IMPLEMENTATION_DESIGN_AUDIT_REPORT.md 리포트가 아직 생성되지 않았습니다. "
                "디자인 어딧을 수행하고 리포트를 작성하십시오."
            ),
        }

    return {"decision": "allow"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Pre-Implementation Design Audit Lifecycle Hook Gate")
    parser.add_argument(
        "--event",
        choices=["PreToolUse", "Stop"],
        required=True,
        help="Hook lifecycle event type",
    )
    args = parser.parse_args()

    payload = read_stdin_payload()
    if args.event == "PreToolUse":
        result = handle_pre_tool_use(payload)
    else:
        result = handle_stop(payload)

    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
