"""Log external scanner invocations (stderr) so operators see exact argv."""

from __future__ import annotations

import json
import shlex
import sys
from typing import Any


def log_tool_command(tool: str, argv: list[str]) -> None:
    """Emit one JSON line to stderr: tool name + argv + shell-escaped hint."""
    line = " ".join(shlex.quote(a) for a in argv)
    payload: dict[str, Any] = {"tool": tool, "argv": argv, "shell": line}
    print(f"[appsec-crew] executing: {json.dumps(payload, ensure_ascii=False)}", file=sys.stderr, flush=True)
