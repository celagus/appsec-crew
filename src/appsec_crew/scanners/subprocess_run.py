"""Run scanner subprocesses with stderr logging of argv."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from appsec_crew.scanners.command_log import log_tool_command


def run_scanner(
    cmd: list[str],
    *,
    cwd: Path,
    tool_label: str,
    commands_log: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    log_tool_command(tool_label, cmd)
    if commands_log is not None:
        commands_log.append(shlex.join(cmd))
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
