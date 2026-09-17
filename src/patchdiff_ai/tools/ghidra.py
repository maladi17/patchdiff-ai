"""Ghidra headless wrapper."""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

import structlog

from patchdiff_ai.tools.process import run

log = structlog.get_logger(__name__)

_SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra_scripts"


def _tail(text: str, lines: int = 20) -> str:
    parts = text.splitlines()
    return "\n".join(parts[-lines:]) if parts else ""


def _sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


@dataclass
class GhidraJob:
    target: Path
    script: str
    args: list[str] = field(default_factory=list)
    log: str | None = None


class GhidraTool:
    """Async batch invoker for `analyzeHeadless`."""

    def __init__(self, executable: Path, timeout: float = 60 * 30) -> None:
        self.executable = Path(executable)
        self.timeout = timeout

    def project_dir(self, target: Path) -> Path:
        return target.parent / "__ghidra__"

    def project_name(self, target: Path) -> str:
        digest = hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:10]
        return f"{_sanitize(target.name)}_{digest}"

    def is_valid(self, job: GhidraJob) -> bool:
        if not self.executable.is_file():
            log.error("ghidra_executable_missing", path=str(self.executable))
            return False
        if not job.target.exists():
            log.error("ghidra_target_missing", path=str(job.target))
            return False
        if job.script != "BinExport.java" and not (_SCRIPTS_DIR / job.script).is_file():
            log.error("ghidra_script_missing", path=str(_SCRIPTS_DIR / job.script))
            return False
        return True

    async def run_script(self, job: GhidraJob) -> int:
        if not self.is_valid(job):
            return -1

        target = Path(job.target).resolve()
        project_dir = self.project_dir(target)
        project_dir.mkdir(parents=True, exist_ok=True)

        argv: list[str] = [
            str(self.executable),
            str(project_dir),
            self.project_name(target),
        ]
        argv.extend(["-import", str(target), "-overwrite"])
        argv.extend(["-scriptPath", str(_SCRIPTS_DIR), "-postScript", job.script, *job.args])

        log.debug("ghidra_run", argv=argv)
        res = await run(argv, timeout=self.timeout, check=False)
        if job.log:
            Path(job.log).write_text(
                f"$ {' '.join(argv)}\n\nSTDOUT\n{res.stdout}\n\nSTDERR\n{res.stderr}",
                encoding="utf-8",
            )
        if res.returncode != 0:
            log.warning(
                "ghidra_run_failed",
                target=str(target),
                returncode=res.returncode,
                script=job.script,
                log_file=job.log,
                stdout_tail=_tail(res.stdout),
                stderr_tail=_tail(res.stderr),
            )
        return res.returncode

    async def batch(
        self,
        jobs: list[GhidraJob],
        *,
        condition: Callable[[GhidraJob], bool] | None = None,
    ) -> list[int]:
        results: list[int] = []
        remaining = [j for j in jobs if (condition(j) if condition else True)]
        while remaining:
            current: list[GhidraJob] = []
            future: list[GhidraJob] = []
            seen: set[Path] = set()
            for job in remaining:
                if job.target in seen:
                    future.append(job)
                else:
                    current.append(job)
                    seen.add(job.target)
            tasks: list[Awaitable[int]] = [self.run_script(j) for j in current]
            if tasks:
                results.extend(await asyncio.gather(*tasks))
            remaining = future
        return results
