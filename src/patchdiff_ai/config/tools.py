from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from patchdiff_ai.runtime.paths import BUNDLED_UPDATE_COMPRESSION_DLL


@dataclass(frozen=True)
class GhidraInstall:
    """A discovered Ghidra install. `executable` is `analyzeHeadless`."""

    root: Path
    version: tuple[int, ...]
    executable: Path

    @property
    def extensions_dir(self) -> Path:
        return self.root / "Extensions"


_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+)")


def _resolve_executable(root: Path) -> Path | None:
    for rel in (
        Path("support") / "analyzeHeadless.bat",
        Path("support") / "analyzeHeadless",
        Path("support") / "analyzeHeadless.exe",
    ):
        exe = root / rel
        if exe.is_file():
            return exe
    return None


def _parse_version(name: str) -> tuple[int, ...]:
    m = _VERSION_RE.search(name)
    if not m:
        return (0, 0, 0)
    return tuple(int(part) for part in m.group(1).split("."))


def _candidate_roots() -> list[Path]:
    return (
        [
        Path(os.environ[env])
        for env in ("ProgramFiles", "ProgramFiles(x86)")
        if os.environ.get(env)
        ]
        + [
            Path(r"C:\Program Files"),
            Path(r"C:\Program Files (x86)"),
            Path("/opt"),
            Path("/Applications"),
            Path.home(),
        ]
    )


def _explicit_env_candidates() -> list[Path]:
    out: list[Path] = []
    for env in ("GHIDRA_INSTALL_DIR", "GHIDRA_HOME"):
        value = os.environ.get(env)
        if not value:
            continue
        path = Path(value)
        out.extend([path, path.parent, path.parent.parent])
    return out


def discover_ghidra_installs() -> list[GhidraInstall]:
    """Return all discovered Ghidra installs sorted newest-first."""

    found: dict[Path, GhidraInstall] = {}
    for root in _explicit_env_candidates():
        exe = _resolve_executable(root)
        if exe is None:
            continue
        resolved = root.resolve()
        found[resolved] = GhidraInstall(
            root=resolved,
            version=_parse_version(root.name),
            executable=exe,
        )

    for base in _candidate_roots():
        if not base.exists():
            continue

        candidates: list[Path] = []
        if _resolve_executable(base) is not None:
            candidates.append(base)
        elif base.is_dir():
            try:
                candidates.extend(
                    child
                    for child in base.iterdir()
                    if child.is_dir() and child.name.lower().startswith("ghidra")
                )
            except OSError:
                continue

        for root in candidates:
            exe = _resolve_executable(root)
            if exe is None:
                continue
            resolved = root.resolve()
            found[resolved] = GhidraInstall(
                root=resolved,
                version=_parse_version(root.name),
                executable=exe,
            )

    return sorted(found.values(), key=lambda inst: inst.version, reverse=True)


def select_ghidra_install(installs: list[GhidraInstall]) -> GhidraInstall | None:
    return installs[0] if installs else None


class ToolPaths(BaseModel):
    """External-tool paths. Override via env (TOOLS__<NAME>=...)."""

    seven_zip: Path = Field(default=Path("C:/Program Files/7-Zip/7z.exe"))
    ghidra: Path | None = Field(default=None)
    update_compression_dll: Path = Field(
        default_factory=lambda: BUNDLED_UPDATE_COMPRESSION_DLL
    )

    process_timeout_seconds: float = 60 * 30
    """Default subprocess timeout for Ghidra / BinDiff / 7-Zip jobs."""

    def exists(self, *, ghidra_exe: Path | None = None) -> dict[str, bool]:
        ghidra = ghidra_exe or self.ghidra
        return {
            "seven_zip": self.seven_zip.is_file(),
            "ghidra": ghidra is not None and ghidra.is_file(),
            "update_compression_dll": self.update_compression_dll.is_file(),
        }
