"""AppContext: the only DI bundle. Built once in cli/app.py, passed everywhere."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from patchdiff_ai.config.tools import (
    GhidraInstall,
    discover_ghidra_installs,
    select_ghidra_install,
)
from patchdiff_ai.llm.catalog import ModelPurpose
from patchdiff_ai.llm.registry import ModelRegistry
from patchdiff_ai.observability.progress import NullProgressReporter, ProgressReporter
from patchdiff_ai.persistence.vector_store import VectorStores
from patchdiff_ai.runtime.paths import BUNDLED_BINDIFF_DIR
from patchdiff_ai.tools.bindiff import BindiffTool
from patchdiff_ai.tools.delta import DeltaApi
from patchdiff_ai.tools.ghidra import GhidraTool
from patchdiff_ai.tools.manifest import WcpManifestExtractor
from patchdiff_ai.tools.seven_zip import SevenZipTool

if TYPE_CHECKING:
    from patchdiff_ai.config.settings import Settings
    from patchdiff_ai.platforms.base import Platform
    from patchdiff_ai.prompts.registry import PromptRegistry


@dataclass
class Tools:
    seven_zip: SevenZipTool
    ghidra: GhidraTool
    bindiff: BindiffTool
    delta: DeltaApi
    idalib: object | None = None
    ida_chat: object | None = None
    manifest: WcpManifestExtractor | None = None


@dataclass
class AppContext:
    """Top-level DI bundle. Holds everything any node, tool, or CLI command needs."""

    settings: Settings
    registry: ModelRegistry
    tools: Tools
    log: structlog.stdlib.BoundLogger
    ghidra_install: GhidraInstall | None = None
    vector_stores: VectorStores | None = None
    prompts: "PromptRegistry | None" = field(default=None)
    progress: ProgressReporter = field(default_factory=NullProgressReporter)
    # Set by the orchestrator at run_cve entry from the CLI-resolved
    # provider/Platform; nodes route per-OS work (advisory fetch,
    # package gather, ranking prompts) through it.
    platform: "Platform | None" = field(default=None)

    @classmethod
    def build(cls, settings: Settings) -> "AppContext":
        """Construct the context; vector stores stay lazy."""
        registry = ModelRegistry.from_settings(settings)
        # Auto-create a starter config.json on first run so the next
        # invocation has a real file to edit. Idempotent — does nothing
        # if the file already exists.
        from patchdiff_ai.cli.commands.init import write_default_config
        from patchdiff_ai.runtime.app_dirs import config_json_path

        write_default_config(config_json_path())

        # `setdefault` so explicit user BINDIFF_PATH wins. python-bindiff
        # resolves the binary lazily on first diff.
        if BUNDLED_BINDIFF_DIR.is_dir() and (BUNDLED_BINDIFF_DIR / "bindiff.exe").is_file():
            os.environ.setdefault("BINDIFF_PATH", str(BUNDLED_BINDIFF_DIR))

        ghidra_install = select_ghidra_install(discover_ghidra_installs())
        if settings.tools.ghidra is not None:
            ghidra_exe = settings.tools.ghidra
        elif ghidra_install is not None:
            ghidra_exe = ghidra_install.executable
        else:
            ghidra_exe = Path(r"C:\ghidra\support\analyzeHeadless.bat")

        tools = Tools(
            seven_zip=SevenZipTool(
                settings.tools.seven_zip,
                timeout=settings.tools.process_timeout_seconds,
            ),
            ghidra=GhidraTool(
                ghidra_exe,
                timeout=settings.tools.process_timeout_seconds,
            ),
            bindiff=BindiffTool(),
            delta=DeltaApi(
                modules=[settings.tools.update_compression_dll]
                if settings.tools.update_compression_dll.exists()
                else []
            ),
            idalib=None,
            ida_chat=None,
            manifest=None,
        )
        log = structlog.get_logger("patchdiff_ai")
        ctx = cls(
            settings=settings,
            registry=registry,
            tools=tools,
            log=log,
            ghidra_install=ghidra_install,
        )

        try:
            from patchdiff_ai.prompts.registry import PromptRegistry

            ctx.prompts = PromptRegistry.default()
        except Exception as exc:
            log.warning("prompts_unavailable", error=str(exc))

        return ctx

    def open_vector_stores(self) -> VectorStores:
        if self.vector_stores is not None:
            return self.vector_stores
        embedding = self.registry.for_purpose(ModelPurpose.EMBEDDING).model
        self.vector_stores = VectorStores.open(self.settings.paths.db_dir, embedding)
        return self.vector_stores

    def close(self) -> None:
        try:
            self.tools.delta.close()
        except Exception:
            pass
        # Ghidra is subprocess-only; no long-lived worker state to tear down.
