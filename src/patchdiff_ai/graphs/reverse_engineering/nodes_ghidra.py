"""Ghidra-backed reverse-engineering nodes."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import binexport
import structlog

from patchdiff_ai.graphs.reverse_engineering._shared import discover_parents
from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext
from patchdiff_ai.runtime.timer import Timer
from patchdiff_ai.schemas.analysis import Artifact, FunctionMatchRef
from patchdiff_ai.tools.ghidra import GhidraJob

log = structlog.get_logger(__name__)


def make_nodes(ctx: AppContext):
    async def analyze(state: ReverseEngineeringState) -> dict[str, Any]:
        log.info("re_analyze_start", file=state.primary_file.name)
        run_start = time.time()
        logs_dir = ctx.settings.paths.logs_dir
        async with Timer("ghidra_export"):
            prim = Path(state.primary_file.path)
            sec = Path(state.secondary_file.path)
            jobs = [
                GhidraJob(
                    target=prim,
                    script="BinExport.java",
                    args=[
                        str(prim.with_name(prim.name + ".BinExport")),
                        "Prepend Namespace to Function Names",
                    ],
                    log=str(logs_dir / f"{prim.parent.name}.{prim.name}.analyze.log"),
                ),
                GhidraJob(
                    target=sec,
                    script="BinExport.java",
                    args=[
                        str(sec.with_name(sec.name + ".BinExport")),
                        "Prepend Namespace to Function Names",
                    ],
                    log=str(logs_dir / f"{sec.parent.name}.{sec.name}.analyze.log"),
                ),
            ]
            ran_targets = {
                j.target
                for j in jobs
                if not j.target.with_name(j.target.name + ".BinExport").exists()
                or not ctx.tools.ghidra.project_exists(j.target)
            }
            log.trace(
                "re_analyze_cache",
                file=state.primary_file.name,
                targets_to_run=len(ran_targets),
                targets_skipped=len(jobs) - len(ran_targets),
            )
            await ctx.tools.ghidra.batch(
                jobs, condition=lambda j: j.target in ran_targets
            )

        for src in (state.primary_file.path, state.secondary_file.path):
            be = Path(src + ".BinExport")
            if not be.exists():
                log.error(
                    "binexport_output_missing",
                    target=str(be),
                    hint=(
                        "Ghidra may have failed before writing the export, or the "
                        "BinExport Ghidra extension is missing — run "
                        "`patchdiff-ai health-check`."
                    ),
                )
                continue
            if Path(src) in ran_targets and be.stat().st_mtime < run_start:
                log.error(
                    "binexport_stale_after_ghidra_failed",
                    target=str(be),
                    mtime=be.stat().st_mtime,
                    run_start=run_start,
                    age_s=round(run_start - be.stat().st_mtime, 1),
                    hint="Ghidra was launched but didn't refresh this export. Removing stale output so bindiff fails cleanly.",
                )
                try:
                    be.unlink()
                except OSError as exc:
                    log.warning(
                        "binexport_unlink_failed",
                        target=str(be),
                        error=str(exc),
                    )
        return {}

    async def diff_and_decompile(state: ReverseEngineeringState) -> dict[str, Any]:
        curr = Path(state.primary_file.path + ".BinExport")
        prev = Path(state.secondary_file.path + ".BinExport")
        if not curr.exists() or not prev.exists():
            log.warning(
                "bindiff_inputs_missing",
                current_exists=curr.exists(),
                previous_exists=prev.exists(),
                current=str(curr),
                previous=str(prev),
            )
            return {"artifacts": []}

        async with Timer("bindiff"):
            out = Path(f"{state.primary_file.path}.{state.secondary_file.kb}.BinDiff")
            bd = await ctx.tools.bindiff.diff(curr, prev, out)
            if bd is None:
                log.warning("bindiff_failed", file=state.primary_file.name)
                return {"artifacts": []}

        async with Timer("decompile_diff"):
            changed = [
                v
                for v in bd.primary_functions_match.values()
                if v.similarity < 1.0
            ]
            primary_funcs = {f"{f.address1:X}" for f in changed} - {
                i.stem for i in (bd.primary.path.parent / "__funcs__").glob("*.c")
            }
            secondary_funcs = {f"{f.address2:X}" for f in changed} - {
                i.stem for i in (bd.secondary.path.parent / "__funcs__").glob("*.c")
            }

            jobs: list[GhidraJob] = []

            def add(export: binexport.program.ProgramBinExport, funcs: list[str]) -> None:
                target = export.path.with_suffix("")
                if not target.exists():
                    return
                target.parent.joinpath("__funcs__").mkdir(parents=True, exist_ok=True)
                for i in range(0, len(funcs), 500):
                    jobs.append(
                        GhidraJob(
                            target=target,
                            script="decompile.py",
                            args=[
                                str(target.parent / "__funcs__"),
                                *funcs[i : i + 500],
                            ],
                            log=str(
                                ctx.settings.paths.logs_dir
                                / f"{target.parent.name}.{target.name}.decompile.log"
                            ),
                            require_existing_project=True,
                        )
                    )

            add(bd.primary, list(primary_funcs))
            add(bd.secondary, list(secondary_funcs))
            log.trace(
                "re_decompile_plan",
                file=state.primary_file.name,
                changed_funcs=len(changed),
                primary_unseen=len(primary_funcs),
                secondary_unseen=len(secondary_funcs),
                batched_jobs=len(jobs),
            )
            await ctx.tools.ghidra.batch(jobs)

            sorted_changed = sorted(changed, key=lambda x: (x.similarity, -x.confidence))
            log.info(
                "re_decompile_done",
                file=state.primary_file.name,
                changed=len(sorted_changed),
            )
            refs = [
                FunctionMatchRef(
                    name1=m.name1,
                    name2=m.name2,
                    address1=m.address1,
                    address2=m.address2,
                    similarity=m.similarity,
                    confidence=m.confidence,
                    parents=next(
                        discover_parents(bd.secondary.get(m.address2)),
                        None,
                    ),
                )
                for m in sorted_changed
            ]
            artifact = Artifact(
                primary_file=state.primary_file,
                secondary_file=state.secondary_file,
                changed=refs,
            )
            return {"artifacts": [artifact]}

    return analyze, diff_and_decompile
