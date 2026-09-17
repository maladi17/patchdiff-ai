"""Binary RE backend (PE / ELF / Mach-O via Ghidra + BinDiff).

One of N backends the M3 RE router (`router.py`) dispatches to.
The Ghidra flow produces the same artefact shapes (`<binary>.BinExport`,
`<primary>.<secondary_kb>.BinDiff`, `__funcs__/<ea>.c`) so VR is
agnostic.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph
from langgraph.types import RetryPolicy

from patchdiff_ai.graphs.reverse_engineering.state import ReverseEngineeringState
from patchdiff_ai.runtime.app_context import AppContext


class BinaryReNodes:
    ANALYZE = "Analyze binaries"
    DIFF_AND_DECOMPILE = "Diff and decompile"


_BUSY_RETRY = RetryPolicy(
    initial_interval=2.0,
    backoff_factor=2.0,
    max_interval=30.0,
    max_attempts=10,
    retry_on=RuntimeError,
)


def build_binary_re_graph(ctx: AppContext):
    """Build the binary RE subgraph for the configured Ghidra install."""
    from patchdiff_ai.graphs.reverse_engineering.nodes_ghidra import make_nodes

    analyze, diff_and_decompile = make_nodes(ctx)

    builder = StateGraph(ReverseEngineeringState)
    builder.add_node(BinaryReNodes.ANALYZE, analyze, retry_policy=_BUSY_RETRY)
    # Diff + decompile is one node so the live BinDiff (sqlite3-backed,
    # not pickleable) never crosses a checkpoint boundary.
    builder.add_node(
        BinaryReNodes.DIFF_AND_DECOMPILE,
        diff_and_decompile,
        retry_policy=_BUSY_RETRY,
    )

    builder.set_entry_point(BinaryReNodes.ANALYZE)
    builder.add_edge(BinaryReNodes.ANALYZE, BinaryReNodes.DIFF_AND_DECOMPILE)
    builder.add_edge(BinaryReNodes.DIFF_AND_DECOMPILE, END)

    return builder.compile()
