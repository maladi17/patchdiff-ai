"""Package-internal constants shared between the agent build and tool registrations."""

from __future__ import annotations


# Surfaced when a CVE_INFO cache hit dispatched no artifacts so binary-level
# tools have nothing to read.
_NO_ARTIFACTS_HINT = (
    "No patch-diff artifacts in this chat session (the run was "
    "served from the report cache, so no per-function diff state "
    "was produced). Re-run the CVE locally to regenerate reverse-"
    "engineering artifacts before asking binary-level questions."
)


# IDA tools that mutate state or arbitrary-execute — never registered.
_DENY_IDA_TOOLS = {
    "py_eval", "py_exec", "py_run_file", "patch", "patch_asm",
    "dbg_start", "dbg_continue", "dbg_step_into", "dbg_step_over",
    "dbg_add_bp", "dbg_bps", "dbg_regs", "dbg_read", "dbg_write",
}
