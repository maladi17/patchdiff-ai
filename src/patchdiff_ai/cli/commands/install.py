"""`patchdiff-ai install` — bootstrap platform prerequisites."""

from __future__ import annotations

import click

from patchdiff_ai.platforms import providers


@click.command(
    "install",
    help="Install prerequisites for every registered platform and print Ghidra setup guidance.",
)
def install_group() -> None:
    failures: list[str] = []
    for provider in providers():
        click.echo(f"\n--- {provider.name} ---")
        try:
            provider.install()
        except Exception as exc:
            click.echo(f"[!] {provider.name} install failed: {exc}")
            failures.append(provider.name)
    if failures:
        raise click.exceptions.Exit(code=1)
    click.echo(
        "\n[+] platform installs complete\n"
        "    Install Ghidra separately, then install the BinExport Ghidra extension\n"
        "    (`ghidra_BinExport.zip`) via File -> Install Extensions and point\n"
        "    `tools.ghidra` / `TOOLS__GHIDRA` at analyzeHeadless."
    )
