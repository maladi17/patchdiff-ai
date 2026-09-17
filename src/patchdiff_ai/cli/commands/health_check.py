"""`patchdiff-ai health-check` — validate environment + every registered platform."""

from __future__ import annotations

import asyncio
import os

import click

from patchdiff_ai.config.settings import get_settings
from patchdiff_ai.config.tools import discover_ghidra_installs, select_ghidra_install
from patchdiff_ai.platforms import providers
from patchdiff_ai.runtime.app_context import AppContext


@click.command("health-check", help="Validate environment, tools, and every registered platform.")
def health_check_command() -> None:
    settings = get_settings()
    settings.paths.ensure()
    ctx = AppContext.build(settings)

    click.echo("== Settings ==")
    click.echo(f"db_dir          = {settings.paths.db_dir}")
    click.echo(f"reports_dir     = {settings.paths.reports_dir}")
    click.echo(f"7z              = {settings.tools.seven_zip}")
    click.echo(f"ghidra          = {ctx.tools.ghidra.executable}")
    click.echo(f"updatecomp dll  = {settings.tools.update_compression_dll}")
    click.echo(f"BINDIFF_PATH    = {os.environ.get('BINDIFF_PATH', '<unset>')}")

    click.echo("\n== Ghidra installs discovered ==")
    installs = discover_ghidra_installs()
    selected = select_ghidra_install(installs)
    if not installs:
        click.echo("  (none — set TOOLS__GHIDRA explicitly or install Ghidra)")
    for inst in installs:
        marker = "*" if selected and inst.root == selected.root else " "
        ver = ".".join(str(x) for x in inst.version if x) or "unknown"
        click.echo(
            f"  {marker} {ver:10}  {inst.executable.name:22}  {inst.root}"
        )

    click.echo("\n== Tool availability ==")
    avail = settings.tools.exists(ghidra_exe=ctx.tools.ghidra.executable)
    for k, v in avail.items():
        click.echo(f"  {k:24} = {'OK' if v else 'MISSING'}")
    click.echo(
        "  ! BinExport Ghidra extension is required for binary export. "
        "Install `ghidra_BinExport.zip` into Ghidra if exports fail."
    )

    click.echo("\n== RE readiness ==")
    click.echo("  backend              = ghidra headless")
    click.echo("  chat binary tools    = unavailable")

    click.echo("\n== Available models ==")
    for spec in ctx.registry.list_available():
        click.echo(f"  {spec.name:32} -> {spec.provider.value} ({spec.deployment})")

    async def smoke() -> None:
        from patchdiff_ai.tools.process import run

        try:
            res = await run(
                [str(settings.tools.seven_zip)],
                timeout=10,
                check=False,
            )
            status = "OK" if res.returncode == 0 else f"rc={res.returncode}"
            click.echo(f"  7-Zip launch         = {status}")
        except Exception as exc:
            click.echo(f"  7-Zip launch         = FAILED ({exc})")
        try:
            status = "OK" if ctx.tools.ghidra.executable.is_file() else "MISSING"
            click.echo(f"  Ghidra executable    = {status}")
        except Exception as exc:
            click.echo(f"  Ghidra executable    = FAILED ({exc})")

    click.echo("\n== Tool smoke ==")
    asyncio.run(smoke())

    failures: list[str] = []
    for provider in providers():
        click.echo(f"\n== Platform: {provider.name} ==")
        try:
            ok = provider.health_check()
        except Exception as exc:
            click.echo(f"  ERROR: {exc}")
            ok = False
        if not ok:
            failures.append(provider.name)

    ctx.close()

    if failures:
        click.echo(f"\n[!] Provider health-check failed: {failures}")
        raise click.exceptions.Exit(code=1)
    click.echo("\n[+] health-check complete")
