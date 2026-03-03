"""ZeroMint CLI — Typer-based command interface.

Commands:
  zeromint init           Copy config.example.yaml -> ./config.yaml
  zeromint doctor         Check tool availability (docker, semgrep, codeql, tree-sitter)
  zeromint recon          Index local repo and identify security hotspots
  zeromint graph          Build code units + call graph via tree-sitter
  zeromint static         Run static analysis (semgrep / codeql)
  zeromint hypothesize    Generate vulnerability hypotheses
  zeromint generate-tests Generate verification tests / harnesses
  zeromint execute        Run tests in sandbox, produce validation results
  zeromint triage         Assess findings conservatively
  zeromint report         Generate REPORT.md + evidence bundle
  zeromint run            Execute the full analysis pipeline
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cve_agent import __version__

app = typer.Typer(
    name="zeromint",
    help="ZeroMint — LLM Agent-based Vulnerability Detection & Automated PoC/Triage Platform (Research/Defense)",
    no_args_is_help=True,
)
console = Console()

# Locate config.example.yaml relative to this package
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent
_EXAMPLE_CONFIG = _PROJECT_ROOT / "config.example.yaml"


# ── init ──────────────────────────────────────────────────


@app.command()
def init(
    output: str = typer.Option(
        "config.yaml", "--output", "-o", help="Output config file path",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing config.yaml",
    ),
) -> None:
    """Create config.yaml from config.example.yaml template."""
    dst = Path(output)
    src = _EXAMPLE_CONFIG

    if not src.exists():
        console.print(f"[red]Error:[/red] Template not found: {src}")
        raise typer.Exit(1)

    if dst.exists() and not force:
        console.print(
            f"[yellow]Warning:[/yellow] {dst} already exists. "
            f"Use [bold]--force[/bold] to overwrite."
        )
        raise typer.Exit(1)

    shutil.copy2(src, dst)
    console.print(f"[green]Created:[/green] {dst}")
    console.print("Edit the file to configure your target and features.")


# ── doctor ────────────────────────────────────────────────


def _check_command(name: str, args: list[str] | None = None) -> tuple[bool, str]:
    """Check if a command is available. Returns (available, version_or_error)."""
    cmd = args or [name, "--version"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            version = result.stdout.strip().split("\n")[0]
            return True, version
        return False, f"exit code {result.returncode}"
    except FileNotFoundError:
        return False, "not installed"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def _check_python_import(module_name: str) -> tuple[bool, str]:
    """Check if a Python module can be imported."""
    try:
        mod = __import__(module_name)
        version = getattr(mod, "__version__", getattr(mod, "VERSION", "installed"))
        return True, str(version)
    except ImportError:
        return False, "not installed"


@app.command()
def doctor() -> None:
    """Check availability of required and optional tools."""
    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        "Tool availability check",
        title="[bold]Doctor[/bold]",
    ))

    table = Table(show_header=True, header_style="bold")
    table.add_column("Tool", style="cyan", min_width=16)
    table.add_column("Status", min_width=10)
    table.add_column("Details")

    checks: list[tuple[str, bool, str]] = []

    # Python
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    checks.append(("Python 3.11+", py_ok, py_ver))

    # Docker
    ok, detail = _check_command("docker", ["docker", "version", "--format", "{{.Client.Version}}"])
    checks.append(("Docker", ok, detail))

    # Semgrep
    ok, detail = _check_command("semgrep")
    checks.append(("Semgrep", ok, detail))

    # CodeQL
    ok, detail = _check_command("codeql")
    checks.append(("CodeQL", ok, detail))

    # tree-sitter (Python library)
    ok, detail = _check_python_import("tree_sitter")
    checks.append(("tree-sitter", ok, detail))

    # tree-sitter-python
    ok, detail = _check_python_import("tree_sitter_python")
    checks.append(("tree-sitter-python", ok, detail))

    # pydantic
    ok, detail = _check_python_import("pydantic")
    checks.append(("pydantic", ok, detail))

    # pytest
    ok, detail = _check_python_import("pytest")
    checks.append(("pytest", ok, detail))

    for name, available, info in checks:
        status = "[green]OK[/green]" if available else "[red]MISSING[/red]"
        table.add_row(name, status, info)

    console.print(table)

    all_ok = all(ok for _, ok, _ in checks)
    if all_ok:
        console.print("\n[bold green]All tools available.[/bold green]")
    else:
        missing = [name for name, ok, _ in checks if not ok]
        console.print(f"\n[yellow]Missing tools:[/yellow] {', '.join(missing)}")
        console.print("Install missing tools for full functionality.")


# ── recon ─────────────────────────────────────────────────


@app.command()
def recon(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Index a local repo and identify security-relevant hotspots."""
    from cve_agent.config import load_config
    from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        console.print("Run [bold]cve-agent init[/bold] to create one.")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] recon requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    # Banner
    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:  [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:  [green]{config.target.path_or_url}[/green]\n"
        f"Ignores: [dim]{len(config.target.all_ignores)} patterns[/dim]",
        title="[bold]Recon[/bold]",
    ))

    # Index
    ctx.mark_running()
    try:
        repo_index, hotspot_index = index_repo(config)
        save_artifacts(repo_index, hotspot_index, ctx.artifacts_dir)

        ctx.result.stats.indexed_files = repo_index.summary.total_files
        ctx.result.stats.languages = repo_index.summary.language_counts
        ctx.result.stats.hotspot_top5 = [h.path for h in hotspot_index.items[:5]]

        ctx.mark_completed()
    except Exception:
        ctx.mark_failed("recon failed")
        console.print("[red]Recon failed.[/red] Check run.log for details.")
        raise typer.Exit(1)

    # ── Summary table ──────────────────────────────────────
    s = repo_index.summary
    summary = Table(title="Repo Index Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Files", str(s.total_files))
    summary.add_row("Total size", f"{s.total_bytes:,} bytes")
    summary.add_row("Keyword hits", str(s.suspicious_keyword_hits))
    summary.add_row("Hotspot candidates", str(len(hotspot_index.items)))
    console.print(summary)

    # Languages
    if s.language_counts:
        lang_table = Table(title="Languages")
        lang_table.add_column("Language", style="cyan")
        lang_table.add_column("Files", style="green", justify="right")
        for lang, count in sorted(s.language_counts.items(), key=lambda x: -x[1])[:15]:
            lang_table.add_row(lang, str(count))
        console.print(lang_table)

    # Top hotspots
    if hotspot_index.items:
        hs_table = Table(title="Top Hotspots")
        hs_table.add_column("#", style="dim", width=4)
        hs_table.add_column("Score", style="bold yellow", width=7, justify="right")
        hs_table.add_column("File", style="green")
        hs_table.add_column("Reasons", style="dim")
        for i, h in enumerate(hotspot_index.items[:10], 1):
            hs_table.add_row(
                str(i),
                f"{h.score:.1f}",
                h.path,
                ", ".join(h.reasons[:5]),
            )
        console.print(hs_table)

    console.print(f"\n[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"[cyan]Log:      [/cyan] [green]{ctx.log_file.resolve()}[/green]")
    console.print(f"\n[bold green]Recon complete.[/bold green]")


# ── graph ─────────────────────────────────────────────────


@app.command()
def graph(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Build code units and call graph using tree-sitter."""
    from cve_agent.config import load_config
    from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        console.print("Run [bold]cve-agent init[/bold] to create one.")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] graph requires target.type = repo")
        raise typer.Exit(1)

    if not config.features.enable_graph:
        console.print("[yellow]Warning:[/yellow] features.enable_graph is false")
        console.print("Set it to true in config.yaml or pass anyway.")

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:  [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:  [green]{config.target.path_or_url}[/green]",
        title="[bold]Code Graph[/bold]",
    ))

    ctx.mark_running()
    try:
        units_art, graph_art = build_graph(config)
        save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)

        ctx.result.stats.nodes_parsed = len(units_art.units)
        ctx.result.stats.edges_built = len(graph_art.edges)
        ctx.mark_completed()
    except Exception:
        ctx.mark_failed("graph build failed")
        console.print("[red]Graph build failed.[/red] Check run.log for details.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    summary = Table(title="Code Graph Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Code units", str(len(units_art.units)))
    summary.add_row("Graph nodes", str(len(graph_art.nodes)))
    summary.add_row("Graph edges", str(len(graph_art.edges)))
    console.print(summary)

    # Units by language
    from collections import Counter
    lang_counts = Counter(u.language for u in units_art.units)
    if lang_counts:
        lang_table = Table(title="Units by Language")
        lang_table.add_column("Language", style="cyan")
        lang_table.add_column("Units", style="green", justify="right")
        for lang, cnt in lang_counts.most_common():
            lang_table.add_row(lang, str(cnt))
        console.print(lang_table)

    # Top edges
    if graph_art.edges:
        edge_table = Table(title="Call Edges (sample)")
        edge_table.add_column("Caller", style="green")
        edge_table.add_column("Callee", style="yellow")
        for edge in graph_art.edges[:15]:
            caller_short = edge.from_unit_id.split("::")[-1] if "::" in edge.from_unit_id else edge.from_unit_id
            edge_table.add_row(caller_short, edge.to_symbol)
        console.print(edge_table)

    console.print(f"\n[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"[cyan]Log:      [/cyan] [green]{ctx.log_file.resolve()}[/green]")
    console.print(f"\n[bold green]Graph build complete.[/bold green]")


# ── static ────────────────────────────────────────────────


@app.command()
def static(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Run static analysis (recon + graph + semgrep/codeql)."""
    from cve_agent.config import load_config
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        console.print("Run [bold]cve-agent init[/bold] to create one.")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] static requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    # Tool availability check
    from cve_agent.analyzers.semgrep_scanner import is_semgrep_available
    from cve_agent.analyzers.codeql_runner import is_codeql_available

    sg_ok = is_semgrep_available()
    cq_ok = is_codeql_available()

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:   [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:   [green]{config.target.path_or_url}[/green]\n"
        f"Semgrep:  {'[green]available[/green]' if sg_ok else '[red]not found[/red]'}\n"
        f"CodeQL:   {'[green]available[/green]' if cq_ok else '[red]not found[/red]'}",
        title="[bold]Static Analysis[/bold]",
    ))

    ctx.mark_running()
    all_findings = []

    try:
        target_dir = Path(config.target.path_or_url).resolve()

        # Phase 1: Recon
        if config.target.type.value == "repo":
            from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts as save_recon
            repo_index, hotspot_index = index_repo(config)
            save_recon(repo_index, hotspot_index, ctx.artifacts_dir)
            ctx.result.stats.indexed_files = repo_index.summary.total_files
            console.print(f"[dim]Recon: {repo_index.summary.total_files} files indexed[/dim]")

        # Phase 2: Graph (if enabled)
        if config.features.enable_graph:
            from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
            units_art, graph_art = build_graph(config)
            save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)
            ctx.result.stats.nodes_parsed = len(units_art.units)
            ctx.result.stats.edges_built = len(graph_art.edges)
            console.print(f"[dim]Graph: {len(units_art.units)} units, {len(graph_art.edges)} edges[/dim]")

        # Phase 3: Semgrep
        if config.features.enable_semgrep:
            from cve_agent.analyzers.semgrep_scanner import run_semgrep
            sg_findings = run_semgrep(
                target_dir,
                artifacts_dir=ctx.artifacts_dir,
                languages=config.target.languages_hint,
            )
            all_findings.extend(sg_findings)

        # Phase 4: CodeQL
        if config.features.enable_codeql:
            from cve_agent.analyzers.codeql_runner import run_codeql
            cq_findings = run_codeql(
                target_dir,
                artifacts_dir=ctx.artifacts_dir,
                languages_hint=config.target.languages_hint,
            )
            all_findings.extend(cq_findings)

        ctx.result.stats.static_candidates = len(all_findings)
        ctx.result.findings.extend(all_findings)
        ctx.mark_completed()

    except Exception:
        ctx.mark_failed("static analysis failed")
        console.print("[red]Static analysis failed.[/red] Check run.log for details.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    summary = Table(title="Static Analysis Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Semgrep", "[green]available[/green]" if sg_ok else "[red]not found[/red]")
    summary.add_row("CodeQL", "[green]available[/green]" if cq_ok else "[red]not found[/red]")
    summary.add_row("Total candidates", str(len(all_findings)))
    console.print(summary)

    if all_findings:
        find_table = Table(title="Finding Candidates")
        find_table.add_column("#", style="dim", width=4)
        find_table.add_column("Severity", width=8)
        find_table.add_column("ID", style="dim", width=14)
        find_table.add_column("Title", style="green")
        find_table.add_column("File", style="cyan")

        for i, f in enumerate(all_findings[:20], 1):
            sev_color = {
                "critical": "red", "high": "red",
                "medium": "yellow", "low": "dim", "info": "dim",
            }.get(f.severity.value, "white")
            loc_file = f.evidence[0].location.file if f.evidence and f.evidence[0].location else "?"
            find_table.add_row(
                str(i),
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f.id,
                f.title[:60],
                loc_file,
            )
        console.print(find_table)
    else:
        if not sg_ok and not cq_ok:
            console.print("\n[yellow]No static analysis tools installed.[/yellow]")
            console.print("Install semgrep: [bold]pip install semgrep[/bold]")
        else:
            console.print("\n[dim]No findings from static analysis.[/dim]")

    console.print(f"\n[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"[cyan]Log:      [/cyan] [green]{ctx.log_file.resolve()}[/green]")
    console.print(f"\n[bold green]Static analysis complete.[/bold green]")


# ── hypothesize ─────────────────────────────────────────


@app.command()
def hypothesize(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Generate vulnerability hypotheses (recon + graph + static + hypothesize)."""
    from cve_agent.config import load_config
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        console.print("Run [bold]cve-agent init[/bold] to create one.")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] hypothesize requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    # Determine LLM mode
    from cve_agent.agents.llm_clients.base import BaseLLMClient
    llm_client: BaseLLMClient | None = None

    if config.llm.enabled:
        if config.llm.provider == "dummy":
            from cve_agent.agents.llm_clients.dummy import DummyLLMClient
            llm_client = DummyLLMClient()
        # Other providers would go here

    mode_label = f"LLM ({llm_client.name})" if llm_client else "offline (rule-based)"

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:  [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:  [green]{config.target.path_or_url}[/green]\n"
        f"Mode:    [cyan]{mode_label}[/cyan]",
        title="[bold]Hypothesis Generation[/bold]",
    ))

    ctx.mark_running()

    try:
        target_dir = Path(config.target.path_or_url).resolve()

        # Phase 1: Recon
        from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts as save_recon
        repo_index, hotspot_index = index_repo(config)
        save_recon(repo_index, hotspot_index, ctx.artifacts_dir)
        ctx.result.stats.indexed_files = repo_index.summary.total_files
        console.print(f"[dim]Recon: {repo_index.summary.total_files} files indexed[/dim]")

        # Phase 2: Graph (if enabled)
        if config.features.enable_graph:
            from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
            units_art, graph_art = build_graph(config)
            save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)
            ctx.result.stats.nodes_parsed = len(units_art.units)
            ctx.result.stats.edges_built = len(graph_art.edges)
            console.print(f"[dim]Graph: {len(units_art.units)} units, {len(graph_art.edges)} edges[/dim]")

        # Phase 3: Static (semgrep/codeql)
        if config.features.enable_semgrep:
            from cve_agent.analyzers.semgrep_scanner import run_semgrep
            sg = run_semgrep(target_dir, artifacts_dir=ctx.artifacts_dir)
            ctx.result.findings.extend(sg)
            console.print(f"[dim]Semgrep: {len(sg)} candidates[/dim]")

        if config.features.enable_codeql:
            from cve_agent.analyzers.codeql_runner import run_codeql
            cq = run_codeql(target_dir, artifacts_dir=ctx.artifacts_dir, languages_hint=config.target.languages_hint)
            ctx.result.findings.extend(cq)
            console.print(f"[dim]CodeQL: {len(cq)} candidates[/dim]")

        # Phase 4: Hypothesis
        from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses

        hyp_findings = generate_hypotheses(
            config,
            ctx.artifacts_dir,
            llm_client=llm_client,
        )
        save_hypotheses(hyp_findings, ctx.artifacts_dir)
        ctx.result.stats.hypotheses_generated = len(hyp_findings)
        ctx.mark_completed()

    except Exception:
        ctx.mark_failed("hypothesis generation failed")
        console.print("[red]Hypothesis generation failed.[/red] Check run.log.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    summary = Table(title="Hypothesis Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Mode", mode_label)
    summary.add_row("Hypotheses generated", str(len(hyp_findings)))
    console.print(summary)

    if hyp_findings:
        hyp_table = Table(title="Hypotheses")
        hyp_table.add_column("#", style="dim", width=4)
        hyp_table.add_column("Vuln Type", style="red", width=22)
        hyp_table.add_column("Conf", style="yellow", width=6)
        hyp_table.add_column("File", style="cyan")
        hyp_table.add_column("Attack Surface", style="green")

        for i, f in enumerate(hyp_findings[:15], 1):
            loc = f.evidence[0].location.file if f.evidence and f.evidence[0].location else "?"
            vt = f.hypothesis.vuln_type if f.hypothesis else "?"
            conf = f"{f.hypothesis.confidence:.2f}" if f.hypothesis else "?"
            surface = (f.hypothesis.attack_surface[:40] + "...") if f.hypothesis and len(f.hypothesis.attack_surface) > 40 else (f.hypothesis.attack_surface if f.hypothesis else "?")
            hyp_table.add_row(str(i), vt, conf, loc, surface)
        console.print(hyp_table)

    console.print(f"\n[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"[cyan]Log:      [/cyan] [green]{ctx.log_file.resolve()}[/green]")
    console.print(f"\n[bold green]Hypothesis generation complete.[/bold green]")


# ── generate-tests ──────────────────────────────────────


@app.command()
def generate_tests(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Generate tests but skip execution",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Generate verification tests and harnesses from hypotheses."""
    from cve_agent.config import load_config
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        console.print("Run [bold]cve-agent init[/bold] to create one.")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] generate-tests requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:   [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:   [green]{config.target.path_or_url}[/green]\n"
        f"Dry-run:  {'[yellow]yes[/yellow]' if dry_run else '[green]no[/green]'}",
        title="[bold]Test Generation[/bold]",
    ))

    ctx.mark_running()

    try:
        target_dir = Path(config.target.path_or_url).resolve()

        # Phase 1: Recon
        from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts as save_recon
        repo_index, hotspot_index = index_repo(config)
        save_recon(repo_index, hotspot_index, ctx.artifacts_dir)
        console.print(f"[dim]Recon: {repo_index.summary.total_files} files indexed[/dim]")

        # Phase 2: Graph (if enabled)
        if config.features.enable_graph:
            from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
            units_art, graph_art = build_graph(config)
            save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)
            console.print(f"[dim]Graph: {len(units_art.units)} units[/dim]")

        # Phase 3: Static
        if config.features.enable_semgrep:
            from cve_agent.analyzers.semgrep_scanner import run_semgrep
            run_semgrep(target_dir, artifacts_dir=ctx.artifacts_dir)

        if config.features.enable_codeql:
            from cve_agent.analyzers.codeql_runner import run_codeql
            run_codeql(target_dir, artifacts_dir=ctx.artifacts_dir, languages_hint=config.target.languages_hint)

        # Phase 4: Hypothesis
        from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses
        llm_client = None
        if config.llm.enabled and config.llm.provider == "dummy":
            from cve_agent.agents.llm_clients.dummy import DummyLLMClient
            llm_client = DummyLLMClient()

        hyp_findings = generate_hypotheses(
            config, ctx.artifacts_dir, llm_client=llm_client,
        )
        save_hypotheses(hyp_findings, ctx.artifacts_dir)
        console.print(f"[dim]Hypotheses: {len(hyp_findings)} generated[/dim]")

        # Phase 5: Test Generation
        from cve_agent.fuzz.test_generator import generate_tests_for_findings
        from cve_agent.fuzz.harness_generator import generate_harness_for_finding
        from cve_agent.fuzz.self_correction import run_all_tests, save_fuzz_attempts

        attempts = generate_tests_for_findings(hyp_findings, ctx.artifacts_dir)

        # C/C++ harnesses
        for hf in hyp_findings:
            c_attempt = generate_harness_for_finding(hf, ctx.artifacts_dir)
            if c_attempt:
                attempts.append(c_attempt)

        # Self-correction
        attempts = run_all_tests(attempts, ctx.artifacts_dir, dry_run=dry_run)

        save_fuzz_attempts(attempts, ctx.artifacts_dir)
        ctx.result.stats.harnesses_created = len(attempts)
        ctx.result.stats.executions_run = sum(a.get("iterations", 0) for a in attempts)
        ctx.mark_completed()

    except Exception:
        ctx.mark_failed("test generation failed")
        console.print("[red]Test generation failed.[/red] Check run.log.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    summary = Table(title="Test Generation Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Tests generated", str(len(attempts)))
    summary.add_row("Executions", str(ctx.result.stats.executions_run))

    status_counts: dict[str, int] = {}
    for a in attempts:
        s = a.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1
    for s, c in sorted(status_counts.items()):
        summary.add_row(f"  {s}", str(c))
    console.print(summary)

    if attempts:
        att_table = Table(title="Generated Tests")
        att_table.add_column("#", style="dim", width=4)
        att_table.add_column("Finding", style="dim", width=14)
        att_table.add_column("Vuln Type", style="red", width=22)
        att_table.add_column("Status", width=10)
        att_table.add_column("File", style="cyan")

        for i, a in enumerate(attempts[:20], 1):
            status_color = {
                "verified": "green", "partial": "yellow",
                "failed": "red", "generated": "dim",
                "dry_run": "cyan",
            }.get(a["status"], "white")
            att_table.add_row(
                str(i),
                a["finding_id"][:12],
                a.get("vuln_type", "?"),
                f"[{status_color}]{a['status']}[/{status_color}]",
                a.get("test_file", a.get("harness_file", "?"))[:50],
            )
        console.print(att_table)

    console.print(f"\n[cyan]Harnesses:[/cyan] [green]{(ctx.artifacts_dir / 'harnesses').resolve()}[/green]")
    console.print(f"[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"[cyan]Log:      [/cyan] [green]{ctx.log_file.resolve()}[/green]")
    console.print(f"\n[bold green]Test generation complete.[/bold green]")


# ── execute ───────────────────────────────────────────


@app.command()
def execute(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Skip actual execution — validate structure only",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Run generated tests in sandbox, produce validation results."""
    from cve_agent.config import load_config
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] execute requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    # Docker availability
    from cve_agent.sandbox.docker_runner import is_docker_available
    docker_ok = is_docker_available()
    exec_mode = "dry-run" if dry_run else ("Docker" if docker_ok else "local")

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:    [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:    [green]{config.target.path_or_url}[/green]\n"
        f"Execution: [cyan]{exec_mode}[/cyan]\n"
        f"Network:   {'[red]OFF[/red]' if config.sandbox.network_off else '[yellow]ON[/yellow]'}\n"
        f"Timeout:   {config.sandbox.timeout_sec}s",
        title="[bold]Sandbox Execution[/bold]",
    ))

    ctx.mark_running()

    try:
        target_dir = Path(config.target.path_or_url).resolve()

        # Phase 1: Recon
        from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts as save_recon
        repo_index, hotspot_index = index_repo(config)
        save_recon(repo_index, hotspot_index, ctx.artifacts_dir)
        console.print(f"[dim]Recon: {repo_index.summary.total_files} files[/dim]")

        # Phase 2: Graph
        if config.features.enable_graph:
            from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
            units_art, graph_art = build_graph(config)
            save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)
            console.print(f"[dim]Graph: {len(units_art.units)} units[/dim]")

        # Phase 3: Static
        if config.features.enable_semgrep:
            from cve_agent.analyzers.semgrep_scanner import run_semgrep
            run_semgrep(target_dir, artifacts_dir=ctx.artifacts_dir)
        if config.features.enable_codeql:
            from cve_agent.analyzers.codeql_runner import run_codeql
            run_codeql(target_dir, artifacts_dir=ctx.artifacts_dir, languages_hint=config.target.languages_hint)

        # Phase 4: Hypothesis
        from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses
        llm_client = None
        if config.llm.enabled and config.llm.provider == "dummy":
            from cve_agent.agents.llm_clients.dummy import DummyLLMClient
            llm_client = DummyLLMClient()
        hyp_findings = generate_hypotheses(config, ctx.artifacts_dir, llm_client=llm_client)
        save_hypotheses(hyp_findings, ctx.artifacts_dir)
        console.print(f"[dim]Hypotheses: {len(hyp_findings)}[/dim]")

        # Phase 5: Test generation
        from cve_agent.fuzz.test_generator import generate_tests_for_findings
        from cve_agent.fuzz.harness_generator import generate_harness_for_finding
        from cve_agent.fuzz.self_correction import save_fuzz_attempts
        attempts = generate_tests_for_findings(hyp_findings, ctx.artifacts_dir)
        for hf in hyp_findings:
            c_attempt = generate_harness_for_finding(hf, ctx.artifacts_dir)
            if c_attempt:
                attempts.append(c_attempt)
        save_fuzz_attempts(attempts, ctx.artifacts_dir)
        console.print(f"[dim]Tests: {len(attempts)} generated[/dim]")

        # Phase 6: Execution
        from cve_agent.analyzers.execution import (
            execute_validations, save_validation_results,
            create_evidence_from_outcome,
        )
        validation = execute_validations(
            ctx.artifacts_dir,
            sandbox_cfg=config.sandbox,
            features_cfg=config.features,
            repo_dir=target_dir if target_dir.is_dir() else None,
            dry_run=dry_run,
        )
        save_validation_results(validation, ctx.artifacts_dir)

        ctx.result.stats.executions_run = validation.total
        ctx.result.stats.findings_confirmed = validation.success
        ctx.mark_completed()

    except Exception:
        ctx.mark_failed("execution failed")
        console.print("[red]Execution failed.[/red] Check run.log.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    summary = Table(title="Execution Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Mode", exec_mode)
    summary.add_row("Total executions", str(validation.total))
    summary.add_row("Success", f"[green]{validation.success}[/green]")
    summary.add_row("Failure", f"[red]{validation.failure}[/red]")
    summary.add_row("Crash", f"[red]{validation.crash}[/red]")
    summary.add_row("Timeout", f"[yellow]{validation.timeout}[/yellow]")
    summary.add_row("Skipped", str(validation.skipped))
    console.print(summary)

    if validation.outcomes:
        out_table = Table(title="Validation Results")
        out_table.add_column("#", style="dim", width=4)
        out_table.add_column("Finding", style="dim", width=14)
        out_table.add_column("Status", width=10)
        out_table.add_column("P/F", width=8)
        out_table.add_column("Time", width=8)
        out_table.add_column("File", style="cyan")

        for i, o in enumerate(validation.outcomes[:20], 1):
            sc = {"success": "green", "failure": "red", "crash": "red",
                  "timeout": "yellow", "dry_run": "cyan"}.get(o.status, "white")
            out_table.add_row(
                str(i),
                o.finding_id[:12],
                f"[{sc}]{o.status}[/{sc}]",
                f"{o.passed_count}/{o.failed_count}",
                f"{o.duration_sec:.1f}s",
                o.test_file[:45],
            )
        console.print(out_table)

    console.print(f"\n[cyan]Results:  [/cyan] [green]{(ctx.artifacts_dir / 'validation_results.json').resolve()}[/green]")
    console.print(f"[cyan]Logs:     [/cyan] [green]{(ctx.artifacts_dir / 'logs').resolve()}[/green]")
    console.print(f"[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"\n[bold green]Execution complete.[/bold green]")


# ── triage ────────────────────────────────────────────


@app.command()
def triage(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Skip test execution, run triage on existing artifacts",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Assess findings conservatively (recon + graph + static + hypothesis + tests + triage)."""
    from cve_agent.config import load_config
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] triage requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:  [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:  [green]{config.target.path_or_url}[/green]",
        title="[bold]Triage Assessment[/bold]",
    ))

    ctx.mark_running()

    try:
        target_dir = Path(config.target.path_or_url).resolve()

        # Phase 1: Recon
        from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts as save_recon
        repo_index, hotspot_index = index_repo(config)
        save_recon(repo_index, hotspot_index, ctx.artifacts_dir)
        console.print(f"[dim]Recon: {repo_index.summary.total_files} files[/dim]")

        # Phase 2: Graph
        if config.features.enable_graph:
            from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
            units_art, graph_art = build_graph(config)
            save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)
            console.print(f"[dim]Graph: {len(units_art.units)} units[/dim]")

        # Phase 3: Static
        if config.features.enable_semgrep:
            from cve_agent.analyzers.semgrep_scanner import run_semgrep
            run_semgrep(target_dir, artifacts_dir=ctx.artifacts_dir)
        if config.features.enable_codeql:
            from cve_agent.analyzers.codeql_runner import run_codeql
            run_codeql(target_dir, artifacts_dir=ctx.artifacts_dir, languages_hint=config.target.languages_hint)

        # Phase 4: Hypothesis
        from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses
        llm_client = None
        if config.llm.enabled and config.llm.provider == "dummy":
            from cve_agent.agents.llm_clients.dummy import DummyLLMClient
            llm_client = DummyLLMClient()
        hyp_findings = generate_hypotheses(config, ctx.artifacts_dir, llm_client=llm_client)
        save_hypotheses(hyp_findings, ctx.artifacts_dir)
        console.print(f"[dim]Hypotheses: {len(hyp_findings)}[/dim]")

        # Phase 5: Test generation + execution
        from cve_agent.fuzz.test_generator import generate_tests_for_findings
        from cve_agent.fuzz.harness_generator import generate_harness_for_finding
        from cve_agent.fuzz.self_correction import save_fuzz_attempts
        attempts = generate_tests_for_findings(hyp_findings, ctx.artifacts_dir)
        for hf in hyp_findings:
            c_attempt = generate_harness_for_finding(hf, ctx.artifacts_dir)
            if c_attempt:
                attempts.append(c_attempt)
        save_fuzz_attempts(attempts, ctx.artifacts_dir)
        console.print(f"[dim]Tests: {len(attempts)} generated[/dim]")

        from cve_agent.analyzers.execution import (
            execute_validations, save_validation_results,
        )
        validation = execute_validations(
            ctx.artifacts_dir,
            sandbox_cfg=config.sandbox,
            features_cfg=config.features,
            repo_dir=target_dir if target_dir.is_dir() else None,
            dry_run=dry_run,
        )
        save_validation_results(validation, ctx.artifacts_dir)
        console.print(f"[dim]Validation: {validation.total} executed[/dim]")

        # Phase 6: Triage
        from cve_agent.triage.triage_agent import (
            run_triage, save_triage_report, save_final_findings,
        )
        triage_report, triaged_findings = run_triage(ctx.artifacts_dir)
        save_triage_report(triage_report, ctx.artifacts_dir)
        save_final_findings(triaged_findings, ctx.artifacts_dir)
        ctx.result.stats.findings_confirmed = triage_report.confirmed
        ctx.mark_completed()

    except Exception:
        ctx.mark_failed("triage failed")
        console.print("[red]Triage failed.[/red] Check run.log.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    summary = Table(title="Triage Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Count", style="green")
    summary.add_row("Total findings", str(triage_report.total))
    summary.add_row("Confirmed", f"[red]{triage_report.confirmed}[/red]")
    summary.add_row("Potential", f"[yellow]{triage_report.potential}[/yellow]")
    summary.add_row("False Positive", f"[green]{triage_report.false_positive}[/green]")
    summary.add_row("Candidate", str(triage_report.candidate))
    console.print(summary)

    if triage_report.verdicts:
        vt = Table(title="Verdicts")
        vt.add_column("#", style="dim", width=4)
        vt.add_column("Finding", style="dim", width=14)
        vt.add_column("Before", width=12)
        vt.add_column("After", width=14)
        vt.add_column("Rationale", style="dim")

        for i, v in enumerate(triage_report.verdicts[:20], 1):
            sc = {"confirmed": "red", "potential": "yellow",
                  "false_positive": "green"}.get(v.new_status, "white")
            rationale = v.rationale[:60] + "..." if len(v.rationale) > 60 else v.rationale
            vt.add_row(
                str(i),
                v.finding_id[:12],
                v.previous_status,
                f"[{sc}]{v.new_status}[/{sc}]",
                rationale,
            )
        console.print(vt)

    console.print(f"\n[cyan]Triage:   [/cyan] [green]{(ctx.artifacts_dir / 'triage.json').resolve()}[/green]")
    console.print(f"[cyan]Findings: [/cyan] [green]{(ctx.artifacts_dir / 'findings.json').resolve()}[/green]")
    console.print(f"[cyan]Artifacts:[/cyan] [green]{ctx.artifacts_dir.resolve()}[/green]")
    console.print(f"\n[bold green]Triage complete.[/bold green]")


# ── report ────────────────────────────────────────────


@app.command()
def report(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Skip execution, run all stages with dry-run",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Generate REPORT.md + evidence_bundle.zip (full pipeline)."""
    from cve_agent.config import load_config
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    if config.target.type.value != "repo":
        console.print("[red]Error:[/red] report requires target.type = repo")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:  [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:  [green]{config.target.path_or_url}[/green]",
        title="[bold]Report Generation[/bold]",
    ))

    ctx.mark_running()

    try:
        target_dir = Path(config.target.path_or_url).resolve()

        # Phase 1: Recon
        from cve_agent.analyzers.repo_indexer import index_repo, save_artifacts as save_recon
        repo_index, hotspot_index = index_repo(config)
        save_recon(repo_index, hotspot_index, ctx.artifacts_dir)
        console.print(f"[dim]Recon: {repo_index.summary.total_files} files[/dim]")

        # Phase 2: Graph
        if config.features.enable_graph:
            from cve_agent.graph.call_graph import build_graph, save_graph_artifacts
            units_art, graph_art = build_graph(config)
            save_graph_artifacts(units_art, graph_art, ctx.artifacts_dir)
            console.print(f"[dim]Graph: {len(units_art.units)} units[/dim]")

        # Phase 3: Static
        if config.features.enable_semgrep:
            from cve_agent.analyzers.semgrep_scanner import run_semgrep
            run_semgrep(target_dir, artifacts_dir=ctx.artifacts_dir)
        if config.features.enable_codeql:
            from cve_agent.analyzers.codeql_runner import run_codeql
            run_codeql(target_dir, artifacts_dir=ctx.artifacts_dir, languages_hint=config.target.languages_hint)

        # Phase 4: Hypothesis
        from cve_agent.agents.hypothesis_agent import generate_hypotheses, save_hypotheses
        llm_client = None
        if config.llm.enabled and config.llm.provider == "dummy":
            from cve_agent.agents.llm_clients.dummy import DummyLLMClient
            llm_client = DummyLLMClient()
        hyp_findings = generate_hypotheses(config, ctx.artifacts_dir, llm_client=llm_client)
        save_hypotheses(hyp_findings, ctx.artifacts_dir)
        console.print(f"[dim]Hypotheses: {len(hyp_findings)}[/dim]")

        # Phase 5: Test generation + execution
        from cve_agent.fuzz.test_generator import generate_tests_for_findings
        from cve_agent.fuzz.harness_generator import generate_harness_for_finding
        from cve_agent.fuzz.self_correction import save_fuzz_attempts
        attempts = generate_tests_for_findings(hyp_findings, ctx.artifacts_dir)
        for hf in hyp_findings:
            c_attempt = generate_harness_for_finding(hf, ctx.artifacts_dir)
            if c_attempt:
                attempts.append(c_attempt)
        save_fuzz_attempts(attempts, ctx.artifacts_dir)

        from cve_agent.analyzers.execution import (
            execute_validations, save_validation_results,
        )
        validation = execute_validations(
            ctx.artifacts_dir,
            sandbox_cfg=config.sandbox,
            features_cfg=config.features,
            repo_dir=target_dir if target_dir.is_dir() else None,
            dry_run=dry_run,
        )
        save_validation_results(validation, ctx.artifacts_dir)
        console.print(f"[dim]Tests: {len(attempts)} generated, {validation.total} executed[/dim]")

        # Phase 6: Triage
        from cve_agent.triage.triage_agent import (
            run_triage, save_triage_report, save_final_findings,
        )
        triage_report, triaged_findings = run_triage(ctx.artifacts_dir)
        save_triage_report(triage_report, ctx.artifacts_dir)
        save_final_findings(triaged_findings, ctx.artifacts_dir)
        console.print(
            f"[dim]Triage: {triage_report.confirmed} confirmed, "
            f"{triage_report.potential} potential, "
            f"{triage_report.false_positive} false positive[/dim]"
        )

        # Phase 7: Report
        from cve_agent.reporting.report_md import generate_report_md, save_report
        from cve_agent.reporting.bundler import create_evidence_bundle

        report_text = generate_report_md(
            triaged_findings,
            triage_report,
            run_id=ctx.run_id,
            target=config.target.path_or_url,
        )
        report_path = save_report(report_text, ctx.run_dir)
        bundle_path = create_evidence_bundle(ctx.run_dir, ctx.artifacts_dir)

        ctx.result.stats.findings_confirmed = triage_report.confirmed
        ctx.mark_completed()

    except Exception:
        ctx.mark_failed("report generation failed")
        console.print("[red]Report generation failed.[/red] Check run.log.")
        raise typer.Exit(1)

    # ── Summary ──────────────────────────────────────────
    console.print(Panel.fit(
        f"[bold green]Report generated successfully![/bold green]\n\n"
        f"[cyan]REPORT.md:[/cyan]      [green]{report_path.resolve()}[/green]\n"
        f"[cyan]Evidence ZIP:[/cyan]   [green]{bundle_path.resolve()}[/green]\n"
        f"[cyan]Artifacts:[/cyan]      [green]{ctx.artifacts_dir.resolve()}[/green]\n\n"
        f"Findings: {triage_report.total} total, "
        f"[red]{triage_report.confirmed}[/red] confirmed, "
        f"[yellow]{triage_report.potential}[/yellow] potential",
        title="[bold]Report Complete[/bold]",
    ))


# ── run ───────────────────────────────────────────────────


@app.command()
def run(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Path to config.yaml",
    ),
    run_id: Optional[str] = typer.Option(
        None, "--run-id", "-r", help="Custom run ID (auto-generated if not set)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Verbose logging",
    ),
) -> None:
    """Run the full vulnerability detection pipeline end-to-end."""
    from cve_agent.config import load_config
    from cve_agent.pipeline import run_pipeline
    from cve_agent.run_context import RunContext

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        console.print(f"[red]Error:[/red] Config not found: {cfg_path}")
        console.print("Run [bold]cve-agent init[/bold] to create one.")
        raise typer.Exit(1)

    try:
        config = load_config(cfg_path)
    except Exception as e:
        console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(1)

    ctx = RunContext(config, run_id=run_id, verbose=verbose)

    # Banner
    budget_info = ""
    if config.budget.max_tokens or config.budget.max_cost_usd:
        budget_info = f"\nBudget:  max_tokens={config.budget.max_tokens}, max_cost=${config.budget.max_cost_usd}"
    console.print(Panel.fit(
        f"[bold cyan]ZeroMint v{__version__}[/bold cyan]\n"
        f"Run ID:  [yellow]{ctx.run_id}[/yellow]\n"
        f"Target:  [green]{config.target.path_or_url}[/green] ({config.target.type.value})\n"
        f"LLM:     {'[green]enabled[/green]' if config.llm.enabled else '[dim]disabled[/dim]'}\n"
        f"Sandbox: {'[green]enabled[/green]' if config.sandbox.enabled else '[dim]disabled[/dim]'}\n"
        f"Fail:    {'[yellow]continue[/yellow]' if config.continue_on_fail else 'abort'}"
        f"{budget_info}",
        title="[bold]Pipeline Run[/bold]",
    ))

    # Execute pipeline
    try:
        run_pipeline(ctx)
    except Exception:
        console.print("[red]Pipeline failed.[/red] Check run.log for details.")
        raise typer.Exit(1)

    # Summary
    r = ctx.result
    summary = Table(title="Run Summary")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Value", style="green")
    summary.add_row("Status", f"[{'green' if r.status.value == 'completed' else 'red'}]{r.status.value}[/]")
    summary.add_row("Files indexed", str(r.stats.indexed_files))
    summary.add_row("Static candidates", str(r.stats.static_candidates))
    summary.add_row("Hypotheses", str(r.stats.hypotheses_generated))
    summary.add_row("Harnesses", str(r.stats.harnesses_created))
    summary.add_row("Executions", str(r.stats.executions_run))
    summary.add_row("Findings", str(len(r.findings)))
    summary.add_row("Confirmed", f"[red]{r.stats.findings_confirmed}[/red]")
    if r.stats.llm_tokens_used:
        summary.add_row("LLM tokens", str(r.stats.llm_tokens_used))
        summary.add_row("LLM cost", f"${r.stats.llm_cost_usd:.4f}")
    console.print(summary)

    # Stage status table
    state_path = ctx.artifact_path("pipeline_state.json")
    if state_path.exists():
        import json as _json
        state = _json.loads(state_path.read_text(encoding="utf-8"))
        st = Table(title="Pipeline Stages")
        st.add_column("#", style="dim", width=4)
        st.add_column("Stage", width=14)
        st.add_column("Status", width=12)
        st.add_column("Error", style="dim")
        for i, s in enumerate(state.get("stages", []), 1):
            sc = {"completed": "green", "skipped": "yellow", "failed": "red"}.get(s["status"], "white")
            err = s.get("error") or ""
            if len(err) > 50:
                err = err[:50] + "..."
            st.add_row(str(i), s["name"], f"[{sc}]{s['status']}[/{sc}]", err)
        console.print(st)

    console.print(f"\n[cyan]Run dir:[/cyan]    [green]{ctx.run_dir.resolve()}[/green]")
    console.print(f"[cyan]Log:    [/cyan]    [green]{ctx.log_file.resolve()}[/green]")

    report_path = ctx.run_dir / "REPORT.md"
    if report_path.exists():
        console.print(f"[cyan]Report: [/cyan]    [green]{report_path.resolve()}[/green]")

    bundle_path = ctx.run_dir / "evidence_bundle.zip"
    if bundle_path.exists():
        console.print(f"[cyan]Bundle: [/cyan]    [green]{bundle_path.resolve()}[/green]")

    status_color = "green" if r.status.value == "completed" else "red"
    console.print(f"\n[bold {status_color}]Status: {r.status.value}[/bold {status_color}]")


# ── version ───────────────────────────────────────────────


@app.command()
def version() -> None:
    """Show version."""
    console.print(f"ZeroMint v{__version__}")


if __name__ == "__main__":
    app()
