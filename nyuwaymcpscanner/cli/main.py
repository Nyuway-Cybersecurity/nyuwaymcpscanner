import json
from pathlib import Path

import click

from nyuwaymcpscanner.scanners.secrets import scan_secrets
from nyuwaymcpscanner.scanners.yara_engine import run_yara
from nyuwaymcpscanner.scanners.supply_chain import scan_supply_chain
from nyuwaymcpscanner.scanners.virustotal import (
    scan_virustotal,
    resolve_api_key,
    count_binaries,
    VTKeyMissing,
)
from nyuwaymcpscanner.scanners.manifest import parse_manifest
from nyuwaymcpscanner.scanners.llm_safety import (
    run_local_llm_analysis,
    OllamaUnavailable,
)
from nyuwaymcpscanner.output.scoring import calculate_score
from nyuwaymcpscanner.output.terminal import render_summary
from nyuwaymcpscanner.output.json_report import render_json
from nyuwaymcpscanner.output.sarif_report import render_sarif
from nyuwaymcpscanner.setup.local_llm import run_setup, SetupError, RECOMMENDED_MODEL
from nyuwaymcpscanner.sources import (
    resolve as resolve_source,
    UnsupportedSource,
    GitHubFetchError,
    NpmFetchError,
    PyPIFetchError,
)
from nyuwaymcpscanner.sources.config import parse_config, ConfigParseError

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Common locations for an MCP manifest inside a project tree.
MANIFEST_CANDIDATES = ("mcp.json", "manifest.json", "mcp_manifest.json")


@click.group()
def cli():
    """nyuwaymcpscanner - Enterprise MCP security scanner."""
    pass


@cli.command()
@click.argument("target")
@click.option(
    "--static-only", is_flag=True, help="Skip local LLM layer, static analysis only."
)
@click.option(
    "--offline", is_flag=True, help="Skip all network calls (no OSV.dev CVE lookup)."
)
@click.option("--deep", is_flag=True, help="Deep Scan (private beta, invite required).")
@click.option("--token", default=None, help="Invite token for Deep Scan beta.")
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Exit with non-zero status if any finding meets or exceeds this severity.",
)
@click.option(
    "--output", type=click.Choice(["summary", "json", "sarif"]), default="summary"
)
@click.option(
    "--batch", is_flag=True, help="Treat TARGET as a file containing a list of servers."
)
@click.option(
    "--config",
    "config_file",
    is_flag=True,
    help="Treat TARGET as an MCP host config (claude_desktop_config.json, etc) and scan each declared server.",
)
@click.option(
    "--model", default=RECOMMENDED_MODEL, help="Ollama model for the local LLM layer."
)
@click.option(
    "--vt-key",
    default=None,
    envvar="VIRUSTOTAL_API_KEY",
    help="VirusTotal API key for binary malware hash lookup (or set VIRUSTOTAL_API_KEY env var).",
)
def scan(
    target,
    static_only,
    offline,
    deep,
    token,
    fail_on,
    output,
    batch,
    config_file,
    model,
    vt_key,
):
    """Scan an MCP server."""
    if deep:
        if not token:
            click.echo(
                "Deep Scan is currently in private beta and requires an invite token.\n"
                "Request access at: https://forms.gle/bH8nToK9Zh7ey5F46",
                err=True,
            )
            raise SystemExit(1)
        click.echo("Deep Scan backend not yet implemented.", err=True)
        raise SystemExit(2)

    if batch and config_file:
        click.echo("Error: --batch and --config are mutually exclusive.", err=True)
        raise SystemExit(2)

    targets = _resolve_targets(target, batch, config_file)
    aggregate: list[dict] = []

    for tgt in targets:
        try:
            # Single-file target: scan parent dir, filter findings to this file.
            tgt_path = Path(tgt)
            single_file: Path | None = None
            if tgt_path.is_file() and not _is_source_prefix(tgt):
                single_file = tgt_path.resolve()
                scan_tgt = str(tgt_path.parent)
            else:
                scan_tgt = tgt

            with resolve_source(scan_tgt) as local_path:
                findings: list[dict] = []
                local_str = str(local_path)
                try:
                    findings.extend(scan_secrets(local_str))
                    findings.extend(run_yara(local_str))
                    # Skip supply chain when scanning a single non-dependency
                    # file - walking the parent dir would pick up unrelated
                    # requirements.txt files and produce misleading CVE findings.
                    if single_file is None or _is_dependency_file(single_file):
                        findings.extend(scan_supply_chain(local_str, offline=offline))
                    if not offline:
                        vt_api_key = resolve_api_key(vt_key)
                        if vt_api_key:
                            try:
                                findings.extend(scan_virustotal(local_str, vt_api_key))
                            except VTKeyMissing:
                                pass
                        else:
                            binary_count = count_binaries(local_str)
                            if binary_count:
                                click.echo(
                                    f"Note: {binary_count} binary file{'s' if binary_count != 1 else ''} not checked for malware - "
                                    f"set VIRUSTOTAL_API_KEY for hash-based detection (free at virustotal.com).",
                                    err=True,
                                )
                except FileNotFoundError as e:
                    click.echo(f"Error: {e}", err=True)
                    raise SystemExit(2)

                if not static_only:
                    llm_findings = _run_local_llm_layer(local_str, model)
                    findings.extend(llm_findings)

                # Restrict to the single file when requested.
                if single_file is not None:
                    # Tag only LLM findings (no file field, source=local_llm)
                    # with the single file so they pass the filter. Do NOT tag
                    # supply chain / other findings - they would be misleading.
                    for f in findings:
                        if not f.get("file") and f.get("source") == "local_llm":
                            f["file"] = str(single_file)
                    findings = _filter_findings_to_file(findings, single_file)

                score, verdict = calculate_score(findings)

                if output == "json":
                    click.echo(render_json(tgt, score, verdict, findings))
                elif output == "sarif":
                    click.echo(render_sarif(tgt, score, verdict, findings))
                else:
                    render_summary(tgt, score, verdict, findings)

                aggregate.extend(findings)
        except (
            UnsupportedSource,
            GitHubFetchError,
            NpmFetchError,
            PyPIFetchError,
            FileNotFoundError,
        ) as e:
            click.echo(f"Error fetching source {tgt!r}: {e}", err=True)
            raise SystemExit(2)

    if fail_on:
        threshold = SEVERITY_RANK[fail_on]
        for f in aggregate:
            if SEVERITY_RANK.get(f.get("severity", "low"), 0) >= threshold:
                raise SystemExit(1)


def _run_local_llm_layer(target: str, model: str) -> list[dict]:
    """Locate a manifest under the target tree and run the local LLM analysis.

    On any soft failure (no manifest, Ollama unavailable, parse error) the
    function prints a warning and returns []. It never raises, so the static
    layer's findings are always preserved.
    """
    manifest_path = _find_manifest(target)
    if not manifest_path:
        return []

    try:
        manifest = parse_manifest(str(manifest_path))
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        click.echo(f"Warning: could not parse manifest {manifest_path}: {e}", err=True)
        return []

    try:
        return run_local_llm_analysis(manifest, model=model)
    except OllamaUnavailable as e:
        click.echo(f"Warning: local LLM layer skipped - {e}", err=True)
        click.echo("Use --static-only to suppress this warning.", err=True)
        return []


def _find_manifest(target: str) -> Path | None:
    root = Path(target)
    if root.is_file() and root.suffix == ".json":
        return root
    if root.is_dir():
        for name in MANIFEST_CANDIDATES:
            candidate = root / name
            if candidate.is_file():
                return candidate
    return None


def _is_dependency_file(path: Path) -> bool:
    """Return True if the file is itself a dependency manifest."""
    return path.name.lower() in {
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-test.txt",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pipfile",
        "pipfile.lock",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "poetry.lock",
    }


def _is_source_prefix(target: str) -> bool:
    """Return True if target uses a remote source prefix (github:, npm:, pypi:)."""
    return any(target.startswith(p) for p in ("github:", "npm:", "pypi:"))


def _filter_findings_to_file(findings: list[dict], single_file: Path) -> list[dict]:
    """Keep only findings whose 'file' field resolves to single_file."""
    result = []
    for f in findings:
        finding_file = f.get("file")
        if not finding_file:
            continue
        try:
            if Path(finding_file).resolve() == single_file:
                result.append(f)
        except (TypeError, ValueError):
            continue
    return result


def _resolve_targets(target: str, batch: bool, config_file: bool) -> list[str]:
    if config_file:
        try:
            entries = parse_config(target)
        except ConfigParseError as e:
            click.echo(f"Error: {e}", err=True)
            raise SystemExit(2)
        specs: list[str] = []
        for entry in entries:
            if entry.spec:
                specs.append(entry.spec)
            else:
                click.echo(f"Skipping '{entry.name}': {entry.notes}", err=True)
        if not specs:
            click.echo(f"Error: no scannable servers found in {target}", err=True)
            raise SystemExit(2)
        return specs

    if not batch:
        return [target]
    p = Path(target)
    if not p.is_file():
        click.echo(
            f"Error: --batch target must be a file listing paths: {target}", err=True
        )
        raise SystemExit(2)
    paths: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            paths.append(line)
    if not paths:
        click.echo(f"Error: --batch file contains no paths: {target}", err=True)
        raise SystemExit(2)
    return paths


@cli.command()
@click.option("--model", default=RECOMMENDED_MODEL, help="Ollama model to install.")
def setup(model):
    """Install and configure the local Ollama model for Baseline LLM analysis."""
    click.echo("Setting up local LLM for nyuwaymcpscanner Baseline...")
    click.echo(f"Target model: {model}")
    try:
        status = run_setup(model=model)
    except SetupError as e:
        click.echo(f"\nSetup failed:\n{e}", err=True)
        raise SystemExit(1)

    click.echo("\nSetup complete:")
    click.echo(f"  Ollama installed: {status['ollama_installed']}")
    click.echo(f"  Ollama running:   {status['ollama_running']}")
    click.echo(f"  Model present:    {status['model_present']} ({status['model']})")
    click.echo("\nYou can now run a full Baseline scan with local LLM analysis.")


if __name__ == "__main__":
    cli()
