"""Rich terminal renderer for scan results."""

from rich.console import Console

SEVERITY_SYMBOL = {
    "critical": "[bold red]X CRITICAL[/]",
    "high": "[red]X HIGH[/]",
    "medium": "[yellow]! MEDIUM[/]",
    "low": "[blue]i LOW[/]",
}


def render_summary(target: str, score: int, verdict: str, findings: list[dict]) -> None:
    console = Console()
    console.print()
    console.print("[bold]nyuwaymcpscanner[/] - Baseline Scan")
    console.print("-" * 50)
    console.print(f"Target:     {target}")
    console.print(f"Risk Score: {score} / 100  [{verdict}]")
    console.print()

    if not findings:
        console.print("[green]+ PASS[/]   No findings.")
    else:
        console.print("Findings:")
        for f in findings:
            sev = SEVERITY_SYMBOL.get(
                f.get("severity", "low"), f.get("severity", "low")
            )
            label = f.get("type", "finding")
            location = f.get("file") or f.get("package") or ""
            description = f.get("description") or f.get("label") or f.get("rule") or ""
            console.print(f"  {sev}   {label}  {description}  {location}")

    console.print()
    console.print("[dim]Powered by nyuwaymcpscanner - nyuway.ai[/]")
