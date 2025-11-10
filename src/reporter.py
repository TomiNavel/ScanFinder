from datetime import datetime
from typing import List, Tuple
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def show_banner() -> None:
    """Display application banner"""
    console.print(Panel.fit(
        "[bold cyan]ScanFinder - Network Scanner[/bold cyan]\n"
        f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        border_style="cyan"
    ))


def show_scan_info(total: int, workers: int, scan_mode: str) -> None:
    """Display scan information table"""
    info_table = Table(show_header=False, box=None)
    info_table.add_row("- Valid IPs in file:", f"[cyan]{total}[/cyan]")
    info_table.add_row("- Concurrent scans:", f"[cyan]{min(workers, total)}[/cyan]")
    info_table.add_row("- Scan mode:", f"[dim]{scan_mode}[/dim]")
    console.print(info_table)
    console.print()


def save_active_ips(ips: List[str], output_file: Path) -> None:
    """Save scannable IPs to file"""
    with open(output_file, 'w') as f:
        for ip in ips:
            f.write(f"{ip}\n")


def save_portscan_results(
    results: List[Tuple[str, bool, str]],
    output_file: Path,
    input_file: Path,
    total: int
) -> None:
    """Save port scan results to file"""
    with open(output_file, 'w') as f:
        f.write(f"Port Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Input file: {input_file}\n")
        f.write(f"Total IPs scanned: {total}\n")
        f.write("="*60 + "\n\n")
        for ip, has_open, details in results:
            status = "OPEN PORTS FOUND" if has_open else "NO OPEN PORTS / FILTERED"
            f.write(f"\n{'='*60}\nIP: {ip} - {status}\n{'='*60}\n{details}\n")


def show_portscan_summary(results: List[Tuple[str, bool, str]], total: int, output_file: Path, title: str = "SUMMARY") -> None:
    """Display port scan summary"""
    ports_found = sum(1 for _, has_open, _ in results if has_open)

    console.print()
    summary = Table(title=title, show_header=False, border_style="cyan")
    summary.add_row("Total scanned:", f"[cyan]{total}[/cyan]")
    summary.add_row("With open ports:", f"[green]{ports_found}[/green]")
    summary.add_row("No open ports:", f"[red]{total - ports_found}[/red]")
    console.print(summary)
    console.print(f"\n[dim]Results saved:[/dim]")
    console.print(f"  [cyan]{output_file}[/cyan]")


def show_discovery_summary(total: int, scannable_count: int, output_file: Path) -> None:
    """Display host discovery summary"""
    console.print()
    summary = Table(title="SUMMARY", show_header=False, border_style="cyan")
    summary.add_row("Total scanned:", f"[cyan]{total}[/cyan]")
    summary.add_row("Scannable IPs:", f"[green]{scannable_count}[/green]")
    summary.add_row("Non-scannable:", f"[red]{total - scannable_count}[/red]")
    console.print(summary)
    console.print(f"\n[dim]Results saved:[/dim]")
    console.print(f"  [cyan]{output_file}[/cyan]")


def run_followup_portscan(scannable_ips: List[str], workers: int, base_name: str, output_dir: Path, input_file: Path) -> None:
    """Execute port scan after discovery with user interaction"""
    import typer
    from src.scanner import run_portscan

    console.print()
    if not typer.confirm(f"Scan top 1000 ports on the {len(scannable_ips)} scannable IP(s)?", default=True):
        return

    console.print()
    console.print(Panel.fit(
        "[bold cyan]Starting Port Scan[/bold cyan]\n"
        f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        border_style="cyan"
    ))

    show_scan_info(len(scannable_ips), workers, "Port Scan (top 1000)")

    portscan_file = output_dir / f"{base_name}_top1000_scan.txt"
    ps_results = run_portscan(scannable_ips, workers)

    save_portscan_results(ps_results, portscan_file, input_file, len(scannable_ips))
    show_portscan_summary(ps_results, len(scannable_ips), portscan_file, title="PORT SCAN SUMMARY")
