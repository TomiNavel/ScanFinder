#!/usr/bin/env python3
import typer
import shutil
from pathlib import Path
from rich.console import Console

from config import MAX_WORKERS
from src.discovery import run_discovery
from src.scanner import run_portscan
from src.utils import read_ips_from_file
from src.reporter import (
    save_active_ips, save_portscan_results, show_portscan_summary,
    show_discovery_summary, show_banner, show_scan_info, run_followup_portscan
)

console = Console()


def main(
    ctx: typer.Context,
    file: Path = typer.Option(
        None,
        "--file", "-f",
        help="Text file with IPs (one per line, supports comments with #)"
    ),
    workers: int = typer.Option(
        MAX_WORKERS,
        "--workers", "-w",
        help="Number of concurrent scans"
    ),
    output: Path = typer.Option(
        None,
        "--output", "-o",
        help="Output directory (default: current directory)"
    ),
    portscan: bool = typer.Option(
        False,
        "--portscan",
        help="Perform port scan (top 1000 ports)"
    ),
    version: bool = typer.Option(
        False,
        "--version", "-v",
        help="Show version and exit"
    )
):
    """Network scanner to detect accessible IPs"""

    # Check nmap is installed
    if not shutil.which("nmap"):
        console.print("[red]Error: nmap is not installed on the system[/red]")
        console.print("[yellow]Please install nmap:[/yellow]")
        console.print("  - Debian/Ubuntu: [cyan]sudo apt install nmap[/cyan]")
        console.print("  - Fedora/RHEL: [cyan]sudo dnf install nmap[/cyan]")
        console.print("  - Arch: [cyan]sudo pacman -S nmap[/cyan]")
        raise typer.Exit(code=1)

    # Show version
    if version:
        console.print("[cyan]ScanFinder[/cyan] [dim]v0.1.0[/dim]")
        raise typer.Exit()

    # Show help if no file
    if file is None:
        console.print(ctx.get_help())
        raise typer.Exit()

    # Validate inputs
    if not file.exists():
        console.print(f"[red]Error: File not found: {file}[/red]")
        raise typer.Exit(code=1)

    output_dir = output if output else Path.cwd()
    if not output_dir.exists():
        console.print(f"[red]Error: Output directory not found: {output_dir}[/red]")
        raise typer.Exit(code=1)

    # Read and validate IPs
    try:
        ips, _ = read_ips_from_file(file)
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        raise typer.Exit(code=1)

    if not ips:
        console.print("[red]Error: No valid IPs found in file[/red]")
        raise typer.Exit(code=1)

    # Setup
    show_banner()
    base_name = file.stem
    scan_mode = "Port Scan (top 1000)" if portscan else "Host Discovery"
    show_scan_info(len(ips), workers, scan_mode)

    if portscan:
        # Direct port scan mode
        output_file = output_dir / f"{base_name}_top1000_scan.txt"
        results = run_portscan(ips, workers)
        save_portscan_results(results, output_file, file, len(ips))
        show_portscan_summary(results, len(ips), output_file)

    else:
        # Discovery mode
        output_file = output_dir / f"{base_name}_scannable_ips.txt"
        results = run_discovery(ips, workers)
        scannable_ips = [ip for ip, is_up, _ in results if is_up]

        save_active_ips(scannable_ips, output_file)
        show_discovery_summary(len(ips), len(scannable_ips), output_file)

        # Optionally run port scan on discovered IPs
        if len(scannable_ips) > 0:
            run_followup_portscan(scannable_ips, workers, base_name, output_dir, file)


def cli():
    """Entry point for CLI"""
    typer.run(main)


if __name__ == "__main__":
    cli()