import nmap
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from config import NMAP_DISCOVERY


console = Console()


def scan_host(ip: str) -> Tuple[str, bool, str]:
    """Check if single host is up using nmap host discovery"""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments=NMAP_DISCOVERY)

        if ip not in nm.all_hosts():
            return (ip, False, "Host not found in scan results")

        host_state = nm[ip].state()
        is_up = host_state == 'up'

        # Build simple output
        details = [f"Host: {ip}", f"State: {host_state}"]

        if is_up and 'hostnames' in nm[ip] and nm[ip]['hostnames']:
            hostnames = [h['name'] for h in nm[ip]['hostnames'] if h['name']]
            if hostnames:
                details.append(f"Hostnames: {', '.join(hostnames)}")

        return (ip, is_up, "\n".join(details))

    except nmap.PortScannerTimeout:
        return (ip, False, "Timeout - No response")
    except Exception as e:
        return (ip, False, f"Error: {str(e)}")


def run_discovery(ips: List[str], workers: int) -> List[Tuple[str, bool, str]]:
    """Run host discovery on list of IPs with progress tracking"""
    total = len(ips)
    actual_workers = min(workers, total)
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:

        task = progress.add_task("[cyan]Discovering hosts...", total=total)

        with ThreadPoolExecutor(max_workers=actual_workers) as executor:
            future_to_ip = {executor.submit(scan_host, ip): ip for ip in ips}

            for future in as_completed(future_to_ip):
                ip, is_up, details = future.result()
                progress.update(task, advance=1)

                results.append((ip, is_up, details))

                if is_up:
                    console.print(f"[green]✓ {ip}[/green] - Scannable")

    return results
