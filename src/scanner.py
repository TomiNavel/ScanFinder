import nmap
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from config import NMAP_PORTSCAN


console = Console()


def scan_ports(ip: str) -> Tuple[str, bool, str]:
    """Scan ports on single IP using nmap"""
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments=NMAP_PORTSCAN)

        if ip not in nm.all_hosts():
            return (ip, False, "Host not found in scan results")

        host_state = nm[ip].state()
        is_up = host_state == 'up'

        # Build detailed output
        details = []
        details.append(f"Host: {ip}")
        details.append(f"State: {host_state}")

        if is_up:
            # Add hostname if available
            if 'hostnames' in nm[ip] and nm[ip]['hostnames']:
                hostnames = [h['name'] for h in nm[ip]['hostnames'] if h['name']]
                if hostnames:
                    details.append(f"Hostnames: {', '.join(hostnames)}")

            # Add port information
            has_open_ports = False
            for proto in nm[ip].all_protocols():
                ports = nm[ip][proto].keys()
                details.append(f"\nProtocol: {proto.upper()}")

                for port in sorted(ports):
                    port_info = nm[ip][proto][port]
                    state = port_info['state']
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('product', '')

                    if version:
                        version_info = f" ({version}"
                        if 'version' in port_info:
                            version_info += f" {port_info['version']}"
                        version_info += ")"
                    else:
                        version_info = ""

                    details.append(f"  {port}/{proto}\t{state}\t{service}{version_info}")

                    if state == 'open':
                        has_open_ports = True

            output = "\n".join(details)
            return (ip, has_open_ports, output)
        else:
            return (ip, False, "\n".join(details))

    except nmap.PortScannerTimeout:
        return (ip, False, "Timeout - No response")
    except Exception as e:
        return (ip, False, f"Error: {str(e)}")


def run_portscan(ips: List[str], workers: int) -> List[Tuple[str, bool, str]]:
    """Run port scan on list of IPs with progress tracking"""
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

        task = progress.add_task("[cyan]Scanning ports...", total=total)

        with ThreadPoolExecutor(max_workers=actual_workers) as executor:
            future_to_ip = {executor.submit(scan_ports, ip): ip for ip in ips}

            for future in as_completed(future_to_ip):
                ip, has_open, details = future.result()
                progress.update(task, advance=1)

                results.append((ip, has_open, details))

                if has_open:
                    console.print(f"[green]✓ {ip}[/green] - Has open ports")

    return results
