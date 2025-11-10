import ipaddress
from typing import List, Tuple
from pathlib import Path

def read_ips_from_file(filepath: Path) -> Tuple[List[str], int]:
    """Read and validate IPs from file, return (valid_ips, ignored_count)"""
    valid_ips = []
    ignored_count = 0

    with open(filepath, 'r') as f:
        for _, line in enumerate(f, 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Extract first word (potential IP or IP:port)
            potential_ip = line.split()[0]

            # Remove port if present (e.g., "192.168.1.1:80" -> "192.168.1.1")
            if ':' in potential_ip:
                potential_ip = potential_ip.split(':')[0]

            # Validate IP format and check if scannable
            try:
                ip_obj = ipaddress.ip_address(potential_ip)

                # Exclude reserved/special IPs that cannot be scanned
                if (ip_obj.is_loopback or
                    ip_obj.is_multicast or
                    ip_obj.is_unspecified or
                    ip_obj.is_link_local or
                    ip_obj.is_reserved or
                    str(ip_obj).startswith('0.') or
                    str(ip_obj) == '255.255.255.255'):
                    ignored_count += 1
                    continue

                valid_ips.append(potential_ip)
            except ValueError:
                ignored_count += 1

    return valid_ips, ignored_count
