# ScanFinder

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Stars](https://img.shields.io/github/stars/tominavel/ScanFinder?style=social)](https://github.com/tominavel/ScanFinder/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/tominavel/ScanFinder)](https://github.com/tominavel/ScanFinder/issues)

A Python CLI network scanner built with Typer and Rich that detects accessible IPs and performs port scanning using nmap.

## Features

- **Host Discovery**: Quickly identify which IPs are responding on your network
- **Port Scanning**: Scan top 1000 ports on discovered hosts with service detection
- **Interactive Workflow**: Automatically offers to scan ports after host discovery
- **IP Validation**: Filters out reserved/special IPs (localhost, multicast, etc.)
- **Flexible Input**: Supports plain text files with IPs, comments, and IP:port format
- **Rich Output**: Beautiful terminal interface with progress bars and colored output
- **Concurrent Scanning**: Multi-threaded for faster results
- **Detailed Reports**: Saves results to timestamped files

## Requirements

- Python 3.8+
- nmap installed on your system

## Installation

### From source

```bash
git clone https://github.com/tominavel/ScanFinder.git
cd ScanFinder

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install
pip install .
```

## Usage

### Basic host discovery

```bash
scanfinder -f file.txt
```

This will:
1. Discover which IPs are responding
2. Save results to `file_scannable_ips.txt`
3. Ask if you want to scan ports on discovered hosts

### Direct port scan

```bash
scanfinder -f file.txt --portscan
```

### Custom output directory

```bash
scanfinder -f file.txt -o /tmp/results
```

### Adjust concurrent workers

```bash
scanfinder -f file.txt -w 20
```

## Input File Format

Create a text file with one IP per line:

**Supported:**
- Valid IPv4 addresses
- Comments with `#`
- Empty lines
- IP:port format (extracts IP only)

**Automatically filtered:**
- Reserved IPs (0.0.0.0/8)
- Localhost (127.0.0.0/8)
- Link-local (169.254.0.0/16)
- Multicast (224.0.0.0/4)
- Broadcast (255.255.255.255)

## Output Files

### Host Discovery Mode
- `{filename}_scannable_ips.txt` - List of IPs that responded

### Port Scan Mode
- `{filename}_top1000_scan.txt` - Detailed scan results with:
  - Open ports
  - Service names
  - Version detection
  - Timestamps


## Examples

### Quick network sweep
```bash
# Create IP list
seq 1 254 | sed 's/^/192.168.1./' > network.txt

# Discover active hosts
scanfinder -f network.txt

# Results in network_scannable_ips.txt
```

### Scan specific targets
```bash
cat > targets.txt << EOF
192.168.1.1
192.168.1.254
10.0.0.1
EOF

scanfinder -f targets.txt --portscan
```

## License

GPL-3.0 License - see LICENSE file for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Acknowledgments

Built with:
- [Typer](https://typer.tiangolo.com/) - CLI framework
- [Rich](https://rich.readthedocs.io/) - Terminal formatting
- [python-nmap](https://pypi.org/project/python-nmap/) - Nmap wrapper
- [nmap](https://nmap.org/) - The actual scanning engine