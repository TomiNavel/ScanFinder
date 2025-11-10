from pathlib import Path

# Directorios
BASE_DIR = Path(__file__).parent
SRC_DIR = BASE_DIR / "src"

# Configuración de escaneo
MAX_WORKERS = 10  # Escaneos simultáneos
TIMEOUT_DISCOVERY = 10  # Timeout por IP para discovery (segundos)
TIMEOUT_PORTSCAN = 120  # Timeout por IP para port scan (segundos)

# Parámetros de nmap
NMAP_DISCOVERY = "-sn"
NMAP_PORTSCAN = "-sS --top-ports 1000 -sV -T4"

