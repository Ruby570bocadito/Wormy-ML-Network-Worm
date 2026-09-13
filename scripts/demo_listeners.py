#!/usr/bin/env python3
"""Tiny loopback service lab for Wormy demo captures.

Binds plausible services to 127.0.0.2 … 127.0.0.7 so the scanner
discovers 6 extra hosts with real open ports and banners:

    127.0.0.2  3306/5432/8080   database + Apache
    127.0.0.3  6379/8888/5900   Redis + nginx + VNC
    127.0.0.4  5985/3000/9090   WinRM + Express + Prometheus
    127.0.0.5  22/80            OpenSSH + Apache
    127.0.0.6  1433/8443        MSSQL + Tomcat
    127.0.0.7  27017/9200       MongoDB + Elasticsearch

Run:  python3 scripts/demo_listeners.py &   (kill by PID)
"""
import signal
import socket
import sys
import threading

LISTENERS = [
    ("127.0.0.2", 3306, b""),
    ("127.0.0.2", 5432, b""),
    ("127.0.0.2", 8080, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"),
    ("127.0.0.3", 6379, b"-ERR unknown command\r\n"),
    ("127.0.0.3", 8888, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n"),
    ("127.0.0.3", 5900, b"RFB 003.008\n"),
    ("127.0.0.4", 5985, b"HTTP/1.1 401 Unauthorized\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n"),
    ("127.0.0.4", 3000, b"HTTP/1.1 302 Found\r\nServer: Express\r\n\r\n"),
    ("127.0.0.4", 9090, b"HTTP/1.1 200 OK\r\nServer: Prometheus/2.40.0\r\n\r\n"),
    ("127.0.0.5", 22, b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"),
    ("127.0.0.5", 80, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.29 (Debian)\r\nContent-Length: 0\r\n\r\n"),
    ("127.0.0.6", 1433, b""),
    ("127.0.0.6", 8443, b"HTTP/1.1 200 OK\r\nServer: Tomcat/9.0.62\r\nContent-Length: 0\r\n\r\n"),
    ("127.0.0.7", 27017, b""),
    ("127.0.0.7", 9200, b"HTTP/1.1 200 OK\r\nServer: Elasticsearch/7.17.9\r\nContent-Length: 0\r\n\r\n"),
]

_stop = threading.Event()


def serve(ip: str, port: int, banner: bytes) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, port))
    srv.listen(16)
    srv.settimeout(1.0)
    print(f"  listening {ip}:{port}", flush=True)
    while not _stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with conn:
            conn.settimeout(2.0)
            if banner:
                try:
                    conn.sendall(banner)
                except OSError:
                    pass
            try:
                conn.recv(1024)
            except OSError:
                pass
    srv.close()


def main() -> int:
    signal.signal(signal.SIGTERM, lambda *_: _stop.set())
    threads = []
    for ip, port, banner in LISTENERS:
        t = threading.Thread(target=serve, args=(ip, port, banner), daemon=True)
        t.start()
        threads.append(t)
    print("demo listeners up", flush=True)
    try:
        while True:
            _stop.wait(3600)
            break
    except KeyboardInterrupt:
        _stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
