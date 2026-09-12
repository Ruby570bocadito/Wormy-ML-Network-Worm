"""Verificación funcional de las correcciones de la ronda de Bugs y Seguridad.

Ejecuta pruebas puntuales (no parte de la suite de CI) para confirmar que:
  1. host_monitor: RLock elimina el deadlock y update_health ordena estados.
  2. multi_operator: admin aleatorio, /agent/ requiere token, lockout login.
  3. scanner/evasion_model: pickle sin firma se rechaza (fail closed).
  4. cloud_c2: GoogleSheetsC2 no re-ejecuta comandos ya entregados.
  5. brute_force_engine: lockout expira tras el cooldown.
  6. metasploit_client: payload msgpack es [method, token, *params].
  7. c2/server: compare_digest de API key.
  8. lateral_movement: credenciales via env, no interpoladas.
"""
import inspect
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'[OK] ' if cond else '[FAIL]'} {name} {detail}")


# ── 1. host_monitor ────────────────────────────────────────────────────────
try:
    from monitoring.host_monitor import HostMonitor, HostState

    hm = HostMonitor()
    hm.register_host("10.0.0.1")
    # Simular salud crítica y disparar self-healing desde dentro del lock
    # (el escenario exacto del deadlock original).
    with hm._lock:
        hm.hosts["10.0.0.1"].update_health(10.0)
        ok = hm.trigger_self_healing("10.0.0.1")
    check("host_monitor: deadlock del monitor loop eliminado (RLock)", True)

    st = HostState("10.0.0.2")
    st.update_health(5.0)
    check("host_monitor: health<20 => 'critical'", st.status == "critical")
    st.update_health(30.0)
    check("host_monitor: 20<=health<50 => 'degraded'", st.status == "degraded")
    st.update_health(80.0)
    check("host_monitor: health>=50 => 'active'", st.status == "active")
except Exception as e:
    check("host_monitor", False, str(e))

# ── 2. multi_operator ──────────────────────────────────────────────────────
try:
    import shutil

    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "ops.db")
    from monitoring.multi_operator import MultiOperatorServer, OperatorDB

    srv = MultiOperatorServer(host="127.0.0.1", port=0, db_path=db_path)
    # El admin debe existir y NO tener la password pública por defecto.
    db = OperatorDB(db_path)
    check("multi_operator: admin/wormy_admin_2024 ya NO autentica",
          db.authenticate("admin", "wormy_admin_2024") is None)
    auth_ok = False
    # No podemos conocer la password aleatoria; verificamos que el log la
    # generó simplemente comprobando que la conocida falla (arriba) y que el
    # hash cambió respecto al salt público anterior.
    import hashlib

    with db._conn() as c:
        row = c.execute("SELECT pw_hash FROM operators WHERE username='admin'").fetchone()
    legacy = hashlib.pbkdf2_hmac("sha256", b"wormy_admin_2024", b"wormy_salt", 100_000).hex()
    check("multi_operator: hash difiere del esquema legacy (salt aleatoria)",
          row["pw_hash"] != legacy)
    # JWT secret: rechazar el default público
    srv2 = MultiOperatorServer(host="127.0.0.1", port=0, jwt_secret="wormy_jwt_secret_change_me",
                               db_path=db_path)
    forged = srv2.jwt.encode({"username": "admin", "role": "admin"})
    decoded_by_srv1 = srv.jwt.decode(forged)
    check("multi_operator: token firmado con secret público rechazado por otra instancia",
          decoded_by_srv1 is None)
    # /agent/ sin token -> 401 (verificación estructural del handler)
    import inspect

    src = inspect.getsource(MultiOperatorServer._make_handler)
    check("multi_operator: endpoint /agent/ exige X-Agent-Token",
          "X-Agent-Token" in src and "compare_digest" in src)
    shutil.rmtree(tmpdir, ignore_errors=True)
except Exception as e:
    check("multi_operator", False, str(e))

# ── 3. pickle fail closed ──────────────────────────────────────────────────
try:
    import pickle

    tmpdir = tempfile.mkdtemp()
    pkl = os.path.join(tmpdir, "model.pkl")
    with open(pkl, "wb") as f:
        pickle.dump({"evil": True}, f)  # pickle SIN .sig
    from evasion.evasion_model import EvasionModel

    m = EvasionModel(model_path=pkl)
    # Debe reentrenar (modelo sintético), NO cargar el pickle malicioso.
    check("evasion_model: pickle sin firma NO se carga (fail closed)",
          not (m.model is not None and hasattr(m.model, "get") and m.model.get("evil") is True))

    from scanner import HostClassifier

    sc = HostClassifier(model_path=pkl)
    check("scanner: pickle sin firma NO se carga (fail closed)",
          not (sc.model is not None and hasattr(sc.model, "get") and sc.model.get("evil") is True))
    shutil.rmtree(tmpdir, ignore_errors=True)
except Exception as e:
    check("pickle fail closed", False, str(e))

# ── 4. GoogleSheetsC2 dedup ────────────────────────────────────────────────
try:
    from c2.cloud_c2 import GoogleSheetsC2
    import c2.cloud_c2 as cc

    gs = GoogleSheetsC2(sheet_id="x")
    # Filas CIFRADAS válidas (el C2 real escribe [CMD]+ciphertext).
    import json as _json

    enc1 = cc._enc({"cmd": "whoami", "id": 1}, gs.passphrase)
    enc2 = cc._enc({"cmd": "id", "id": 2}, gs.passphrase)
    rows = f"[CMD]{enc1}\n[CMD]{enc2}\n"
    calls = {"n": 0}

    def fake_get(url):
        calls["n"] += 1
        return rows

    orig = cc._http_get
    cc._http_get = fake_get
    try:
        first = gs.poll_commands()
        second = gs.poll_commands()
    finally:
        cc._http_get = orig
    check("GoogleSheetsC2: primera poll devuelve los comandos", len(first) == 2)
    check("GoogleSheetsC2: segunda poll NO re-ejecuta (dedup)", len(second) == 0)
except Exception as e:
    check("GoogleSheetsC2 dedup", False, str(e))

# ── 5. brute_force_engine lockout con cooldown ─────────────────────────────
try:
    from exploits.brute_force_engine import BruteForceEngine

    bfe = BruteForceEngine()
    target, user = "10.1.1.1", "root"
    for _ in range(5):
        bfe._failure_counts[target][user] += 1
    bfe._lockout_started[(target, user)] = time.time() - 301  # hace >300s
    check("brute_force: lockout expira tras cooldown (300s)",
          bfe._is_locked_out(target, user) is False)
    bfe2 = BruteForceEngine()
    for _ in range(5):
        bfe2._failure_counts[target][user] += 1
    bfe2._lockout_started[(target, user)] = time.time()  # ahora mismo
    check("brute_force: lockout activo dentro del cooldown",
          bfe2._is_locked_out(target, user) is True)
except Exception as e:
    check("brute_force lockout", False, str(e))

# ── 6. metasploit_client framing ───────────────────────────────────────────
try:
    import exploits.metasploit_client as mc

    src = inspect.getsource(mc.MetasploitClient._raw_call)
    check("metasploit: payload es array [method, token, *params]",
          "payload = [method]" in src and "payload.append(self.token)" in src)
except Exception as e:
    check("metasploit framing", False, str(e))

# ── 7. c2/server compare_digest ────────────────────────────────────────────
try:
    src = inspect.getsource(__import__("c2.server", fromlist=["C2Server"]).C2Server)
    check("c2/server: comparación de API key en tiempo constante",
          "compare_digest" in src)
    check("c2/server: host por defecto 127.0.0.1", 'host="127.0.0.1"' in src)
except Exception as e:
    check("c2/server", False, str(e))

# ── 8. lateral_movement / dcom env vars ────────────────────────────────────
try:
    import post_exploit.lateral_movement as lm
    import post_exploit.dcom_lateral as dl

    lm_src = inspect.getsource(lm)
    dl_src = inspect.getsource(dl)
    check("lateral_movement: credenciales por env, no interpoladas",
          "WORMY_PASSWORD" in lm_src and "os.environ" in lm_src)
    check("dcom_lateral: credenciales/comando por env",
          "WORMY_COMMAND" in dl_src and "WORMY_PASSWORD" in dl_src)
except Exception as e:
    check("lateral env vars", False, str(e))

# ── Resumen ────────────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print(f"VERIFICACIÓN: {len(PASS)} OK / {len(FAIL)} FAIL")
if FAIL:
    print("FALLOS:", FAIL)
    sys.exit(1)
print("TODAS LAS VERIFICACIONES PASARON")
