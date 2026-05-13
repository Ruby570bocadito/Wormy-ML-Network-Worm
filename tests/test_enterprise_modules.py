"""
Quick integration test for all new enterprise modules.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

__test__ = False  # pytest marker: run as script, not auto-discovered


def test(label, func):
    try:
        result = func()
        print(f"  [OK] {label}: {result}")
    except Exception as e:
        print(f"  [FAIL] {label}: {e}")


print("=" * 60)
print("  ENTERPRISE MODULES — INTEGRATION TEST")
print("=" * 60)


# 1. Enterprise Scanner
def t_scanner():
    from scanner.enterprise_scanner import ASSET_VALUE, PORT_META, EnterpriseScanner

    s = EnterpriseScanner()
    return f"{len(PORT_META)} ports defined, {len(ASSET_VALUE)} asset types"


test("EnterpriseScanner", t_scanner)


# 2. Redis exploit
def t_redis():
    from exploits.modules.redis_exploit import Redis_Exploit

    r = Redis_Exploit()
    return f"name={r.name} ports={r.target_ports}"


test("Redis_Exploit", t_redis)


# 3. Elasticsearch exploit
def t_es():
    from exploits.modules.elasticsearch_exploit import Elasticsearch_Exploit

    e = Elasticsearch_Exploit()
    return f"name={e.name} ports={e.target_ports}"


test("Elasticsearch_Exploit", t_es)


# 4. Enterprise password engine
def t_pwd():
    from exploits.enterprise_password_engine import CredentialMutator, EnterprisePasswordEngine

    eng = EnterprisePasswordEngine()
    mutator = CredentialMutator()
    mutations = mutator.mutate("Admin")
    return f"{len(eng.CORPORATE_PASSWORDS)} corporate passwords, {len(mutations)} Admin mutations"


test("EnterprisePasswordEngine", t_pwd)


# 5. Payload obfuscation round-trip
def t_obf():
    from evasion.enterprise_evasion import PayloadObfuscator

    obf = PayloadObfuscator()
    payload = b"test_shellcode_" + bytes(range(32))
    enc = obf.multi_layer_obfuscate(payload)
    dec = obf.deobfuscate(enc)
    assert dec == payload, "Round-trip FAILED"
    layers = enc["layers"]
    size = enc["encoded_size"]
    return f"{layers} layers, {size} bytes encoded, round-trip OK"


test("PayloadObfuscator (round-trip)", t_obf)


# 6. Sandbox detector
def t_sandbox():
    from evasion.enterprise_evasion import SandboxDetector

    sd = SandboxDetector()
    is_sb, reasons = sd.is_sandboxed()
    return f"sandboxed={is_sb} reasons={reasons}"


test("SandboxDetector", t_sandbox)


# 7. Active Directory module
def t_ad():
    from exploits.active_directory import ActiveDirectoryAttacker

    ad = ActiveDirectoryAttacker()
    return "DCFinder + LDAPEnumerator + ASREPRoaster + Kerberoaster loaded"


test("ActiveDirectoryAttacker", t_ad)


# 8. Credential mutation examples
def t_mutations():
    from exploits.enterprise_password_engine import CredentialMutator

    m = CredentialMutator()
    company_pwds = m.generate_from_company("Acme")
    return f"{len(company_pwds)} company-based passwords generated"


test("CredentialMutator (company)", t_mutations)


# 9. LOLBins wrapper
def t_lolbin():
    from evasion.enterprise_evasion import EnterpriseEvasionEngine

    ev = EnterpriseEvasionEngine()
    cmd = ev.get_lolbin_command("whoami")
    return f"LOLBin: {cmd[:60]}..."


test("LOLBins wrapper", t_lolbin)


# 10. TCP scanner (local scan)
def t_tcp_scan():
    from scanner.enterprise_scanner import EnterpriseScanner

    s = EnterpriseScanner(timeout=1.0)
    open_, banner = s.scan_port("127.0.0.1", 6379)
    return f"Redis@127.0.0.1:6379 open={open_} banner={repr(banner[:30]) if banner else 'none'}"


test("TCP port scan (Redis)", t_tcp_scan)

print("=" * 60)
print("  Done. Check [OK]/[FAIL] above.")
print("=" * 60)
