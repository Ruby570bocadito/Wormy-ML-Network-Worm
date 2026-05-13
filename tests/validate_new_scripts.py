import os
import sys

sys.path.insert(0, ".")

# Test 1: cleanup dry-run
print("=== cleanup_engagement ===")
from scripts.cleanup_engagement import LocalCleanup

c = LocalCleanup(".", dry_run=True)
r = c.run_all()
print(f"LocalCleanup dry-run: total_removed={r['total_removed']} mode={r['dry_run']}")
assert r["dry_run"] == True

# Test 2: BloodHound export
print("\n=== bloodhound_export ===")
import json
import tempfile

from utils.bloodhound_export import BloodHoundExporter

exp = BloodHoundExporter("TEST.LOCAL")
dc_id = exp.add_computer("DC01", "10.0.0.1", is_dc=True)
u_admin = exp.add_user("administrator", is_admin=True, rid=500)
u_svc = exp.add_user("svc_backup", has_spn=True, rid=1105)
u_hr = exp.add_user("jsmith", no_preauth=True, rid=1110)
g_da = exp.add_group("Domain Admins", [u_admin], is_admin_group=True, rid=512)

with tempfile.TemporaryDirectory() as td:
    files = exp.export(td)
    for f in files:
        data = json.load(open(f))
        name = os.path.basename(f)
        count = data["meta"]["count"]
        print(f"  {name}: {count} objects")

print("\nAll OK")
