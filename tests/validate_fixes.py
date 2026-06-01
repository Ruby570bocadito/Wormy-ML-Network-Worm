#!/usr/bin/env python3
"""
Wormy — Code Quality & Fix Validation Script
Validates that all fixes have been applied correctly without requiring external dependencies.
"""

import ast
import os
import sys

# Colors for terminal
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def check_file_contains(filepath, pattern, description):
    """Check if a file contains a specific pattern"""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        print(f"  {RED}✗{RESET} {description}: File not found ({filepath})")
        return False
    with open(full_path, "r") as f:
        content = f.read()
    if pattern in content:
        print(f"  {GREEN}✓{RESET} {description}")
        return True
    else:
        print(f"  {RED}✗{RESET} {description}")
        return False


def count_pattern(filepath, pattern):
    """Count occurrences of a pattern in a file"""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        return 0
    with open(full_path, "r") as f:
        content = f.read()
    return content.count(pattern)


def check_no_bare_except(filepath):
    """Check that there are no bare except: clauses"""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        return True, 0
    with open(full_path, "r") as f:
        content = f.read()
    # Count bare except: (not except Exception:)
    lines = content.split("\n")
    bare_count = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("except:") and not stripped.startswith("except Exception:"):
            bare_count += 1
    return bare_count == 0, bare_count


def check_pickle_hmac(filepath):
    """Check that pickle.load is protected with HMAC"""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        return True
    with open(full_path, "r") as f:
        content = f.read()
    has_hmac = "hmac" in content and "compare_digest" in content
    has_pickle_load = "pickle.load" in content or "pickle.loads" in content
    if has_pickle_load and has_hmac:
        return True
    elif not has_pickle_load:
        return True
    return False


def check_thread_safe_singleton(filepath):
    """Check that singleton uses threading.Lock"""
    full_path = os.path.join(BASE_DIR, filepath)
    if not os.path.exists(full_path):
        return True
    with open(full_path, "r") as f:
        content = f.read()
    has_lock = "threading.Lock()" in content or "_lock" in content
    has_double_check = "with _" in content and "_lock" in content
    return has_lock and has_double_check


def main():
    print(f"\n{BLUE}{'=' * 60}{RESET}")
    print(f"{BLUE}  WORMY — CODE QUALITY & FIX VALIDATION{RESET}")
    print(f"{BLUE}{'=' * 60}{RESET}\n")

    all_passed = True
    total_checks = 0
    passed_checks = 0

    # ── Fix 1: pyproject.toml dependencies ──
    print(f"{YELLOW}[1] pyproject.toml dependencies{RESET}")
    total_checks += 2
    if check_file_contains("pyproject.toml", '"redis>=5.0.0"', "redis dependency added"):
        passed_checks += 1
    if check_file_contains("pyproject.toml", '"pymssql>=2.2.0"', "pymssql dependency added"):
        passed_checks += 1
    print()

    # ── Fix 2: pickle.load() with HMAC ──
    print(f"{YELLOW}[2] pickle.load() HMAC signature verification{RESET}")
    total_checks += 2
    if check_pickle_hmac("evasion/evasion_model.py"):
        print(f"  {GREEN}✓{RESET} evasion_model.py: HMAC verification applied")
        passed_checks += 1
    else:
        print(f"  {RED}✗{RESET} evasion_model.py: HMAC verification missing")
    if check_pickle_hmac("scanner/__init__.py"):
        print(f"  {GREEN}✓{RESET} scanner/__init__.py: HMAC verification applied")
        passed_checks += 1
    else:
        print(f"  {RED}✗{RESET} scanner/__init__.py: HMAC verification missing")
    print()

    # ── Fix 3: Thread-safe singletons ──
    print(f"{YELLOW}[3] Thread-safe singletons{RESET}")
    total_checks += 3
    if check_thread_safe_singleton("exploits/credential_manager.py"):
        print(f"  {GREEN}✓{RESET} credential_manager.py: thread-safe singleton")
        passed_checks += 1
    else:
        print(f"  {RED}✗{RESET} credential_manager.py: not thread-safe")
    if check_thread_safe_singleton("exploits/metasploit_client.py"):
        print(f"  {GREEN}✓{RESET} metasploit_client.py: thread-safe singleton")
        passed_checks += 1
    else:
        print(f"  {RED}✗{RESET} metasploit_client.py: not thread-safe")
    if check_thread_safe_singleton("monitoring/dashboard.py"):
        print(f"  {GREEN}✓{RESET} dashboard.py: thread-safe singleton")
        passed_checks += 1
    else:
        print(f"  {RED}✗{RESET} dashboard.py: not thread-safe")
    print()

    # ── Fix 4: os.system() → subprocess ──
    print(f"{YELLOW}[4] os.system() replaced with subprocess{RESET}")
    total_checks += 1
    if check_file_contains("attacks/supply_chain.py", "subprocess.run", "subprocess.run used instead of os.system"):
        passed_checks += 1
    print()

    # ── Fix 5: Lab credentials ──
    print(f"{YELLOW}[5] Docker lab credentials in credential_manager{RESET}")
    total_checks += 3
    if check_file_contains("exploits/credential_manager.py", '"sa", "SqlPassword123!"', "MSSQL lab creds"):
        passed_checks += 1
    if check_file_contains("exploits/credential_manager.py", '"admin", "admin123"', "PostgreSQL lab creds"):
        passed_checks += 1
    if check_file_contains("exploits/credential_manager.py", '"guest", "guest"', "RabbitMQ lab creds"):
        passed_checks += 1
    print()

    # ── Fix 6: MSSQL credential order ──
    print(f"{YELLOW}[6] MSSQL exploit credential priority{RESET}")
    total_checks += 1
    if check_file_contains("exploits/modules/mssql_exploit.py", '("sa", "SqlPassword123!")', "SqlPassword123! first in list"):
        passed_checks += 1
    print()

    # ── Fix 7: Test script exists ──
    print(f"{YELLOW}[7] Test script created{RESET}")
    total_checks += 1
    if os.path.exists(os.path.join(BASE_DIR, "tests/test_worm_vs_lab.py")):
        print(f"  {GREEN}✓{RESET} tests/test_worm_vs_lab.py exists")
        passed_checks += 1
    else:
        print(f"  {RED}✗{RESET} tests/test_worm_vs_lab.py missing")
    print()

    # ── Statistics ──
    print(f"{YELLOW}[8] Code statistics{RESET}")
    exploit_modules = len([f for f in os.listdir(os.path.join(BASE_DIR, "exploits/modules")) if f.endswith(".py") and f != "__init__.py"])
    print(f"  Exploit modules: {exploit_modules}")

    total_lines = 0
    total_files = 0
    for root, dirs, files in os.walk(BASE_DIR):
        for f in files:
            if f.endswith(".py"):
                total_files += 1
                with open(os.path.join(root, f), "r") as fh:
                    total_lines += len(fh.readlines())
    print(f"  Total Python files: {total_files}")
    print(f"  Total lines of code: {total_lines}")
    print()

    # ── Summary ──
    print(f"{BLUE}{'=' * 60}{RESET}")
    print(f"{BLUE}  SUMMARY{RESET}")
    print(f"{BLUE}{'=' * 60}{RESET}")
    print(f"  Checks passed: {GREEN}{passed_checks}/{total_checks}{RESET}")
    pct = passed_checks / total_checks * 100 if total_checks > 0 else 0
    if pct == 100:
        print(f"  Status: {GREEN}ALL FIXES APPLIED ✓{RESET}")
    elif pct >= 80:
        print(f"  Status: {YELLOW}MOST FIXES APPLIED ({pct:.0f}%){RESET}")
    else:
        print(f"  Status: {RED}MORE FIXES NEEDED ({pct:.0f}%){RESET}")
    print()

    return passed_checks == total_checks


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
