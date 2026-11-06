"""System packages (platforms/linux/packages.sh) against stub apt tools, and doctor's .venv advice."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ROOT / "platforms/linux/packages.sh"

# dpkg-query reports the packages named in $INSTALLED as installed; every other stub only
# records how it was called, so the test sees whether setup would have needed root.
STUBS = {
    "dpkg-query": 'for a; do pkg="$a"; done\n'
    'case " $INSTALLED " in *" $pkg "*) echo "install ok installed" ;; *) exit 1 ;; esac\n',
    "apt-get": 'echo "apt-get $*" >>"$CALLS"\n',
    "sudo": 'echo "sudo $1" >>"$CALLS"\n"$@"\n',
}


@unittest.skipUnless(shutil.which("bash"), "needs bash")
class AptInstall(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name, body in STUBS.items():
            stub = bin_dir / name
            stub.write_text("#!/usr/bin/env bash\n" + body)
            stub.chmod(0o755)
        self.calls = self.root / "calls"
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "CALLS": str(self.calls),
            "INSTALLED": "curl git",
        }

    def install(self, *args: str) -> list[str]:
        script = f'set -euo pipefail; source "{PACKAGES}"; pkg_install "$@"'
        subprocess.run(["bash", "-c", script, "bash", *args], env=self.env, check=True)
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def apt_calls(self, *args: str) -> list[str]:
        return [c for c in self.install(*args) if c.startswith("apt-get")]

    def test_everything_installed_runs_no_apt_and_no_sudo(self) -> None:
        self.assertEqual(self.install("curl", "git"), [])

    def test_only_the_missing_packages_are_installed(self) -> None:
        apt = self.apt_calls("curl", "git", "jq")
        self.assertEqual(apt[-1], "apt-get install -y jq")

    def test_an_upgrade_passes_every_package_to_apt(self) -> None:
        apt = self.apt_calls("--upgrade", "curl", "git")
        self.assertEqual(apt[-1], "apt-get install -y curl git")

    def test_a_reinstall_passes_every_package_to_apt(self) -> None:
        apt = self.apt_calls("--reinstall", "curl", "git")
        self.assertEqual(apt[-1], "apt-get install -y --reinstall curl git")


class DoctorVenvAdvice(unittest.TestCase):
    """An out-of-sync .venv needs only uv, not a setup that stops at sudo for apt."""

    def test_both_doctors_name_uv_sync_locked(self) -> None:
        for script in ("bin/rea-suite", "platforms/windows/rea-suite.ps1"):
            text = (ROOT / script).read_text()
            line = next(ln for ln in text.splitlines() if "out of sync with uv.lock" in ln)
            with self.subTest(script=script):
                self.assertIn("run uv sync --locked", line)
                self.assertNotIn("setup", line)


if __name__ == "__main__":
    unittest.main()
