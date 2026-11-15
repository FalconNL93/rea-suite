"""Download digests for tools.yml (#29): GitHub's digests from the API or the release page, the
check at download, the order of sources (GitHub, then tools.yml's pinned sha256), and what is
recorded. The network is patched out."""

from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rea_suite import cli, github

DATA = b"a release asset's bytes"
GOOD = hashlib.sha256(DATA).hexdigest()

PAGE = f"""
<a href="/o/r/releases/download/v1/tool-linux.tar.gz">tool-linux.tar.gz</a>
<span class="Truncate-text">sha256:{GOOD}</span><span>sha256:{GOOD}</span>
<a href="/o/r/releases/download/v1/tool-old.zip">tool-old.zip</a>
<a href="/o/r/releases/download/v1/tool-mac.zip">tool-mac.zip</a>
<span>sha256:{"b" * 64}</span>
"""


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def geturl(self) -> str:
        return "https://github.com/o/r/releases/tag/v1"


class Digests(unittest.TestCase):
    def test_the_release_page_pairs_each_asset_with_its_digest(self) -> None:
        with patch.object(github, "_open", return_value=Response(PAGE.encode())):
            release = github._html_release("o/r", "v1")
        digests = {a["name"]: github.asset_digest(a) for a in release["assets"]}
        self.assertEqual(
            digests, {"tool-linux.tar.gz": GOOD, "tool-old.zip": None, "tool-mac.zip": "b" * 64}
        )

    def test_a_download_is_checked_and_a_wrong_one_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "a.tar.gz"
            with patch.object(github, "_open", return_value=Response(DATA)):
                self.assertEqual(github.download("https://x/a.tar.gz", dest, GOOD.upper()), GOOD)
            with (
                patch.object(github, "_open", return_value=Response(DATA)),
                self.assertRaises(github.DigestMismatch),
            ):
                github.download("https://x/a.tar.gz", dest, "0" * 64)
            self.assertFalse(dest.exists())  # nothing half-trusted is left to extract

    def test_github_first_then_a_pinned_sha256_and_a_conflict_stops(self) -> None:
        tool = cli.Tool(name="t", sha256={"tool-old.zip": "c" * 64, "tool-linux.tar.gz": "d" * 64})
        self.assertEqual(
            cli.expected_digest(tool, {"name": "tool-old.zip"}), ("c" * 64, "tools.yml")
        )
        self.assertEqual(cli.expected_digest(cli.Tool(name="t"), {"name": "x"}), (None, "recorded"))
        with self.assertRaises(github.DigestMismatch):  # tools.yml and GitHub disagree
            cli.expected_digest(tool, {"name": "tool-linux.tar.gz", "digest": f"sha256:{GOOD}"})
        plain = cli.Tool(name="t")
        self.assertEqual(
            cli.expected_digest(plain, {"name": "a", "digest": f"sha256:{GOOD}"}), (GOOD, "github")
        )

    def test_what_is_recorded(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.object(cli, "DIGESTS_FILE", Path(tmp) / "digests.json"),
            patch.object(github, "_open", return_value=Response(DATA)),
        ):
            row = cli.fetch("https://x/a.zip", Path(tmp) / "a.zip", None, "github")
            cli.record_digests("t", "v1", {"a.zip": row})
            self.assertEqual(cli.load_digests()["t"]["files"]["a.zip"]["sha256"], GOOD)
            self.assertEqual(row["vouched"], "recorded")  # nothing published to check against


if __name__ == "__main__":
    unittest.main()
