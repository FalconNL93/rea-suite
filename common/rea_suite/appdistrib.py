"""Release lookups on AppDistrib (distrib.app), where PCSX-Redux publishes its builds.

PCSX-Redux has no GitHub releases: every commit on its main branch becomes a build on
a channel per platform, listed in a JSON manifest that its own updater reads. The
newest build of a channel is shaped like a GitHub release, so `rea-tools` installs,
updates and rolls it back the same way.
"""

from __future__ import annotations

import json
import urllib.parse

from .github import _open

BASE = "https://distrib.app"


def _manifest(path: str) -> dict:
    with _open(f"{BASE}/storage/manifests/{path}", timeout=30) as resp:
        return json.load(resp)


def release(org: str, channel: str) -> dict:
    """The newest build of org/channel: {"tag_name": version, "assets": [one file]}."""
    builds = _manifest(f"{org}/{channel}/manifest.json")["builds"]
    if not builds:
        raise LookupError(f"distrib.app {org}/{channel} lists no builds")
    newest = max(builds, key=lambda b: b["id"])["id"]
    build = _manifest(f"{org}/{channel}/manifest-{newest}.json")
    path = build["path"]
    return {
        "tag_name": str(build["manifest"]["version"]),
        "assets": [
            {
                "name": urllib.parse.unquote(path.rsplit("/", 1)[1]),
                "browser_download_url": BASE + urllib.parse.quote(path),
            }
        ],
    }
