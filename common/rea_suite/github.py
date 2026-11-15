"""GitHub release lookups and downloads.

Uses the REST API (with GITHUB_TOKEN/GH_TOKEN when set). Anonymous API access is
limited to 60 requests/hour, so once that is exhausted lookups fall back to the
public github.com release pages, which are not rate limited the same way.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .components import env_file_value

_api_exhausted = False


def _open(url: str, headers: dict[str, str] | None = None, timeout: int = 60):
    req = urllib.request.Request(url, headers={"User-Agent": "rea-suite", **(headers or {})})
    return urllib.request.urlopen(req, timeout=timeout)


def _api(path: str) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token := token or env_file_value("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    with _open(f"https://api.github.com/{path}", headers, timeout=30) as resp:
        return json.load(resp)


def _html_release(repo: str, tag: str | None) -> dict:
    if tag is None:
        # /releases/latest redirects to /releases/tag/<tag>
        with _open(f"https://github.com/{repo}/releases/latest") as resp:
            tag = urllib.parse.unquote(resp.geturl().rstrip("/").rsplit("/tag/", 1)[1])
    quoted = urllib.parse.quote(tag, safe="")
    with _open(f"https://github.com/{repo}/releases/expanded_assets/{quoted}") as resp:
        page = resp.read().decode("utf-8", "replace")
    # each asset's link, then its digest (`sha256:<hex>`) before the next asset's link
    events = sorted(
        [
            (m.start(), "link", m.group(1))
            for m in re.finditer(r'href="(/[^"]+/releases/download/[^"]+)"', page)
        ]
        + [(m.start(), "digest", m.group(1)) for m in re.finditer(r"sha256:([0-9a-f]{64})", page)]
    )
    assets: dict[str, dict] = {}
    current = None
    for _at, kind, value in events:
        if kind == "link":
            current = assets.setdefault(value, {
                "name": urllib.parse.unquote(value.rsplit("/", 1)[1]),
                "browser_download_url": f"https://github.com{value}",
            })  # fmt: skip
        elif current is not None and "digest" not in current:
            current["digest"] = f"sha256:{value}"
    return {"tag_name": tag, "assets": list(assets.values())}


@functools.cache
def release(repo: str, version: str = "latest") -> dict:
    """Release metadata: {"tag_name": ..., "assets": [{"name", "browser_download_url"}]}."""
    global _api_exhausted
    tag = None if version == "latest" else version
    if not _api_exhausted:
        path = f"repos/{repo}/releases/" + ("latest" if tag is None else f"tags/{tag}")
        try:
            return _api(path)
        except urllib.error.HTTPError as exc:
            if exc.code not in (403, 429) or exc.headers.get("X-RateLimit-Remaining") != "0":
                raise
            _api_exhausted = True
            print(
                "  note: GitHub API rate limit reached; using github.com release pages "
                "(set GITHUB_TOKEN in .envrc.local to avoid this)",
                file=sys.stderr,
            )
    return _html_release(repo, tag)


def releases(repo: str, limit: int = 15):
    """Yield releases newest first (lazily, to spend as few requests as possible)."""
    global _api_exhausted
    if not _api_exhausted:
        try:
            yield from _api(f"repos/{repo}/releases?per_page={limit}")
            return
        except urllib.error.HTTPError as exc:
            if exc.code not in (403, 429) or exc.headers.get("X-RateLimit-Remaining") != "0":
                raise
            _api_exhausted = True
    with _open(f"https://github.com/{repo}/releases") as resp:
        page = resp.read().decode("utf-8", "replace")
    tags = dict.fromkeys(
        re.findall(rf'href="/{re.escape(repo)}/releases/tag/([^"]+)"', page, re.IGNORECASE)
    )
    for tag in list(tags)[:limit]:
        yield release(repo, urllib.parse.unquote(tag))


def source_url(repo: str, tag: str) -> str:
    """The source archive of a release tag, or of a commit given by its full hash."""
    if re.fullmatch(r"[0-9a-f]{40}", tag):
        return f"https://github.com/{repo}/archive/{tag}.tar.gz"
    return f"https://github.com/{repo}/archive/refs/tags/{urllib.parse.quote(tag, safe='')}.tar.gz"


class DigestMismatch(OSError):
    """A download whose SHA-256 is not the one GitHub or tools.yml gives: the install stops."""


def asset_digest(asset: dict) -> str | None:
    """The SHA-256 GitHub gives for a release asset (the API's `digest`, or the release page's),
    as hex; None for an asset GitHub has none for (releases from before it recorded them)."""
    digest = asset.get("digest") or ""
    return digest.removeprefix("sha256:").lower() if digest.startswith("sha256:") else None


def download(url: str, dest: Path, expected: str | None = None) -> str:
    """The file at url saved to dest; its SHA-256 (hex). With expected, a different digest
    deletes the file and raises DigestMismatch."""
    print(f"  downloading {url}")
    digest = hashlib.sha256()
    with _open(url) as resp, dest.open("wb") as out:
        while chunk := resp.read(1 << 20):
            digest.update(chunk)
            out.write(chunk)
    got = digest.hexdigest()
    if expected is not None and got != expected.lower():
        dest.unlink(missing_ok=True)
        raise DigestMismatch(f"{url}: SHA-256 {got}, expected {expected.lower()}: not installed")
    return got
