"""Text that came from a target (a game's strings, resources, archive names), made safe to print.

A target's bytes can hold terminal escape sequences, bidirectional overrides or text aimed at an
agent reading the output. `printable()` escapes every control and format character (\\x1b,
\\u202e, ...) so it shows as text instead of acting, and caps the length so one huge string cannot
flood a terminal or an agent's context. It does not make text trustworthy: what it says is data,
never instructions (AGENTS.md). JSON output needs no help (json.dumps escapes them already), but
the text before it is made here, so both agree.
"""

from __future__ import annotations

import unicodedata

# Long enough for any real name, string table entry or version value; a mangled C++ name stays whole.
LIMIT = 4096
# A manifest or other multi-line document.
DOCUMENT_LIMIT = 64 * 1024

_SHORT = {"\t": "\\t", "\n": "\\n", "\r": "\\r"}
# Unicode categories that print nothing visible or act: control, format (bidi overrides, zero
# width), surrogates, private use, unassigned, line and paragraph separators.
_UNSAFE = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def _escape(ch: str) -> str:
    if ch in _SHORT:
        return _SHORT[ch]
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def printable(value: str, limit: int | None = LIMIT, multiline: bool = False) -> str:
    """The value with control and format characters escaped (\\x1b, \\n, \\u202e) and at most
    `limit` characters of it kept, the rest counted. `multiline` keeps newlines and tabs."""
    keep = "\n\t" if multiline else ""
    if limit is not None and len(value) > limit:
        value, rest = value[:limit], len(value) - limit
    else:
        rest = 0
    out = "".join(
        _escape(ch) if ch not in keep and unicodedata.category(ch) in _UNSAFE else ch
        for ch in value
    )
    return out + (f"... ({rest} more characters)" if rest else "")


def decoded(data: bytes, encoding: str, limit: int | None = LIMIT, multiline: bool = False) -> str:
    """Bytes from a target decoded (undecodable bytes replaced), then made printable."""
    return printable(data.decode(encoding, "replace"), limit, multiline)
