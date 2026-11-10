"""A port's patch sites, declared once and checked against an executable.

A declaration (JSON, schema "rea-image-sites-v1") names the executable by hash and lists every
address the port uses, each with a kind, the bytes it expects there where that applies, and the
evidence it rests on:

  {"schema": "rea-image-sites-v1",
   "source": {"name": "Game.exe", "sha256": "...", "bytes": 1234, "image_base": "0x400000",
              "entry_rva": "0x1000"},
   "sites": [
     {"name": "load_config", "kind": "call", "rva": "0x1234", "expected": "e8...", "target": "MyLoad",
      "evidence": "ev_..."},
     {"name": "skip_check", "kind": "edit", "rva": "0x2000", "expected": "7505", "replacement": "eb05",
      "evidence": "..."},
     {"name": "save_file", "kind": "function", "rva": "0x3000", "expected": "4055488bec", "evidence": "..."},
     {"name": "create_file_slot", "kind": "iat", "rva": "0x5000", "import": "KERNEL32.dll!CreateFileW",
      "evidence": "..."},
     {"name": "settings", "kind": "data", "rva": "0x6000", "evidence": "...", "writable": true},
     {"name": "option_block", "kind": "range", "rva": "0x1800", "size": "0x200", "evidence": "..."},
     {"name": "player_health", "kind": "offset", "value": "0x1c"}]}

Kinds: call (a 5-byte E8 or 6-byte FF 15 call the port redirects to `target`), edit (bytes the
port replaces with `replacement`, same length), function (the first bytes of a function the port
calls or hooks), iat (an import slot; `import` names the function it must hold), data (a global,
outside code; `writable` when it must be), range (code the port scans, inside an executable
section), offset (a structure offset: no address, nothing to check). Any other member is the
port's own and kept as it is. Numbers are "0x" strings. A site other than an offset needs
`evidence` (a REA Evidence id, a document, a commit: anything the port can look up).

This is the suite's general checker, for investigating and validating; a port keeps its own copy
of its declaration's reader as its build gate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .pemodel import Image

SCHEMA = "rea-image-sites-v1"
KINDS = ("call", "edit", "function", "iat", "data", "range", "offset")


def number(value) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"expected a hexadecimal string: {value!r}")
    return int(value, 16)


def load(path: Path) -> dict:
    """The declaration, or ValueError naming what is wrong with it."""
    spec = json.loads(Path(path).read_text())
    if spec.get("schema") != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA!r}")
    source = spec.get("source") or {}
    for key in ("name", "sha256"):
        if not source.get(key):
            raise ValueError(f"source needs {key}")
    for key in ("image_base", "entry_rva"):
        if key in source:
            number(source[key])
    names = set()
    for site in spec.get("sites", []):
        name, kind = site.get("name"), site.get("kind")
        if not isinstance(name, str) or not name.isidentifier() or name in names:
            raise ValueError(f"site names are unique identifiers: {name!r}")
        names.add(name)
        if kind not in KINDS:
            raise ValueError(f"{name}: kind is one of {', '.join(KINDS)}")
        if kind == "offset":
            number(site.get("value"))
            continue
        number(site.get("rva"))
        if not site.get("evidence"):
            raise ValueError(f"{name}: a site needs evidence")
        if kind in ("call", "edit", "function"):
            expected = bytes.fromhex(site.get("expected", ""))
            if not expected:
                raise ValueError(f"{name}: expected bytes are required")
            if kind == "call" and (len(expected) not in (5, 6) or not site.get("target")):
                raise ValueError(f"{name}: a call site is a 5- or 6-byte call with a target")
            if kind == "edit" and len(bytes.fromhex(site.get("replacement", ""))) != len(expected):
                raise ValueError(f"{name}: an edit keeps its length")
        if kind == "range":
            number(site.get("size"))
    return spec


def verify(spec: dict, image: Image, data: bytes) -> list[str]:
    """Every way the executable differs from the declaration; empty when it agrees."""
    problems = []
    source = spec["source"]
    digest = hashlib.sha256(data).hexdigest()
    if digest != source["sha256"].lower():
        problems.append(f"source: sha256 {digest} is not the declared {source['sha256']}")
    if "bytes" in source and len(data) != source["bytes"]:
        problems.append(f"source: {len(data)} bytes, declared {source['bytes']}")
    if "image_base" in source and image.base != number(source["image_base"]):
        problems.append(f"source: image base {image.base:#x}, declared {source['image_base']}")
    if "entry_rva" in source and image.entry != number(source["entry_rva"]):
        problems.append(f"source: entry {image.entry:#x}, declared {source['entry_rva']}")
    slots = image.iat_slots
    for site in spec.get("sites", []):
        kind, name = site["kind"], site["name"]
        if kind == "offset":
            continue
        rva = number(site["rva"])
        section = image.section_at(rva)
        if kind in ("call", "edit", "function"):
            expected = bytes.fromhex(site["expected"])
            try:
                actual = image.read(rva, len(expected))
            except ValueError:
                problems.append(f"{name}: {rva:#x} is not in the file")
                continue
            if actual != expected:
                problems.append(f"{name}: {actual.hex()} at {rva:#x}, expected {expected.hex()}")
            elif kind == "call" and not (expected[0] == 0xE8 or expected[:2] == b"\xff\x15"):
                problems.append(f"{name}: {expected.hex()} is not an E8 or FF 15 call")
            if section is None or not section.executable:
                problems.append(f"{name}: {rva:#x} is not in code")
        elif kind == "range":
            end = rva + number(site["size"])
            if section is None or not section.executable or end > section.end:
                problems.append(f"{name}: {rva:#x}..{end:#x} is not inside one code section")
        elif kind == "iat":
            row = slots.get(rva)
            if row is None:
                problems.append(f"{name}: {rva:#x} is no import slot")
            elif "import" in site and site["import"].lower() != row.label.lower():
                problems.append(f"{name}: the slot holds {row.label}, declared {site['import']}")
        elif kind == "data":
            if section is None or section.executable:
                problems.append(f"{name}: {rva:#x} is not in a data section")
            elif site.get("writable") and not section.writable:
                problems.append(f"{name}: {rva:#x} is in read-only {section.name}")
    return problems


def skeleton(image: Image, data: bytes, name: str) -> dict:
    """A new declaration for this executable, with no sites yet."""
    return {
        "schema": SCHEMA,
        "source": {
            "name": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "image_base": f"{image.base:#x}",
            "entry_rva": f"{image.entry:#x}",
        },
        "sites": [],
    }
