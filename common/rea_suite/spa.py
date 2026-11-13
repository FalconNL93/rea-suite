"""An Xbox 360 title's SPA: achievements, strings, images, rich presence, stats and the embedded XLAST.

The SPA is the XDBF resource an XEX names after its title id. Its metadata sections (namespace 1,
the id its four-letter name) start with that name, a version and a size; the size field is not
relied on (XTHD's is 0 in shipped titles), the entry's length is. Layouts, from Xenia's
xdbf_utils.h and checked against a shipped title's SPA and its own XLAST (Lost: Via Domus):

  XTHD  title id u32, title type u32, version u16 x4 (major, minor, build, revision)
  XSTC  default language u32
  XACH  u16 count; 36 bytes each: id u16, name, unlocked and locked description string ids u16
        (0xFFFF none), image id u32, gamerscore u16, u16, flags u32 (type in bits 0-2, 0x8 shown
        while locked), 16 reserved
  XSTR  (namespace 3, id the language) u16 count; id u16, length u16, UTF-8 bytes
  XCXT  u32 count; id u32, name string id u32, highest value u32, u32
  XPRP  u16 count; id u32, name string id u16, data size u16
  XRPT  a property bag of what presence uses, u16 mode count, a property bag per mode
  XPBM  a property bag: `XPBM`, version, size, u32 context count, u32 property count, the ids
  XMAT  the matchmaking property bag; XITB the images' file names (u32 count; id u32, length
        u32, name); XVC2 stats views (u16 count, the rest not decoded: listed); XSRC the XLAST
        (u32 name length, name, u32 size, u32 compressed size, gzip)

What the binary sections do not hold, the XLAST does: the presence modes' templates, the context
values' strings and every friendly name. When the SPA embeds it, it fills those in and is
compared with the binary sections. A section, namespace or XLAST element this module does not
know is listed, never dropped. One parser per section type (SECTIONS); a new one is one class.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from rea_suite import xdbf, xex
from rea_suite.xdbf import Reader, XdbfError

PNG = b"\x89PNG\r\n\x1a\n"
NONE = 0xFFFF
TITLE_STRING = TITLE_IMAGE = 0x8000
PRESENCE_CONTEXT = 0x8001
MAX_XLAST = 32 << 20
MAX_COUNT = 65536

# XC_LANGUAGE_* (the XDK's xconfig.h), named as XLAST's Translation locales.
LANGUAGES = {
    1: "en-US",
    2: "ja-JP",
    3: "de-DE",
    4: "fr-FR",
    5: "es-ES",
    6: "it-IT",
    7: "ko-KR",
    8: "zh-CHT",
    9: "pt-PT",
    10: "zh-CHS",
    11: "pl-PL",
    12: "ru-RU",
}
# Achievement types (flags bits 0-2), XLAST's achievementType; the numbers are gm-achievements-v1's.
TYPES = {
    0: "None",
    1: "Completion",
    2: "Leveling",
    3: "Unlock",
    4: "Event",
    5: "Tournament",
    6: "Checkpoint",
    7: "Other",
}
SHOW_UNACHIEVED = 0x8
TITLE_TYPES = {0: "system", 1: "full", 2: "demo", 3: "download"}
# A property id's top nibble is its data type (XUSER_DATA_TYPE_*).
PROPERTY_TYPES = {
    0: "context",
    1: "int32",
    2: "int64",
    3: "double",
    4: "unicode",
    5: "float",
    6: "binary",
    7: "datetime",
    0xF: "null",
}


class SpaError(ValueError):
    """No SPA found, or one this module cannot read."""


@dataclass
class Spa:
    """Everything read from one SPA, JSON-ready but for the images and the XLAST's bytes."""

    sections: list[dict] = field(default_factory=list)
    meta: dict[str, dict] = field(default_factory=dict)
    strings: dict[str, dict[int, str]] = field(default_factory=dict)
    images: dict[int, bytes] = field(default_factory=dict)
    unknown: list[dict] = field(default_factory=list)
    xlast_bytes: bytes | None = None
    xlast: dict | None = None
    notes: list[str] = field(default_factory=list)

    # Assembled views ---------------------------------------------------------------------------

    @property
    def default_language(self) -> str:
        code = self.meta.get("XSTC", {}).get("defaultLanguage", 1)
        return LANGUAGES.get(code, f"language-{code}")

    def languages(self) -> list[str]:
        return sorted(self.strings)

    def text(self, string_id: int | None) -> dict[str, str] | None:
        """A string in every language that has it, or None."""
        if string_id is None:
            return None
        found = {
            lang: table[string_id] for lang, table in self.strings.items() if string_id in table
        }
        return found or None

    def title(self) -> dict:
        thd = self.meta.get("XTHD", {})
        project = (self.xlast or {}).get("project", {})
        name = self.text(TITLE_STRING) or {}
        return {
            "titleId": thd.get("titleId"),
            "titleType": thd.get("titleType"),
            "version": thd.get("version"),
            "name": name.get(self.default_language) or project.get("titleName"),
            "names": name,
            "defaultLanguage": self.default_language,
        }

    def achievements(self) -> list[dict]:
        named = {a["id"]: a for a in (self.xlast or {}).get("achievements", [])}
        rows = []
        for a in self.meta.get("XACH", {}).get("achievements", []):
            rows.append(
                {
                    **a,
                    "friendlyName": named.get(a["id"], {}).get("friendlyName"),
                    "name": self.text(a["nameStringId"]),
                    "unlockedDescription": self.text(a["unlockedStringId"]),
                    "lockedDescription": self.text(a["lockedStringId"]),
                }
            )
        return rows

    def presence(self) -> dict:
        xl = self.xlast or {}
        contexts_xl = {c["id"]: c for c in xl.get("contexts", [])}
        contexts = []
        for c in self.meta.get("XCXT", {}).get("contexts", []):
            known = contexts_xl.get(c["id"], {})
            values = [{**v, "text": self.text(v["stringId"])} for v in known.get("values", [])]
            contexts.append(
                {
                    **c,
                    "friendlyName": known.get("friendlyName"),
                    "default": known.get("default"),
                    "name": self.text(c["stringId"]),
                    "values": values,
                }
            )
        props_xl = {p["id"]: p for p in xl.get("properties", [])}
        properties = [
            {
                **p,
                "friendlyName": props_xl.get(p["id"], {}).get("friendlyName"),
                "name": self.text(p["stringId"]),
            }
            for p in self.meta.get("XPRP", {}).get("properties", [])
        ]
        modes_xl = {m["contextValue"]: m for m in xl.get("presenceModes", [])}
        rpt = self.meta.get("XRPT", {})
        modes = []
        for value, bag in enumerate(rpt.get("modes", [])):
            known = modes_xl.get(value, {})
            modes.append(
                {
                    "value": value,
                    "friendlyName": known.get("friendlyName"),
                    "stringId": known.get("stringId"),
                    "template": self.text(known.get("stringId")),
                    "contexts": bag["contexts"],
                    "properties": bag["properties"],
                }
            )
        return {
            "uses": rpt.get("uses"),
            "modes": modes,
            "contexts": contexts,
            "properties": properties,
        }

    def summary(self) -> dict:
        achievements = self.achievements()
        presence = self.presence()
        xl = self.xlast or {}
        types: dict[str, int] = {}
        for a in achievements:
            types[a["type"]] = types.get(a["type"], 0) + 1
        return {
            "achievements": len(achievements),
            "points": sum(a["points"] for a in achievements),
            "secret": sum(a["secret"] for a in achievements),
            "types": types,
            "presenceModes": len(presence["modes"]),
            "contexts": len(presence["contexts"]),
            "contextsInXlast": len(xl.get("contexts", [])),
            "contextValues": sum(len(c.get("values", [])) for c in xl.get("contexts", [])),
            "properties": len(presence["properties"]),
            "propertiesInXlast": len(xl.get("properties", [])),
            "languages": self.languages(),
            "strings": {lang: len(t) for lang, t in sorted(self.strings.items())},
            "images": len(self.images),
            "statsViews": self.meta.get("XVC2", {}).get("views", 0),
            "statsViewsInXlast": len(xl.get("statsViews", [])),
            "xlast": self.xlast_bytes is not None,
            "unknown": len(self.unknown) + len(xl.get("unknown", [])),
        }


# Section parsers --------------------------------------------------------------------------------


class Section(Protocol):
    """One metadata section type: its four-letter magic and how its body reads."""

    magic: bytes

    def parse(self, r: Reader, spa: Spa) -> dict: ...


def bag(r: Reader, at: int) -> tuple[dict, int]:
    """A property bag (XPBM) at `at`: the contexts and properties it names, and where it ends."""
    if r.bytes(at, 4) != b"XPBM":
        raise XdbfError(f"{r.what}: no XPBM at 0x{at:x}")
    contexts, properties = r.u32(at + 12), r.u32(at + 16)
    if contexts + properties > MAX_COUNT:
        raise XdbfError(f"{r.what}: a property bag of {contexts + properties} ids")
    ids = [r.u32(at + 20 + 4 * k) for k in range(contexts + properties)]
    end = at + 20 + 4 * len(ids)
    return {"contexts": ids[:contexts], "properties": ids[contexts:]}, end


def optional_id(value: int) -> int | None:
    return None if value == NONE else value


def counted(r: Reader, at: int, size: int, wide: bool = False) -> int:
    count = r.u32(at) if wide else r.u16(at)
    if count > MAX_COUNT:
        raise XdbfError(f"{r.what}: {count} entries")
    r.check(at + (4 if wide else 2), count * size)
    return count


class TitleHeader:
    magic = b"XTHD"

    def parse(self, r: Reader, spa: Spa) -> dict:
        title, kind = r.u32(12), r.u32(16)
        version = ".".join(str(r.u16(20 + 2 * k)) for k in range(4))
        return {
            "titleId": f"{title:08X}",
            "titleType": TITLE_TYPES.get(kind, kind),
            "version": version,
        }


class DefaultLanguage:
    magic = b"XSTC"

    def parse(self, r: Reader, spa: Spa) -> dict:
        return {"defaultLanguage": r.u32(12)}


class Achievements:
    magic = b"XACH"

    def parse(self, r: Reader, spa: Spa) -> dict:
        rows = []
        for i in range(counted(r, 12, 36)):
            at = 14 + 36 * i
            flags = r.u32(at + 16)
            rows.append(
                {
                    "id": r.u16(at),
                    "nameStringId": r.u16(at + 2),
                    "unlockedStringId": optional_id(r.u16(at + 4)),
                    "lockedStringId": optional_id(r.u16(at + 6)),
                    "imageId": r.u32(at + 8),
                    "points": r.u16(at + 12),
                    "flags": f"0x{flags:08x}",
                    "type": TYPES[flags & 7],
                    "typeNumber": flags & 7,
                    "secret": not flags & SHOW_UNACHIEVED,
                }
            )
        return {"achievements": rows}


class Strings:
    magic = b"XSTR"

    def parse(self, r: Reader, spa: Spa) -> dict:
        table, at = {}, 14
        for _ in range(counted(r, 12, 4)):
            string_id, length = r.u16(at), r.u16(at + 2)
            table[string_id] = r.bytes(at + 4, length).decode("utf-8", "replace")
            at += 4 + length
        return {"strings": table}


class Contexts:
    magic = b"XCXT"

    def parse(self, r: Reader, spa: Spa) -> dict:
        rows = []
        for i in range(counted(r, 12, 16, wide=True)):
            at = 16 + 16 * i
            rows.append(
                {
                    "id": f"0x{r.u32(at):08X}",
                    "stringId": optional_id(r.u32(at + 4)),
                    "maxValue": r.u32(at + 8),
                    "unknown": r.u32(at + 12),
                }
            )
        return {"contexts": rows}


class Properties:
    magic = b"XPRP"

    def parse(self, r: Reader, spa: Spa) -> dict:
        rows = []
        for i in range(counted(r, 12, 8)):
            at = 14 + 8 * i
            prop = r.u32(at)
            rows.append(
                {
                    "id": f"0x{prop:08X}",
                    "type": PROPERTY_TYPES.get(prop >> 28, f"type-{prop >> 28}"),
                    "stringId": optional_id(r.u16(at + 4)),
                    "dataSize": r.u16(at + 6),
                }
            )
        return {"properties": rows}


def hexed(ids: dict) -> dict:
    return {k: [f"0x{v:08X}" for v in values] for k, values in ids.items()}


class RichPresence:
    magic = b"XRPT"

    def parse(self, r: Reader, spa: Spa) -> dict:
        uses, at = bag(r, 12)
        modes, count = [], counted(r, at, 20)
        at += 2
        for _ in range(count):
            mode, at = bag(r, at)
            modes.append(hexed(mode))
        return {"uses": hexed(uses), "modes": modes}


class PropertyBag:
    magic = b"XPBM"

    def parse(self, r: Reader, spa: Spa) -> dict:
        return hexed(bag(r, 0)[0])


class Matchmaking:
    magic = b"XMAT"

    def parse(self, r: Reader, spa: Spa) -> dict:
        return hexed(bag(r, 12)[0])


class ImageNames:
    magic = b"XITB"

    def parse(self, r: Reader, spa: Spa) -> dict:
        names, at = {}, 16
        for _ in range(counted(r, 12, 8, wide=True)):
            image, length = r.u32(at), r.u32(at + 4)
            names[image] = r.bytes(at + 8, length).decode("latin-1")
            at += 8 + length
        return {"names": names}


class StatsViews:
    magic = b"XVC2"

    def parse(self, r: Reader, spa: Spa) -> dict:
        # Only the count and the property bags are decoded; the rest is kept so it can be.
        bags, at = [], r.data.find(b"XPBM", 14)
        while at >= 0:
            found, end = bag(r, at)
            bags.append(hexed(found))
            at = r.data.find(b"XPBM", end)
        return {
            "views": r.u16(12),
            "propertyBags": bags,
            "layout": "not decoded beyond the count and the property bags",
            "bytes": r.data[12:].hex(),
        }


class XlastSource:
    magic = b"XSRC"

    def parse(self, r: Reader, spa: Spa) -> dict:
        length = r.u32(12)
        name = r.bytes(16, length).rstrip(b"\0").decode("latin-1")
        at = 16 + length
        size, packed = r.u32(at), r.u32(at + 4)
        if size > MAX_XLAST:
            raise XdbfError(f"XSRC: an XLAST of {size} bytes (at most {MAX_XLAST})")
        try:
            inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = inflate.decompress(r.bytes(at + 8, packed), MAX_XLAST + 1)
        except zlib.error as exc:
            raise XdbfError(f"XSRC: {exc}") from exc
        if len(data) > MAX_XLAST:
            raise XdbfError(f"XSRC: the XLAST inflates past {MAX_XLAST} bytes")
        if len(data) != size:
            spa.notes.append(f"XSRC: the XLAST is {len(data)} bytes, its header says {size}")
        spa.xlast_bytes = data
        return {"name": name, "size": size, "compressedSize": packed}


SECTIONS: dict[bytes, Section] = {
    s.magic: s
    for s in (
        TitleHeader(),
        DefaultLanguage(),
        Achievements(),
        Strings(),
        Contexts(),
        Properties(),
        RichPresence(),
        PropertyBag(),
        Matchmaking(),
        ImageNames(),
        StatsViews(),
        XlastSource(),
    )
}


# XLAST -------------------------------------------------------------------------------------------

# The elements read; any other element with attributes under these parents is listed as unknown.
XLAST_READ = {
    "LocalizedString",
    "Translation",
    "Achievement",
    "Context",
    "ContextValue",
    "Property",
    "PresenceMode",
    "StatsView",
    "GameConfigProject",
}


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def number(text: str | None) -> int | None:
    if text is None or not text.strip():
        return None
    return int(text, 0)


def parse_xlast(data: bytes) -> dict:
    """The parts of an XLAST (the XDK's title configuration, XML) the SPA leaves out."""
    try:
        root = ET.fromstring(data)  # expat: no external entities, expansion limits
    except ET.ParseError as exc:
        raise SpaError(f"XLAST: {exc}") from exc
    out: dict = {
        "project": {},
        "strings": {},
        "achievements": [],
        "contexts": [],
        "properties": [],
        "presenceModes": [],
        "statsViews": [],
        "unknown": [],
    }
    tags: dict[str, int] = {}
    for el in root.iter():
        name = local(el.tag)
        tags[name] = tags.get(name, 0) + 1
        a = el.attrib
        if name == "GameConfigProject":
            out["project"] = dict(a)
        elif name == "LocalizedString":
            out["strings"][int(a["id"])] = {
                t.get("locale"): (t.text or "") for t in el if local(t.tag) == "Translation"
            }
        elif name == "Achievement":
            out["achievements"].append(
                {
                    "id": int(a["id"]),
                    "friendlyName": a.get("friendlyName"),
                    "type": a.get("achievementType"),
                    "points": number(a.get("cred")),
                    "secret": a.get("showUnachieved") != "true",
                    "imageId": number(a.get("imageId")),
                    "nameStringId": number(a.get("titleStringId")),
                    "unlockedStringId": number(a.get("descriptionStringId")),
                    "lockedStringId": number(a.get("unachievedStringId")),
                }
            )
        elif name == "Context":
            out["contexts"].append(
                {
                    "id": f"0x{int(a['id'], 0):08X}",
                    "friendlyName": a.get("friendlyName"),
                    "stringId": number(a.get("stringId")),
                    "default": number(a.get("defaultValue")),
                    "values": [
                        {
                            "value": int(v.get("value")),
                            "friendlyName": v.get("friendlyName"),
                            "stringId": number(v.get("stringId")),
                        }
                        for v in el
                        if local(v.tag) == "ContextValue"
                    ],
                }
            )
        elif name == "Property":
            out["properties"].append(
                {
                    "id": f"0x{int(a['id'], 0):08X}",
                    "friendlyName": a.get("friendlyName"),
                    "stringId": number(a.get("stringId")),
                    "dataSize": number(a.get("dataSize")),
                }
            )
        elif name == "PresenceMode":
            out["presenceModes"].append(
                {
                    "contextValue": int(a["contextValue"]),
                    "friendlyName": a.get("friendlyName"),
                    "stringId": number(a.get("stringId")),
                }
            )
        elif name == "StatsView":
            out["statsViews"].append(
                {
                    **dict(a),
                    "fields": [dict(f.attrib) for f in el.iter() if local(f.tag) == "Field"],
                }
            )
    out["elements"] = tags
    return out


# Reading ------------------------------------------------------------------------------------------


def read(data: bytes) -> Spa:
    """An SPA (XDBF bytes), every section parsed or listed, its XLAST read and compared."""
    container = xdbf.read(data)
    spa = Spa()
    for entry in container.entries:
        row = {
            "namespace": xdbf.NAMESPACES.get(entry.namespace, entry.namespace),
            "id": f"0x{entry.id:X}",
            "bytes": len(entry.data),
        }
        spa.sections.append(row)
        r = Reader(entry.data, f"{entry.magic.decode('latin-1')} entry")
        if entry.namespace == xdbf.METADATA:
            magic = entry.magic
            row["section"] = magic.decode("latin-1")
            parser = SECTIONS.get(magic)
            if parser is None or entry.data[:4] != magic:
                spa.unknown.append(unknown(entry, "no parser for this section"))
                continue
            spa.meta[magic.decode()] = parser.parse(r, spa)
        elif entry.namespace == xdbf.STRINGS:
            lang = LANGUAGES.get(entry.id, f"language-{entry.id}")
            row["section"] = lang
            if entry.data[:4] != b"XSTR":
                spa.unknown.append(unknown(entry, "a string table without XSTR"))
                continue
            spa.strings[lang] = Strings().parse(Reader(entry.data, f"XSTR {lang}"), spa)["strings"]
        elif entry.namespace == xdbf.IMAGE:
            if entry.data[:8] != PNG:
                spa.unknown.append(unknown(entry, "an image that is not a PNG"))
                continue
            spa.images[entry.id] = entry.data
        else:
            spa.unknown.append(unknown(entry, "unknown namespace"))
    if spa.xlast_bytes is not None:
        try:
            spa.xlast = parse_xlast(spa.xlast_bytes)
        except (KeyError, ValueError) as exc:
            raise SpaError(f"XLAST: {exc!r}") from exc
        spa.notes += cross_check(spa)
    return spa


def unknown(entry: xdbf.Entry, why: str) -> dict:
    return {
        "namespace": entry.namespace,
        "id": f"0x{entry.id:X}",
        "section": entry.magic.decode("latin-1") if entry.namespace == xdbf.METADATA else None,
        "bytes": len(entry.data),
        "head": entry.data[:32].hex(),
        "why": why,
    }


def same_text(a: str, b: str) -> bool:
    # XML parsing turns CRLF into LF; the SPA keeps CRLF.
    return a.replace("\r\n", "\n") == b.replace("\r\n", "\n")


def cross_check(spa: Spa) -> list[str]:
    """Where the XLAST and the binary sections disagree; an empty list when they agree."""
    xl = spa.xlast or {}
    out = []
    binary = {a["id"]: a for a in spa.meta.get("XACH", {}).get("achievements", [])}
    declared = {a["id"]: a for a in xl.get("achievements", [])}
    for missing in sorted(set(binary) ^ set(declared)):
        where = "the XLAST" if missing in binary else "XACH"
        out.append(f"achievement {missing} is not in {where}")
    for key in sorted(set(binary) & set(declared)):
        b, d = binary[key], declared[key]
        for name in ("points", "secret", "imageId", "nameStringId", "unlockedStringId"):
            if b[name] != d[name]:
                out.append(f"achievement {key}: {name} {b[name]} in XACH, {d[name]} in the XLAST")
        if b["type"] != d["type"]:
            out.append(f"achievement {key}: type {b['type']} in XACH, {d['type']} in the XLAST")
    for string_id, translations in xl.get("strings", {}).items():
        for lang, text in translations.items():
            have = spa.strings.get(lang, {}).get(string_id)
            if have is None:
                out.append(f"string {string_id} ({lang}) is in the XLAST only")
            elif not same_text(have, text):
                out.append(f"string {string_id} ({lang}) differs from the XLAST")
    contexts = {c["id"]: c for c in spa.meta.get("XCXT", {}).get("contexts", [])}
    for c in xl.get("contexts", []):
        have = contexts.get(c["id"])
        if have is None:
            out.append(f"context {c['id']} is in the XLAST only")
        elif c["values"] and have["maxValue"] != max(v["value"] for v in c["values"]):
            out.append(f"context {c['id']}: highest value {have['maxValue']} in XCXT")
    props = {p["id"] for p in spa.meta.get("XPRP", {}).get("properties", [])}
    out += [
        f"property {p['id']} is in the XLAST only"
        for p in xl.get("properties", [])
        if p["id"] not in props
    ]
    modes = len(spa.meta.get("XRPT", {}).get("modes", []))
    if modes != len(xl.get("presenceModes", [])):
        out.append(
            f"{modes} presence modes in XRPT, {len(xl.get('presenceModes', []))} in the XLAST"
        )
    return out


def load(path: Path) -> tuple[Spa, str]:
    """An SPA from a default.xex (the title's resource), an .spa or any XDBF file."""
    data = path.read_bytes()
    if data[:4] == xex.MAGIC:
        info, img, _ = xex.image(data)
        return read(xex.title_resource(info, img)), "xex"
    if data[:4] == xdbf.MAGIC:
        return read(data), "xdbf"
    raise SpaError(f"{path.name}: neither an XEX (XEX2) nor an SPA (XDBF)")


def snake(name: str | None) -> str:
    """A friendly name (BaseStatus, GAME_EPISODE) as lowercase_with_underscores."""
    if not name:
        return ""
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
