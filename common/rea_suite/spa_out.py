"""Writers for an Xbox 360 SPA (rea_suite.spa): the whole of it as JSON, or the platform's declarations.

  json          spa.json (everything read), images/<id>.png, xlast.xml when the SPA embeds one
  declarations  master-sdk's gm-achievements-v1 (achievements.json) and gm-presence-v1
                (presence.json), in one language, then checked with master-sdk's declarations.py

The declarations hold printable ASCII within master-sdk's limits (sdk/tests/contract/
declarations-v1/limits.json, read from the master-sdk checkout when there is one). Text is
folded to ASCII (accents dropped, typographic quotes and dashes made plain, line breaks joined),
each change reported; what still breaks a limit stops the run with its place, never cut short. A
picture over the limits is scaled down (PngScaler) and reported. One writer per format (WRITERS).
"""

from __future__ import annotations

import base64
import json
import os
import re
import struct
import subprocess
import sys
import unicodedata
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from rea_suite import spa as spa_reader
from rea_suite.spa import PNG, Spa, snake
from rea_suite.text import printable

# master-sdk's limits when its checkout is not here; Limits' parity test holds them to the file.
FALLBACK_LIMITS = {
    "achievements": {
        "maxGameLength": 32,
        "maxEntries": 1024,
        "minId": 1,
        "maxId": 4294967295,
        "maxText": 200,
        "pictureMaxBytes": 65536,
        "pictureMaxSide": 256,
    },
    "presence": {
        "maxEntries": 64,
        "entryIdPattern": "^[a-z][a-z0-9_]{0,31}$",
        "maxTemplate": 200,
        "maxTokens": 8,
        "maxLists": 32,
        "listNamePattern": "^[a-z][a-z0-9_]{0,31}$",
        "maxChoices": 4096,
        "choiceIdPattern": "^[a-z0-9_-]{1,32}$",
        "maxChoiceText": 64,
    },
}
SDK_ENV = "REA_MASTER_SDK"
SDK_DEFAULT = Path.home() / "Dev" / "Falcon" / "master-sdk"
LIMITS = Path("sdk/tests/contract/declarations-v1/limits.json")
CHECKER = Path("sdk/tools/declarations.py")


class DeclarationError(ValueError):
    """The SPA does not fit the declarations; the message names where."""


@dataclass
class Options:
    out: Path
    lang: str = "en-US"
    game: str | None = None
    sdk: Path | None = None
    notes: list[str] = field(default_factory=list)


class Writer(Protocol):
    """One output format: writes into options.out and returns the files written."""

    name: str

    def write(self, spa: Spa, options: Options) -> list[Path]: ...


# JSON --------------------------------------------------------------------------------------------


def png_size(data: bytes) -> tuple[int, int]:
    return struct.unpack(">II", data[16:24]) if len(data) >= 24 else (0, 0)


class JsonWriter:
    name = "json"

    def write(self, spa: Spa, options: Options) -> list[Path]:
        out = options.out
        (out / "images").mkdir(parents=True, exist_ok=True)
        names = spa.meta.get("XITB", {}).get("names", {})
        images, files = [], []
        for image_id, data in sorted(spa.images.items()):
            path = out / "images" / f"{image_id}.png"
            path.write_bytes(data)
            files.append(path)
            width, height = png_size(data)
            images.append(
                {
                    "id": image_id,
                    "file": f"images/{image_id}.png",
                    "name": names.get(image_id),
                    "bytes": len(data),
                    "width": width,
                    "height": height,
                }
            )
        xlast = None
        if spa.xlast_bytes is not None:
            path = out / "xlast.xml"
            path.write_bytes(spa.xlast_bytes)
            files.append(path)
            xl = spa.xlast or {}
            xlast = {
                "file": "xlast.xml",
                "source": spa.meta.get("XSRC", {}),
                "project": xl.get("project"),
                "elements": xl.get("elements"),
                "statsViews": xl.get("statsViews"),
            }
        doc = {
            "format": "rea-xbox360-spa-v1",
            "title": spa.title(),
            "summary": spa.summary(),
            "achievements": spa.achievements(),
            "presence": spa.presence(),
            "stats": spa.meta.get("XVC2"),
            "matchmaking": spa.meta.get("XMAT"),
            "propertyBag": spa.meta.get("XPBM"),
            "images": images,
            "strings": {
                lang: {str(k): v for k, v in sorted(table.items())}
                for lang, table in sorted(spa.strings.items())
            },
            "xlast": xlast,
            "crossCheck": {"checked": spa.xlast is not None, "differences": spa.notes},
            "sections": spa.sections,
            "unknown": spa.unknown + (spa.xlast or {}).get("unknown", []),
        }
        path = out / "spa.json"
        path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return [path, *files]


# Pictures ----------------------------------------------------------------------------------------


class PictureScaler(Protocol):
    """Makes a PNG fit a side and a size; the picture unchanged when it already does."""

    def fit(self, png: bytes, side: int, max_bytes: int) -> bytes: ...


class PngScaler:
    """PNG decoding, box-filter scaling and encoding in Python's standard library: 8-bit, not
    interlaced, every color type. Achievement pictures are 64x64, so this rarely runs."""

    def fit(self, png: bytes, side: int, max_bytes: int) -> bytes:
        width, height = png_size(png)
        if 1 <= width <= side and 1 <= height <= side and len(png) <= max_bytes:
            return png
        w, h, rgba = decode_png(png)
        target = side
        while target >= 8:
            scale = min(1.0, target / max(w, h))
            sw, sh = max(1, round(w * scale)), max(1, round(h * scale))
            out = encode_png(sw, sh, box_scale(w, h, rgba, sw, sh))
            if len(out) <= max_bytes:
                return out
            target //= 2
        raise DeclarationError(f"a {w}x{h} picture does not fit {max_bytes} bytes even at 8x8")


def decode_png(data: bytes) -> tuple[int, int, bytes]:
    """Width, height and RGBA pixels of an 8-bit, non-interlaced PNG."""
    if data[:8] != PNG:
        raise DeclarationError("a picture that is not a PNG")
    at, idat, palette, alpha = 8, b"", b"", b""
    width = height = depth = color = interlace = 0
    while at + 8 <= len(data):
        length, kind = struct.unpack(">I4s", data[at : at + 8])
        body = data[at + 8 : at + 8 + length]
        if kind == b"IHDR":
            width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", body)
        elif kind == b"PLTE":
            palette = body
        elif kind == b"tRNS":
            alpha = body
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        at += 12 + length
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color)
    if depth != 8 or interlace or channels is None or not 0 < width * height <= 1 << 24:
        raise DeclarationError(
            f"a PNG this scaler does not read (depth {depth}, color {color}, interlace {interlace})"
        )
    raw = zlib.decompress(idat)
    stride = width * channels
    rows, prev = [], bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        kind, line = raw[start], bytearray(raw[start + 1 : start + 1 + stride])
        for x in range(stride):
            a = line[x - channels] if x >= channels else 0
            b = prev[x]
            c = prev[x - channels] if x >= channels else 0
            if kind == 1:
                line[x] = (line[x] + a) & 0xFF
            elif kind == 2:
                line[x] = (line[x] + b) & 0xFF
            elif kind == 3:
                line[x] = (line[x] + (a + b) // 2) & 0xFF
            elif kind == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        rows.append(bytes(line))
        prev = line
    out = bytearray()
    for line in rows:
        for x in range(width):
            px = line[x * channels : (x + 1) * channels]
            if color == 0:
                out += bytes((px[0], px[0], px[0], 255))
            elif color == 2:
                out += px + b"\xff"
            elif color == 3:
                i = px[0]
                out += palette[i * 3 : i * 3 + 3] + bytes((alpha[i] if i < len(alpha) else 255,))
            elif color == 4:
                out += bytes((px[0], px[0], px[0], px[1]))
            else:
                out += px
    return width, height, bytes(out)


def box_scale(w: int, h: int, rgba: bytes, sw: int, sh: int) -> bytes:
    out = bytearray()
    for y in range(sh):
        y0, y1 = y * h // sh, max(y * h // sh + 1, (y + 1) * h // sh)
        for x in range(sw):
            x0, x1 = x * w // sw, max(x * w // sw + 1, (x + 1) * w // sw)
            sums, n = [0, 0, 0, 0], (y1 - y0) * (x1 - x0)
            for yy in range(y0, y1):
                row = yy * w * 4
                for xx in range(x0, x1):
                    p = row + xx * 4
                    for k in range(4):
                        sums[k] += rgba[p + k]
            out += bytes(s // n for s in sums)
    return bytes(out)


def encode_png(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return (
            struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        )

    raw = b"".join(b"\0" + rgba[y * width * 4 : (y + 1) * width * 4] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        PNG + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")
    )


# Text --------------------------------------------------------------------------------------------

PLAIN = str.maketrans(
    {
        "‘": "'",
        "’": "'",
        "‚": "'",
        "“": '"',
        "”": '"',
        "„": '"',
        "–": "-",
        "—": "-",
        "…": "...",
        " ": " ",
        "«": '"',
        "»": '"',
        "ß": "ss",
        "æ": "ae",
        "Æ": "AE",
        "œ": "oe",
        "Œ": "OE",
        "ø": "o",
        "Ø": "O",
        "™": "(TM)",
        "®": "(R)",
        "©": "(C)",
    }
)


def ascii_text(text: str, where: str, limit: int, notes: list[str], joiner: str = " ") -> str:
    """The text as printable ASCII within `limit`, each change noted; DeclarationError otherwise."""
    lines = [line.strip() for line in re.split(r"[\r\n]+", text)]
    folded = joiner.join(line for line in lines if line)
    folded = unicodedata.normalize("NFKD", folded.translate(PLAIN))
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    bad = sorted({c for c in folded if not " " <= c <= "~"})
    if bad:
        shown = ", ".join(f"U+{ord(c):04X}" for c in bad)
        raise DeclarationError(f"{where}: characters with no ASCII form ({shown})")
    if len(folded) > limit:
        raise DeclarationError(f"{where}: {len(folded)} characters, at most {limit}")
    if folded != text:
        notes.append(f"{where}: folded to ASCII {folded!r}")
    return folded


# Declarations ------------------------------------------------------------------------------------


def sdk_root(options: Options) -> Path | None:
    root = options.sdk or Path(os.environ.get(SDK_ENV) or SDK_DEFAULT)
    return root if (root / LIMITS).is_file() else None


def limits(options: Options) -> dict:
    root = sdk_root(options)
    if root is None:
        return FALLBACK_LIMITS
    return json.loads((root / LIMITS).read_text(encoding="utf-8"))


class DeclarationsWriter:
    name = "declarations"

    def __init__(self, scaler: PictureScaler | None = None):
        self.scaler = scaler or PngScaler()

    def write(self, spa: Spa, options: Options) -> list[Path]:
        lim = limits(options)
        game = options.game or spa.title()["titleId"] or ""
        if not 1 <= len(game) <= lim["achievements"]["maxGameLength"]:
            raise DeclarationError(f"game id {game!r}: 1 to 32 characters (--game)")
        options.out.mkdir(parents=True, exist_ok=True)
        written = []
        achievements = self.achievements(spa, options, lim["achievements"], game)
        path = options.out / "achievements.json"
        path.write_text(json.dumps(achievements, indent=2) + "\n", encoding="utf-8")
        written.append(path)
        presence = self.presence(spa, options, lim["presence"], game)
        if presence is not None:
            path = options.out / "presence.json"
            path.write_text(json.dumps(presence, indent=2) + "\n", encoding="utf-8")
            written.append(path)
        return written

    def pick(
        self, spa: Spa, texts: dict[str, str] | None, where: str, options: Options
    ) -> str | None:
        """The text in --lang, else in the title's default language (noted)."""
        if not texts:
            return None
        if options.lang in texts:
            return texts[options.lang]
        fallback = texts.get(spa.default_language)
        if fallback is None:
            raise DeclarationError(f"{where}: not in {options.lang} nor {spa.default_language}")
        options.notes.append(f"{where}: no {options.lang} text, took {spa.default_language}")
        return fallback

    def achievements(self, spa: Spa, options: Options, lim: dict, game: str) -> dict:
        rows, notes = [], options.notes
        entries = spa.achievements()
        if len(entries) > lim["maxEntries"]:
            raise DeclarationError(f"{len(entries)} achievements, at most {lim['maxEntries']}")
        for a in entries:
            where = f"achievement {a['id']}"
            if not lim["minId"] <= a["id"] <= lim["maxId"]:
                raise DeclarationError(f"{where}: id out of {lim['minId']}..{lim['maxId']}")
            name = self.pick(spa, a["name"], f"{where} name", options)
            if not name:
                raise DeclarationError(f"{where}: no name")
            unlocked = self.pick(spa, a["unlockedDescription"], f"{where} description", options)
            locked = self.pick(spa, a["lockedDescription"], f"{where} locked description", options)
            if locked is None:
                # The 360 shows the description of a locked achievement that has no locked one;
                # a secret one shows none.
                locked = "" if a["secret"] else unlocked or ""
            picture = spa.images.get(a["imageId"])
            if picture is None:
                notes.append(f"{where}: image {a['imageId']} is not in the SPA, no picture")
            else:
                fitted = self.scaler.fit(picture, lim["pictureMaxSide"], lim["pictureMaxBytes"])
                if fitted != picture:
                    w, h = png_size(picture)
                    nw, nh = png_size(fitted)
                    notes.append(
                        f"{where}: picture {w}x{h} scaled to {nw}x{nh} ({len(fitted)} bytes)"
                    )
                picture = base64.b64encode(fitted).decode("ascii")
            text = lim["maxText"]
            rows.append(
                {
                    "id": a["id"],
                    "name": ascii_text(name, f"{where} name", text, notes),
                    "lockedDescription": ascii_text(
                        locked, f"{where} locked description", text, notes
                    ),
                    "unlockedDescription": ascii_text(
                        unlocked or "", f"{where} description", text, notes
                    ),
                    "points": a["points"],
                    "type": a["typeNumber"],
                    "secret": a["secret"],
                    "picture": picture,
                    "group": None,
                }
            )
        return {"format": "gm-achievements-v1", "game": game, "achievements": rows}

    def presence(self, spa: Spa, options: Options, lim: dict, game: str) -> dict | None:
        p = spa.presence()
        if not p["modes"]:
            options.notes.append("presence: no modes in this SPA, presence.json not written")
            return None
        if any(m["template"] is None for m in p["modes"]):
            options.notes.append(
                "presence: the modes' templates are only in the XLAST, which this SPA does not"
                " embed; presence.json not written"
            )
            return None
        notes = options.notes
        contexts = {int(c["id"], 16): c for c in p["contexts"]}
        properties = {int(q["id"], 16): q for q in p["properties"]}
        lists: dict[str, dict[str, str]] = {}
        entries, ids = [], set()

        def context_token(number: int, where: str) -> dict:
            c = contexts.get(number)
            if c is None or not c["values"]:
                raise DeclarationError(f"{where}: {{c{number}}} names no context with values")
            name = snake(c["friendlyName"]) or f"context_{number:x}"
            if not re.fullmatch(lim["listNamePattern"], name):
                raise DeclarationError(f"{where}: list name {name!r} does not fit")
            if name not in lists:
                choices = {}
                for v in c["values"]:
                    choice = snake(v["friendlyName"])[:32] or str(v["value"])
                    if not re.fullmatch(lim["choiceIdPattern"], choice) or choice in choices:
                        choice = str(v["value"])
                    text = self.pick(spa, v["text"], f"{name} value {v['value']}", options)
                    choices[choice] = ascii_text(
                        text or v["friendlyName"] or str(v["value"]),
                        f"{name} value {v['value']}",
                        lim["maxChoiceText"],
                        notes,
                    )
                if len(choices) > lim["maxChoices"]:
                    raise DeclarationError(f"list {name}: {len(choices)} choices")
                lists[name] = choices
            return {"name": name, "kind": "choice", "list": name}

        def property_token(number: int, where: str) -> dict:
            q = next(
                (v for k, v in properties.items() if k == number or k & 0xFFFF == number), None
            )
            if q is None:
                raise DeclarationError(f"{where}: {{p{number}}} names no property")
            name = snake(q["friendlyName"]) or f"property_{number:x}"
            kinds = {"int32": "number", "int64": "number", "double": "number", "float": "number"}
            kind = "name" if q["type"] == "unicode" else kinds.get(q["type"])
            if kind is None:
                raise DeclarationError(f"{where}: property {q['id']} of type {q['type']}")
            return {"name": name, "kind": kind}

        for m in p["modes"]:
            where = f"presence mode {m['value']}"
            entry_id = snake(m["friendlyName"]) or f"mode_{m['value']}"
            if not re.fullmatch(lim["entryIdPattern"], entry_id) or entry_id in ids:
                entry_id = f"mode_{m['value']}"
            ids.add(entry_id)
            raw = self.pick(spa, m["template"], f"{where} template", options) or ""
            text = ascii_text(raw, f"{where} template", 10**6, notes, joiner=" - ")
            tokens: dict[str, dict] = {}
            parts, at = [], 0
            for match in re.finditer(r"\{([cp])(\d+)\}", text):
                number = int(match.group(2))
                make = context_token if match.group(1) == "c" else property_token
                token = make(number, where)
                tokens.setdefault(token["name"], token)
                parts += [text[at : match.start()], "{" + token["name"] + "}"]
                at = match.end()
            template = "".join(parts) + text[at:]
            if re.search(r"[\[\]{}]", re.sub(r"\{[a-z0-9_]+\}", "", template)):
                raise DeclarationError(
                    f"{where}: brackets in {template!r} that are not placeholders"
                )
            if len(template) > lim["maxTemplate"]:
                raise DeclarationError(f"{where}: template of {len(template)} characters")
            if len(tokens) > lim["maxTokens"]:
                raise DeclarationError(f"{where}: {len(tokens)} tokens")
            entries.append(
                {"id": entry_id, "template": template, "tokens": list(tokens.values()), "data": []}
            )
        if len(entries) > lim["maxEntries"] or len(lists) > lim["maxLists"]:
            raise DeclarationError(f"{len(entries)} presence entries and {len(lists)} lists")
        left = [
            c["id"]
            for c in p["contexts"]
            if c["values"]
            and (snake(c["friendlyName"]) or f"context_{int(c['id'], 16):x}") not in lists
        ]
        if left:
            notes.append(f"presence: contexts no template names, left out: {', '.join(left)}")
        return {"format": "gm-presence-v1", "game": game, "lists": lists, "entries": entries}


def check(folder: Path, options: Options) -> tuple[bool | None, str]:
    """master-sdk's declarations.py `check` on the folder: passed, or None when it is not here."""
    root = sdk_root(options)
    if root is None or not (root / CHECKER).is_file():
        return None, f"not checked: no master-sdk at {options.sdk or SDK_DEFAULT} ({SDK_ENV})"
    run = subprocess.run(
        [sys.executable, "-I", str(root / CHECKER), "check", str(folder)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return run.returncode == 0, (run.stdout + run.stderr).strip()


WRITERS: dict[str, Writer] = {w.name: w for w in (JsonWriter(), DeclarationsWriter())}


def run(path: Path, options: Options, fmt: str) -> int:
    """`rea-suite xbox360 spa`: read, write in the format, check, report on stderr."""
    spa, kind = spa_reader.load(path)
    title = spa.title()
    files = WRITERS[fmt].write(spa, options)

    def say(text: str) -> None:
        print(printable(text, multiline=True), file=sys.stderr)

    say(f"{title['titleId']} {title['name'] or '(no name)'} {title['version']} from the {kind}")
    say(json.dumps(spa.summary()))
    for note in spa.notes:
        say(f"XLAST cross-check: {note}")
    for item in spa.unknown + (spa.xlast or {}).get("unknown", []):
        say(f"unknown: {json.dumps(item)}")
    for note in options.notes:
        say(f"note: {note}")
    for file in files:
        print(file)
    if fmt != "declarations":
        return 0
    passed, report = check(options.out, options)
    verdict = {True: "passed", False: "REFUSED", None: "skipped"}[passed]
    say(f"master-sdk declarations.py check: {verdict}" + (f"\n{report}" if report else ""))
    return 1 if passed is False else 0
