"""yetibig and lzo1x: LZO1X streams built by hand (and by liblzo2 or python-lzo when present), and tiny
Yeti.big archives built here (a duplicated resource, LZO bodies, a key list, a flag the format leaves
unknown), read back through every command. No game data.

The real archives are opt-in: REA_YETIBIG_PC and REA_YETIBIG_X360 name Lost: Via Domus's Yeti.big files;
the test reads them whole, so run it under `heavy run`."""

from __future__ import annotations

import ctypes
import ctypes.util
import io
import json
import os
import random
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rea_suite import lzo1x, yetibig

END = b"\x11\x00\x00"  # M4 with distance 0: the end marker
CLASSES = [0x12B0, 0x50E1, 0x3434, 0x0520] + [0] * 252

# Hand-built streams and what they unpack to.
VECTORS = [
    # first byte 17 + n: n literals
    (b"\x16hello" + END, b"hello"),
    # four literals, then M3 (t 0x26: length 6 + 2, distance (0x0c >> 2) + 1 = 4), overlapping
    (b"\x15abcd\x26\x0c\x00" + END, b"abcdabcdabcd"),
    # four literals, M2 (t 0x46: length 3, distance 2, two trailing literals), then a two-byte match
    # at distance 1 (t < 16 after 1-3 literals)
    (b"\x15abcd\x46\x00xy\x00\x00" + END, b"abcdcdcxyyy"),
    # a long literal run: t 0, one zero byte (255), then 27: 3 + 15 + 255 + 27 = 300 literals
    (
        b"\x00\x00\x1b" + bytes(range(256)) + bytes(range(44)) + END,
        bytes(range(256)) + bytes(range(44)),
    ),
]


def m4_vector() -> tuple[bytes, bytes]:
    """20000 literals, then M4 (t 0x17: length 7 + 2, distance 0x4000 + 5)."""
    rng = random.Random(7)
    lits = bytes(rng.randrange(256) for _ in range(20000))
    n = len(lits) - 3 - 15
    run = b"\x00" + b"\x00" * (n // 255) + bytes([n % 255])
    if n % 255 == 0:
        raise AssertionError("pick another length")
    stream = run + lits + b"\x17\x14\x00" + END
    start = len(lits) - (0x4000 + 5)
    return stream, lits + lits[start : start + 9]


def m1_after_run_vector() -> tuple[bytes, bytes]:
    """3000 literals, then t 0x04 after the run: three bytes from 1 + 0x800 + 1 + (0 << 2) = 2050 back."""
    lits = bytes(i * 7 % 251 for i in range(3000))
    n = len(lits) - 3 - 15
    stream = b"\x00" + b"\x00" * (n // 255) + bytes([n % 255]) + lits + b"\x04\x00" + END
    start = len(lits) - 2050
    return stream, lits + lits[start : start + 3]


def liblzo2_compress():
    """lzo1x_1_compress through ctypes, or None."""
    name = ctypes.util.find_library("lzo2")
    if not name:
        return None
    fn = ctypes.CDLL(name).lzo1x_1_compress
    fn.restype = ctypes.c_int

    def run(data: bytes) -> bytes:
        dst = ctypes.create_string_buffer(len(data) + len(data) // 16 + 64 + 3)
        size = ctypes.c_size_t(len(dst))
        work = ctypes.create_string_buffer(16384 * ctypes.sizeof(ctypes.c_void_p))
        if fn(data, ctypes.c_size_t(len(data)), dst, ctypes.byref(size), work) != 0:
            raise AssertionError("lzo1x_1_compress failed")
        return dst.raw[: size.value]

    return run


def compressors() -> list:
    found = []
    lib = liblzo2_compress()
    if lib:
        found.append(("liblzo2", lib))
    try:
        import lzo  # type: ignore[import-not-found]

        # python-lzo prefixes a 5-byte header (0xf0 and the big-endian length) unless told not to
        found.append(("python-lzo", lambda data: lzo.compress(data, 1, False)))
    except ImportError:
        pass
    return found


def sample_data() -> bytes:
    rng = random.Random(1)
    words = [b"Locke", b"Jack", b"Kate", b"Hatch", b"\x00\x00\x00\x01", b"0123456789" * 3]
    return b"".join(rng.choice(words) for _ in range(30000)) + bytes(
        rng.randrange(256) for _ in range(5000)
    )


class Lzo1xTest(unittest.TestCase):
    def test_hand_built_streams(self) -> None:
        for stream, expected in [*VECTORS, m4_vector(), m1_after_run_vector()]:
            out, used = lzo1x.decompress(stream, len(expected))
            self.assertEqual(out, expected)
            self.assertEqual(used, len(stream))
            self.assertEqual(lzo1x.unpack(stream, len(expected)), expected)
            with patch.object(lzo1x, "LIBLZO2", None):
                self.assertEqual(lzo1x.unpack(stream, len(expected)), expected)

    def test_malformed_streams_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "lookbehind"):
            lzo1x.decompress(b"\x12x\x26\x0c\x00" + END)  # one literal, then four bytes back
        with self.assertRaisesRegex(ValueError, "input overrun"):
            lzo1x.decompress(b"\x16hel")
        with self.assertRaisesRegex(ValueError, "expected 6"):
            lzo1x.decompress(b"\x16hello" + END, 6)
        with self.assertRaisesRegex(ValueError, "overrun past 3"):
            lzo1x.decompress(b"\x16hello" + END, 3)
        with self.assertRaises(ValueError):
            lzo1x.unpack(b"\x16hello" + END, 6)

    def test_streams_from_a_real_compressor(self) -> None:
        found = compressors()
        if not found:
            self.skipTest("neither liblzo2 nor python-lzo is installed")
        data = sample_data()
        for name, compress in found:
            with self.subTest(name):
                stream = compress(data)
                self.assertLess(len(stream), len(data))
                self.assertEqual(lzo1x.decompress(stream, len(data)), (data, len(stream)))
                self.assertEqual(lzo1x.unpack(stream, len(data)), data)


def resource(
    body: bytes, flags: int = 0, keys: tuple[int, ...] = (), stream: bytes | None = None
) -> bytes:
    out = bytes([1, flags])
    if flags & 0x08:
        out += struct.pack("<I", len(body))
    if flags & 0x02:
        out += struct.pack(f"<H{len(keys)}I", len(keys), *keys)
    return out + (stream if flags & 0x08 else body)


def literal_stream(data: bytes) -> bytes:
    assert 4 <= len(data) <= 238
    return bytes([17 + len(data)]) + data + END


TEXT = b"abcdabcdabcd"
TEXT_STREAM = VECTORS[1][0]


def items() -> list[tuple[int, int, bytes, int]]:
    """key, type (class slot), stored bytes, copies."""
    return [
        (0x0A, 1, resource(b"raw body"), 1),
        (0x0B, 1, resource(b"listing", 0x02, (0x0A, 0xDEAD, 0xFFFFFFFF)), 1),
        (0x0C, 2, resource(TEXT, 0x0A, (0x0B,), TEXT_STREAM), 2),
        (0x0D, 3, b"\x01\x03??", 1),
    ]


def build(path: Path, entries, version: int = 0x57, gap: int = 16) -> Path:
    """A Yeti.big: the duplicate list (key 0x1000, LZO) first, `gap` zero bytes, then the resources."""
    copies = sum(c for *_, c in entries if c > 1)
    dup_size = len(
        resource(bytes(4 + 4 * copies), 0x08, stream=literal_stream(bytes(4 + 4 * copies)))
    )
    pos = dup_size + gap
    table, dups, placed = [], [], []
    for key, kind, blob, count in entries:
        offsets = []
        for _ in range(count):
            offsets.append(pos)
            placed.append((pos, blob))
            pos += len(blob)
        if count == 1:
            stored = offsets[0]
        else:
            stored = 0xFE000000 | count << 18 | len(dups)
            dups += offsets
        table.append((stored, key, kind << 24 | len(blob)))
    body = struct.pack(f"<I{len(dups)}I", len(dups), *dups)
    table.insert(0, (0, 0x1000, len(resource(body, 0x08, stream=literal_stream(body)))))
    data = bytearray(pos)
    data[:dup_size] = resource(body, 0x08, stream=literal_stream(body))
    for at, blob in placed:
        data[at : at + len(blob)] = blob
    header = bytearray(0x268)
    struct.pack_into("<HBxII", header, 0, version, 1, len(table), 0x10000)
    header[0x36:0x3C] = b"/Data/"
    struct.pack_into("<256H", header, 0x68, *CLASSES)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(header) + b"".join(struct.pack("<III", *row) for row in table) + data)
    return path


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = yetibig.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class YetibigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.big = build(self.dir / "game" / "Yeti.big", items())

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_info(self) -> None:
        code, out, _ = run("info", str(self.big), "--json")
        self.assertEqual(code, 0)
        info = json.loads(out)
        self.assertEqual((info["version"], info["entries"], info["root"]), (0x57, 5, "/Data/"))
        self.assertEqual((info["placed"], info["duplicated"], info["copies"]), (4, 1, 2))
        self.assertEqual(info["data_base"], 0x268 + 12 * 5)
        self.assertEqual({t["class"]: t["entries"] for t in info["types"]}[0x50E1], 2)
        code, out, _ = run("info", str(self.big))
        self.assertIn("class 50e1  2", out)

    def test_list(self) -> None:
        code, out, _ = run("list", str(self.big), "--json")
        self.assertEqual(code, 0)
        rows = {e["key"]: e for e in json.loads(out)["entries"]}
        base = 0x268 + 12 * 5
        self.assertEqual(len(rows[0x0C]["offsets"]), 2)
        self.assertEqual(rows[0x0C]["flags"], 0x0A)
        self.assertEqual(rows[0x0D]["flags"], 0x03)
        self.assertEqual(rows[0x1000]["offsets"], [base])
        raw = self.big.read_bytes()
        for row in rows.values():
            for at in row["offsets"]:
                self.assertEqual(raw[at], 1)
        code, out, _ = run("list", str(self.big), "--class", "50e1")
        self.assertEqual([line.split()[0] for line in out.splitlines()], ["0000000a", "0000000b"])
        self.assertEqual(run("list", str(self.big), "--class", "7777")[0], 1)

    def test_blob(self) -> None:
        out = self.dir / "out"
        code, text, _ = run("blob", str(self.big), "c", "0x1000", "d", "0b", "--out", str(out))
        self.assertEqual(code, 0)
        self.assertEqual((out / "0000000c.bin").read_bytes(), TEXT)
        self.assertEqual((out / "0000000b.bin").read_bytes(), b"listing")
        dups = (out / "00001000.bin").read_bytes()
        self.assertEqual(struct.unpack_from("<I", dups)[0], 2)
        self.assertEqual((out / "0000000d.stored").read_bytes(), b"\x01\x03??")
        self.assertIn("flags 0x03 not known", text)
        self.assertIn("keys 0000000a 0000dead ffffffff", text)
        run("blob", str(self.big), "c", "--out", str(out), "--raw")
        self.assertEqual((out / "0000000c.bin").read_bytes(), items()[2][2])
        self.assertEqual(run("blob", str(self.big), "beef", "--out", str(out))[0], 1)

    def test_diff(self) -> None:
        changed = items()
        changed[1] = (0x0B, 1, resource(b"listing, longer", 0x02, (0x0A, 0xDEAD)), 1)
        del changed[2]
        changed.append((0x0E, 2, resource(b"new"), 1))
        other = build(self.dir / "other" / "Yeti.big", changed)
        code, out, _ = run("diff", str(self.big), str(other), "--json")
        self.assertEqual(code, 0)
        diff = json.loads(out)
        self.assertEqual([e["key"] for e in diff["only_a"]], [0x0C])
        self.assertEqual([e["key"] for e in diff["only_b"]], [0x0E])
        # the duplicate list (0x1000) shrinks too: the other archive has no duplicated resource
        self.assertEqual(sorted(e["key"] for e in diff["size_differs"]), [0x0B, 0x1000])
        self.assertEqual(diff["same_size"], 2)
        self.assertEqual(diff["by_class"]["only_a"], {"3434": 1})
        code, out, _ = run("diff", str(self.big), str(other))
        self.assertIn("in both, size differs: 2; same size: 2", out)

    def test_refs(self) -> None:
        code, out, _ = run("refs", str(self.big), "--json")
        self.assertEqual(code, 0)
        refs = json.loads(out)
        self.assertEqual(sorted(e["key"] for e in refs["unreferenced"]), [0x0C, 0x0D, 0x1000])
        self.assertEqual(refs["absent"], [{"key": 0xDEAD, "uses": 1}])
        self.assertEqual(refs["absent_uses_by_referrer_class"], {"50e1": 1})
        self.assertEqual([s["key"] for s in refs["skipped"]], [0x0D])
        self.assertEqual(refs["referenced"], 2)

    def test_check(self) -> None:
        code, out, _ = run("check", str(self.big), "--json")
        self.assertEqual(code, 0, out)
        proof = json.loads(out)
        self.assertTrue(proof["ok"])
        self.assertTrue(proof["slots_tile_list"])
        self.assertEqual(proof["regions"], 6)
        self.assertEqual(proof["overlaps"], [])
        self.assertEqual(
            [(g["size"], g["zero"], g["after"]) for g in proof["gaps"]], [(16, True, 0x1000)]
        )
        self.assertEqual(proof["decoded_by_flags"], {"0x00": 1, "0x02": 1, "0x08": 1, "0x0a": 1})
        self.assertEqual(proof["unknown_flags"], [{"key": 0x0D, "flags": 3}])
        code, out, _ = run("check", str(self.big))
        self.assertIn("the proof holds", out)

    def test_check_without_liblzo2(self) -> None:
        with patch.object(lzo1x, "LIBLZO2", None):
            code, out, _ = run("check", str(self.big))
        self.assertEqual(code, 0, out)

    def test_check_finds_a_differing_copy_and_a_bad_body(self) -> None:
        raw = bytearray(self.big.read_bytes())
        archive = yetibig.read_archive(self.big)
        offsets = archive.copies(archive.by_key()[0x0C])
        raw[offsets[1] + len(items()[2][2]) - 4] ^= 0xFF  # the second copy's LZO stream
        raw[offsets[0] + len(items()[2][2]) - 3] = (
            0x01  # the first copy's end marker, now a literal run
        )
        self.big.write_bytes(bytes(raw))
        code, out, _ = run("check", str(self.big), "--json")
        self.assertEqual(code, 1)
        proof = json.loads(out)
        self.assertEqual([d["key"] for d in proof["copies_differing"]], [0x0C])
        self.assertEqual([f["key"] for f in proof["failed"]], [0x0C])

    def test_check_finds_an_overlap(self) -> None:
        raw = bytearray(self.big.read_bytes())
        at = 0x268 + 12 * 2  # entry 2 (key 0x0b) moved onto entry 1 (key 0x0a)
        struct.pack_into("<I", raw, at, struct.unpack_from("<I", raw, 0x268 + 12)[0] + 1)
        self.big.write_bytes(bytes(raw))
        code, out, _ = run("check", str(self.big), "--json")
        self.assertEqual(code, 1)
        self.assertEqual([o["key"] for o in json.loads(out)["overlaps"]], [0x0B])

    def test_refusals(self) -> None:
        old = build(self.dir / "old" / "Yeti.big", items(), version=0x56)
        code, _, err = run("info", str(old))
        self.assertEqual(code, 2)
        self.assertIn("older than 0x57", err)
        raw = bytearray(self.big.read_bytes())
        struct.pack_into("<I", raw, 0x268 + 12, len(raw))  # key 0x0a placed past the end
        outside = self.dir / "outside" / "Yeti.big"
        outside.parent.mkdir()
        outside.write_bytes(bytes(raw))
        code, _, err = run("list", str(outside))
        self.assertEqual(code, 2)
        self.assertIn("lies outside the file", err)
        code, _, err = run("blob", str(self.big), "a", "--out", str(self.big.parent / "x"))
        self.assertEqual(code, 2)
        self.assertIn("inside the archive's folder", err)
        self.assertFalse((self.big.parent / "x").exists())
        relative = run("--caller-cwd", str(self.big.parent), "blob", "Yeti.big", "a", "--out", "y")
        self.assertEqual(relative[0], 2)
        code, _, err = run("info", str(self.dir / "missing.big"))
        self.assertEqual(code, 2)

    def test_long_table_form_is_refused(self) -> None:
        raw = bytearray(self.big.read_bytes())
        raw[2] = 0
        self.big.write_bytes(bytes(raw))
        code, _, err = run("info", str(self.big))
        self.assertEqual(code, 2)
        self.assertIn("table flag 0", err)


PC = os.environ.get("REA_YETIBIG_PC")
X360 = os.environ.get("REA_YETIBIG_X360")


@unittest.skipUnless(
    PC and X360, "set REA_YETIBIG_PC and REA_YETIBIG_X360 to Lost: Via Domus's Yeti.big files"
)
class RealArchivesTest(unittest.TestCase):
    """Lost: Via Domus, PC and Xbox 360: reads both archives whole; run under `heavy run`."""

    def test_counts_and_diff(self) -> None:
        pc, x360 = yetibig.read_archive(Path(PC)), yetibig.read_archive(Path(X360))
        self.assertEqual((len(pc.entries), len(x360.entries)), (73527, 74271))
        code, out, _ = run("diff", PC, X360, "--json")
        self.assertEqual(code, 0)
        diff = json.loads(out)
        self.assertEqual(
            (len(diff["only_a"]), len(diff["only_b"]), len(diff["size_differs"])), (870, 1614, 1182)
        )

    def test_check(self) -> None:
        for path in (PC, X360):
            with self.subTest(path):
                proof = yetibig.prove(yetibig.read_archive(Path(path)))
                self.assertTrue(
                    proof["ok"], {k: proof[k] for k in ("overlaps", "failed", "copies_differing")}
                )
                self.assertEqual(len(proof["gaps"]), 1)
                self.assertEqual(proof["overlaps"], [])


if __name__ == "__main__":
    unittest.main()
