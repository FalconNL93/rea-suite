"""ZArchive and XDVDFS readers and `rea-suite zar` / `xbox360 disc`, on archives and disc images built
here the way their writers lay them out (no game bytes).

Opt-in, read-only: REA_ZAR_SAMPLE=<a .zar or .wua> lists a real archive and reads its first file;
REA_XBOX360_DISC_SAMPLE=<a .zar or disc image> runs `xbox360 disc info` on a real game.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

import zstandard

from rea_suite import containers, xbox360, xdvdfs, zar
from rea_suite.test_xex import TITLE, make_xex

# ZArchive


def name_bytes(name: str) -> bytes:
    raw = name.encode()
    if len(raw) >= 0x80:
        return bytes([(len(raw) & 0x7F) | 0x80, len(raw) >> 7]) + raw
    return bytes([len(raw)]) + raw


def make_zar(files: dict[str, bytes], raw_names: dict[str, str] | None = None) -> bytes:
    """A ZArchive as zarchivewriter.cpp writes it: the files' data concatenated and cut into 64 KiB
    blocks (zstd, or stored when it does not shrink), offset records, names, a breadth-first tree
    (every directory's children in one run), the big-endian footer. raw_names renames nodes after
    the fact, to plant names a writer would refuse."""
    root: dict = {}
    for path, data in files.items():
        node = root
        *dirs, leaf = path.split("/")
        for d in dirs:
            node = node.setdefault(d, {})
        node[leaf] = {} if isinstance(data, dict) else data
    data_blob = bytearray()
    nodes: list[list] = [["", None]]  # name, payload (dict for a directory, (offset, size) a file)
    queue = [(0, root)]
    while queue:
        index, directory = queue.pop(0)
        start = len(nodes)
        for name in sorted(directory, key=str.lower):
            value = directory[name]
            if isinstance(value, dict):
                nodes.append([name, value])
            else:
                nodes.append([name, (len(data_blob), len(value))])
                data_blob += value
        nodes[index].append((start, len(directory)))
        for i in range(start, len(nodes)):
            if isinstance(nodes[i][1], dict):
                queue.append((i, nodes[i][1]))
    # The last block is padded to 64 KiB; an archive of empty files still has one block.
    data_blob += bytes(-len(data_blob) % zar.BLOCK if data_blob else zar.BLOCK)
    compressed, sizes = bytearray(), []
    for at in range(0, len(data_blob), zar.BLOCK):
        block = bytes(data_blob[at : at + zar.BLOCK])
        packed = zstandard.ZstdCompressor().compress(block)
        stored = packed if len(packed) < zar.BLOCK else block
        sizes.append(len(stored))
        compressed += stored
    records = bytearray()
    offset = 0
    for first in range(0, len(sizes), zar.PER_RECORD):
        group = sizes[first : first + zar.PER_RECORD]
        group += [1] * (zar.PER_RECORD - len(group))
        records += zar.RECORD.pack(offset, *(s - 1 for s in group))
        offset += sum(sizes[first : first + zar.PER_RECORD])
    names, tree = bytearray(), bytearray()
    for name, payload, *children in nodes:
        if children and not tree:  # the root: no name
            name_offset = 0x7FFFFFFF
        else:
            name_offset = len(names)
            names += name_bytes((raw_names or {}).get(name, name))
        if isinstance(payload, tuple):
            at, size = payload
            high = (at >> 32) & 0xFFFF | ((size >> 32) & 0xFFFF) << 16
            tree += zar.NODE.pack(
                0x80000000 | name_offset, at & 0xFFFFFFFF, size & 0xFFFFFFFF, high
            )
        else:
            start, count = children[0]
            tree += zar.NODE.pack(name_offset, start, count, 0)
    out = bytearray(compressed)
    sections = []
    for blob in (records, names, tree, b"", b""):
        sections.append((len(out), len(blob)))
        out += blob
    pairs = [0, len(compressed)] + [v for pair in sections for v in pair]
    total = len(out) + zar.FOOTER.size
    out += zar.FOOTER.pack(*pairs, bytes(32), total, zar.VERSION1, zar.MAGIC)
    return bytes(out)


SAMPLE = {
    "default.xex": b"",
    "media/big.bin": bytes(range(256)) * 600,  # 150 KiB: three blocks, compressible
    "media/noise.bin": os.urandom(70_000),  # crosses a block, stored raw
    "media/empty.txt": b"",
    "Readme.TXT": b"hello\n",
    "n" * 140: b"a long name",  # the two-byte length upstream's reader misreads
}


def write(folder: Path, name: str, data: bytes) -> Path:
    path = folder / name
    path.write_bytes(data)
    return path


class ZarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_every_file_reads_back_byte_for_byte(self):
        path = write(self.dir, "a.zar", make_zar(SAMPLE))
        self.assertTrue(zar.is_zar(path))
        archive = zar.ZarArchive(path)
        try:
            tree = archive.tree()
            self.assertEqual(tree.skipped, [])
            for name, data in SAMPLE.items():
                entry = containers.find(tree, name)
                self.assertIsNotNone(entry, name)
                self.assertEqual(b"".join(archive.read(entry)), data, name)
            self.assertTrue(containers.find(tree, "MEDIA").is_dir)
        finally:
            archive.close()

    def test_extract_writes_the_named_folder_only(self):
        write(self.dir, "a.zar", make_zar(SAMPLE))
        with contextlib.redirect_stderr(io.StringIO()):
            zar.main(["--caller-cwd", str(self.dir), "extract", "a.zar", "media", "-o", "out"])
        out = self.dir / "out"
        self.assertEqual(
            sorted(p.relative_to(out).as_posix() for p in out.rglob("*")),
            ["media", "media/big.bin", "media/empty.txt", "media/noise.bin"],
        )
        self.assertEqual((out / "media/noise.bin").read_bytes(), SAMPLE["media/noise.bin"])

    def test_list_and_info(self):
        write(self.dir, "a.zar", make_zar(SAMPLE))
        listed, info = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(listed):
            zar.main(["--caller-cwd", str(self.dir), "list", "a.zar"])
        with contextlib.redirect_stdout(info):
            zar.main(["--caller-cwd", str(self.dir), "info", "a.zar"])
        self.assertIn("6\tReadme.TXT\n", listed.getvalue())
        self.assertIn("\tmedia/\n", listed.getvalue())
        found = json.loads(info.getvalue())
        self.assertEqual(
            (found["format"], found["files"], found["directories"]), ("ZArchive", 6, 1)
        )

    def test_unsafe_names_are_skipped_and_reported(self):
        files = {"ok.txt": b"1", "evil": b"2", "media/x": b"3"}
        data = make_zar(files, raw_names={"evil": "..", "x": "a\\b"})
        archive = zar.ZarArchive(write(self.dir, "bad.zar", data))
        try:
            tree = archive.tree()
        finally:
            archive.close()
        self.assertEqual([e.path for e in tree.entries], ["media", "ok.txt"])
        self.assertEqual(len(tree.skipped), 2)

    def test_damaged_archives_are_refused(self):
        good = make_zar(SAMPLE)
        cases = {
            "not one": b"\0" * 400,
            "truncated": good[:-1],
            "wrong total": good[:-16] + struct.pack(">Q", 1) + good[-8:],
        }
        for label, data in cases.items():
            path = write(self.dir, "x.zar", data)
            with self.subTest(label), self.assertRaises(ValueError):
                zar.ZarArchive(path)

    def test_a_corrupt_block_is_an_error_not_short_output(self):
        data = bytearray(make_zar({"a.bin": bytes(range(256)) * 400}))
        data[10] ^= 0xFF  # inside the first zstd frame
        archive = zar.ZarArchive(write(self.dir, "c.zar", bytes(data)))
        try:
            entry = containers.find(archive.tree(), "a.bin")
            with self.assertRaises(ValueError):
                b"".join(archive.read(entry))
        finally:
            archive.close()

    def test_a_directory_cycle_ends(self):
        data = bytearray(make_zar({"d/f": b"1"}))
        tree_offset = zar.FOOTER.unpack(data[-zar.FOOTER.size :])[6]
        # point directory "d" (node 1) back at the root's run of children
        struct.pack_into(">II", data, tree_offset + 16 + 4, 1, 1)
        archive = zar.ZarArchive(write(self.dir, "loop.zar", bytes(data)))
        try:
            tree = archive.tree()
        finally:
            archive.close()
        self.assertEqual([e.path for e in tree.entries], ["d"])
        self.assertTrue(tree.skipped)


# XDVDFS


def make_xdvdfs(path: Path, files: dict, offset: int = 0) -> Path:
    """An XDVDFS partition at offset, written sparse: volume descriptor in sector 32, then each
    directory's table (a right-leaning tree, entries 4-byte aligned, padded with 0xFF), then the
    files' sectors. A dict value is an empty directory."""
    root: dict = {}
    for name, data in files.items():
        node = root
        *dirs, leaf = name.split("/")
        for d in dirs:
            node = node.setdefault(d, {})
        node[leaf] = {} if isinstance(data, dict) else data
    sectors: dict[int, bytes] = {}
    next_sector = [33]

    def allocate(data: bytes) -> int:
        sector = next_sector[0]
        sectors[sector] = data
        next_sector[0] += max(1, -(-len(data) // xdvdfs.SECTOR))
        return sector

    def table(directory: dict) -> tuple[int, int]:
        names = sorted(directory, key=str.lower)
        if not names:
            return allocate(b"\xff" * xdvdfs.SECTOR), xdvdfs.SECTOR
        placed = []
        for name in names:
            value = directory[name]
            if isinstance(value, dict):
                start, size = table(value)
                placed.append((name, start, size, xdvdfs.DIRECTORY))
            else:
                placed.append((name, allocate(value) if value else 0, len(value), 0x20))
        out = bytearray()
        for i, (name, start, size, attributes) in enumerate(placed):
            raw = name.encode("latin-1")
            length = (xdvdfs.HEAD.size + len(raw) + 3) & ~3
            right = (len(out) + length) // 4 if i + 1 < len(placed) else 0
            entry = xdvdfs.HEAD.pack(0, right, start, size, attributes, len(raw)) + raw
            out += entry.ljust(length, b"\xff")
        out += b"\xff" * (-len(out) % xdvdfs.SECTOR)
        return allocate(bytes(out)), len(out)

    root_sector, root_size = table(root)
    descriptor = bytearray(xdvdfs.SECTOR)
    descriptor[:20] = xdvdfs.MAGIC
    struct.pack_into("<IIQ", descriptor, 20, root_sector, root_size, 0x01D0_0000_0000_0000)
    descriptor[0x7EC : 0x7EC + 20] = xdvdfs.MAGIC
    sectors[32] = bytes(descriptor)
    with path.open("wb") as f:
        f.write(b"VIDEO")  # a Redump image's video partition starts here
        for sector, data in sectors.items():
            f.seek(offset + sector * xdvdfs.SECTOR)
            f.write(data)
        f.truncate(offset + next_sector[0] * xdvdfs.SECTOR)
    return path


DISC = {
    "default.xex": make_xex(),
    "Media/Movies/intro.wmv": os.urandom(5000),
    "Media/empty": {},
    "$SystemUpdate/su.bin": b"x" * 3000,
    "zero.dat": b"",
}


class XdvdfsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def flat(self, files: dict) -> bytearray:
        """An XISO's bytes, to damage in place."""
        return bytearray(make_xdvdfs(self.dir / "flat.iso", files).read_bytes())

    def test_the_partition_is_found_at_every_layout(self):
        for layout, offset in xdvdfs.OFFSETS.items():
            with self.subTest(layout):
                path = make_xdvdfs(self.dir / f"{layout}.iso", DISC, offset)
                image = xdvdfs.XdvdfsImage(path)
                try:
                    self.assertEqual((image.layout, image.offset), (layout, offset))
                    tree = image.tree()
                    entry = containers.find(tree, "MEDIA/movies/INTRO.wmv")
                    self.assertEqual(b"".join(image.read(entry)), DISC["Media/Movies/intro.wmv"])
                finally:
                    image.close()

    def test_an_empty_directory_and_an_empty_file_are_kept(self):
        path = make_xdvdfs(self.dir / "e.iso", {"a/b": b"1", "c": {}, "zero.dat": b""}, 0x0FD90000)
        image = xdvdfs.XdvdfsImage(path)
        try:
            paths = {e.path: e for e in image.tree().entries}
        finally:
            image.close()
        self.assertEqual(sorted(paths), ["a", "a/b", "c", "zero.dat"])
        self.assertEqual(paths["zero.dat"].size, 0)

    def test_no_partition_is_refused_with_the_way_on(self):
        path = write(self.dir, "plain.iso", bytes(0x20000))
        with self.assertRaisesRegex(ValueError, "Games on Demand"):
            xdvdfs.XdvdfsImage(path)

    def test_unsafe_names_and_files_past_the_end_are_skipped(self):
        data = self.flat({"ok": b"1", "zz": b"2"})
        descriptor = 32 * xdvdfs.SECTOR
        root_sector, _ = struct.unpack_from("<II", data, descriptor + 20)
        table = root_sector * xdvdfs.SECTOR
        first = (xdvdfs.HEAD.size + 2 + 3) & ~3  # "ok", aligned to four
        data[table + xdvdfs.HEAD.size : table + xdvdfs.HEAD.size + 2] = b".."
        struct.pack_into("<I", data, table + first + 8, 1 << 30)  # zz's size
        image = xdvdfs.XdvdfsImage(write(self.dir, "bad.iso", bytes(data)))
        try:
            tree = image.tree()
        finally:
            image.close()
        self.assertEqual(tree.entries, [])
        self.assertEqual(len(tree.skipped), 2)

    def test_a_directory_loop_ends(self):
        data = self.flat({"d/f": b"1"})
        root_sector, _ = struct.unpack_from("<II", data, 32 * xdvdfs.SECTOR + 20)
        root_at = root_sector * xdvdfs.SECTOR
        d_sector = struct.unpack_from("<I", data, root_at + 4)[0]
        # make d's only entry a directory that points back at d's own table
        struct.pack_into("<IIB", data, d_sector * xdvdfs.SECTOR + 4, d_sector, 2048, 0x10)
        image = xdvdfs.XdvdfsImage(write(self.dir, "loop.iso", bytes(data)))
        try:
            tree = image.tree()
        finally:
            image.close()
        self.assertEqual([e.path for e in tree.entries], ["d"])
        self.assertTrue(tree.skipped)


class DiscCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args: str) -> str:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(xbox360.main(["--caller-cwd", str(self.dir), "disc", *args]), 0)
        return out.getvalue()

    def test_info_names_the_title_from_a_zar_and_from_an_xgd2_image(self):
        write(self.dir, "game.zar", make_zar(DISC))
        make_xdvdfs(self.dir / "game.iso", DISC, xdvdfs.OFFSETS["XGD2"])
        for name, container in (("game.zar", "ZArchive"), ("game.iso", "XDVDFS")):
            with self.subTest(name):
                info = json.loads(self.run_cli("info", name))
                self.assertEqual(info["format"], container)
                self.assertEqual(info["default_xex"]["title_id"], f"{TITLE:08X}")
                self.assertEqual(info["executables"], ["default.xex"])
        self.assertEqual(json.loads(self.run_cli("info", "game.iso"))["layout"], "XGD2")

    def test_extract_takes_default_xex_out_of_an_xgd3_image(self):
        make_xdvdfs(self.dir / "game.iso", DISC, xdvdfs.OFFSETS["XGD3"])
        self.run_cli("extract", "game.iso", "default.xex", "-o", "out")
        self.assertEqual((self.dir / "out/default.xex").read_bytes(), DISC["default.xex"])
        self.assertIn("5000\tMedia/Movies/intro.wmv\n", self.run_cli("list", "game.iso"))

    def test_a_folder_is_refused_with_the_way_on(self):
        (self.dir / "god").mkdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            xbox360.main(["--caller-cwd", str(self.dir), "disc", "list", "god"])
        self.assertIn("Games on Demand", err.getvalue())


@unittest.skipUnless(os.environ.get("REA_ZAR_SAMPLE"), "set REA_ZAR_SAMPLE=<.zar or .wua>")
class ZarSampleTests(unittest.TestCase):
    def test_a_real_archive_lists_and_its_first_file_reads(self):
        archive = zar.ZarArchive(Path(os.environ["REA_ZAR_SAMPLE"]).resolve())
        try:
            tree = archive.tree()
            files = [e for e in tree.entries if not e.is_dir]
            self.assertTrue(files)
            first = min(files, key=lambda e: e.size)
            self.assertEqual(sum(len(c) for c in archive.read(first)), first.size)
        finally:
            archive.close()


@unittest.skipUnless(
    os.environ.get("REA_XBOX360_DISC_SAMPLE"), "set REA_XBOX360_DISC_SAMPLE=<.zar or disc image>"
)
class DiscSampleTests(unittest.TestCase):
    def test_a_real_game_names_its_title(self):
        game = xbox360.open_game(Path(os.environ["REA_XBOX360_DISC_SAMPLE"]).resolve())
        try:
            found = xbox360.disc_extra(game)
        finally:
            game.close()
        self.assertRegex(found["default_xex"]["title_id"], "^[0-9A-F]{8}$")


if __name__ == "__main__":
    unittest.main()
