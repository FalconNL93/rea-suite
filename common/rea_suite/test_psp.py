"""PSP: EBOOT.PBP sections, PARAM.SFO, a PRX's module info with its NIDs, the encrypted header, UMD
images (ISO and CSO) and the extension check, on synthetic files built here (no game bytes).

Opt-in with a real file, read-only: REA_PSP_SAMPLE=<EBOOT.PBP, a PRX, an ISO or a CSO> runs `info`.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from rea_suite import extcheck, psp

SEGMENT_AT = 0x100  # file offset of the one loaded segment, which starts at address 0
CTRL = "sceCtrlReadBufferPositive"


def prx(kind: int = psp.ET_PRX, with_section: bool = False) -> bytes:
    """A PRX laid out as the toolchain does: stubs, module info, export and import tables, NIDs."""
    seg = bytearray(0xC0)
    info = psp.MODULE_INFO.pack(0x0000, 1, 2, b"TestModule", 0x8000, 0x60, 0x70, 0x70, 0x84)
    seg[0x20 : 0x20 + len(info)] = info
    struct.pack_into("<IHHBBHI", seg, 0x60, 0, 0, 0x8000, 4, 1, 1, 0xB0)
    struct.pack_into("<IHHBBHII", seg, 0x70, 0xA0, 0x11, 0x4001, 5, 0, 2, 0x90, 0x00)
    struct.pack_into("<4I", seg, 0xB0, 0xD632ACDB, 0xF01D73A7, 0x0, 0x20)
    struct.pack_into("<2I", seg, 0x90, psp.nid(CTRL), psp.nid("sceSomethingUnlisted"))
    seg[0xA0:0xA8] = b"sceCtrl\0"
    head = bytearray(SEGMENT_AT)
    head[0:4] = psp.ELF_MAGIC
    head[4], head[5], head[6] = 1, 1, 1
    shnum = 3 if with_section else 0
    shoff = SEGMENT_AT + len(seg) + 0x30 if with_section else 0
    struct.pack_into(
        "<HHIIIIIHHHHHH", head, 0x10, kind, psp.EM_MIPS, 1, 0x0, 0x34, shoff, 0x10A23001,
        0x34, 32, 1, 40, shnum, 2,
    )  # fmt: skip
    paddr = SEGMENT_AT + 0x20
    struct.pack_into(
        "<8I", head, 0x34, psp.PT_LOAD, SEGMENT_AT, 0, paddr, len(seg), len(seg), 7, 16
    )
    data = bytes(head) + bytes(seg)
    if with_section:
        names = b"\0.rodata.sceModuleInfo\0.shstrtab\0"
        data += names.ljust(0x30, b"\0")
        sections = bytes(40)
        sections += struct.pack("<10I", 1, 1, 2, 0x20, SEGMENT_AT + 0x20, 0x34, 0, 0, 4, 0)
        sections += struct.pack("<10I", 23, 3, 0, 0, SEGMENT_AT + len(seg), len(names), 0, 0, 1, 0)
        data += sections
    return data


def sfo(entries: dict[str, str | int]) -> bytes:
    keys, values, table = bytearray(), bytearray(), bytearray()
    for key, value in entries.items():
        raw = struct.pack("<I", value) if isinstance(value, int) else value.encode() + b"\0"
        fmt = 0x0404 if isinstance(value, int) else 0x0204
        table += struct.pack("<HHIII", len(keys), fmt, len(raw), len(raw), len(values))
        keys += key.encode() + b"\0"
        values += raw
    keys_at = 0x14 + len(table)
    values_at = keys_at + len(keys)
    head = psp.SFO_MAGIC + struct.pack("<4I", 0x101, keys_at, values_at, len(entries))
    return bytes(head + table + keys + values)


PARAM = {"CATEGORY": "UG", "DISC_ID": "ULUS99999", "TITLE": "Test Game", "PARENTAL_LEVEL": 2}


def encrypted_module() -> bytes:
    data = bytearray(0x150)
    data[0:4] = psp.PSP_MAGIC
    struct.pack_into("<HHBB", data, 4, 0x0000, 0x0001, 3, 1)
    data[0x0A:0x14] = b"GameModule"
    struct.pack_into("<II", data, 0x28, 0x12345, 0x13000)
    struct.pack_into("<I", data, 0x7C, 9)
    struct.pack_into("<I", data, 0xD0, 0xC0CB167C)
    return bytes(data)


def pbp(data_psp: bytes, psar: bytes = b"") -> bytes:
    param = sfo(PARAM)
    offsets = [0x28]
    parts = [param, b"", b"", b"", b"", b"", data_psp, psar]
    for part in parts[:-1]:
        offsets.append(offsets[-1] + len(part))
    return psp.PBP_MAGIC + struct.pack("<I8I", 0x10000, *offsets) + b"".join(parts)


def iso(files: dict[str, bytes]) -> bytes:
    """An ISO 9660 image with PSP_GAME/<files> and PSP_GAME/SYSDIR/<files>, one sector each."""
    sectors: dict[int, bytes] = {}

    def record(name: bytes, extent: int, size: int, is_dir: bool) -> bytes:
        body = struct.pack(
            "<BBI4sI4s7sBBBHHB",
            0,
            0,
            extent,
            b"",
            size,
            b"",
            b"",
            2 if is_dir else 0,
            0,
            0,
            1,
            0,
            len(name),
        )
        rec = body + name
        rec = bytes([len(rec) + (len(rec) % 2)]) + rec[1:] + (b"\0" if len(rec) % 2 else b"")
        return rec

    next_free = 20
    top, sysdir = {}, {}
    for path, data in files.items():
        (sysdir if path.startswith("SYSDIR/") else top)[path.split("/")[-1]] = data

    def place(entries: dict[str, bytes]) -> bytes:
        nonlocal next_free
        out = record(b"\0", 0, 0, True) + record(b"\1", 0, 0, True)
        for name, data in entries.items():
            sectors[next_free] = data
            out += record(name.encode() + b";1", next_free, len(data), False)
            next_free += 1
        return out

    sys_listing = place(sysdir)
    sectors[next_free], sys_at = sys_listing, next_free
    next_free += 1
    game_listing = place(top) + record(b"SYSDIR", sys_at, 2048, True)
    sectors[next_free], game_at = game_listing, next_free
    next_free += 1
    root = (
        record(b"\0", 0, 0, True)
        + record(b"\1", 0, 0, True)
        + record(b"PSP_GAME", game_at, 2048, True)
    )
    sectors[next_free], root_at = root, next_free
    next_free += 1
    image = bytearray(next_free * psp.SECTOR)
    pvd = bytearray(psp.SECTOR)
    pvd[0:6] = b"\1CD001"
    pvd[156 : 156 + 34] = record(b"\0", root_at, 2048, True)
    image[16 * psp.SECTOR : 17 * psp.SECTOR] = pvd
    for at, data in sectors.items():
        image[at * psp.SECTOR : at * psp.SECTOR + len(data)] = data
    return bytes(image)


def cso(image: bytes, block: int = psp.SECTOR) -> bytes:
    """CSO v1: every other block stored plain, the rest raw deflate."""
    blocks, index, body = len(image) // block, [], bytearray()
    start = 0x18 + 4 * (blocks + 1)
    for n in range(blocks):
        chunk = image[n * block : (n + 1) * block]
        plain = n % 2 == 1
        if not plain:
            packer = zlib.compressobj(9, zlib.DEFLATED, -15)
            chunk = packer.compress(chunk) + packer.flush()
        index.append((start + len(body)) | (0x80000000 if plain else 0))
        body += chunk
    index.append(start + len(body))
    head = struct.pack("<4sIQIBB2x", b"CISO", 0x18, len(image), block, 1, 0)
    return head + struct.pack(f"<{len(index)}I", *index) + bytes(body)


def written(tmp: str, name: str, data: bytes) -> Path:
    path = Path(tmp) / name
    path.write_bytes(data)
    return path


class Module(unittest.TestCase):
    def test_module_info_exports_and_imports_are_read_from_the_program_header(self):
        found = psp.module(prx())
        self.assertEqual(found["kind"], "prx")
        self.assertEqual(found["flags"], "0x10a23001")
        self.assertEqual(
            found["module"],
            {
                "name": "TestModule",
                "version": "2.1",
                "attribute": "0x0000",
                "kernel": False,
                "gp": "0x00008000",
            },
        )
        self.assertEqual(found["exports"][0]["library"], "(module)")
        self.assertEqual(
            found["exports"][0]["functions"], [{"nid": "0xd632acdb", "name": "module_start"}]
        )
        self.assertEqual(
            found["exports"][0]["variables"], [{"nid": "0xf01d73a7", "name": "module_info"}]
        )
        imports = found["imports"][0]
        self.assertEqual((imports["library"], imports["version"]), ("sceCtrl", "0x0011"))
        self.assertEqual(
            imports["functions"],
            [
                {"nid": "0x1f803938", "stub": "0x00000000"},
                {"nid": f"0x{psp.nid('sceSomethingUnlisted'):08x}", "stub": "0x00000008"},
            ],
        )
        self.assertEqual(found["unnamed_imports"], 2)

    def test_names_from_a_list_name_the_nids_they_hash_to(self):
        found = psp.module(prx(), {psp.nid(CTRL): CTRL})
        self.assertEqual(found["imports"][0]["functions"][0]["name"], CTRL)
        self.assertEqual(found["unnamed_imports"], 1)

    def test_a_static_elf_finds_its_module_info_by_section(self):
        found = psp.module(prx(kind=psp.ET_EXEC, with_section=True))
        self.assertEqual(found["kind"], "elf")
        self.assertIn(psp.MODULE_INFO_SECTION, found["sections"])
        self.assertEqual(found["module"]["name"], "TestModule")

    def test_a_table_entry_of_size_zero_is_refused(self):
        broken = bytearray(prx())
        broken[SEGMENT_AT + 0x70 + 8] = 0
        with self.assertRaisesRegex(ValueError, "has size 0"):
            psp.module(bytes(broken))

    def test_an_encrypted_module_shows_its_outer_header_and_says_so(self):
        found = psp.executable(encrypted_module())
        self.assertEqual(found["kind"], "encrypted")
        self.assertEqual(found["module"]["name"], "GameModule")
        self.assertEqual(found["module"]["version"], "1.3")
        self.assertTrue(found["compressed"])
        self.assertEqual(
            (found["elf_size"], found["decrypt_mode"], found["tag"]), (0x12345, 9, "0xc0cb167c")
        )
        self.assertIn("decrypt your own copy", found["note"])

    def test_the_nid_is_the_sha1_prefix_little_endian(self):
        self.assertEqual(psp.nid("module_start"), 0xD632ACDB)
        self.assertEqual(psp.nid("sceKernelExitGame"), 0x05572A5F)


class Containers(unittest.TestCase):
    def test_an_eboot_gives_its_sections_param_sfo_and_module(self):
        found = psp.pbp(pbp(prx()))
        self.assertEqual([s["name"] for s in found["sections"]], ["PARAM.SFO", "DATA.PSP"])
        self.assertEqual(found["param_sfo"], PARAM)
        self.assertEqual(found["data_psp"]["module"]["name"], "TestModule")

    def test_a_ps1_classic_is_named_by_its_psar(self):
        found = psp.pbp(pbp(prx(), b"PSISOIMG0000" + bytes(4)))
        self.assertEqual(found["data_psar"], "a PS1 classic's disc image (POPS)")

    def test_section_offsets_out_of_order_are_refused(self):
        broken = bytearray(pbp(prx()))
        struct.pack_into("<I", broken, 8 + 4 * 6, 0x10)
        with self.assertRaisesRegex(ValueError, "out of order"):
            psp.pbp_sections(bytes(broken))

    def test_an_iso_and_the_same_image_as_cso_give_the_same_answer(self):
        image = iso(
            {
                "PARAM.SFO": sfo(PARAM),
                "SYSDIR/EBOOT.BIN": encrypted_module(),
                "SYSDIR/BOOT.BIN": bytes(64),
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            from_iso = psp.info(written(tmp, "game.iso", image))
            from_cso = psp.info(written(tmp, "game.cso", cso(image)))
        self.assertEqual(from_iso, from_cso)
        self.assertEqual(from_iso["param_sfo"]["DISC_ID"], "ULUS99999")
        self.assertEqual(from_iso["eboot_bin"]["kind"], "encrypted")
        self.assertEqual(from_iso["boot_bin"]["kind"], "empty")

    def test_an_iso_without_psp_game_is_refused(self):
        image = iso({})
        image = image.replace(b"PSP_GAME", b"XXX_GAME")
        with (
            tempfile.TemporaryDirectory() as tmp,
            self.assertRaisesRegex(ValueError, "not a PSP game UMD"),
        ):
            psp.info(written(tmp, "x.iso", image))


class Command(unittest.TestCase):
    def test_info_writes_json_and_names_from_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            written(tmp, "EBOOT.PBP", pbp(prx()))
            (Path(tmp) / "names.txt").write_text(f"# candidates\n{CTRL}\n")
            psp.main(
                ["--caller-cwd", tmp, "info", "EBOOT.PBP", "--names", "names.txt", "-o", "o.json"]
            )
            found = json.loads((Path(tmp) / "o.json").read_text())
        self.assertEqual(found["data_psp"]["imports"][0]["functions"][0]["name"], CTRL)

    def test_nid_prints_the_hash_of_each_name(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            psp.main(["nid", "module_start"])
        self.assertEqual(out.getvalue(), "0xd632acdb\tmodule_start\n")


class Check(unittest.TestCase):
    def install(self, tmp: str, version: str, files: list[str]) -> Path:
        root = Path(tmp)
        (root / "Ghidra").mkdir()
        (root / "Ghidra" / "application.properties").write_text("application.version=12.1.4\n")
        ext = root / "Ghidra" / "Extensions" / psp.EXTENSION
        (ext / "lib").mkdir(parents=True)
        (ext / "lib" / "ghidra-allegrex.jar").write_bytes(b"")
        (ext / "extension.properties").write_text(f"name=ghidra-allegrex\nversion={version}\n")
        for name in files:
            (ext / name).parent.mkdir(parents=True, exist_ok=True)
            (ext / name).write_text("")
        return root

    def test_the_check_wants_the_files_rea_checks_and_this_ghidra_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            install = self.install(tmp, "12.2", psp.EXTENSION_FILES)
            found = extcheck.problem(install, psp.EXTENSION, psp.EXTENSION_FILES, "fix")
        self.assertEqual(found, "ghidra-allegrex is built for Ghidra 12.2, not 12.1.4; fix")
        with tempfile.TemporaryDirectory() as tmp:
            install = self.install(tmp, "12.1.4", psp.EXTENSION_FILES[:-1])
            found = extcheck.problem(install, psp.EXTENSION, psp.EXTENSION_FILES, "fix")
        self.assertEqual(found, "ghidra-allegrex lacks data/languages/allegrex.cspec; fix")
        with tempfile.TemporaryDirectory() as tmp:
            install = self.install(tmp, "12.1.4", psp.EXTENSION_FILES)
            out = io.StringIO()
            with (
                patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": str(install)}),
                contextlib.redirect_stdout(out),
            ):
                self.assertEqual(psp.main(["check"]), 0)
        self.assertIn("ghidra-allegrex in place for Ghidra 12.1.4", out.getvalue())

    def test_without_a_ghidra_the_check_fails_and_says_why(self):
        out = io.StringIO()
        with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": ""}), contextlib.redirect_stdout(out):
            self.assertEqual(psp.main(["check"]), 1)
        self.assertIn("GHIDRA_INSTALL_DIR missing", out.getvalue())


@unittest.skipUnless(os.environ.get("REA_PSP_SAMPLE"), "REA_PSP_SAMPLE not set")
class Sample(unittest.TestCase):
    def test_the_sample_is_read(self):
        found = psp.info(Path(os.environ["REA_PSP_SAMPLE"]))
        self.assertIn(found["kind"], ("pbp", "prx", "elf", "encrypted", "umd", "sfo"))


if __name__ == "__main__":
    unittest.main()
