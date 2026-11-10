"""The PE model and scans on synthetic programs (samples.program_x64/x86): RTTI, references,
callers, strings, containing functions."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rea_suite import pe, rtti, samples, scan
from rea_suite.pemodel import Image


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = pe.main(list(argv))
    return code, out.getvalue()


class Model(unittest.TestCase):
    def setUp(self) -> None:
        data, self.at = samples.program_x64()
        self.image = Image(data)

    def test_sections_and_addresses_map_through_the_section_table(self) -> None:
        image = self.image
        self.assertEqual([s.name for s in image.sections], [".text", ".rdata", ".pdata"])
        self.assertTrue(image.x64)
        self.assertNotEqual(image.offset(0x2000), 0x2000)
        self.assertEqual(image.string(self.at["hello"]), "hello world")
        self.assertEqual(image.address(0x140002000), 0x2000)
        self.assertEqual(image.address(0x2000), 0x2000)
        with self.assertRaises(ValueError):
            image.offset(0x9000)

    def test_imports_carry_their_iat_slots(self) -> None:
        labels = {row.slot: row.label for row in self.image.imports}
        self.assertEqual(
            labels,
            {
                self.at["iat_tick"]: "KERNEL32.dll!GetTickCount",
                self.at["iat_exit"]: "KERNEL32.dll!ExitProcess",
            },
        )

    def test_a_chained_unwind_entry_belongs_to_its_primary_function(self) -> None:
        image = self.image
        self.assertEqual(image.function_at(0x1005), (0x1000, 0x1030))
        self.assertEqual(image.function_at(0x1031), (0x1000, 0x1030))
        self.assertEqual(image.function_at(0x1040), (0x1040, 0x1050))
        self.assertIsNone(image.function_at(0x1080))

    def test_a_fixed_base_image_has_no_relocations(self) -> None:
        self.assertEqual(self.image.relocations, {})


class Rtti(unittest.TestCase):
    def test_x64_classes_vtables_and_bases(self) -> None:
        data, at = samples.program_x64()
        found = {c.name: c for c in rtti.classes(Image(data))}
        self.assertEqual(sorted(found), ["Base", "game::Derived"])
        derived = found["game::Derived"]
        self.assertEqual([b.name for b in derived.bases], ["game::Derived", "Base"])
        self.assertEqual(len(derived.vtables), 1)
        vtable = derived.vtables[0]
        self.assertEqual((vtable.rva, vtable.locator), (at["vt_derived"], at["col_derived"]))
        self.assertEqual(vtable.slots, [at["vf3"], at["vf2"]])
        self.assertEqual(found["Base"].vtables[0].slots, [at["vf1"], at["vf2"]])

    def test_x86_classes_are_found_by_their_type_names(self) -> None:
        data, at = samples.program_x86()
        (thing,) = rtti.classes(Image(data))
        self.assertEqual((thing.name, thing.type_descriptor), ("Thing", at["td"]))
        self.assertEqual(thing.vtables[0].rva, at["vtable"])
        self.assertEqual(thing.vtables[0].slots, [at["vf1"], at["vf2"]])

    def test_simple_names_demangle_without_a_tool(self) -> None:
        self.assertEqual(rtti.demangle(".?AVWidget@ui@engine@@"), "engine::ui::Widget")
        self.assertEqual(rtti.demangle(".?AUPlain@@"), "Plain")
        self.assertEqual(rtti.demangle(".?AV?$List@H@@"), ".?AV?$List@H@@")


class Scans(unittest.TestCase):
    def setUp(self) -> None:
        data, self.at = samples.program_x64()
        self.image = Image(data)

    def test_rip_relative_references_to_a_string(self) -> None:
        (site,) = scan.refs(self.image, self.at["hello"])
        self.assertEqual((site.rva, site.function), (0x1000, 0x1000))
        self.assertTrue(site.text.startswith("lea rax"), site.text)

    def test_a_string_is_found_by_its_text_in_either_encoding(self) -> None:
        self.assertEqual(scan.find_string(self.image, "hello world"), [self.at["hello"]])
        self.assertEqual(scan.find_string(self.image, "wide"), [self.at["wide"]])
        self.assertEqual(scan.find_string(self.image, "world"), [])

    def test_callers_by_call_and_jump(self) -> None:
        sites = scan.callers(self.image, self.at["f2"])
        self.assertEqual(
            [(s.rva, s.text.split()[0]) for s in sites], [(0x1007, "call"), (0x1030, "jmp")]
        )
        self.assertEqual(
            [s.rva for s in scan.callers(self.image, self.at["f2"], jumps=False)], [0x1007]
        )

    def test_strings_loaded_in_a_range(self) -> None:
        rows = scan.strings_in(self.image, 0x1000, 0x20)
        self.assertEqual(
            [(r["encoding"], r["text"]) for r in rows],
            [("ascii", "hello world"), ("utf16", "wide")],
        )

    def test_x86_absolute_references(self) -> None:
        data, at = samples.program_x86()
        (site,) = scan.refs(Image(data), at["hello"])
        self.assertEqual((site.rva, site.text), (at["push"], "push 0x402000"))


class ImportCalls(unittest.TestCase):
    def test_direct_calls_thunks_and_calls_through_thunks(self) -> None:
        data, at = samples.program_x64()
        rows = {r["name"]: r for r in scan.import_calls(Image(data), dll="kernel32.DLL")}
        tick = rows["GetTickCount"]
        self.assertEqual(tick["slot"], f"{at['iat_tick']:#x}")
        self.assertEqual(
            [(u["rva"], u["kind"], u["function"]) for u in tick["sites"]],
            [("0x100c", "call", "0x1000")],
        )
        self.assertEqual(tick["functions"], ["0x1000"])
        exits = rows["ExitProcess"]["sites"]
        self.assertEqual(
            [(u["rva"], u["kind"]) for u in exits], [("0x1080", "jmp"), ("0x1090", "via-thunk")]
        )
        self.assertEqual(exits[1]["thunk"], "0x1080")

    def test_a_filter_that_matches_nothing(self) -> None:
        data, _ = samples.program_x64()
        self.assertEqual(scan.import_calls(Image(data), dll="user32.dll"), [])


class Cli(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.exe = Path(tmp.name) / "program.exe"
        self.exe.write_bytes(samples.program_x64()[0])

    def test_rtti_json(self) -> None:
        code, out = run("rtti", str(self.exe), "--json", "--class", "Derived")
        self.assertEqual(code, 0)
        (cls,) = json.loads(out)
        self.assertEqual(cls["bases"][0]["name"], "Base")
        self.assertEqual(cls["vtables"][0]["slots"], ["0x1070", "0x1060"])

    def test_refs_by_string_and_callers_by_va(self) -> None:
        code, out = run("refs", str(self.exe), "--string", "hello world")
        self.assertEqual(code, 0)
        self.assertIn("0x1000  lea rax", out)
        code, out = run("callers", str(self.exe), "0x140001040", "--json")
        self.assertEqual([row["rva"] for row in json.loads(out)], ["0x1007", "0x1030"])

    def test_imports_text(self) -> None:
        code, out = run("imports", str(self.exe), "--function", "GetTickCount")
        self.assertEqual(code, 0)
        self.assertIn("KERNEL32.dll!GetTickCount  slot 0x2040: 1 sites in 1 functions", out)
        self.assertIn("0x100c  call", out)

    def test_a_missing_string_and_a_non_pe(self) -> None:
        self.assertEqual(run("refs", str(self.exe), "--string", "absent")[0], 1)
        other = self.exe.with_name("notes.txt")
        other.write_text("hello")
        self.assertEqual(run("rtti", str(other))[0], 2)


if __name__ == "__main__":
    unittest.main()
