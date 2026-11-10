"""The PE model and scans on synthetic programs (samples.program_x64/x86): RTTI, references,
callers, strings, containing functions."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rea_suite import pe, rtti, samples, scan, sites
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


class Directories(unittest.TestCase):
    def test_exports_delay_imports_tls_and_relocations(self) -> None:
        data, at = samples.program_dll()
        image = Image(data)
        self.assertEqual(
            [(e.name, e.rva) for e in image.exports], [("Alpha", 0x1000), ("Beta", 0x1010)]
        )
        (late,) = image.imports
        self.assertEqual(
            (late.label, late.slot, late.delay), ("late.dll!Later", at["late_slot"], True)
        )
        self.assertEqual(image.tls["callbacks"], [0x180001010])
        self.assertEqual(image.relocations, {0x2320: 10, 0x2200: 10})
        self.assertEqual(image.runtime_functions, [])


class Sites(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.data, self.at = samples.program_x64()
        self.image = Image(self.data)

    def declaration(self, **changes) -> dict:
        spec = sites.skeleton(self.image, self.data, "program.exe")
        spec["sites"] = [
            {"name": "call_f2", "kind": "call", "rva": "0x1007", "expected": self.data[
                self.image.offset(0x1007) : self.image.offset(0x1007) + 5].hex(),
             "target": "Replacement", "evidence": "ev_test"},
            {"name": "f1_head", "kind": "function", "rva": "0x1000", "expected": "488d05", "evidence": "doc"},
            {"name": "ret_to_jmp", "kind": "edit", "rva": "0x1019", "expected": "c3",
             "replacement": "cc", "evidence": "doc"},
            {"name": "tick_slot", "kind": "iat", "rva": "0x2040", "import": "KERNEL32.dll!GetTickCount",
             "evidence": "doc"},
            {"name": "greeting", "kind": "data", "rva": "0x2000", "evidence": "doc"},
            {"name": "f1_body", "kind": "range", "rva": "0x1000", "size": "0x30", "evidence": "doc"},
            {"name": "health", "kind": "offset", "value": "0x1c"},
        ]  # fmt: skip
        for name, change in changes.items():
            next(s for s in spec["sites"] if s["name"] == name).update(change)
        return spec

    def write(self, spec: dict) -> Path:
        path = self.root / "sites.json"
        path.write_text(json.dumps(spec))
        return path

    def test_a_matching_declaration_agrees(self) -> None:
        spec = sites.load(self.write(self.declaration()))
        self.assertEqual(sites.verify(spec, self.image, self.data), [])

    def test_every_difference_is_reported(self) -> None:
        spec = self.declaration(
            f1_head={"expected": "90"},
            tick_slot={"import": "KERNEL32.dll!ExitProcess"},
            greeting={"writable": True},
            f1_body={"size": "0x2000"},
        )
        spec["source"]["sha256"] = "0" * 64
        problems = sites.verify(sites.load(self.write(spec)), self.image, self.data)
        self.assertEqual(len(problems), 5, problems)
        self.assertTrue(problems[0].startswith("source: sha256"))
        self.assertIn("f1_head: 48 at 0x1000, expected 90", problems[1])
        self.assertIn("the slot holds KERNEL32.dll!GetTickCount", problems[2])

    def test_invalid_declarations_are_refused(self) -> None:
        for change in (
            {"ret_to_jmp": {"replacement": "cccc"}},
            {"call_f2": {"expected": "e8"}},
            {"greeting": {"evidence": ""}},
            {"health": {"kind": "pointer"}},
        ):
            with self.assertRaises(ValueError, msg=change):
                sites.load(self.write(self.declaration(**change)))


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


class Registry(unittest.TestCase):
    def test_settings_with_their_strings_and_stored_defaults(self) -> None:
        data, at = samples.program_registry()
        rows = scan.registry(
            Image(data),
            [(at["start"], at["size"])],
            {
                at["bool"]: scan.Registrar("bool", ["description", "name"]),
                at["string"]: scan.Registrar("string", ["default", "hint", "description", "name"]),
            },
            stack_byte=0x30,
        )
        self.assertEqual(
            [(r["name"], r["type"], r["description"], r.get("default"), r["stored"]) for r in rows],
            [
                ("fog", "bool", "Enables fog", None, 1),
                ("language", "string", "Interface language", "en", None),
                ("skipintro", "bool", "Skips intros", None, "r14b"),
            ],
        )
        self.assertEqual([r["site"] for r in rows], [f"{s:#x}" for s in at["sites"][:3]])


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

    def test_registry_markdown_from_a_config(self) -> None:
        data, at = samples.program_registry()
        self.exe.write_bytes(data)
        config = self.exe.with_name("registry.json")
        config.write_text(
            json.dumps(
                {
                    "ranges": [[f"{at['start']:#x}", f"{at['size']:#x}"]],
                    "registrars": {
                        f"{at['bool']:#x}": {"type": "bool", "fields": ["description", "name"]}
                    },
                    "stack_byte": "0x30",
                }
            )
        )
        code, out = run("registry", str(self.exe), "--config", str(config), "--markdown",
                        "--registrar", f"{at['string']:#x}=string:default,hint,description,name")  # fmt: skip
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(lines[0], "| description | name | default | hint | type | stored | site |")
        self.assertIn("| Interface language | language | en | language code | string |  |", out)

    def test_info_and_sites_init(self) -> None:
        code, out = run("info", str(self.exe), "--imports")
        self.assertEqual(code, 0)
        self.assertIn("imports: 2 functions from 1 DLLs (0 delay-loaded)", out)
        self.assertIn("relocations: none (fixed base)", out)
        self.assertIn("unwind table: 3 functions", out)
        code, out = run("sites", str(self.exe), "--init")
        spec_path = self.exe.with_name("sites.json")
        spec_path.write_text(out)
        self.assertEqual(run("sites", str(self.exe), str(spec_path)), (0, "0 sites: all agree\n"))

    def test_a_missing_string_and_a_non_pe(self) -> None:
        self.assertEqual(run("refs", str(self.exe), "--string", "absent")[0], 1)
        other = self.exe.with_name("notes.txt")
        other.write_text("hello")
        self.assertEqual(run("rtti", str(other))[0], 2)


if __name__ == "__main__":
    unittest.main()
