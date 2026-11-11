"""The PE model and scans on synthetic programs (samples.program_*): RTTI, references,
callers, strings, containing functions from the unwind table, a function table or the
heuristic, disassembly and resources."""

from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from rea_suite import pe, pefunctions, peresources, rtti, samples, scan, sites
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


class RttiCompare(unittest.TestCase):
    def setUp(self) -> None:
        data, self.at = samples.program_rtti()
        self.image = Image(data)
        self.found = rtti.classes(self.image)
        self.by_name = {c.name: c for c in self.found}

    def compare(self, *pure: int) -> dict[tuple[str, int], rtti.Vtable]:
        rtti.compare(self.found, rtti.purecalls(self.image) | set(pure))
        return {(c.name, v.offset): v for c in self.found for v in c.vtables}

    def test_the_imported_purecall_thunk_is_found(self) -> None:
        self.assertEqual(rtti.purecalls(self.image), {self.at["purecall"]})

    def test_each_vtable_is_set_against_the_base_at_its_mdisp(self) -> None:
        vtables = self.compare()
        primary, second = vtables[("Impl", 0)], vtables[("Impl", 8)]
        self.assertEqual((primary.base, primary.base_vtable), ("Iface", self.at["vt_iface_0"]))
        self.assertEqual(primary.states, ["overridden", "inherited", "new"])
        self.assertEqual((second.base, second.base_vtable), ("Other", self.at["vt_other_0"]))
        self.assertEqual(second.states, ["overridden", "inherited"])
        self.assertEqual(vtables[("Iface", 0)].states, ["pure", "new"])
        self.assertIsNone(vtables[("Iface", 0)].base)

    def test_a_static_purecall_stub_given_by_address_is_pure(self) -> None:
        vtables = self.compare(self.at["stub"])
        self.assertEqual(vtables[("Impl", 8)].states, ["overridden", "pure"])
        self.assertEqual(vtables[("Other", 0)].states, ["new", "pure"])

    def test_a_vtable_no_base_covers_in_a_class_with_virtual_bases_is_unknown(self) -> None:
        impl = self.by_name["Impl"]
        impl.bases[2].pdisp = 0  # Other as a virtual base
        vtables = self.compare()
        self.assertIsNone(vtables[("Impl", 8)].base)
        self.assertEqual(vtables[("Impl", 8)].states, ["unknown", "unknown"])


class Scans(unittest.TestCase):
    def setUp(self) -> None:
        data, self.at = samples.program_x64()
        self.image = Image(data)

    def test_every_row_says_whether_its_function_is_known(self) -> None:
        image, at = self.image, self.at
        inside = scan.refs(image, at["hello"])[0].as_json(image)
        self.assertEqual((inside["function"], inside["function_known"]), ("0x1000", True))
        # the thunk at 0x1080 has no unwind entry
        outside = scan.callers(image, at["thunk"])[0].as_json(image)
        self.assertEqual((outside["function"], outside["function_known"]), (None, False))
        rows = scan.strings_in(image, 0x1000, 0x20)
        self.assertEqual({(r["function"], r["function_known"]) for r in rows}, {("0x1000", True)})
        (exits,) = [r for r in scan.import_calls(image) if r["name"] == "ExitProcess"]
        self.assertEqual([u["function_known"] for u in exits["sites"]], [False, False])
        self.assertEqual(exits["functions"], [])

    def test_rip_relative_references_to_a_string(self) -> None:
        (site,) = scan.refs(self.image, self.at["hello"])
        self.assertEqual(
            (site.rva, site.function.start, site.function.source), (0x1000, 0x1000, "unwind")
        )
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

    def test_rtti_slots_text_and_json(self) -> None:
        data, at = samples.program_rtti()
        self.exe.write_bytes(data)
        code, out = run("rtti", str(self.exe), "--class", "^Impl$", "--slots",
                        "--purecall", f"{0x140000000 + at['stub']:#x}")  # fmt: skip
        self.assertEqual(code, 0)
        self.assertIn(f"offset 0: 3 slots, base Iface {at['vt_iface_0']:#x}", out)
        self.assertIn(f"[1] {at['a']:#x}  inherited", out)
        self.assertIn(f"[1] {at['stub']:#x}  pure", out)
        code, out = run("rtti", str(self.exe), "--json", "--class", "Iface")
        (iface,) = json.loads(out)
        self.assertEqual(iface["vtables"][0]["slot_states"], ["pure", "new"])
        self.assertIsNone(iface["vtables"][0]["base"])

    def test_refs_json_rows_sort_by_function(self) -> None:
        code, out = run("callers", str(self.exe), "0x1080", "--json")
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual([(r["function"], r["function_known"]) for r in rows], [(None, False)])
        code, out = run("refs", str(self.exe), "0x2000", "--json")
        rows = json.loads(out)
        self.assertTrue(all("function_known" in r for r in rows))
        rows.sort(key=lambda r: (not r["function_known"], int(r["function"] or "0", 16)))

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


class X86Functions(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data, self.at = samples.program_x86_functions()
        self.image = Image(data)

    def table(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text)
        return path

    def test_heuristic_starts_without_a_table(self) -> None:
        at = self.at
        found = pefunctions.heuristic_starts(self.image)
        self.assertEqual(found, {at["main"], at["helper"], at["leaf"], at["callback"]})
        row = scan.refs(self.image, at["leafstr"])[0].as_json(self.image)
        self.assertEqual(
            (row["function"], row["function_source"], row["function_known"]),
            (f"{at['leaf']:#x}", "heuristic", False),
        )

    def test_a_ghidra_table_names_the_function_and_bounds_it_by_size(self) -> None:
        at = self.at
        tsv = self.table(
            "functions.tsv",
            "entry\tsize\tname\tthunk\tcallers\n00401000\t31\tmain\t0\t0\n"
            "00401020\t11\thelper\t0\t1\n",
        )
        self.image.functions = pefunctions.Functions.from_tables(self.image, [tsv])
        (site,) = scan.refs(self.image, at["hello"])
        self.assertEqual((site.function.start, site.function.name), (at["main"], "main"))
        self.assertEqual(site.as_json(self.image)["function_known"], True)
        # leaf lies past helper's 11 bytes: in no function the table names
        self.assertIsNone(scan.refs(self.image, at["leafstr"])[0].function)

    def test_tables_merge_starts_and_names_and_pick_a_game(self) -> None:
        entries = self.table("entries.tsv", "entry\n00401000\n00401020\n00401040\n")
        names = self.table(
            "names.tsv",
            "game\taddress\tname\twhat\nsp\t0x00401040\tLeaf_Clear\t\nmp\t0x401040\tOther\t\n",
        )
        functions = pefunctions.Functions.from_tables(self.image, [entries, names], "sp")
        self.assertEqual(functions.at(self.at["leaf_push"]).name, "Leaf_Clear")
        self.assertIsNone(functions.at(self.at["main_push"]).name)
        self.assertEqual(functions.address_of("Leaf_Clear"), self.at["leaf"])

    def test_imports_name_the_function_from_the_table(self) -> None:
        tsv = self.table("t.tsv", "00401000\tmain\n00401020\thelper\n")
        self.image.functions = pefunctions.Functions.from_tables(self.image, [tsv])
        (row,) = scan.import_calls(self.image)
        (site,) = row["sites"]
        self.assertEqual(
            (site["rva"], site["function_name"], site["function_source"]),
            (f"{self.at['main_call_iat']:#x}", "main", "table"),
        )


class Disassembly(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.exe = Path(tmp.name) / "program.exe"
        data, self.at = samples.program_x86_functions()
        self.exe.write_bytes(data)
        self.tsv = self.exe.with_name("functions.tsv")
        self.tsv.write_text("entry\tname\n00401000\tmain\n00401020\thelper\n")

    def test_a_listing_notes_strings_imports_and_names(self) -> None:
        code, out = run("disasm", str(self.exe), "main", "--count", "6",
                        "--functions", str(self.tsv))  # fmt: skip
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(lines[0], "main:")
        self.assertIn('push 0x402000  ; "hello"', out)
        self.assertIn("call 0x401020  ; helper", out)
        self.assertIn("call dword ptr [0x402040]  ; KERNEL32.dll!GetTickCount", out)
        self.assertEqual(len([line for line in lines if line.startswith("  0x")]), 6)

    def test_a_whole_function_stops_at_the_next_start_without_its_padding(self) -> None:
        code, out = run("disasm", str(self.exe), "0x401042", "--function", "--json")
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual((rows[0]["rva"], rows[0]["start"]), ("0x1040", "heuristic"))
        self.assertEqual(rows[-1]["instruction"], "ret")

    def test_to_an_address_and_a_histogram(self) -> None:
        code, out = run("disasm", str(self.exe), "0x401020", "--to", "0x401023", "--json")
        self.assertEqual([r["instruction"] for r in json.loads(out)], ["push ebp", "mov ebp, esp"])
        code, out = run("disasm", str(self.exe), "main", "--function", "--histogram", "--json",
                        "--functions", str(self.tsv))  # fmt: skip
        found = json.loads(out)
        self.assertEqual(found["mnemonics"]["call"], 3)
        self.assertEqual(found["instructions"], 9)
        code, out = run("disasm", str(self.exe), "--histogram")
        self.assertEqual(code, 0)
        self.assertIn("int3", out)

    def test_an_unknown_name_is_refused(self) -> None:
        self.assertEqual(run("disasm", str(self.exe), "Nowhere")[0], 2)


class Resources(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        data, self.parts = samples.program_resources()
        self.image = Image(data)
        self.found = peresources.resources(self.image)

    def one(self, kind: str, name) -> dict:
        (row,) = [r for r in self.found if r["type"] == kind and r["name"] == name]
        self.assertNotIn("error", row)
        return row

    def test_dialogs_with_their_controls(self) -> None:
        about = self.one("DIALOG", 101)
        self.assertEqual((about["kind"], about["title"], about["font"]["name"]),
                         ("dialog", "About", "MS Sans Serif"))  # fmt: skip
        self.assertEqual(
            [(c["id"], c["class"], c["text"]) for c in about["controls"]],
            [(1, "Button", "OK"), (-1, "Static", "Version 1")],
        )
        launcher = self.one("DIALOG", "LAUNCHER")
        (play,) = launcher["controls"]
        self.assertEqual((launcher["kind"], launcher["font"]["weight"]), ("dialogex", 400))
        self.assertEqual((play["id"], play["class"], play["text"], play["extra"]),
                         (1001, "SysListView32", "&Play", "abcd"))  # fmt: skip

    def test_menus_in_both_formats(self) -> None:
        plain = self.one("MENU", 102)["items"]
        self.assertEqual([i["text"] for i in plain], ["&File", "&Help"])
        self.assertEqual([(i.get("id"), i.get("separator", False)) for i in plain[0]["items"]],
                         [(40001, False), (0, True), (40002, False)])  # fmt: skip
        (game,) = self.one("MENU", 103)["items"]
        self.assertEqual(game["items"][0]["id"], 50001)
        self.assertTrue(game["items"][1]["separator"])

    def test_strings_accelerators_messages_and_version(self) -> None:
        self.assertEqual(self.one("STRING", 2)["strings"],
                         [{"id": 17, "text": "Hello"}, {"id": 31, "text": "Last"}])  # fmt: skip
        self.assertEqual(
            [e["key"] for e in self.one("ACCELERATOR", 104)["entries"]], ["Ctrl+O", "F1"]
        )
        self.assertEqual(self.one("MESSAGETABLE", 1)["messages"], [{"id": 7, "text": "Disk full"}])
        version = self.one("VERSION", 1)
        self.assertEqual(
            (version["file_version"], version["product_version"]), ("1.2.3.4", "1.2.0.0")
        )
        self.assertEqual(version["strings"]["040904b0"]["CompanyName"], "Example")
        self.assertEqual(version["translations"], ["0409:04b0"])

    def test_filters_by_type_and_name(self) -> None:
        rows = peresources.resources(self.image, ["rcdata"], ["CONFIG"])
        self.assertEqual(sorted(r["lang"] for r in rows), ["0x0407", "0x0409"])
        self.assertEqual(len(peresources.resources(self.image, ["5"])), 2)

    def test_export_writes_icons_cursors_bitmaps_and_raw_data(self) -> None:
        out = self.root / "out"
        peresources.export(self.image, peresources.walk(self.image), out)
        ico = (out / "group_icon" / "105.ico").read_bytes()
        self.assertEqual(struct.unpack_from("<HHH", ico), (0, 1, 2))
        size, offset = struct.unpack_from("<II", ico, 6 + 8)
        self.assertEqual(ico[offset : offset + size], self.parts["dib"])
        self.assertEqual((out / "group_icon" / "105" / "256x256-32bpp-2.png").read_bytes(),
                         self.parts["png"])  # fmt: skip
        cur = (out / "group_cursor" / "106.cur").read_bytes()
        self.assertEqual(struct.unpack_from("<HHH", cur), (0, 2, 1))
        self.assertEqual(cur[22:], self.parts["cursor"][4:])
        self.assertTrue((out / "bitmap" / "107.bmp").read_bytes().startswith(b"BM"))
        self.assertEqual((out / "rcdata" / "CONFIG-0407.bin").read_bytes(), b"Schluessel=Wert")
        self.assertTrue((out / "manifest" / "1.xml").is_file())

    def test_a_32_bit_icon_converts_to_png_with_its_alpha(self) -> None:
        converted = peresources.dib_to_png(self.parts["dib"])
        self.assertTrue(converted.startswith(samples.PNG_SIGNATURE))
        width, height = struct.unpack_from(">II", converted, 16)
        self.assertEqual((width, height), (2, 2))
        (idat,) = [converted[i + 8 : i + 8 + struct.unpack_from(">I", converted, i)[0]]
                   for i in range(8, len(converted) - 8)
                   if converted[i + 4 : i + 8] == b"IDAT"]  # fmt: skip
        pixels = zlib.decompress(idat)
        # top row first: green opaque, transparent; then red opaque, blue at half alpha
        self.assertEqual(pixels, b"\0" + bytes([0, 255, 0, 255, 0, 0, 0, 0])
                         + b"\0" + bytes([255, 0, 0, 255, 0, 0, 255, 128]))  # fmt: skip

    def test_a_one_bit_image_takes_transparency_from_its_mask(self) -> None:
        mono = self.parts["cursor"][4:]
        converted = peresources.dib_to_png(mono)
        idat = converted[converted.index(b"IDAT") + 4 :]
        self.assertEqual(zlib.decompress(idat)[:5], b"\0\xff\xff\xff\xff")

    def test_a_truncated_resource_reports_an_error(self) -> None:
        resource = next(r for r in peresources.walk(self.image) if r.type_name == "DIALOG")
        resource.size = 20
        self.assertIn("error", peresources.decode(self.image, resource))

    def test_cli_text_json_and_extract(self) -> None:
        exe = self.root / "game" / "program.exe"
        exe.parent.mkdir()
        exe.write_bytes(samples.program_resources()[0])
        code, out = run("resources", str(exe), "--type", "dialog")
        self.assertEqual(code, 0)
        self.assertIn("dialog 101 (lang 0x0409, ", out)
        self.assertIn("  id 1      Button         'OK'", out)
        code, out = run("resources", str(exe), "--json", "--type", "version")
        self.assertEqual(json.loads(out)[0]["file_version"], "1.2.3.4")
        self.assertEqual(run("resources", str(exe), "--extract", str(exe.parent / "x"))[0], 2)
        code, _ = run("resources", str(exe), "--extract", str(self.root / "x"))
        self.assertEqual(code, 0)
        listed = json.loads((self.root / "x" / "resources.json").read_text())
        self.assertEqual(len(listed), 17)


if __name__ == "__main__":
    unittest.main()
