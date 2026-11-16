"""The interface census: the slot tables' layout rules, the static census of a synthetic program
(samples.program_census), rea-census/1 documents and the diff against a runtime's answers."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rea_suite import census, census_returns, census_slots, pe, pecensus, pefunctions, samples
from rea_suite.pemodel import Image


class Tables(unittest.TestCase):
    def setUp(self) -> None:
        self.slots = census.Slots.load()

    def test_the_slots_a_port_stopped_on(self) -> None:
        for interface, slot, name in [
            ("IDirect3DDevice9", 118, "CreateQuery"),
            ("IDirect3DDevice9", 16, "Reset"),
            ("IDirectInputDevice8A", 14, "GetObjectInfo"),
            ("NxActor", 17, "createShape"),
            ("NxScene", 6, "createActor"),
            ("NxPhysicsSDK", 4, "createScene"),
        ]:
            self.assertEqual(self.slots.method(interface, slot).name, name, (interface, slot))

    def test_what_hands_out_an_interface(self) -> None:
        self.assertEqual(self.slots.method("IDirect3D9", 16).out, ((6, "IDirect3DDevice9"),))
        self.assertEqual(self.slots.method("NxScene", 6).returns, "NxActor")
        self.assertEqual(self.slots.method("IDirectSound8", 0).riid, (1, 2))
        self.assertEqual(
            self.slots.function("d3dx9_35.dll", "D3DXCreateTexture").out,
            ((7, "IDirect3DTexture9"),),
        )
        self.assertIsNone(self.slots.function("other.dll", "D3DXCreateTexture"))
        self.assertEqual(self.slots.iids[samples.IID_IDIRECTINPUT8A], "IDirectInput8A")

    def test_com_methods_pop_this_and_thiscall_does_not(self) -> None:
        self.assertEqual(self.slots.method("IDirect3DDevice9", 118).pops, 12)
        self.assertEqual(self.slots.method("NxScene", 6).pops, 4)


class MsvcLayout(unittest.TestCase):
    def test_overrides_overloads_and_the_destructor(self) -> None:
        text = """
        class Base { public: virtual ~Base() {} virtual void a() = 0; virtual int f(int x) = 0; };
        class Derived : public Base {
          public:
            virtual void b() = 0;
            virtual void f2(int) = 0;
            virtual void g(int x) = 0;
            virtual void g(float x) = 0;
            virtual void a() = 0;
            virtual ~Derived() {}
            NX_INLINE int inline_helper() { return 0; }
        };
        """
        classes = census_slots.cpp_classes(text)
        names = [m.name for m in census_slots.msvc_vtable("Derived", classes)]
        self.assertEqual(names, ["~Derived", "a", "f", "b", "f2", "g", "g"])
        table = census_slots.msvc_vtable("Derived", classes)
        self.assertEqual([m.params for m in table[5:]], [["float x"], ["int x"]])  # reversed

    def test_com_blocks_and_typedefs(self) -> None:
        text = census_slots.strip_comments("""
        typedef struct IThing *LPTHING, **LPLPTHING;
        DECLARE_INTERFACE_(IThing, IUnknown) {
            STDMETHOD_(HRESULT,QueryInterface)(THIS_ REFIID riid, void** ppvObject) PURE;
            STDMETHOD_(ULONG,AddRef)(THIS) PURE;
            STDMETHOD(Clone)(THIS_ DWORD flags, LPLPTHING out) PURE;  /* a comment */
        };
        """)
        blocks = census_slots.COM_BLOCK.findall(text)
        types = census_slots.Types({"IThing", "IUnknown"}, census_slots.typedefs_of(text))
        methods = [census_slots.Method(m, census_slots.split_params(p.replace("THIS_", "")), r or "HRESULT")
                   for r, m, p in census_slots.COM_METHOD.findall(blocks[0][2])]  # fmt: skip
        rows = [census_slots.method_json(m, types, 1) for m in methods]
        self.assertEqual([r["name"] for r in rows], ["QueryInterface", "AddRef", "Clone"])
        self.assertEqual(rows[0]["riid"], {"iid": 1, "out": 2})
        self.assertEqual(rows[2]["out"], [{"stack": 2, "interface": "IThing"}])


class Votes(unittest.TestCase):
    def setUp(self) -> None:
        self.facts = pecensus.Facts(census.Slots.load())

    def vote(self, interface: str, *sites: int) -> None:
        for site in sites:
            self.facts.site = site
            self.facts.set_type(("g", 1), interface)

    def test_one_wrong_store_does_not_undo_many(self) -> None:
        self.vote("IDirect3DDevice9", 1, 2, 3, 4, 5, 6)
        self.vote("IDirect3DVertexBuffer9", 7)
        self.assertEqual(self.facts.type(("g", 1)), "IDirect3DDevice9")

    def test_a_close_split_is_no_answer(self) -> None:
        self.vote("IDirect3DDevice9", 1, 2)
        self.vote("IDirect3DVertexBuffer9", 3)
        self.assertIsNone(self.facts.type(("g", 1)))

    def test_a_base_and_its_derived_keep_the_base(self) -> None:
        self.vote("IDirect3DTexture9", 1, 2)
        self.vote("IDirect3DBaseTexture9", 3)
        self.assertEqual(self.facts.type(("g", 1)), "IDirect3DBaseTexture9")

    def test_a_site_votes_once(self) -> None:
        self.vote("IDirect3DDevice9", 1)
        self.facts.changed = False
        self.vote("IDirect3DDevice9", 1)
        self.assertFalse(self.facts.changed)


HEADER = """
#define STDAPI EXTERN_C HRESULT STDAPICALLTYPE
#define STDAPI_(type) EXTERN_C type STDAPICALLTYPE
#define WINOLEAPI STDAPI
typedef long LONG;
typedef LONG LSTATUS;
typedef unsigned long DWORD;
typedef void *HANDLE, *LPVOID;
typedef int (WINAPI *FARPROC)();
DECLARE_HANDLE(HWND);
typedef enum _KIND { KIND_A, KIND_B } KIND, *PKIND;
typedef struct _THING { int x; } THING;
WINBASEAPI HANDLE WINAPI CreateThing (LPCSTR name);  /* HANDLE: NULL */
WINOLEAPI CoMakeThing (REFCLSID rclsid, LPVOID *ppv);
STDAPI_(LPVOID) CoThingAlloc (SIZE_T cb);
WINADVAPI LSTATUS WINAPI RegThing (DWORD a);
WINUSERAPI HWND WINAPI FindThing (void);
WINBASEAPI VOID WINAPI Rest (DWORD ms);
DECL_WINELIB_TYPE_AW(LPTHING) KIND WINAPI KindOf (void);
THING WINAPI ThingByValue (void);
WINBASEAPI FARPROC WINAPI ThingProc (HANDLE h, LPCSTR name);
_CRTIMP double __cdecl thing_sqrt (double x);
int WINAPI Twice (void);
LPVOID WINAPI Twice (void);
struct IThing { virtual HRESULT STDMETHODCALLTYPE Rest (void) = 0; };
"""


class ReturnKinds(unittest.TestCase):
    def test_kinds_from_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "things.h").write_text(HEADER, encoding="utf-8")
            kinds, found, disagree = census_returns.header_kinds(Path(tmp))
        self.assertEqual(
            found,
            {
                "CreateThing": "handle", "CoMakeThing": "hresult", "CoThingAlloc": "pointer",
                "RegThing": "lstatus", "FindThing": "handle", "Rest": "void", "KindOf": "int",
                "ThingByValue": "unknown", "ThingProc": "pointer", "thing_sqrt": "float",
                "Twice": "unknown",  # declarations that disagree; the C++ method is no export
            },
        )  # fmt: skip
        self.assertEqual(disagree, 1)
        self.assertEqual(kinds.of("PKIND"), "pointer")

    def test_kinds_of_cpp_return_types(self) -> None:
        kinds = census_returns.ReturnKinds(
            "typedef unsigned int NxU32; typedef float NxReal; typedef NxU32 NxActorGroup;"
        )
        for text, kind in [
            ("NxU32", "dword"), ("NxActorGroup", "dword"), ("NxReal", "float"),
            ("NxActor*", "pointer"), ("const NxVec3&", "pointer"), ("bool", "bool"),
            ("void", "void"), ("NxVec3", "unknown"), ("unsigned __int64", "qword"),
        ]:  # fmt: skip
            self.assertEqual(kinds.of(text), kind, text)

    def test_rules_over_names(self) -> None:
        declared = {"CreateFileA": "handle", "CreateEventA": "handle", "RegOpenKeyA": "int",
                    "connect": "int", "WSAStartup": "int", "WSAGetLastError": "int"}  # fmt: skip
        kind = census_slots.import_kind
        self.assertEqual(kind("kernel32.dll", "CreateFileA", declared), "handle_invalid")
        self.assertEqual(kind("kernel32.dll", "CreateEventA", declared), "handle")
        self.assertEqual(kind("advapi32.dll", "RegOpenKeyA", declared), "lstatus")
        self.assertEqual(kind("ws2_32.dll", "connect", declared), "socket_error")
        self.assertEqual(kind("wsock32.dll", "WSAStartup", declared), "lstatus")
        self.assertEqual(kind("ws2_32.dll", "WSAGetLastError", declared), "int")
        self.assertEqual(kind("mss32.dll", "AIL_startup", declared), "unknown")

    def test_the_generated_tables_kinds(self) -> None:
        imports = json.loads((census.TABLES / "win32-imports.json").read_text())
        functions = imports["functions"]
        for key, kind in [
            ("ddraw.dll!DirectDrawCreateEx", "hresult"),
            ("dsound.dll!DirectSoundCreate8", "hresult"),
            ("ole32.dll!CoCreateInstance", "hresult"),
            ("kernel32.dll!CreateFileA", "handle_invalid"),
            ("kernel32.dll!CreateEventA", "handle"),
            ("advapi32.dll!RegOpenKeyA", "lstatus"),
            ("kernel32.dll!GetProcAddress", "pointer"),
            ("kernel32.dll!Sleep", "void"),
            ("user32.dll!GetMessageA", "bool"),
            ("winmm.dll!waveOutOpen", "mmresult"),
            ("wsock32.dll!#101", "socket_error"),  # an ordinal has its name's kind
            ("msvcrt.dll!sqrt", "float"),
        ]:
            self.assertEqual(functions[key]["return_kind"], kind, key)
        self.assertEqual(
            imports["return_kinds"]["hresult"]["failure"], 0x80004005
        )  # E_FAIL, not S_OK
        self.assertEqual(imports["return_kinds"]["handle_invalid"]["failure"], 0xFFFFFFFF)
        for path in sorted(census.TABLES.glob("*.json")):
            table = json.loads(path.read_text())
            self.assertEqual(set(table["return_kinds"]), set(census_returns.KINDS), path.name)
            rows = [m for i in table["interfaces"].values() for m in i["methods"]]
            for row in [*rows, *table["functions"].values()]:
                self.assertIn(row["return_kind"], census_returns.KINDS, (path.name, row))
                self.assertEqual(
                    bool(row.get("returns_float")), row["return_kind"] == "float", (path.name, row)
                )


class Win32Imports(unittest.TestCase):
    def test_decorated_names_give_stdcall_counts(self) -> None:
        found = census_slots.parse_nm(
            "00000000 T _CreateFileA@28\n00000000 I __imp__CreateFileA@28\n00000000 T _wsprintfA\n"
        )
        self.assertEqual(found, {"CreateFileA": (7, "stdcall"), "wsprintfA": (None, "cdecl")})

    def test_the_generated_table(self) -> None:
        table = json.loads((census.TABLES / "win32-imports.json").read_text())
        functions = table["functions"]
        self.assertEqual(table["kind"], "imports")
        self.assertEqual(
            functions["kernel32.dll!CreateFileA"],
            {
                "module": "kernel32.dll",
                "args": 7,
                "conv": "stdcall",
                "return_kind": "handle_invalid",
            },
        )
        self.assertEqual(functions["wsock32.dll!#101"]["args"], 4)  # WSAAsyncSelect by ordinal
        self.assertEqual(functions["mss32.dll!AIL_open_digital_driver"]["args"], 4)
        self.assertNotIn(
            "kernel32.dll!createfilea", census.Slots.load().functions
        )  # not a slot table


class StaticCensus(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        data, cls.at = samples.program_census()
        image = Image(data)
        starts = {v - image.base: k for k, v in cls.at.items() if k.startswith("f_")}
        cls.doc = census.static_census(image, pefunctions.Functions(image, starts))

    def sites(self) -> dict[tuple[str, int], list[dict]]:
        return {
            (i["name"], m["slot"]): m["sites"] for i in self.doc["interfaces"] for m in i["methods"]
        }

    def call(self, name: str) -> str:
        return f"{self.at[name]:#x}"

    def test_every_channel(self) -> None:
        sites = self.sites()
        expect = {
            ("IDirect3D9", 16): "c_createdevice",  # a global, from the factory's return
            ("IDirect3DDevice9", 118): "c_createquery",  # an out-parameter into a global, a return
            ("IDirectInput8A", 3): "c_dicreatedevice",  # an out-parameter typed by its IID
            ("IDirectInputDevice8A", 14): "c_getobjectinfo",
            ("IDirectSound8", 3): "c_createsoundbuffer",  # a factory called through a jmp thunk
            ("NxPhysicsSDK", 4): "c_createscene",  # thiscall
            ("NxScene", 6): "c_createactor",  # a field of a global object, through `this`
            ("NxActor", 17): "c_createshape",  # a method's return
            ("IDirect3DDevice9", 57): "c_setrenderstate",  # a field reached through EDI
        }
        # through a constructor's vtable: a virtual call made direct, a field of the class
        self.assertEqual(
            [s["call"] for s in sites[("IDirectInput8A", 3)]],
            [self.call("c_dicreatedevice"), self.call("c_m1_createdevice")],
        )
        self.assertEqual(
            [s["call"] for s in sites[("IDirectInputDevice8A", 14)]],
            [self.call("c_getobjectinfo"), self.call("c_m2_getobjectinfo")],
        )
        del expect[("IDirectInput8A", 3)], expect[("IDirectInputDevice8A", 14)]
        self.assertEqual(
            set(sites), set(expect) | {("IDirectInput8A", 3), ("IDirectInputDevice8A", 14)}
        )
        self.assertEqual(
            [s["call"] for s in sites[("IDirect3D9", 16)]],
            [self.call("c_createdevice"), self.call("c_rend_createdevice")],
        )
        del expect[("IDirect3D9", 16)]
        for key, mark in expect.items():
            self.assertEqual([s["call"] for s in sites[key]], [self.call(mark)], key)

    def test_sites_name_their_function_and_return_address(self) -> None:
        site = self.sites()[("IDirect3DDevice9", 118)][0]
        self.assertEqual(site["function"], self.call("f_query"))
        self.assertEqual(int(site["return"], 16), self.at["c_createquery"] + 6)
        self.assertEqual(
            self.sites()[("NxScene", 6)][0]["how"], f"global {self.at['g_world'] + 8:#x}"
        )

    def test_imports_and_coverage(self) -> None:
        imports = {(r["module"], r["name"]): r["sites"] for r in self.doc["imports"]}
        self.assertEqual(
            imports[("dsound.dll", "DirectSoundCreate8")][0]["call"], self.call("c_dscreate")
        )
        self.assertEqual(len(imports), 4)
        coverage = self.doc["coverage"]
        self.assertEqual((coverage["resolved"], coverage["unresolved"]), (12, 1))

    def test_a_run_seeds_what_the_code_alone_cannot_tie(self) -> None:
        data, at = samples.program_census()
        image = Image(data)
        starts = {v - image.base: k for k, v in at.items() if k.startswith("f_")}
        run = doc("runtime", [{"name": "IDirect3DDevice9", "methods": [
            {"slot": 2, "name": "Release", "sites": [{"return": f"{at['c_unknown'] + 3:#x}", "count": 1}]}]}])  # fmt: skip
        seeded = census.static_census(image, pefunctions.Functions(image, starts), seeds=[run])
        sites = {
            (i["name"], m["slot"]): m["sites"] for i in seeded["interfaces"] for m in i["methods"]
        }
        self.assertEqual(sites[("IDirect3DDevice9", 2)][0]["call"], self.call("c_unknown"))
        self.assertEqual(seeded["coverage"]["unresolved"], 0)
        with self.assertRaises(census.CensusError):
            census.static_census(
                image, pefunctions.Functions(image, starts), seeds=[doc("static", [])]
            )

    def test_the_document_reads_back(self) -> None:
        census.check(json.loads(json.dumps(self.doc)))
        self.assertEqual(self.doc["kind"], "static")
        self.assertEqual(
            {i["name"]: i["sdk"] for i in self.doc["interfaces"]}["NxActor"], "physx-2.6.4"
        )

    def test_the_cli(self) -> None:
        data, _ = samples.program_census()
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "game.exe"
            exe.write_bytes(data)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = pe.main(["--caller-cwd", tmp, "census", "game.exe"])
            self.assertEqual(code, 0)
            doc = json.loads(out.getvalue())
            self.assertEqual(doc["source"]["name"], "game.exe")
            self.assertIn("IDirect3D9", [i["name"] for i in doc["interfaces"]])


def doc(kind: str, interfaces: list, imports: list = ()) -> dict:
    return {
        "schema": census.SCHEMA,
        "kind": kind,
        "interfaces": interfaces,
        "imports": list(imports),
    }


class FromFrida(unittest.TestCase):
    def test_an_imports_log_becomes_a_runtime_census(self) -> None:
        lines = [
            json.dumps({"kind": "import", "import": "d3d9.dll!Direct3DCreate9", "caller": "Game.exe+0x1006"}),
            "not json",
            json.dumps({"kind": "imports", "module": "Game.exe", "counts": {
                "d3d9.dll!Direct3DCreate9": {"calls": 1, "callers": {"0x1006": 1}},
                "KERNEL32.dll!Sleep": {"calls": 5, "callers": {"0x2000": 2, "0x1f00": 3}}}}),
        ]  # fmt: skip
        doc = census.check(census.from_frida(lines, "Game.exe", 0x400000))
        rows = {(r["module"], r["name"]): r for r in doc["imports"]}
        self.assertEqual(
            rows[("d3d9.dll", "Direct3DCreate9")]["sites"],
            [{"return": "0x401006", "count": 1, "image": "Game.exe", "first": True}],
        )
        self.assertEqual(
            [s["return"] for s in rows[("kernel32.dll", "Sleep")]["sites"]],
            ["0x401f00", "0x402000"],
        )
        self.assertEqual(doc["kind"], "runtime")
        with self.assertRaises(census.CensusError):
            census.from_frida(lines[:2], "Game.exe", 0x400000)


class Diff(unittest.TestCase):
    answers = doc(
        "answers",
        [{"name": "IDirect3DDevice9", "sdk": "d3d9", "methods": [
            {"slot": 16, "answer": "implemented"}, {"slot": 41, "answer": "stub"},
            {"slot": 118, "answer": "missing"}]}],
        [{"module": "d3d9.dll", "name": "Direct3DCreate9", "answer": "implemented"}],
    )  # fmt: skip

    def test_gaps_from_both_sides(self) -> None:
        static = doc(
            "static",
            [{"name": "IDirect3DDevice9", "sdk": "d3d9", "methods": [
                {"slot": 16, "name": "Reset", "sites": [{"call": "0x1"}]},
                {"slot": 118, "name": "CreateQuery", "sites": [{"call": "0x2"}, {"call": "0x3"}]},
                {"slot": 119, "name": None, "sites": [{"call": "0x4"}]}]}],
            [{"module": "D3D9.dll", "name": "Direct3DCreate9", "sites": [{"call": "0x5"}]},
             {"module": "dsound.dll", "name": "#11", "sites": [{"call": "0x6"}]}],
        )  # fmt: skip
        runtime = doc(
            "runtime",
            [{"name": "IDirect3DDevice9", "sdk": "d3d9-other", "methods": [
                {"slot": 41, "name": "BeginScene", "answer": "stub", "sites": [{"return": "0x9", "count": 7}]}]}],
        )  # fmt: skip
        rows, warnings = census.diff(self.answers, [static, runtime])
        by = {(g.interface or g.module, g.slot if g.interface else g.name): g for g in rows}
        self.assertEqual(by[("IDirect3DDevice9", 118)].answer, "missing")
        self.assertEqual(by[("IDirect3DDevice9", 118)].static_sites, 2)
        self.assertEqual(by[("IDirect3DDevice9", 41)].answer, "stub")
        self.assertEqual(by[("IDirect3DDevice9", 41)].runtime_calls, 7)
        self.assertEqual(by[("IDirect3DDevice9", 119)].answer, "missing")  # not listed: no thunk
        self.assertEqual(by[("IDirect3DDevice9", 16)].answer, "implemented")
        self.assertEqual(by[("d3d9.dll", "Direct3DCreate9")].answer, "implemented")
        self.assertEqual(by[("dsound.dll", "#11")].answer, "missing")
        self.assertEqual(len(warnings), 1)
        text = "\n".join(census.diff_text(rows, warnings, every=False))
        self.assertIn("CreateQuery", text)
        self.assertNotIn("Reset", text)
        self.assertIn("4 of 6 methods and imports the game calls are not answered", text)

    def test_static_coverage_of_a_run(self) -> None:
        static = doc("static", [{"name": "IDirect3DDevice9", "methods": [
            {"slot": 57, "sites": [{"call": "0x10", "return": "0x16"}]},
            {"slot": 58, "sites": [{"call": "0x20", "return": "0x26"}]}]}])  # fmt: skip
        static["source"] = {"name": "Game.exe"}
        runtime = doc("runtime", [{"name": "IDirect3DDevice9", "methods": [
            {"slot": 57, "sites": [{"return": "0x16", "count": 3, "image": "Game.exe"}]},
            {"slot": 59, "sites": [{"return": "0x26", "count": 1}, {"return": "0x36", "count": 1}]},
            {"slot": 60, "sites": [{"return": "0x99", "count": 1, "image": "binkw32.dll"}]}]}])  # fmt: skip
        coverage = census.static_coverage([static, runtime])
        self.assertEqual((coverage["reached"], coverage["found"]), (3, 1))
        self.assertEqual([w["return"] for w in coverage["wrong"]], ["0x26"])
        self.assertEqual([m["return"] for m in coverage["missed"]], ["0x36"])
        self.assertIsNone(census.static_coverage([static]))

    def test_a_dll_the_game_ships_answers_its_imports(self) -> None:
        static = doc(
            "static",
            [],
            [{"module": "binkw32.dll", "name": "_BinkOpen@8", "sites": [{"call": "0x1"}]}],
        )
        runtime = doc("runtime", [])
        runtime["source"] = {
            "name": "Game.exe",
            "images": [{"name": "Game.exe"}, {"name": "binkw32.dll"}],
        }
        rows, _ = census.diff(self.answers, [static, runtime])
        bink = next(g for g in rows if g.module == "binkw32.dll")
        self.assertEqual((bink.answer, bink.guest), ("implemented", True))

    def test_the_runtime_s_counts_are_checked_against_the_sdk(self) -> None:
        answers = doc(
            "answers",
            [{"name": "IDirect3DDevice9", "methods": [
                {"slot": 118, "args": 2, "answer": "implemented"},  # CreateQuery: right
                {"slot": 57, "args": 3, "answer": "implemented"},  # SetRenderState takes 2
                {"slot": 16, "answer": "implemented"}]},  # no count: not checked
             {"name": "NxActor", "methods": [{"slot": 17, "args": 1, "returns_float": True}]}],
            [{"module": "KERNEL32.dll", "name": "CreateFileA", "args": 6}, {"module": "kernel32.dll", "name": "Sleep", "args": 1}],
        )  # fmt: skip
        found = census.check_counts(answers, census.Slots.load(), census.imports_table())
        self.assertEqual(len(found), 3, found)
        self.assertIn(
            "IDirect3DDevice9::SetRenderState (slot 57): the runtime says 3 arguments, d3d9 says 2",
            found,
        )
        self.assertTrue(any("NxActor::createShape" in f and "float" in f for f in found))
        self.assertTrue(
            any(f.startswith("kernel32.dll!CreateFileA: the runtime says 6") for f in found)
        )

    def test_documents_are_checked(self) -> None:
        with self.assertRaises(census.CensusError):
            census.check({"schema": "rea-census/2", "kind": "static"})
        with self.assertRaises(census.CensusError):
            census.check(doc("static", [{"name": "I", "methods": [{"slot": -1}]}]))
        with self.assertRaises(census.CensusError):
            census.check(
                doc("runtime", [{"name": "I", "methods": [{"slot": 1, "answer": "maybe"}]}])
            )
        with self.assertRaises(census.CensusError):
            census.diff(doc("static", []), [])

    def test_the_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.json").write_text(json.dumps(self.answers), encoding="utf-8")
            Path(tmp, "s.json").write_text(json.dumps(doc("static", [{"name": "IDirect3DDevice9", "methods": [
                {"slot": 118, "name": "CreateQuery", "sites": [{"call": "0x2"}]}]}])), encoding="utf-8")  # fmt: skip
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = census.main(["--caller-cwd", tmp, "diff", "a.json", "s.json", "--json"])
            self.assertEqual(code, 0)
            rows = json.loads(out.getvalue())["rows"]
            self.assertEqual(rows, [{"interface": "IDirect3DDevice9", "slot": 118, "name": "CreateQuery",
                                     "answer": "missing", "static_sites": 1, "runtime_calls": 0}])  # fmt: skip
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(census.main(["--caller-cwd", tmp, "diff", "s.json", "a.json"]), 2)


if __name__ == "__main__":
    unittest.main()
