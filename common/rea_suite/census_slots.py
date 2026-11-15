"""Slot tables for the interface census (docs/census.md), generated from SDK headers.

  uv run python -m rea_suite.census_slots com <include-dir> [--out DIR]
      COM interfaces from MinGW-w64's headers: d3d9, d3dx9, dinput8, dsound
  uv run python -m rea_suite.census_slots physx <SDKs-dir> --sdk physx-2.6.4 [--out DIR]
      PhysX 2.x classes from the SDK's headers, preprocessed by g++ -E as a Win32 build
  uv run python -m rea_suite.census_slots imports <mingw-lib-dir> --dlls <SysWOW64> [--extra mss32.dll]
      [--include <mingw-include-dir>] [--out DIR]
      the Win32 imports' argument counts and calling conventions (win32-imports.json, below)

A table (`common/rea_suite/data/census/<sdk>.json`, schema "rea-census-slots/1") lists per
interface its vtable in slot order: each method's name, its argument count without `this`, the
interface it returns in EAX, the ones it hands out through out-parameters (by the index of the
argument dword on the stack at the call, `this` counted for a COM method) and, for
QueryInterface-shaped methods, which argument is the IID and which the out-pointer. It lists the
factory functions the same way, and the IIDs by their bytes. The tables are generated files:
change the generator, never the JSON.

COM headers declare each interface with every inherited method in its block, in vtable order.
C++ classes follow MSVC's layout: the base's vtable first, an override in its base's slot, a
virtual destructor one slot (the deleting destructor), new virtuals in declaration order except
that overloads of one name are grouped at the first one's place in reverse declaration order.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

OUT = Path(__file__).resolve().parent / "data" / "census"
SCHEMA = "rea-census-slots/1"

# The COM SDKs: name, headers (globs under the include directory), modules their functions are in.
COM_SDKS = {
    "d3d9": (["d3d9.h"], "d3d9.dll"),
    "d3dx9": (["d3dx9*.h"], "d3dx9_*.dll"),
    "dinput8": (["dinput.h"], "dinput8.dll"),
    "dsound": (["dsound.h"], "dsound.dll"),
}

# The PhysX 2.x headers a game reaches, and the module of each header's exported functions.
PHYSX_HEADERS = {
    "NxPhysics.h": "physxloader.dll",
    "PhysXLoader.h": "physxloader.dll",
    "NxCooking.h": "nxcooking.dll",
    "NxCharacter.h": "nxcharacter.dll",
    "ControllerManager.h": "nxcharacter.dll",
    "NxBoxController.h": "nxcharacter.dll",
    "NxCapsuleController.h": "nxcharacter.dll",
}
PHYSX_INCLUDES = ("Physics", "Foundation", "PhysXLoader", "Cooking", "NxCharacter")


@dataclass
class Method:
    name: str
    params: list[str]
    returns: str  # the return type as written
    signature: str = ""  # normalized parameters, for overrides


@dataclass
class Interface:
    name: str
    base: str | None
    methods: list[Method] = field(default_factory=list)
    thiscall: bool = False


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def split_params(text: str) -> list[str]:
    """Top-level comma split; `void`, `THIS` and empty lists are no parameters."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    out = [p for p in out if p]
    return [] if out in ([], ["void"], ["THIS"]) else out


class Types:
    """Pointer depth of a type to an interface, through the headers' typedefs."""

    def __init__(
        self,
        interfaces: set[str],
        typedefs: dict[str, tuple[str, int]],
        records: set[str] = frozenset(),
    ):
        self.interfaces = interfaces
        self.typedefs = typedefs
        self.records = records
        self.callbacks: dict[
            str, int
        ] = {}  # callback typedef -> its context parameter's index  # classes and structs: one returned by value takes a hidden pointer

    def resolve(self, text: str) -> tuple[str, int] | None:
        """(interface, pointer depth) for a type or parameter text, references counted as
        pointers; None when it names no interface."""
        stars = text.count("*") + text.count("&")
        text = re.sub(r"=.*$", "", text)  # a default argument
        for word in re.findall(r"[A-Za-z_]\w*", text):
            depth, seen = 0, 0
            while word not in self.interfaces and word in self.typedefs and seen < 8:
                word, more = self.typedefs[word]
                depth += more
                seen += 1
            if word in self.interfaces:
                return word, stars + depth
        return None


TYPEDEF = re.compile(
    r"\btypedef\s+(?:const\s+)?(?:struct\s+|interface\s+|class\s+)?(\w+)\s+([^;{}()]+);"
)


def typedefs_of(text: str) -> dict[str, tuple[str, int]]:
    found: dict[str, tuple[str, int]] = {}
    for base, declarators in TYPEDEF.findall(text):
        for d in declarators.split(","):
            name = re.findall(r"\w+", d)
            if name and name[-1] != base:
                found.setdefault(name[-1], (base, d.count("*")))
    return found


COM_BLOCK = re.compile(
    r"DECLARE_INTERFACE(?:_|_IID_)?\(\s*(\w+)\s*(?:,\s*(\w+)\s*)?(?:,[^)]*)?\)\s*\{(.*?)\}\s*;",
    re.DOTALL,
)
COM_METHOD = re.compile(
    r"STDMETHOD(?:_)?\(\s*(?:([^,()]+?)\s*,\s*)?(\w+)\s*\)\s*\((.*?)\)\s*(?:const\s*)?PURE\s*;",
    re.DOTALL,
)
WINAPI_FN = re.compile(
    r"(?:^|[;}\n])\s*(?:extern\s+)?((?:const\s+)?(?:struct\s+)?\w+(?:\s*\*)*)\s*WINAPI\s+(\w+)\s*\(([^;{]*?)\)\s*;",
    re.DOTALL,
)
GUID = re.compile(r"DEFINE_GUID\(\s*IID_(\w+)\s*,((?:\s*0x[0-9A-Fa-f]+\s*,?){11})\)")


def guid_bytes(numbers: list[int]) -> str:
    d1, d2, d3, *rest = numbers
    return (
        d1.to_bytes(4, "little") + d2.to_bytes(2, "little") + d3.to_bytes(2, "little") + bytes(rest)
    ).hex()


def com_tables(include: Path) -> dict[str, dict]:
    """One table per COM SDK in COM_SDKS, from the MinGW headers under include."""
    texts: dict[str, list[tuple[Path, str]]] = {}
    for sdk, (globs, _module) in COM_SDKS.items():
        files = sorted({p for g in globs for p in include.glob(g)})
        texts[sdk] = [
            (p, strip_comments(p.read_text(encoding="utf-8", errors="replace"))) for p in files
        ]
    every = "\n".join(t for files in texts.values() for _p, t in files)
    blocks = {name: (base, body) for name, base, body in COM_BLOCK.findall(every)}
    types = Types(set(blocks) | {"IUnknown"}, typedefs_of(every))
    types.callbacks = callbacks_of(every)
    iids = {}
    for name, numbers in GUID.findall(every):
        if name in types.interfaces:
            iids[name] = guid_bytes([int(n, 16) for n in re.findall(r"0x[0-9A-Fa-f]+", numbers)])
    tables = {}
    for sdk, files in texts.items():
        module = COM_SDKS[sdk][1]
        interfaces, functions = {}, {}
        for path, text in files:
            for name, base, body in COM_BLOCK.findall(text):
                if name in interfaces:
                    continue
                methods = [
                    Method(m, split_params(p.replace("THIS_", "")), r or "HRESULT")
                    for r, m, p in COM_METHOD.findall(body)
                ]
                interfaces[name] = interface_json(
                    Interface(name, base or None, methods), types, com=True
                )
            for returns, name, params in WINAPI_FN.findall(text):
                functions.setdefault(
                    name, function_json(module, Method(name, split_params(params), returns), types)
                )
        tables[sdk] = {
            "schema": SCHEMA,
            "sdk": sdk,
            "source": {"headers": "mingw-w64", "files": {p.name: sha256(p) for p, _t in files}},
            "conv": "stdcall",
            "interfaces": interfaces,
            "functions": {
                k: v for k, v in functions.items() if v["returns"] or v["out"] or v.get("riid")
            },
            "iids": {k: v for k, v in iids.items() if k in interfaces},
        }
    return tables


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def method_json(m: Method, types: Types, this_slot: int) -> dict:
    """A method or function: its arguments, what it returns and hands out. this_slot is 1 when
    `this` is the first stack argument (COM), else 0."""
    ret = types.resolve(m.returns)
    # MSVC returns a class by value through a hidden pointer, the first stack argument; the
    # count includes it, as winrt's tables do
    hidden = 1 if not ret and by_value_record(m.returns, types.records) else 0
    row: dict = {"name": m.name, "args": len(m.params) + hidden}
    if ret and ret[1] == 1:
        row["returns"] = ret[0]
    if returns_float(m.returns):
        row["returns_float"] = True  # in ST(0)
    outs, riid = [], None
    for i, p in enumerate(m.params):
        t = types.resolve(p)
        index = this_slot + hidden + i
        if t and t[1] == 2:
            outs.append({"stack": index, "interface": t[0]})
        elif re.search(r"\bREFIID\b|\bREFGUID\b.*riid", p) and riid is None:
            riid = index
        elif riid is not None and re.search(r"(void|VOID)\s*\*\s*\*|LPVOID\s*\*", p):
            row["riid"] = {"iid": riid, "out": index}
    if outs:
        row["out"] = outs
    callbacks = []
    for i, p in enumerate(m.params):
        words = re.findall(r"\w+", p)
        k = next((types.callbacks[w] for w in words if w in types.callbacks), None)
        if k is None:
            continue
        ctx = next(
            (
                j
                for j in range(i + 1, len(m.params))
                if re.search(r"\bLPVOID\b|\bvoid\s*\*", m.params[j])
            ),
            None,
        )
        if ctx is not None:
            callbacks.append(
                {
                    "function": this_slot + hidden + i,
                    "context": this_slot + hidden + ctx,
                    "param": k,
                }
            )
    if callbacks:
        row["callbacks"] = callbacks  # the context argument reaches the callback as parameter k
    return row


CALLBACK = re.compile(
    r"typedef\s+[\w\s]+?\(\s*(?:CALLBACK|WINAPI|PASCAL|__stdcall)\s*\*\s*(\w+)\s*\)\s*\(([^;]*?)\)\s*;"
)


def callbacks_of(text: str) -> dict[str, int]:
    """Callback typedefs and the index of their context parameter (the last void pointer)."""
    found = {}
    for name, params in CALLBACK.findall(text):
        plist = split_params(params)
        ctx = [i for i, q in enumerate(plist) if re.search(r"\bLPVOID\b|\bvoid\s*\*|\bPVOID\b", q)]
        if ctx:
            found[name] = ctx[-1]
    return found


FLOATS = {"float", "double", "FLOAT", "DOUBLE", "NxReal", "NxF32", "NxF64"}


def returns_float(text: str) -> bool:
    words = [w for w in re.findall(r"\w+", text) if w not in ("const", "virtual", "inline")]
    return (
        "*" not in text
        and "&" not in text
        and words[-1:] == [w for w in words[-1:] if w in FLOATS]
        and bool(words)
    )


def by_value_record(text: str, records: set[str]) -> bool:
    words = [
        w for w in re.findall(r"\w+", text) if w not in ("const", "struct", "class", "virtual")
    ]
    return bool(words) and "*" not in text and "&" not in text and words[-1] in records


def function_json(module: str, m: Method, types: Types) -> dict:
    row = method_json(m, types, 0)
    row.pop("name")
    row["module"] = module
    row.setdefault("returns", None)
    row.setdefault("out", [])
    return row


def interface_json(i: Interface, types: Types, com: bool) -> dict:
    return {
        "base": i.base,
        "methods": [method_json(m, types, 1 if com else 0) for m in i.methods],
    }


# --- C++ (PhysX) ---------------------------------------------------------------------------

CLASS = re.compile(
    r"\b(?:class|struct)\s+(?:__declspec\s*\([^)]*\)\s*)?(\w+)\s*(?::\s*(?:public|protected|private)?\s*(?:virtual\s+)?(\w+)\s*)?\{"
)
KEYWORDS = {"const", "virtual", "unsigned", "signed", "struct", "class", "inline", "NX_INLINE"}


def block_end(text: str, start: int) -> int:
    """Index just past the brace block opening at text[start] == '{'."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def class_statements(body: str) -> list[str]:
    """The declarations at the class body's own level, inline bodies and nested blocks cut."""
    out, cur, i = [], [], 0
    while i < len(body):
        ch = body[i]
        if ch == "{":
            out.append("".join(cur).strip())
            cur = []
            i = block_end(body, i)
            continue
        if ch == ";":
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    return [s for s in out if s]


def parse_virtual(statement: str) -> Method | None:
    statement = re.sub(r"\b(?:public|protected|private)\s*:", "", statement).strip()
    if not re.match(r"virtual\b", statement):
        return None
    rest = statement[len("virtual") :]
    for match in re.finditer(r"(~?[A-Za-z_]\w*)\s*\(", rest):
        if match.group(1) in KEYWORDS or match.group(1) == "__declspec":
            continue
        name = match.group(1)
        start = match.end() - 1
        depth, end = 0, start
        for end in range(start, len(rest)):
            depth += {"(": 1, ")": -1}.get(rest[end], 0)
            if depth == 0:
                break
        params = split_params(rest[start + 1 : end])
        returns = rest[: match.start()].strip()
        signature = ",".join(re.sub(r"\s+\w+\s*(=.*)?$", "", p).replace(" ", "") for p in params)
        if rest[end + 1 :].strip().startswith("const"):
            signature += " const"
        return Method(name, params, returns, signature)
    return None


def cpp_classes(text: str) -> dict[str, Interface]:
    found: dict[str, Interface] = {}
    for match in CLASS.finditer(text):
        name, base = match.group(1), match.group(2)
        start = match.end() - 1
        if text[max(0, match.start() - 40) : match.start()].rstrip().endswith(">"):
            continue  # a template's body: not a class with one layout
        body = text[start + 1 : block_end(text, start) - 1]
        methods = [m for s in class_statements(body) if (m := parse_virtual(s))]
        if name not in found or (methods and not found[name].methods):
            found[name] = Interface(name, base, methods, thiscall=True)
    return found


def msvc_vtable(
    name: str, classes: dict[str, Interface], memo: dict[str, list[Method]] | None = None
) -> list[Method]:
    """The class's vtable in MSVC's slot order (see the module's description)."""
    memo = {} if memo is None else memo
    if name in memo:
        return memo[name]
    cls = classes[name]
    table = list(msvc_vtable(cls.base, classes, memo)) if cls.base in classes else []
    new: list[Method] = []
    for m in cls.methods:
        if m.name.startswith("~"):
            at = next((i for i, b in enumerate(table) if b.name.startswith("~")), None)
        else:
            at = next(
                (i for i, b in enumerate(table) if b.name == m.name and b.signature == m.signature),
                None,
            )
        if at is not None:
            table[at] = m
        else:
            new.append(m)
    order: list[str] = []
    for m in new:
        if m.name not in order:
            order.append(m.name)
    for n in order:
        table.extend(reversed([m for m in new if m.name == n]))
    memo[name] = table
    return table


def physx_table(sdks: Path, sdk: str) -> dict:
    """The PhysX table from the SDK directory (the one holding Physics/, Foundation/...)."""
    includes = [f"-I{sdks / d / 'include'}" for d in PHYSX_INCLUDES]
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "all.cpp"
        source.write_text("".join(f'#include "{h}"\n' for h in PHYSX_HEADERS), encoding="utf-8")
        done = subprocess.run(
            ["g++", "-E", "-P", "-x", "c++", "-DWIN32", "-D_WIN32", *includes, str(source)],
            capture_output=True,
            text=True,
            check=True,
        )
    text = done.stdout
    classes = cpp_classes(text)
    names = {
        n for n in classes if msvc_vtable(n, classes)
    }  # a class without virtuals is no interface
    types = Types(names, typedefs_of(text), set(classes))
    interfaces = {}
    for name in sorted(classes):
        table = msvc_vtable(name, classes)
        if not table:
            continue
        interfaces[name] = {
            "base": classes[name].base if classes[name].base in classes else None,
            "methods": [method_json(m, types, 0) for m in table],
        }
    functions = {}
    for header, module in PHYSX_HEADERS.items():
        path = next(
            (
                sdks / d / "include" / header
                for d in PHYSX_INCLUDES
                if (sdks / d / "include" / header).exists()
            ),
            None,
        )
        if path is None:
            continue
        raw = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        for returns, name, params in re.findall(
            r"\b(?:NXPHYSXLOADERDLL_API|NXC_DLL_EXPORT|NXCHARACTER_API)\s+((?:const\s+)?\w+(?:\s*[*&])*)\s*(?:NX_CALL_CONV\s+)?(\w+)\s*\(([^;{]*?)\)\s*;",
            raw,
        ):
            row = function_json(module, Method(name, split_params(params), returns), types)
            if row["returns"] or row["out"]:
                functions.setdefault(name, row)
    files = {}
    for d in PHYSX_INCLUDES:
        for p in sorted((sdks / d / "include").glob("*.h")):
            files[f"{d}/{p.name}"] = sha256(p)
    return {
        "schema": SCHEMA,
        "sdk": sdk,
        "source": {"headers": f"PhysX SDK ({sdk}), preprocessed as a Win32 build", "files": files},
        "conv": "thiscall",
        "interfaces": interfaces,
        "functions": functions,
        "iids": {},
    }


# --- Win32 imports ----------------------------------------------------------------------------

IMPORT_MODULES = (
    "kernel32", "user32", "gdi32", "advapi32", "winmm", "wsock32", "ws2_32", "ole32", "oleaut32",
    "shell32", "version", "imm32", "comctl32", "comdlg32", "d3d9", "dinput", "dinput8", "dsound",
    "ddraw", "msvcrt", "opengl32", "glu32", "xinput1_1", "xinput1_2", "xinput1_3", "xinput9_1_0",
    "wininet", "iphlpapi", *(f"d3dx9_{n}" for n in range(24, 44)),
)  # fmt: skip
DECORATED = re.compile(r"^[0-9a-f]+ T _(\w+?)(?:@(\d+))?$")


def import_library(path: Path) -> dict[str, tuple[int | None, str]]:
    """Name -> (argument count, convention) from an i686 import library: `_Name@N` is stdcall
    with N bytes of arguments, an undecorated `_Name` is cdecl (count unknown: the caller cleans)."""
    out = subprocess.run(
        ["i686-w64-mingw32-nm", "--defined-only", str(path)],
        capture_output=True,
        text=True,
        check=True,
    )
    return parse_nm(out.stdout)


def parse_nm(text: str) -> dict[str, tuple[int | None, str]]:
    found: dict[str, tuple[int | None, str]] = {}
    for line in text.splitlines():
        match = DECORATED.match(line.strip())
        if not match:
            continue
        name, size = match.group(1), match.group(2)
        found.setdefault(name, (int(size) // 4, "stdcall") if size is not None else (None, "cdecl"))
    return found


def dll_exports(path: Path) -> list[tuple[int, str | None]]:
    """(ordinal, name or None) for every export of a DLL."""
    from rea_suite.pemodel import Image

    return [(e.ordinal, e.name) for e in Image.open(path).exports]


def float_returns(include: Path | None) -> set[str]:
    """Functions the headers declare as returning FLOAT or double (WINAPI ones)."""
    if include is None:
        return set()
    names = set()
    pattern = re.compile(
        r"\b(?:FLOAT|float|DOUBLE|double)\s+(?:WINAPI|APIENTRY|__stdcall|WINGDIAPI\s+\w+\s+APIENTRY)\s+(\w+)\s*\("
    )
    for header in include.glob("*.h"):
        names.update(pattern.findall(header.read_text(encoding="utf-8", errors="replace")))
    return names


def imports_table(
    lib_dir: Path, dll_dir: Path | None, extra: list[Path], include: Path | None
) -> dict:
    """The Win32 imports table: `module!Name` -> args, conv, returns_float; each named export
    also as `module!#ordinal` where the DLL is at hand."""
    floats = float_returns(include)
    functions: dict[str, dict] = {}
    sources: dict[str, str] = {}

    def add(module: str, name: str, args: int | None, conv: str) -> None:
        row: dict = {"module": module, "args": args, "conv": conv}
        if name in floats:
            row["returns_float"] = True
        functions[f"{module}!{name}"] = row

    for stem in IMPORT_MODULES:
        lib = lib_dir / f"lib{stem}.a"
        if not lib.exists():
            continue
        module = f"{stem}.dll"
        known = import_library(lib)
        sources[module] = f"{lib.name} {sha256(lib)[:16]}"
        for name, (args, conv) in sorted(known.items()):
            add(module, name, args, conv)
        dll = dll_dir / module if dll_dir else None
        if dll and dll.exists():
            for ordinal, name in dll_exports(dll):
                if name and name in known:
                    args, conv = known[name]
                    add(module, f"#{ordinal}", args, conv)
            sources[module] += f"; ordinals from {dll.name} {sha256(dll)[:16]}"
    for dll in extra:
        module = dll.name.lower()
        sources[module] = f"{dll.name} {sha256(dll)[:16]} (decorated exports)"
        for ordinal, name in dll_exports(dll):
            match = re.fullmatch(r"_?(\w+?)@(\d+)", name or "")
            if match:
                add(module, match.group(1), int(match.group(2)) // 4, "stdcall")
                add(module, name, int(match.group(2)) // 4, "stdcall")  # as imported, decorated
                add(module, f"#{ordinal}", int(match.group(2)) // 4, "stdcall")
    return {
        "schema": SCHEMA,
        "kind": "imports",
        "sdk": "win32",
        "source": {"note": "args and conv from MinGW-w64's i686 import libraries (_Name@N: stdcall, N/4 "
                   "arguments; undecorated: cdecl, args null); #ordinals from the DLLs named", "files": sources},
        "interfaces": {},
        "functions": dict(sorted(functions.items())),
        "iids": {},
    }  # fmt: skip


def write(table: dict, out: Path, name: str | None = None) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    path = out / (name or f"{table['sdk']}.json")
    path.write_text(json.dumps(table, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="census_slots", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    com = sub.add_parser("com", help="COM tables from MinGW-w64 headers")
    com.add_argument("include", type=Path)
    px = sub.add_parser("physx", help="a PhysX 2.x table from the SDK's headers")
    px.add_argument("sdks", type=Path, help="the SDK's SDKs/ directory")
    px.add_argument("--sdk", required=True, help="the table's name, as physx-2.6.4")
    im = sub.add_parser("imports", help="the Win32 imports' argument counts and conventions")
    im.add_argument("lib_dir", type=Path, help="MinGW-w64's i686 lib directory (lib<dll>.a)")
    im.add_argument("--dlls", type=Path, help="a folder of the 32-bit DLLs (SysWOW64): ordinals")
    im.add_argument(
        "--extra",
        type=Path,
        action="append",
        default=[],
        help="a DLL with decorated exports (mss32.dll)",
    )
    im.add_argument("--include", type=Path, help="MinGW-w64's include directory: float returns")
    for c in (com, px, im):
        c.add_argument("--out", type=Path, default=OUT)
    args = p.parse_args(argv)
    if args.command == "imports":
        table = imports_table(args.lib_dir, args.dlls, args.extra, args.include)
        path = args.out / "win32-imports.json"
        head = {k: v for k, v in table.items() if k != "functions"}
        lines = [
            f"  {json.dumps(k)}: {json.dumps(v, separators=(',', ':'))}"
            for k, v in table["functions"].items()
        ]
        text = (
            json.dumps(head, indent=1)[:-2]
            + ',\n "functions": {\n'
            + ",\n".join(lines)
            + "\n }\n}\n"
        )
        path.write_text(text, encoding="utf-8")  # one function a line: readable diffs
        print(f"{path}: {len(table['functions'])} functions")
        return 0
    tables = (
        com_tables(args.include).values()
        if args.command == "com"
        else [physx_table(args.sdks, args.sdk)]
    )
    for table in tables:
        path = write(table, args.out)
        count = sum(len(i["methods"]) for i in table["interfaces"].values())
        print(
            f"{path}: {len(table['interfaces'])} interfaces, {count} slots, {len(table['functions'])} functions"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
