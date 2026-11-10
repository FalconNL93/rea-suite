"""PE scans for porting work, from the file alone and without a disassembler project.

  rea-suite pe info <exe> [--imports] [--exports]      headers, sections, directories
  rea-suite pe sites <exe> <sites.json> | --init      check a port's declared sites
  rea-suite pe rtti <exe> [--class REGEX] [--slots] [--purecall ADDR]
                                                      MSVC classes: vtables, slots against
                                                      their bases' (overridden, inherited, pure)
  rea-suite pe refs <exe> (<address> | --string TEXT) instructions naming an address or string
  rea-suite pe callers <exe> <function> [--no-jumps]  E8/E9 rel32 calls and jumps to a function
  rea-suite pe strings <exe> <start> <size>           strings the code in a range loads
  rea-suite pe imports <exe> [--dll D] [--function F] every call site of imported functions
  rea-suite pe registry <exe> --range S:N --registrar ADDR=TYPE:FIELDS [--stack-byte OFF]
                                                      settings a game registers, from its code

Addresses are hexadecimal; one at or above the image base is a VA, a smaller one an RVA. Every
command takes --json. Results name the containing function from the x64 unwind table where it
has one; in JSON `function` is its address or null, and `function_known` says which. These are byte scans confirmed by decoding each hit (pemodel.py, scan.py, rtti.py);
for a full cross-reference picture use REA (`rea xrefs`, `search_strings`) or rea-ghidra.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from rea_suite import rtti, scan, sites
from rea_suite.pemodel import Image


def number(text: str) -> int:
    return int(text, 0) if text.lower().startswith("0x") else int(text, 16)


def hexa(value: int | None) -> str:
    return "-" if value is None else f"{value:#x}"


def emit(args, rows: list, line) -> None:
    if args.json:
        print(json.dumps(rows, indent=1))
        return
    for row in rows:
        print(line(row))


def section(s) -> dict:
    access = "r" if s.flags & 0x40000000 else "-"
    access += ("w" if s.writable else "-") + ("x" if s.executable else "-")
    return {
        "name": s.name,
        "rva": f"{s.rva:#x}",
        "size": f"{s.size:#x}",
        "offset": f"{s.offset:#x}",
        "raw_size": f"{s.raw_size:#x}",
        "flags": f"{s.flags:#010x}",
        "access": access,
    }


def info(image: Image) -> dict:
    imports = image.imports
    return {
        "machine": f"{image.machine:#06x}",
        "pe32+": image.x64,
        "image_base": f"{image.base:#x}",
        "entry_rva": f"{image.entry:#x}",
        "size_of_image": f"{image.size_of_image:#x}",
        "sections": [section(s) for s in image.sections],
        "imports": [{"import": r.label, "slot": f"{r.slot:#x}", "delay": r.delay} for r in imports],
        "exports": [
            {"name": e.name, "ordinal": e.ordinal, "rva": f"{e.rva:#x}", "forwarder": e.forwarder}
            for e in image.exports
        ],
        "relocations": len(image.relocations),
        "tls": None
        if image.tls is None
        else {**image.tls, "callbacks": [f"{v:#x}" for v in image.tls["callbacks"]]},
        "runtime_functions": len(image.runtime_functions),
    }


def cmd_info(args, image: Image) -> int:
    found = info(image)
    if args.json:
        print(json.dumps(found, indent=1))
        return 0
    print(
        f"machine {found['machine']}  {'PE32+' if image.x64 else 'PE32'}  base {found['image_base']}"
        f"  entry {found['entry_rva']}  size {found['size_of_image']}"
    )
    for s in found["sections"]:
        print(f"  {s['name']:<8} rva {s['rva']:>10}  size {s['size']:>10}  {s['access']}")
    dlls = {r["import"].split("!")[0].lower() for r in found["imports"]}
    delay = sum(1 for r in found["imports"] if r["delay"])
    print(
        f"imports: {len(found['imports'])} functions from {len(dlls)} DLLs ({delay} delay-loaded)"
    )
    print(f"exports: {len(found['exports'])}")
    print(f"relocations: {found['relocations'] or 'none (fixed base)'}")
    tls = found["tls"]
    callbacks = "none" if tls is None else f"{len(tls['callbacks'])} callbacks"
    print(f"tls: {callbacks}")
    print(f"unwind table: {found['runtime_functions']} functions")
    if args.imports:
        for r in found["imports"]:
            print(f"  {r['slot']}  {r['import']}{'  (delay)' if r['delay'] else ''}")
    if args.exports:
        for e in found["exports"]:
            print(
                f"  {e['rva']}  #{e['ordinal']}  {e['name'] or ''}{'  -> ' + e['forwarder'] if e['forwarder'] else ''}"
            )
    return 0


def cmd_sites(args, image: Image) -> int:
    data = image.data
    if args.init:
        print(json.dumps(sites.skeleton(image, data, args.exe.name), indent=2))
        return 0
    if args.spec is None:
        print("sites: give the declaration (sites.json) or --init", file=sys.stderr)
        return 2
    try:
        spec = sites.load(args.caller_cwd / args.spec)
    except (OSError, ValueError) as exc:
        print(f"sites: {args.spec}: {exc}", file=sys.stderr)
        return 2
    problems = sites.verify(spec, image, data)
    if args.json:
        print(json.dumps({"sites": len(spec.get("sites", [])), "problems": problems}, indent=1))
    else:
        for problem in problems:
            print(problem)
        count = len(spec.get("sites", []))
        print(f"{count} sites: {'all agree' if not problems else f'{len(problems)} problems'}")
    return 1 if problems else 0


def cmd_rtti(args, image: Image) -> int:
    found = rtti.classes(image)
    pure = rtti.purecalls(image) | {image.address(number(a)) for a in args.purecall}
    rtti.compare(found, pure)
    if args.cls:
        wanted = re.compile(args.cls)
        found = [c for c in found if wanted.search(c.name) or wanted.search(c.mangled)]
    if args.json:
        print(json.dumps([c.as_json() for c in found], indent=1))
        return 0
    for c in found:
        bases = ", ".join(b.name for b in c.bases[1:]) or "-"
        print(f"{c.name}  td {c.type_descriptor:#x}  bases: {bases}")
        for v in c.vtables:
            against = f", base {v.base} {v.base_vtable:#x}" if v.base else ""
            print(
                f"  vtable {v.rva:#x} (va {image.va(v.rva):#x}) offset {v.offset}: "
                f"{len(v.slots)} slots{against}"
            )
            if args.slots:
                for index, (slot, state) in enumerate(zip(v.slots, v.states, strict=True)):
                    print(f"    [{index}] {slot:#x}  {state}")
    print(f"{len(found)} classes", file=sys.stderr)
    return 0


def site_line(image: Image):
    return lambda s: f"{s.rva:#x}  {s.text:<40}  in {hexa(s.function)}"


def cmd_refs(args, image: Image) -> int:
    targets = (
        scan.find_string(image, args.string)
        if args.string is not None
        else [image.address(number(args.address))]
    )
    if args.string is not None and not targets:
        print(f"refs: string not found: {args.string!r}", file=sys.stderr)
        return 1
    rows = [s for target in targets for s in scan.refs(image, target)]
    if args.json:
        print(json.dumps([s.as_json(image) for s in rows], indent=1))
    else:
        if args.string is not None:
            print("string at " + ", ".join(f"{t:#x}" for t in targets))
        for s in rows:
            print(site_line(image)(s) + f"  -> {s.target:#x}")
    return 0 if rows else 1


def cmd_callers(args, image: Image) -> int:
    rows = scan.callers(image, image.address(number(args.function)), jumps=not args.no_jumps)
    if args.json:
        print(json.dumps([s.as_json(image) for s in rows], indent=1))
    else:
        for s in rows:
            print(site_line(image)(s))
    return 0 if rows else 1


def cmd_strings(args, image: Image) -> int:
    rows = scan.strings_in(
        image, image.address(number(args.start)), number(args.size), args.min_length
    )
    emit(args, rows, lambda r: f"{r['rva']}  {r['string']}  {r['encoding']:<5}  {r['text']!r}")
    return 0


def cmd_imports(args, image: Image) -> int:
    rows = scan.import_calls(image, args.dll, args.function)
    if args.used:
        rows = [r for r in rows if r["sites"]]
    if args.json:
        print(json.dumps(rows, indent=1))
        return 0 if rows else 1
    for r in rows:
        delay = " (delay-loaded)" if r["delay"] else ""
        print(
            f"{r['import']}  slot {r['slot']}{delay}: "
            f"{len(r['sites'])} sites in {len(r['functions'])} functions"
        )
        for u in r["sites"]:
            thunk = f" through thunk {u['thunk']}" if "thunk" in u else ""
            print(
                f"  {u['rva']}  {u['kind']:<9} {u['instruction']:<36} in {u['function'] or '-'}{thunk}"
            )
    return 0 if rows else 1


def registry_input(args, image: Image) -> tuple[list, dict, int | None]:
    """--config FILE, or --range/--registrar/--stack-byte; the file's values come first."""
    config = json.loads((args.caller_cwd / args.config).read_text()) if args.config else {}
    ranges = [(number(a), number(b)) for a, b in config.get("ranges", [])]
    ranges += [tuple(number(v) for v in r.split(":", 1)) for r in args.range]
    registrars = {
        image.address(number(addr)): scan.Registrar(spec["type"], list(spec["fields"]))
        for addr, spec in config.get("registrars", {}).items()
    }
    for text in args.registrar:
        addr, _, rest = text.partition("=")
        kind, _, fields = rest.partition(":")
        registrars[image.address(number(addr))] = scan.Registrar(kind, fields.split(","))
    byte = args.stack_byte or config.get("stack_byte")
    ranges = [(image.address(start), size) for start, size in ranges]
    return ranges, registrars, number(byte) if byte is not None else None


def cmd_registry(args, image: Image) -> int:
    ranges, registrars, byte = registry_input(args, image)
    if not ranges or not registrars:
        print(
            "registry: give at least one --range and one --registrar (or --config)", file=sys.stderr
        )
        return 2
    rows = scan.registry(image, ranges, registrars, byte)
    if args.json:
        print(json.dumps(rows, indent=1))
    elif args.markdown:
        fields = list(dict.fromkeys(f for r in registrars.values() for f in r.fields))
        columns = [*fields, "type", *(["stored"] if byte is not None else []), "site"]
        print("| " + " | ".join(columns) + " |")
        print("|" + "---|" * len(columns))
        for r in rows:
            cells = ["" if r.get(c) is None else str(r[c]).replace("|", "\\|") for c in columns]
            print("| " + " | ".join(cells) + " |")
    else:
        for r in rows:
            named = "  ".join(f"{f}={r[f]!r}" for f in registrars[int(r["registrar"], 16)].fields)
            stored = f"  stored={r['stored']!r}" if "stored" in r else ""
            print(f"{r['site']}  {r['type']:<8} {named}{stored}")
    print(f"{len(rows)} registrations", file=sys.stderr)
    return 0 if rows else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rea-suite pe",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)

    def command(name: str, help: str, run) -> argparse.ArgumentParser:
        c = sub.add_parser(name, help=help)
        c.add_argument("exe", type=Path)
        c.add_argument("--json", action="store_true")
        c.set_defaults(run=run)
        return c

    c = command("info", "headers, sections and directories", cmd_info)
    c.add_argument("--imports", action="store_true", help="list every import with its slot")
    c.add_argument("--exports", action="store_true", help="list every export")
    c = command("sites", "check a port's declared sites against the executable", cmd_sites)
    c.add_argument("spec", type=Path, nargs="?", help="the declaration (rea-image-sites-v1)")
    c.add_argument("--init", action="store_true", help="print a new declaration for this file")
    c = command("rtti", "MSVC RTTI: classes, vtables and slots, base classes", cmd_rtti)
    c.add_argument("--class", dest="cls", help="only classes whose name matches this regex")
    c.add_argument(
        "--slots", action="store_true", help="list every slot: overridden, inherited, pure, new"
    )
    c.add_argument(
        "--purecall",
        action="append",
        default=[],
        help="a statically linked _purecall stub (hex); an imported one is found; repeatable",
    )
    c = command("refs", "instructions that name an address or a string", cmd_refs)
    c.add_argument("address", nargs="?")
    c.add_argument("--string", help="the string's text (ASCII or UTF-16, whole string)")
    c = command("callers", "E8/E9 rel32 calls and jumps to a function", cmd_callers)
    c.add_argument("function")
    c.add_argument("--no-jumps", action="store_true", help="calls only")
    c = command("strings", "strings the code in a range loads", cmd_strings)
    c.add_argument("start")
    c.add_argument("size")
    c.add_argument("--min-length", type=int, default=4)
    c = command("imports", "every call site of imported functions, by IAT slot", cmd_imports)
    c.add_argument("--dll", help="one DLL (case-insensitive)")
    c.add_argument("--function", help="one function name (case-insensitive)")
    c.add_argument("--used", action="store_true", help="leave out imports no code uses")
    c = command("registry", "settings registered by calls in a code range", cmd_registry)
    c.add_argument("--range", action="append", default=[], help="START:SIZE (hex), repeatable")
    c.add_argument(
        "--registrar",
        action="append",
        default=[],
        help="ADDR=TYPE:FIELD,FIELD... the strings before each call, in load order; repeatable",
    )
    c.add_argument("--stack-byte", help="report the byte stored to [rsp+OFF] before each call")
    c.add_argument("--config", type=Path, help="JSON with ranges, registrars, stack_byte")
    c.add_argument("--markdown", action="store_true", help="a Markdown table")
    return p


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if args.command == "refs" and (args.address is None) == (args.string is None):
        p.error("refs: give an address or --string")
    try:
        image = Image.open(args.caller_cwd / args.exe)
    except (OSError, ValueError) as exc:
        print(f"pe: {args.exe}: {exc}", file=sys.stderr)
        return 2
    return args.run(args, image)


if __name__ == "__main__":
    raise SystemExit(main())
