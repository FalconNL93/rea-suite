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
  rea-suite pe disasm <exe> <addr|name>... [--count N | --to ADDR | --function] [--histogram]
                                                      disassembly with imports, names and
                                                      strings noted; a mnemonic histogram
  rea-suite pe resources <exe> [--type T] [--name N] [--extract DIR]
                                                      dialogs, menus, strings, version,
                                                      accelerators; icons and cursors exported
  rea-suite pe match <old> <new> --functions T --functions-new T [--header H --header-out F]
                                                      a known build's functions and data found
                                                      in a later build of the same code

Addresses are hexadecimal; one at or above the image base is a VA, a smaller one an RVA. Every
command takes --json. Results name the function they lie in: from --functions TSV (a
`rea-ghidra functions` export or a port's function table; repeatable, --game picks a `game`
column's rows), else the x64 unwind table, else starts guessed from the bytes (x86: call
targets, frames, padding), marked heuristic (`~0x401000` in text). In JSON `function` is the
start or null, `function_name` its name, `function_source` table, unwind or heuristic, and
`function_known` is true for a table or unwind start only. These are byte scans confirmed by
decoding each hit (pemodel.py, pefunctions.py, scan.py, rtti.py, peresources.py); for a full
cross-reference picture use REA (`rea xrefs`, `search_strings`) or rea-ghidra.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from rea_suite import pefunctions, pematch, peresources, rtti, scan, sites
from rea_suite.pemodel import Image


def number(text: str) -> int:
    return int(text, 0) if text.lower().startswith("0x") else int(text, 16)


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
    return lambda s: f"{s.rva:#x}  {s.text:<40}  in {scan.function_label(s.function)}"


def row_function(row: dict) -> str:
    """A JSON row's function fields as site_line shows them."""
    if not row.get("function"):
        return "-"
    mark = "~" if row.get("function_source") == "heuristic" else ""
    name = f" {row['function_name']}" if row.get("function_name") else ""
    return f"{mark}{row['function']}{name}"


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
    emit(
        args,
        rows,
        lambda r: (
            f"{r['rva']}  {r['string']}  {r['encoding']:<5}  {r['text']!r}  in {row_function(r)}"
        ),
    )
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
                f"  {u['rva']}  {u['kind']:<9} {u['instruction']:<36} in {row_function(u)}{thunk}"
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
            print(f"{r['site']}  {r['type']:<8} {named}{stored}  in {row_function(r)}")
    print(f"{len(rows)} registrations", file=sys.stderr)
    return 0 if rows else 1


def resolve(image: Image, text: str) -> int:
    """An address (hex, VA or RVA) or a function's name from --functions or the exports."""
    found = image.functions.address_of(text) if image.functions else None
    if found is None:
        found = next((e.rva for e in image.exports if e.name == text), None)
    if found is not None:
        return found
    try:
        return image.address(number(text))
    except ValueError:
        raise ValueError(f"neither an address nor a known function name: {text!r}") from None


def cmd_disasm(args, image: Image) -> int:
    functions = pefunctions.of(image)
    try:
        starts = [resolve(image, a) for a in args.at]
        end = image.address(number(args.to)) if args.to else None
    except ValueError as exc:
        print(f"disasm: {exc}", file=sys.stderr)
        return 2
    selections = []
    for start in starts:
        if args.function:
            found = functions.at(start)
            if found is None:
                print(f"disasm: no function known at {start:#x}", file=sys.stderr)
                return 1
            selections.append((found.start, functions.end_of(found.start), None))
        elif end is not None:
            selections.append((start, end, None))
        else:
            selections.append((start, None, args.count))
    listings = []
    for start, stop, count in selections:
        try:
            rows = scan.listing(image, start, stop, count)
        except ValueError as exc:
            print(f"disasm: {exc}", file=sys.stderr)
            return 1
        while args.function and len(rows) > 1 and rows[-1]["instruction"] in ("int3", "nop"):
            rows.pop()  # the padding before the next function
        listings.append(rows)
    if args.histogram:
        ranges = [(int(rows[0]["rva"], 16), sum(len(r["bytes"]) // 2 for r in rows))
                  for rows in listings if rows]  # fmt: skip
        if not selections:
            ranges = [(s.rva, s.data_size) for s in image.code_sections()]
        found = scan.histogram(image, ranges)
        if args.json:
            print(json.dumps(found, indent=1))
            return 0
        print(
            f"{found['instructions']} instructions, {found['distinct']} mnemonics, "
            f"{found['undecoded_bytes']} undecoded bytes"
        )
        for mnemonic, count in found["mnemonics"].items():
            print(f"  {count:>9}  {mnemonic}")
        return 0
    if not selections:
        print(
            "disasm: give an address or a name (or --histogram for the whole image)",
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(listings if len(listings) > 1 else listings[0], indent=1))
        return 0
    for rows in listings:
        if rows and "start" not in rows[0]:
            found = functions.at(int(rows[0]["rva"], 16))
            print(f"; in {scan.function_label(found)}")
        for r in rows:
            if "start" in r:
                mark = "~" if r["start"] == "heuristic" else ""
                print(f"{mark}{r['label'] or 'sub_' + r['va'][2:]}:")
            note = f"  ; {r['note']}" if r["note"] else ""
            print(f"  {r['va']}  {r['bytes']:<20} {r['instruction']}{note}")
        print()
    return 0


def resource_line(r: dict) -> list[str]:
    """A decoded resource for text output: one heading line and its items, briefly."""
    head = f"{r['type'].lower()} {r['name']} (lang {r['lang']}, {r['size']} bytes)"
    if "error" in r:
        return [f"{head}: {r['error']}"]
    kind = r["type"]
    if kind == "DIALOG":
        font = f", font {r['font']['size']} {r['font']['name']!r}" if "font" in r else ""
        controls = len(r["controls"])
        lines = [
            f"{head}: {r['kind']} {r['title']!r} {r['cx']}x{r['cy']}{font}, {controls} controls"
        ]
        for c in r["controls"]:
            lines.append(
                f"  id {c['id']:<6} {c['class']:<14} {c['text']!r:<24} style {c['style']}  "
                f"{c['x']},{c['y']} {c['cx']}x{c['cy']}"
            )
        return lines
    if kind == "MENU":
        lines = [f"{head}: {r['kind']}"]

        def items(entries: list, depth: int) -> None:
            for i in entries:
                if i.get("separator"):
                    lines.append("  " * depth + "-----")
                    continue
                ident = f"  id {i['id']}" if "id" in i and "items" not in i else ""
                lines.append("  " * depth + f"{i['text']!r}{ident}")
                items(i.get("items", []), depth + 1)

        items(r["items"], 1)
        return lines
    if kind == "STRING":
        return [head, *(f"  {s['id']:<6} {s['text']!r}" for s in r["strings"])]
    if kind == "MESSAGETABLE":
        return [head, *(f"  {m['id']:#010x} {m['text']!r}" for m in r["messages"])]
    if kind == "ACCELERATOR":
        return [head, *(f"  {e['key']:<16} id {e['id']}" for e in r["entries"])]
    if kind == "VERSION":
        lines = [
            f"{head}: file {r.get('file_version', '?')}, product {r.get('product_version', '?')}"
        ]
        for table, entries in r["strings"].items():
            lines += [f"  [{table}] {k}: {v!r}" for k, v in entries.items()]
        return lines
    if kind in ("GROUP_ICON", "GROUP_CURSOR"):
        sizes = ", ".join(f"{i['width']}x{i['height']} {i['bpp']}bpp" for i in r["images"])
        return [f"{head}: {sizes}"]
    if kind in ("BITMAP", "ICON", "CURSOR"):
        bpp = f" {r['bpp']}bpp" if "bpp" in r else ""
        return [f"{head}: {r['format']} {r['width']}x{r['height']}{bpp}"]
    return [head]


def cmd_resources(args, image: Image) -> int:
    rows = peresources.resources(image, args.type, args.name)
    if args.extract:
        out = (args.caller_cwd / args.extract).resolve()
        if out.is_relative_to((args.caller_cwd / args.exe).resolve().parent):
            print(
                "resources: --extract into the executable's own folder is refused", file=sys.stderr
            )
            return 2
        chosen = [r for r in peresources.walk(image)
                  if peresources.matches(r, args.type, args.name)]  # fmt: skip
        written = peresources.export(image, chosen, out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "resources.json").write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
        print(f"{len(written) + 1} files written to {out}", file=sys.stderr)
    if args.json:
        print(json.dumps(rows, indent=1))
    elif not args.extract:
        shown = [r for r in rows if r["type"] not in ("ICON", "CURSOR")] if not args.type else rows
        for r in shown:
            for line in resource_line(r):
                print(line)
        print(f"{len(rows)} resources", file=sys.stderr)
    return 0 if rows else 1


GENERATED_NAME = re.compile(r"(?:thunk_)?(?:FUN|sub)_[0-9A-Fa-f]+$")


def cmd_match(args, image: Image) -> int:
    if args.header and not args.header_out:
        print("match: --header needs --header-out", file=sys.stderr)
        return 2
    try:
        other = Image.open(args.caller_cwd / args.new)
        if args.functions_new:
            tables = [args.caller_cwd / t for t in args.functions_new]
            other.functions = pefunctions.Functions.from_tables(other, tables, args.game_new)
        header = (
            (args.caller_cwd / args.header).read_text(encoding="utf-8") if args.header else None
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(f"match: {exc}", file=sys.stderr)
        return 2
    if image.x64 != other.x64:
        print("match: one image is x86 and the other x64", file=sys.stderr)
        return 2
    old, new = pematch.Side(image), pematch.Side(other)
    result = pematch.match(old, new)
    rows = pematch.rows(old, new, result)
    summary = {
        "functions": len(result.functions),
        "old_functions": len(old.shapes),
        "new_functions": len(new.shapes),
        "data": len(result.data),
        "function_source": [old.functions.source, new.functions.source],
    }
    print(
        f"functions: {summary['functions']} of {summary['old_functions']} matched "
        f"({summary['new_functions']} in the new one); data: {summary['data']}",
        file=sys.stderr,
    )
    entries = []
    if header is not None:
        entries = pematch.translate_header(header, old, new, result)
        lines = pematch.header_lines(entries, image.x64)
        (args.caller_cwd / args.header_out).write_text("\n".join(lines) + "\n", encoding="utf-8")
        found = sum(1 for e in entries if e["kind"] in ("function", "data"))
        missing = sum(1 for e in entries if e["new"] is None)
        summary["header"] = {
            "found": found,
            "missing": missing,
            "constants": len(entries) - found - missing,
        }
        print(f"header: {found} addresses found, {missing} not", file=sys.stderr)
    if args.names:
        named = [r for r in rows if r["kind"] == "func" and r["name"]
                 and not GENERATED_NAME.match(r["name"])]  # fmt: skip
        lines = ["address\tname\told"] + [f"{r['new']}\t{r['name']}\t{r['old']}" for r in named]
        (args.caller_cwd / args.names).write_text("\n".join(lines) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps({"summary": summary, "map": rows}, indent=1))
    else:
        for r in rows:
            print("\t".join([r["kind"], r["old"], r["new"], r["how"], r["name"] or ""]))
    return 0 if result.functions else 1


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
        c.add_argument(
            "--functions",
            action="append",
            default=[],
            type=Path,
            metavar="TSV",
            help="function starts and names (rea-ghidra functions, a port's table); repeatable",
        )
        c.add_argument("--game", help="only --functions rows whose `game` column is this")
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
    c = command("disasm", "disassembly with imports, function names and strings noted", cmd_disasm)
    c.add_argument("at", nargs="*", help="addresses (hex) or function names")
    span = c.add_mutually_exclusive_group()
    span.add_argument("--count", type=int, default=24, help="instructions from each (default 24)")
    span.add_argument("--to", help="end address (exclusive)")
    span.add_argument(
        "--function", action="store_true", help="the whole function each address lies in"
    )
    c.add_argument(
        "--histogram",
        action="store_true",
        help="mnemonic counts over the selection, or every code section when none is given",
    )
    c = command("resources", "dialogs, menus, string tables, version, icons", cmd_resources)
    c.add_argument(
        "--type",
        action="append",
        default=[],
        help="DIALOG, MENU, STRING, ... or a number; repeatable",
    )
    c.add_argument("--name", action="append", default=[], help="a resource name or id; repeatable")
    c.add_argument(
        "--extract",
        type=Path,
        metavar="DIR",
        help="write icons (.ico/.cur and .png), bitmaps, manifests, the rest raw, resources.json",
    )
    c = command("match", "a known build's functions and data in a later build", cmd_match)
    c.add_argument("new", type=Path, help="the later build")
    c.add_argument(
        "--functions-new",
        action="append",
        default=[],
        type=Path,
        metavar="TSV",
        help="the later build's function table (the same formats as --functions); repeatable",
    )
    c.add_argument("--game-new", help="only --functions-new rows whose `game` column is this")
    c.add_argument("--header", type=Path, help="a C header of #define NAME 0x... for the old build")
    c.add_argument("--header-out", type=Path, help="where the header with candidates goes")
    c.add_argument(
        "--names", type=Path, metavar="TSV", help="write the old names at their new addresses"
    )
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
    if args.functions:
        tables = [args.caller_cwd / t for t in args.functions]
        try:
            image.functions = pefunctions.Functions.from_tables(image, tables, args.game)
        except (OSError, UnicodeDecodeError) as exc:
            print(f"pe: --functions: {exc}", file=sys.stderr)
            return 2
    return args.run(args, image)


if __name__ == "__main__":
    raise SystemExit(main())
