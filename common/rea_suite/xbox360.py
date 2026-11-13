"""Xbox 360 executables in a Ghidra project of your own: XEX through XEXLoaderWV, or the PE
image extracted from one (COFF machine 0x01f2) as PowerPC big-endian 64-bit with Altivec.

  rea-suite xbox360 analyze   <file> --project DIR [--name NAME] [--force]
  rea-suite xbox360 decomp    --project DIR [--program NAME] [-o OUT] <address>...
  rea-suite xbox360 xrefs     --project DIR [--program NAME] [-o OUT] <text>...
  rea-suite xbox360 functions --project DIR [--program NAME] [-o OUT]
  rea-suite xbox360 names     --project DIR [--program NAME] --from MAP.tsv [--where COL=VALUE]... [-o OUT]
  rea-suite xbox360 check                                 XEXLoaderWV installed and loading

`analyze` imports and analyzes once; `names` writes a port's map of names and comments into the project (a
TSV whose header names `address` and `name`, `what` or `comment` the comment: a name Ghidra gave is replaced, one a
person or an import gave is kept and reported); the other commands open the project read-only. Every one
first repairs the register save/restore helpers (common/ghidra_scripts/XenonHelpers.java) and
reports what Ghidra could not decode. Ghidra's logs go to DIR/logs/.

A game as it arrives, without extracting all of it: a .zar (Xenia's ZArchive), or a disc image (a
Redump XGD2/XGD3 ISO or an XISO, the XDVDFS partition found by itself):

  rea-suite xbox360 disc info    <game> [-o JSON]      container, partition, default.xex's title id
  rea-suite xbox360 disc list    <game> [-o TSV]       size and path of every file
  rea-suite xbox360 disc extract <game> [path...] -o DIR   default.xex, a folder, or everything

Without Ghidra, on an XEX, its extracted PE image, or a raw memory dump (--base):

  rea-suite xbox360 info    <xex> [-o JSON]           headers, security info, import libraries
  rea-suite xbox360 extract <xex> -o IMAGE            decrypted, decompressed image at its base
  rea-suite xbox360 imports <xex> [-o TSV]            import thunks with their names
  rea-suite xbox360 icon    <xex> -o OUT.png|.ico     the dashboard title image
  rea-suite xbox360 spa     <xex|spa> [--out DIR] [--format json|declarations] [--lang en-US]
                                                      achievements, strings, images, presence
  rea-suite xbox360 pdata   <image> [address...]      .pdata functions (containing the addresses)
  rea-suite xbox360 callers <image> <address>...      b/bl instructions to the addresses
  rea-suite xbox360 refs    <image> <text|0xaddr>...  lis + addi/load/store pairs building them
  rea-suite xbox360 rtti    <image> <Class>...        MSVC type descriptor, locators, vtables
  rea-suite xbox360 helpers <image>                   save/restore helpers (XenonRecomp keys)
  rea-suite xbox360 disasm  <image> <address> [count] Capstone; undecoded words are marked
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from rea_suite import containers, ghidra_headless, ppc, spa, spa_out, xdvdfs, xex, zar

# XEXLoaderWV's own choice; Ghidra's PE opinions know only little-endian PowerPC (0x01f0/0x01f1).
LANGUAGE = "PowerPC:BE:64:A2ALT-32addr"
XEX_LOADER = "XEXLoaderWVLoader"
XEX_LOADER_NAME = "XEX Loader by Warranty Voider"
PE_LOADER = "PeLoader"
MACHINE_POWERPCBE = 0x01F2
SCRIPTS = Path(__file__).resolve().parents[1] / "ghidra_scripts"
FIX = "rea-suite tools reinstall ghidra"


def kind(path: Path) -> str:
    """'xex' by the XEX2 magic, 'pe' for a PE with COFF machine 0x01f2; anything else refused."""
    with path.open("rb") as stream:
        head = stream.read(4096)
    if head.startswith(b"XEX2"):
        return "xex"
    if head.startswith(b"MZ") and len(head) >= 0x40:
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        if offset + 6 <= len(head) and head[offset : offset + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", head, offset + 4)[0]
            if machine == MACHINE_POWERPCBE:
                return "pe"
            raise ValueError(f"PE machine 0x{machine:04x} is not the Xbox 360's 0x01f2")
    raise ValueError(f"{path.name}: neither an XEX (XEX2) nor an Xbox 360 PE image")


def ghidra_install() -> Path:
    install = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install:
        raise ValueError("GHIDRA_INSTALL_DIR missing; run through rea-suite")
    return Path(install)


def ghidra_version(install: Path) -> str:
    props = (install / "Ghidra" / "application.properties").read_text()
    return re.search(r"^application\.version=(.+)$", props, re.MULTILINE)[1].strip()


def loader_problem(install: Path) -> str | None:
    """Why Ghidra would not load XEXLoaderWV, from the files alone; None when it is in place."""
    ext = install / "Ghidra" / "Extensions" / "XEXLoaderWV"
    jar = ext / "lib" / "XEXLoaderWV.jar"
    props = ext / "extension.properties"
    if not jar.is_file() or not props.is_file():
        return f"XEXLoaderWV is not installed in {install.name}; run {FIX}"
    match = re.search(r"^version=(.+)$", props.read_text(), re.MULTILINE)
    want = ghidra_version(install)
    if not match or match[1].strip() != want:
        found = match[1].strip() if match else "none"
        return f"XEXLoaderWV is built for Ghidra {found}, not {want}; run {FIX}"
    return None


def runner(install: Path) -> str:
    return str(ghidra_headless.AnalyzeHeadless(install).executable)


def project_name(project: Path, name: str | None) -> str:
    """The project's one .gpr, or the name given for a new project."""
    found = sorted(p.stem for p in project.glob("*.gpr")) if project.is_dir() else []
    if name:
        if found and name not in found:
            raise ValueError(f"{project} holds {', '.join(found)}, not {name}")
        return name
    if len(found) == 1:
        return found[0]
    if found:
        raise ValueError(f"{project} holds several projects ({', '.join(found)}); pass --name")
    raise ValueError(f"no Ghidra project in {project}; run analyze first or pass --name")


def import_command(install: Path, project: Path, name: str, target: Path, summary: Path,
                   timeout: int, force: bool) -> list[str]:  # fmt: skip
    loader = (
        ["-loader", XEX_LOADER]
        if kind(target) == "xex"
        else ["-loader", PE_LOADER, "-processor", LANGUAGE, "-cspec", "default"]
    )
    return [
        runner(install),
        str(project),
        name,
        "-import",
        str(target),
        *loader,
        *(["-overwrite"] if force else []),
        "-analysisTimeoutPerFile",
        str(timeout),
        "-scriptPath",
        str(SCRIPTS),
        "-preScript",
        "XenonHelpers.java",
        "prepare",
        str(summary),
        "-postScript",
        "XenonHelpers.java",
        "repair",
        str(summary.with_suffix(".repair.json")),
    ]


def query_command(install: Path, project: Path, name: str, program: str | None,
                  summary: Path, script: list[str]) -> list[str]:  # fmt: skip
    return [
        runner(install),
        str(project),
        name,
        "-process",
        *([program] if program else []),
        "-noanalysis",
        "-readOnly",
        "-scriptPath",
        str(SCRIPTS),
        "-postScript",
        "XenonHelpers.java",
        "repair",
        str(summary),
        "-postScript",
        *script,
    ]


def limits(summary: dict, log_text: str, source: str) -> list[str]:
    """What the result leaves out, stated rather than silent."""
    found = []
    undecoded = summary.get("undecoded_instructions", 0)
    if undecoded:
        sample = ", ".join(summary.get("undecoded_sample", [])[:5])
        opcodes = summary.get("undecoded_opcodes", {})
        vmx128 = sum(n for op, n in opcodes.items() if op in ("4", "5", "6"))
        by_opcode = ", ".join(f"{op}: {n}" for op, n in opcodes.items())
        found.append(
            f"{undecoded} instruction(s) Ghidra cannot decode, {vmx128} of them in the VMX128"
            f" opcodes 4-6 that {LANGUAGE} lacks (by primary opcode: {by_opcode});"
            f" disassembly and decompiles stop there (first: {sample})"
        )
    pcode = len(set(re.findall(r"pcode error at ([0-9a-f]+): Unable to resolve", log_text)))
    if pcode:
        found.append(f"{pcode} decompiler p-code error(s) at undecodable instructions; see the log")
    if not summary.get("helpers"):
        found.append("no register save/restore helpers found; prologue calls may cut decompiles")
    if source == "pe":
        found.append(
            "PE image: no XEX import names or XEX headers (XEXLoaderWV reads those from the XEX)"
        )
    if summary.get("helpers"):
        found.append(
            "decompiles leave out the calls to the register save/restore helpers"
            " (a call-fixup without effect keeps them returning)"
        )
    return found


def read_summary(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def ghidra(command: list[str], project: Path, log: Path, timeout: int) -> None:
    """Runs analyzeHeadless into its log, bounded (ghidra_headless); a failure names the log."""
    ghidra_headless.run(command, log, timeout)


def analyze(args: argparse.Namespace, install: Path) -> int:
    target = (args.caller_cwd / args.file).resolve()
    project = (args.caller_cwd / args.project).resolve()
    if not target.is_file():
        raise ValueError(f"no such file: {target}")
    source = kind(target)
    if source == "xex" and (problem := loader_problem(install)):
        raise ValueError(problem)
    name = args.name or (project_name(project, None) if any(project.glob("*.gpr")) else None)
    name = name or target.stem
    program = project / f"{name}.rep"
    logs = project / "logs"
    summary = logs / f"{target.name}.summary.json"
    command = import_command(install, project, name, target, summary, args.timeout, args.force)
    if args.plan:
        print(json.dumps({"kind": source, "command": command}, indent=2))
        return 0
    if program.is_dir() and not args.force and target.name in program_names(project, name):
        raise ValueError(f"{target.name} is already in {project}; pass --force to redo it")
    logs.mkdir(parents=True, exist_ok=True)
    log = logs / f"analyze-{target.name}.log"
    print(f"xbox360: analyzing {target.name} as {source} (log: {log})", file=sys.stderr)
    with tempfile.TemporaryDirectory(dir=logs) as tmp:
        data = target.read_bytes() if source == "pe" else b""
        if source == "pe" and ppc.memory_layout(data):
            # An image extracted from an XEX is laid out as loaded while its section table still
            # gives the linker's file offsets; Ghidra's PE loader would map the wrong bytes.
            copy = Path(tmp) / target.name
            copy.write_bytes(ppc.loaded_headers(data))
            command[command.index(str(target))] = str(copy)
            print("xbox360: memory-layout image; section table rewritten to match", file=sys.stderr)
        ghidra(command, project, log, args.timeout + 300)
    text = log.read_text(errors="replace")
    used = re.search(r"Using Loader: (.+) \(\w+\)", text)
    want = XEX_LOADER_NAME if source == "xex" else "Portable Executable (PE)"
    if not used or used[1].strip() != want:
        raise ValueError(f"Ghidra used {used[1] if used else 'no loader'}, not {want}; see {log}")
    if "Import succeeded" not in text and "REPORT: Save succeeded" not in text:
        raise ValueError(f"import failed; see {log}")
    report = {**read_summary(summary.with_suffix(".repair.json")), "mode": "prepare"}
    prepared = read_summary(summary)
    report["pdata_functions"] = prepared.get("pdata_functions", 0)
    summary.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Project: {project / name}.gpr; program: {target.name} ({report.get('language')})")
    print(
        f"Helpers: {report.get('helpers', 0)} save/restore entries kept returning;"
        f" {report.get('pdata_functions', 0)} functions defined from .pdata;"
        f" {report.get('calls_repaired', 0)} call sites repaired after analysis"
    )
    for line in limits(report, text, source):
        print(f"Limit: {line}")
    return 0


def program_names(project: Path, name: str) -> set[str]:
    """Program names in a project, from its index (no Ghidra needed); empty when unreadable."""
    index = project / f"{name}.rep" / "idata" / "~index.dat"
    try:
        lines = index.read_text(errors="replace").splitlines()
    except OSError:
        return set()
    # "  <id>:<name>:<file id>" under each folder line
    return {line.split(":")[1] for line in lines if line.startswith("  ") and line.count(":") >= 2}


def read_names(path: Path, where: list[str]) -> list[tuple[str, str, str]]:
    """A port's map of names: a TSV whose header names `address` and `name` (`what` or `comment` the comment), the
    rows matching every `column=value` of where: [(address as hex digits, name, comment)]."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"{path}: empty")
    header = [c.strip() for c in lines[0].split("\t")]
    for column in ("address", "name"):
        if column not in header:
            raise ValueError(f"{path}: no `{column}` column in its header")
    note = next((c for c in ("comment", "what") if c in header), None)
    filters = []
    for given in where:
        column, sep, value = given.partition("=")
        if not sep or column not in header:
            raise ValueError(f"--where {given}: a column of {path} and its value, as game=mp")
        filters.append((header.index(column), value))
    rows = []
    for number, line in enumerate(lines[1:], start=2):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t") + [""] * len(header)
        if any(fields[i].strip() != value for i, value in filters):
            continue
        address, name = (
            fields[header.index("address")].strip(),
            fields[header.index("name")].strip(),
        )
        try:
            digits = f"{int(address, 16):x}"
        except ValueError:
            raise ValueError(f"{path}:{number}: `{address}` is no hex address") from None
        if not name:
            raise ValueError(f"{path}:{number}: no name")
        comment = fields[header.index(note)].strip() if note else ""
        rows.append((digits, name, comment))
    return rows


def names_command(install: Path, project: Path, name: str, program: str | None, summary: Path,
                  given: Path, report: Path, extra: tuple[str, ...] = ()) -> list[str]:  # fmt: skip
    """The query's command without -readOnly: the one command that writes to the project after analyze."""
    command = query_command(
        install,
        project,
        name,
        program,
        summary,
        ["ApplyNames.java", str(given), str(report), *extra],
    )
    command.remove("-readOnly")
    return command


NAME_RESULTS = ("named", "created", "same", "kept", "invalid", "missing")


def names(args: argparse.Namespace, install: Path) -> int:
    project = (args.caller_cwd / args.project).resolve()
    name = project_name(project, args.name)
    programs = program_names(project, name)
    if args.program is None and len(programs) > 1:
        raise ValueError(
            f"the project holds {', '.join(sorted(programs))}: name one with --program"
        )
    rows = read_names((args.caller_cwd / args.source).resolve(), args.where)
    with tempfile.TemporaryDirectory() as tmp:
        given, report, summary = (
            Path(tmp) / "names.tsv",
            Path(tmp) / "report.tsv",
            Path(tmp) / "summary.json",
        )
        given.write_text("".join(f"{a}\t{n}\t{c}\n" for a, n, c in rows), encoding="utf-8")
        extra = ("functions",) if args.functions else ()
        command = names_command(install, project, name, args.program, summary, given, report, extra)
        if args.plan:
            print(json.dumps({"command": command, "names": len(rows)}, indent=2))
            return 0
        logs = project / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / "names.log"
        ghidra(command, project, log, args.timeout)
        if not report.is_file():
            raise ValueError(f"ApplyNames.java wrote nothing; see {log}")
        text = report.read_text(errors="replace")
        if args.output:
            target = (args.caller_cwd / args.output).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        results = [line.split("\t") for line in text.splitlines()[1:] if line.count("\t") >= 3]
        counts = {r: sum(1 for line in results if line[1] == r) for r in NAME_RESULTS}
        print(
            ", ".join(f"{counts[r]} {r}" for r in NAME_RESULTS if counts[r]) or "nothing to apply"
        )
        for address, result, old, new in results:
            if result in ("kept", "invalid", "missing"):
                print(f"{result}: {address} {old or '-'} (the map says {new})", file=sys.stderr)
    return 0


def query(args: argparse.Namespace, install: Path) -> int:
    project = (args.caller_cwd / args.project).resolve()
    name = project_name(project, args.name)
    logs = project / "logs"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        summary = Path(tmp) / "summary.json"
        script = {
            "decomp": ["DecompileAt.java", str(out)],
            "xrefs": ["DecompileXrefs.java", str(out)],
            "functions": ["ExportFunctions.java", str(out)],
        }[args.command] + getattr(args, "items", [])
        command = query_command(install, project, name, args.program, summary, script)
        if args.plan:
            print(json.dumps({"command": command}, indent=2))
            return 0
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / f"{args.command}.log"
        ghidra(command, project, log, args.timeout)
        if not out.is_file():
            raise ValueError(f"{script[0]} wrote nothing; see {log}")
        text = out.read_text(errors="replace")
        if args.output:
            target = (args.caller_cwd / args.output).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        else:
            sys.stdout.write(text)
        report = read_summary(summary)
        for line in limits(report, log.read_text(errors="replace"), "project"):
            print(f"Limit: {line}", file=sys.stderr)
    return 0


def check(install: Path) -> int:
    """Doctor's check: the files are in place, and Ghidra asks the loader about a file."""
    problem = loader_problem(install)
    if problem:
        print(problem)
        return 1
    with tempfile.TemporaryDirectory() as tmp:
        sample = Path(tmp) / "probe.bin"
        sample.write_bytes(bytes(64))
        command = [runner(install), tmp, "probe", "-import", str(sample), "-readOnly"]
        log = Path(tmp) / "probe.log"
        try:
            ghidra_headless.run(command, log, 300, check=False)
        except ghidra_headless.GhidraError as exc:
            print(exc)
            return 1
        text = log.read_text(errors="replace") if log.is_file() else ""
    if "XEX Loader: Checking Signature" not in text:
        print(f"Ghidra {ghidra_version(install)} did not load XEXLoaderWV; run {FIX}")
        return 1
    print(f"XEXLoaderWV loads in Ghidra {ghidra_version(install)}")
    return 0


STATIC = {
    "info": "XEX headers as JSON",
    "extract": "write the decrypted in-memory image",
    "imports": "import thunks with ordinal names (TSV)",
    "icon": "the dashboard title image",
    "pdata": "the .pdata function table",
    "callers": "b/bl callers of addresses",
    "refs": "lis/addi and lis/load-store address references",
    "rtti": "MSVC RTTI of classes",
    "helpers": "register save/restore helper addresses",
    "disasm": "disassemble words",
}


def number(text: str) -> int:
    """Addresses are hexadecimal, with or without 0x."""
    return int(text, 16)


def static_parsers(sub) -> None:
    for name, text in STATIC.items():
        q = sub.add_parser(name, help=text)
        q.add_argument(
            "file",
            type=Path,
            help="XEX"
            if name in ("info", "extract", "imports", "icon")
            else "XEX, PE image or raw dump",
        )
        if name not in ("info", "extract", "imports", "icon"):
            q.add_argument(
                "--base", type=number, help="load address of a raw dump (default 0x82000000)"
            )
        if name in ("pdata", "callers", "refs", "rtti"):
            q.add_argument("items", nargs="*" if name == "pdata" else "+")
        if name == "disasm":
            q.add_argument("address", type=number)
            q.add_argument("count", type=int, nargs="?", default=16)
        q.add_argument("-o", "--output", type=Path, required=name in ("extract", "icon"))


def emit(args: argparse.Namespace, text: str) -> None:
    if args.output:
        target = (args.caller_cwd / args.output).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    else:
        sys.stdout.write(text)


def static(args: argparse.Namespace) -> int:
    data = (args.caller_cwd / args.file).resolve().read_bytes()
    if args.command in ("info", "extract", "imports", "icon"):
        if args.command == "info":
            emit(args, json.dumps(xex.parse(data), indent=1) + "\n")
            return 0
        info, img, key = xex.image(data)
        if args.command == "extract":
            target = (args.caller_cwd / args.output).resolve()
            target.write_bytes(img)
            base = info["headers"]["IMAGE_BASE_ADDRESS"]["value"]
            print(f"{target}: 0x{len(img):x} bytes at {base} ({key} key)", file=sys.stderr)
        elif args.command == "imports":
            rows = xex.imports(info, img)
            lines = ["library\taddress\ttype\tordinal\tname"]
            lines += [
                f"{r['library']}\t{r['address']}\t{r['type']}\t{r['ordinal']}\t{r['name']}"
                for r in rows
            ]
            emit(args, "\n".join(lines) + "\n")
            unnamed = sum(1 for r in rows if not r["name"])
            if unnamed:
                print(
                    f"Limit: {unnamed} import(s) without a name in Xenia's tables", file=sys.stderr
                )
        else:
            png = xex.title_image(info, img)
            target = (args.caller_cwd / args.output).resolve()
            target.write_bytes(xex.ico(png) if target.suffix.lower() == ".ico" else png)
            print(f"{target}", file=sys.stderr)
        return 0

    img = ppc.load(data, args.base)
    out = []
    if args.command == "pdata":
        entries = ppc.pdata(img)
        if not args.items:
            out.append("begin\tlength\tend")
            out += [f"{b:08X}\t0x{n:x}\t{b + n:08X}" for b, n in entries]
        for item in args.items:
            hit = ppc.containing(entries, number(item))
            out.append(
                f"{item}\t"
                + (
                    f"{hit[0]:08X}\t0x{hit[1]:x}\t{hit[0] + hit[1]:08X}"
                    if hit
                    else "no .pdata function"
                )
            )
    elif args.command == "callers":
        out += [
            f"{t:08X}\t{s:08X}\t{m}"
            for t, s, m in ppc.callers(img, [number(i) for i in args.items])
        ]
    elif args.command == "refs":
        for item in args.items:
            targets = [number(item)] if item.lower().startswith("0x") else ppc.strings_at(img, item)
            if not targets:
                out.append(f"{item!r}: not found")
            for target, lis, use in ppc.address_refs(img, targets):
                out.append(f"{item!r}\t{target:08X}\t{lis:08X}\t{use:08X}")
    elif args.command == "rtti":
        for item in args.items:
            found = ppc.rtti(img, item)
            out.append(json.dumps({"class": item, **(found or {"found": False})}, default=str))
    elif args.command == "helpers":
        for key, hits in ppc.helpers(img).items():
            out.append(f"{key} = " + ", ".join(f"0x{h:08X}" for h in hits))
    else:
        out += [
            f"{a:08X}  {raw}  {text}"
            for a, raw, text in ppc.disassemble(img, args.address, args.count)
        ]
    emit(args, "\n".join(out) + ("\n" if out else ""))
    return 0


def spa_command(args: argparse.Namespace) -> int:
    path = (args.caller_cwd / args.file).resolve()
    out = args.out
    if out is None:
        found, _ = spa.load(path)
        out = Path(f"spa-{found.title()['titleId'] or path.stem}")
    sdk = (args.caller_cwd / args.sdk).resolve() if args.sdk else None
    options = spa_out.Options((args.caller_cwd / out).resolve(), args.lang, args.game, sdk)
    return spa_out.run(path, options, args.format)


def open_game(path: Path) -> containers.Container:
    """A .zar by its footer, else a disc image by its XDVDFS volume descriptor."""
    if path.is_dir():
        raise ValueError(
            "a folder: an extracted game needs no reading; a Games on Demand package needs"
            " converting first (docs/XBOX360.md, step 1)"
        )
    return zar.ZarArchive(path) if zar.is_zar(path) else xdvdfs.XdvdfsImage(path)


def disc_extra(game: containers.Container) -> dict:
    """The executables, and default.xex's execution info: the title id names the game."""
    tree = game.tree()
    found: dict = {
        "executables": [
            e.path for e in tree.entries if e.path.lower().endswith((".xex", ".xexp", ".dll"))
        ]
    }
    entry = containers.find(tree, "default.xex")
    if entry is None:
        return found
    try:
        headers = xex.parse(b"".join(game.read(entry)))["headers"]
        found["default_xex"] = headers.get("EXECUTION_INFO", {"error": "no execution info"})
    except ValueError as exc:
        found["default_xex"] = {"error": str(exc)}
    return found


def disc(args: argparse.Namespace) -> int:
    game = open_game((args.caller_cwd / args.file).resolve())
    try:
        return containers.run(game, args, disc_extra(game) if args.action == "info" else None)
    finally:
        game.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="rea-suite xbox360",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="import and analyze an XEX or its PE image")
    a.add_argument("file", type=Path)
    for name in ("decomp", "xrefs", "functions"):
        q = sub.add_parser(name, help=f"{name} from an analyzed project (read-only)")
        q.add_argument("--program", help="program in the project (default: every program)")
        q.add_argument("-o", "--output", type=Path, help="write here instead of stdout")
        if name != "functions":
            q.add_argument("items", nargs="+", metavar="address" if name == "decomp" else "text")
    n = sub.add_parser("names", help="write a port's map of names and comments into the project")
    n.add_argument("--program", help="program in the project (needed when it holds several)")
    n.add_argument(
        "--from",
        dest="source",
        type=Path,
        required=True,
        help="the map: a TSV with address and name",
    )
    n.add_argument(
        "--where",
        action="append",
        default=[],
        metavar="COL=VALUE",
        help="only the rows with this value",
    )
    n.add_argument("-o", "--output", type=Path, help="write the per-entry report here")
    n.add_argument(
        "--functions",
        action="store_true",
        help="the map lists functions: create one where Ghidra has none and the code disassembles",
    )
    for parser in [a, n, *(sub.choices[c] for c in ("decomp", "xrefs", "functions"))]:
        parser.add_argument("--project", type=Path, required=True, help="Ghidra project folder")
        parser.add_argument("--name", help="project name (default: the folder's one .gpr)")
        parser.add_argument(
            "--timeout",
            type=int,
            help=f"seconds (default {ghidra_headless.TIMEOUT_SETTING},"
            f" else {ghidra_headless.DEFAULT_TIMEOUT_SECONDS})",
        )
        parser.add_argument("--plan", action="store_true", help="print the Ghidra command only")
    a.add_argument("--force", action="store_true", help="import again over the same program")
    sub.add_parser("check", help="XEXLoaderWV installed for this Ghidra, and loading")
    static_parsers(sub)
    s = sub.add_parser("spa", help="a title's achievements, strings, images and presence (SPA)")
    s.add_argument("file", type=Path, help="default.xex, an .spa or another XDBF file")
    s.add_argument("--out", type=Path, help="folder to write (default: spa-<title id>)")
    s.add_argument("--format", choices=sorted(spa_out.WRITERS), default="json")
    s.add_argument("--lang", default="en-US", help="the declarations' language (default en-US)")
    s.add_argument("--game", help="the declarations' game id (default: the title id)")
    s.add_argument("--sdk", type=Path, help=f"master-sdk checkout (default ${spa_out.SDK_ENV})")
    d = sub.add_parser("disc", help="a game's .zar or disc image: info, list, extract")
    containers.add_actions(d.add_subparsers(dest="action", required=True), "game")
    args = p.parse_args(argv)
    try:
        if args.command == "disc":
            return disc(args)
        if args.command == "spa":
            return spa_command(args)
        if args.command in STATIC:
            return static(args)
        install = ghidra_install()
        if args.command == "check":
            return check(install)
        if args.timeout is None:
            args.timeout = ghidra_headless.timeout_seconds()
        if args.timeout < 1:
            p.error("--timeout must be positive")
        if args.command == "analyze":
            return analyze(args, install)
        if args.command == "names":
            return names(args, install)
        return query(args, install)
    except (OSError, ValueError, struct.error, subprocess.SubprocessError) as exc:
        p.exit(1, f"xbox360: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
