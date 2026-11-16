"""Prepare PS1/PS2 images, extracted trees, or executables for static analysis."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path, PurePosixPath

from rea_suite import bounded, ghidra_headless
from rea_suite.archive import seven_zip

# ELF type of an IOP module (IRX): an SCE-specific relocatable, R3000 code for the IOP.
IRX_TYPE = 0xFF80
# ELF type of an EE relocatable module (ERX, Sony's liberx): R5900 code loaded at run time
# (Emotion Engine: Reloaded's ET_ERX2).
ERX_TYPE = 0xFF91
LANGUAGES = {"ps1-exe": "PSX:LE:32:default", "ps2-ee": "r5900:LE:32:default"}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def executable(path: Path) -> dict | None:
    with path.open("rb") as stream:
        head = stream.read(64)
    if head.startswith(b"PS-X EXE") and len(head) == 64:
        entry, gp, load, size = struct.unpack_from("<4I", head, 0x10)
        return {
            "kind": "ps1-exe",
            "entry": hex(entry),
            "gp": hex(gp),
            "load": hex(load),
            "payload_size": size,
            "payload_offset": 2048,
        }
    if head.startswith(b"\x7fELF\x01\x01") and len(head) >= 52:
        elf_type, machine = struct.unpack_from("<HH", head, 16)
        if machine == 8:
            flags = struct.unpack_from("<I", head, 36)[0]
            if elf_type == IRX_TYPE:
                kind = "ps2-irx"
            elif elf_type == ERX_TYPE:
                kind = "ps2-erx"
            else:
                kind = "ps2-ee" if flags & 0x00FF0000 == 0x00920000 else "mips-elf"
            return {
                "kind": kind,
                "entry": hex(struct.unpack_from("<I", head, 24)[0]),
                "flags": hex(flags),
            }
    return None


def files(root: Path, limit: int) -> list[Path]:
    if root.is_file():
        return [root]
    found = []
    for current, dirs, names in os.walk(root, followlinks=False):
        if any((Path(current) / d).is_symlink() for d in dirs):
            raise ValueError(f"symlink directory in extracted tree: {current}")
        dirs.sort()
        for name in sorted(names):
            p = Path(current) / name
            if p.is_symlink():
                raise ValueError(f"symlink in extracted tree: {p}")
            found.append(p)
            if len(found) > limit:
                raise ValueError(f"more than {limit} files; increase --max-files")
    return found


def boot_path(value: str) -> str:
    value = re.sub(r"^cdrom\d*:\\?", "", value.strip().strip('"'), flags=re.IGNORECASE)
    value = value.replace("\\", "/").lstrip("/")
    parts = PurePosixPath(value).parts
    if not parts or any(p in ("..", ".") or ":" in p for p in parts):
        raise ValueError(f"unsafe boot path: {value}")
    return "/".join(parts).split(";")[0].casefold()


def inventory(root: Path, limit: int, override: str | None = None) -> dict:
    items = files(root, limit)
    base = root if root.is_dir() else root.parent
    by_name = {}
    rows, programs = [], []
    for path in items:
        relative = path.relative_to(base).as_posix()
        key = relative.split(";")[0].casefold()
        if key in by_name:
            raise ValueError(f"ambiguous case/version-normalized path: {relative}")
        by_name[key] = path
        rows.append({"path": relative, "size": path.stat().st_size})
        info = executable(path)
        if info:
            programs.append(dict(path=relative, sha256=digest(path), **info))
    cnf = by_name.get("system.cnf")
    requested, system = override, None
    if cnf:
        with cnf.open("r", encoding="ascii", errors="replace") as stream:
            text = stream.read(65536)
        match = re.search(r"^\s*(BOOT2?)\s*=\s*(.+?)\s*$", text, re.MULTILINE | re.IGNORECASE)
        if match:
            system = "ps2" if match[1].upper() == "BOOT2" else "ps1"
            requested = requested or match[2]
    if requested:
        target = by_name.get(boot_path(requested))
        boot = target.relative_to(base).as_posix() if target else None
    else:
        boot = programs[0]["path"] if len(programs) == 1 else None
    program = next((p for p in programs if p["path"] == boot), None)
    if not system and program:
        system = {"ps1-exe": "ps1", "ps2-ee": "ps2"}.get(program["kind"])
    return {
        "root": str(root),
        "system": system,
        "boot": boot,
        "boot_request": requested,
        "boot_executable": program,
        "executables": programs,
        "files": rows,
    }


def overlay_spec(value: str) -> tuple[str, int | None]:
    """`PATH[@ADDRESS]`: a file of the disc (as --boot names one) and its hex load address."""
    path, _, address = value.rpartition("@") if "@" in value else (value, "", "")
    if not path:
        raise ValueError(f"overlay {value!r}: expected PATH[@ADDRESS]")
    if not address:
        return path, None
    try:
        number = int(address, 16)
    except ValueError:
        raise ValueError(f"overlay {value!r}: {address!r} is no hex address") from None
    if not 0 <= number <= 0xFFFFFFFF:
        raise ValueError(f"overlay {value!r}: the address is outside 32 bits")
    return path, number


def block_name(path: str, taken: set[str]) -> str:
    """An overlay space's name: the file's, with what Ghidra refuses in one replaced."""
    base = "ovl_" + re.sub(r"[^A-Za-z0-9_]", "_", PurePosixPath(path).name)
    name, n = base, 1
    while name in taken:
        n += 1
        name = f"{base}_{n}"
    taken.add(name)
    return name


def overlays(state: dict, specs: list[str]) -> list[dict]:
    """How each requested overlay is imported. Code that runs on the boot program's CPU over its
    memory (a PS1 overlay, a raw PS2 one, a PS-X EXE loaded later) becomes an overlay block in the
    boot program, where its calls into the program resolve; an IOP module (IRX, the IOP's R3000)
    or an EE module or program in an ELF of its own is a program of its own in the project's
    `overlays/` folder, at the given base for a relocatable one."""
    root = Path(state["root"])
    if not root.is_dir():
        raise ValueError("--overlay needs a disc or an extracted tree, not a lone executable")
    boot = state["boot_executable"]
    by_name = {row["path"].split(";")[0].casefold(): row["path"] for row in state["files"]}
    plan, taken = [], set()
    for spec in specs:
        request, address = overlay_spec(spec)
        relative = by_name.get(boot_path(request))
        if not relative:
            raise ValueError(f"overlay {request!r} is not on the disc")
        if relative == boot["path"]:
            raise ValueError(f"overlay {request!r} is the boot program")
        path = root / relative
        info = executable(path) or {"kind": "raw"}
        kind, row = info["kind"], {"path": relative, "kind": info["kind"], "sha256": digest(path)}
        if kind in ("raw", "ps1-exe"):
            if boot["kind"] != "ps1-exe" and kind == "ps1-exe":
                raise ValueError(f"overlay {relative}: a PS-X EXE beside a PS2 program")
            if kind == "ps1-exe":
                load, offset, length = int(info["load"], 16), 2048, info["payload_size"]
                if address is not None and address != load:
                    raise ValueError(
                        f"overlay {relative}: its PS-X EXE header loads it at {load:#x}, not "
                        f"{address:#x}"
                    )
                entry = int(info["entry"], 16)
            else:
                if address is None:
                    raise ValueError(f"overlay {relative}: a raw file needs @ADDRESS")
                load, offset, length, entry = address, 0, path.stat().st_size, address
            if length < 1 or offset + length > path.stat().st_size:
                raise ValueError(f"overlay {relative}: {length} bytes at {offset} are not there")
            row |= {"import": "block", "block": block_name(relative, taken), "address": hex(load),
                    "offset": offset, "length": length, "entry": hex(entry)}  # fmt: skip
        elif kind in ("ps2-irx", "ps2-erx", "ps2-ee"):
            if boot["kind"] != "ps2-ee":
                raise ValueError(f"overlay {relative}: a PS2 module beside a PS1 program")
            if kind == "ps2-ee" and address is not None:
                raise ValueError(f"overlay {relative}: an EE executable loads at its own address")
            language = "MIPS:LE:32:default" if kind == "ps2-irx" else LANGUAGES["ps2-ee"]
            folder = PurePosixPath("overlays", relative).parent.as_posix()
            row |= {"import": "program", "language": language, "folder": folder,
                    "address": hex(address) if address is not None else None}  # fmt: skip
        else:
            raise ValueError(f"overlay {relative}: a {kind} is not one this command imports")
        plan.append(row)
    return plan


def image_kind(source: Path) -> str:
    if source.suffix.lower() == ".cue":
        return "cd"
    if source.suffix.lower() == ".chd":
        raise ValueError("convert CHD with chdman first; see docs/PLAYSTATION.md")
    with source.open("rb") as stream:
        for sector, offset, kind in [(2352, 24, "cd"), (2352, 16, "cd"), (2048, 0, "iso")]:
            stream.seek(16 * sector + offset)
            if stream.read(7).startswith(b"\x01CD001\x01"):
                return kind
    raise ValueError("unsupported image: expected ISO9660 ISO or 2352-byte CD BIN/CUE")


def image_sources(source: Path) -> list[Path]:
    source = source.resolve()
    result = [source]
    if source.suffix.lower() == ".cue":
        text = source.read_text(encoding="utf-8-sig", errors="replace")
        for match in re.finditer(
            r'^\s*FILE\s+(?:"([^"]+)"|(\S+))\s+\S+', text, re.MULTILINE | re.IGNORECASE
        ):
            name = (match[1] or match[2]).replace("\\", "/")
            track = (source.parent / name).resolve()
            if not track.is_relative_to(source.parent) or not track.is_file():
                raise ValueError(f"CUE track must exist inside the image directory: {name}")
            if track not in result:
                result.append(track)
        if len(result) == 1:
            raise ValueError("CUE has no FILE entries")
    return result


def extraction(source: Path, project: Path, kind: str) -> list[str]:
    if kind == "cd":
        tool = shutil.which("dumpsxiso")
        command = [
            tool or "dumpsxiso",
            str(source),
            "-x",
            str(project / "disc"),
            "-s",
            str(project / "disc.xml"),
            "-l",
        ]
    else:
        tool = seven_zip()
        command = [tool or "7z", "x", str(source), f"-o{project / 'disc'}", "-y"]
    return command


def run(command: list[str], project: Path, log, timeout: int) -> None:
    """Bound owned tool processes, including their children on timeout or interruption."""
    bounded.run(command, project, log, timeout)


def import_overlay(runner, project: Path, root: Path, o: dict, timeout: int) -> None:
    """A module or program of its own, into the project's overlays/ folder, with its functions."""
    out = project / "analysis/overlays" / (o["path"].replace("/", "_") + ".tsv")
    out.parent.mkdir(parents=True, exist_ok=True)
    log = project / "logs" / f"ghidra-overlay-{o['path'].replace('/', '_')}.log"
    options = [("imagebase", o["address"])] if o["address"] else []
    command = runner.command(
        project / "ghidra",
        f"playstation/{o['folder']}",
        *ghidra_headless.import_arguments(root / o["path"], "ElfLoader", options),
        "-processor", o["language"], "-cspec", "default",
        "-analysisTimeoutPerFile", str(timeout),
        "-scriptPath", str(Path(__file__).resolve().parents[1] / "ghidra_scripts"),
        "-preScript", "ConfigureConsole.java",
        "-postScript", "ExportFunctions.java", str(out),
    )  # fmt: skip
    o["ghidra_command"] = command
    runner.run(command, log, timeout + 120)
    if not out.is_file():
        raise ValueError(f"Ghidra did not import overlay {o['path']}; inspect {log}")
    o["functions"] = str(out.relative_to(project))


def prepare(args: argparse.Namespace) -> dict:
    specs = getattr(args, "overlay", None) or []
    if specs and not args.ghidra:
        raise ValueError("--overlay imports into the Ghidra project; add --ghidra")
    for spec in specs:
        overlay_spec(spec)
    source = (args.caller_cwd / args.input).resolve()
    project = (args.caller_cwd / args.project).resolve()
    if not source.exists():
        raise ValueError(f"input does not exist: {source}")
    if project.exists():
        raise ValueError("project already exists; choose a new --project path")
    if project == source or (source.is_dir() and project.is_relative_to(source)):
        raise ValueError("project must be outside the input tree")
    direct = source.is_dir() or executable(source) is not None
    kind = None if direct else image_kind(source)
    sources = [source] if direct else image_sources(source)
    command = extraction(source, project, kind) if kind else None
    if args.plan:
        return {
            "input": str(source),
            "project": str(project),
            "extraction": command,
            "ghidra_requested": args.ghidra,
            "overlays_requested": specs,
            "writes": False,
        }
    if command and not (Path(command[0]).is_file() or shutil.which(command[0])):
        hint = "select playstation" if kind == "cd" else "7-Zip is part of the base suite"
        raise ValueError(f"{command[0]} missing; {hint} and run rea-suite setup")
    project.mkdir(parents=True)
    for name in ("logs", "notes", "patches", "analysis", "ghidra"):
        (project / name).mkdir()
    state = {
        "format": "rea-suite-playstation",
        "version": 1,
        "status": "incomplete",
        "input": str(source),
        "sources": [],
        "extraction": command,
    }
    manifest = project / "project.json"
    try:
        state["sources"] = [{"path": str(p), "sha256": digest(p)} for p in sources if p.is_file()]
        if command:
            with (project / "logs/extract.log").open("w") as log:
                run(command, project, log, args.timeout)
        state.update(inventory(project / "disc" if command else source, args.max_files, args.boot))
        boot = state["boot_executable"]
        if args.ghidra:
            if not boot:
                raise ValueError("no supported boot executable; inspect inventory or supply --boot")
            language = LANGUAGES.get(boot["kind"])
            if not language:
                raise ValueError(
                    "boot ELF is not identified as R5900; import IOP/modules separately"
                )
            runner = ghidra_headless.headless()
            root = Path(state["root"])
            target = root / boot["path"] if root.is_dir() else root
            extra = state["overlays"] = overlays(state, specs) if specs else []
            blocks = []
            for o in (o for o in extra if o["import"] == "block"):
                blocks += ["-preScript", "AddOverlay.java", str(root / o["path"]), str(o["offset"]),
                           str(o["length"]), o["address"], o["block"], o["entry"]]  # fmt: skip
            ghidra = runner.command(
                project / "ghidra",
                "playstation",
                "-import",
                str(target),
                "-loader",
                "PsxLoader" if boot["kind"] == "ps1-exe" else "ElfLoader",
                "-processor",
                language,
                "-cspec",
                "default",
                "-analysisTimeoutPerFile",
                str(args.timeout),
                "-scriptPath",
                str(Path(__file__).resolve().parents[1] / "ghidra_scripts"),
                "-preScript",
                "ConfigureConsole.java",
                *blocks,
                "-postScript",
                "ExportFunctions.java",
                str(project / "analysis/functions.tsv"),
                "-postScript",
                "DecompileAt.java",
                str(project / "analysis/entry.c"),
                boot["entry"],
            )
            state["ghidra_command"] = ghidra
            runner.run(ghidra, project / "logs/ghidra.log", args.timeout + 120)
            database = project / "ghidra/playstation.gpr"
            if not database.is_file():
                raise ValueError("Ghidra produced no project; inspect logs/ghidra.log")
            state["ghidra_project"] = str(database)
            log_text = (project / "logs/ghidra.log").read_text(errors="replace")
            errors = [line.strip() for line in log_text.splitlines() if line.startswith("ERROR")]
            if "Using Loader: Raw Binary" in log_text:
                raise ValueError("Ghidra used Raw Binary instead of the console loader")
            state["ghidra_analysis_errors"] = errors
            if errors:
                state["warnings"] = [
                    "Ghidra logged analyzer/script errors; inspect logs/ghidra.log"
                ]
            for output in ("analysis/functions.tsv", "analysis/entry.c"):
                if not (project / output).is_file():
                    raise ValueError(f"Ghidra did not produce {output}; inspect logs/ghidra.log")

            for o in (o for o in extra if o["import"] == "program"):
                import_overlay(runner, project, root, o, args.timeout)

            entry_text = (project / "analysis/entry.c").read_text(errors="replace")
            if "no function" in entry_text or "decompile failed" in entry_text:
                state.setdefault("warnings", []).append(
                    "Entrypoint pseudocode unavailable; inspect assembly"
                )
        state["status"] = "prepared"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        state["error"] = str(exc)
        raise
    finally:
        manifest.write_text(json.dumps(state, indent=2) + "\n")
    return state


# Tools of their own under `rea-suite playstation <name>`: their modules, loaded when asked for.
TOOLS = {"drive": "psx_drive"}


def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    at = 2 if argv[:1] == ["--caller-cwd"] else 0  # bin/rea-suite puts it first
    if len(argv) > at and argv[at] in TOOLS:
        tool = argv.pop(at)
        return importlib.import_module(f"rea_suite.{TOOLS[tool]}").main(argv)
    p = argparse.ArgumentParser(
        description=__doc__
        + " Also: playstation drive (a PSXRecomp game driven from a script), with --help."
    )
    p.add_argument(
        "input", type=Path, help="ISO, BIN/CUE, extracted directory, PS-X EXE or MIPS ELF"
    )
    p.add_argument("--project", type=Path, required=True, help="new project directory")
    p.add_argument("--boot", help="boot path relative to extracted root; overrides SYSTEM.CNF")
    p.add_argument(
        "--ghidra", action="store_true", help="also import boot into an editable Ghidra project"
    )
    p.add_argument(
        "--plan", action="store_true", help="show extraction command; no writes or tools run"
    )
    p.add_argument(
        "--overlay",
        action="append",
        metavar="PATH[@ADDRESS]",
        help="with --ghidra, also import this disc file: a PS1 or raw overlay as an overlay block "
        "in the boot program at ADDRESS (a PS-X EXE at its header's), an IRX/ERX as a program "
        "of its own (ADDRESS its base); repeatable",
    )
    p.add_argument("--max-files", type=int, default=100000)
    p.add_argument(
        "--timeout", type=int, default=600, help="extraction and Ghidra analysis timeout in seconds"
    )
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    if min(args.max_files, args.timeout) < 1:
        p.error("limits must be positive")
    try:
        result = prepare(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        p.exit(1, f"playstation: {exc}\n")
    if args.plan:
        print(json.dumps(result, indent=2))
    else:
        print(f"Project: {(args.caller_cwd / args.project).resolve()}")
        print(f"System: {result['system'] or 'unknown'}; boot: {result['boot'] or 'not resolved'}")
        print(f"Files: {len(result['files'])}; executables: {len(result['executables'])}")
        print("Inventory: project.json; extraction/import logs: logs/")
        for warning in result.get("warnings", []):
            print(f"Warning: {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
