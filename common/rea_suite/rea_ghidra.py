"""Headless Ghidra for one binary: analyze once, then query the project.

  rea-ghidra analyze   [options] <binary>             import + auto-analysis (once)
  rea-ghidra decomp    [options] <binary> <addr>...   decompile the functions containing the addresses
  rea-ghidra xrefs     [options] <binary> <text>...   decompile functions referencing strings with the text
  rea-ghidra functions [options] <binary>             TSV: entry, size, name, thunk, callers

  --project DIR  a Ghidra project folder of your own (a port's); default
                 work/ghidra/<binary name>/ (REA_GHIDRA_PROJECTS overrides work/ghidra)
  --name NAME    the project's name: default the folder's one .gpr, else the binary's name
  -o FILE        write the output there instead of stdout
  --force        analyze: run the auto-analysis again on the program in the project; its
                 names, types and comments stay (it is never imported again over them)
  --loader NAME  analyze: the Ghidra loader to import with (GameCubeLoader, ElfLoader, ...)
  --loader-KEY VALUE
                 analyze: an option of that loader, as analyzeHeadless takes it
                 (--loader GameCubeLoader --loader-autoloadMaps false for a GameCube DOL);
                 both are for the import only, never --force's analysis in place

The queries open the project read-only; with --project, <binary> may be the program's name
alone. Ghidra's logs go to <project>/logs/. Scripts: common/ghidra_scripts/.
Limits (common/rea_suite/ghidra_headless.py): REA_GHIDRA_IMPORT_TIMEOUT_SECONDS for a whole run,
REA_GHIDRA_MAXMEM for Ghidra's heap, and REA's REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS per decompiled
function (default in common/env.sh, yours in .env).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

from rea_suite import ghidra_headless

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "common" / "ghidra_scripts"
COMMANDS = ("analyze", "decomp", "xrefs", "functions")
QUERIES = {"decomp": "DecompileAt.java", "xrefs": "DecompileXrefs.java"}
# Kaiju types zero-filled variables after data as Alignment, which hangs the decompiler
REPAIR = ("-postScript", "ClearDataAlignment.java")


class Refused(Exception):
    pass


def usage() -> str:
    return __doc__.strip("\n") + "\n"


def parse(argv: list[str]) -> dict:
    """Options anywhere; after -- everything is an argument (a text that starts with -)."""
    opts = {"force": False, "project": None, "name": None, "output": None, "loader": None,
            "loader_options": [], "rest": []}  # fmt: skip
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == "--force":
            opts["force"] = True
        elif arg in ("--project", "--name", "-o", "--output"):
            key = {"-o": "output", "--output": "output"}.get(arg, arg[2:])
            if not args:
                raise Refused(f"{arg} needs a value")
            opts[key] = args.pop(0)
        elif arg.startswith("--loader"):
            if not args:
                raise Refused(f"{arg} needs a value")
            if arg == "--loader":
                opts["loader"] = args.pop(0)
            elif arg.startswith("--loader-") and len(arg) > len("--loader-"):
                opts["loader_options"].append((arg[len("--loader-") :], args.pop(0)))
            else:
                raise Refused(f"unknown option: {arg}")
        elif arg == "--":
            opts["rest"] += args
            break
        elif arg.startswith("-") and len(arg) > 1:
            raise Refused(f"unknown option: {arg} (put -- before a text that starts with -)")
        else:
            opts["rest"].append(arg)
    return opts


class Session:
    def __init__(self, opts: dict, cwd: Path, runner: ghidra_headless.Headless) -> None:
        self.cwd = cwd
        self.runner = runner
        self.force = opts["force"]
        self.loader = opts["loader"]
        self.loader_options = opts["loader_options"]
        self.output = opts["output"]
        self.binary = opts["rest"][0]
        self.items = opts["rest"][1:]
        self.program = Path(self.binary).name
        name = opts["name"]
        if opts["project"]:
            project = (cwd / opts["project"]).resolve()
            ghidra_headless.check_project(project)
            project.mkdir(parents=True, exist_ok=True)
            if not name:
                gprs = sorted(project.glob("*.gpr"))
                if len(gprs) > 1:
                    raise Refused(f"{project} holds several projects; pass --name")
                name = gprs[0].stem if gprs else None
        else:
            projects = os.environ.get("REA_GHIDRA_PROJECTS") or str(ROOT / "work" / "ghidra")
            project = Path(projects) / self.program
        self.project = project
        self.name = name or self.program
        ghidra_headless.check_project(self.project)
        (self.project / "logs").mkdir(parents=True, exist_ok=True)

    def command(self, *arguments: str) -> list[str]:
        return self.runner.command(self.project, self.name, *arguments)

    def imported(self) -> bool:
        """The program is in the project's index (read without Ghidra)."""
        index = self.project / f"{self.name}.rep" / "idata" / "~index.dat"
        try:
            return f":{self.program}:" in index.read_text(errors="replace")
        except OSError:
            return False

    def analyze(self) -> None:
        log = self.project / "logs" / "analyze.log"
        repair = ("-scriptPath", str(SCRIPTS), *REPAIR)
        if self.imported():
            if not self.force:
                return
            print(f"rea-ghidra: analyzing {self.program} again, its names kept (log: {log})",
                  file=sys.stderr)  # fmt: skip
            command = self.command("-process", self.program, *repair)
        else:
            binary = self.cwd / self.binary
            if not binary.is_file():
                raise Refused(
                    f"no such file: {self.binary} (and no program {self.program} in {self.project})"
                )
            print(f"rea-ghidra: analyzing {self.program} (once; log: {log})", file=sys.stderr)
            arguments = ghidra_headless.import_arguments(
                binary.resolve(), self.loader, self.loader_options
            )
            command = self.command(*arguments, *repair)
        try:
            self.runner.run(command, log)
        except ghidra_headless.GhidraError as exc:
            raise Refused(f"analysis failed: {exc}") from exc

    def query(self, script: str, *arguments: str) -> None:
        self.analyze()
        log = self.project / "logs" / f"{Path(script).stem}.log"
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.txt"
            command = self.command(
                "-process", self.program, "-noanalysis", "-readOnly",
                "-scriptPath", str(SCRIPTS), "-postScript", script, str(out), *arguments,
            )  # fmt: skip
            try:
                self.runner.run(command, log)
            except ghidra_headless.GhidraError as exc:
                raise Refused(f"{script} failed: {exc}") from exc
            if not out.is_file():
                raise Refused(f"{script} wrote nothing; see {log}")
            if self.output:
                target = self.cwd / self.output
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(out, target)
            else:
                with out.open("rb") as stream:
                    sys.stdout.flush()
                    shutil.copyfileobj(stream, sys.stdout.buffer)


def main(argv: list[str] | None = None, runner: ghidra_headless.Headless | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cwd = Path.cwd()
    if argv[:1] == ["--caller-cwd"] and len(argv) > 1:
        cwd = Path(argv[1])
        argv = argv[2:]
    if not argv or argv[0] in ("-h", "--help"):
        sys.stdout.write(usage())
        return 0
    command, argv = argv[0], argv[1:]
    if command not in COMMANDS:
        sys.stderr.write(usage())
        return 2
    try:
        opts = parse(argv)
        if not opts["rest"]:
            raise Refused("missing <binary>")
        if runner is None:
            install = ghidra_headless.install_dir()
            runner = ghidra_headless.AnalyzeHeadless(install)
            if not runner.executable.is_file():
                raise Refused("Ghidra missing; run rea-suite setup")
        if opts["force"] and command != "analyze":
            raise Refused("--force is for analyze")
        if (opts["loader"] or opts["loader_options"]) and command != "analyze":
            raise Refused("--loader and its options are for analyze")
        session = Session(opts, cwd, runner)
        if command == "analyze":
            session.analyze()
        elif command == "functions":
            session.query("ExportFunctions.java")
        else:
            if not session.items:
                raise Refused(f"{command} needs {'addresses' if command == 'decomp' else 'texts'}")
            session.query(QUERIES[command], *session.items)
    except (Refused, ghidra_headless.GhidraError) as exc:
        print(f"rea-ghidra: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
