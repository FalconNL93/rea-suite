"""Offline analysis projects, driven by the same REA CLI an agent uses.

One entry point: rea-suite analyze --examples. Inputs are never executed or patched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REA = ["node", str(ROOT / "node_modules/rea-agents/scripts/rea.mjs")]
IGNORED = {".git", ".venv", "node_modules", ".runtime", "__pycache__"}
EXAMPLES = """rea-suite analyze: local analysis without an AI service

  # Several files and directories, including subdirectories:
  rea-suite analyze ./game.exe ./plugins ./other-game --project ./research --plan
  rea-suite analyze ./game.exe ./plugins --project ./research

  # Fast metadata and strings, without native auto-analysis:
  rea-suite analyze ./game.exe --project ./research --preset triage

  # Follow a literal string or function name through native code:
  rea-suite analyze --project ./research --query ServerList --select game.exe
  rea-suite analyze --project ./research --function 0x401230 --select game.exe

  # Export pseudocode, up to 200 functions per native image (configurable):
  rea-suite analyze ./game.exe --project ./research --preset decompile --max-functions 200

  # Search saved reports and generated code; no analysis engine is started:
  rea-suite analyze --project ./research --search connect
  rea-suite analyze --project ./research --list

  # An extracted JavaScript/Electron application, rather than a directory of binaries:
  rea-suite analyze ./extracted-app --kind javascript --project ./app-research

Repeat an input to resume verified successful steps. Add more inputs to extend a project.
--refresh reruns selected steps. Original tool JSON, diagnostics and exit codes are retained.
Queries are literal selectors, not natural-language prompts. Native results are reconstructed
pseudocode and static references: review calling conventions, instruction boundaries, register
use and runtime behavior before implementing a hook or patch in your IDE.
"""


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def triage(path: Path) -> dict:
    """Bounded literal strings with original file offsets, before any engine runs."""
    with path.open("rb") as stream:
        data = stream.read(8 * 1024 * 1024)
    strings = []
    for encoding, pattern in [("ascii", rb"[ -~]{5,}"), ("utf-16le", rb"(?:[ -~]\x00){5,}")]:
        for match in re.finditer(pattern, data):
            value = match.group().decode(encoding)
            strings.append(
                {
                    "file_offset": hex(match.start()),
                    "encoding": encoding,
                    "value": value[:2000],
                    "value_truncated": len(value) > 2000,
                }
            )
            if len(strings) >= 5000:
                break
        if len(strings) >= 5000:
            break
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "strings": strings,
        "coverage": {
            "examined_bytes": len(data),
            "file_bytes": path.stat().st_size,
            "string_limit_reached": len(strings) >= 5000,
            "limitations": "Literal ASCII/ASCII-range UTF-16LE only; no string deobfuscation.",
        },
    }


def save(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")
    temporary.replace(path)


def detect(path: Path) -> str | None:
    if path.is_dir():
        return None
    with path.open("rb") as stream:
        head = stream.read(4096)
    if head.startswith(b"\x7fELF") or head[:4] in {
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xfe\xed\xfa\xce",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }:
        # Java class files share one universal Mach-O magic.
        return "android" if path.suffix.lower() == ".class" else "native"
    if head.startswith(b"MZ"):
        import pefile

        try:
            pe = pefile.PE(str(path), fast_load=True)
            try:
                directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                cli = directories[14] if len(directories) > 14 else None
                return "managed" if cli and cli.VirtualAddress and cli.Size else "native"
            finally:
                pe.close()
        except pefile.PEFormatError:
            return None
    if head.startswith(b"dex\n") or (
        head.startswith(b"PK") and path.suffix.lower() in {".apk", ".jar", ".aab", ".aar"}
    ):
        return "android"
    if path.suffix.lower() == ".asar":
        return "javascript"
    return None


def discover(
    inputs: list[Path], project: Path, kind: str, max_files: int
) -> list[tuple[Path, str]]:
    found: dict[Path, str] = {}
    examined = 0
    for source in inputs:
        if not source.exists():
            raise ValueError(f"input does not exist: {source}")
        if source == project or source.is_relative_to(project):
            raise ValueError(f"input is inside the output project: {source}")
        if kind == "javascript" and source.is_dir():
            if project.is_relative_to(source):
                raise ValueError("JavaScript application output must be outside the input tree")
            found[source] = kind
            continue
        candidates = [source]
        if source.is_dir():
            candidates = []
            for directory, directories, files in os.walk(source, followlinks=False):
                directories[:] = sorted(
                    d
                    for d in directories
                    if d not in IGNORED
                    and not (Path(directory) / d).is_symlink()
                    and not (Path(directory) / d).resolve().is_relative_to(project)
                )
                for name in sorted(files):
                    path = Path(directory) / name
                    if not path.is_symlink() and path.is_file():
                        examined += 1
                        if examined > max_files:
                            raise ValueError(f"directory scan exceeds --max-files {max_files}")
                        candidates.append(path)
        for path in candidates:
            if not path.is_file():
                continue
            selected = kind if kind != "auto" else detect(path)
            if selected:
                found[path.resolve()] = selected
                if len(found) > max_files:
                    raise ValueError(f"selection exceeds --max-files {max_files}")
    return sorted(found.items())


def fingerprint(command: list[str]) -> dict:
    executable = shutil.which(command[0])
    package = ROOT / "node_modules/rea-agents/package.json"
    executable_path = Path(executable).resolve() if executable else None
    return {
        "rea": digest(package),
        "suite": digest(Path(__file__)),
        "tools": digest(ROOT / "tools/state.json")
        if (ROOT / "tools/state.json").exists()
        else None,
        "python_lock": digest(ROOT / "uv.lock"),
        "node_lock": digest(ROOT / "package-lock.json"),
        "engines": {
            name: {"path": str(path.resolve()), "mtime": path.stat().st_mtime_ns}
            for name in ("GHIDRA_INSTALL_DIR", "JAVA_HOME", "REA_KUNA_COMMAND")
            if (value := os.environ.get(name)) and (path := Path(value)).exists()
        },
        "executable": str(executable_path),
        "executable_mtime": executable_path.stat().st_mtime_ns if executable_path else None,
        "environment": {
            k: v
            for k, v in os.environ.items()
            if k.startswith("REA_") or k in {"JAVA_HOME", "GHIDRA_INSTALL_DIR"}
        },
    }


def steps(
    path: Path, kind: str, args: argparse.Namespace, out: Path
) -> list[tuple[str, list[str]]]:
    base = [str(path)]
    result = []
    if kind == "native":
        provider = ["--provider", args.provider, "--snapshot", str(out / "snapshot.json")]
        if args.preset == "triage":
            with path.open("rb") as stream:
                header = stream.read(4)
            pe = header[:2] == b"MZ"
            operation = "inspect-native-exports" if pe or header == b"\x7fELF" else "inspect-macho"
            result.append(("metadata", REA + [operation, *base, "--json"]))
            if pe:
                result.append(("imports", REA + ["inspect-pe-imports", *base, "--json"]))
        else:
            result.append(("overview", REA + ["analyze", *base, *provider, "--json"]))
        for query in args.query:
            result.append(
                ("trace", REA + ["trace", *base, f"--query={query}", *provider, "--json"])
            )
        for function in args.function:
            result.append(
                (
                    "function",
                    REA + ["function", *base, f"--procedure={function}", *provider, "--json"],
                )
            )
        if args.preset == "decompile":
            export_key = hashlib.sha256(
                json.dumps(fingerprint(REA), sort_keys=True).encode()
            ).hexdigest()[:12]
            export = out / "code" / f"{args.provider}-{export_key}"
            result.append(
                (
                    "decompile",
                    REA
                    + [
                        "decompile-all",
                        *base,
                        "--provider",
                        args.provider,
                        "--output",
                        str(export),
                        *(["--resume"] if export.exists() else []),
                        "--limit",
                        str(args.max_functions),
                        "--json",
                    ],
                )
            )
    elif kind == "managed":
        result.append(("metadata", REA + ["inspect-managed-members", *base, "--json"]))
        if args.preset == "decompile":
            result.append(
                (
                    "decompile",
                    ["ilspycmd", "-p", "-o", str(out / "code" / f"ilspy-{time.time_ns()}"), *base],
                )
            )
    elif kind == "android":
        result.append(("metadata", REA + ["inspect-artifact", *base, "--json"]))
        if args.preset == "decompile":
            result.append(
                ("decompile", ["jadx", "-d", str(out / "code" / f"jadx-{time.time_ns()}"), *base])
            )
    elif kind == "javascript":
        result.append(("javascript", REA + ["analyze-javascript-application", *base, "--json"]))
    for tool in args.extra:
        if kind == "native":
            command = {"capa": ["capa", "-j"], "floss": ["floss", "-j"]}[tool]
            result.append((tool, command + base))
    return result


def run_step(
    label: str, command: list[str], out: Path, state: dict, refresh: bool, cacheable: bool
) -> bool:
    signature = hashlib.sha256(
        json.dumps([command, fingerprint(command)], sort_keys=True).encode()
    ).hexdigest()
    previous = state.get(signature)
    if not refresh and cacheable and previous and previous["exit_code"] == 0:
        report = out / previous["output"]
        if report.is_file() and digest(report) == previous["output_sha256"]:
            print(f"  reuse {label}: {report}", flush=True)
            for line in previous.get("summary", []):
                print(f"  {line}")
            if label == "function":
                function_views(report)
            return True
    # Every attempt has its own files; a failed retry never replaces a successful report.
    number = 1
    while (out / f"{label}-{signature[:12]}-{number}.json").exists():
        number += 1
    report = out / f"{label}-{signature[:12]}-{number}.json"
    stderr = report.with_suffix(".stderr")
    print(f"  run   {label}", flush=True)
    with report.open("wb") as output, stderr.open("wb") as errors:
        try:
            process = subprocess.run(command, stdout=output, stderr=errors, check=False)
            code = process.returncode
        except OSError as error:
            errors.write(str(error).encode())
            code = 127
    state[signature] = {
        "step": label,
        "command": command,
        "exit_code": code,
        "output": report.name,
        "stderr": stderr.name,
        "output_sha256": digest(report),
    }
    if code == 0 and command[:2] == REA[:2] and report.stat().st_size <= 32 * 1024 * 1024:
        # A producer error is never a successful stage, even with an incorrect exit status.
        try:
            value = json.loads(report.read_text())
            if isinstance(value, dict) and (
                value.get("ok") is False or ("code" in value and "category" in value)
            ):
                code = state[signature]["exit_code"] = 1
            if isinstance(value, dict):
                normalized = value.get("normalized_result", {})
                if isinstance(normalized, dict) and "counts" in normalized:
                    state[signature]["counts"] = normalized["counts"]
                if isinstance(normalized, dict) and label in {"trace", "function"}:
                    summary = summarize(normalized)
                    state[signature]["summary"] = summary
                    for line in summary:
                        print(f"  {line}")
        except (ValueError, UnicodeError):
            code = state[signature]["exit_code"] = 1
    if code:
        print(f"  FAIL {label}: exit {code}; see {report} and {stderr}", file=sys.stderr)
    elif label == "function":
        function_views(report)
    return code == 0


def summarize(value: dict) -> list[str]:
    """Show source-bound locations, never guessed behavior or hook suitability."""
    lines = []
    procedure = value.get("procedure")
    if isinstance(procedure, dict):
        lines.append(f"function {procedure.get('name')} @ {procedure.get('address')}")
        for direction in ("callers", "callees"):
            rows = value.get(direction)
            for item in rows[:5] if isinstance(rows, list) else []:
                if not isinstance(item, dict):
                    continue
                lines.append(f"{direction}: {item.get('name')} @ {item.get('address')}")
    for match in value.get("matches", [])[:8]:
        if isinstance(match, dict) and "address" in match:
            text = str(match.get("value", match.get("name", "")))[:160]
            lines.append(f"match {text!r} @ {match['address']}")
    seen = set()
    for reference in value.get("references", []):
        containing = reference.get("containing_procedure", {})
        function = containing.get("procedure", {}) if isinstance(containing, dict) else {}
        address = function.get("address")
        if address and address not in seen:
            seen.add(address)
            lines.append(f"referring function {function.get('name')} @ {address}")
        if len(seen) >= 8:
            break
    if value.get("truncated"):
        lines.append("partial results: the engine reported truncation")
    return lines


def function_views(report: Path) -> None:
    """Expose engine pseudocode and assembly beside the original dossier Evidence."""
    if report.stat().st_size > 32 * 1024 * 1024:
        return
    value = json.loads(report.read_text())
    if isinstance(value, dict) and "data" in value:
        value = value["data"]
    dossier = value.get("normalized_result", {}) if isinstance(value, dict) else {}
    if not isinstance(dossier, dict):
        return
    pseudocode = dossier.get("pseudocode")
    if isinstance(pseudocode, str):
        code = report.with_suffix(".c")
        if not code.exists():
            code.write_text(f"// Reconstructed pseudocode; Evidence: {report.name}\n{pseudocode}\n")
        print(f"  code  {code}")
    assembly = dossier.get("assembly")
    assembly_path = report.with_suffix(".asm")
    if (
        isinstance(assembly, list)
        and all(isinstance(line, str) for line in assembly)
        and not assembly_path.exists()
    ):
        assembly_path.write_text("\n".join(assembly) + "\n")


@contextmanager
def locked(project: Path):
    lock = project / ".analysis.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError(f"project is locked: {lock}; check for a running analysis first") from None
    try:
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        yield
    finally:
        lock.unlink()


def report_project(project: Path, state: dict) -> None:
    lines = [
        "# Analysis project",
        "",
        "Static observations and reconstructed code; not verified runtime behavior.",
        "Native addresses are analysis addresses, not automatically patch-file offsets.",
        "REA snapshots cache exact queries; they are not editable Ghidra projects.",
        "",
        "## Artifacts",
        "",
    ]
    for key, artifact in state["artifacts"].items():
        lines.extend([f"- `{key[:12]}` {artifact['kind']}: {artifact['path']}"])
        lines.append(f"  - [Literal strings and byte coverage](artifacts/{key}/triage.json)")
        for step in artifact["steps"].values():
            location = f"artifacts/{key}/{step['output']}"
            lines.append(
                f"  - {step['step']}: exit {step['exit_code']}; [{step['output']}]({location})"
            )
            if "counts" in step:
                lines.append(f"    - Reported coverage: `{json.dumps(step['counts'])}`")
            for summary in step.get("summary", []):
                lines.append(f"    - {summary}")
            if step["step"] == "function":
                for suffix in (".c", ".asm"):
                    view = Path(location).with_suffix(suffix)
                    if (project / view).exists():
                        lines.append(f"    - [{view.name}]({view.as_posix()})")
    (project / "REPORT.md").write_text("\n".join(lines) + "\n")


def search(project: Path, state: dict, query: str, select: str, limit: int) -> None:
    count = 0
    for key, artifact in state["artifacts"].items():
        if select and select not in key and select not in artifact["path"]:
            continue
        directory = project / "artifacts" / key
        # Only current successful reports and generated source are searched, never failed logs.
        files = [
            directory / step["output"]
            for step in artifact["steps"].values()
            if step["exit_code"] == 0
        ]
        files.append(directory / "triage.json")
        files.extend(directory.glob("*.c"))
        files.extend(directory.glob("*.asm"))
        files.extend(
            p
            for p in (directory / "code").rglob("*")
            if p.is_file() and p.suffix in {".c", ".cs", ".java", ".js", ".json"}
        )
        for path in files:
            if not path.is_file():
                continue
            pattern = re.compile(re.escape(query), re.IGNORECASE)
            with path.open(encoding="utf-8", errors="replace") as stream:
                tail, consumed, lines, last_match = "", 0, 0, -1
                while chunk := stream.read(65536):
                    buffer = tail + chunk
                    line_base = lines - tail.count("\n")
                    for match in pattern.finditer(buffer):
                        absolute = consumed - len(tail) + match.start()
                        if absolute <= last_match:
                            continue
                        last_match = absolute
                        number = line_base + buffer.count("\n", 0, match.start()) + 1
                        snippet = buffer[max(0, match.start() - 100) : match.end() + 220].strip()
                        snippet = snippet.replace("\n", " ")
                        print(f"{path}:{number}: {snippet}")
                        count += 1
                        if count >= limit:
                            print(
                                f"Stopped at --limit {limit}; refine the search or increase the limit."
                            )
                            return
                    consumed += len(chunk)
                    lines += chunk.count("\n")
                    tail = buffer[-max(100, len(query) - 1) :]
    print(f"{count} matching report/source occurrences (saved results only).")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog="Use --examples for workflows. No AI service or API key is needed.",
    )
    p.add_argument("inputs", nargs="*", help="files and/or directories to add; directories recurse")
    p.add_argument("--project", type=Path, default=ROOT / "work/analysis/default")
    p.add_argument("--preset", choices=["triage", "analyze", "decompile"], default="analyze")
    p.add_argument(
        "--kind", choices=["auto", "native", "managed", "android", "javascript"], default="auto"
    )
    p.add_argument("--provider", choices=["ghidra", "kuna"], default="ghidra")
    p.add_argument(
        "--query",
        action="append",
        default=[],
        help="literal native feature/string to trace; repeatable",
    )
    p.add_argument(
        "--function", action="append", default=[], help="exact native name or address; repeatable"
    )
    p.add_argument("--search", help="search saved results and source without starting analysis")
    p.add_argument(
        "--select", default="", help="restrict saved targets by path substring or digest prefix"
    )
    p.add_argument("--extra", action="append", choices=["capa", "floss"], default=[])
    p.add_argument("--max-files", type=int, default=10000, help="directory inventory bound")
    p.add_argument(
        "--max-functions", type=int, default=200, help="native export attempts per invocation"
    )
    p.add_argument("--limit", type=int, default=30, help="maximum saved search matches")
    p.add_argument(
        "--plan", action="store_true", help="show commands without running tools or creating output"
    )
    p.add_argument(
        "--refresh", action="store_true", help="rerun selected steps; retains previous reports"
    )
    p.add_argument("--list", action="store_true", help="list saved artifacts")
    p.add_argument("--examples", action="store_true")
    p.add_argument("--caller-cwd", type=Path, default=Path.cwd(), help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    p = parser()
    args = p.parse_args(argv)
    if args.examples:
        print(EXAMPLES)
        return 0
    if min(args.max_files, args.max_functions, args.limit) < 1:
        p.error("limits must be positive")
    project = (args.caller_cwd / args.project).resolve()
    state_path = project / "project.json"
    if (
        not args.inputs
        and not (args.search or args.list or args.query or args.function)
        and not state_path.exists()
    ):
        p.error("provide input paths or an existing --project; see --examples")
    state = (
        json.loads(state_path.read_text())
        if state_path.exists()
        else {"format": "rea-suite-analysis", "version": 1, "artifacts": {}}
    )
    if (
        not isinstance(state, dict)
        or state.get("format") != "rea-suite-analysis"
        or state.get("version") != 1
        or not isinstance(state.get("artifacts"), dict)
    ):
        raise ValueError(
            f"unrecognized project manifest; choose a separate output directory: {state_path}"
        )
    if args.search or args.list:
        if args.inputs or args.query or args.function or args.plan:
            p.error("saved --search/--list cannot be combined with analysis inputs or queries")
        if not state_path.exists():
            raise ValueError(f"no saved project: {project}")
        if args.list:
            for key, item in state["artifacts"].items():
                if args.select and args.select not in key and args.select not in item["path"]:
                    continue
                print(f"{key[:12]}\t{item['kind']}\t{item['path']}")
        if args.search:
            search(project, state, args.search, args.select, args.limit)
        return 0
    found = discover(
        [(args.caller_cwd / Path(s)).resolve() for s in args.inputs],
        project,
        args.kind,
        args.max_files,
    )
    if not args.inputs:
        saved = [
            (key, a)
            for key, a in state["artifacts"].items()
            if not args.select or args.select in key or args.select in a["path"]
        ]
        for key, artifact in saved:
            path = Path(artifact["path"])
            if path.is_file() and digest(path) != key:
                if args.select and args.select in key:
                    raise ValueError(
                        "saved artifact no longer matches the input bytes; use --search or add its original file"
                    )
                continue
            found.append((path, artifact["kind"]))
        found = sorted(set(found))
    if not found:
        raise ValueError("no supported targets selected; use --kind for explicit format selection")
    targets = []
    for path, kind in found:
        if not path.exists():
            raise ValueError(f"saved input is unavailable: {path}")
        # A directory slot has no assumed content digest. Its analyses are never reused.
        key = digest(path) if path.is_file() else hashlib.sha256(str(path).encode()).hexdigest()
        if args.select and args.select not in key and args.select not in str(path):
            continue
        targets.append((key, path, kind))
    if not targets:
        raise ValueError("no current inputs match --select; add input paths or use saved --search")
    if args.plan:
        for key, path, kind in targets:
            out = project / "artifacts" / key
            print(f"{kind}: {path}")
            for label, command in steps(path, kind, args, out):
                available = "" if shutil.which(command[0]) else " [missing executable]"
                print(f"  {label}{available}: {subprocess.list2cmdline(command)}")
        return 0
    project.mkdir(parents=True, exist_ok=True)
    failed = False
    with locked(project):
        # Re-read under the lock so a completed competing run is not overwritten.
        if state_path.exists():
            state = json.loads(state_path.read_text())
        for key, path, kind in targets:
            out = project / "artifacts" / key
            out.mkdir(parents=True, exist_ok=True)
            artifact = state["artifacts"].setdefault(
                key, {"path": str(path), "kind": kind, "steps": {}}
            )
            artifact["path"] = str(path)
            print(f"{kind}: {path} [{key[:12]}]", flush=True)
            if path.is_file():
                save(out / "triage.json", triage(path))
            if (args.query or args.function) and kind != "native":
                print("  Native --query/--function do not apply here; export and use --search.")
                failed = True
            engine_failed = False
            for label, command in steps(path, kind, args, out):
                if engine_failed and label in {"trace", "function", "decompile"}:
                    print(f"  skip  {label}: native overview failed")
                    continue
                if label == "decompile":
                    (out / "code").mkdir(exist_ok=True)
                ok = run_step(
                    label,
                    command,
                    out,
                    artifact["steps"],
                    args.refresh,
                    path.is_file() and label != "decompile",
                )
                failed |= not ok
                engine_failed |= kind == "native" and label == "overview" and not ok
                # Preserve identity across a run that races with a binary replacement.
                if path.is_file() and digest(path) != key:
                    for step in artifact["steps"].values():
                        step["exit_code"] = 1
                    save(state_path, state)
                    raise ValueError(
                        f"input changed during analysis: {path}; rerun with stable input"
                    )
                save(state_path, state)
            report_project(project, state)
    print(f"Project: {project}\nReport: {project / 'REPORT.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, json.JSONDecodeError) as error:
        sys.exit(f"rea-suite analyze: {error}")
