"""`diec`: Detect It Easy console scanner on top of die-python.

The official Linux AppImage only ships the GUI (`die`); this gives the console
scanner without the system-wide .deb.
"""

from __future__ import annotations

import argparse
import sys

try:
    import die
except ImportError:
    die = None


def main() -> None:
    if die is None:
        sys.exit("diec: die-python is not installed (no build for this platform)")
    parser = argparse.ArgumentParser(prog="diec", description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+")
    parser.add_argument("-j", "--json", action="store_true", help="JSON output")
    parser.add_argument("-d", "--deep", action="store_true", help="deep scan")
    parser.add_argument("-u", "--heuristic", action="store_true", help="heuristic scan")
    parser.add_argument("-r", "--recursive", action="store_true", help="recursive scan")
    parser.add_argument("-a", "--all-types", action="store_true", help="scan all file types")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    flags = die.ScanFlags(0)
    for enabled, flag in [
        (args.json, die.ScanFlags.RESULT_AS_JSON),
        (args.deep, die.ScanFlags.DEEP_SCAN),
        (args.heuristic, die.ScanFlags.HEURISTIC_SCAN),
        (args.recursive, die.ScanFlags.RECURSIVE_SCAN),
        (args.all_types, die.ScanFlags.ALL_TYPES_SCAN),
        (args.verbose, die.ScanFlags.VERBOSE_FLAG),
    ]:
        if enabled:
            flags |= flag
    status = 0
    for path in args.files:
        result = die.scan_file(path, flags, str(die.database_path))
        if result is None:
            print(f"{path}: scan failed", file=sys.stderr)
            status = 1
            continue
        if len(args.files) > 1 and not args.json:
            print(f"{path}:")
        print(result.rstrip())
    sys.exit(status)


if __name__ == "__main__":
    main()
