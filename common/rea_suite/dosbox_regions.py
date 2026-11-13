"""Named memory regions at sync points, for comparing a port's run against the original's.

  rea-suite dosbox run --regions FILE ... PROGRAM   reads the regions at each sync point into a
                                                    sequence file (regions.jsonl in the run's folder)
  rea-suite dosbox compare A B [--regions FILE]     the first difference between two sequences

The format, the sequence file and the comparison are the oracle's, shared with every emulator back
end (oracle.py; docs/PORT-TOOLS.md, "The oracle"). What is DOSBox-X's own is this dialect of the
regions file: addresses as --dump takes them (linear or SEL:OFF), the triggers of dosbox_actions
(INT calls, file opens, t=, input:, start, exit), `repeat` for calls and opens, and `mode`.
"""

from __future__ import annotations

from pathlib import Path

from rea_suite import dosbox_actions as acts
from rea_suite import oracle
from rea_suite.oracle import (  # noqa: F401  (the names this module has always offered)
    FORMAT,
    INLINE_MAX,
    TYPES,
    VERSION,
    BadRegions,
    BadSequence,
    Difference,
    Entry,
    Point,
    RegionsFile,
    SequenceWriter,
    compare_entry,
    first_difference,
    hex_rows,
    ignored,
    read_sequence,
    typed_value,
)

REPEATABLE = ("int", "open")  # triggers that come more than once; the others are one moment


class DosDialect:
    """Regions files for `rea-suite dosbox`."""

    sync_keys = frozenset({"repeat", "mode"})

    def address(self, text: str) -> acts.Address:
        return acts.parse_address(text)

    def trigger(self, text: str) -> acts.Trigger:
        return acts.parse_trigger(text)

    def options(self, name: str, trigger: acts.Trigger, spec: dict) -> dict:
        repeat = spec.get("repeat", False)
        if not isinstance(repeat, bool):
            raise BadRegions(f"sync {name!r}: repeat is true or false")
        if repeat and trigger.kind not in REPEATABLE:
            raise ValueError(f"sync {name!r}: repeat needs an int or open trigger")
        mode = spec.get("mode", "auto")
        if mode not in acts.MODES:
            raise ValueError(f"sync {name!r}: mode is one of {', '.join(acts.MODES)}")
        if mode == "pm" and trigger.kind not in (*acts.MOVABLE, *acts.CALLS):
            raise ValueError(f"sync {name!r}: mode pm needs an int, open, t= or input: trigger")
        return {"repeat": repeat, "mode": mode}

    def sync(
        self, name: str, trigger: acts.Trigger, regions: list[acts.Region], options: dict
    ) -> acts.Sync:
        return acts.Sync(name, trigger, regions, options["repeat"], mode=options["mode"])


DOS = DosDialect()


def parse_region(name: str, spec) -> acts.Region:
    return oracle.parse_region(name, spec, DOS)


def parse_regions(data: dict) -> RegionsFile:
    """The regions file's contents (a parsed TOML or JSON document)."""
    return oracle.parse_regions(data, DOS)


def load_regions(path: Path) -> RegionsFile:
    return oracle.load_regions(path, DOS)


def compare(args) -> int:
    """`rea-suite dosbox compare A B`: 0 equal, 1 a difference, 2 bad input."""
    import sys

    try:
        regions = load_regions(args.caller_cwd / args.regions) if args.regions else None
    except (OSError, ValueError) as exc:
        print(f"dosbox compare: {exc}", file=sys.stderr)
        return 2
    paths = (args.caller_cwd / args.a, args.caller_cwd / args.b)
    return oracle.compare_files(
        *paths, regions, args.context, (str(args.a), str(args.b)), "dosbox compare"
    )
