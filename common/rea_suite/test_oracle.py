"""The oracle's shared part: the emulator dialect of the regions file, --sync, byte order, the
driver against a scripted EmulatorTarget, and `oracle compare` on a sequence DOSBox-X's dialect
wrote. The format's own tests (the sequence file, the comparison) are test_dosbox_regions.py's,
which run through the same code."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from rea_suite import dosbox_actions as acts
from rea_suite import dosbox_regions as rg
from rea_suite import oracle

REGIONS = {
    "regions": {
        "hp": {"addr": "0x80100000", "len": 4, "type": "i32", "endian": "big"},
        "map": {"addr": "80100100", "len": 16},
    },
    "sync": [
        {"name": "boot", "at": "start", "regions": ["hp"]},
        {"name": "frame", "at": "pc=80003000", "repeat": True},
        {"name": "later", "at": "t=5"},
    ],
}


class Dialect(unittest.TestCase):
    def test_addresses_triggers_and_byte_order(self) -> None:
        parsed = oracle.parse_regions(REGIONS, oracle.EMULATOR)
        hp = parsed.regions["hp"]
        self.assertEqual((hp.address.value, hp.endian, hp.type), (0x80100000, "big", "i32"))
        boot, frame, later = parsed.syncs
        self.assertEqual(boot.trigger.kind, "start")
        self.assertEqual(frame.trigger.breakpoint, (0x80003000, False))
        self.assertTrue(frame.repeat)
        self.assertEqual(later.trigger.seconds, 5)
        self.assertEqual(oracle.parse_trigger("hw=0x1000").breakpoint, (0x1000, True))

    def test_mistakes_are_named(self) -> None:
        region = {"a": {"addr": "0", "len": 1}}
        cases = {
            "repeat a time": {"regions": region, "sync": [{"name": "s", "at": "t=1", "repeat": True}]},
            "dos trigger": {"regions": region, "sync": [{"name": "s", "at": "int21"}]},
            "dos mode": {"regions": region, "sync": [{"name": "s", "at": "start", "mode": "pm"}]},
            "sel:off": {"regions": {"a": {"addr": "0168:0", "len": 1}},
                        "sync": [{"name": "s", "at": "start"}]},
            "endian": {"regions": {"a": {"addr": "0", "len": 1, "endian": "middle"}},
                       "sync": [{"name": "s", "at": "start"}]},
            "no sync": {"regions": region},
        }  # fmt: skip
        for why, data in cases.items():
            with self.assertRaises(ValueError, msg=why):
                oracle.parse_regions(data, oracle.EMULATOR)
        self.assertEqual(
            oracle.parse_regions({"regions": region}, oracle.EMULATOR, False).syncs, []
        )

    def test_sync_on_the_command_line(self) -> None:
        regions = oracle.parse_regions(REGIONS, oracle.EMULATOR).regions
        sync = oracle.parse_sync_option("hit@pc=8000F000@map", regions, [])
        self.assertEqual(
            ([r.name for r in sync.regions], sync.trigger.address), (["map"], 0x8000F000)
        )
        self.assertEqual(len(oracle.parse_sync_option("all@start", regions, []).regions), 2)
        for bad in ("nothing", "x@pc=zz", "x@start@nope", "boot@start"):
            with self.assertRaises(ValueError, msg=bad):
                oracle.parse_sync_option(bad, regions, ["boot"])

    def test_the_dos_dialect_still_refuses_what_it_refused(self) -> None:
        data = {"regions": {"a": {"addr": "0", "len": 1}}, "sync": [{"name": "s", "at": "pc=10"}]}
        with self.assertRaises(ValueError):
            rg.parse_regions(data)
        self.assertIs(acts.Region, oracle.Region)


class ScriptedTarget(oracle.EmulatorTarget):
    """An EmulatorTarget whose stops are a list: each resume takes the next."""

    producer = "scripted"

    def __init__(self, stops: list[oracle.Stop], memory: dict[int, bytes]):
        self.stops, self.memory = stops, memory
        self.armed: set[tuple[int, bool]] = set()
        self.calls: list[str] = []

    def connect(self) -> oracle.Stop:
        self.calls.append("connect")
        return oracle.Stop("signal", 0x80000000)

    def set_breakpoint(self, address: int, hardware: bool = False) -> None:
        self.calls.append(f"set {address:x}")
        self.armed.add((address, hardware))

    def clear_breakpoint(self, address: int, hardware: bool = False) -> None:
        self.calls.append(f"clear {address:x}")
        self.armed.discard((address, hardware))

    def resume(self, timeout: float | None) -> oracle.Stop:
        self.calls.append("resume")
        return self.stops.pop(0) if self.stops else oracle.Stop("exited", None, "W00")

    def read(self, address: int, length: int) -> bytes:
        if address not in self.memory:
            raise oracle.TargetError(f"nothing at {address:#x}")
        return self.memory[address][:length]

    def close(self) -> None:
        self.calls.append("close")


class Driver(unittest.TestCase):
    def run_target(self, target, syncs, **options) -> tuple[oracle.Outcome, list, list[dict]]:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.jsonl"
            writer = oracle.SequenceWriter(path, target.producer)
            records: list[dict] = []
            clock = iter(range(1000)).__next__  # one second per look at the clock
            outcome = oracle.run_syncs(target, syncs, writer, emit=records.append,
                                       clock=lambda: float(clock()), **options)  # fmt: skip
            writer.close()
            _, points = oracle.read_sequence(path)
        return outcome, points, records

    def test_start_breakpoints_and_repeats_until_the_end(self) -> None:
        syncs = oracle.parse_regions(
            {"regions": REGIONS["regions"], "sync": REGIONS["sync"][:2]}, oracle.EMULATOR
        ).syncs
        hp, table = b"\0\0\0\x05", bytes(range(16))
        target = ScriptedTarget(
            [oracle.Stop("break", 0x80003000), oracle.Stop("signal", 0x80004444),
             oracle.Stop("break", 0x80003000)],
            {0x80100000: hp, 0x80100100: table},
        )  # fmt: skip
        outcome, points, records = self.run_target(target, syncs, seconds=100)
        self.assertEqual(
            [(p.sync, p.hit) for p in points], [("boot", 1), ("frame", 1), ("frame", 2)]
        )
        self.assertEqual(points[1].entries[1].data, table)
        self.assertEqual(outcome.ended, "exited W00")
        self.assertEqual(target.calls[:2], ["connect", "set 80003000"])
        self.assertEqual(target.calls[-1], "close")
        self.assertIn({"kind": "stop", "reason": "signal", "detail": "", "pc": "80004444"}, records)

    def test_a_breakpoint_is_cleared_once_its_one_time_sync_is_read(self) -> None:
        syncs = [
            oracle.parse_sync_option(
                "once@pc=10", {"a": oracle.Region("a", oracle.parse_address("0"), 1)}, []
            )
        ]
        target = ScriptedTarget([oracle.Stop("break", 0x10)], {0: b"\x01"})
        outcome, _, _ = self.run_target(target, syncs, seconds=100)
        self.assertEqual(outcome.ended, "done")
        self.assertEqual(target.calls, ["connect", "set 10", "resume", "close"])

    def test_time_triggers_unreadable_regions_and_the_limits(self) -> None:
        regions = {"a": oracle.Region("a", oracle.parse_address("40"), 2)}
        syncs = [oracle.parse_sync_option("tick@t=1", regions, [])]
        target = ScriptedTarget([oracle.Stop("timeout", 0x20)], {})
        _, points, records = self.run_target(target, syncs, seconds=100)
        self.assertEqual(points[0].entries[0].error, "nothing at 0x40")
        self.assertEqual(records[-1]["errors"], 1)
        syncs = [oracle.parse_sync_option("rep@pc=10", regions, [])]
        syncs[0].repeat = True
        target = ScriptedTarget([oracle.Stop("break", 0x10)] * 9, {0x40: b"ab"})
        outcome, points, _ = self.run_target(target, syncs, seconds=100, max_points=3)
        self.assertEqual((len(points), outcome.ended), (3, "max-points"))
        target = ScriptedTarget([oracle.Stop("break", 0x10)] * 99, {0x40: b"ab"})
        syncs[0].done = False
        outcome, _, _ = self.run_target(target, syncs, seconds=4)
        self.assertEqual(outcome.ended, "seconds")


class Compare(unittest.TestCase):
    def test_oracle_compare_reads_a_dosbox_sequence_and_regions_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            for name, value in (("a.jsonl", b"\x01\0"), ("b.jsonl", b"\x02\0")):
                w = rg.SequenceWriter(tmp / name, "test")
                w.region("end", acts.Region("n", acts.parse_address("0168:10"), 2, "u16"), value)
                w.next()
                w.close()
            (tmp / "r.toml").write_text(
                '[regions.n]\naddr = "0168:10"\nlen = 2\ntype = "u16"\n'
                '[[sync]]\nname = "end"\nat = "exit"\nmode = "any"\n'
            )
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = oracle.main(["--caller-cwd", d, "compare", "a.jsonl", "b.jsonl",
                                      "--regions", "r.toml"])  # fmt: skip
            self.assertEqual(status, 1)
            self.assertIn("u16 [0] = 1", out.getvalue())
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(oracle.main(["--caller-cwd", d, "compare", "a.jsonl", "x"]), 2)
            self.assertIn("oracle compare:", err.getvalue())

    def test_an_unknown_target_is_bad_input(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            Path(d, "r.json").write_text('{"regions": {"a": {"addr": "0", "len": 1}}}')
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                status = oracle.main(["--caller-cwd", d, "run", "--target", "tcp://h:1",
                                      "--regions", "r.json", "--sync", "s@start"])  # fmt: skip
            self.assertEqual(status, 2)
            self.assertIn("gdb://HOST:PORT", err.getvalue())


if __name__ == "__main__":
    unittest.main()
