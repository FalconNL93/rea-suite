"""`rea-suite dosbox --regions` and `compare`: the regions file, the sequence file both ways, the
comparison on synthetic sequences, and the tracer's sync points against the stand-in debugger. The
run against a real DOSBox-X is in test_dosbox.py (RealRun, opt-in)."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import ClassVar

from rea_suite import dosbox
from rea_suite import dosbox_actions as acts
from rea_suite import dosbox_regions as rg
from rea_suite.test_dosbox import FakeDebugger, regs, tracer

REGIONS_TOML = """
[regions.money]
addr = "0168:0001A2B0"
len = 4
type = "i32"

[regions.map]
addr = "1A2B30"
len = "0x40"
ignore = ["0x10:4"]

[[sync]]
name = "level"
at = "open:DATA/LEVEL.DAT"
repeat = true

[[sync]]
name = "end"
at = "exit"
regions = ["money"]
"""


def write_sequence(path: Path, points: list[tuple[str, dict[str, bytes]]], **options) -> None:
    w = rg.SequenceWriter(path, "test", **options)
    for name, regions in points:
        for region, data in regions.items():
            w.region(name, acts.Region(region, acts.parse_address("0"), len(data)), data)
        w.next()
    w.close()


def compare(a: Path, b: Path, *options: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = dosbox.main(["compare", str(a), str(b), *options])
    return status, out.getvalue(), err.getvalue()


class RegionsFile(unittest.TestCase):
    def test_toml_and_json_say_the_same(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            toml = Path(tmp) / "r.toml"
            toml.write_text(REGIONS_TOML)
            parsed = rg.load_regions(toml)
            as_json = Path(tmp) / "r.json"
            as_json.write_text(json.dumps({
                "regions": {
                    "money": {"addr": "0168:0001A2B0", "len": 4, "type": "i32"},
                    "map": {"addr": "1A2B30", "len": "0x40", "ignore": ["0x10:4"]},
                },
                "sync": [
                    {"name": "level", "at": "open:DATA/LEVEL.DAT", "repeat": True},
                    {"name": "end", "at": "exit", "regions": ["money"]},
                ],
            }))  # fmt: skip
            self.assertEqual(rg.load_regions(as_json), parsed)
        money, map_ = parsed.regions["money"], parsed.regions["map"]
        self.assertEqual((money.address.sel, money.address.off, money.length, money.type),
                         (0x168, 0x1A2B0, 4, "i32"))  # fmt: skip
        self.assertEqual(
            (map_.address.linear, map_.length, map_.ignore), (0x1A2B30, 64, ((16, 4),))
        )
        level, end = parsed.syncs
        self.assertEqual((level.name, level.trigger.kind, level.repeat), ("level", "open", True))
        self.assertEqual([r.name for r in level.regions], ["money", "map"])  # all, in file order
        self.assertEqual([r.name for r in end.regions], ["money"])
        self.assertEqual(end.text, "sync end@exit")

    def test_mistakes_are_named(self) -> None:
        cases = {
            "no regions": {"sync": [{"name": "a", "at": "exit"}]},
            "no sync": {"regions": {"a": {"addr": "0", "len": 1}}},
            "no len": {"regions": {"a": {"addr": "0"}}, "sync": [{"name": "s", "at": "exit"}]},
            "bad type": {"regions": {"a": {"addr": "0", "len": 1, "type": "f32"}},
                         "sync": [{"name": "s", "at": "exit"}]},
            "odd length": {"regions": {"a": {"addr": "0", "len": 3, "type": "u16"}},
                           "sync": [{"name": "s", "at": "exit"}]},
            "ignore past": {"regions": {"a": {"addr": "0", "len": 4, "ignore": ["2:4"]}},
                            "sync": [{"name": "s", "at": "exit"}]},
            "unknown region": {"regions": {"a": {"addr": "0", "len": 1}},
                               "sync": [{"name": "s", "at": "exit", "regions": ["b"]}]},
            "twice": {"regions": {"a": {"addr": "0", "len": 1}},
                      "sync": [{"name": "s", "at": "exit"}, {"name": "s", "at": "start"}]},
            "repeat a time": {"regions": {"a": {"addr": "0", "len": 1}},
                              "sync": [{"name": "s", "at": "t=3", "repeat": True}]},
            "bad trigger": {"regions": {"a": {"addr": "0", "len": 1}},
                            "sync": [{"name": "s", "at": "soon"}]},
            "unknown key": {"regions": {"a": {"addr": "0", "len": 1, "size": 2}},
                            "sync": [{"name": "s", "at": "exit"}]},
        }  # fmt: skip
        for why, data in cases.items():
            with self.assertRaises(ValueError, msg=why):
                rg.parse_regions(data)

    def test_input_trigger_and_items(self) -> None:
        steps = acts.parse_input('t=1:ENTER t=2:"ab" t=3:mouse:1,1')
        self.assertEqual(sorted({s.item for s in steps}), [1, 2, 3])
        self.assertEqual(acts.parse_trigger("input:2").item, 2)
        for bad in ("input:", "input:0", "input:x"):
            with self.assertRaises(ValueError, msg=bad):
                acts.parse_trigger(bad)
        data = rg.parse_regions({"regions": {"a": {"addr": "0", "len": 1}},
                                 "sync": [{"name": "s", "at": "input:4"}]})  # fmt: skip
        with self.assertRaises(ValueError):  # three items only
            acts.Actions.from_args([], [], "t=1:ENTER t=2:A t=3:B", data.syncs)
        actions = acts.Actions.from_args([], [], "t=1:ENTER t=2:A t=3:B t=4:C", data.syncs)
        self.assertEqual(actions.due(0, {1, 2, 3}), [])
        self.assertEqual(actions.due(0, {4}), data.syncs)


class Sequence(unittest.TestCase):
    def test_written_and_read_back_with_the_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run.jsonl"
            big = bytes(range(256)) * 20
            w = rg.SequenceWriter(path, "test", inline_max=64)
            region = acts.Region("money", acts.parse_address("90000"), 4, "u32")
            w.region("first", region, b"\x01\x00\x00\x00", hit=1, at="00A7:00000199")
            w.region("first", acts.Region("map", acts.parse_address("1000"), len(big)), big)
            w.next()
            w.region("second", region, None, "no 32-bit selector covers it")
            w.region("second", acts.Region("map", acts.parse_address("1000"), len(big)), big[:9])
            w.next()
            w.close()
            lines = [json.loads(x) for x in path.read_text().splitlines()]
            self.assertEqual(lines[0], {"format": "rea-regions", "version": 1, "producer": "test",
                                        "sidecar": "run.bin"})  # fmt: skip
            self.assertEqual(lines[1]["hex"], "01000000")
            self.assertEqual((lines[1]["type"], lines[1]["hit"], lines[1]["at"]),
                             ("u32", 1, "00A7:00000199"))  # fmt: skip
            self.assertEqual((lines[2]["offset"], "hex" in lines[2]), (0, False))
            self.assertEqual(lines[4]["error"], "read 9 of 5120 bytes")  # a short read
            header, points = rg.read_sequence(path)
        self.assertEqual(header["producer"], "test")
        self.assertEqual([(p.index, p.sync) for p in points], [(0, "first"), (1, "second")])
        self.assertEqual([e.data for e in points[0].entries], [b"\x01\x00\x00\x00", big])
        self.assertEqual(points[1].entries[0].error, "no 32-bit selector covers it")

    def test_a_port_line_needs_only_the_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "port.jsonl"
            path.write_text(
                '{"format": "rea-regions", "version": 1}\n'
                '{"index": 0, "sync": "level", "region": "money", "len": 2, "hex": "0a0b"}\n'
            )
            _, points = rg.read_sequence(path)
        self.assertEqual(points[0].entries[0].data, b"\x0a\x0b")

    def test_broken_files_are_refused(self) -> None:
        head = '{"format": "rea-regions", "version": 1}\n'
        line = '{"index": 0, "sync": "s", "region": "r", "len": 2, "hex": "0a0b"}\n'
        cases = {
            "no header": line,
            "a later version": '{"format": "rea-regions", "version": 2}\n',
            "not json": head + "{index\n",
            "hex too short": head + line.replace("0a0b", "0a"),
            "bad sha": head + line.replace('"hex"', '"sha256": "00", "hex"'),
            "no data": head + '{"index": 0, "sync": "s", "region": "r", "len": 2}\n',
            "index back": head + line.replace('"index": 0', '"index": 1') + line,
            "region twice": head + line + line,
            "two names": head + line + line.replace('"s"', '"t"').replace('"r"', '"q"'),
            "no sidecar": head
            + '{"index": 0, "sync": "s", "region": "r", "len": 2, "offset": 0}\n',
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            for why, text in cases.items():
                path.write_text(text)
                with self.assertRaises(rg.BadSequence, msg=why):
                    rg.read_sequence(path)


class Compare(unittest.TestCase):
    POINTS: ClassVar[list[tuple[str, dict[str, bytes]]]] = [
        ("title", {"money": b"\x00\x10\x00\x00", "map": bytes(64)}),
        ("level", {"money": b"\x00\x20\x00\x00", "map": bytes(range(64))}),
        ("level", {"money": b"\x00\x30\x00\x00", "map": bytes(range(64))}),
    ]

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.a = self.dir / "a.jsonl"
        write_sequence(self.a, self.POINTS)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def b(self, points, **options) -> Path:
        path = self.dir / "b.jsonl"
        write_sequence(path, points, **options)
        return path

    def test_equal_sequences_exit_0(self) -> None:
        status, out, _ = compare(self.a, self.b(self.POINTS, inline_max=16))  # map in the sidecar
        self.assertEqual(status, 0)
        self.assertIn("equal: 3 sync point(s)", out)

    def test_a_difference_in_the_middle_names_the_place_and_the_bytes(self) -> None:
        changed = list(self.POINTS)
        level = dict(changed[1][1])
        level["map"] = bytes(range(40)) + b"\xee" + bytes(range(41, 64))
        changed[1] = ("level", level)
        changed[2] = ("level", {"money": b"\xff" * 4, "map": bytes(64)})  # after: not reported
        status, out, _ = compare(self.a, self.b(changed))
        self.assertEqual(status, 1)
        self.assertIn("1 sync point(s) equal, then:", out)
        self.assertIn("sync point 1 (level), region 'map': offset 0x28 (40), 1 byte(s) differ", out)
        self.assertIn("  00000020  20 21 22 23 24 25 26 27[28]29 2a", out)  # A, the byte marked
        self.assertIn("  00000020  20 21 22 23 24 25 26 27[ee]29 2a", out)
        self.assertNotIn("money", out)

    def test_a_missing_sync_point(self) -> None:
        status, out, _ = compare(self.a, self.b(self.POINTS[:2]))
        self.assertEqual(status, 1)
        self.assertIn("B ends after 2 sync point(s); A goes on with 'level' (sync point 2)", out)
        status, out, _ = compare(self.a, self.b([self.POINTS[0], self.POINTS[2]]))
        self.assertEqual(status, 1)  # same names, the second level's money differs
        status, out, _ = compare(
            self.a, self.b([self.POINTS[0], ("menu", {"money": bytes(4)}), *self.POINTS[1:]])
        )
        self.assertEqual(status, 1)
        self.assertIn("sync point 1: A has 'level', B has 'menu'", out)

    def test_a_missing_region(self) -> None:
        status, out, _ = compare(self.a, self.b([("title", {"money": b"\x00\x10\x00\x00"})]))
        self.assertEqual(status, 1)
        self.assertIn("sync point 0 (title): B has no region 'map'", out)

    def test_the_regions_file_limits_types_and_ignores(self) -> None:
        regions = self.dir / "r.toml"
        regions.write_text(REGIONS_TOML)
        changed = [(n, dict(r)) for n, r in self.POINTS]
        changed[0][1]["map"] = bytes(16) + b"\x01\x02\x03\x04" + bytes(44)  # the ignored range
        changed[2][1]["money"] = b"\x00\x30\x00\x80"
        changed[2][1]["extra"] = b"\x01"  # not in the regions file
        status, out, _ = compare(self.a, self.b(changed), "--regions", str(regions))
        self.assertEqual(status, 1)
        self.assertIn("sync point 2 (level), region 'money': offset 0x3 (3)", out)
        self.assertIn("A: i32 [0] = 12288", out)
        self.assertIn("B: i32 [0] = -2147471360", out)

    def test_an_unreadable_region_is_a_difference(self) -> None:
        path = self.dir / "b.jsonl"
        w = rg.SequenceWriter(path, "test")
        w.region("title", acts.Region("money", acts.parse_address("0"), 4), None, "no selector")
        w.close()
        status, out, _ = compare(self.a, path)
        self.assertEqual(status, 1)
        self.assertIn("B could not read it: no selector", out)

    def test_bad_input_exits_2(self) -> None:
        missing = self.dir / "none.jsonl"
        status, _, err = compare(self.a, missing)
        self.assertEqual(status, 2)
        self.assertIn("none.jsonl", err)
        broken = self.dir / "broken.jsonl"
        broken.write_text("{}\n")
        self.assertEqual(compare(self.a, broken)[0], 2)
        bad_regions = self.dir / "r.toml"
        bad_regions.write_text("[regions]\n")
        self.assertEqual(compare(self.a, self.a, "--regions", str(bad_regions))[0], 2)


class SyncStops(unittest.TestCase):
    """The tracer's sync points against the stand-in debugger."""

    def test_regions_read_at_each_open_and_at_the_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "regions.toml"
            path.write_text(
                '[regions.pattern]\naddr = "9000:0"\nlen = 4\n'
                '[regions.word]\naddr = "90010"\nlen = 2\ntype = "u16"\n'
                '[[sync]]\nname = "load"\nat = "open:LEVEL.DAT"\nrepeat = true\n'
                '[[sync]]\nname = "end"\nat = "exit"\nregions = ["word"]\n'
            )
            actions = acts.Actions.from_args([], [], None, rg.load_regions(path).syncs)
            fake = FakeDebugger(Path(tmp))
            fake.memory["0814:0139"] = b"C:\\GAME\\LEVEL.DAT\0"
            fake.memory["09000:00"] = b"PATT"
            fake.memory["09001:00"] = b"\x34\x12"
            sequence = rg.SequenceWriter(Path(tmp) / "run.jsonl", "rea-suite dosbox")
            t, records = tracer(fake, Path(tmp), actions=actions, ints="")
            t.sequence = sequence
            for state, code in [
                (regs(eip=0x100), b"\x90\x90"),
                (regs(eax=0x3D00, edx=0x139, eip=0x109), b"\xcd\x21"),
                (regs(eax=0x3D00, edx=0x139, eip=0x10B), b"\xcd\x21"),  # again: repeat
                (regs(eax=0x4C00, eip=0x10D), b"\xcd\x21"),
            ]:
                fake.stop(t, state, code)
            sequence.close()
            syncs = [r for r in records if r["kind"] == "sync"]
            self.assertEqual([(r["sync"], r["index"], r["hit"]) for r in syncs],
                             [("load", 0, 1), ("load", 1, 2), ("end", 2, 1)])  # fmt: skip
            self.assertEqual(syncs[0]["path"], "C:\\GAME\\LEVEL.DAT")
            _, points = rg.read_sequence(Path(tmp) / "run.jsonl")
        self.assertEqual([[(e.region, e.data) for e in p.entries] for p in points], [
            [("pattern", b"PATT"), ("word", b"\x34\x12")],
            [("pattern", b"PATT"), ("word", b"\x34\x12")],
            [("word", b"\x34\x12")],
        ])  # fmt: skip

    def test_a_region_that_cannot_be_read_is_an_error_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            region = acts.Region("high", acts.parse_address("200000"), 4)  # past real mode
            sync = acts.Sync("s", acts.parse_trigger("start"), [region])
            sequence = rg.SequenceWriter(Path(tmp) / "run.jsonl", "rea-suite dosbox")
            t, records = tracer(FakeDebugger(Path(tmp)), Path(tmp),
                                actions=acts.Actions(syncs=[sync]), ints="")  # fmt: skip
            t.sequence = sequence
            t.act(sync, regs())
            sequence.close()
            self.assertEqual(records[0]["errors"], 1)
            _, points = rg.read_sequence(Path(tmp) / "run.jsonl")
        self.assertIn("real mode", points[0].entries[0].error)

    def test_an_input_item_delivered_whole_makes_its_sync_due(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sync = acts.Sync("typed", acts.parse_trigger("input:2"),
                             [acts.Region("r", acts.parse_address("0"), 1)])  # fmt: skip
            actions = acts.Actions.from_args([], [], 't=0:ENTER t=0:"ab"', [sync])
            t, _ = tracer(FakeDebugger(Path(tmp)), Path(tmp), actions=actions, ints="")
            clock = [0.0]
            t.now = lambda: clock[0]  # type: ignore[method-assign]
            for now in (0.0, 0.05):  # ENTER pressed and released, "a" too, on time
                clock[0] = now
                t.deliver_input()
            self.assertEqual(t.delivered, {1})  # "b" is still to come
            self.assertEqual(t.due(), [])
            for now in (1.0, 2.0):  # late: the release moves back as much, and comes after
                clock[0] = now
                t.deliver_input()
            self.assertEqual(t.delivered, {1, 2})
            self.assertEqual(t.due(), [sync])


if __name__ == "__main__":
    unittest.main()
