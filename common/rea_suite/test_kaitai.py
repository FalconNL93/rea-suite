"""Kaitai Struct: the runtime (kaitaistruct) reads a stream as generated parsers do; with
REA_KAITAI_INTEGRATION=1, the compiler (`ksc`, tools.yml) turns a .ksy into a Python parser that
reads an IW3 fastfile's header."""

from __future__ import annotations

import importlib.util
import io
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from kaitaistruct import KaitaiStream

KSY = """\
meta:
  id: iw_fastfile_header
  endian: le
seq:
  - id: magic
    contents: IWff
  - id: kind
    type: str
    size: 4
    encoding: ASCII
  - id: version
    type: u4
"""


class Runtime(unittest.TestCase):
    def test_the_stream_reads_little_endian_and_bytes(self) -> None:
        stream = KaitaiStream(io.BytesIO(b"IWffu100" + struct.pack("<I", 5)))
        self.assertEqual(stream.read_bytes(4), b"IWff")
        self.assertEqual(stream.read_bytes(4), b"u100")
        self.assertEqual(stream.read_u4le(), 5)


@unittest.skipUnless(os.environ.get("REA_KAITAI_INTEGRATION"), "runs the Kaitai Struct compiler")
class Compiler(unittest.TestCase):
    def test_a_ksy_becomes_a_parser(self) -> None:
        ksc = shutil.which("ksc")
        self.assertIsNotNone(ksc, "ksc is not on PATH (rea-tools install kaitai-struct-compiler)")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "header.ksy").write_text(KSY)
            subprocess.run(
                [ksc, "-t", "python", "--outdir", tmp, str(Path(tmp, "header.ksy"))], check=True
            )
            spec = importlib.util.spec_from_file_location(
                "iw_fastfile_header", Path(tmp, "iw_fastfile_header.py")
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            header = module.IwFastfileHeader.from_bytes(b"IWffu100" + struct.pack("<I", 5))
        self.assertEqual((header.kind, header.version), ("u100", 5))


if __name__ == "__main__":
    unittest.main()
