"""LZO1X decompression: liblzo2's lzo1x_decompress_safe through ctypes when the system has the library,
else a pure-Python decoder written from the instruction set of lzo1x_d.ch (read as a reference; no code
of it is used). Both refuse a stream that reads past its input, copies from before the output's start
or does not unpack to exactly the expected length.

  unpack(src, size) -> bytes           exactly `size` bytes, with liblzo2 when present
  decompress(src, size=None) -> (bytes, consumed)   the pure-Python decoder
"""

from __future__ import annotations

import ctypes
import ctypes.util
from collections.abc import Callable

M2_MAX_OFFSET = 0x0800
M4_BASE = 0x4000


def decompress(src: bytes, size: int | None = None) -> tuple[bytes, int]:
    """Decode one LZO1X stream up to its end marker; returns the output and the input bytes used."""
    out = bytearray()
    ip = 0
    end = len(src)

    def byte() -> int:
        nonlocal ip
        if ip >= end:
            raise ValueError("input overrun")
        ip += 1
        return src[ip - 1]

    def literals(count: int) -> None:
        nonlocal ip
        if ip + count > end:
            raise ValueError("input overrun")
        out.extend(src[ip : ip + count])
        ip += count
        if size is not None and len(out) > size:
            raise ValueError(f"output overrun past {size} bytes")

    def run_length(base: int) -> int:
        """A zero length field: each zero byte adds 255, the first nonzero byte ends it."""
        zeros = 0
        while (b := byte()) == 0:
            zeros += 255
        return zeros + base + b

    def match(dist: int, length: int) -> None:
        start = len(out) - dist
        if start < 0:
            raise ValueError(f"lookbehind overrun at input {ip:#x}")
        if size is not None and len(out) + length > size:
            raise ValueError(f"output overrun past {size} bytes")
        if dist >= length:
            out.extend(out[start : start + length])
        else:  # overlapping copy: the run repeats with period `dist`
            for i in range(length):
                out.append(out[start + i])

    # state: literals copied by the previous instruction (0, 1-3, or 4 for a run of four or more)
    state = 0
    t = byte()
    if t > 17:
        literals(t - 17)
        state = min(4, t - 17)
        t = byte()
    while True:
        if t < 16:
            if state == 0:  # a literal run of t + 3 bytes
                literals((run_length(15) if t == 0 else t) + 3)
                state = 4
                t = byte()
                continue
            low = byte()
            if state == 4:  # three bytes from 2049..3072 back
                match(1 + M2_MAX_OFFSET + (t >> 2) + (low << 2), 3)
            else:  # two bytes from 1..1024 back
                match(1 + (t >> 2) + (low << 2), 2)
            tail = t & 3
        elif t >= 64:  # M2: 3..8 bytes from 1..2048 back
            low = byte()
            match(1 + ((t >> 2) & 7) + (low << 3), (t >> 5) + 1)
            tail = t & 3
        elif t >= 32:  # M3: up to 16 KiB back
            length = run_length(31) if t & 31 == 0 else t & 31
            d = byte() | (byte() << 8)
            match(1 + (d >> 2), length + 2)
            tail = d & 3
        else:  # M4: 16..48 KiB back, or the end marker
            length = run_length(7) if t & 7 == 0 else t & 7
            d = byte() | (byte() << 8)
            dist = ((t & 8) << 11) + (d >> 2)
            if dist == 0:
                break
            match(dist + M4_BASE, length + 2)
            tail = d & 3
        state = tail
        if tail:
            literals(tail)
        t = byte()
    if size is not None and len(out) != size:
        raise ValueError(f"unpacked {len(out)} bytes, expected {size}")
    return bytes(out), ip


def _liblzo2() -> Callable[[bytes, int], bytes] | None:
    name = ctypes.util.find_library("lzo2")
    if not name:
        return None
    try:
        fn = ctypes.CDLL(name).lzo1x_decompress_safe
    except (OSError, AttributeError):
        return None
    fn.restype = ctypes.c_int
    fn.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
    ]

    def run(src: bytes, size: int) -> bytes:
        dst = ctypes.create_string_buffer(max(size, 1))
        done = ctypes.c_size_t(size)
        code = fn(src, len(src), dst, ctypes.byref(done), None)
        # -8 (LZO_E_INPUT_NOT_CONSUMED): bytes after the end marker, which the pure decoder ignores too
        if code not in (0, -8) or done.value != size:
            raise ValueError(f"liblzo2 error {code}: {done.value} of {size} bytes")
        return dst.raw[:size]

    return run


LIBLZO2 = _liblzo2()


def unpack(src: bytes, size: int) -> bytes:
    """Exactly `size` bytes from an LZO1X stream, with liblzo2 when present."""
    if LIBLZO2 is not None:
        return LIBLZO2(src, size)
    return decompress(src, size)[0]
