"""LZ4 block decompression (the raw block format, no frame), written from the format's description
(lz4's doc/lz4_Block_format.md): a sequence is a token (literal count in the high nibble, match
length minus 4 in the low one, 15 meaning more length bytes follow), the literals, then a 2-byte
little-endian offset back into the output. The last sequence has literals only. A block that reads
past its input, copies from before the output's start or does not unpack to exactly the expected
size is refused.

  unpack(src, size) -> bytes      exactly `size` bytes
"""

from __future__ import annotations


def _length(src: bytes, ip: int, base: int) -> tuple[int, int]:
    """A 4-bit length and, when it is 15, the bytes after it (each adds; 255 means more)."""
    if base != 15:
        return base, ip
    while True:
        if ip >= len(src):
            raise ValueError("LZ4: input overrun in a length")
        b = src[ip]
        ip += 1
        base += b
        if b != 255:
            return base, ip


def unpack(src: bytes, size: int) -> bytes:
    out = bytearray()
    ip, end = 0, len(src)
    while True:
        if ip >= end:
            raise ValueError("LZ4: input overrun at a token")
        token = src[ip]
        ip += 1
        count, ip = _length(src, ip, token >> 4)
        if ip + count > end:
            raise ValueError("LZ4: input overrun in literals")
        out += src[ip : ip + count]
        ip += count
        if len(out) > size:
            raise ValueError(f"LZ4: output overrun past {size} bytes")
        if ip == end:  # the last sequence: literals only
            break
        if ip + 2 > end:
            raise ValueError("LZ4: input overrun at an offset")
        offset = src[ip] | src[ip + 1] << 8
        ip += 2
        if not 0 < offset <= len(out):
            raise ValueError(f"LZ4: offset {offset} before the output's start")
        length, ip = _length(src, ip, token & 15)
        length += 4
        if len(out) + length > size:
            raise ValueError(f"LZ4: output overrun past {size} bytes")
        start = len(out) - offset
        if offset >= length:
            out += out[start : start + length]
        else:  # the match overlaps what it writes: repeat the last `offset` bytes
            while length:
                piece = out[start : start + min(offset, length)]
                out += piece
                start += len(piece)
                length -= len(piece)
    if len(out) != size:
        raise ValueError(f"LZ4: {len(out)} bytes, expected {size}")
    return bytes(out)
