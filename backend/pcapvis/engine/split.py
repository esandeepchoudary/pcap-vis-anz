"""Split a capture into N streams by host pair, for parallel dissection.

Every packet between the same two IP addresses goes to the same partition, so each tshark worker sees
whole conversations in their original order (TCP reassembly, FTP USER/PASS, Telnet logins all stay
intact). Non-IP frames (ARP, LLDP, CDP, STP…) go to partition 0.

Supports classic pcap (both byte orders, µs and ns) and pcapng (any number of sections and
interfaces). Each partition gets valid file headers, so tshark reads it from stdin like the original.
The splitter also records each partition's original frame numbers, so results merge in file order.
"""

import struct
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",  # microsecond
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",  # nanosecond
}
PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_EPB = 0x00000006
PCAPNG_SPB = 0x00000003
PCAPNG_OPB = 0x00000002  # obsolete packet block

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100, 0x9200}


class SplitUnsupported(Exception):
    """The capture can't be split (compressed, unknown format); analyse it in one process instead."""


def capture_format(head: bytes) -> str:
    if head[:4] in PCAP_MAGICS:
        return "pcap"
    if len(head) >= 4 and struct.unpack("<I", head[:4])[0] == PCAPNG_SHB:
        return "pcapng"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    return "unknown"


def _ip_pair_key(linktype: int, frame: bytes) -> bytes | None:
    """Return a direction-independent key for the IP pair in this frame, or None for non-IP frames."""
    off = 0
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        etype = (frame[12] << 8) | frame[13]
        off = 14
        while etype in VLAN_ETHERTYPES and len(frame) >= off + 4:
            etype = (frame[off + 2] << 8) | frame[off + 3]
            off += 4
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        etype, off = (frame[14] << 8) | frame[15], 16
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        etype, off = (frame[0] << 8) | frame[1], 20
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        version = frame[0] >> 4 if frame else 0
        etype = 0x0800 if version == 4 else 0x86DD if version == 6 else 0
    else:
        return None
    if etype == 0x0800 and len(frame) >= off + 20:
        a, b = frame[off + 12 : off + 16], frame[off + 16 : off + 20]
    elif etype == 0x86DD and len(frame) >= off + 40:
        a, b = frame[off + 8 : off + 24], frame[off + 24 : off + 40]
    else:
        return None
    return a + b if a <= b else b + a


def partition_of(key: bytes | None, n: int) -> int:
    return 0 if key is None else zlib.crc32(key) % n


@dataclass
class Partition:
    write: Callable[[bytes], None]
    frames: list[int] = field(default_factory=list)  # original frame number of each packet written
    started_section: int = -1  # pcapng: last section whose preamble this partition received
    interfaces_sent: int = 0  # pcapng: IDBs of the current section already written


def split(
    fh: BinaryIO, writers: list[Callable[[bytes], None]], on_packet: Callable[[int], None] | None = None
) -> list[list[int]]:
    """Stream the capture in ``fh`` to the writers. Returns each partition's original frame numbers.

    ``on_packet(i)`` is called after each packet is written to partition ``i``, in file order.
    """
    head = fh.read(4)
    fmt = capture_format(head)
    parts = [Partition(w) for w in writers]
    notify = on_packet or (lambda i: None)
    if fmt == "pcap":
        _split_pcap(fh, head, parts, notify)
    elif fmt == "pcapng":
        _split_pcapng(fh, head, parts, notify)
    else:
        raise SplitUnsupported(f"cannot split {fmt} captures")
    return [p.frames for p in parts]


def _read_exact(fh: BinaryIO, n: int) -> bytes:
    data = fh.read(n)
    if len(data) < n:
        raise EOFError
    return data


def _split_pcap(fh: BinaryIO, magic: bytes, parts: list[Partition], notify: Callable[[int], None]) -> None:
    endian = PCAP_MAGICS[magic]
    rest = fh.read(20)
    if len(rest) < 20:
        raise SplitUnsupported("truncated pcap header")
    header = magic + rest
    linktype = struct.unpack(endian + "I", rest[16:20])[0] & 0x0FFFFFFF
    for p in parts:
        p.write(header)
    rec = struct.Struct(endian + "IIII")
    frame_no = 0
    while True:
        hdr = fh.read(16)
        if len(hdr) < 16:
            break
        incl = rec.unpack(hdr)[2]
        data = fh.read(incl)
        frame_no += 1
        i = partition_of(_ip_pair_key(linktype, data), len(parts))
        parts[i].write(hdr + data)
        parts[i].frames.append(frame_no)
        notify(i)
        if len(data) < incl:
            break  # truncated final record: pass it on, tshark reports it


def _iter_pcapng_blocks(fh: BinaryIO, first4: bytes) -> Iterator[tuple[int, bytes, str]]:
    """Yield (block_type, raw_block_bytes, endian)."""
    endian = "<"
    pending = first4
    while True:
        head = pending + fh.read(8 - len(pending)) if pending else fh.read(8)
        pending = b""
        if len(head) < 8:
            return
        btype_le = struct.unpack("<I", head[:4])[0]
        if btype_le == PCAPNG_SHB:
            bom = fh.read(4)
            if len(bom) < 4:
                return
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", head[4:8])[0]
            body = fh.read(blen - 12)
            yield PCAPNG_SHB, head + bom + body, endian
            continue
        btype, blen = struct.unpack(endian + "II", head)
        if blen < 12:
            raise SplitUnsupported("corrupt pcapng block length")
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            yield btype, head + body, endian  # truncated tail
            return
        yield btype, head + body, endian


def _split_pcapng(fh: BinaryIO, first4: bytes, parts: list[Partition], notify: Callable[[int], None]) -> None:
    section = -1
    preamble: list[bytes] = []  # SHB + IDBs (+ other non-packet blocks) of the current section
    linktypes: list[int] = []
    frame_no = 0

    def catch_up(p: Partition) -> None:
        """Give a partition the current section's preamble before its first packet in that section."""
        if p.started_section != section:
            for blk in preamble:
                p.write(blk)
            p.started_section = section
            p.interfaces_sent = len(linktypes)

    for btype, raw, endian in _iter_pcapng_blocks(fh, first4):
        if btype == PCAPNG_SHB:
            section += 1
            preamble = [raw]
            linktypes = []
            continue
        if btype == PCAPNG_IDB:
            linktypes.append(struct.unpack(endian + "H", raw[8:10])[0])
            preamble.append(raw)
            for p in parts:  # partitions already in this section need the new interface too
                if p.started_section == section:
                    p.write(raw)
                    p.interfaces_sent = len(linktypes)
            continue
        if btype in (PCAPNG_EPB, PCAPNG_SPB, PCAPNG_OPB):
            frame_no += 1
            if btype == PCAPNG_EPB:
                iface = struct.unpack(endian + "I", raw[8:12])[0]
                caplen = struct.unpack(endian + "I", raw[20:24])[0]
                data = raw[28 : 28 + caplen]
            elif btype == PCAPNG_SPB:
                iface, data = 0, raw[12:-4]
            else:
                iface = struct.unpack(endian + "H", raw[8:10])[0]
                caplen = struct.unpack(endian + "I", raw[20:24])[0]
                data = raw[28 : 28 + caplen]
            lt = linktypes[iface] if iface < len(linktypes) else -1
            i = partition_of(_ip_pair_key(lt, data), len(parts))
            catch_up(parts[i])
            parts[i].write(raw)
            parts[i].frames.append(frame_no)
            notify(i)
            continue
        # Name resolution, interface statistics, decryption secrets, custom blocks: everyone gets them.
        preamble.append(raw)
        for p in parts:
            if p.started_section == section:
                p.write(raw)
    for p in parts:
        catch_up(p)  # partitions that got no packets still need valid headers
