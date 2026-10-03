"""Tiny synthetic files for format tests: EXIF/TIFF, JPEG, PNG, WebP, MP4, PDF, DOCX, .DS_Store."""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile
import zlib
from typing import Dict, Iterable, List, Optional, Tuple

ASCII, LONG, RATIONAL = 2, 4, 5


def _entry(tag: int, typ: int, count: int, raw: bytes) -> Tuple[int, int, int, bytes]:
    return tag, typ, count, raw


def _ascii(tag: int, text: str) -> Tuple[int, int, int, bytes]:
    raw = text.encode() + b"\x00"
    return _entry(tag, ASCII, len(raw), raw)


def _rationals(tag: int, values: Iterable[Tuple[int, int]]) -> Tuple[int, int, int, bytes]:
    vals = list(values)
    raw = b"".join(struct.pack("<II", n, d) for n, d in vals)
    return _entry(tag, RATIONAL, len(vals), raw)


def _ifd(entries: List[Tuple[int, int, int, bytes]], offset: int) -> bytes:
    n = len(entries)
    data_off = offset + 2 + 12 * n + 4
    head = struct.pack("<H", n)
    extra = b""
    for tag, typ, count, raw in sorted(entries):
        if len(raw) <= 4:
            head += struct.pack("<HHI", tag, typ, count) + raw.ljust(4, b"\x00")
        else:
            head += struct.pack("<HHII", tag, typ, count, data_off + len(extra))
            extra += raw + (b"\x00" if len(raw) % 2 else b"")
    return head + struct.pack("<I", 0) + extra


def tiff(artist: Optional[str] = None, owner: Optional[str] = None, serial: Optional[str] = None,
         gps: Optional[Tuple[float, float]] = None) -> bytes:
    exif_entries = []
    if owner:
        exif_entries.append(_ascii(0xA430, owner))
    if serial:
        exif_entries.append(_ascii(0xA431, serial))
    gps_entries = []
    if gps:
        def dms(value: float) -> List[Tuple[int, int]]:
            value = abs(value)
            deg = int(value)
            minutes = int((value - deg) * 60)
            seconds = round(((value - deg) * 60 - minutes) * 60 * 100)
            return [(deg, 1), (minutes, 1), (seconds, 100)]
        lat, lon = gps
        gps_entries = [_ascii(1, "N" if lat >= 0 else "S"), _rationals(2, dms(lat)),
                       _ascii(3, "E" if lon >= 0 else "W"), _rationals(4, dms(lon))]
    base = []
    if artist:
        base.append(_ascii(0x013B, artist))
    pointers = []
    if exif_entries:
        pointers.append(0x8769)
    if gps_entries:
        pointers.append(0x8825)
    placeholder = base + [_entry(t, LONG, 1, struct.pack("<I", 0)) for t in pointers]
    ifd0_len = len(_ifd(placeholder, 8))
    offsets: Dict[int, int] = {}
    cursor = 8 + ifd0_len
    blocks = []
    for tag, entries in ((0x8769, exif_entries), (0x8825, gps_entries)):
        if entries:
            offsets[tag] = cursor
            block = _ifd(entries, cursor)
            blocks.append(block)
            cursor += len(block)
    ifd0 = _ifd(base + [_entry(t, LONG, 1, struct.pack("<I", offsets[t])) for t in pointers], 8)
    return b"II*\x00" + struct.pack("<I", 8) + ifd0 + b"".join(blocks)


def xmp(creator: str = "", extra: str = "") -> str:
    return ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'<dc:creator><rdf:Seq><rdf:li>{creator}</rdf:li></rdf:Seq></dc:creator>{extra}'
            '</rdf:Description></rdf:RDF></x:xmpmeta>')


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def jpeg(exif: Optional[bytes] = None, xmp_packet: Optional[str] = None, comment: Optional[str] = None) -> bytes:
    out = b"\xff\xd8"
    if exif is not None:
        out += _segment(0xE1, b"Exif\x00\x00" + exif)
    if xmp_packet is not None:
        out += _segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp_packet.encode())
    if comment is not None:
        out += _segment(0xFE, comment.encode())
    out += _segment(0xDA, b"\x01\x01\x00\x00\x3f\x00") + bytes(range(256)) * 4 + b"\xff\xd9"
    return out


def _chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)


def png(text: Iterable[Tuple[str, str, str]] = (), exif: Optional[bytes] = None) -> bytes:
    """text items: (kind, key, value) with kind tEXt, zTXt or iTXt (iTXt is compressed)."""
    out = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    for kind, key, value in text:
        if kind == "tEXt":
            out += _chunk(b"tEXt", key.encode("latin-1") + b"\x00" + value.encode("latin-1"))
        elif kind == "zTXt":
            out += _chunk(b"zTXt", key.encode("latin-1") + b"\x00\x00" + zlib.compress(value.encode("latin-1")))
        else:
            out += _chunk(b"iTXt", key.encode() + b"\x00\x01\x00" + b"en\x00" + b"\x00" + zlib.compress(value.encode()))
    if exif is not None:
        out += _chunk(b"eXIf", exif)
    out += _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + _chunk(b"IEND", b"")
    return out


def webp(exif: bytes) -> bytes:
    body = b"WEBP" + b"EXIF" + struct.pack("<I", len(exif)) + exif + (b"\x00" if len(exif) % 2 else b"")
    return b"RIFF" + struct.pack("<I", len(body)) + body


def _box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload) + 8) + kind + payload


def mp4(location: Optional[str] = None, artist: Optional[str] = None) -> bytes:
    ftyp = _box(b"ftyp", b"isom" + b"\x00\x00\x02\x00" + b"isomiso2mp41")
    udta = b""
    if location:
        loc = location.encode()
        udta += _box(b"\xa9xyz", struct.pack(">HH", len(loc), 0x15C7) + loc)
    if artist:
        data = _box(b"data", struct.pack(">II", 1, 0) + artist.encode())
        udta += _box(b"\xa9ART", data)
    moov = _box(b"moov", _box(b"udta", udta))
    mdat = _box(b"mdat", bytes(range(256)) * 16)
    return ftyp + mdat + moov


def pdf(author: str, title: str, page_text: List[str]) -> bytes:
    content = "BT /F1 12 Tf 72 712 Td " + "[" + "".join(f"({part})-20" for part in page_text) + "] TJ ET\n"
    stream = zlib.compress(content.encode("latin-1"))
    title_hex = (b"\xfe\xff" + title.encode("utf-16-be")).hex().upper()
    parts = [
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        b"3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n",
        b"4 0 obj << /Length " + str(len(stream)).encode() + b" /Filter /FlateDecode >> stream\n",
        stream,
        b"\nendstream endobj\n",
        b"5 0 obj << /Author (" + author.encode("latin-1") + b") /Title <" + title_hex.encode()
        + b"> /Producer (Example Writer 1.0) >> endobj\n",
        b"trailer << /Root 1 0 R /Info 5 0 R >>\n%%EOF\n",
    ]
    return b"".join(parts)


def docx(creator: str, modified_by: str, company: str, runs: List[str], comment_author: str,
         comment_text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        zf.writestr("docProps/core.xml",
                    '<cp:coreProperties xmlns:cp="cp" xmlns:dc="dc">'
                    f"<dc:creator>{creator}</dc:creator><cp:lastModifiedBy>{modified_by}</cp:lastModifiedBy>"
                    "</cp:coreProperties>")
        zf.writestr("docProps/app.xml", f"<Properties><Company>{company}</Company></Properties>")
        body = "".join(f"<w:r><w:t>{r}</w:t></w:r>" for r in runs)
        zf.writestr("word/document.xml", f"<w:document><w:body><w:p>{body}</w:p></w:body></w:document>")
        zf.writestr("word/comments.xml",
                    f'<w:comments><w:comment w:id="0" w:author="{comment_author}" w:initials="X">'
                    f"<w:p><w:r><w:t>{comment_text}</w:t></w:r></w:p></w:comment></w:comments>")
    return buf.getvalue()


def ds_store(names: Iterable[str]) -> bytes:
    out = b"\x00\x00\x00\x01Bud1" + b"\x00" * 16
    for name in names:
        out += struct.pack(">I", len(name)) + name.encode("utf-16-be") + b"Iloc" + b"\x00" * 8
    return out


def zip_bytes(members: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def mark_zip_member_encrypted(data: bytes) -> bytes:
    out = bytearray(data)
    for sig, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = out.find(sig)
        while i != -1:
            out[i + flag_offset] |= 0x01
            i = out.find(sig, i + 4)
    return bytes(out)


def tar_gz(members: Dict[str, bytes], symlinks: Dict[str, str] = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (symlinks or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()
