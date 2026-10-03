"""Metadata extraction: built-in parsers and optional external tools.

Built-in parsers (no dependencies) cover EXIF (JPEG, TIFF, PNG eXIf, WebP),
GPS, PNG text chunks, XMP packets in any file, RIFF INFO (WAV/AVI),
QuickTime/MP4 user data and ISO 6709 locations, PDF info dictionaries and
compressed page text (best effort), and Office/OpenDocument properties.

Every parser here sees untrusted bytes, so each one does a bounded amount of
work per input byte: forward-only searches with a cursor, no regular
expression that can rescan the rest of the input from every start position,
and capped slices.

When ``exiftool``, ``ffprobe`` or ``pdfinfo`` are installed they are used as
well; their results are merged and de-duplicated by the scanner.
"""

from __future__ import annotations

import html
import json
import re
import shutil
import struct
import subprocess
import zlib
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

AUTHOR = "author"
LOCATION = "location"
SERIAL = "serial"
TEXT = "text"

# One XML tag. "[^<>]*" cannot run past the next "<", so stripping tags stays
# linear even for input such as "<<<<<<...".
_TAG = re.compile(r"<[^<>]*>")


@dataclass
class MetaField:
    name: str
    value: str
    kind: str = TEXT


_AUTHOR_KEYS = {
    "artist", "author", "authors", "creator", "by-line", "byline", "writer-editor", "writer", "ownername",
    "owner", "cameraownername", "lastmodifiedby", "company", "manager", "hostcomputer", "xpauthor",
    "authorsposition", "credit", "initial-creator", "album_artist", "albumartist", "composer",
    "performer", "encoded_by", "encodedby", "com.apple.quicktime.author", "com.apple.quicktime.artist",
    "creatorcontactinfo", "creatorworkemail", "creatorworktelephone", "contact", "creatoraddress",
    "lastsavedby", "usercomment-author", "engineer", "technician", "copyrightowner",
}
_LOCATION_KEYS = {
    "gpslatitude", "gpslongitude", "gpsposition", "gpscoordinates", "location", "location-eng",
    "iso6709", "com.apple.quicktime.location.iso6709", "xyz", "gpsdestlatitude", "gpsdestlongitude",
}
_SERIAL_KEYS = {"serialnumber", "bodyserialnumber", "lensserialnumber", "internalserialnumber",
                "cameraserialnumber", "camera serial number"}
_AUTHOR_PLACEHOLDERS = {
    "", "user", "owner", "admin", "administrator", "unknown", "microsoft office user", "author", "none",
    "n/a", "-", "default", "windows user", "nobody", "root", "anonymous", "<unknown>", "(none)",
}


def classify(key: str, group: str = "") -> str:
    k = key.split(":")[-1].strip().lower()
    if k == "creator" and group.upper() in ("PDF", "XMP-PDF", "XMP-XMP"):
        return TEXT  # the producing application, not a person
    if k in _LOCATION_KEYS or k.endswith(".location.iso6709"):
        return LOCATION
    if k in _SERIAL_KEYS:
        return SERIAL
    if k in _AUTHOR_KEYS:
        return AUTHOR
    return TEXT


def is_placeholder_author(value: str) -> bool:
    return value.strip().lower() in _AUTHOR_PLACEHOLDERS


def meaningful_location(value: str) -> bool:
    numbers = [float(x) for x in re.findall(r"[-+]?\d+(?:\.\d+)?", value)]
    return bool(numbers) and any(abs(n) > 1e-6 for n in numbers[:2])


# ---------------------------------------------------------------------------
# TIFF / EXIF

_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
_IFD0_TAGS = {
    0x010E: ("ImageDescription", TEXT), 0x0131: ("Software", TEXT), 0x013B: ("Artist", AUTHOR),
    0x013C: ("HostComputer", AUTHOR), 0x8298: ("Copyright", TEXT), 0x9C9B: ("XPTitle", TEXT),
    0x9C9C: ("XPComment", TEXT), 0x9C9D: ("XPAuthor", AUTHOR), 0x9C9E: ("XPKeywords", TEXT),
    0x9C9F: ("XPSubject", TEXT),
}
_EXIF_TAGS = {
    0x9286: ("UserComment", TEXT), 0xA430: ("CameraOwnerName", AUTHOR),
    0xA431: ("BodySerialNumber", SERIAL), 0xA435: ("LensSerialNumber", SERIAL),
}
# Tags whose values the parser reads: text tags, the EXIF and GPS pointers and
# the four GPS position tags (which share numbers with nothing above).
_WANTED_TAGS = frozenset(_IFD0_TAGS) | frozenset(_EXIF_TAGS) | {0x8769, 0x8825, 1, 2, 3, 4}
_MAX_TAG_BYTES = 64 * 1024


def _ascii(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def parse_tiff(data: bytes) -> List[MetaField]:
    if len(data) < 8:
        return []
    order = data[:2]
    if order == b"II":
        e = "<"
    elif order == b"MM":
        e = ">"
    else:
        return []
    try:
        magic, ifd0 = struct.unpack(e + "HI", data[2:8])
    except struct.error:
        return []
    if magic != 42:
        return []
    visited: set = set()

    def read_ifd(offset: int) -> Dict[int, Tuple[int, int, bytes]]:
        out: Dict[int, Tuple[int, int, bytes]] = {}
        if offset in visited or offset < 8 or offset + 2 > len(data):
            return out
        visited.add(offset)
        (count,) = struct.unpack(e + "H", data[offset:offset + 2])
        for i in range(min(count, 1000)):
            p = offset + 2 + 12 * i
            if p + 12 > len(data):
                break
            tag, typ, n = struct.unpack(e + "HHI", data[p:p + 8])
            size = _TYPE_SIZES.get(typ)
            if size is None or n > 1_000_000 or tag not in _WANTED_TAGS:
                continue  # only copy the values that are read below
            total = size * n
            if total <= 4:
                raw = data[p + 8:p + 8 + total]
            else:
                (voff,) = struct.unpack(e + "I", data[p + 8:p + 12])
                if voff + total > len(data):
                    continue
                raw = data[voff:voff + min(total, _MAX_TAG_BYTES)]
            out[tag] = (typ, n, raw)
        return out

    def text_value(tag: int, typ: int, raw: bytes) -> str:
        if 0x9C9B <= tag <= 0x9C9F:
            return raw.decode("utf-16-le", "replace").split("\x00", 1)[0].strip()
        if tag == 0x9286:
            code, body = raw[:8], raw[8:]
            if code.startswith(b"UNICODE"):
                enc = "utf-16-be" if e == ">" else "utf-16-le"
                return body.decode(enc, "replace").split("\x00", 1)[0].strip()
            return body.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        if typ == 2:
            return _ascii(raw)
        if typ in (1, 7):
            return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        return ""

    fields: List[MetaField] = []
    ifd = read_ifd(ifd0)
    for tag, (name, kind) in _IFD0_TAGS.items():
        if tag in ifd:
            value = text_value(tag, ifd[tag][0], ifd[tag][2])
            if value:
                fields.append(MetaField(f"EXIF {name}", value, kind))
    if 0x8769 in ifd:
        typ, n, raw = ifd[0x8769]
        if len(raw) >= 4:
            sub = read_ifd(struct.unpack(e + "I", raw[:4])[0])
            for tag, (name, kind) in _EXIF_TAGS.items():
                if tag in sub:
                    value = text_value(tag, sub[tag][0], sub[tag][2])
                    if value:
                        fields.append(MetaField(f"EXIF {name}", value, kind))
    if 0x8825 in ifd:
        typ, n, raw = ifd[0x8825]
        if len(raw) >= 4:
            gps = read_ifd(struct.unpack(e + "I", raw[:4])[0])
            lat = _gps_coord(gps, 1, 2, e)
            lon = _gps_coord(gps, 3, 4, e)
            if lat is not None and lon is not None and (abs(lat) > 1e-6 or abs(lon) > 1e-6):
                fields.append(MetaField("EXIF GPS position", f"{lat:.6f}, {lon:.6f}", LOCATION))
    return fields


def _gps_coord(gps: Dict[int, Tuple[int, int, bytes]], ref_tag: int, tag: int, e: str) -> Optional[float]:
    if tag not in gps:
        return None
    typ, n, raw = gps[tag]
    if typ != 5 or n < 3 or len(raw) < 24:
        return None
    parts = struct.unpack(e + "6I", raw[:24])
    values = []
    for num, den in zip(parts[0::2], parts[1::2]):
        values.append(num / den if den else 0.0)
    coord = values[0] + values[1] / 60 + values[2] / 3600
    ref = _ascii(gps[ref_tag][2]) if ref_tag in gps else ""
    if ref in ("S", "W"):
        coord = -coord
    return coord


# ---------------------------------------------------------------------------
# Container walkers

def _jpeg(data: bytes) -> List[MetaField]:
    fields: List[MetaField] = []
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            break
        marker = data[i + 1]
        if marker in (0xD9, 0xDA):
            break
        if 0xD0 <= marker <= 0xD7 or marker in (0x01, 0xFF):
            i += 1 if marker == 0xFF else 2
            continue
        (length,) = struct.unpack(">H", data[i + 2:i + 4])
        payload = data[i + 4:i + 2 + length]
        if marker == 0xE1 and payload.startswith(b"Exif\x00\x00"):
            fields.extend(parse_tiff(payload[6:]))
        elif marker == 0xFE:
            text = payload.decode("utf-8", "replace").strip("\x00 \r\n")
            if text:
                fields.append(MetaField("JPEG comment", text, TEXT))
        i += 2 + length
    return fields


def _png(data: bytes) -> List[MetaField]:
    fields: List[MetaField] = []
    i = 8
    for _ in range(100000):
        if i + 8 > len(data):
            break
        (length,) = struct.unpack(">I", data[i:i + 4])
        ctype = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + length]
        i += 12 + length
        try:
            if ctype == b"tEXt":
                key, _, value = body.partition(b"\x00")
                fields.extend(_png_field(key, value.decode("latin-1")))
            elif ctype == b"zTXt":
                key, _, rest = body.partition(b"\x00")
                fields.extend(_png_field(key, _inflate(rest[1:]).decode("latin-1")))
            elif ctype == b"iTXt":
                key, _, rest = body.partition(b"\x00")
                compressed, rest = rest[0], rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _tkey, _, value = rest.partition(b"\x00")
                if compressed:
                    value = _inflate(value)
                fields.extend(_png_field(key, value.decode("utf-8", "replace")))
            elif ctype == b"eXIf":
                fields.extend(parse_tiff(body))
            elif ctype == b"IEND":
                break
        except (IndexError, zlib.error, ValueError):
            continue
    return [f for f in fields if f.value.strip()]


def _png_field(key: bytes, value: str) -> List[MetaField]:
    name = key.decode("latin-1", "replace")
    if name == "XML:com.adobe.xmp":
        return xmp_fields(value)
    kind = AUTHOR if name.lower() in ("author", "artist") else TEXT
    return [MetaField(f"PNG {name}", value.strip(), kind)]


def _inflate(data: bytes, limit: int = 8 * 1024 * 1024) -> bytes:
    return zlib.decompressobj().decompress(data, limit)


_RIFF_INFO = {
    b"IART": ("Artist", AUTHOR), b"IENG": ("Engineer", AUTHOR), b"ITCH": ("Technician", AUTHOR),
    b"ICMT": ("Comment", TEXT), b"INAM": ("Title", TEXT), b"ICOP": ("Copyright", TEXT),
    b"ISFT": ("Software", TEXT), b"IKEY": ("Keywords", TEXT), b"ISBJ": ("Subject", TEXT),
}


def _riff(data: bytes) -> List[MetaField]:
    fields: List[MetaField] = []
    if len(data) < 12:
        return fields

    def walk(start: int, end: int, depth: int) -> None:
        i = start
        while i + 8 <= end and depth < 4:
            fourcc = data[i:i + 4]
            (size,) = struct.unpack("<I", data[i + 4:i + 8])
            body = data[i + 8:min(end, i + 8 + size)]
            if fourcc == b"EXIF":
                fields.extend(parse_tiff(body[6:] if body.startswith(b"Exif\x00\x00") else body))
            elif fourcc == b"LIST" and body[:4] == b"INFO":
                j = 4
                while j + 8 <= len(body):
                    sub = body[j:j + 4]
                    (ssize,) = struct.unpack("<I", body[j + 4:j + 8])
                    value = body[j + 8:j + 8 + ssize].split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
                    if sub in _RIFF_INFO and value:
                        name, kind = _RIFF_INFO[sub]
                        fields.append(MetaField(f"RIFF {name}", value, kind))
                    j += 8 + ssize + (ssize & 1)
            elif fourcc == b"LIST":
                walk(i + 12, min(end, i + 8 + size), depth + 1)
            i += 8 + size + (size & 1)

    walk(12, len(data), 0)
    return fields


_ISO6709 = re.compile(rb"[+-]\d{2}(?:\.\d{2,})?[+-]\d{3}(?:\.\d{2,})?(?:[+-]\d+(?:\.\d+)?)?(?:CRS[A-Za-z0-9:]+)?/")
_QT_ATOMS = {
    b"\xa9ART": ("Artist", AUTHOR), b"\xa9aut": ("Author", AUTHOR), b"\xa9wrt": ("Composer", AUTHOR),
    b"\xa9cmt": ("Comment", TEXT), b"\xa9nam": ("Title", TEXT), b"\xa9xyz": ("Location", LOCATION),
    b"\xa9des": ("Description", TEXT), b"\xa9inf": ("Information", TEXT),
}


def _isobmff(data: bytes) -> List[MetaField]:
    fields: List[MetaField] = []
    seen = set()
    for m in _ISO6709.finditer(data):
        value = m.group().decode("ascii", "replace")
        if value not in seen and meaningful_location(value):
            seen.add(value)
            fields.append(MetaField("QuickTime ISO 6709 location", value, LOCATION))
    for atom, (name, kind) in _QT_ATOMS.items():
        start = 0
        for _ in range(10000):
            i = data.find(atom, start)
            if i == -1 or i < 4:
                break
            start = i + 4
            value = ""
            if data[i + 8:i + 12] == b"data" and i + 16 <= len(data):
                (child,) = struct.unpack(">I", data[i + 4:i + 8])
                end = i + 4 + min(child, 4096)
                value = data[i + 16:end].decode("utf-8", "replace")
                start = max(start, end)  # never re-read a value: work stays linear in the input
            elif i + 8 <= len(data):
                (length,) = struct.unpack(">H", data[i + 4:i + 6])
                if 0 < length < 4096:
                    value = data[i + 8:i + 8 + length].decode("utf-8", "replace")
                    start = i + 8 + length
            value = value.strip("\x00 ")
            if value and value.isprintable() and value not in seen:
                seen.add(value)
                if kind == LOCATION and not meaningful_location(value):
                    continue
                fields.append(MetaField(f"QuickTime {name}", value, kind))
    return fields


# ---------------------------------------------------------------------------
# XMP

_XMP_OPEN = b"<x:xmpmeta"
_XMP_CLOSE = b"</x:xmpmeta>"
_XMP_MAX_PACKET = 4 * 1024 * 1024
_XMP_ELEMENTS = {
    "dc:creator": AUTHOR, "pdf:Author": AUTHOR, "xmpRights:Owner": AUTHOR, "photoshop:AuthorsPosition": AUTHOR,
    "photoshop:Credit": AUTHOR, "exifEX:CameraOwnerName": AUTHOR, "Iptc4xmpCore:CreatorContactInfo": AUTHOR,
    "aux:OwnerName": AUTHOR, "exif:GPSLatitude": LOCATION, "exif:GPSLongitude": LOCATION,
    "aux:SerialNumber": SERIAL, "exifEX:BodySerialNumber": SERIAL, "exifEX:LensSerialNumber": SERIAL,
    "stRef:filePath": TEXT, "dc:description": TEXT, "dc:title": TEXT, "dc:subject": TEXT,
    "photoshop:City": TEXT, "photoshop:State": TEXT, "photoshop:Country": TEXT, "Iptc4xmpCore:Location": TEXT,
    "xmp:CreatorTool": TEXT, "pdf:Keywords": TEXT, "dc:rights": TEXT,
}


def xmp_packets(data: bytes, limit: int = 32) -> List[str]:
    """XMP packets (``<x:xmpmeta ...>...</x:xmpmeta>``) found anywhere in *data*.

    A forward scan with a cursor: an opening tag without a closing tag ends
    the search instead of being retried from every later start position.
    """
    out: List[str] = []
    pos = 0
    while len(out) < limit:
        i = data.find(_XMP_OPEN, pos)
        if i == -1:
            break
        after = data[i + len(_XMP_OPEN):i + len(_XMP_OPEN) + 1]
        if not after or after not in b" \t\r\n\f\v>":
            pos = i + len(_XMP_OPEN)
            continue
        j = data.find(_XMP_CLOSE, i)
        if j == -1:
            break
        end = j + len(_XMP_CLOSE)
        if end - i <= _XMP_MAX_PACKET:
            out.append(data[i:end].decode("utf-8", "replace"))
        pos = end
    return out


def element_values(xml: str, name: str) -> Iterator[Tuple[str, str]]:
    """``(opening tag, inner XML)`` for every non-empty ``<name>...</name>`` element.

    Linear in the input: after an element the search continues behind its
    closing tag, and an opening tag without any closing tag ends the search.
    """
    opening = re.compile(r"<" + re.escape(name) + r"(?=[\s/>])[^<>]*>")
    close = "</" + name + ">"
    pos = 0
    while True:
        m = opening.search(xml, pos)
        if m is None:
            return
        if m.group().endswith("/>"):
            pos = m.end()
            continue
        end = xml.find(close, m.end())
        if end == -1:
            return
        yield m.group(), xml[m.end():end]
        pos = end + len(close)


def xmp_fields(xml: str) -> List[MetaField]:
    fields: List[MetaField] = []
    for name, kind in _XMP_ELEMENTS.items():
        for _, inner in element_values(xml, name):
            value = html.unescape(_TAG.sub(" ", inner))
            value = re.sub(r"\s+", " ", value).strip()
            if value:
                fields.append(MetaField(f"XMP {name}", value, kind))
        for m in re.finditer(r"\b" + re.escape(name) + r"=\"([^\"<>]*)\"", xml):
            value = html.unescape(m.group(1)).strip()
            if value:
                fields.append(MetaField(f"XMP {name}", value, kind))
    return [f for f in fields if not (f.kind == LOCATION and not meaningful_location(f.value))]


# ---------------------------------------------------------------------------
# PDF

_PDF_INFO = re.compile(
    rb"/(Author|Creator|Producer|Title|Subject|Keywords|Company|Manager|SourceModified)\s*"
    rb"(\((?:\\.|[^\\()]|\((?:\\.|[^\\()])*\))*\)|<[0-9A-Fa-f\s]*>)",
    re.DOTALL,
)
_PDF_STREAM = re.compile(rb"stream\r?\n")
_PDF_LITERAL = re.compile(rb"\((?:\\.|[^\\()]|\((?:\\.|[^\\()])*\))*\)", re.DOTALL)
_PDF_KIND = {b"Author": AUTHOR, b"Company": AUTHOR, b"Manager": AUTHOR}


def _pdf_bytes_to_text(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


def pdf_literal(raw: bytes) -> str:
    body = raw[1:-1]
    out = bytearray()
    i = 0
    escapes = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
    while i < len(body):
        c = body[i]
        if c == 0x5C and i + 1 < len(body):
            n = body[i + 1]
            if n in escapes:
                out.append(escapes[n])
                i += 2
            elif 0x30 <= n <= 0x37:
                j = i + 1
                digits = b""
                while j < len(body) and len(digits) < 3 and 0x30 <= body[j] <= 0x37:
                    digits += bytes([body[j]])
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
            elif n in (0x0D, 0x0A):
                i += 2
                if n == 0x0D and i < len(body) and body[i] == 0x0A:
                    i += 1
            else:
                out.append(n)
                i += 2
        else:
            out.append(c)
            i += 1
    return _pdf_bytes_to_text(bytes(out))


def _pdf_value(raw: bytes) -> str:
    if raw.startswith(b"<"):
        digits = re.sub(rb"[^0-9A-Fa-f]", b"", raw)
        if len(digits) % 2:
            digits += b"0"
        try:
            return _pdf_bytes_to_text(bytes.fromhex(digits.decode("ascii")))
        except ValueError:
            return ""
    return pdf_literal(raw)


def pdf_extract(data: bytes, max_output: int = 32 * 1024 * 1024,
                max_streams: int = 20000) -> Tuple[List[MetaField], str]:
    """Info-dictionary fields and a best-effort text view of a PDF.

    Streams are visited once, front to back: the search for the next stream
    starts after the previous ``endstream``, so crafted input cannot make it
    rescan the file from every ``stream`` keyword.
    """
    blobs = [data]
    total = 0
    view = memoryview(data)
    pos = 0
    for _ in range(max_streams):
        m = _PDF_STREAM.search(data, pos)
        if m is None:
            break
        start = m.end()
        end = data.find(b"endstream", start)
        if end == -1:
            break
        pos = end + len(b"endstream")
        try:
            out = zlib.decompressobj().decompress(view[start:end], max(1, max_output - total))
        except zlib.error:
            continue
        if out:
            blobs.append(out)
            total += len(out)
            if total >= max_output:
                break
    fields: List[MetaField] = []
    seen = set()
    for blob in blobs:
        for m in _PDF_INFO.finditer(blob):
            value = _pdf_value(m.group(2)).strip()
            key = m.group(1)
            if value and (key, value) not in seen:
                seen.add((key, value))
                fields.append(MetaField(f"PDF {key.decode()}", value, _PDF_KIND.get(key, TEXT)))
    lines: List[str] = []
    for blob in blobs[1:]:
        if b"Tj" not in blob and b"TJ" not in blob:
            continue
        for raw_line in blob.split(b"\n"):
            if b"(" not in raw_line:
                continue
            parts = [pdf_literal(m.group()) for m in _PDF_LITERAL.finditer(raw_line)]
            text = "".join(parts).strip()
            if text:
                lines.append(text)
    return fields, "\n".join(lines)


# ---------------------------------------------------------------------------
# Office / OpenDocument

OFFICE_TEXT_PARTS = re.compile(
    r"^(?:word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
    r"|ppt/(?:slides/slide|notesSlides/notesSlide|comments/comment|comments/modernComment_)[^/]*\.xml"
    r"|xl/(?:sharedStrings|comments\d*|threadedComments/threadedComment\d*)\.xml"
    r"|content\.xml)$"
)
_PARA_END = re.compile(r"</(?:w:p|a:p|text:p|text:h|si|row|w:tr|p:txBody)>")
_BREAKS = re.compile(r"<(?:w:tab|w:br|a:br|text:tab|text:line-break)\b[^<>]*/>")
# The lookbehind makes every attempt start at the beginning of a name, so a
# long run of name characters is scanned once, not once per position.
_ATTRIBUTE = re.compile(r"(?<![\w:.-])([A-Za-z_][\w:.-]*)\s*=\s*(?:\"([^\"<>]*)\"|'([^'<>]*)')")
_CORE = {
    "dc:creator": AUTHOR, "cp:lastModifiedBy": AUTHOR, "dc:title": TEXT, "dc:subject": TEXT,
    "dc:description": TEXT, "cp:keywords": TEXT, "cp:category": TEXT, "cp:contentStatus": TEXT,
}
_APP = {"Company": AUTHOR, "Manager": AUTHOR, "HyperlinkBase": TEXT, "Template": TEXT}
_ODF = {"meta:initial-creator": AUTHOR, "dc:creator": AUTHOR, "dc:title": TEXT, "dc:description": TEXT,
        "dc:subject": TEXT, "meta:keyword": TEXT}
_AUTHOR_ATTRS = re.compile(r"\b(?:w:author|w15:author|author|displayName|name)=\"([^\"]{1,200})\"")
_AUTHOR_ATTR_PARTS = re.compile(r"^(?:word/(?:comments|people|document)|ppt/(?:commentAuthors|authors)|xl/persons/person)[^/]*\.xml$")


def xml_text(xml: str) -> str:
    """The character data of an XML document, one paragraph per line."""
    text = _PARA_END.sub("\n", xml)
    text = _BREAKS.sub(" ", text)
    text = _TAG.sub("", text)
    return html.unescape(text)


def xml_attribute_text(xml: str) -> str:
    """Every attribute value of an XML document, one per line.

    Alt text, bookmark names, field instructions and custom property names
    live in attributes, which :func:`xml_text` drops. Namespace declarations
    are left out.
    """
    values: List[str] = []
    for tag in _TAG.finditer(xml):
        for m in _ATTRIBUTE.finditer(tag.group()):
            name = m.group(1)
            if name == "xmlns" or name.startswith("xmlns:"):
                continue
            value = m.group(2) if m.group(2) is not None else m.group(3)
            value = html.unescape(value).strip()
            if value:
                values.append(value)
    return "\n".join(values)


def xml_property_text(xml: str) -> str:
    """Element text and attribute values of a document-properties part."""
    parts = [xml_text(xml).strip(), xml_attribute_text(xml)]
    return "\n".join(p for p in parts if p)


def _elements(xml: str, table: Dict[str, str], source: str) -> List[MetaField]:
    out: List[MetaField] = []
    for name, kind in table.items():
        for _, inner in element_values(xml, name):
            value = html.unescape(_TAG.sub("", inner)).strip()
            if value:
                out.append(MetaField(f"{source} {name}", value, kind))
    return out


_NAME_ATTR = re.compile(r"\bname=\"([^\"<>]*)\"")


def office_fields(read: Callable[[str], Optional[str]], names: Sequence[str]) -> List[MetaField]:
    """Author, location and other named fields of an Office/ODF document.

    Used to classify values (an author is reported as metadata.author); the
    scanner also checks the full text of every property part.
    """
    fields: List[MetaField] = []
    core = read("docProps/core.xml")
    if core:
        fields.extend(_elements(core, _CORE, "docProps/core.xml"))
    app = read("docProps/app.xml")
    if app:
        fields.extend(_elements(app, _APP, "docProps/app.xml"))
    custom = read("docProps/custom.xml")
    if custom:
        for tag, inner in element_values(custom, "property"):
            m = _NAME_ATTR.search(tag)
            value = html.unescape(_TAG.sub("", inner)).strip()
            if m and value:
                fields.append(MetaField(f"docProps/custom.xml {html.unescape(m.group(1))}", value, TEXT))
    meta = read("meta.xml")
    if meta:
        fields.extend(_elements(meta, _ODF, "meta.xml"))
    for name in names:
        if _AUTHOR_ATTR_PARTS.match(name):
            xml = read(name)
            if not xml:
                continue
            for m in _AUTHOR_ATTRS.finditer(xml):
                value = html.unescape(m.group(1)).strip()
                if value:
                    fields.append(MetaField(f"{name} author", value, AUTHOR))
            for _, inner in element_values(xml, "author"):
                value = html.unescape(inner).strip()
                if value:
                    fields.append(MetaField(f"{name} author", value, AUTHOR))
    return fields


# ---------------------------------------------------------------------------
# Dispatch for built-in parsers

def builtin_fields(data: bytes, kind: str) -> List[MetaField]:
    fields: List[MetaField] = []
    try:
        if kind == "jpeg":
            fields.extend(_jpeg(data))
        elif kind == "png":
            fields.extend(_png(data))
        elif kind == "tiff":
            fields.extend(parse_tiff(data))
        elif kind in ("webp", "riff-audio", "riff-video"):
            fields.extend(_riff(data))
        elif kind in ("isobmff", "heif"):
            fields.extend(_isobmff(data))
    except (struct.error, IndexError, ValueError):
        pass
    for packet in xmp_packets(data):
        fields.extend(xmp_fields(packet))
    return fields


# ---------------------------------------------------------------------------
# External tools

_EXIFTOOL_SKIP_GROUPS = {"ExifTool", "System", "File", "Composite"}


class Tools:
    """Optional external metadata tools. All of them are read-only."""

    def __init__(self, enabled: bool = True, timeout: int = 300) -> None:
        self.exiftool = shutil.which("exiftool") if enabled else None
        self.ffprobe = shutil.which("ffprobe") if enabled else None
        self.pdfinfo = shutil.which("pdfinfo") if enabled else None
        self.timeout = timeout
        self.failures: Counter = Counter()
        self.runs: Counter = Counter()

    def available(self) -> List[str]:
        return [n for n in ("exiftool", "ffprobe", "pdfinfo") if getattr(self, n)]

    def _run(self, cmd: List[str], tool: str) -> Optional[bytes]:
        try:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            self.failures[tool] += 1
            return None
        self.runs[tool] += 1
        if p.returncode not in (0, 1) or not p.stdout.strip():
            if p.returncode not in (0, 1):
                self.failures[tool] += 1
            return None
        return p.stdout

    def exiftool_batch(self, paths: Sequence[str]) -> Dict[str, List[MetaField]]:
        results: Dict[str, List[MetaField]] = {}
        if not self.exiftool:
            return results
        for i in range(0, len(paths), 200):
            chunk = list(paths[i:i + 200])
            out = self._run([self.exiftool, "-json", "-G1", "-a", "-n", "-q", "-q", "-charset", "filename=utf8",
                             *chunk], "exiftool")
            if out is None:
                continue
            try:
                items = json.loads(out.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                self.failures["exiftool"] += 1
                continue
            for item in items if isinstance(items, list) else []:
                src = item.get("SourceFile")
                if not isinstance(src, str):
                    continue
                fields: List[MetaField] = []
                for key, value in item.items():
                    if key == "SourceFile" or ":" not in key:
                        continue
                    group, tag = key.split(":", 1)
                    if group in _EXIFTOOL_SKIP_GROUPS:
                        continue
                    text = _flatten(value)
                    if not text or text.startswith("(Binary data") or text.startswith("base64:"):
                        continue
                    fields.append(MetaField(f"exiftool {key}", text, classify(tag, group)))
                results[src] = fields
        return results

    def ffprobe_fields(self, path: str) -> List[MetaField]:
        if not self.ffprobe:
            return []
        out = self._run([self.ffprobe, "-v", "error", "-print_format", "json", "-show_format", "-show_streams",
                         "-show_chapters", "file:" + path], "ffprobe")
        if out is None:
            return []
        try:
            data = json.loads(out.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            self.failures["ffprobe"] += 1
            return []
        fields: List[MetaField] = []

        def add(prefix: str, tags: object) -> None:
            if isinstance(tags, dict):
                for key, value in tags.items():
                    text = _flatten(value)
                    if text:
                        fields.append(MetaField(f"ffprobe {prefix}{key}", text, classify(str(key))))

        fmt = data.get("format") if isinstance(data, dict) else None
        if isinstance(fmt, dict):
            add("format:", fmt.get("tags"))
        for i, stream in enumerate(data.get("streams") or [] if isinstance(data, dict) else []):
            if isinstance(stream, dict):
                add(f"stream{i}:", stream.get("tags"))
        for i, chapter in enumerate(data.get("chapters") or [] if isinstance(data, dict) else []):
            if isinstance(chapter, dict):
                add(f"chapter{i}:", chapter.get("tags"))
        return fields

    def pdfinfo_fields(self, path: str) -> List[MetaField]:
        if not self.pdfinfo:
            return []
        out = self._run([self.pdfinfo, "-enc", "UTF-8", path], "pdfinfo")
        if out is None:
            return []
        fields: List[MetaField] = []
        for line in out.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition(":")
            if not sep:
                continue
            key, value = key.strip(), value.strip()
            if key in ("Author", "Creator", "Producer", "Title", "Subject", "Keywords") and value:
                fields.append(MetaField(f"pdfinfo {key}", value, AUTHOR if key == "Author" else TEXT))
        return fields


def _flatten(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(_flatten(v) for v in value if v not in (None, ""))
    if isinstance(value, dict):
        return ", ".join(f"{k}={_flatten(v)}" for k, v in value.items())
    if value is None:
        return ""
    return str(value).strip()
