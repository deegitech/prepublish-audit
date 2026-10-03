"""File-type sniffing, text decoding and printable-string extraction."""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Tuple

TEXT_KINDS = ("text", "utf16")

_MAGIC: Tuple[Tuple[bytes, str], ...] = (
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\x00\x00\x00\x01Bud1", "ds_store"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"fLaC", "flac"),
    (b"\x1aE\xdf\xa3", "matroska"),
    (b"wOFF", "font"),
    (b"wOF2", "font"),
    (b"OTTO", "font"),
    (b"\xca\xfe\xba\xbe", "binary"),
    (b"\xcf\xfa\xed\xfe", "binary"),
    (b"\x7fELF", "binary"),
    (b"MZ", "binary"),
)

UNSUPPORTED_CONTAINERS = {"rar", "7z"}
UNSUPPORTED_EXTENSIONS = (".rar", ".7z", ".dmg", ".iso", ".cab", ".msi", ".xar", ".pkg", ".zst", ".lz4", ".lzma", ".z")

IMAGE_KINDS = {"jpeg", "png", "gif", "tiff", "webp", "heif"}
MEDIA_KINDS = {"isobmff", "ogg", "mp3", "flac", "matroska", "riff-audio", "riff-video"}

MEDIA_EXTENSIONS = (
    ".mp4", ".m4v", ".mov", ".qt", ".m4a", ".mp3", ".wav", ".aac", ".flac", ".ogg", ".oga", ".opus",
    ".webm", ".mkv", ".avi", ".3gp", ".caf", ".aif", ".aiff", ".wma", ".wmv", ".flv", ".mts", ".m2ts",
)
IMAGE_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".tif", ".tiff", ".webp", ".heic", ".heif", ".avif", ".dng",
    ".cr2", ".cr3", ".nef", ".arw", ".raf", ".orf", ".rw2", ".psd", ".bmp",
)
OFFICE_EXTENSIONS = (
    ".docx", ".docm", ".dotx", ".xlsx", ".xlsm", ".xltx", ".pptx", ".pptm", ".potx",
    ".odt", ".ods", ".odp", ".odg", ".pages", ".numbers", ".key", ".epub",
)
ZIP_EXTENSIONS = (".zip", ".jar", ".war", ".apk", ".aab", ".ipa", ".xpi", ".crx", ".nupkg", ".whl", ".vsix",
                  ".sketch", ".fig", ".xd", ".kmz") + OFFICE_EXTENSIONS


def sniff(head: bytes, name: str = "") -> str:
    """Classify content from its first bytes (and, as a hint, its name).

    Returns a kind such as ``text``, ``utf16``, ``pdf``, ``zip``, ``png`` or
    ``binary``.
    """
    if not head:
        return "text"
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            if kind == "binary" and magic == b"MZ" and not _looks_binary(head):
                break
            return kind
    if head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis"):
            return "heif"
        return "isobmff"
    if head.startswith(b"RIFF") and len(head) >= 12:
        form = head[8:12]
        if form == b"WEBP":
            return "webp"
        if form in (b"WAVE",):
            return "riff-audio"
        if form in (b"AVI ",):
            return "riff-video"
        return "binary"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith((b"\xef\xbb\xbf",)):
        return "text"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf16"
    if _looks_binary(head):
        return "binary"
    return "text"


def _looks_binary(head: bytes) -> bool:
    sample = head[:8192]
    if b"\x00" in sample:
        return True
    control = sum(1 for b in sample if b < 32 and b not in (9, 10, 12, 13, 27))
    return control > len(sample) * 0.1


def decode_text(data: bytes, kind: str = "text") -> str:
    if kind == "utf16" or data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{6,}")
_UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_UTF16BE_RUN = re.compile(rb"(?:\x00[\x20-\x7e]){6,}")

STRINGS_CHUNK = 4 * 1024 * 1024


def _strings_chunk(pieces: List[Tuple[int, str]]) -> Tuple[str, List[int]]:
    pieces.sort()
    return "\n".join(t for _, t in pieces), [o for o, _ in pieces]


def iter_strings(data: bytes, chunk: int = STRINGS_CHUNK) -> Iterator[Tuple[str, List[int]]]:
    """Printable runs from binary *data*, one per line, plus their byte offsets.

    Finds ASCII runs and UTF-16 (LE and BE) runs of six or more characters,
    which is where names, paths, URLs and tokens live inside compiled code,
    databases, fonts and .DS_Store files.

    Every run is returned: the runs come in chunks of about *chunk*
    characters (ordered by offset within a chunk), so a large binary is
    covered completely without building one huge string.
    """
    pieces: List[Tuple[int, str]] = []
    total = 0
    for rx, enc in ((_ASCII_RUN, "utf-8"), (_UTF16LE_RUN, "utf-16-le"), (_UTF16BE_RUN, "utf-16-be")):
        for m in rx.finditer(data):
            text = m.group().decode(enc, errors="replace").strip()
            if len(text) < 6:
                continue
            pieces.append((m.start(), text))
            total += len(text) + 1
            if total >= chunk:
                yield _strings_chunk(pieces)
                pieces, total = [], 0
    if pieces:
        yield _strings_chunk(pieces)


def is_media(kind: str, name: str) -> bool:
    lowered = name.lower()
    return kind in MEDIA_KINDS or kind in IMAGE_KINDS or lowered.endswith(MEDIA_EXTENSIONS + IMAGE_EXTENSIONS) \
        or kind in ("font",)


def extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1].lower()
    return "." + base.rsplit(".", 1)[-1] if "." in base else ""


def strip_compression_suffix(name: str) -> Optional[str]:
    for suffix in (".gz", ".bz2", ".xz", ".tgz"):
        if name.lower().endswith(suffix):
            base = name[: -len(suffix)]
            return base + ".tar" if suffix == ".tgz" else base
    return None


_NO_STRINGS_BOXES = {b"mdat", b"free", b"skip", b"wide"}


def metadata_region(data: bytes, kind: str) -> bytes:
    """The parts of a media file that can hold text (headers, tags, boxes).

    Compressed pixel and sample data is skipped: printable runs found there
    are random noise, and scanning it is slow.
    """
    import struct

    try:
        if kind == "jpeg":
            end = data.find(b"\xff\xda")
            return data[: end if end != -1 else min(len(data), 1 << 20)]
        if kind == "png":
            out, i = [], 8
            while i + 8 <= len(data):
                (length,) = struct.unpack(">I", data[i:i + 4])
                ctype = data[i + 4:i + 8]
                if ctype != b"IDAT":
                    out.append(data[i:i + 12 + length])
                if ctype == b"IEND":
                    break
                i += 12 + length
            return b"".join(out)
        if kind in ("isobmff", "heif"):
            out, i = [], 0
            while i + 8 <= len(data):
                (size,) = struct.unpack(">I", data[i:i + 4])
                box = data[i + 4:i + 8]
                header = 8
                if size == 1 and i + 16 <= len(data):
                    (size,) = struct.unpack(">Q", data[i + 8:i + 16])
                    header = 16
                elif size == 0:
                    size = len(data) - i
                if size < header:
                    break
                if box not in _NO_STRINGS_BOXES:
                    out.append(data[i:i + size])
                i += size
            return b"".join(out)
        if kind in ("webp", "riff-audio", "riff-video"):
            out, i = [data[:12]], 12
            while i + 8 <= len(data):
                fourcc = data[i:i + 4]
                (size,) = struct.unpack("<I", data[i + 4:i + 8])
                if fourcc not in (b"VP8 ", b"VP8L", b"ALPH", b"ANMF", b"data", b"idx1") and \
                        not (fourcc == b"LIST" and data[i + 8:i + 12] == b"movi"):
                    out.append(data[i:i + 8 + size])
                i += 8 + size + (size & 1)
            return b"".join(out)
        if kind == "mp3":
            if data.startswith(b"ID3") and len(data) >= 10:
                size = ((data[6] & 0x7F) << 21) | ((data[7] & 0x7F) << 14) | ((data[8] & 0x7F) << 7) | (data[9] & 0x7F)
                return data[: 10 + size] + data[-128:]
            return data[-128:]
    except (struct.error, IndexError, ValueError):
        return data[: 1 << 16]
    if kind in ("tiff", "gif", "ogg", "flac", "matroska"):
        return data[: 1 << 18]
    return data
