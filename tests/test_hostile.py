"""Crafted input must not make the parsers do quadratic work.

Each case is about 2 MB, built to defeat a naive parser (an opening tag
repeated without its closing tag, and so on). Before the parsers were
rewritten, the first case took minutes; every case must now finish in well
under two seconds.
"""

import struct
import time
import unittest
import zlib

from prepublish_audit.config import Settings
from prepublish_audit.denylist import Denylist
from prepublish_audit.metadata import (
    builtin_fields,
    office_fields,
    parse_tiff,
    pdf_extract,
    xml_attribute_text,
    xml_property_text,
    xml_text,
    xmp_fields,
    xmp_packets,
)
from prepublish_audit.scanner import Scanner

SIZE = 2 * 1024 * 1024
LIMIT = 2.0


def repeat(unit, size=SIZE):
    return unit * (size // len(unit))


class HostileInputTests(unittest.TestCase):
    def assertFast(self, label, fn, *args, **kwargs):
        start = time.perf_counter()
        fn(*args, **kwargs)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, LIMIT, f"{label} took {elapsed:.2f}s")

    def test_xmp_without_closing_tags(self):
        data = b"\xff\xd8\xff" + repeat(b"<x:xmpmeta>")
        self.assertFast("xmp_packets", xmp_packets, data)
        self.assertFast("builtin_fields(jpeg)", builtin_fields, data, "jpeg")
        text = repeat("<dc:creator>")
        self.assertFast("xmp_fields(open tags)", xmp_fields, text)
        self.assertFast("xmp_fields(open attributes)", xmp_fields, repeat('dc:creator="'))

    def test_pdf_streams_without_end(self):
        self.assertFast("pdf_extract(stream)", pdf_extract, b"%PDF-" + repeat(b"stream\n"))
        self.assertFast("pdf_extract(stream + endstream)", pdf_extract, b"%PDF-" + repeat(b"stream\n") + b"endstream")
        self.assertFast("pdf_extract(literals)", pdf_extract,
                        b"%PDF-stream\n" + zlib.compress(b"BT " + repeat(b"(", SIZE // 4) + b" Tj ET") + b"endstream")

    def test_xml_without_closing_brackets(self):
        for label, text in (("lt", repeat("<")), ("open tags", repeat("<dc:title>")), ("tab", repeat("<w:tab")),
                            ("name run", "<x " + "a" * SIZE + ">"), ("attributes", repeat('<x a="1" b=\'2\' ')),
                            ("unclosed author", repeat("<author>"))):
            with self.subTest(label):
                self.assertFast(f"xml_text {label}", xml_text, text)
                self.assertFast(f"xml_attribute_text {label}", xml_attribute_text, text)
                self.assertFast(f"xml_property_text {label}", xml_property_text, text)
                parts = {"docProps/core.xml": text, "docProps/app.xml": text, "docProps/custom.xml": text,
                         "meta.xml": text, "word/comments.xml": text}
                self.assertFast(f"office_fields {label}", office_fields, parts.get, list(parts))

    def test_tiff_with_many_large_entries(self):
        # 200 IFD entries that each point at the same 1 MB value: only the
        # tags the parser reads may be copied.
        n = 200
        entries = b"".join(struct.pack("<HHII", 0x1000 + i, 1, 1024 * 1024, 8 + 2 + 12 * n + 4) for i in range(n))
        data = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", n) + entries + b"\x00" * 4 + b"x" * (1024 * 1024)
        self.assertFast("parse_tiff", parse_tiff, data)

    def test_quicktime_atoms(self):
        unit = b"\xa9ART" + struct.pack(">I", 0x7FFFFFFF) + b"data" + b"\x00" * 8
        self.assertFast("builtin_fields(isobmff)", builtin_fields, repeat(unit), "isobmff")

    def test_whole_scan_of_hostile_files(self):
        scanner = Scanner(Settings(external_tools=False), Denylist())
        for name, data in (("a.jpg", b"\xff\xd8\xff" + repeat(b"<x:xmpmeta>")),
                           ("b.pdf", b"%PDF-" + repeat(b"stream\n") + b"endstream"),
                           ("c.docx", None)):
            if data is None:
                import io
                import zipfile

                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("[Content_Types].xml", "<Types/>")
                    zf.writestr("docProps/custom.xml", repeat("<property name='x'>"))
                    zf.writestr("word/document.xml", repeat("<w:t"))
                data = buf.getvalue()
            with self.subTest(name):
                self.assertFast(name, scanner.scan_bytes, data, name=name, match_path=name, display=name,
                                origin="file", depth=0)


if __name__ == "__main__":
    unittest.main()
