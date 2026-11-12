from volatility3.plugins.linux.rpi import dtchanges as fdt
"""Independent FDT parser: known fixture and malformed input rejection."""
import struct

import unittest



def fixture():
    # Empty reservation map, root model and /chosen/bootloader partition.
    words = lambda *values: struct.pack(">" + "I" * len(values), *values)
    tree = words(1) + b"\0\0\0\0"
    tree += words(3, 4, 0) + b"Pi\0\0"
    tree += words(1) + b"chosen\0\0"
    tree += words(1) + b"bootloader\0\0"
    tree += words(3, 4, 6) + words(2)
    tree += words(2, 2, 2, 9)
    strings = b"model\0partition\0"
    total = 56 + len(tree) + len(strings)
    header = words(0xD00DFEED, total, 56, 56 + len(tree), 40, 17, 16, 0, len(strings), len(tree))
    return header + bytes(16) + tree + strings


def changed(offset, value):
    raw = bytearray(fixture())
    struct.pack_into(">I", raw, offset, value)
    return bytes(raw)


class FdtTests(unittest.TestCase):
    def test_known_big_endian_properties_and_paths(self):
        rows, nodes = fdt.dtchanges_parse_fdt(fixture())
        self.assertEqual(nodes, {"/", "/chosen", "/chosen/bootloader"})
        self.assertEqual([(p, n, raw) for p, n, _, raw in rows], [
            ("/", "model", b"Pi\0\0"),
            ("/chosen/bootloader", "partition", b"\0\0\0\x02"),
        ])
        for _, _, offset, raw in rows:
            self.assertEqual(fixture()[offset:offset + len(raw)], raw)

    def test_rejects_bad_header_token_length_and_name_offset(self):
        for offset, value in [
            (0, 0), (4, fdt.DTCHANGES_MAX_FDT_SIZE + 1), (8, 0xFFFFFFFC),
            (12, 56), (16, 56), (24, 18), (56, 0xDEAD), (68, 0xFFFFFFFF),
            (72, 0xFFFFFFFF),
        ]:
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                fdt.dtchanges_parse_fdt(changed(offset, value))

    def test_rejects_truncation(self):
        for end in (0, 39, 40, len(fixture()) - 1):
            with self.subTest(end=end), self.assertRaises(ValueError):
                fdt.dtchanges_parse_fdt(fixture()[:end])

    def test_rejects_early_end_and_missing_end(self):
        with self.assertRaises(ValueError):
            fdt.dtchanges_parse_fdt(changed(64, 9))
        raw = fixture()
        end_offset = struct.unpack_from(">I", raw, 12)[0] - 4
        with self.assertRaises(ValueError):
            fdt.dtchanges_parse_fdt(changed(end_offset, 4))


if __name__ == "__main__":
    unittest.main()
