import struct
import unittest
from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import physical, avml


def frame(typ, data):
    return ((len(data) << 8) | typ).to_bytes(4, "little") + data


def chunk(start, data):
    return (
        struct.pack("<IIQQQ", 0x4C4D5641, 2, start, start + len(data) - 1, 0)
        + frame(255, b"sNaPpY")
        + frame(1, b"\0" * 4 + data)
        + b"\0" * 8
    )


class Tests(unittest.TestCase):
    def test_incompressible_multirange(self):
        c = contexts.Context()
        blob = chunk(0, b"ABCD") + chunk(4096, b"EFGH")
        c.layers.add_layer(physical.BufferDataLayer(c, "buffer", "buffer", blob))
        c.config["avml.base_layer"] = "buffer"
        layer = avml.AVMLLayer(c, "avml", "avml")
        self.assertEqual(layer.read(0, 4), b"ABCD")
        self.assertEqual(layer.read(4096, 4), b"EFGH")

    def test_truncation_rejected(self):
        obj = object.__new__(avml.AVMLLayer)
        for data in [
            b"",
            b"\x01",
            frame(255, b"sNaPpY"),
            frame(1, b"\0" * 4 + b"abc")[:-1],
        ]:
            with self.subTest(data=data), self.assertRaises(exceptions.LayerException):
                obj._read_snappy_frames(data, 3)

    def test_overlong_range_rejected(self):
        with self.assertRaises(exceptions.LayerException):
            object.__new__(avml.AVMLLayer)._read_snappy_frames(
                frame(1, b"\0" * 4 + b"ABCDE"), 3
            )

    def test_skippable_frame(self):
        obj = object.__new__(avml.AVMLLayer)
        data = frame(128, b"padding") + frame(1, b"\0" * 4 + b"abcd")
        segments, used = obj._read_snappy_frames(data, 3)
        self.assertEqual(used, len(data))
        self.assertEqual(segments[0][2], 4)

    @unittest.skipUnless(avml.HAS_SNAPPY, "snappy library not available")
    def test_compressed_frame(self):
        data = frame(0, b"\0" * 4 + b"\x04\x0cABCD")
        segments, used = object.__new__(avml.AVMLLayer)._read_snappy_frames(data, 3)
        self.assertEqual(segments[0][2], 4)
        self.assertEqual(used, len(data))


if __name__ == "__main__":
    unittest.main()
