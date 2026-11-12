from volatility3.plugins.linux.rpi import rpi as rpi
"""Offline corruption and decoding tests, independent of captured Pi data."""
from types import SimpleNamespace
import unittest


class Kernel:
    def __init__(self, objects): self.objects = objects
    def object(self, type_name, offset, absolute): return self.objects[offset]

class Layer:
    def __init__(self): self.calls = []
    def read(self, address, size, pad):
        self.calls.append((address, size, pad))
        return b"foo\0"

class TestRpi(unittest.TestCase):
    def setUp(self):
        self.original_string = rpi.Rpi._string
        rpi.Rpi._string = staticmethod(lambda value: value)
    def tearDown(self): rpi.Rpi._string = staticmethod(self.original_string)
    def test_binary_not_misreported_as_text(self):
        self.assertEqual(rpi.decode_value("x", b"\0\0\0\1"), ("big-endian cells (uninterpreted)", "0x1"))
        self.assertEqual(rpi.decode_value("x", b"abc"), ("bytes", "616263"))
        self.assertEqual(rpi.decode_value("compatible", b"raspberrypi,4-model-b\0brcm,bcm2711\0")[1], "raspberrypi,4-model-b | brcm,bcm2711")
        self.assertEqual(rpi.decode_value("linux,revision", b"\0\xc0\x31\x12")[1], "0xc03112")
        self.assertEqual(rpi.decode_value("flag", b""), ("boolean", "present"))
    def test_cycle_stops_and_preserves_path(self):
        kernel = Kernel({1: SimpleNamespace(child=2, sibling=0), 2: SimpleNamespace(full_name="soc", child=3, sibling=0), 3: SimpleNamespace(full_name="gpio@7e200000", child=2, sibling=0)})
        rows = list(rpi.Rpi.walk_nodes(kernel, 1, 20))
        self.assertEqual([row[1] for row in rows[:3]], ["/", "/soc", "/soc/gpio@7e200000"])
        self.assertEqual(rows[-1][3], "node-cycle-or-shared-link")
        self.assertEqual(len(rows), 4)
    def test_node_limit_is_reported(self):
        kernel = Kernel({1: SimpleNamespace(child=2, sibling=0)})
        rows = list(rpi.Rpi.walk_nodes(kernel, 1, 1))
        self.assertEqual(rows[-1][3], "node-limit-reached")
    def test_bad_property_lengths_are_not_read(self):
        kernel = Kernel({1: SimpleNamespace(name="bad", length=-1, value=5, next=2), 2: SimpleNamespace(name="huge", length=1000, value=5, next=3), 3: SimpleNamespace(name="null", length=4, value=0, next=4), 4: SimpleNamespace(name="ok", length=4, value=7, next=1)})
        layer = Layer()
        rows = list(rpi.Rpi.read_properties(kernel, layer, SimpleNamespace(properties=1), 10, 32))
        self.assertEqual([row[-1] for row in rows], ["invalid-or-oversized-length", "invalid-or-oversized-length", "null-value-pointer", "ok", "property-cycle"])
        self.assertEqual(layer.calls, [(7, 4, False)])
        self.assertEqual(rows[3][4], b"foo\0")
    def test_property_limit_is_reported(self):
        kernel = Kernel({1: SimpleNamespace(name="flag", length=0, value=0, next=2)})
        rows = list(rpi.Rpi.read_properties(kernel, Layer(), SimpleNamespace(properties=1), 1, 32))
        self.assertEqual(rows[-1][-1], "property-limit-reached")
    def test_old_absolute_names_and_siblings(self):
        kernel = Kernel({1: SimpleNamespace(child=2, sibling=0), 2: SimpleNamespace(full_name="/chosen", child=0, sibling=3), 3: SimpleNamespace(full_name="/system", child=0, sibling=0)})
        self.assertEqual([row[1] for row in rpi.Rpi.walk_nodes(kernel, 1, 10)], ["/", "/chosen", "/system"])
    def test_pi_semantics_are_scoped_and_unknown_bits_preserved(self):
        self.assertIn("SD/eMMC", rpi.decode_value("boot-mode", bytes.fromhex("00000001"), "/chosen/bootloader")[1])
        self.assertNotIn("SD/eMMC", rpi.decode_value("boot-mode", bytes.fromhex("00000001"), "/other")[1])
        signed = rpi.decode_value("signed", bytes.fromhex("0000000f"), "/chosen/bootloader")[1]
        self.assertIn("reserved bits 0x2", signed)
        self.assertIn("not attestation", signed)
        self.assertIn("not boot time", rpi.decode_value("build_timestamp", bytes.fromhex("00000001"), "/chosen/bootloader")[1])

    def generator_fixture(self, compatible, allow_generic=False):
        # Exercise the actual property traversal and identity gate, with an
        # in-memory substitute for the dump layer and kernel symbol objects.
        kernel = Kernel({
            1: SimpleNamespace(properties=10, child=2, sibling=0),
            2: SimpleNamespace(full_name="chosen", properties=0, child=3, sibling=0),
            3: SimpleNamespace(full_name="bootloader", properties=11, child=0, sibling=0),
            10: SimpleNamespace(name="compatible", length=len(compatible), value=100, next=0),
            11: SimpleNamespace(name="boot-mode", length=4, value=101, next=0),
        })
        kernel.layer_name = "memory"
        kernel.object_from_symbol = lambda name: 1
        values = {100: compatible, 101: bytes.fromhex("00000001")}
        layer = SimpleNamespace(read=lambda address, length, pad: values[address][:length])
        return SimpleNamespace(
            config={"kernel": "kernel", "max-nodes": 20, "max-properties": 20, "max-value": 1024, "allow-generic": allow_generic},
            context=SimpleNamespace(modules={"kernel": kernel}, layers={"memory": layer}),
            read_properties=rpi.Rpi.read_properties, walk_nodes=rpi.Rpi.walk_nodes,
        )

    def test_generator_rejects_non_pi_and_unterminated_identity(self):
        for compatible in (b"linux,dummy-virt\0", b"", b"raspberrypi,4-model-b"):
            with self.subTest(compatible=compatible):
                with self.assertRaisesRegex(ValueError, "does not establish Raspberry Pi identity"):
                    list(rpi.Rpi._generator(self.generator_fixture(compatible)))

    def test_generator_generic_override_keeps_unverified_platform_and_semantics(self):
        rows = list(rpi.Rpi._generator(self.generator_fixture(b"linux,dummy-virt\0", True)))
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row[1][0] == "generic-or-unverified" for row in rows))
        boot = next(row[1] for row in rows if row[1][4] == "boot-mode")
        self.assertEqual(boot[2], "/chosen/bootloader")
        self.assertNotIn("SD/eMMC", boot[9])
        self.assertEqual(boot[10], "00000001")

    def test_generator_confirmed_pi_enables_pi_semantics(self):
        rows = list(rpi.Rpi._generator(self.generator_fixture(b"raspberrypi,4-model-b\0brcm,bcm2711\0")))
        self.assertTrue(all(row[1][0] == "raspberry-pi" for row in rows))
        boot = next(row[1] for row in rows if row[1][4] == "boot-mode")
        self.assertIn("SD/eMMC", boot[9])

if __name__ == "__main__": unittest.main()
