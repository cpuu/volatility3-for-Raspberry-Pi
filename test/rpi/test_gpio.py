"""GPIO recovery using real Volatility byte layers and synthetic kernel objects."""
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from development.rpi_gpio_synthetic import make_fixture, HEAD, DEVICE, DESCS, DESC_SIZE, LIST_OFFSET
from volatility3.plugins.linux.rpi import gpio


class GpioTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.context, self.kernel, self.layer = make_fixture(Path(self.temp.name), 'rcu', 'requested')

    def rows(self, **kwargs):
        return list(gpio.scan_gpio(self.kernel, self.layer, **kwargs))

    def write64(self, address, value):
        self.layer.write(address, struct.pack('<Q', value))

    def test_both_label_abis_with_real_bytes(self):
        for layout in ('legacy', 'rcu'):
            _, k, layer = make_fixture(Path(self.temp.name), layout)
            rows = list(gpio.scan_gpio(k, layer))
            self.assertEqual([r['consumer'] for r in rows], ['volab-input', 'volab-output', '', 'volab-hog'])
            self.assertEqual(rows[0]['layout'], 'char-pointer' if layout == 'legacy' else 'rcu-label')

    def test_released_direction_not_claimed_as_current_input(self):
        _, k, layer = make_fixture(Path(self.temp.name), 'rcu', 'released')
        rows = list(gpio.scan_gpio(k, layer))
        self.assertEqual(gpio.display_row(rows[1])[6:9], ('No', 'Not requested', 'Not requested'))
        self.assertEqual(rows[3]['consumer'], 'volab-hog')

    def test_requested_direction_and_active_low(self):
        rows = self.rows()
        self.assertEqual(gpio.display_row(rows[0])[6:9], ('Yes', 'Input', 'No'))
        self.assertEqual(gpio.display_row(rows[1])[6:9], ('Yes', 'Output', 'Yes'))
        self.assertIn('hogged', gpio.display_row(rows[3], True)[11])

    def test_loop_and_backlink_and_tail(self):
        for location, value in [(DEVICE + LIST_OFFSET, DEVICE + LIST_OFFSET),
                                (DEVICE + LIST_OFFSET + 8, 0), (HEAD + 8, 0)]:
            with self.subTest(location=location):
                old = self.layer.read(location, 8)
                self.write64(location, value)
                with self.assertRaises(ValueError): self.rows()
                self.layer.write(location, old)

    def test_null_list_pointer(self):
        self.write64(HEAD, 0)
        with self.assertRaises(ValueError): self.rows()

    def test_missing_descriptors(self):
        self.write64(DEVICE + 16, 0)
        with self.assertRaises(ValueError): self.rows()

    def test_parent_pointer_mismatch(self):
        self.write64(DESCS, DEVICE + 8)
        with self.assertRaisesRegex(ValueError, 'back-pointer'): self.rows()

    def test_read_bounds(self):
        for kw in ({'max_chips': 0}, {'max_lines': 2}, {'max_string': 0}):
            with self.subTest(kw=kw), self.assertRaises(ValueError): self.rows(**kw)

    def test_unreadable_label_keeps_diagnostic(self):
        self.write64(DESCS + 16, 0xff00)
        row = self.rows()[0]
        self.assertEqual(row['consumer'], '(unreadable)')
        self.assertTrue(row['notes'])

    def test_text_limits_and_controls(self):
        self.layer.write(0x8000, b'A' * 8 + b'\0')
        with self.assertRaises(ValueError): gpio.read_string(self.layer, 0x8000, 8)
        self.layer.write(0x8000, b'A\x1b\0')
        with self.assertRaises(ValueError): gpio.read_string(self.layer, 0x8000)
        self.assertEqual(gpio.read_string(self.layer, 0), '')

    def test_stale_consumer_and_detached_chip(self):
        self.write64(DESCS + 8, 0)
        self.write64(DEVICE + 24, 0)
        notes = self.rows()[0]['notes']
        self.assertIn('consumer label present without request flag', notes)
        self.assertIn('detached controller', notes)

    def test_unknown_and_conflicting_flags(self):
        self.assertIn('unknown', gpio.flag_summary(1 << 40)[4])
        self.assertIn('drive', gpio.flag_summary((1 << 7) | (1 << 8))[4])
        self.assertIn('bias', gpio.flag_summary((1 << 13) | (1 << 14))[4])

    def generate(self, **options):
        fake = NS(context=self.context, config={'kernel': self.kernel.name, 'max-chips': 64,
                  'max-lines': 4096, 'max-string': 256, 'allow-generic': True, **options},
                  _diagnostic=gpio.Gpio._diagnostic)
        return list(gpio.Gpio._generator(fake))

    def test_default_all_and_chip_filter(self):
        self.assertEqual(len(self.generate()), 3)
        self.assertEqual(len(self.generate(**{'all': True})), 4)
        self.assertIn('No matching', self.generate(chip='gpiochip99')[0][1][9])
        self.assertEqual(len(self.generate(chip='gpiochip17')), 3)

    def test_generic_requires_opt_in_and_has_no_header_mapping(self):
        self.assertIn('Pi identity', self.generate(**{'allow-generic': False})[0][1][9])
        for _, row in self.generate():
            self.assertEqual(row[3], '-')
            self.assertIn('generic Linux', row[9])

    def test_incomplete_never_empty_success(self):
        self.write64(DESCS, 0)
        self.assertIn('Incomplete', self.generate()[0][1][9])

    def test_header_mapping_requires_board_and_controller_evidence(self):
        device = NS(chip=0)
        self.assertFalse(gpio.pi4_controller(None, None, device, ['raspberrypi,4-model-b']))
        self.assertEqual(gpio.PI4_HEADER[7], 26)
        self.assertEqual(gpio.PI4_HEADER[8], 24)

    def test_details_preserve_flags_and_address(self):
        row = gpio.display_row(self.rows()[1], True)
        self.assertEqual(row[10], '0x43')
        self.assertEqual(row[12], hex(DESCS + DESC_SIZE))
