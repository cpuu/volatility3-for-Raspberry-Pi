"""Validate simulation guards and independent snapshot comparison without GPIO hardware."""
import copy
from pathlib import Path
import tempfile
import unittest
from development.rpi_gpio_sim import verify_sim_device, check_snapshot
from development.rpi_gpio_compare import compare


def reference(phase='requested'):
    return {'phase': phase, 'chip': 'gpiochip17', 'controller': 'volab-gpio-sim-test', 'lines': [
        {'offset': i, 'name': name, 'consumer': consumer if phase == 'requested' or i == 3 else '',
         'used': (i in (0, 1, 3) if phase == 'requested' else i == 3),
         'direction': 'INPUT' if i == 0 else 'OUTPUT', 'active_low': i == 1 and phase == 'requested'}
        for i, (name, consumer) in enumerate(zip(
            ['VOLAB_INPUT', 'VOLAB_OUTPUT', 'VOLAB_FREE', 'VOLAB_HOG'],
            ['volab-input', 'volab-output', '', 'volab-hog']))]}


def rendered(ref):
    return [{'Chip': ref['chip'], 'Controller': ref['controller'], 'Offset': r['offset'],
             'HeaderPin': '-', 'LineName': r['name'], 'Consumer': r['consumer'] or '(none)',
             'Requested': 'Yes' if r['used'] else 'No',
             'KernelDirection': r['direction'].title() if r['used'] else 'Not requested',
             'ActiveLow': ('Yes' if r['active_low'] else 'No') if r['used'] else 'Not requested',
             'Status': 'ok'} for r in ref['lines']]


class SimulationTests(unittest.TestCase):
    def test_snapshot_states_and_comparison(self):
        for phase in ('baseline', 'requested', 'released'):
            ref = reference(phase)
            check_snapshot(ref, phase)
            self.assertEqual(compare(ref, rendered(ref))['fields_matched'], 24)
            from development.rpi_gpio_synthetic import make_fixture
            from volatility3.plugins.linux.rpi import gpio
            with tempfile.TemporaryDirectory() as directory:
                for layout in ('legacy', 'rcu'):
                    _, kernel, layer = make_fixture(Path(directory), layout, 'requested' if phase == 'requested' else 'released')
                    rows = [dict(zip(('Chip', 'Controller', 'Offset', 'HeaderPin', 'LineName', 'Consumer',
                                      'Requested', 'KernelDirection', 'ActiveLow', 'Status'), gpio.display_row(row)))
                            for row in gpio.scan_gpio(kernel, layer)]
                    actual_ref = copy.deepcopy(ref)
                    actual_ref['controller'] = 'volab-gpio-sim'
                    self.assertTrue(compare(actual_ref, rows)['passed'])


    def test_mismatch_missing_duplicate_and_diagnostic(self):
        ref = reference()
        variations = [rendered(ref)[:-1], rendered(ref) + [rendered(ref)[0]]]
        for field in ('Consumer', 'Requested', 'KernelDirection', 'HeaderPin', 'ActiveLow', 'Status'):
            rows = rendered(ref)
            rows[0][field] = 'wrong'
            variations.append(rows)
        variations.append(rendered(ref) + [{'Status': 'Incomplete: cycle'}])
        for rows in variations:
            with self.subTest(rows=rows), self.assertRaises(ValueError): compare(ref, rows)

    def test_reference_wrong_consumer_rejected(self):
        ref = reference(); ref['lines'][0]['consumer'] = 'wrong'
        with self.assertRaises(RuntimeError): check_snapshot(ref, 'requested')

    def test_refuses_real_chip_driver_or_unrelated_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            device = root / 'devices/platform/gpio-sim.5'
            device.mkdir(parents=True)
            drivers = root / 'bus/platform/drivers'
            (drivers / 'gpio-sim').mkdir(parents=True)
            (drivers / 'pinctrl-bcm2711').mkdir()
            (device / 'driver').symlink_to(drivers / 'gpio-sim')
            link = root / 'bus/platform/devices'
            link.mkdir(); (link / 'gpio-sim.5').symlink_to(device)
            (device / 'gpiochip17').mkdir()
            chips = root / 'bus/gpio/devices'; chips.mkdir(parents=True)
            (chips / 'gpiochip17').symlink_to(device / 'gpiochip17')
            verify_sim_device('gpio-sim.5', 'gpiochip17', root)
            (device / 'driver').unlink(); (device / 'driver').symlink_to(drivers / 'pinctrl-bcm2711')
            with self.assertRaises(RuntimeError): verify_sim_device('gpio-sim.5', 'gpiochip17', root)
            with self.assertRaises(RuntimeError): verify_sim_device('../physical', 'gpiochip17', root)
