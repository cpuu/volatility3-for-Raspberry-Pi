"""Create an isolated gpio-sim chip and hold three states for memory acquisition.

Linux + CONFIG_GPIO_SIM + configfs + libgpiod Python API v2 are required.
No physical chip path is accepted. The only requested lines belong to the chip
created by this process. The tool never invokes a memory-acquisition command.
"""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import uuid

CONFIG = Path('/sys/kernel/config/gpio-sim')
NAMES = ('VOLAB_INPUT', 'VOLAB_OUTPUT', 'VOLAB_FREE', 'VOLAB_HOG')


def verify_sim_device(devname, chipname, sysroot=Path('/sys')):
    if not re.fullmatch(r'gpio-sim\.\d+', devname) or not re.fullmatch(r'gpiochip\d+', chipname):
        raise RuntimeError('Unexpected gpio-sim device identity')
    platform = (sysroot / 'bus/platform/devices' / devname).resolve(strict=True)
    driver = (platform / 'driver').resolve(strict=True)
    chip = (sysroot / 'bus/gpio/devices' / chipname).resolve(strict=True)
    if driver.name != 'gpio-sim' or platform not in chip.parents:
        raise RuntimeError('Refusing a GPIO chip not parented by the created gpio-sim device')


def check_snapshot(data, phase):
    if len(data['lines']) != 4 or [r['offset'] for r in data['lines']] != list(range(4)):
        raise RuntimeError('Expected exactly four virtual lines')
    for row in data['lines']:
        offset = row['offset']
        expected = {3: ('volab-hog', 'OUTPUT', False)}
        if phase == 'requested':
            expected.update({0: ('volab-input', 'INPUT', False), 1: ('volab-output', 'OUTPUT', True)})
        if row['name'] != NAMES[offset] or row['used'] != (offset in expected):
            raise RuntimeError('Unexpected line name/request state')
        if offset in expected:
            consumer, direction, active_low = expected[offset]
            if (row['consumer'], row['direction'], row['active_low']) != (consumer, direction, active_low):
                raise RuntimeError('Unexpected consumer/configuration on a virtual line')
        elif row['consumer']:
            raise RuntimeError('Unrequested line has a consumer')


def snapshot(gpiod, chip_path, phase, chip_label):
    with gpiod.Chip(str(chip_path)) as chip:
        info = chip.get_info()
        if info.label != chip_label or info.num_lines != 4:
            raise RuntimeError('Created chip label/size mismatch')
        lines = []
        for offset in range(4):
            line = chip.get_line_info(offset)
            lines.append({'offset': offset, 'name': line.name or '', 'consumer': line.consumer or '',
                          'used': line.used, 'direction': line.direction.name, 'active_low': line.active_low})
        data = {'phase': phase, 'chip': info.name, 'controller': info.label, 'lines': lines,
                'kernel': os.uname().release, 'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'source': 'libgpiod GPIO character device line-info ioctl'}
    check_snapshot(data, phase)
    return data


def cleanup(device):
    """Remove only this invocation's configfs objects, never another user's chip."""
    if (device / 'live').exists():
        (device / 'live').write_text('0\n')
    bank = device / 'bank0'
    if bank.exists():
        for i in reversed(range(4)):
            line = bank / ('line' + str(i))
            if (line / 'hog').exists():
                (line / 'hog').rmdir()
            if line.exists():
                line.rmdir()
        bank.rmdir()
    device.rmdir()


def run_lab(gpiod, output):
    token = uuid.uuid4().hex[:12]
    device = CONFIG / ('volab-' + token)
    bank = device / 'bank0'
    chip_label = 'volab-gpio-sim-' + token
    device.mkdir()  # Never reuse or take ownership of an existing experiment.
    try:
        bank.mkdir()
        (bank / 'num_lines').write_text('4\n')
        (bank / 'label').write_text(chip_label + '\n')
        for offset, name in enumerate(NAMES):
            line = bank / ('line' + str(offset))
            line.mkdir()
            (line / 'name').write_text(name + '\n')
        hog = bank / 'line3/hog'
        hog.mkdir()
        (hog / 'name').write_text('volab-hog\n')
        (hog / 'direction').write_text('output-low\n')
        (device / 'live').write_text('1\n')
        chipname = (bank / 'chip_name').read_text().strip()
        devname = (device / 'dev_name').read_text().strip()
        verify_sim_device(devname, chipname)
        chip_path = Path('/dev') / chipname
        for _ in range(50):
            if chip_path.exists():
                break
            time.sleep(0.1)
        if not chip_path.exists():
            raise RuntimeError('Virtual character device did not appear')
        metadata = {'configfs_device': str(device), 'platform_device': devname,
                    'chip': chipname, 'controller': chip_label, 'pid': os.getpid(),
                    'libgpiod': getattr(gpiod, '__version__', 'unknown')}
        (output / 'experiment.json').write_text(json.dumps(metadata, indent=2) + '\n')

        def checkpoint(phase):
            before = snapshot(gpiod, chip_path, phase, chip_label)
            (output / (phase + '-before.json')).write_text(json.dumps(before, indent=2) + '\n')
            print(f'\n{phase.upper()}: {chipname}, {chip_label}', flush=True)
            print('Virtual lines: ' + ', '.join(f"{r['offset']}={r['consumer'] or '(free)'}" for r in before['lines']), flush=True)
            input(f'Acquire {phase} memory in another terminal now. Press Enter ONLY after acquisition finishes: ')
            after = snapshot(gpiod, chip_path, phase, chip_label)
            (output / (phase + '-after.json')).write_text(json.dumps(after, indent=2) + '\n')
            if before['lines'] != after['lines']:
                raise RuntimeError('GPIO metadata changed across acquisition; repeat this experiment')

        checkpoint('baseline')
        with ExitStack() as requests:
            requests.enter_context(gpiod.request_lines(str(chip_path), consumer='volab-input',
                config={0: gpiod.LineSettings(direction=gpiod.line.Direction.INPUT)}))
            requests.enter_context(gpiod.request_lines(str(chip_path), consumer='volab-output',
                config={1: gpiod.LineSettings(direction=gpiod.line.Direction.OUTPUT, active_low=True,
                                             output_value=gpiod.line.Value.INACTIVE)}))
            checkpoint('requested')
        checkpoint('released')
        print('All reference snapshots verified. Compare the three memory dumps with the Gpio plugin.')
    finally:
        cleanup(device)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New directory for capture-time reference JSON')
    parser.add_argument('--check', action='store_true', help='Check prerequisites without creating a chip')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.exit(2, 'gpio-sim requires Linux. On macOS run development/rpi_gpio_synthetic.py instead.\n')
    try:
        import gpiod
    except ImportError:
        parser.exit(2, 'Install libgpiod Python bindings v2 in the selected interpreter.\n')
    if not hasattr(gpiod, 'request_lines'):
        parser.exit(2, 'libgpiod Python API v2 is required (v1 is not supported).\n')
    if not CONFIG.is_dir():
        parser.exit(2, 'Load gpio-sim and mount configfs at /sys/kernel/config; see the guide.\n')
    if args.check:
        print('Prerequisites present. No virtual chip created and no GPIO requested.')
        return
    if os.geteuid() != 0:
        parser.exit(2, 'Run the Linux lab with sudo using the prepared Python interpreter.\n')
    if not args.output:
        parser.error('--output is required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run_lab(gpiod, output)
    except (KeyboardInterrupt, EOFError):
        parser.exit(130, 'Interrupted; this experiment\'s requests and virtual chip were cleaned up.\n')
    except (OSError, RuntimeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
