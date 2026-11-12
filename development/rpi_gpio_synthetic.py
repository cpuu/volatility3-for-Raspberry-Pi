"""Hardware-free GPIO memory fixtures. These are NOT captures of a running kernel."""
import argparse
import json
from pathlib import Path
import struct
import tempfile

from volatility3.framework import contexts
from volatility3.framework.layers import physical
from volatility3.framework.symbols import intermed
from volatility3.plugins.linux.rpi import gpio

HEAD, DEVICE, DESCS, CHIP = 0x1000, 0x2000, 0x3000, 0x4000
DESC_SIZE, LIST_OFFSET = 32, 40
LINE_NAMES = ('VOLAB_INPUT', 'VOLAB_OUTPUT', 'VOLAB_FREE', 'VOLAB_HOG')
CONSUMERS = ('volab-input', 'volab-output', '', 'volab-hog')


def make_fixture(directory, layout='rcu', state='requested'):
    """Build real byte-addressed Volatility objects with either Linux label ABI."""
    if layout not in ('legacy', 'rcu') or state not in ('requested', 'released'):
        raise ValueError('Invalid fixture layout/state')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    base = lambda name: {'kind': 'base', 'name': name}
    record = lambda name: {'kind': 'struct', 'name': name}
    pointer = lambda subtype: {'kind': 'pointer', 'subtype': subtype}
    member = lambda offset, subtype: {'offset': offset, 'type': subtype}
    types = {
        'list_head': {'kind': 'struct', 'size': 16, 'fields': {
            'next': member(0, pointer(record('list_head'))), 'prev': member(8, pointer(record('list_head')))}},
        'gpio_device': {'kind': 'struct', 'size': 56, 'fields': {
            'id': member(0, base('int')), 'ngpio': member(4, base('int')),
            'label': member(8, pointer(base('char'))), 'descs': member(16, pointer(record('gpio_desc'))),
            'chip': member(24, pointer(record('gpio_chip'))), 'list': member(40, record('list_head'))}},
        'gpio_chip': {'kind': 'struct', 'size': 8, 'fields': {}},
        'gpio_desc': {'kind': 'struct', 'size': DESC_SIZE, 'fields': {
            'gdev': member(0, pointer(record('gpio_device'))), 'flags': member(8, base('unsigned long')),
            'label': member(16, pointer(base('char') if layout == 'legacy' else record('gpio_desc_label'))),
            'name': member(24, pointer(base('char')))}},
        # Deliberately present even for the legacy layout: member type must win.
        'gpio_desc_label': {'kind': 'struct', 'size': 16, 'fields': {
            'str': member(16, {'kind': 'array', 'count': 0, 'subtype': base('char')})}},
    }
    isf = {'metadata': {'format': '6.2.0'}, 'base_types': {
        'pointer': {'size': 8, 'signed': False, 'kind': 'int', 'endian': 'little'},
        'char': {'size': 1, 'signed': True, 'kind': 'char', 'endian': 'little'},
        'int': {'size': 4, 'signed': True, 'kind': 'int', 'endian': 'little'},
        'unsigned long': {'size': 8, 'signed': False, 'kind': 'int', 'endian': 'little'},
    }, 'user_types': types, 'enums': {},
        'symbols': {'gpio_devices': {'address': HEAD, 'type': record('list_head')}}}
    path = directory / (layout + '-' + state + '.json')
    path.write_text(json.dumps(isf, indent=2) + '\n')
    memory = bytearray(0xf000)
    struct.pack_into('<QQ', memory, HEAD, DEVICE + LIST_OFFSET, DEVICE + LIST_OFFSET)
    struct.pack_into('<iiQQQ', memory, DEVICE, 17, 4, 0x5000, DESCS, CHIP)
    struct.pack_into('<QQ', memory, DEVICE + LIST_OFFSET, HEAD, HEAD)
    memory[0x5000:0x5000 + len(b'volab-gpio-sim\0')] = b'volab-gpio-sim\0'
    for line, name in enumerate(LINE_NAMES):
        name_address, label_address = 0x5100 + line * 256, 0x6100 + line * 256
        name_bytes = name.encode() + b'\0'
        memory[name_address:name_address + len(name_bytes)] = name_bytes
        requested = state == 'requested' and line in (0, 1)
        # Hog remains requested after userspace releases lines 0 and 1.
        flags = (1 if line == 0 else 67) if requested else (2051 if line == 3 else (2 if line == 1 else 0))
        consumer = CONSUMERS[line] if requested or line == 3 else ''
        if consumer:
            data = consumer.encode() + b'\0'
            start = label_address + (16 if layout == 'rcu' else 0)
            memory[start:start + len(data)] = data
        struct.pack_into('<QQQQ', memory, DESCS + DESC_SIZE * line,
                         DEVICE, flags, label_address if consumer else 0, name_address)
    (directory / (layout + '-' + state + '.bin')).write_bytes(memory)
    context = contexts.Context()
    layer = physical.BufferDataLayer(context, 'memory', 'memory', bytes(memory), metadata={'architecture': 'Intel64'})
    context.layers.add_layer(layer)
    table = intermed.IntermediateSymbolTable(context, 'symbols.fixture', 'fixture', path.as_uri(), validate=False)
    context.symbol_space.append(table)
    kernel = context.module('fixture', 'memory', 0)
    return context, kernel, layer


def demo(output):
    summary = []
    for layout in ('legacy', 'rcu'):
        for state in ('requested', 'released'):
            context, kernel, layer = make_fixture(output, layout, state)
            rows = list(gpio.scan_gpio(kernel, layer))
            expected = [0, 1, 3] if state == 'requested' else [3]
            observed = [row['offset'] for row in rows if row['flags'] & 1]
            if observed != expected or rows[3]['consumer'] != 'volab-hog':
                raise AssertionError('Synthetic state did not match independent expectations')
            if state == 'requested' and (rows[0]['consumer'] != 'volab-input' or rows[1]['consumer'] != 'volab-output'):
                raise AssertionError('Consumer label recovery failed')
            if state == 'released' and any(rows[i]['consumer'] for i in (0, 1)):
                raise AssertionError('Released consumer label incorrectly retained')
            rendered = [dict(zip(('Chip', 'Controller', 'Offset', 'HeaderPin', 'LineName', 'Consumer',
                                 'Requested', 'KernelDirection', 'ActiveLow', 'Status', 'RawFlags', 'Flags',
                                 'DescriptorAddress', 'ConsumerLayout'), gpio.display_row(row, True))) for row in rows]
            print(f'\nSYNTHETIC MEMORY: {layout} / {state} (not a live kernel)')
            print('Offset  Line           Consumer       Requested  KernelDirection  ActiveLow')
            for row in rendered:
                print(f"{row['Offset']:<7} {row['LineName']:<14} {row['Consumer']:<14} {row['Requested']:<10} {row['KernelDirection']:<16} {row['ActiveLow']}")
            summary.append({'layout': layout, 'state': state, 'expected_requested_offsets': expected,
                            'observed_requested_offsets': observed, 'passed': True, 'rows': rendered})
    (Path(output) / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print('\nPASS: 4/4 synthetic memory scenarios; both label ABIs and request/release states.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Save synthetic memory, ISF and result files here')
    args = parser.parse_args()
    if args.output:
        demo(args.output.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='rpi-gpio-synthetic-') as directory:
            demo(directory)


if __name__ == '__main__':
    main()
