"""Recover gpiolib ownership/configuration, not electrical pin levels."""
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux.rpi.common import DeviceTree, interface_strings

# Stable gpiolib descriptor flag positions (Linux 6.8/6.12 and newer).
# Unknown bits are retained, never silently interpreted as hardware state.
FLAG_NAMES = {0: 'requested', 1: 'output', 2: 'export', 3: 'sysfs',
              6: 'active-low', 7: 'open-drain', 8: 'open-source', 9: 'irq',
              10: 'irq-enabled', 11: 'hogged', 12: 'transitory', 13: 'pull-up',
              14: 'pull-down', 15: 'bias-disabled', 16: 'edge-rising',
              17: 'edge-falling', 18: 'clock-realtime', 19: 'clock-hte'}
PI4_HEADER = dict(zip(
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27),
    (27, 28, 3, 5, 7, 29, 31, 26, 24, 21, 19, 23, 32, 33, 8, 10, 36, 11, 12, 35, 38, 40, 15, 16, 18, 22, 37, 13)))


def read_string(layer, address, limit=256):
    if not address:
        return ''
    data = bytearray()
    for i in range(limit):
        raw = layer.read(address + i, 1, pad=False)
        if len(raw) != 1:
            raise ValueError('short GPIO string read')
        if raw == b'\0':
            if any(c < 32 or c > 126 for c in data):
                raise ValueError('non-printable GPIO string')
            return data.decode('ascii')
        data.extend(raw)
    raise ValueError('GPIO string exceeds limit or is unterminated')


def label_layout(kernel):
    """Inspect the actual label member type; type existence alone is insufficient."""
    member = kernel.get_type('gpio_desc').vol.members['label'][1]
    subtype = member.vol.subtype.type_name.split('!')[-1]
    if subtype == 'char':
        return 0, 'char-pointer'
    if subtype == 'gpio_desc_label':
        return kernel.get_type('gpio_desc_label').relative_child_offset('str'), 'rcu-label'
    raise ValueError('Unsupported gpio_desc.label type: ' + subtype)


def flag_summary(flags):
    requested = bool(flags & 1)
    unknown = flags & ~sum(1 << bit for bit in FLAG_NAMES)
    notes = []
    if unknown:
        notes.append(f'unknown flag bits {unknown:#x}')
    if flags & (1 << 7) and flags & (1 << 8):
        notes.append('conflicting drive flags')
    if sum(bool(flags & (1 << bit)) for bit in (13, 14, 15)) > 1:
        notes.append('conflicting bias flags')
    # Released descriptors can retain direction/configuration bits.
    return ('Yes' if requested else 'No',
            ('Output' if flags & 2 else 'Input') if requested else 'Not requested',
            ('Yes' if flags & 64 else 'No') if requested else 'Not requested',
            ', '.join(name for bit, name in FLAG_NAMES.items() if flags & (1 << bit)) or '(none)',
            '; '.join(notes))


def node_compatibles(kernel, layer, node):
    values = []
    for _, name, _, _, raw, status in DeviceTree.read_properties(kernel, layer, node, 1024, 65536):
        if status != 'ok':
            raise ValueError('Incomplete DT properties: ' + status)
        if name == 'compatible':
            values.append(interface_strings(raw))
    if len(values) != 1 or values[0] is None:
        raise ValueError('Missing, duplicate or invalid compatible')
    return values[0]


def platform_compatibles(kernel, layer):
    if not kernel.has_symbol('of_root'):
        return []
    root = int(kernel.object_from_symbol('of_root'))
    if not root:
        return []
    return node_compatibles(kernel, layer, kernel.object('device_node', offset=root, absolute=True))


def pi4_controller(kernel, layer, gdev, compatible):
    """Only map a confirmed Pi 4 B and its real BCM2711 DT controller."""
    if 'raspberrypi,4-model-b' not in compatible or not int(gdev.chip):
        return False
    chip = gdev.chip.dereference()
    if not int(chip.parent):
        return False
    parent = chip.parent.dereference()
    if not parent.has_member('of_node') or not int(parent.of_node):
        return False
    return 'brcm,bcm2711-gpio' in node_compatibles(kernel, layer, parent.of_node.dereference())


def scan_gpio(kernel, layer, *, max_chips=64, max_lines=4096, max_string=256, compatible=()):
    """Yield bounded live-list records. Corruption is explicit, never an empty success."""
    if min(max_chips, max_lines, max_string) <= 0:
        raise ValueError('GPIO bounds must be positive')
    label_offset, layout = label_layout(kernel)
    head = kernel.object_from_symbol('gpio_devices')
    end, previous, cursor = head.vol.offset, head.vol.offset, int(head.next)
    offset = kernel.get_type('gpio_device').relative_child_offset('list')
    size = kernel.get_type('gpio_desc').size
    if size <= 0:
        raise ValueError('Invalid GPIO descriptor size')
    seen = set()
    while cursor != end:
        if not cursor or cursor in seen:
            raise ValueError('NULL/cyclic GPIO device list')
        if len(seen) >= max_chips:
            raise ValueError('GPIO chip limit reached')
        seen.add(cursor)
        gdev = kernel.object('gpio_device', offset=cursor - offset, absolute=True)
        if int(gdev.list.prev) != previous:
            raise ValueError('Inconsistent GPIO device list backlink')
        count, descs = int(gdev.ngpio), int(gdev.descs)
        if not 0 < count <= max_lines or not descs:
            raise ValueError('Invalid/oversized GPIO descriptor array')
        chip_id = int(gdev.id)
        if chip_id < 0:
            raise ValueError('Invalid GPIO chip id')
        controller = read_string(layer, int(gdev.label), max_string)
        header, header_note = False, ''
        try:
            header = pi4_controller(kernel, layer, gdev, compatible)
        except (exceptions.InvalidAddressException, AttributeError, ValueError) as error:
            header_note = 'header mapping unavailable: ' + str(error)
        detached = not int(gdev.chip)
        for line in range(count):
            address = descs + line * size
            desc = kernel.object('gpio_desc', offset=address, absolute=True)
            if int(desc.gdev) != gdev.vol.offset:
                raise ValueError('GPIO descriptor back-pointer mismatch')
            flags = int(desc.flags)
            notes = [note for note in (header_note, 'detached controller' if detached else '') if note]
            strings = []
            for pointer in (int(desc.name), int(desc.label)):
                try:
                    strings.append(read_string(layer, pointer + (label_offset if len(strings) == 1 and pointer else 0), max_string))
                except (exceptions.InvalidAddressException, ValueError) as error:
                    strings.append('(unreadable)')
                    notes.append(str(error))
            name, consumer = strings
            if not flags & 1 and consumer:
                notes.append('consumer label present without request flag')
            yield {'chip': f'gpiochip{chip_id}', 'controller': controller, 'offset': line,
                   'name': name, 'consumer': consumer, 'flags': flags, 'address': address,
                   'header': str(PI4_HEADER[line]) if header and line in PI4_HEADER else '-',
                   'layout': layout, 'notes': notes}
        previous, cursor = cursor, int(gdev.list.next)
    if int(head.prev) != previous:
        raise ValueError('Inconsistent GPIO list tail')


def display_row(record, details=False):
    requested, direction, active_low, flags, warning = flag_summary(record['flags'])
    notes = record['notes'] + ([warning] if warning else [])
    row = (record['chip'], record['controller'], record['offset'], record['header'],
           record['name'] or '(unnamed)', record['consumer'] or '(none)', requested,
           direction, active_low, '; '.join(notes) or 'ok')
    return row + (hex(record['flags']), flags, hex(record['address']), record['layout']) if details else row


class Gpio(interfaces.plugins.PluginInterface):
    """Recover GPIO consumers and cached kernel configuration; no pin voltages."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name='kernel', description='Linux kernel', architectures=['AArch64', 'Intel64']),
            requirements.BooleanRequirement(name='all', description='Include unrequested lines', default=False, optional=True),
            requirements.BooleanRequirement(name='details', description='Include raw flags and descriptor address', default=False, optional=True),
            requirements.BooleanRequirement(name='allow-generic', description='Allow non-Pi Linux, e.g. a gpio-sim VM', default=False, optional=True),
            requirements.StringRequirement(name='chip', description='Exact gpiochipN name to display', optional=True),
            requirements.IntRequirement(name='max-chips', description='Maximum GPIO devices', default=64, optional=True),
            requirements.IntRequirement(name='max-lines', description='Maximum lines per device', default=4096, optional=True),
            requirements.IntRequirement(name='max-string', description='Maximum GPIO string bytes', default=256, optional=True),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]
        layer = self.context.layers[kernel.layer_name]
        details = self.config.get('details', False)
        count = 0
        try:
            compatible = platform_compatibles(kernel, layer)
            is_pi = any(s.startswith('raspberrypi,') for s in compatible)
            if not is_pi and not self.config.get('allow-generic', False):
                raise ValueError('Pi identity not established; --allow-generic is required for a non-Pi simulator')
            if not kernel.has_symbol('gpio_devices'):
                raise ValueError('Missing gpio_devices symbol')
            for record in scan_gpio(kernel, layer,
                                    max_chips=self.config['max-chips'], max_lines=self.config['max-lines'],
                                    max_string=self.config['max-string'], compatible=compatible):
                if self.config.get('chip') and record['chip'] != self.config['chip']:
                    continue
                if not self.config.get('all', False) and not record['flags'] & 1 and not record['notes']:
                    continue
                if not is_pi:
                    record['notes'].append('generic Linux; Pi identity not established')
                count += 1
                yield 0, display_row(record, details)
            if not count:
                yield 0, self._diagnostic('No matching GPIO lines (filters applied)', details)
        except (exceptions.InvalidAddressException, exceptions.SymbolError, ValueError, AttributeError, KeyError) as error:
            yield 0, self._diagnostic('Incomplete: ' + str(error), details)

    @staticmethod
    def _diagnostic(status, details):
        row = ('-', '-', -1, '-', '-', '-', 'Unknown', 'Unknown', 'Unknown', status)
        return row + ('', '', '', '') if details else row

    def run(self):
        columns = [(name, int if name == 'Offset' else str) for name in (
            'Chip', 'Controller', 'Offset', 'HeaderPin', 'LineName', 'Consumer',
            'Requested', 'KernelDirection', 'ActiveLow', 'Status')]
        if self.config.get('details', False):
            columns += [(name, str) for name in ('RawFlags', 'Flags', 'DescriptorAddress', 'ConsumerLayout')]
        return renderers.TreeGrid(columns, self._generator())
