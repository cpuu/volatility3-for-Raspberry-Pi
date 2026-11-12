"""Raspberry Pi model analysis from captured kernel Device Tree data."""
from volatility3.framework import interfaces, renderers
from volatility3.plugins.linux.rpi.rpi import Rpi


def decode_board_revision(code):
    """Decode documented fields; preserve unknown values without guessing."""
    if code & (1 << 23):
        memory = (code >> 20) & 7
        maker = (code >> 16) & 15
        processor = (code >> 12) & 15
        board_type = (code >> 4) & 255
        types = {0: 'A', 1: 'B', 2: 'A+', 3: 'B+', 4: '2B',
                 5: 'Alpha', 6: 'CM1', 8: '3B', 9: 'Zero', 10: 'CM3',
                 12: 'Zero W', 13: '3B+', 14: '3A+', 16: 'CM3+',
                 17: '4B', 18: 'Zero 2 W', 19: '400', 20: 'CM4',
                 21: 'CM4S', 23: '5', 24: 'CM5', 25: '500/500+',
                 26: 'CM5 Lite', 27: 'CM0'}
        return {
            'ram': {0: '256 MB', 1: '512 MB', 2: '1 GB', 3: '2 GB',
                    4: '4 GB', 5: '8 GB', 6: '16 GB', 7: 'Other' }[memory],
            'manufacturer': {0: 'Sony UK', 1: 'Egoman', 2: 'Embest',
                             3: 'Sony Japan', 4: 'Embest', 5: 'Stadium'}.get(maker, f'Unknown (0x{maker:x})'),
            'soc': {0: 'BCM2835', 1: 'BCM2836', 2: 'BCM2837', 3: 'BCM2711',
                    4: 'BCM2712'}.get(processor, f'Unknown (0x{processor:x})'),
            'type': types.get(board_type, f'Unknown (0x{board_type:x})'),
            # The field is a revision index. Prefer the firmware's explicit
            # human-readable revision; do not assume future indices mean 1.x.
            'revision': f'index {code & 15}',
        }
    old = {
        2: ('B', '1.0', '256 MB', 'Egoman'), 3: ('B', '1.0', '256 MB', 'Egoman'),
        4: ('B', '2.0', '256 MB', 'Sony UK'), 5: ('B', '2.0', '256 MB', 'Qisda'),
        6: ('B', '2.0', '256 MB', 'Egoman'), 7: ('A', '2.0', '256 MB', 'Egoman'),
        8: ('A', '2.0', '256 MB', 'Sony UK'), 9: ('A', '2.0', '256 MB', 'Qisda'),
        13: ('B', '2.0', '512 MB', 'Egoman'), 14: ('B', '2.0', '512 MB', 'Sony UK'),
        15: ('B', '2.0', '512 MB', 'Egoman'), 16: ('B+', '1.2', '512 MB', 'Sony UK'),
        17: ('CM1', '1.0', '512 MB', 'Sony UK'), 18: ('A+', '1.1', '256 MB', 'Sony UK'),
        19: ('B+', '1.2', '512 MB', 'Embest'), 20: ('CM1', '1.0', '512 MB', 'Embest'),
        21: ('A+', '1.1', '256 MB / 512 MB', 'Embest'),
    }
    # Retain full raw code in the output; old-style warranty flags are outside
    # the low sixteen-bit board code.
    entry = old.get(code & 0xffff)
    if entry:
        return dict(zip(('type', 'revision', 'ram', 'manufacturer'), entry), soc='BCM2835')
    return dict.fromkeys(('type', 'revision', 'ram', 'manufacturer', 'soc'), 'Unknown')


def board_summary(properties, diagnostics=()):
    """Summarize validated DT bytes; no values inferred from dump file names."""
    import re
    missing = 'Not available'
    notes = list(diagnostics)

    def string(path, name):
        data = properties.get((path, name))
        if data is None:
            return None
        if not data.endswith(b'\0') or b'\0' in data[:-1]:
            notes.append(f'invalid {path}:{name}')
            return None
        try:
            text = data[:-1].decode('ascii')
        except UnicodeDecodeError:
            text = ''
        if not text or any(ord(c) < 32 or ord(c) > 126 for c in text):
            notes.append(f'invalid {path}:{name}')
            return None
        return text

    compat = properties.get(('/', 'compatible'), b'')
    try:
        parts = compat[:-1].decode('ascii').split('\0') if compat.endswith(b'\0') else []
    except UnicodeDecodeError:
        parts = []
    identifiers = [p for p in parts if p.startswith('raspberrypi,')]
    if not identifiers:
        raise ValueError('Root compatible does not establish Raspberry Pi identity')
    board = string('/', 'model')
    revision = None
    if board:
        match = re.fullmatch(r'(.+) Rev ([0-9]+(?:\.[0-9]+)*)', board)
        if match:
            board, revision = match.groups()
    serial = string('/', 'serial-number')
    system_serial = properties.get(('/system', 'linux,serial'))
    if system_serial is not None:
        if len(system_serial) == 8:
            fallback = f'{int.from_bytes(system_serial, "big"):016x}'
            if serial is None:
                serial = fallback
            elif not re.fullmatch(r'[0-9a-fA-F]+', serial) or int(serial, 16) != int(fallback, 16):
                notes.append(f'serial mismatch: /system={fallback}')
        else:
            notes.append('invalid /system:linux,serial length')
    raw_code = properties.get(('/system', 'linux,revision'))
    decoded = dict.fromkeys(('ram', 'manufacturer', 'soc', 'revision', 'type'), missing)
    code_text = missing
    if raw_code is not None and len(raw_code) == 4:
        code = int.from_bytes(raw_code, 'big')
        code_text = f'0x{code:08x}'
        decoded = decode_board_revision(code)
        if revision is None:
            revision = decoded['revision']
        elif code & (1 << 23) and int(revision.split('.')[-1]) != (code & 15):
            notes.append('revision mismatch: model vs revision-code index')
    else:
        notes.append('revision code missing' if raw_code is None else 'invalid revision-code length')
    socs = [p.split(',', 1)[1].upper() for p in parts if p.startswith('brcm,bcm')]
    soc = socs[0] if socs else decoded['soc']
    if socs and decoded['soc'] != missing and not decoded['soc'].startswith('Unknown') and soc != decoded['soc']:
        notes.append('SoC mismatch: compatible vs revision code')
    ram = decoded['ram']
    if ram == 'Other':
        sdram = properties.get(('/chosen', 'rpi-sdram-size-gbit'))
        if sdram is not None and len(sdram) == 4 and int.from_bytes(sdram, 'big') > 0:
            ram = f'{int.from_bytes(sdram, "big") * 128} MB (firmware SDRAM property)'
    if board is None:
        notes.append('model missing or invalid')
    if serial is None:
        notes.append('serial missing or invalid')
    return (board or missing, ' | '.join(identifiers), revision or missing,
            serial or missing, code_text, ram, decoded['manufacturer'], soc,
            '; '.join(dict.fromkeys(notes)) or 'ok')


class Model(interfaces.plugins.PluginInterface):
    """Summarize Raspberry Pi board identity and decode revision-code hardware fields."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Share validated bounded OF traversal, not the EEPROM reader or output.
        return [requirement for requirement in Rpi.get_requirements()
                if requirement.name not in ('allow-generic', 'max-eeprom')]

    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]
        layer = self.context.layers[kernel.layer_name]
        root = int(kernel.object_from_symbol('of_root'))
        if not root:
            raise ValueError('of_root is NULL')
        bounds = [self.config[name] for name in ('max-nodes', 'max-properties', 'max-value')]
        if min(bounds) <= 0:
            raise ValueError('Traversal and value bounds must be positive')
        wanted = {('/', 'model'), ('/', 'compatible'), ('/', 'serial-number'),
                  ('/system', 'linux,revision'), ('/system', 'linux,serial'),
                  ('/chosen', 'rpi-sdram-size-gbit')}
        values, seen, diagnostics = {}, set(), []
        for node, path, address, status in Rpi.walk_nodes(kernel, root, bounds[0]):
            if node is None:
                diagnostics.append(status)
                continue
            if path not in ('/', '/system', '/chosen'):
                continue
            for _, name, _, _, raw, status in Rpi.read_properties(kernel, layer, node, bounds[1], bounds[2]):
                key = (path, name)
                if key in wanted:
                    if key in seen:
                        values.pop(key, None)
                        diagnostics.append(f'duplicate {path}:{name}')
                    else:
                        seen.add(key)
                        if status == 'ok':
                            values[key] = raw
                        else:
                            diagnostics.append(f'{path}:{name}: {status}')
                elif status != 'ok':
                    diagnostics.append(status)
        yield 0, board_summary(values, diagnostics)

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        if not kernel.has_symbol('of_root') or not all(kernel.has_type(name) for name in ('device_node', 'property')):
            raise TypeError('Requires of_root and device_node/property types in the matching kernel ISF')
        return renderers.TreeGrid([
            ('Board', str), ('Model', str), ('Revision', str), ('Serial', str),
            ('RevisionCode', str), ('RAM', str), ('BoardManufacturer', str),
            ('SoC', str), ('Status', str),
        ], self._generator())
