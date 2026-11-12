"""Raspberry Pi interfaces analysis from captured kernel Device Tree data."""
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux.rpi.model import Model
from volatility3.plugins.linux.rpi.rpi import Rpi
from volatility3.plugins.linux.rpi.common import interface_strings, INTERFACE_BINDINGS


def interface_rows(tree, diagnostics=()):
    """DT configuration inventory, not driver binding or electrical activity.

    tree[path][property] is raw bytes or None for known corrupt data. A None
    property name marks an incompletely read node so absent status isn't assumed.
    """
    import re
    root_compat = interface_strings(tree.get('/', {}).get('compatible'))
    if not root_compat or not any(p.startswith('raspberrypi,') for p in root_compat):
        raise ValueError('Root compatible does not establish Raspberry Pi identity')
    candidates, alias_errors = {}, []
    for path, props in tree.items():
        compat = interface_strings(props.get('compatible')) or []
        match = next((INTERFACE_BINDINGS[c] for c in compat if c in INTERFACE_BINDINGS), None)
        if match:
            candidates[path] = [match[0], match[1], []]
    for name, raw in tree.get('/aliases', {}).items():
        if name is None or not re.fullmatch(r'(serial\d+|i2c\d*|spi\d+|usb\d*)', name):
            continue
        target = interface_strings(raw)
        if not target or len(target) != 1 or not target[0].startswith('/'):
            alias_errors.append(f'{name}: invalid alias')
            continue
        path = target[0]
        kind = 'UART' if name.startswith('serial') else 'I2C' if name.startswith('i2c') else 'SPI' if name.startswith('spi') else 'USB'
        if path not in candidates:
            compat = interface_strings(tree.get(path, {}).get('compatible'))
            candidates[path] = [kind, compat[0] if compat else 'Not specified (alias)', []]
        candidates[path][2].append(name)

    def state(path):
        if path not in tree:
            return 'Unknown', False
        props = tree[path]
        if 'status' not in props:
            return ('Unknown', False) if None in props else ('okay (implicit)', True)
        values = interface_strings(props['status'])
        if not values or len(values) != 1:
            return 'Unknown', False
        return values[0], values[0] in ('ok', 'okay')

    for path, (kind, controller, aliases) in sorted(candidates.items(), key=lambda p: (p[1][0], p[0])):
        notes = []
        local, _ = state(path)
        if local == 'Unknown':
            notes.append('node/status unavailable or invalid')
        parent = path.rsplit('/', 1)[0] or '/'
        parent_problems = []
        while True:
            value, available = state(parent)
            if not available:
                parent_problems.append(f'{value}: {parent}')
            if parent == '/':
                break
            parent = parent.rsplit('/', 1)[0] or '/'
        props = tree.get(path, {})
        if None in props:
            notes.append('incomplete node properties')
        mode = '-'
        if kind == 'USB':
            values = interface_strings(props.get('dr_mode'))
            mode = values[0] if values and len(values) == 1 else 'Not specified'
            if 'dr_mode' in props and (not values or len(values) != 1):
                mode = 'Unknown'
                notes.append('invalid dr_mode')
        compat = interface_strings(props.get('compatible'))
        yield (', '.join(sorted(aliases)) if aliases else path.rsplit('/', 1)[-1],
               kind, controller, local, '; '.join(parent_problems) or 'okay',
               mode, '; '.join(notes) or 'ok', path,
               ' | '.join(compat) if compat else 'Not available')
    for note in list(diagnostics) + alias_errors:
        yield ('-', 'Diagnostic', '-', 'Unknown', 'Unknown', '-', note, '-', '-')


class Interfaces(Model):
    """Summarize UART, I2C, SPI and USB controller configuration in the Pi DT."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return Model.get_requirements() + [requirements.BooleanRequirement(
            name='details', description='Include full Device Tree paths and compatible strings',
            default=False, optional=True)]

    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]
        layer = self.context.layers[kernel.layer_name]
        root = int(kernel.object_from_symbol('of_root'))
        if not root:
            raise ValueError('of_root is NULL')
        bounds = [self.config[name] for name in ('max-nodes', 'max-properties', 'max-value')]
        if min(bounds) <= 0:
            raise ValueError('Traversal and value bounds must be positive')
        tree, diagnostics, duplicates = {}, [], set()
        for node, path, _, status in Rpi.walk_nodes(kernel, root, bounds[0]):
            if node is None:
                diagnostics.append(f'{path}: {status}')
                continue
            if path in tree:
                duplicates.add(path)
                diagnostics.append(f'{path}: duplicate node path')
                continue
            props = tree[path] = {}
            for _, name, _, _, raw, status in Rpi.read_properties(kernel, layer, node, bounds[1], bounds[2]):
                if status != 'ok':
                    props[None] = None
                if name in ('compatible', 'status', 'dr_mode') or path == '/aliases':
                    if name in props:
                        props[name] = None
                        diagnostics.append(f'{path}:{name}: duplicate property')
                    else:
                        props[name] = raw if status == 'ok' else None
        for path in duplicates:
            tree[path] = {None: None}
        for row in interface_rows(tree, diagnostics):
            yield 0, row if self.config.get('details', False) else row[:7]

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        if not kernel.has_symbol('of_root') or not all(kernel.has_type(name) for name in ('device_node', 'property')):
            raise TypeError('Requires of_root and device_node/property types in the matching kernel ISF')
        columns = [('Interface', str), ('Type', str), ('Controller', str),
                   ('DTStatus', str), ('ParentStatus', str), ('USBMode', str), ('Status', str)]
        if self.config.get('details', False):
            columns += [('Path', str), ('Compatible', str)]
        return renderers.TreeGrid(columns, self._generator())
