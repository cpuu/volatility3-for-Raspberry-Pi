"""Raspberry Pi console analysis from captured kernel Device Tree data."""
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux.rpi.model import Model
from volatility3.plugins.linux.rpi.rpi import Rpi
from volatility3.plugins.linux.rpi.common import interface_strings, INTERFACE_BINDINGS


def console_summary(tree, diagnostics=()):
    """Compare declared firmware stdout with console= requests, not active consoles."""
    import shlex
    notes = list(diagnostics)
    compat = interface_strings(tree.get('/', {}).get('compatible'))
    if not compat or not any(c.startswith('raspberrypi,') for c in compat):
        raise ValueError('Root compatible does not establish Raspberry Pi identity')
    chosen = tree.get('/chosen', {})
    source = 'stdout-path' if 'stdout-path' in chosen else 'linux,stdout-path'
    output = chosen.get(source)
    values = interface_strings(output)
    firmware, path = 'Not available', 'Not available'
    if output is None or not values or len(values) != 1:
        notes.append('stdout missing or invalid')
    else:
        firmware = values[0]
        target = firmware.split(':', 1)[0]
        if target.startswith('/'):
            path = target
        else:
            alias = interface_strings(tree.get('/aliases', {}).get(target))
            if alias and len(alias) == 1 and alias[0].startswith('/') and ':' not in alias[0]:
                path = alias[0]
            else:
                notes.append('stdout alias missing or invalid')
    controller, local, parents = 'Not available', 'Unknown', 'Unknown'
    if path in tree:
        props = tree[path]
        target_compat = interface_strings(props.get('compatible'))
        if target_compat:
            controller = next((INTERFACE_BINDINGS[c][1] for c in target_compat if c in INTERFACE_BINDINGS), target_compat[0])
        else:
            notes.append('controller compatible missing or invalid')

        def state(node):
            if node not in tree:
                return 'Unknown', False
            p = tree[node]
            if 'status' not in p:
                return ('Unknown', False) if None in p else ('okay (implicit)', True)
            v = interface_strings(p['status'])
            if not v or len(v) != 1:
                return 'Unknown', False
            return v[0], v[0] in ('ok', 'okay')

        local, available = state(path)
        if not available:
            notes.append('stdout target unavailable in DT')
        parent = path.rsplit('/', 1)[0] or '/'
        problems = []
        while True:
            value, available = state(parent)
            if not available:
                problems.append(f'{value}: {parent}')
            if parent == '/':
                break
            parent = parent.rsplit('/', 1)[0] or '/'
        parents = '; '.join(problems) or 'okay'
        if problems:
            notes.append('stdout ancestor unavailable in DT')
        if None in props:
            notes.append('incomplete stdout target properties')
    elif path != 'Not available':
        notes.append('stdout target not found')
    raw = chosen.get('bootargs')
    requests = []
    consoles = 'Not available'
    if raw == b'\0':
        consoles = '(none specified)'
    else:
        args = interface_strings(raw)
        if not args or len(args) != 1:
            notes.append('bootargs missing or invalid')
        else:
            lexer = shlex.shlex(args[0], posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ''
            lexer.quotes = '"'
            lexer.escape = ''
            try:
                for token in lexer:
                    if token == '--':
                        break
                    if token.startswith('console='):
                        requests.append(token[8:])
                consoles = ' | '.join(r or '(empty)' for r in requests) if requests else '(none specified)'
                if any(not r for r in requests):
                    notes.append('empty console= value')
            except ValueError:
                notes.append('malformed bootargs quoting')
    if None in chosen:
        notes.append('incomplete chosen properties')
    return (firmware, controller, local, parents, consoles,
            '; '.join(dict.fromkeys(notes)) or 'ok', path,
            f'/chosen/{source}' if output is not None else 'Not available')


class Console(Model):
    """Summarize DT firmware stdout routing and bootargs console requests."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return Model.get_requirements() + [requirements.BooleanRequirement(
            name='details', description='Include resolved DT target and stdout source property',
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
                if name in ('compatible', 'status') or path == '/aliases' or (path == '/chosen' and name in ('stdout-path', 'linux,stdout-path', 'bootargs')):
                    if name in props:
                        props[name] = None
                        diagnostics.append(f'{path}:{name}: duplicate property')
                    else:
                        props[name] = raw if status == 'ok' else None
        for path in duplicates:
            tree[path] = {None: None}
        row = console_summary(tree, diagnostics)
        yield 0, row if self.config.get('details', False) else row[:6]

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        if not kernel.has_symbol('of_root') or not all(kernel.has_type(name) for name in ('device_node', 'property')):
            raise TypeError('Requires of_root and device_node/property types in the matching kernel ISF')
        columns = [('FirmwareOutput', str), ('Controller', str), ('DTStatus', str),
                   ('ParentStatus', str), ('KernelConsoles', str), ('Status', str)]
        if self.config.get('details', False):
            columns += [('Path', str), ('StdoutSource', str)]
        return renderers.TreeGrid(columns, self._generator())
