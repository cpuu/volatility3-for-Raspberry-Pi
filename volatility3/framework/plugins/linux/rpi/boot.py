"""Raspberry Pi boot analysis from captured kernel Device Tree data."""
from volatility3.framework import renderers
from volatility3.plugins.linux.rpi.model import Model
from volatility3.plugins.linux.rpi.rpi import Rpi


def boot_summary(properties, diagnostics=()):
    """Summarize firmware boot metadata; root= is a requested root, not a mount."""
    import shlex
    notes = list(diagnostics)
    unavailable = 'Not available'
    compatible = properties.get(('/', 'compatible'), b'')
    if not compatible.endswith(b'\0') or not any(
        part.startswith(b'raspberrypi,') for part in compatible[:-1].split(b'\0')
    ):
        raise ValueError('Root compatible does not establish Raspberry Pi identity')

    def text(path, key):
        raw = properties.get((path, key))
        if raw is None:
            notes.append(f'{key} missing')
            return None
        if not raw.endswith(b'\0') or b'\0' in raw[:-1]:
            notes.append(f'invalid {key}')
            return None
        try:
            value = raw[:-1].decode('ascii')
        except UnicodeDecodeError:
            notes.append(f'invalid {key}')
            return None
        if any(ord(c) < 32 or ord(c) > 126 for c in value):
            notes.append(f'invalid {key}')
            return None
        return value

    def u32(key):
        raw = properties.get(('/chosen/bootloader', key))
        if raw is None:
            notes.append(f'{key} missing')
            return None
        if len(raw) != 4:
            notes.append(f'invalid {key} length')
            return None
        return int.from_bytes(raw, 'big')

    mode, partition, trial = u32('boot-mode'), u32('partition'), u32('tryboot')
    modes = {1: 'SD/eMMC', 2: 'Network', 3: 'RPIBOOT', 4: 'USB mass storage',
             5: 'BCM USB mass storage', 6: 'NVMe', 7: 'HTTP'}
    media = unavailable if mode is None else modes.get(mode, f'Unknown (0x{mode:x})')
    if mode is not None and mode not in modes:
        notes.append('unknown boot-mode')
    tryboot = unavailable if trial is None else {0: 'No', 1: 'Yes'}.get(trial, f'Unknown ({trial})')
    if trial is not None and trial not in (0, 1):
        notes.append('unknown tryboot value')
    prefix = text('/chosen', 'os_prefix')
    args = text('/chosen', 'bootargs')
    roots = []
    if args is not None:
        # Kernel parameters support double-quoted values. Do not implement
        # shell expansion, shell comments, single-quote or backslash semantics.
        lexer = shlex.shlex(args, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ''
        lexer.quotes = '"'
        lexer.escape = ''
        try:
            for token in lexer:
                if token == '--':
                    break  # following arguments belong to init
                if token.startswith('root='):
                    roots.append(token[5:])
        except ValueError:
            roots = []
            notes.append('malformed bootargs quoting')
        if not roots:
            notes.append('root= not found')
        elif len(roots) > 1:
            notes.append('multiple root= values; preserved in order')
        if any(not root for root in roots):
            notes.append('empty root= value')
    return (media, str(partition) if partition is not None else unavailable,
            tryboot, unavailable if prefix is None else prefix or '(none)',
            ' | '.join(root or '(empty)' for root in roots) if roots else unavailable,
            '; '.join(dict.fromkeys(notes)) or 'ok')


class Boot(Model):
    """Summarize Pi boot medium, partition, tryboot, OS prefix and requested root."""

    _version = (1, 0, 0)

    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]
        layer = self.context.layers[kernel.layer_name]
        root = int(kernel.object_from_symbol('of_root'))
        if not root:
            raise ValueError('of_root is NULL')
        bounds = [self.config[name] for name in ('max-nodes', 'max-properties', 'max-value')]
        if min(bounds) <= 0:
            raise ValueError('Traversal and value bounds must be positive')
        wanted = {('/', 'compatible'), ('/chosen', 'os_prefix'), ('/chosen', 'bootargs'),
                  ('/chosen/bootloader', 'boot-mode'), ('/chosen/bootloader', 'partition'),
                  ('/chosen/bootloader', 'tryboot')}
        values, seen, diagnostics = {}, set(), []
        for node, path, _, status in Rpi.walk_nodes(kernel, root, bounds[0]):
            if node is None:
                diagnostics.append(status)
                continue
            if path not in ('/', '/chosen', '/chosen/bootloader'):
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
        yield 0, boot_summary(values, diagnostics)

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        if not kernel.has_symbol('of_root') or not all(kernel.has_type(name) for name in ('device_node', 'property')):
            raise TypeError('Requires of_root and device_node/property types in the matching kernel ISF')
        return renderers.TreeGrid([
            ('BootMedia', str), ('Partition', str), ('TryBoot', str),
            ('OSPrefix', str), ('RootFilesystem', str), ('Status', str),
        ], self._generator())
