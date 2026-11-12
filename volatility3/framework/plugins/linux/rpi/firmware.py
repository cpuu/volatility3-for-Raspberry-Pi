"""Raspberry Pi firmware analysis from captured kernel Device Tree data."""
from datetime import datetime, timezone

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux.rpi.model import Model
from volatility3.plugins.linux.rpi.rpi import Rpi
from volatility3.plugins.linux.rpi.common import interface_strings


def firmware_summary(properties, diagnostics=(), details=False):
    """Interpret firmware-reported metadata; dates are NOT system boot times."""
    import re
    notes = list(diagnostics)
    compat = interface_strings(properties.get(('/', 'compatible')))
    if not compat or not any(c.startswith('raspberrypi,') for c in compat):
        raise ValueError('Root compatible does not establish Raspberry Pi identity')
    unavailable = 'Not available'
    boot = '/chosen/bootloader'

    def string(path, name, optional=False):
        key = (path, name)
        if key not in properties:
            if not optional:
                notes.append(f'{name} missing')
            return None
        value = interface_strings(properties[key])
        if not value or len(value) != 1:
            notes.append(f'invalid {name}')
            return None
        return value[0]

    version = string(boot, 'version')
    display_version = version or unavailable
    if version and not details and re.fullmatch(r'[0-9a-fA-F]{13,64}', version):
        display_version = version[:12] + '...'

    def timestamp(name):
        # Accept both actual hyphenated and documented underscored names.
        entries = [properties[(boot, key)] for key in (name, name.replace('-', '_')) if (boot, key) in properties]
        if not entries:
            notes.append(f'{name} missing')
            return unavailable
        if any(v is None or len(v) != 4 for v in entries):
            notes.append(f'invalid {name} length')
            return unavailable
        if len(set(entries)) != 1:
            notes.append(f'conflicting {name} spellings')
            return unavailable
        number = int.from_bytes(entries[0], 'big')
        if number == 0:
            notes.append(f'{name} is zero (unspecified)')
            return 'Unspecified (0)'
        return datetime.fromtimestamp(number, timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')

    build, update = timestamp('build-timestamp'), timestamp('update-timestamp')
    uboot = string('/chosen', 'u-boot,version', optional=True)
    additional = 'U-Boot ' + uboot if uboot else ('Unknown' if ('/chosen', 'u-boot,version') in properties else 'Not reported')
    uefi, address = 'Not reported', 'Not available'
    key = ('/chosen', 'linux,uefi-system-table')
    if key in properties:
        raw = properties[key]
        if raw is None or len(raw) != 8 or int.from_bytes(raw, 'big') == 0:
            uefi = 'Unknown'
            notes.append('invalid UEFI system-table pointer')
        else:
            uefi = 'Present'
            address = f'0x{int.from_bytes(raw, "big"):x}'
    warning_key = ('/chosen', 'user-warnings')
    raw_warning = properties.get(warning_key)
    warning, warning_hex = 'Not reported', ''
    if warning_key in properties:
        if raw_warning is None:
            warning = 'Unknown'
            notes.append('unreadable user-warnings')
        else:
            warning_hex = raw_warning.hex()
            content = raw_warning[:-1] if raw_warning.endswith(b'\0') else raw_warning
            # This property can be newline-terminated rather than a DT string.
            if any(c not in (9, 10, 13) and not 32 <= c < 127 for c in content):
                warning = 'Unknown (non-text)'
                notes.append('invalid user-warnings text')
            else:
                warning = content.decode('ascii').replace('\\', '\\\\').replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t') or '(empty)'
    row = (display_version, build, update, additional, uefi, warning,
           '; '.join(dict.fromkeys(notes)) or 'ok')
    return row + (address, warning_hex) if details else row


class Firmware(Model):
    """Summarize EEPROM version/timestamps, U-Boot, UEFI metadata and warnings."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return Model.get_requirements() + [requirements.BooleanRequirement(
            name='details', description='Show full version, UEFI table address and warning bytes',
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
        wanted = {('/', 'compatible'), ('/chosen', 'u-boot,version'),
                  ('/chosen', 'linux,uefi-system-table'), ('/chosen', 'user-warnings')}
        wanted.update(('/chosen/bootloader', key) for key in
                      ('version', 'build-timestamp', 'update-timestamp', 'build_timestamp', 'update_timestamp'))
        values, seen, diagnostics = {}, set(), []
        for node, path, _, status in Rpi.walk_nodes(kernel, root, bounds[0]):
            if node is None:
                diagnostics.append(f'{path}: {status}')
                continue
            if path not in ('/', '/chosen', '/chosen/bootloader'):
                continue
            for _, name, _, _, raw, status in Rpi.read_properties(kernel, layer, node, bounds[1], bounds[2]):
                key = (path, name)
                if key in wanted:
                    if key in seen:
                        values[key] = None
                        diagnostics.append(f'duplicate {path}:{name}')
                    else:
                        seen.add(key)
                        values[key] = raw if status == 'ok' else None
                        if status != 'ok':
                            diagnostics.append(f'{path}:{name}: {status}')
                elif status != 'ok':
                    diagnostics.append(status)
        yield 0, firmware_summary(values, diagnostics, self.config.get('details', False))

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        if not kernel.has_symbol('of_root') or not all(kernel.has_type(name) for name in ('device_node', 'property')):
            raise TypeError('Requires of_root and device_node/property types in the matching kernel ISF')
        columns = [('BootloaderVersion', str), ('EEPROMBuildUTC', str), ('EEPROMUpdateUTC', str),
                   ('AdditionalBootloader', str), ('UEFIData', str), ('FirmwareWarnings', str), ('Status', str)]
        if self.config.get('details', False):
            columns += [('UEFISystemTable', str), ('WarningsRawHex', str)]
        return renderers.TreeGrid(columns, self._generator())
