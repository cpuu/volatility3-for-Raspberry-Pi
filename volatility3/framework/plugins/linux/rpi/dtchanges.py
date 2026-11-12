"""Raspberry Pi dtchanges analysis from captured kernel Device Tree data."""
import struct

from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux.rpi.model import Model
from volatility3.plugins.linux.rpi.rpi import Rpi
from volatility3.plugins.linux.rpi.common import interface_strings


DTCHANGES_MAX_FDT_SIZE = 16 * 1024 * 1024


def dtchanges_fdt_header(blob):
    if len(blob) < 40:
        raise ValueError("Truncated FDT header")
    values = struct.unpack_from(">10I", blob)
    magic, total, tree, strings, reserve, version, compatible, _, nstrings, ntree = values
    if magic != 0xD00DFEED:
        raise ValueError("Invalid FDT magic")
    if not 40 <= total <= DTCHANGES_MAX_FDT_SIZE:
        raise ValueError("FDT totalsize exceeds bounds")
    if version < 17 or compatible > 17:
        raise ValueError("Only version 17-compatible FDT headers are supported")
    for offset, size in ((tree, ntree), (strings, nstrings)):
        if offset < 40 or size > total or offset > total - size:
            raise ValueError("FDT block outside declared totalsize")
    if tree % 4 or ntree % 4 or reserve % 8 or not 40 <= reserve <= total - 16:
        raise ValueError("Invalid FDT alignment or reservation offset")
    if tree < strings + nstrings and strings < tree + ntree:
        raise ValueError("Overlapping FDT structure and strings blocks")
    return total, tree, strings, reserve, nstrings, ntree


def dtchanges_parse_fdt(blob):
    """Return (node path, property, value offset, raw bytes), validating first."""
    total, tree, strings, reserve, nstrings, ntree = dtchanges_fdt_header(blob)
    if len(blob) != total:
        raise ValueError("FDT input size differs from totalsize")
    limit = tree + ntree
    cursor = reserve
    while True:
        if cursor + 16 > total:
            raise ValueError("Unterminated FDT reservation map")
        if (cursor < limit and tree < cursor + 16) or (
            cursor < strings + nstrings and strings < cursor + 16
        ):
            raise ValueError("FDT reservation map overlaps another block")
        address, length = struct.unpack_from(">QQ", blob, cursor)
        cursor += 16
        if address == 0 and length == 0:
            break
    cursor = tree
    stack, rows, seen_nodes, seen_properties = [], [], set(), set()
    root_seen = False
    while cursor + 4 <= limit:
        token = struct.unpack_from(">I", blob, cursor)[0]
        cursor += 4
        if token == 1:  # FDT_BEGIN_NODE
            end = blob.find(b"\0", cursor, limit)
            if end < 0:
                raise ValueError("Unterminated FDT node name")
            name = blob[cursor:end].decode("ascii", errors="strict")
            if "/" in name or (not stack and (root_seen or name)) or (stack and not name):
                raise ValueError("Invalid FDT node nesting/name")
            if len(stack) >= 256:
                raise ValueError("FDT depth exceeds limit")
            stack.append(name)
            root_seen = True
            path = "/" + "/".join(stack[1:])
            if path in seen_nodes:
                raise ValueError("Duplicate FDT node")
            seen_nodes.add(path)
            cursor = (end + 4) & ~3
        elif token == 2:  # FDT_END_NODE
            if not stack:
                raise ValueError("Unbalanced FDT end node")
            stack.pop()
        elif token == 3:  # FDT_PROP
            if not stack or cursor + 8 > limit:
                raise ValueError("FDT property outside a node or truncated")
            length, nameoff = struct.unpack_from(">II", blob, cursor)
            cursor += 8
            if length > limit - cursor or nameoff >= nstrings:
                raise ValueError("FDT property exceeds block bounds")
            end = blob.find(b"\0", strings + nameoff, strings + nstrings)
            if end < 0:
                raise ValueError("Unterminated FDT property name")
            name = blob[strings + nameoff:end].decode("ascii", errors="strict")
            if not name or "/" in name:
                raise ValueError("Invalid FDT property name")
            path = "/" + "/".join(stack[1:])
            if (path, name) in seen_properties:
                raise ValueError("Duplicate FDT property")
            seen_properties.add((path, name))
            rows.append((path, name, cursor, blob[cursor:cursor + length]))
            cursor = (cursor + length + 3) & ~3
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            if stack or not root_seen:
                raise ValueError("FDT ends before root is closed")
            return rows, seen_nodes
        else:
            raise ValueError(f"Unknown FDT token {token}")
    raise ValueError("Missing FDT_END token")


def dtchanges_compare(boot, live, boot_nodes, live_nodes, diagnostics=(), include_generated=False):
    """Compare raw bytes only; incomplete reads never imply absence or equality.

    Maps contain (path, property): (raw bytes, kernel virtual value address).
    Generated-name classification is structural, not proof of provenance.
    """
    if diagnostics:
        return [('Unavailable', '', '', '', '', '; '.join(diagnostics), '', '', '', '')]
    for label, values in (('boot', boot), ('live', live)):
        compatible = interface_strings(values.get(('/', 'compatible'), (b'', 0))[0])
        if not compatible or not any(s.startswith('raspberrypi,') for s in compatible):
            return [('Unavailable', '', '', '', '', label + ': Raspberry Pi identity not established', '', '', '', '')]

    def preview(raw):
        if raw is None:
            return '(absent)'
        strings = interface_strings(raw)
        value = repr(' | '.join(strings)) if strings else ('(empty)' if not raw else 'hex:' + raw[:48].hex())
        return value[:120] + ('...' if len(value) > 120 or (not strings and len(raw) > 48) else '')

    rows, generated, unchanged = [], 0, 0
    for path in sorted(boot_nodes ^ live_nodes):
        rows.append(('NodeAdded' if path in live_nodes else 'NodeRemoved', path, '', '', '', 'ok', '', '', '', ''))
    for key in sorted(boot.keys() | live.keys()):
        old, oldaddr = boot.get(key, (None, None))
        new, newaddr = live.get(key, (None, None))
        if old == new:
            unchanged += 1
            continue
        path, name = key
        kind = 'Added' if old is None else ('Removed' if new is None else 'Modified')
        basename = path.rsplit('/', 1)[-1].rsplit('@', 1)[0]
        # Only hide name synthesis on nodes already present in the retained blob.
        if old is None and name == 'name' and path in boot_nodes and new == basename.encode('ascii') + b'\0':
            generated += 1
            kind = 'GeneratedName'
            if not include_generated:
                continue
        rows.append((kind, path, name, preview(old), preview(new), 'ok',
                     '' if oldaddr is None else hex(oldaddr), '' if newaddr is None else hex(newaddr),
                     '' if old is None else old.hex(), '' if new is None else new.hex()))
    summary = f'boot={len(boot)}; live={len(live)}; unchanged={unchanged}; generated-name={generated}'
    return [('Summary' if rows else 'No changes', '', '', '', '', summary, '', '', '', '')] + rows


class DtChanges(Model):
    """Compare retained initial_boot_params with live DT nodes and properties."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return Model.get_requirements() + [
            requirements.BooleanRequirement(name='details', description='Show full raw bytes and kernel virtual value addresses', default=False, optional=True),
            requirements.BooleanRequirement(name='include-generated', description='Include live-only name properties matching kernel synthesis', default=False, optional=True)]

    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]
        layer = self.context.layers[kernel.layer_name]
        boot, live, boot_nodes, live_nodes, errors = {}, {}, set(), set(), []
        bounds = [self.config[name] for name in ('max-nodes', 'max-properties', 'max-value')]
        if min(bounds) <= 0:
            raise ValueError('Traversal and value bounds must be positive')
        try:
            if not kernel.has_symbol('initial_boot_params') or not kernel.has_symbol('of_root'):
                raise ValueError('Requires initial_boot_params and of_root symbols')
            address = int(kernel.object_from_symbol('initial_boot_params'))
            root = int(kernel.object_from_symbol('of_root'))
            if not address or not root:
                raise ValueError('NULL retained FDT or live DT pointer')
            total, *_ = dtchanges_fdt_header(layer.read(address, 40, pad=False))
            props, boot_nodes = dtchanges_parse_fdt(layer.read(address, total, pad=False))
            boot = {(path, name): (raw, address + offset) for path, name, offset, raw in props}
            for node, path, _, status in Rpi.walk_nodes(kernel, root, bounds[0]):
                if node is None or status != 'ok':
                    errors.append(f'{path}: {status}')
                    continue
                if path in live_nodes:
                    errors.append(f'duplicate node {path}')
                live_nodes.add(path)
                for _, name, valueaddr, length, raw, status in Rpi.read_properties(kernel, layer, node, bounds[1], bounds[2]):
                    key = (path, name)
                    if status != 'ok' or not name or len(raw) != length or key in live:
                        errors.append(f'{path}:{name}: {status}; invalid/duplicate/incomplete property')
                        continue
                    live[key] = (raw, valueaddr)
        except (exceptions.InvalidAddressException, ValueError, UnicodeError) as error:
            errors.append(str(error))
        rows = dtchanges_compare(boot, live, boot_nodes, live_nodes, errors, self.config.get('include-generated', False))
        for row in rows:
            yield 0, row if self.config.get('details', False) else row[:6]

    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        if not all(kernel.has_type(name) for name in ('device_node', 'property')):
            raise TypeError('Requires device_node/property types in the matching kernel ISF')
        columns = [(name, str) for name in ('Change', 'Path', 'Property', 'BootValue', 'LiveValue', 'Status')]
        if self.config.get('details', False):
            columns += [(name, str) for name in ('BootValueAddress', 'LiveValueAddress', 'BootRawHex', 'LiveRawHex')]
        return renderers.TreeGrid(columns, self._generator())
