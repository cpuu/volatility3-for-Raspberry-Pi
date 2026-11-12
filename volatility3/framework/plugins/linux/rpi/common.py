"""Shared bounded Device Tree traversal and Raspberry Pi interface decoding."""
from volatility3.framework import exceptions
from volatility3.framework.objects import utility


class DeviceTree:
    """Traversal helpers shared by the Raspberry Pi plugin family."""

    @staticmethod
    def _string(pointer):
        return utility.pointer_to_string(pointer, 1024)

    @classmethod
    def walk_nodes(cls, kernel, root, limit):
        """Iterative bounded traversal; shared/cyclic links are explicitly diagnosed."""
        seen = set()
        stack = [(root, "/", True)]
        while stack:
            address, parent, is_root = stack.pop()
            if address in seen:
                yield None, parent, address, "node-cycle-or-shared-link"
                continue
            if len(seen) >= limit:
                yield None, parent, address, "node-limit-reached"
                return
            seen.add(address)
            try:
                node = kernel.object("device_node", offset=address, absolute=True)
                if is_root:
                    path = "/"
                else:
                    name = cls._string(node.full_name)
                    # full_name is a basename in newer kernels, an absolute path in older ones.
                    path = name if name.startswith("/") else parent.rstrip("/") + "/" + name
                yield node, path, address, "ok"
                sibling = int(node.sibling)
                child = int(node.child)
                if sibling:
                    stack.append((sibling, parent, False))
                if child:
                    stack.append((child, path, False))
            except exceptions.InvalidAddressException:
                yield None, parent, address, "unreadable-node-or-links"

    @classmethod
    def read_properties(cls, kernel, layer, node, limit, max_value):
        seen = set()
        try:
            address = int(node.properties)
        except exceptions.InvalidAddressException:
            yield 0, "", 0, 0, b"", "unreadable-property-head"
            return
        while address:
            if address in seen:
                yield address, "", 0, 0, b"", "property-cycle"
                return
            if len(seen) >= limit:
                yield address, "", 0, 0, b"", "property-limit-reached"
                return
            seen.add(address)
            try:
                prop = kernel.object("property", offset=address, absolute=True)
                next_address = int(prop.next)
            except exceptions.InvalidAddressException:
                yield address, "", 0, 0, b"", "unreadable-property-link"
                return
            name, length, value_address = "", 0, 0
            try:
                name = cls._string(prop.name)
                length = int(prop.length)
                value_address = int(prop.value)
                if length < 0 or length > max_value:
                    yield address, name, value_address, length, b"", "invalid-or-oversized-length"
                elif length and not value_address:
                    yield address, name, value_address, length, b"", "null-value-pointer"
                else:
                    data = layer.read(value_address, length, pad=False) if length else b""
                    yield address, name, value_address, length, data, "ok"
            except exceptions.InvalidAddressException:
                yield address, name, value_address, length, b"", "unreadable-property"
            address = next_address


INTERFACE_BINDINGS = {
    'arm,pl011-axi': ('UART', 'PL011 AXI UART'),
    'arm,pl011': ('UART', 'PL011 UART'),
    'brcm,bcm2835-aux-uart': ('UART', 'BCM2835 mini UART'),
    'brcm,bcm2711-i2c': ('I2C', 'BCM2711 I2C'),
    'brcm,bcm2835-i2c': ('I2C', 'BCM2835 I2C'),
    'brcm,bcm2711-hdmi-i2c': ('I2C', 'BCM2711 HDMI I2C'),
    'brcm,bcm2835-spi': ('SPI', 'BCM2835 SPI'),
    'brcm,bcm2835-aux-spi': ('SPI', 'BCM2835 auxiliary SPI'),
    'brcm,bcm2708-usb': ('USB', 'BCM2708 USB'),
    'brcm,bcm2835-usb': ('USB', 'BCM2835 USB'),
    'brcm,bcm2711-xhci': ('USB', 'BCM2711 xHCI'),
    'brcm,xhci-brcm-v2': ('USB', 'Broadcom xHCI'),
    'generic-xhci': ('USB', 'xHCI'),
}


def interface_strings(raw):
    """Strict DT string-list decoding; None denotes unreadable/malformed data."""
    if raw is None or not raw.endswith(b'\0'):
        return None
    try:
        parts = raw[:-1].decode('ascii').split('\0')
    except UnicodeDecodeError:
        return None
    if any(not p or any(ord(c) < 32 or ord(c) > 126 for c in p) for p in parts):
        return None
    return parts
