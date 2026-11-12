"""Raspberry Pi rpi analysis from captured kernel Device Tree data."""
import logging
import struct
from datetime import datetime, timezone

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux.rpi.common import DeviceTree

vollog = logging.getLogger(__name__)


def decode_value(name, data, path=""):
    """Conservative DT decoding; raw bytes remain available in every output row."""
    if not data:
        return "boolean", "present"
    # Raspberry Pi documentation: /chosen/bootloader uses big-endian u32
    # properties. Scope interpretation to the exact node to avoid confusing
    # similarly named properties in other hardware bindings.
    # https://www.raspberrypi.com/documentation/computers/configuration.html
    if path == "/chosen/bootloader" and len(data) == 4:
        number = int.from_bytes(data, "big")
        if name == "boot-mode":
            modes = {1: "SD/eMMC", 2: "network", 3: "RPIBOOT", 4: "USB mass storage", 5: "BCM USB mass storage", 6: "NVMe", 7: "HTTP"}
            return "Pi boot mode (u32)", f"{number:#x}: {modes.get(number, 'unknown/reserved')}"
        if name in {"build_timestamp", "update_timestamp", "build-timestamp", "update-timestamp"}:
            meaning = "EEPROM build" if name in {"build_timestamp", "build-timestamp"} else "EEPROM update"
            stamp = datetime.fromtimestamp(number, timezone.utc).isoformat()
            return "Pi EEPROM timestamp (u32)", f"{number}: {stamp} ({meaning}; not boot time)"
        if name == "tryboot":
            return "Pi tryboot (u32)", f"{number}: " + ({0: "not set", 1: "set at boot"}.get(number, "unknown value"))
        if name == "signed":
            labels = {0: "SIGNED_BOOT configured", 2: "ROM development key revoked", 3: "customer key digest in OTP"}
            flags = [label for bit, label in labels.items() if number & (1 << bit)]
            unknown = number & ~0xD
            if unknown:
                flags.append(f"reserved bits {unknown:#x}")
            return "Pi signed flags (u32)", f"{number:#x}: " + (", ".join(flags) or "no reported flags") + " (firmware-reported; not attestation)"
        if name in {"partition", "count", "arg1", "pm_rsts", "rsts", "capabilities"}:
            return "Pi bootloader u32", f"{number} ({number:#x})"
    if name in {"linux,revision", "linux,serial", "boot-mode", "partition", "reset-status"}:
        if len(data) in (4, 8):
            return "big-endian integer", hex(int.from_bytes(data, "big"))
    if data.endswith(b"\0"):
        parts = data[:-1].split(b"\0")
        if all(part and all(32 <= c < 127 or c in (9, 10, 13) for c in part) for part in parts):
            return "string-list", " | ".join(part.decode("ascii") for part in parts)
    if len(data) % 4 == 0:
        return "big-endian cells (uninterpreted)", " ".join(hex(x[0]) for x in struct.iter_unpack(">I", data))
    return "bytes", data.hex()


def eeprom_region(tree, max_size=65536):
    """Resolve blconfig through validated DT metadata, never guessed addresses.

    Returns (path, physical address, byte size). Only identity-mapped reserved
    memory with one reg tuple is supported; reject ambiguous translations.
    tree maps paths to property-name/raw-byte dictionaries.
    """
    alias = tree.get("/aliases", {}).get("blconfig")
    if alias is None:
        raise ValueError("alias-absent-or-unreadable")
    if not alias.endswith(b"\0") or b"\0" in alias[:-1]:
        raise ValueError("invalid-alias")
    try:
        path = alias[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid-alias")
    if not path.startswith("/reserved-memory/") or len(path.split("/")) != 3:
        raise ValueError("unsupported-alias-target")
    if path not in tree:
        raise ValueError("target-absent-or-unreadable")
    target = tree[path]
    if b"raspberrypi,bootloader-config" not in target.get("compatible", b"").rstrip(b"\0").split(b"\0"):
        raise ValueError("unexpected-compatible")
    parent = tree.get("/reserved-memory", {})
    if parent.get("ranges") != b"":
        raise ValueError("unsupported-or-missing-ranges")
    cells = []
    for key in ("#address-cells", "#size-cells"):
        value = parent.get(key, b"")
        if len(value) != 4 or int.from_bytes(value, "big") not in (1, 2):
            raise ValueError("unsupported-or-missing-cells")
        cells.append(int.from_bytes(value, "big"))
    ac, sc = cells
    reg = target.get("reg", b"")
    if len(reg) != 4 * (ac + sc):
        raise ValueError("invalid-or-multiple-reg")
    address = int.from_bytes(reg[:4*ac], "big")
    size = int.from_bytes(reg[4*ac:], "big")
    if size == 0 or size > max_size or address + size > 1 << 64:
        raise ValueError("invalid-or-oversized-region")
    return path, address, size


def read_eeprom(physical, address, size):
    """Read exactly the declared bytes; never pad missing evidence with zeros."""
    try:
        raw = physical.read(address, size, pad=False)
    except exceptions.InvalidAddressException:
        return b"", "", "unavailable-in-physical-layer"
    if len(raw) != size:
        return raw, "", "short-read"
    # Preserve all bytes; a single trailing NUL is a text terminator, not data
    # to silently discard from the raw evidence.
    text_bytes = raw[:-1] if raw.endswith(b"\0") else raw
    if not text_bytes:
        return raw, "", "empty-text"
    if any(c not in (9, 10, 13) and not 32 <= c < 127 for c in text_bytes):
        return raw, "", "non-text-region"
    text = text_bytes.decode("ascii")
    # Do not evaluate conditional sections or collapse repeated keys. Preserve
    # source text, including comments/order. A printable region alone is not
    # sufficient evidence of configuration content.
    if not any("=" in line and line.split("=", 1)[0].strip()
               for line in text.splitlines() if not line.lstrip().startswith("#")):
        return raw, text, "unrecognized-config-text"
    return raw, text, "recovered"


def category(path, name):
    if path == "/" and name in {"model", "compatible", "serial-number"}:
        return "board-identity"
    if path == "/system" or path.startswith("/system/"):
        return "board-identity"
    if path == "/chosen" or path.startswith("/chosen/"):
        return "boot-configuration"
    if path == "/hat" or path.startswith("/hat/"):
        return "hat-metadata"
    if path == "/aliases":
        return "peripheral-alias"
    if name in {"status", "compatible", "pinctrl-names", "gpio-line-names", "label"}:
        return "hardware-configuration"
    return "device-tree"


class Rpi(DeviceTree, interfaces.plugins.PluginInterface):
    """Recover Pi board, boot, HAT and peripheral configuration from kernel memory."""

    _required_framework_version = (2, 0, 0)
    _version = (0, 2, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["AArch64", "Intel32", "Intel64"]),
            requirements.BooleanRequirement(name="allow-generic", description="Allow a non-Pi tree for negative-control research", default=False, optional=True),
            requirements.IntRequirement(name="max-eeprom", description="Maximum EEPROM config region bytes", default=65536, optional=True),
            requirements.IntRequirement(name="max-nodes", description="Maximum live device-tree nodes", default=16384, optional=True),
            requirements.IntRequirement(name="max-properties", description="Maximum properties per node", default=1024, optional=True),
            requirements.IntRequirement(name="max-value", description="Maximum bytes read per property", default=65536, optional=True),
        ]




    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]
        root = int(kernel.object_from_symbol("of_root"))
        if not root:
            raise ValueError("of_root is NULL: no live Device Tree is available")
        root_node = kernel.object("device_node", offset=root, absolute=True)
        max_nodes = self.config["max-nodes"]
        max_properties = self.config["max-properties"]
        max_value = self.config["max-value"]
        if min(max_nodes, max_properties, max_value) <= 0:
            raise ValueError("Traversal and value bounds must be positive")
        root_properties = list(self.read_properties(kernel, layer, root_node, max_properties, max_value))
        compatible = [row[4] for row in root_properties if row[1] == "compatible" and row[5] == "ok"]
        is_pi = any(value.endswith(b"\0") and any(part.startswith(b"raspberrypi,") for part in value[:-1].split(b"\0")) for value in compatible)
        if not is_pi and not self.config["allow-generic"]:
            raise ValueError("Root compatible does not establish Raspberry Pi identity (non-Pi, missing, or unreadable). Use --allow-generic only for research.")
        platform = "raspberry-pi" if is_pi else "generic-or-unverified"
        eeprom_tree, eeprom_sources = {}, {}
        duplicate_metadata = False
        for node, path, node_address, status in self.walk_nodes(kernel, root, max_nodes):
            if node is None:
                vollog.warning("%s at %#x", status, node_address)
                yield 0, (platform, "diagnostic", path, format_hints.Hex(node_address), "", format_hints.Hex(0), format_hints.Hex(0), 0, "", "", "", status)
                continue
            collect = path == "/aliases" or path == "/reserved-memory" or path.startswith("/reserved-memory/")
            if collect:
                if path in eeprom_tree:
                    duplicate_metadata = True
                eeprom_tree[path] = {}
                eeprom_sources[path] = (node_address, 0)
            properties = root_properties if node_address == root else self.read_properties(kernel, layer, node, max_properties, max_value)
            for prop_address, name, value_address, length, data, status in properties:
                if collect:
                    if name in eeprom_tree[path]:
                        duplicate_metadata = True
                    if status == "ok":
                        eeprom_tree[path][name] = data
                    if name == "reg":
                        eeprom_sources[path] = (node_address, prop_address)
                encoding, value = decode_value(name, data, path if is_pi else "") if status == "ok" else ("", "")
                if status != "ok":
                    vollog.warning("%s at %s property %#x", status, path, prop_address)
                yield 0, (platform, category(path, name), path, format_hints.Hex(node_address), name, format_hints.Hex(prop_address), format_hints.Hex(value_address), length, encoding, value, data.hex(), status)

        if is_pi:
            path, address, size = "/aliases", 0, 0
            raw, value, status = b"", "", ""
            try:
                if duplicate_metadata:
                    raise ValueError("ambiguous-device-tree-metadata")
                max_eeprom = self.config.get("max-eeprom", 65536)
                if max_eeprom <= 0:
                    raise ValueError("invalid-max-eeprom")
                path, address, size = eeprom_region(eeprom_tree, max_eeprom)
                physical_name = layer.config.get("memory_layer")
                if not physical_name or physical_name not in self.context.layers:
                    status = "physical-layer-unavailable"
                else:
                    raw, value, status = read_eeprom(self.context.layers[physical_name], address, size)
            except ValueError as exc:
                status = str(exc)
            node_address, prop_address = eeprom_sources.get(path, (0, 0))
            yield 0, (platform, "eeprom-config", path, format_hints.Hex(node_address),
                      "blconfig", format_hints.Hex(prop_address), format_hints.Hex(address),
                      size, "ASCII config (physical memory)", value, raw.hex(), status)

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        if not kernel.has_symbol("of_root") or not all(kernel.has_type(name) for name in ("device_node", "property")):
            raise TypeError("Requires of_root and device_node/property types in the matching kernel ISF")
        return renderers.TreeGrid([
            ("Platform", str), ("Category", str), ("Path", str),
            ("Node", format_hints.Hex), ("Property", str),
            ("PropertyAddress", format_hints.Hex), ("ValueAddress", format_hints.Hex),
            ("Length", int), ("Encoding", str), ("Value", str), ("RawHex", str), ("Status", str),
            ("AddressSpace", str),
        ], ((depth, row + ("physical" if row[1] == "eeprom-config" else "kernel-virtual",))
            for depth, row in self._generator()))
