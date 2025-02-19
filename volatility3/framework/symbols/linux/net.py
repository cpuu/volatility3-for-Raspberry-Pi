from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import net
from volatility3.framework.interfaces.configuration import VersionableInterface


class NetSymbols(VersionableInterface):
    _version = (1, 0, 0)

    @classmethod
    def apply(cls, symbol_table: intermed.IntermediateSymbolTable):
        # Network
        symbol_table.set_type_class("net", net.net)
        symbol_table.set_type_class("net_device", net.net_device)
        symbol_table.set_type_class("in_device", net.in_device)
        symbol_table.set_type_class("in_ifaddr", net.in_ifaddr)
        symbol_table.set_type_class("inet6_dev", net.inet6_dev)
        symbol_table.set_type_class("inet6_ifaddr", net.inet6_ifaddr)
        symbol_table.set_type_class("socket", net.socket)
        symbol_table.set_type_class("sock", net.sock)
        symbol_table.set_type_class("inet_sock", net.inet_sock)
        symbol_table.set_type_class("unix_sock", net.unix_sock)
        # Might not exist in older kernels or the current symbols
        symbol_table.optional_set_type_class("netlink_sock", net.netlink_sock)
        symbol_table.optional_set_type_class("vsock_sock", net.vsock_sock)
        symbol_table.optional_set_type_class("packet_sock", net.packet_sock)
        symbol_table.optional_set_type_class("bt_sock", net.bt_sock)
        symbol_table.optional_set_type_class("xdp_sock", net.xdp_sock)
