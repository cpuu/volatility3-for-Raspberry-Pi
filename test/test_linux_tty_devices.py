"""Driver arrays and file-backed Unix98 PTY discovery."""

from types import SimpleNamespace

import pytest

from volatility3.framework.symbols import linux
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux.malware.tty_check import Tty_Check


class Pointer(int):
    def dereference(self):
        assert self != 0, "Null pointer must not be dereferenced"
        return self.target


def pointer(address, target=None):
    result = Pointer(address)
    result.target = target
    return result


@pytest.mark.parametrize("private_type", [False, True])
@pytest.mark.parametrize("valid_owner", [False, True])
def test_null_arrays_peer_cycles_and_file_deduplication(
    monkeypatch, private_type, valid_owner
):
    serial = pointer(0x100)
    master = pointer(0x200)
    slave = pointer(0x300)
    serial.target = SimpleNamespace(driver=0x10, has_member=lambda name: False)
    master.target = SimpleNamespace(
        driver=0x20, has_member=lambda name: True, link=slave
    )
    slave.target = SimpleNamespace(
        driver=0x30, has_member=lambda name: True, link=master
    )
    drivers = [
        SimpleNamespace(
            vol=SimpleNamespace(offset=0x10), ttys=pointer(0x1000, "array"), num=1
        ),
        SimpleNamespace(vol=SimpleNamespace(offset=0x20), ttys=pointer(0), num=1048576),
        SimpleNamespace(vol=SimpleNamespace(offset=0x30), ttys=pointer(0), num=1048576),
    ]
    filp = pointer(0x400)
    filp.f_op = 0x500
    filp.private_data = 0x600
    private = SimpleNamespace(file=0x400 if valid_owner else 0xBAD, tty=master)
    module = SimpleNamespace(
        symbol_table_name="vmlinux",
        offset=0,
        has_type=lambda name: private_type,
        has_symbol=lambda name: name == "ptmx_fops",
        get_symbol=lambda name: SimpleNamespace(address=0x500),
        object=lambda **kwargs: private,
    )
    plugin = SimpleNamespace(context=object(), config={"kernel": "kernel"})
    head = SimpleNamespace(to_list=lambda *args: drivers)
    monkeypatch.setattr(
        utility,
        "array_of_pointers",
        lambda *args, **kwargs: [serial, serial, pointer(0)],
    )
    monkeypatch.setattr(
        pslist.PsList, "list_tasks", lambda *args, **kwargs: [object(), object()]
    )
    monkeypatch.setattr(
        linux.LinuxUtilities,
        "files_descriptors_for_process",
        lambda *args: iter([(0, filp, "/dev/ptmx"), (1, filp, "/dev/ptmx")]),
    )
    found = list(Tty_Check._get_tty_devices(plugin, module, head))
    expected = [serial.target]
    if private_type and valid_owner:
        expected += [master.target, slave.target]
    assert found == expected
