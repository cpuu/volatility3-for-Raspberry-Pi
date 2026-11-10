"""Sysfs module discovery follows live kobject ownership, not a refcount quota."""

from types import SimpleNamespace as NS
from unittest.mock import MagicMock
import pytest
from volatility3.framework import exceptions, objects
from volatility3.framework.symbols.linux.utilities.modules import Modules
from volatility3.framework.objects import utility


def kset_fixture(monkeypatch, target=0x1000, readable=True, refs=2, owner=0x1040):
    module = NS(vol=NS(offset=target), mkobj=NS(kobj=NS(vol=NS(offset=owner))))
    ptr = MagicMock(spec=objects.Pointer)
    ptr.vol = NS(offset=0x1090)
    ptr.__bool__.return_value = bool(target)
    ptr.is_readable.return_value = readable
    ptr.dereference.return_value = module
    obj = NS(name="test_module", vol=NS(offset=0x1040), reference_count=lambda: refs)
    head = NS(list=NS(to_list=lambda *args: [obj]))
    kernel = NS(
        symbol_table_name="kernel",
        object_from_symbol=lambda *args: head,
        get_type=lambda *args: NS(relative_child_offset=lambda name: 0),
        object=lambda **kwargs: NS(mod=ptr),
    )
    monkeypatch.setattr(utility, "pointer_to_string", lambda p, n: p)
    return NS(modules={"kernel": kernel}), module, ptr, obj


@pytest.mark.parametrize("refs", [1, 2, 3, 4])
def test_live_kset_module_is_dereferenced_without_refcount_quota(monkeypatch, refs):
    context, module, ptr, _ = kset_fixture(monkeypatch, refs=refs)
    result = Modules.get_kset_modules(context, "kernel")
    assert result == {"test_module": module}
    assert result["test_module"].vol.offset == 0x1000
    assert result["test_module"].vol.offset != ptr.vol.offset


@pytest.mark.parametrize(
    "target,readable,refs",
    [(0, False, 3), (0x1000, False, 3), (0x1000, True, 0), (0x1000, True, -1)],
)
def test_null_unreadable_or_released_module_is_excluded(
    monkeypatch, target, readable, refs
):
    context, _, ptr, _ = kset_fixture(monkeypatch, target, readable, refs)
    assert Modules.get_kset_modules(context, "kernel") == {}
    ptr.dereference.assert_not_called()


def test_kobject_cannot_point_to_an_unrelated_readable_module(monkeypatch):
    context, _, _, _ = kset_fixture(monkeypatch, owner=0x2040)
    assert Modules.get_kset_modules(context, "kernel") == {}


@pytest.mark.parametrize("name", [None, ""])
def test_missing_name_is_excluded(monkeypatch, name):
    context, _, ptr, obj = kset_fixture(monkeypatch)
    obj.name = name
    assert Modules.get_kset_modules(context, "kernel") == {}
    ptr.dereference.assert_not_called()


@pytest.mark.parametrize("failure", ["module", "name", "owner"])
def test_partial_or_unmapped_memory_is_skipped(monkeypatch, failure):
    context, module, ptr, _ = kset_fixture(monkeypatch)
    error = exceptions.InvalidAddressException("kernel", 0xDEAD)
    if failure == "module":
        ptr.dereference.side_effect = error
    elif failure == "name":
        monkeypatch.setattr(utility, "pointer_to_string", MagicMock(side_effect=error))
    else:

        class UnreadableOwner:
            @property
            def kobj(self):
                raise error

        module.mkobj = UnreadableOwner()
    assert Modules.get_kset_modules(context, "kernel") == {}


def test_kobject_name_is_not_filtered_by_module_name(monkeypatch):
    # Check_modules must be able to observe a sysfs/procfs name discrepancy.
    context, module, _, obj = kset_fixture(monkeypatch)
    module.name = "different_module_name"
    obj.name = "sysfs_name"
    assert Modules.get_kset_modules(context, "kernel") == {"sysfs_name": module}


def test_sysfs_gatherer_preserves_module_objects(monkeypatch):
    from volatility3.framework.symbols.linux.utilities.modules import (
        ModuleGathererSysFs,
    )

    modules = [NS(vol=NS(offset=0x1000)), NS(vol=NS(offset=0x2000))]
    monkeypatch.setattr(
        Modules, "get_kset_modules", lambda *args: dict(zip(["one", "two"], modules))
    )
    assert list(ModuleGathererSysFs.gather_modules(NS(), "kernel")) == modules
