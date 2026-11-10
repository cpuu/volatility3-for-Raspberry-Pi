"""Sysfs module discovery returns module structs, never pointer-slot offsets."""

from types import SimpleNamespace as NS
from unittest.mock import MagicMock
import pytest
from volatility3.framework import objects
from volatility3.framework.symbols.linux.utilities.modules import Modules
from volatility3.framework.objects import utility


@pytest.mark.parametrize(
    "target,readable,refs,expected",
    [
        (0x1000, True, 3, True),
        (0, False, 3, False),
        (0x1000, False, 3, False),
        (0x1000, True, 2, False),
    ],
)
def test_kset_result_is_dereferenced(monkeypatch, target, readable, refs, expected):
    module = NS(vol=NS(offset=target))
    ptr = MagicMock(spec=objects.Pointer)
    ptr.vol = NS(offset=0x1090)
    ptr.__bool__.return_value = bool(target)
    ptr.is_readable.return_value = readable
    ptr.dereference.return_value = module
    obj = NS(name="test_module", vol=NS(offset=0x1040), reference_count=lambda: refs)
    head = NS(list=NS(to_list=lambda *args: [obj]))
    k = NS(
        symbol_table_name="kernel",
        object_from_symbol=lambda *args: head,
        get_type=lambda *args: NS(relative_child_offset=lambda name: 0),
        object=lambda **kwargs: NS(mod=ptr),
    )
    monkeypatch.setattr(utility, "pointer_to_string", lambda p, n: p)
    result = Modules.get_kset_modules(NS(modules={"kernel": k}), "kernel")
    if expected:
        assert result == {"test_module": module}
        assert result["test_module"].vol.offset == 0x1000
    else:
        assert result == {}
        ptr.dereference.assert_not_called()


def test_sysfs_gatherer_preserves_module_objects(monkeypatch):
    from volatility3.framework.symbols.linux.utilities.modules import (
        ModuleGathererSysFs,
    )

    modules = [NS(vol=NS(offset=0x1000)), NS(vol=NS(offset=0x2000))]
    monkeypatch.setattr(
        Modules, "get_kset_modules", lambda *args: dict(zip(["one", "two"], modules))
    )
    assert list(ModuleGathererSysFs.gather_modules(NS(), "kernel")) == modules
