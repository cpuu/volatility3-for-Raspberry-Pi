"""Regression cases for module ownership and selected-module symbol lookup."""

from types import SimpleNamespace
import pytest
from volatility3.framework.symbols.linux.utilities.modules import Modules, ModuleInfo


def context_for(objects):
    kernel = SimpleNamespace(
        layer_name="kernel",
        object=lambda type_name, offset, absolute: objects[offset],
        get_symbols_by_absolute_location=lambda address: ["vmlinux!kernel_fn"],
    )
    return SimpleNamespace(
        modules={"kernel": kernel},
        layers={"kernel": SimpleNamespace(address_mask=(1 << 64) - 1)},
    )


def obj(symbol, regions=None):
    return SimpleNamespace(
        has_member=lambda name: name == "mem" and regions is not None,
        mem=[SimpleNamespace(base=b, size=s) for b, s in (regions or [])],
        get_symbol_by_address=lambda address: symbol,
    )


def test_symbol_comes_from_selected_module_not_last_candidate():
    modules = [
        ModuleInfo(1, "first", 0x1000, 0x1100),
        ModuleInfo(2, "last", 0x2000, 0x2100),
    ]
    context = context_for({1: obj("first_fn"), 2: obj("wrong_fn")})
    assert Modules.module_lookup_by_address(context, "kernel", modules, 0x1050) == (
        modules[0],
        "first_fn",
    )


@pytest.mark.parametrize(
    "address,owner",
    [
        (0x1000, 0),
        (0x10FF, 0),
        (0x1100, None),
        (0x1200, 1),
        (0x12FF, 1),
        (0x1300, None),
        (0x9000, 0),
        (0x92FF, 0),
        (0x9300, None),
    ],
)
def test_discontiguous_module_allocations_and_exclusive_ends(address, owner):
    # Summing A's allocations would incorrectly claim B and miss A's remote data.
    modules = [ModuleInfo(1, "A", 0x1000, 0x1400), ModuleInfo(2, "B", 0x1200, 0x1300)]
    context = context_for(
        {
            1: obj("a_fn", [(0x1000, 0x100), (0x9000, 0x300), (0, 0x100)]),
            2: obj("b_fn", [(0x1200, 0x100)]),
        }
    )
    expected = (
        (None, None) if owner is None else (modules[owner], ["a_fn", "b_fn"][owner])
    )
    assert (
        Modules.module_lookup_by_address(context, "kernel", modules, address)
        == expected
    )


def test_kernel_lookup_and_legacy_ranges_remain_supported():
    modules = [ModuleInfo(0, "__kernel__", 0x8000, 0x9000)]
    assert Modules.module_lookup_by_address(
        context_for({}), "kernel", modules, 0x8100
    ) == (modules[0], "kernel_fn")


def test_real_overlaps_still_warn_and_use_first_match():
    modules = [ModuleInfo(1, "A", 0x1000, 0x1100), ModuleInfo(2, "B", 0x1000, 0x1100)]
    context = context_for(
        {1: obj("a_fn", [(0x1000, 0x100)]), 2: obj("b_fn", [(0x1000, 0x100)])}
    )
    with pytest.warns(UserWarning, match="overlap"):
        assert Modules.module_lookup_by_address(context, "kernel", modules, 0x1050) == (
            modules[0],
            "a_fn",
        )
