"""Sparse page-array decoding and physical page conversion regressions."""

from types import SimpleNamespace
from unittest.mock import patch
import pytest
from volatility3.framework import exceptions
from volatility3.framework.symbols.linux.extensions import page


class FakePointer:
    def __init__(self, value):
        self.value = value

    def __int__(self):
        return self.value

    def __bool__(self):
        return bool(self.value)

    def dereference(self):
        return self


class FakeArray(list):
    pass


def fixture(shift=12, layout="pointer", enum=True, empty_first_root=False):
    section_size = 16
    per_root = (1 << shift) // section_size
    section_shift = 29 if shift == 16 else 27
    frames = 1 << (section_shift - shift)
    # A nonzero effective base captures a randomized/nonzero physical origin.
    base = 0xFFFFFC2373000000
    number = per_root if empty_first_root else 0
    highest = number + 1
    roots = [FakePointer(0 if empty_first_root else 0x10000)]
    if empty_first_root:
        roots.append(FakePointer(0x20000))
    encoded = base | 15
    sections = {
        int(roots[number // per_root])
        + (number % per_root) * section_size: SimpleNamespace(section_mem_map=encoded),
        int(roots[number // per_root])
        + ((number + 1) % per_root) * section_size: SimpleNamespace(
            section_mem_map=encoded
        ),
    }
    if layout == "pointer":
        mem_section = FakePointer(0x8000)
    elif layout == "array_pointer":
        mem_section = FakeArray(roots)
    else:
        mem_section = FakeArray(
            [
                FakeArray([SimpleNamespace(section_mem_map=encoded)])
                for _ in range(highest + 1)
            ]
        )
    symbols = {
        "mem_section": mem_section,
        "max_pfn": (highest + 1) * frames,
        "__highest_present_section_nr": highest,
    }
    kernel = SimpleNamespace(
        layer_name="kernel",
        symbol_table_name="symbols",
        get_type=lambda name: SimpleNamespace(
            size=64 if name == "page" else section_size
        ),
        object_from_symbol=lambda name: symbols[name],
        has_symbol=lambda name: name in symbols,
        object=lambda name, offset, absolute: sections.get(
            offset, SimpleNamespace(section_mem_map=0)
        ),
    )
    table = SimpleNamespace(
        enumerations=["flags"] if enum else [],
        get_enumeration=lambda name: SimpleNamespace(
            choices={"SECTION_MAP_LAST_BIT": 4}
        ),
    )
    context = SimpleNamespace(
        modules={"kernel": kernel},
        layers={"kernel": SimpleNamespace(page_shift=shift, page_size=1 << shift)},
        symbol_space={"symbols": table},
    )
    return context, roots, symbols, base, frames, number


def decode(context, roots):
    with patch(
        "volatility3.framework.symbols.linux.extensions.objects.Pointer", FakePointer
    ), patch(
        "volatility3.framework.symbols.linux.extensions.objects.Array", FakeArray
    ), patch(
        "volatility3.framework.symbols.linux.extensions.utility.array_of_pointers",
        return_value=roots,
    ):
        return page._arm64_section_mappings.__wrapped__(context, "kernel")


@pytest.mark.parametrize("shift", [12, 14, 16])
@pytest.mark.parametrize("layout", ["pointer", "array_pointer", "array"])
@pytest.mark.parametrize("enum", [True, False])
def test_sparse_layouts_preserve_encoded_pfn_origin(shift, layout, enum):
    context, roots, _, base, frames, number = fixture(shift, layout, enum)
    assert decode(context, roots) == (
        (base, base + frames * 64, 0),
        (base + frames * 64, base + frames * 128, frames),
    )


def test_skips_absent_root_without_assuming_ram_starts_at_zero():
    context, roots, _, base, frames, number = fixture(empty_first_root=True)
    mappings = decode(context, roots)
    assert mappings[0] == (
        base + number * frames * 64,
        base + (number + 1) * frames * 64,
        number * frames,
    )


def test_rejects_corrupt_section_bound():
    context, roots, symbols, *_ = fixture()
    symbols["__highest_present_section_nr"] += 1
    with pytest.raises(exceptions.VolatilityException, match="highest"):
        decode(context, roots)


@pytest.mark.parametrize(
    "offset,expected",
    [
        (0x1000, 0x200000),
        (0x1040, 0x201000),
        (0x10C0, 0x203000),
        (0x1100, -1),
        (0x0FC0, -1),
        (0x1001, -1),
    ],
)
def test_page_conversion_checks_section_bounds_and_struct_alignment(offset, expected):
    kernel = SimpleNamespace(
        name="kernel",
        layer_name="kernel",
        get_type=lambda name: SimpleNamespace(size=64),
    )
    layer = SimpleNamespace(page_size=4096, canonicalize=lambda value: value)
    context = SimpleNamespace(layers={"kernel": layer})
    fake_page = SimpleNamespace(
        _context=context,
        vol=SimpleNamespace(offset=offset),
        _arm64_section_mappings=lambda *args: ((0x1000, 0x1100, 512),),
    )
    with patch(
        "volatility3.framework.symbols.linux.extensions.linux.LinuxUtilities.get_module_from_volobj_type",
        return_value=kernel,
    ):
        assert page._arm64_to_paddr(fake_page) == expected


def test_no_populated_sections_fails_explicitly():
    context, roots, symbols, *_ = fixture(layout="array")
    for root in symbols["mem_section"]:
        root[0].section_mem_map = 1  # Present, but no initialized mem_map.
    with pytest.raises(exceptions.VolatilityException, match="No readable"):
        decode(context, roots)


def test_overlapping_page_arrays_are_rejected():
    context, roots, symbols, base, frames, _ = fixture(layout="array")
    symbols["mem_section"][1][0].section_mem_map = (base - frames * 64) | 15
    with pytest.raises(exceptions.VolatilityException, match="Overlapping"):
        decode(context, roots)


def test_distinct_section_arrays_keep_their_own_pfn_offsets():
    context, roots, symbols, base, frames, _ = fixture(layout="array")
    symbols["mem_section"][1][0].section_mem_map = (base + frames * 64) | 15
    assert decode(context, roots) == (
        (base, base + frames * 64, 0),
        (base + frames * 128, base + frames * 192, frames),
    )
