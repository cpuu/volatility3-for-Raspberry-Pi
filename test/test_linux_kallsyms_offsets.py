"""Kallsyms offset encodings and evidence-based mode selection."""

from types import SimpleNamespace

import pytest

from volatility3.framework import exceptions
from volatility3.framework.symbols.linux.kallsyms import Kallsyms


def decoder(value, base=0xFFFF800000000000, expected=None, symbol="_stext"):
    kas = object.__new__(Kallsyms)
    kas._context = SimpleNamespace(
        layers={"kernel": SimpleNamespace(address_mask=(1 << 64) - 1)}
    )
    kas._layer_name = "kernel"
    kas._relative_to_entry = False
    kas._kallsyms_relative_base = base
    kas._kallsyms_offsets_address = 0x1000
    kas._kallsyms_num_syms = 1
    kas._long_size = 8
    kas._kas_config = SimpleNamespace(_stext=expected, addresses_address=None)
    kas._expand_symbol = lambda offset: (SimpleNamespace(name=symbol), 1)

    def read(address, size, signed=False):
        if value is None:
            return None
        return (
            value - (1 << (size * 8))
            if signed and value >= (1 << (size * 8 - 1))
            else value
        )

    kas._read_int = read
    return kas


@pytest.mark.parametrize("value", [0, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF])
def test_unsigned_relative_offsets_preserve_all_32_bits(value):
    kas = decoder(value)
    kas._absolute_percpu = False
    assert kas._get_symbol_address_by_index(0) == kas._kallsyms_relative_base + value


@pytest.mark.parametrize(
    "value,delta", [(0xFFFFFFFF, 0), (0xFFFEFFFF, 0x10000), (0x80000000, 0x7FFFFFFF)]
)
def test_negative_percpu_offsets(value, delta):
    kas = decoder(value)
    kas._absolute_percpu = True
    assert kas._get_symbol_address_by_index(0) == kas._kallsyms_relative_base + delta


@pytest.mark.parametrize("value", [0, 0x1234, 0x7FFFFFFF])
def test_nonnegative_percpu_offsets_are_absolute(value):
    kas = decoder(value)
    kas._absolute_percpu = True
    assert kas._get_symbol_address_by_index(0) == value


@pytest.mark.parametrize("raw,percpu", [(0x10000, False), (0xFFFEFFFF, True)])
def test_mode_selected_from_known_text_address(raw, percpu):
    kas = decoder(raw, expected=0xFFFF800000010000)
    assert kas._detect_absolute_percpu() is percpu


@pytest.mark.parametrize(
    "value,base,expected,symbol",
    [
        (None, 0xFFFF800000000000, 0xFFFF800000010000, "_stext"),
        (0x10000, 0xFFFF800000000000, None, "_stext"),
        (0x10000, 0xFFFF800000000000, 0xFFFF800000010000, "other"),
        (0x10000, 0xFFFF800000000000, 0xFFFF800000020000, "_stext"),
        (0, 0, 0, "_stext"),
    ],
)
def test_missing_mismatched_or_ambiguous_evidence_fails(value, base, expected, symbol):
    kas = decoder(value, base, expected, symbol)
    with pytest.raises(exceptions.VolatilityException, match="Cannot determine"):
        kas._detect_absolute_percpu()


def test_absolute_address_array_and_unreadable_offset():
    kas = decoder(0xFFFF800000012345)
    kas._kallsyms_offsets_address = None
    kas._kas_config.addresses_address = 0x2000
    assert kas._get_symbol_address_by_index(0) == 0xFFFF800000012345
    kas = decoder(None)
    kas._absolute_percpu = False
    assert kas._get_symbol_address_by_index(0) is None


@pytest.mark.parametrize("member_offset,relative", [(0, 0x80), (4, 0x80), (8, -0x40)])
def test_prel32_is_relative_to_each_field(member_offset, relative):
    from volatility3.framework.symbols.linux.extensions import kernel_symbol

    class Field(int):
        pass

    field = Field(relative)
    field.vol = SimpleNamespace(offset=0x1000 + member_offset)
    obj = SimpleNamespace(
        _context=SimpleNamespace(
            layers={"kernel": SimpleNamespace(bits_per_register=64)}
        ),
        vol=SimpleNamespace(layer_name="kernel", offset=0x1000),
    )
    assert kernel_symbol._offset_to_ptr(obj, field) == 0x1000 + member_offset + relative


@pytest.mark.parametrize("relative", [False, True])
@pytest.mark.parametrize("kind", ["name", "namespace"])
def test_export_strings_accept_absolute_and_relative_addresses(
    monkeypatch, relative, kind
):
    from volatility3.framework.objects import utility
    from volatility3.framework.symbols.linux.extensions import kernel_symbol

    obj = SimpleNamespace(
        _context=object(),
        vol=SimpleNamespace(layer_name="kernel"),
        has_member=lambda name: name == (kind + "_offset" if relative else kind),
        member=lambda name: 0x3000,
        _offset_to_ptr=lambda field: 0x3000,
    )
    setattr(obj, kind + "_offset", -4)

    def read(**kwargs):
        assert kwargs["address"] == 0x3000
        assert kwargs["layer_name"] == "kernel"
        return "symbol_or_namespace"

    monkeypatch.setattr(utility, "address_to_string", read)
    method = (
        kernel_symbol._do_get_name
        if kind == "name"
        else kernel_symbol._do_get_namespace
    )
    assert method(obj) == "symbol_or_namespace"


@pytest.mark.parametrize("slide", [0, 0x21800000])
@pytest.mark.parametrize("index", [0, 1, 37])
@pytest.mark.parametrize("displacement", [-0x80000000, -0x10000, 0, 0x7FFFFFFF])
def test_entry_relative_signed_offsets_and_kaslr(slide, index, displacement):
    kas = decoder(displacement & 0xFFFFFFFF, base=None)
    kas._relative_to_entry = True
    kas._kallsyms_offsets_address = 0xFFFF8000814E0528 + slide
    expected = kas._kallsyms_offsets_address + index * 4 + displacement
    assert kas._get_symbol_address_by_index(index) == expected


def test_entry_encoding_requires_matching_relocated_stext_at_its_index():
    kas = decoder(0xFFFF0000, base=None)
    kas._kallsyms_offsets_address = 0xFFFF8000A14E0528
    kas._kallsyms_num_syms = 3
    kas._kas_config._stext = kas._kallsyms_offsets_address + 8 - 0x10000
    kas._expand_symbol = lambda offset: (
        SimpleNamespace(name="_stext" if offset == 4 else "other"),
        1,
    )
    assert kas._detect_relative_to_entry() is True
    kas._kas_config._stext -= 0x20000000
    with pytest.raises(exceptions.VolatilityException, match="Cannot determine"):
        kas._detect_relative_to_entry()


@pytest.mark.parametrize(
    "value,expected,symbol",
    [
        (None, 0x1000, "_stext"),
        (0, None, "_stext"),
        (0, 0x1000, "other"),
        (0x10000, 0xFFFF800000010000, "_stext"),
        (0xFFFEFFFF, 0xFFFF800000010000, "_stext"),
    ],
)
def test_missing_base_does_not_make_legacy_or_damaged_data_entry_relative(
    value, expected, symbol
):
    kas = decoder(value, base=None, expected=expected, symbol=symbol)
    with pytest.raises(exceptions.VolatilityException, match="Cannot determine"):
        kas._detect_relative_to_entry()


def test_entry_relative_lookup_uses_decoded_addresses_and_aliases():
    kas = decoder(0, base=None)
    kas._relative_to_entry = True
    table = 0xFFFF800081400000
    kas._kallsyms_offsets_address = table
    # Aliases have different raw offsets; raw offsets are not monotonically sorted.
    addresses = [table - 0x10000, table - 0x10000, table - 0xFF00, table + 0x100]
    kas._kallsyms_num_syms = len(addresses)
    kas._kas_config._sinittext = None
    kas._kas_config._einittext = None
    kas._kas_config._end = table + 0x200
    kas._read_int = lambda address, size, signed=False: (
        addresses[(address - table) // 4] - address
    )
    assert kas._get_symbol_pos(addresses[0] + 1) == (0, 0x100)
    assert kas._get_symbol_pos(addresses[2] + 1) == (2, 0x10000)
    assert kas._get_symbol_pos(addresses[3]) == (3, 0x100)


def test_unreadable_global_base_is_not_reinterpreted_as_entry_relative():
    kas = decoder(None)
    kas._kas_config.num_syms_address = 0x100
    kas._kas_config.num_syms_type_size = 4
    kas._kas_config.relative_base_address = 0x200
    with pytest.raises(
        exceptions.VolatilityException, match="unreadable relative base"
    ):
        kas._bootstrap()


@pytest.mark.parametrize("encoding", ["entry", "unsigned", "percpu", "absolute"])
def test_bootstrap_selects_each_supported_layout(encoding):
    base = 0xFFFF800080000000
    table = base + 0x100000
    target = base + 0x10000
    kas = decoder(0, base=None, expected=target)
    kas._kas_config.num_syms_address = 0x100
    kas._kas_config.num_syms_type_size = 4
    kas._kas_config.relative_base_address = (
        0x200 if encoding in ("unsigned", "percpu") else None
    )
    kas._kas_config.offsets_address = None if encoding == "absolute" else table
    kas._kas_config.addresses_address = table if encoding == "absolute" else None
    kas._kas_config.token_index_address = 0x300
    values = {0x100: 1, 0x200: base}
    values[table] = {
        "entry": (target - table) & 0xFFFFFFFF,
        "unsigned": target - base,
        "percpu": (base - 1 - target) & 0xFFFFFFFF,
        "absolute": target,
    }[encoding]

    def read(address, size, signed=False):
        value = values.get(address, 0)
        return (
            value - (1 << (size * 8)) if signed and value >> (size * 8 - 1) else value
        )

    kas._read_int = read
    kas._bootstrap()
    assert kas._relative_to_entry is (encoding == "entry")
    assert kas._get_symbol_address_by_index(0) == target
