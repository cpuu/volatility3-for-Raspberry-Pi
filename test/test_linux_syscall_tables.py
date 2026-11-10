"""Syscall sizing from typed arrays and ARM64 dispatch arguments."""

import struct
from types import SimpleNamespace

import pytest

from volatility3.framework import exceptions
from volatility3.plugins.linux.malware.check_syscall import Check_syscall


def mov(count):
    return 0x52800002 | (count << 5)  # mov w2, immediate


def branch(source, target):
    return 0x94000000 | (((target - source) // 4) & 0x3FFFFFF)


def arm_context(code, symbols):
    symbols = {**symbols, "end": max(code) + 0x100}
    memory = {
        a: struct.pack("<" + "I" * len(words), *words) for a, words in code.items()
    }

    def read(addr, size):
        return memory[addr][:size]

    layer = SimpleNamespace(metadata={"architecture": "AArch64"}, read=read)
    module = SimpleNamespace(
        layer_name="kernel",
        offset=0,
        symbols=list(symbols),
        has_symbol=lambda name: name in symbols,
        get_symbol=lambda name: SimpleNamespace(address=symbols[name]),
    )
    plugin = SimpleNamespace(context=SimpleNamespace(layers={"kernel": layer}))
    return plugin, module


@pytest.mark.parametrize("native,compat", [(462, 462), (451, 450)])
def test_native_and_compat_dispatch_counts_are_separate(native, compat):
    plugin, module = arm_context(
        {
            0x1000: [mov(native), branch(0x1004, 0x3000)],
            0x2000: [mov(compat), branch(0x2004, 0x3000)],
            0x3000: [0xD65F03C0],
        },
        {"do_el0_svc": 0x1000, "do_el0_svc_compat": 0x2000, "el0_svc_common": 0x3000},
    )
    assert (
        Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == native
    )
    assert (
        Check_syscall._get_arm64_table_size(plugin, module, "compat_sys_call_table")
        == compat
    )


def test_count_from_constant_propagated_common_function():
    plugin, module = arm_context(
        {
            0x1000: [branch(0x1000, 0x2000)],
            0x2000: [mov(462), branch(0x2004, 0x3000)],
            0x3000: [0xD65F03C0],
        },
        {
            "do_el0_svc": 0x1000,
            "el0_svc_common.constprop.0": 0x2000,
            "invoke_syscall": 0x3000,
        },
    )
    assert Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == 462
    assert (
        Check_syscall._get_arm64_table_size(plugin, module, "compat_sys_call_table")
        == 0
    )


@pytest.mark.parametrize(
    "words",
    [
        [mov(462), 0x2A0103E2, branch(0x1008, 0x3000)],  # mov w2,w1 clobbers count
        [mov(462), branch(0x1004, 0x4000), branch(0x1008, 0x3000)],
        [mov(462), branch(0x1004, 0x3000), mov(463), branch(0x100C, 0x3000)],
        [0xD65F03C0],
    ],
)
def test_unknown_clobbered_or_conflicting_counts_are_not_guessed(words):
    plugin, module = arm_context(
        {0x1000: words, 0x3000: [0xD65F03C0], 0x4000: [0xD65F03C0]},
        {"do_el0_svc": 0x1000, "invoke_syscall": 0x3000, "other": 0x4000},
    )
    assert Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == 0


@pytest.mark.parametrize("architecture", ["Intel32", "Intel64", "AArch64"])
def test_complete_type_takes_priority_over_heuristics(architecture):
    module = SimpleNamespace(
        get_symbol=lambda name: SimpleNamespace(
            address=0x1000, type=SimpleNamespace(vol={"count": 462}, size=3696)
        )
    )
    plugin = SimpleNamespace()
    assert Check_syscall._get_table_info(plugin, module, "sys_call_table", 8) == (
        0x1000,
        462,
    )


def test_unknown_arm_layout_fails_instead_of_using_metadata_minimum():
    module = SimpleNamespace(
        layer_name="kernel",
        get_symbol=lambda name: SimpleNamespace(
            address=0x1000, type=SimpleNamespace(vol={"count": 0})
        ),
    )
    plugin = SimpleNamespace(
        context=SimpleNamespace(
            layers={"kernel": SimpleNamespace(metadata={"architecture": "AArch64"})}
        ),
        _get_arm64_table_size=lambda *args: 0,
        _get_table_size_next_symbol=lambda *args: 467,
    )
    with pytest.raises(exceptions.VolatilityException, match="Unable to establish"):
        Check_syscall._get_table_info(plugin, module, "sys_call_table", 8)


def test_intel_disassembly_and_fallback_remain_available():
    module = SimpleNamespace(
        layer_name="kernel",
        get_symbol=lambda name: SimpleNamespace(
            address=0x1000, type=SimpleNamespace(vol={"count": 0})
        ),
    )
    plugin = SimpleNamespace(
        context=SimpleNamespace(
            layers={"kernel": SimpleNamespace(metadata={"architecture": "Intel64"})}
        ),
        _get_table_info_disassembly=lambda *args: 400,
        _get_table_info_other=lambda *args: 399,
    )
    assert Check_syscall._get_table_info(plugin, module, "sys_call_table", 8) == (
        0x1000,
        400,
    )
    plugin._get_table_info_disassembly = lambda *args: 0
    assert Check_syscall._get_table_info(plugin, module, "sys_call_table", 8) == (
        0x1000,
        399,
    )


def test_high_kernel_call_targets_are_unsigned_addresses():
    base = 0xFFFF800000000000
    plugin, module = arm_context(
        {
            base + 0x1000: [mov(462), branch(base + 0x1004, base + 0x3000)],
            base + 0x3000: [0xD65F03C0],
        },
        {"do_el0_svc": base + 0x1000, "el0_svc_common": base + 0x3000},
    )
    assert Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == 462


@pytest.mark.parametrize(
    "count,bound,valid", [(462, 467, True), (468, 467, False), (462, 0, False)]
)
def test_dispatch_count_must_fit_address_upper_bound(count, bound, valid):
    module = SimpleNamespace(
        layer_name="kernel",
        get_symbol=lambda name: SimpleNamespace(
            address=0x1000, type=SimpleNamespace(vol={"count": 0})
        ),
    )
    plugin = SimpleNamespace(
        context=SimpleNamespace(
            layers={"kernel": SimpleNamespace(metadata={"architecture": "AArch64"})}
        ),
        _get_arm64_table_size=lambda *args: count,
        _get_table_size_next_symbol=lambda *args: bound,
    )
    if valid:
        assert Check_syscall._get_table_info(plugin, module, "sys_call_table", 8) == (
            0x1000,
            count,
        )
    else:
        with pytest.raises(exceptions.VolatilityException):
            Check_syscall._get_table_info(plugin, module, "sys_call_table", 8)


def specialized_context(count=470, guard_changes=None, common_prefix=(), table=0x8040):
    # GCC's specialized array_index_nospec path, with two consistent bounds.
    words = [
        0x7100003F | ((count - 1) << 10),  # cmp w1, last index
        0x54000168,  # b.hi 0x3030 (past the indirect dispatch)
        0x2A0103E0,  # mov w0, w1
        0xF100001F | (count << 10),  # cmp x0, entry count
        0xDA1F03E0,  # ngc x0, xzr
        0xD503229F,  # csdb
        0x0A000021,  # and w1, w1, w0
        0xAA1303E0,  # mov x0, x19
        0xF8617841,  # ldr x1, [x2, x1, lsl #3]
        0xD63F0020,  # blr x1
        0xD503201F,
        0xD503201F,
        0xD65F03C0,
    ]
    for index, value in (guard_changes or {}).items():
        words[index] = value
    common = list(common_prefix)
    common.append(branch(0x2000 + len(common) * 4, 0x3000))
    return arm_context(
        {
            0x1000: [0xF0000022, 0x91010042, branch(0x1008, 0x2000)],
            0x2000: common,
            0x3000: words,
            0x4000: [0xB0000022, 0x91020042, branch(0x4008, 0x2000)],
        },
        {
            "do_el0_svc": 0x1000,
            "el0_svc_common.constprop.0": 0x2000,
            "invoke_syscall.constprop.0": 0x3000,
            "do_el0_svc_compat": 0x4000,
            "sys_call_table": table,
            "compat_sys_call_table": 0x9080,
        },
    )


@pytest.mark.parametrize("count", [470, 472, 473])
def test_specialized_dispatch_guard_sizes_both_tables(count):
    plugin, module = specialized_context(count)
    for name in ("sys_call_table", "compat_sys_call_table"):
        assert Check_syscall._get_arm64_table_size(plugin, module, name) == count


@pytest.mark.parametrize(
    "changes",
    [
        {1: 0x54000162},  # b.hs is not the unsigned > last-index guard
        {1: 0x54000088},  # rejection branch enters the dispatch sequence
        {3: 0xF100001F | (471 << 10)},  # speculation bound disagrees
        {0: 0x7140003F | (469 << 10)},  # shifted immediate is not count 470
        {3: 0xF140001F | (470 << 10)},  # shifted speculation bound
        {2: 0x2A0303E0},  # wrong syscall index copied
        {6: 0xD503201F},  # index not speculation-masked
        {8: 0xF8617861},  # wrong table register x3
        {8: 0xF8616841},  # wrong pointer scale
        {9: 0xD63F0000},  # calls a different register
        {9: 0},  # truncated/undecodable indirect call
    ],
)
def test_specialized_dispatch_rejects_inconsistent_or_unrelated_patterns(changes):
    plugin, module = specialized_context(guard_changes=changes)
    assert Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == 0


def test_specialized_dispatch_requires_requested_table_in_entry():
    plugin, module = specialized_context(table=0x8050)
    assert Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == 0


@pytest.mark.parametrize("prefix", [(0xAA0303E2,), (branch(0x2000, 0x4000),)])
def test_specialized_dispatch_rejects_clobbered_common_table_argument(prefix):
    plugin, module = specialized_context(common_prefix=prefix)
    assert Check_syscall._get_arm64_table_size(plugin, module, "sys_call_table") == 0
