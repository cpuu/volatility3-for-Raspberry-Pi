"""Native ARM64 Malfind rendering and dirty-page preview regressions."""

from types import SimpleNamespace as NS
from functools import partial
from unittest.mock import patch
import pytest
from volatility3.plugins.linux.malware.malfind import Malfind, MaliciousFlags
from volatility3.cli.text_renderer import display_disassembly, CAPSTONE_PRESENT


def fixture(protection="r-x", file_backed=True, show_all=False):
    reads = []
    vma = NS(
        vm_start=0x1000,
        vm_end=0x4000,
        get_protection=lambda: protection,
        vm_file=NS(dereference=lambda: NS(vol=NS(offset=0x9000 if file_backed else 0))),
        get_name=lambda *args: "fixture",
    )
    layer = NS(
        page_size=4096,
        _translate=lambda address: (address, 4096, "physical"),
        is_dirty=lambda address: address in [0x2000, 0x3000],
        read=lambda address, size, pad: (
            reads.append(address) or bytes([address // 4096]) * size
        ),
    )
    task = NS(
        add_process_layer=lambda: "process",
        mm=NS(get_vma_iter=lambda: iter([vma])),
        pid=10,
    )
    obj = NS(
        context=NS(layers={"process": layer}),
        config={"hexdump-size": 8, "show-all-dirty-pages": show_all},
    )
    obj._get_dirty_pages = partial(Malfind._get_dirty_pages, obj)
    obj._is_suspicious = partial(Malfind._is_suspicious, obj)
    return obj, task, layer, vma, reads


@pytest.mark.parametrize(
    "protection,backed,expected",
    [
        ("rwx", True, MaliciousFlags.RWX),
        ("r-x", False, MaliciousFlags.RX),
        ("r-x", True, MaliciousFlags.X_DIRTY),
        ("rw-", False, None),
    ],
)
def test_detection_conditions_remain_architecture_independent(
    protection, backed, expected
):
    obj, _, layer, vma, _ = fixture(protection, backed)
    result = Malfind._is_suspicious(obj, layer, vma)
    assert (result[2] if result else None) == expected


@pytest.mark.parametrize(
    "all_pages,expected", [(False, [0x2000]), (True, [0x2000, 0x3000])]
)
def test_dirty_preview_bytes_match_detected_page_not_vma_start(all_pages, expected):
    obj, task, _, _, reads = fixture(show_all=all_pages)
    rows = list(Malfind._list_injections(obj, task))
    assert reads == expected
    assert [r[3] for r in rows] == expected
    assert [r[2] for r in rows] == [bytes([a // 4096]) * 8 for a in expected]


@pytest.mark.parametrize(
    "kernel_arch,bits,expected",
    [("AArch64", 64, "arm64"), ("Intel64", 64, "intel64"), ("Intel32", 32, "intel")],
)
def test_disassembly_architecture_comes_from_kernel_layer(kernel_arch, bits, expected):
    vma = NS(vm_start=0x1000, vm_end=0x4000, get_protection=lambda: "r-x")
    data = bytes.fromhex("40058052c0035fd6")
    obj = NS(
        config={"kernel": "kernel", "dump-regions": False},
        context=NS(
            modules={"kernel": NS(layer_name="kernel", symbol_table_name="symbols")},
            layers={"kernel": NS(metadata={"architecture": kernel_arch})},
        ),
        _list_injections=lambda task: iter([(vma, "fixture", data, 0x2000, 4096)]),
    )
    task = NS(pid=10, comm=None)
    with patch(
        "volatility3.plugins.linux.malware.malfind.symbols.symbol_table_is_64bit",
        return_value=bits == 64,
    ), patch(
        "volatility3.plugins.linux.malware.malfind.utility.array_to_string",
        return_value="probe",
    ):
        row = next(Malfind._generator(obj, [task]))[1]
    assert row[7].architecture == expected
    assert row[7].offset == 0x2000
    assert row[7].data == data
    if expected == "arm64" and CAPSTONE_PRESENT:
        rendered = display_disassembly(row[7])
        assert "0x2000:\tmov\tw0, #0x2a" in rendered
        assert "0x2004:\tret" in rendered
