"""ARM64 kernel stack geometry and scan-layer regression tests."""

from types import SimpleNamespace as NS
from unittest.mock import patch
import pytest
from volatility3.framework import exceptions
from volatility3.plugins.linux.pscallstack import PsCallStack


def fixture(page_size=4096, pages=4, guard=True, vmap=True):
    base = 0xFFFF800000008000
    size = pages * page_size
    area = NS(
        addr=base,
        size=size + (page_size if guard else 0),
        nr_pages=pages,
        flags=2 if guard else 0x42,
    )
    task = NS(
        stack=base,
        stack_vm_area=area if vmap else 0,
        thread=NS(cpu_context=NS(sp=base + size - 32)),
        pid=123,
        has_member=lambda name: name == "stack_vm_area",
        files=NS(vol=NS(data_format=NS(byteorder="little"))),
    )
    layer = NS(page_size=page_size, canonicalize=int, address_mask=(1 << 64) - 1)
    kernel = NS(
        has_symbol=lambda name: name == "init_stack",
        get_symbol=lambda name: NS(type=NS(size=size)),
        has_type=lambda name: False,
        layer_name="kernel",
        get_type=lambda name: NS(size=8),
    )
    return kernel, layer, task, base, size


@pytest.mark.parametrize(
    "page_size,pages", [(4096, 4), (4096, 8), (16384, 1), (16384, 2), (65536, 1)]
)
@pytest.mark.parametrize("guard", [True, False])
@pytest.mark.parametrize("vmap", [True, False])
def test_stack_size_comes_from_runtime_or_debug_information(
    page_size, pages, guard, vmap
):
    kernel, layer, task, base, size = fixture(page_size, pages, guard, vmap)
    assert PsCallStack._arm64_stack_bounds(kernel, layer, task) == (
        base + size - 32,
        base + size,
    )


@pytest.mark.parametrize(
    "field,change", [("addr", 16), ("size", 4096), ("nr_pages", 1)]
)
def test_inconsistent_vmap_metadata_is_rejected(field, change):
    kernel, layer, task, *_ = fixture()
    setattr(task.stack_vm_area, field, getattr(task.stack_vm_area, field) + change)
    with pytest.raises(exceptions.VolatilityException, match="allocation"):
        PsCallStack._arm64_stack_bounds(kernel, layer, task)


@pytest.mark.parametrize("offset", [-16, 16384, 16385, 1])
def test_saved_sp_must_be_aligned_and_inside_stack(offset):
    kernel, layer, task, base, _ = fixture()
    task.thread.cpu_context.sp = base + offset
    with pytest.raises(exceptions.VolatilityException, match="pointer"):
        PsCallStack._arm64_stack_bounds(kernel, layer, task)


def test_missing_stack_geometry_is_not_guessed_as_four_pages():
    kernel, layer, task, *_ = fixture(vmap=False)
    kernel.has_symbol = lambda name: False
    with pytest.raises(exceptions.VolatilityException, match="size"):
        PsCallStack._arm64_stack_bounds(kernel, layer, task)


def test_non_vmap_thread_union_debug_fallback():
    kernel, layer, task, base, size = fixture(vmap=False)
    kernel.has_symbol = lambda name: False
    kernel.has_type = lambda name: name == "thread_union"
    kernel.get_type = lambda name: NS(size=size)
    assert PsCallStack._arm64_stack_bounds(kernel, layer, task) == (
        base + size - 32,
        base + size,
    )


def test_arm64_scan_reads_kernel_stack_without_a_user_address_space():
    kernel, layer, task, base, size = fixture()
    calls = []

    def forbidden():
        raise AssertionError("Kernel stack scan must not require a user mm or TTBR0")

    task.get_address_space_layer = forbidden

    def read(address, length):
        calls.append((address, length))
        return (0xFFFF800001001000).to_bytes(8, "little")

    layer.read = read
    context = NS(modules={"kernel": kernel}, layers={"kernel": layer})
    with patch("volatility3.plugins.linux.pscallstack.arm.LinuxAArch64", NS):
        rows = list(
            PsCallStack.get_task_callstack(
                context,
                "kernel",
                task,
                NS(lookup_address=lambda addr: None),
                include_unresolved=True,
            )
        )
    assert len(rows) == 4
    assert calls == [(base + size - 32 + i * 8, 8) for i in range(4)]
    assert [r.position for r in rows] == [0, 1, 2, 3]


def test_invalid_arm64_task_is_reported_and_skipped(caplog):
    kernel, layer, task, *_ = fixture()
    task.thread.cpu_context.sp = 0
    context = NS(modules={"kernel": kernel}, layers={"kernel": layer})
    with patch("volatility3.plugins.linux.pscallstack.arm.LinuxAArch64", NS):
        assert list(PsCallStack.get_task_callstack(context, "kernel", task, NS())) == []
    assert "Skipping task 123 stack" in caplog.text


def test_intel_retains_saved_sp_and_task_layer_path():
    kernel, layer, task, base, size = fixture()
    task.thread.sp = base + size - 16
    task.thread.cpu_context.sp = 0  # ARM64 context must not affect Intel.
    reads = []

    def read(address, length):
        reads.append(address)
        return (1234).to_bytes(length, "little")

    task.get_address_space_layer = lambda: NS(read=read)
    context = NS(modules={"kernel": kernel}, layers={"kernel": layer})
    rows = list(
        PsCallStack.get_task_callstack(
            context,
            "kernel",
            task,
            NS(lookup_address=lambda address: None),
            include_unresolved=True,
        )
    )
    assert reads == [base + size - 16, base + size - 8]
    assert [row.value for row in rows] == [1234, 1234]
