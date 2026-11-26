from types import SimpleNamespace

import pytest

from volatility3.framework import symbols
from volatility3.plugins.linux.psscan import PsScan


@pytest.mark.parametrize("is_64bit", [False, True])
@pytest.mark.parametrize("limit", [32768, 4194304])
def test_scan_respects_kernel_pid_limit_and_preserves_high_pids(
    monkeypatch, limit, is_64bit
):
    pids = [-1, 0, 1, 32767, 32768, 65534, 65535, 171671, 4194303, 4194304]
    tasks = {
        index * 0x1000: SimpleNamespace(
            pid=pid, exit_state=0, vol=SimpleNamespace(offset=index * 0x1000)
        )
        for index, pid in enumerate(pids, start=1)
    }

    # pid_max could have been lowered since a task was allocated. Only the
    # kernel's maximum supported limit is suitable for scanning old objects.
    def object_from_symbol(name):
        assert name == "pid_max_max"
        return limit

    kernel = SimpleNamespace(
        symbol_table_name="vmlinux",
        symbols=["fair_sched_class"],
        offset=0,
        get_symbol=lambda name: SimpleNamespace(address=0x100000),
        get_type=lambda name: SimpleNamespace(members={"sched_class": (0x20, None)}),
        object_from_symbol=object_from_symbol,
    )
    context = SimpleNamespace(
        modules={"kernel": kernel},
        layers={
            "kernel": SimpleNamespace(
                dependencies=["memory"], canonicalize=lambda address: address
            ),
            "memory": SimpleNamespace(
                scan=lambda context, scanner: ((addr + 0x20, b"") for addr in tasks)
            ),
        },
        object=lambda type_name, offset, **kwargs: tasks[offset],
    )
    monkeypatch.setattr(symbols, "symbol_table_is_64bit", lambda **kwargs: is_64bit)
    found = [task.pid for task in PsScan.scan_tasks(context, "kernel", "kernel")]
    assert found == [pid for pid in pids if 0 < pid < limit]
