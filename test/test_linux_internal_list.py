"""Linked-list traversal must dereference pointer values, not pointer slots."""

from types import SimpleNamespace as NS
from unittest.mock import MagicMock
import pytest
from volatility3.framework import objects, exceptions
from volatility3.framework.symbols.linux import LinuxUtilities


def pointer(slot, target, readable=True):
    p = MagicMock(spec=objects.Pointer)
    p.vol = NS(offset=slot)
    p.__int__.return_value = target
    p.__bool__.return_value = bool(target)
    p.is_readable.return_value = readable
    return p


def fixture(cycle=False):
    nodes = {
        0x1000: NS(
            vol=NS(offset=0x1000),
            next=pointer(0x1008, 0x2000),
            is_readable=lambda: True,
        ),
        0x2000: NS(
            vol=NS(offset=0x2000),
            next=pointer(0x2008, 0x1000 if cycle else 0),
            is_readable=lambda: True,
        ),
    }

    def obj(object_type, offset, absolute):
        assert object_type == "notifier_block" and absolute
        return nodes[offset]

    return NS(object=obj), nodes, pointer(0x800, 0x1000)


def test_pointer_values_are_used_for_every_node():
    k, nodes, head = fixture()
    assert list(
        LinuxUtilities.walk_internal_list(k, "notifier_block", "next", head)
    ) == list(nodes.values())


def test_starting_struct_remains_supported():
    k, nodes, head = fixture()
    assert list(
        LinuxUtilities.walk_internal_list(k, "notifier_block", "next", nodes[0x1000])
    ) == list(nodes.values())


def test_cycle_detected_by_target_despite_distinct_pointer_slots():
    k, nodes, head = fixture(cycle=True)
    assert list(
        LinuxUtilities.walk_internal_list(k, "notifier_block", "next", head)
    ) == list(nodes.values())


@pytest.mark.parametrize("limit,expected", [(0, 0), (-1, 0), (1, 1), (2, 2)])
def test_max_count_is_exact(limit, expected):
    k, nodes, head = fixture()
    assert (
        len(
            list(
                LinuxUtilities.walk_internal_list(
                    k, "notifier_block", "next", head, max_count=limit
                )
            )
        )
        == expected
    )


def test_null_head_yields_nothing():
    k, nodes, head = fixture()
    assert (
        list(
            LinuxUtilities.walk_internal_list(
                k, "notifier_block", "next", pointer(0x800, 0)
            )
        )
        == []
    )


def test_unreadable_target_yields_nothing():
    k, nodes, head = fixture()
    assert (
        list(
            LinuxUtilities.walk_internal_list(
                k, "notifier_block", "next", pointer(0x800, 0x1000, False)
            )
        )
        == []
    )


def test_unreadable_next_ends_after_valid_node():
    k, nodes, head = fixture()

    class Smeared:
        @property
        def next(self):
            raise exceptions.InvalidAddressException("kernel", 0x1008)

    k.object = lambda **kw: Smeared()
    assert (
        len(list(LinuxUtilities.walk_internal_list(k, "notifier_block", "next", head)))
        == 1
    )
