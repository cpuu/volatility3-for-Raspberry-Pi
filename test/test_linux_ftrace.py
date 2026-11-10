"""Ftrace must traverse all buckets and resolve in-function instrumentation sites."""

from types import SimpleNamespace as NS
from unittest.mock import Mock
import pytest
from volatility3.framework import exceptions
from volatility3.plugins.linux.tracing.ftrace import CheckFtrace


class Node:
    def __init__(self, address, next_node=0):
        self.address = address
        self.next = next_node

    def __int__(self):
        return self.address

    def is_readable(self):
        return True

    def dereference(self):
        return self

    def cast(self, name):
        return self


class Buckets:
    def __init__(self, nodes):
        self.nodes = nodes
        self.vol = NS(subtype=object())

    def dereference(self):
        return self

    def cast(self, name, count, subtype):
        assert name == "array" and count == len(self.nodes)
        assert subtype is self.vol.subtype
        return self.nodes


def ops(nodes, bits=1, legacy=False):
    h = NS(size_bits=bits, buckets=Buckets(nodes))
    return (
        NS(filter_hash=h, vol=NS(offset=0x1000))
        if legacy
        else NS(func_hash=NS(filter_hash=h), vol=NS(offset=0x1000))
    )


@pytest.mark.parametrize("legacy", [False, True])
def test_all_buckets_and_collision_chains(legacy):
    a, b, c = Node(1), Node(2), Node(3)
    b.next = c
    result = list(
        CheckFtrace.extract_hash_table_filters(
            ops([NS(first=a), NS(first=b)], legacy=legacy)
        )
    )
    assert [int(n) for n in result] == [1, 2, 3]


def test_empty_first_bucket_does_not_hide_later_bucket():
    assert [
        int(n)
        for n in CheckFtrace.extract_hash_table_filters(
            ops([NS(first=0), NS(first=Node(5))])
        )
    ] == [5]


def test_cycle_does_not_hang_or_hide_later_bucket():
    a = Node(1)
    a.next = a
    assert [
        int(n)
        for n in CheckFtrace.extract_hash_table_filters(
            ops([NS(first=a), NS(first=Node(2))])
        )
    ] == [1, 2]


def test_invalid_bucket_does_not_hide_later_bucket():
    class Bad:
        @property
        def first(self):
            raise exceptions.InvalidAddressException("kernel", 0)

    assert [
        int(n)
        for n in CheckFtrace.extract_hash_table_filters(ops([Bad(), NS(first=Node(2))]))
    ] == [2]


@pytest.mark.parametrize("bits", [-1, 13, 63])
def test_invalid_geometry_is_rejected(bits):
    assert list(CheckFtrace.extract_hash_table_filters(ops([], bits=bits))) == []


def test_single_bucket_layout():
    assert (
        len(
            list(
                CheckFtrace.extract_hash_table_filters(ops([NS(first=Node(1))], bits=0))
            )
        )
        == 1
    )


def test_exact_aliases_preserved_without_fallback():
    k = NS(
        get_symbols_by_absolute_location=lambda ip: iter(["kernel!foo", "kernel!bar"])
    )
    kas = NS(lookup_address=Mock(side_effect=AssertionError("fallback not needed")))
    assert CheckFtrace._resolve_hook_symbols(k, kas, 0x1000) == "foo,bar"


@pytest.mark.parametrize("offset", [0, 4, 8, 31])
def test_resolves_bounded_function_instruction(offset):
    k = NS(get_symbols_by_absolute_location=lambda ip: [])
    kas = NS(
        lookup_address=lambda ip: NS(name="function", type="t", address=0x1000, size=32)
    )
    assert CheckFtrace._resolve_hook_symbols(k, kas, 0x1000 + offset) == "function"


@pytest.mark.parametrize(
    "kind,address,size,ip",
    [
        ("d", 0x1000, 32, 0x1004),
        ("t", 0x1000, 32, 0x1020),
        ("t", 0x1000, 32, 0x0FFF),
        ("t", 0x1000, 0, 0x1000),
    ],
)
def test_rejects_data_and_out_of_range_fallback(kind, address, size, ip):
    k = NS(get_symbols_by_absolute_location=lambda ip: [])
    kas = NS(
        lookup_address=lambda ip: NS(name="bad", type=kind, address=address, size=size)
    )
    assert CheckFtrace._resolve_hook_symbols(k, kas, ip) == ""


def test_missing_fallback_symbol_remains_unknown():
    k = NS(get_symbols_by_absolute_location=lambda ip: [])
    assert (
        CheckFtrace._resolve_hook_symbols(k, NS(lookup_address=lambda ip: None), 0x1000)
        == ""
    )
