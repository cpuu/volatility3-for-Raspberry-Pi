"""Native helper tables must not break ISF producer validation."""

from types import SimpleNamespace as NS
from unittest.mock import Mock
from volatility3.framework.symbols import SymbolSpace
from volatility3.framework.symbols.native import NativeTable


def space(version):
    s = SymbolSpace()
    s.append(NativeTable("native", {}))
    s._dict["isf"] = NS(producer=NS(name="dwarf2json", version=version, datetime=None))
    return s


def test_native_table_is_ignored_and_real_isf_is_checked():
    validator = Mock(return_value=True)
    assert space((0, 9, 0)).verify_table_versions("dwarf2json", validator)
    validator.assert_called_once_with((0, 9, 0), None)


def test_native_table_does_not_hide_rejected_isf():
    assert not space((0, 7, 0)).verify_table_versions(
        "dwarf2json", lambda v, d: v >= (0, 8, 0)
    )


def test_missing_isf_producer_retains_skip_behavior():
    s = space((0, 9, 0))
    s._dict["isf"].producer = None
    validator = Mock(side_effect=AssertionError("no matching metadata"))
    assert s.verify_table_versions("dwarf2json", validator)


def test_different_producer_is_not_validated():
    s = space((0, 9, 0))
    s._dict["isf"].producer.name = "other"
    assert s.verify_table_versions("dwarf2json", lambda v, d: False)


def test_explicit_table_selection_still_applies():
    s = space((0, 7, 0))
    assert s.verify_table_versions("dwarf2json", lambda v, d: False, tables=["native"])
    assert not s.verify_table_versions("dwarf2json", lambda v, d: False, tables=["isf"])
