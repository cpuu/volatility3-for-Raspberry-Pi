"""Regression coverage for aggregate child replacement and cyclic ISF resolution."""
import json

import pytest

from volatility3.framework import contexts, objects
from volatility3.framework.objects import templates
from volatility3.framework.symbols import intermed


@pytest.mark.parametrize("aggregate", [objects.StructType, objects.UnionType, objects.ClassType])
@pytest.mark.parametrize("field_name", ["members", "ordinary_field"])
def test_replace_child_updates_all_matching_fields_preserving_offsets(aggregate, field_name):
    old = templates.ReferenceTemplate("test!list_head")
    unrelated = templates.ReferenceTemplate("test!unrelated")
    new = templates.ObjectTemplate(objects.StructType, "test!list_head", size=16, members={})
    parent = templates.ObjectTemplate(
        aggregate, "test!container", size=160,
        members={field_name: (120, old), "another": (136, old), "unchanged": (144, unrelated)},
    )

    parent.replace_child(old, new)

    assert parent.vol.members == {
        field_name: (120, new), "another": (136, new), "unchanged": (144, unrelated)
    }
    assert parent.relative_child_offset(field_name) == 120
    assert parent.child_template(field_name) is new


@pytest.mark.parametrize("lookup", ["type", "symbol"])
def test_symbol_space_resolves_member_named_members_and_recursive_list(tmp_path, lookup):
    pointer = lambda name: {"kind": "pointer", "subtype": {"kind": "struct", "name": name}}
    data = {
        "metadata": {"format": "6.2.0"},
        "base_types": {"pointer": {"size": 8, "signed": False, "kind": "int", "endian": "little"}},
        "enums": {},
        "symbols": {"dstgroup": {"address": 0, "type": pointer("qgroup")}},
        "user_types": {
            "qgroup": {"kind": "struct", "size": 136, "fields": {
                "members": {"offset": 120, "type": {"kind": "struct", "name": "list_head"}}
            }},
            "list_head": {"kind": "struct", "size": 16, "fields": {
                "next": {"offset": 0, "type": pointer("list_head")},
                "prev": {"offset": 8, "type": pointer("list_head")}
            }}
        }
    }
    path = tmp_path / "minimal.json"
    path.write_text(json.dumps(data))
    context = contexts.Context()
    table = intermed.IntermediateSymbolTable(context, "symbols.test", "test", path.as_uri(), validate=False)
    context.symbol_space.append(table)
    if lookup == "symbol":
        symbol = context.symbol_space.get_symbol("test!dstgroup")
        root = symbol.type.vol.subtype
    else:
        root = context.symbol_space.get_type("test!qgroup")
    member = root.child_template("members")
    assert isinstance(member, templates.ObjectTemplate)
    assert member.vol.type_name == "test!list_head"
    assert root.relative_child_offset("members") == 120
    assert member.child_template("next").vol.subtype is member
    assert member.child_template("prev").vol.subtype is member
