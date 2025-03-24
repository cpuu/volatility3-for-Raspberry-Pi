import importlib
import inspect
import pkgutil
import sys
import traceback
import types
from textwrap import dedent
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple, Type

from tree_sitter import Language, Node, Parser
from tree_sitter_python import language as python_language

from volatility3.framework import configuration, interfaces


class UnrequiredVersionableUsage(NamedTuple):
    versionable_item_class: str
    """
    The name of the VersionableInterface class
    """

    consuming_class: str
    """
    The name of the class that is using the imported VersionableInterface class
    """

    methodname: Optional[str]
    """
    The name of the invoked method or attribute, if one is used or referenced
    """

    node: Node
    """
    The tree-sitter node encapsulating the used module component.
    """

    def __str__(self) -> str:
        return (
            f"Found usage of {self.versionable_item_class} "
            f"in class {self.consuming_class} that is not declared "
            f"in {self.consuming_class}'s `get_requirements()` classmethod"
        )


class RequirementValidator:
    language = Language(python_language(), "python")

    def __init__(self, plugin_module: types.ModuleType) -> None:
        if plugin_module.__file__ is None:
            raise ValueError("Attempting to validate a module without a file")

        self._module = plugin_module

        # See which classes in *this* module are configurable (can have requirements declared)
        self._configurable_classes = get_configurable_classes(plugin_module)

        # Get a mapping of class names to configurable classes that they declare in their requirements
        self._versioned_item_mapping = get_versioned_item_mapping(
            self._configurable_classes
        )

        # Get a mapping of module name -> versionable classes within the namespace of each module
        self._imported_mod_classes = get_versionable_import_mapping(
            get_imported_modules(plugin_module)
        )

        with open(plugin_module.__file__, "rb") as f:
            source = f.read()

        self._parser = Parser()
        self._parser.set_language(self.language)
        self._tree = self._parser.parse(source)

    def enumerate_unrequired_usages(
        self,
        clazz: Type[interfaces.configuration.ConfigurableInterface],
        class_node: Node,
    ):

        # This query is designed to look for three different identifier usages:
        # simple identifiers: PsList
        # module attrs: pslist.PsList
        # method calls: pslist.PsList.list_processes
        obj_query = self.language.query(
            dedent(
                """
                [
                  (identifier)
                  (attribute
                    object: (identifier)
                    attribute: (identifier))
                  (attribute
                    object: (attribute
                      object: (identifier)
                      attribute: (identifier))
                  )
                ] @ident
                """
            )
        )

        containing_name = class_node.child_by_field_name("name").text.decode("utf-8")

        valid_types = self._versioned_item_mapping[containing_name]
        for _, match in obj_query.matches(class_node):
            if "ident" not in match:
                continue

            # Get the raw text of the match. This could be something like
            # - PsList
            # - pslist.PsList
            # - pslist.PsList.list_processes
            ident_text = match["ident"].text.decode("utf-8")

            # split the attributes
            components = ident_text.split(".")
            try:
                # See if the first attribute is in the module namespace.
                item = vars(self._module)[components[0]]
            except KeyError:
                # If it's not, it's likely a variable in a smaller scope and we
                # can ignore it.
                continue

            # If it's in the module namespace and is a module...
            if isinstance(item, types.ModuleType):
                try:
                    # We try getting attributes from it until we
                    # find one that is a versionable class

                    # Ideally, we shouldn't have to look further than
                    # two levels
                    item = getattr(item, components[1])
                    if not is_versionable(item):
                        item = getattr(item, components[2])
                        if not is_versionable(item):
                            continue

                except (IndexError, AttributeError):
                    # we ran out of attributes to check
                    continue

            elif is_versionable(item):
                # The versionable thing was at the top level. This
                # goes against our preferred style, but is possible.
                pass
            else:
                # This isn't something we care about.
                continue

            if (
                item in valid_types
                or item is clazz
                or inspect.isabstract(item)
                or item
                is interfaces.configuration.VersionableInterface  # Avoid checking the interface itself
            ):
                continue

            yield UnrequiredVersionableUsage(
                item,
                containing_name,
                components[1] if len(components) > 1 else None,
                match["ident"],
            )

    def find_class_nodes(
        self,
    ) -> Iterator[Tuple[Type[interfaces.configuration.ConfigurableInterface], Node]]:
        """
        Yields an iterator of (classname, node) tuples, where the node is the subtree containing
        the entire class definition.
        """
        class_query = self.language.query("(class_definition) @classdef")

        matches = class_query.captures(self._tree.root_node)
        for node, _ in matches:
            classname = node.child_by_field_name("name").text.decode("utf-8")
            if classname not in self._configurable_classes:
                continue

            yield self._configurable_classes[classname], node


def is_versionable(var):
    try:
        return issubclass(var, interfaces.configuration.VersionableInterface)
    except TypeError:
        return False


def is_configurable(var):
    try:
        return issubclass(var, interfaces.configuration.ConfigurableInterface)
    except TypeError:
        return False


def get_imported_modules(
    plugin_module: types.ModuleType,
) -> List[Tuple[str, types.ModuleType]]:
    return [
        (name, var)
        for name, var in vars(plugin_module).items()
        if isinstance(var, types.ModuleType)
    ]


def get_configurable_classes(
    plugin_module: types.ModuleType,
) -> Dict[str, Type[interfaces.configuration.ConfigurableInterface]]:
    return {
        name: clazz
        for name, clazz in vars(plugin_module).items()
        if is_configurable(clazz)
    }


def get_versioned_item_mapping(
    configurable_classes: Dict[
        str, Type[interfaces.configuration.ConfigurableInterface]
    ]
) -> Dict[str, List[Type[interfaces.configuration.VersionableInterface]]]:
    return {
        name: [
            req._component
            for req in clazz.get_requirements()
            if isinstance(req, configuration.requirements.VersionRequirement)
        ]
        for name, clazz in configurable_classes.items()
    }


def get_versionable_import_mapping(
    imported_modules: List[Tuple[str, types.ModuleType]]
) -> Dict[str, List[str]]:
    return {
        modname: [name for name, var in vars(module).items() if is_versionable(var)]
        for modname, module in imported_modules
    }


def report_missing_requirements() -> Iterator[Tuple[str, UnrequiredVersionableUsage]]:
    vol3 = importlib.import_module("volatility3")

    for _, module_name, _ in pkgutil.walk_packages(
        vol3.__path__, vol3.__name__ + ".", onerror=lambda _: None
    ):
        try:
            # import the module that we want to check
            modname = module_name.replace(
                "volatility3.framework.plugins", "volatility3.plugins"
            )
            plugin_module = importlib.import_module(modname)

        except ImportError:
            continue
        except Exception:
            continue

        if plugin_module.__file__ is None:
            continue

        try:
            # construct a validator for the module
            try:
                validator = RequirementValidator(plugin_module)
            except Exception:
                traceback.print_stack()
                continue
            for clazz, node in validator.find_class_nodes():
                for item in validator.enumerate_unrequired_usages(clazz, node):
                    yield module_name, item
        except Exception as exc:
            traceback.print_exc()
            print(
                f"Failed to create validator for source code from {plugin_module.__file__}: {exc}"
            )
            sys.exit(1)


def perform_review():
    found = 0
    for mod, usage in report_missing_requirements():
        found += 1
        print(
            f"Violation in module {mod} (line {usage.node.start_point[0]}): {str(usage)}"
        )

    if found:
        print(
            f"Found {found} uses of versionable components not declared in get_requirements()"
        )
        sys.exit(1)

    print("All configurable classes passed validation!")


if __name__ == "__main__":
    perform_review()
