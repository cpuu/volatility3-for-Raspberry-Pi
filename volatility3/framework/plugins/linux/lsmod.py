# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a plugin that lists loaded kernel modules."""

import logging
from typing import List, Iterable

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import exceptions, renderers, interfaces, Deprecation
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="linux_utilities_modules",
                component=linux_utilities_modules.Modules,
                version=(2, 0, 0),
            ),
        ]

    @classmethod
    @Deprecation.deprecated_method(
        replacement=linux_utilities_modules.Modules.list_modules,
        replacement_version=(2, 0, 0),
    )
    def list_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        return linux_utilities_modules.Modules.list_modules(
            context, vmlinux_module_name
        )

    def _generator(self):
        try:
            for module in linux_utilities_modules.Modules.list_modules(
                self.context, self.config["kernel"]
            ):
                mod_size = module.get_init_size() + module.get_core_size()

                mod_name = utility.array_to_string(module.name)

                yield 0, (format_hints.Hex(module.vol.offset), mod_name, mod_size)

        except exceptions.SymbolError:
            vollog.warning(
                "The required symbol 'module' is not present in symbol table. Please check that kernel modules are enabled for the system under analysis."
            )

    def run(self):
        return renderers.TreeGrid(
            [("Offset", format_hints.Hex), ("Name", str), ("Size", int)],
            self._generator(),
        )
