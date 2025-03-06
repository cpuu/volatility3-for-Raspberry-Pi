# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Dict

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import interfaces, renderers, Deprecation
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.linux import extensions

vollog = logging.getLogger(__name__)


class Check_modules(plugins.PluginInterface):
    """Compares module list to sysfs info, if available"""

    _version = (2, 0, 0)
    _required_framework_version = (2, 0, 0)

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
        replacement=linux_utilities_modules.Modules.get_kset_modules,
        replacement_version=(2, 0, 0),
    )
    def get_kset_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_name: str
    ) -> Dict[str, extensions.module]:
        return linux_utilities_modules.Modules.get_kset_modules(context, vmlinux_name)

    def _generator(self):
        kset_modules = linux_utilities_modules.Modules.get_kset_modules(
            self.context, self.config["kernel"]
        )

        lsmod_modules = set(
            str(utility.array_to_string(modules.name))
            for modules in linux_utilities_modules.Modules.list_modules(
                self.context, self.config["kernel"]
            )
        )

        for mod_name in set(kset_modules.keys()).difference(lsmod_modules):
            yield (0, (format_hints.Hex(kset_modules[mod_name]), str(mod_name)))

    def run(self):
        return renderers.TreeGrid(
            [("Module Address", format_hints.Hex), ("Module Name", str)],
            self._generator(),
        )
