# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import logging
import pefile

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, pe_symbols 

vollog = logging.getLogger(__name__)

class EtwPatch(interfaces.plugins.PluginInterface):
    """Detects ETW patching by examining the first opcode of EtwEventWrite in ntdll.dll."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 26, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name='kernel',
                description='Windows kernel',
                architectures=["Intel32", "Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pe_symbols", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name='pid',
                description='Filter on specific process IDs',
                element_type=int,
                optional=True
            )
        ]

    def _get_dll_vads(self, proc, dll_name):
        """Retrieve VADs for a specific DLL in the process."""
        collected_modules = pe_symbols.PESymbols.get_proc_vads_with_file_paths(proc)
        return [
            (vad_start, vad_size, proc.add_process_layer())
            for vad_start, vad_size, filepath in collected_modules
            if pe_symbols.PESymbols.filename_for_path(filepath) == dll_name
        ]

    def _find_symbols(self, dll_name, symbols, proc_layer_name, dll_vads):
        """Find symbols for a specific DLL."""
        filter_module = {dll_name: {"names": symbols}}
        process_modules = {dll_name: [(proc_layer_name, vad_start, vad_size) for vad_start, vad_size, _ in dll_vads]}
        return pe_symbols.PESymbols.find_symbols(self.context, self.config_path, filter_module, process_modules)

    def _get_first_opcode(self, proc_layer_name, function_start):
        """Check the first opcode of a function."""
        try:
            return self.context.layers[proc_layer_name].read(function_start, 1).hex()
        except exceptions.InvalidAddressException:
            return None

    def _generator(self):
        pid_filter = self.config.get('pid', None)

        for proc in pslist.PsList.list_processes(
                context=self.context,
                kernel_module_name=self.config['kernel']):
            # Skip processes not in the PID filter
            if pid_filter and proc.UniqueProcessId not in pid_filter:
                continue

            pid = int(proc.UniqueProcessId)
            proc_name = proc.ImageFileName.cast(
                "string",
                max_length=proc.ImageFileName.vol.count,
                errors='replace'
            )

            try:
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                continue

            dlls_to_check = {
                "ntdll.dll": [
                    "EtwEventWrite",
                    "EtwEventWriteFull",
                    "NtTraceEvent"
                ],
                "advapi32.dll": [
                    "EventWrite"
                ]
            }

            for dll_name, symbols in dlls_to_check.items():
                dll_vads = self._get_dll_vads(proc, dll_name)
                if not dll_vads:
                    continue

                found_symbols, _ = self._find_symbols(dll_name, symbols, proc_layer_name, dll_vads)
                if dll_name not in found_symbols:
                    continue

                for symbol_name, function_start in found_symbols[dll_name]:
                    opcode = self._get_first_opcode(proc_layer_name, function_start)
                    if opcode in ('c3', 'e9'):  # RET or JMP
                        yield (0, (
                            pid,
                            proc_name,
                            dll_name,
                            symbol_name,
                            format_hints.Hex(function_start),
                            opcode
                        ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("DLL", str),
                ("Function", str),
                ("Offset", format_hints.Hex),
                ("Opcode", str)
            ],
            self._generator()
        )
