import logging
import warnings
from typing import Iterable, Iterator, List, Optional, Tuple, NamedTuple, Dict, Set

from volatility3 import framework
from volatility3.framework import (
    constants,
    interfaces,
    deprecation,
    exceptions,
    objects,
)
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import extensions

vollog = logging.getLogger(__name__)


class Modules(interfaces.configuration.VersionableInterface):
    """Kernel modules related utilities."""

    _version = (2, 0, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    class ModuleInfo(NamedTuple):
        """
        Used to track the name and boundary of a kernel module
        """

        offset: int
        name: str
        start: int
        end: int

    @staticmethod
    def module_lookup_by_address(
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        modules: Iterable[ModuleInfo],
        target_address: int,
        run_hidden_modules: bool = True,
    ) -> Optional[Tuple[ModuleInfo, Optional[str]]]:
        """
        Determine if a target address lies in a module memory space.
        Returns the module where the provided address lies.

        `modules` must be non-empty and contain masked addresses via `get_module_info_for_module` or
        a ValueError will be thrown

        Args:
            context: The context on which to operate
            layer_name: The name of the layer on which to operate
            modules: An iterable containing the modules to match the address against
            target_address: The address to check for a match

        Returns:
            The first memory module in which the address fits and the symbol name for `target_address`

        Kernel documentation:
            "within_module" and "within_module_mem_type" functions
        """
        kernel = context.modules[kernel_module_name]

        kernel_layer = context.layers[kernel.layer_name]

        if not modules:
            raise ValueError("Empty list sent to `module_lookup_by_address`")

        matches = []
        for module in modules:
            if module.start != module.start & kernel_layer.address_mask:
                raise ValueError(
                    "Modules list must be gathered from `run_modules_scanners` to be used in this function"
                )

            if module.start <= target_address < module.end:
                matches.append(module)

        if len(matches) >= 1:
            if len(matches) > 1:
                warnings.warn(
                    f"Address {hex(target_address)} fits in modules at {[hex(module.start) for module in matches]}, indicating potential modules memory space overlap. The first matching entry {matches[0].name} will be used",
                    UserWarning,
                )

            symbol_name = None

            match = matches[0]

            if match.name == constants.linux.KERNEL_NAME:
                symbols = list(kernel.get_symbols_by_absolute_location(target_address))

                if len(symbols):
                    symbol_name = symbols[0]
            else:
                module = kernel.object("module", offset=module.offset, absolute=True)
                symbol_name = module.get_symbol_by_address(target_address)

            if symbol_name and symbol_name.find(constants.BANG) != -1:
                symbol_name = symbol_name.split(constants.BANG)[1]

            return match, symbol_name

        return None, None

    @classmethod
    @deprecation.method_being_removed(
        removal_date="2025-09-25",
        message="Code using this function should adapt `linux_utilities_modules.Modules.run_module_scanners`",
    )
    def mask_mods_list(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_layer_name: str,
        mods: Iterator[extensions.module],
    ) -> List[Tuple[str, int, int]]:
        """
        A helper function to mask the starting and end address of kernel modules
        """
        mask = context.layers[kernel_layer_name].address_mask

        return [
            (
                utility.array_to_string(mod.name),
                mod.get_module_base() & mask,
                (mod.get_module_base() & mask) + mod.get_core_size(),
            )
            for mod in mods
        ]

    @classmethod
    @deprecation.method_being_removed(
        removal_date="2025-09-25",
        message="Use `module_lookup_by_address` to map address to their hosting kernel module and symbol.",
    )
    def lookup_module_address(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        handlers: List[Tuple[str, int, int]],
        target_address: int,
    ) -> Tuple[str, str]:
        """
        Searches between the start and end address of the kernel module using target_address.
        Returns the module and symbol name of the address provided.
        """
        kernel_module = context.modules[kernel_module_name]
        mod_name = "UNKNOWN"
        symbol_name = "N/A"

        for name, start, end in handlers:
            if start <= target_address <= end:
                mod_name = name
                if name == constants.linux.KERNEL_NAME:
                    symbols = list(
                        kernel_module.get_symbols_by_absolute_location(target_address)
                    )

                    if len(symbols):
                        symbol_name = (
                            symbols[0].split(constants.BANG)[1]
                            if constants.BANG in symbols[0]
                            else symbols[0]
                        )

                break

        return mod_name, symbol_name

    @classmethod
    def get_module_info_for_module(
        cls, address_mask: int, module: extensions.module
    ) -> Optional[ModuleInfo]:
        """
        Returns a ModuleInfo instance for `module`

        This performs address masking to avoid endless calls to `mask_mods_list`

        Returns None if the name is smeared
        """
        try:
            mod_name = utility.array_to_string(module.name)
        except exceptions.InvalidAddressException:
            return None

        start = module.get_module_base() & address_mask

        end = start + module.get_core_size()

        return Modules.ModuleInfo(module.vol.offset, mod_name, start, end)

    @staticmethod
    def get_kernel_module_info(
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> ModuleInfo:
        """
        Returns a ModuleInfo instance that encodes the kernel
        This is required to map function pointers to the kerenl executable
        """
        kernel = context.modules[kernel_module_name]

        address_mask = context.layers[kernel.layer_name].address_mask

        start_addr = kernel.object_from_symbol("_text")
        start_addr = start_addr.vol.offset & address_mask

        end_addr = kernel.object_from_symbol("_etext")
        end_addr = end_addr.vol.offset & address_mask

        return Modules.ModuleInfo(
            start_addr, constants.linux.KERNEL_NAME, start_addr, end_addr
        )

    @classmethod
    def run_modules_scanners(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        run_hidden_modules: bool = True,
        flatten: bool = True,
    ) -> Dict[str, List[ModuleInfo]]:
        """Run module scanning plugins and aggregate the results. It is designed
        to not operate any inter-plugin results triage.

        Args:
            run_hidden_modules: specify if the hidden_modules plugin should be run
        Returns:
            Dictionary mapping each plugin to its corresponding result
        """

        kernel = context.modules[kernel_name]

        address_mask = context.layers[kernel.layer_name].address_mask

        run_results = {}

        # the kernel module boundaries
        run_results["kernel"] = [cls.get_kernel_module_info(context, kernel_name)]

        # lsmod
        run_results["lsmod"] = []

        for module in cls.list_modules(context, kernel_name):
            modinfo = cls.get_module_info_for_module(address_mask, module)
            if modinfo:
                run_results["lsmod"].append(modinfo)

        # check_modules
        run_results["check_modules"] = []

        sysfs_modules: dict = cls.get_kset_modules(context, kernel_name)

        for m_offset in sysfs_modules.values():
            module = kernel.object(object_type="module", offset=m_offset, absolute=True)
            modinfo = cls.get_module_info_for_module(address_mask, module)
            if modinfo:
                run_results["check_modules"].append(modinfo)

        # hidden_modules
        if run_hidden_modules:
            known_modules_addresses = set(
                context.layers[kernel.layer_name].canonicalize(modinfo.start)
                for modinfo in run_results["kernel"]
                + run_results["lsmod"]
                + run_results["check_modules"]
            )
            modules_memory_boundaries = cls.get_modules_memory_boundaries(
                context, kernel_name
            )
            run_results["hidden_modules"] = []

            for module in cls.get_hidden_modules(
                context,
                kernel_name,
                known_modules_addresses,
                modules_memory_boundaries,
            ):
                modinfo = cls.get_module_info_for_module(address_mask, module)
                if modinfo:
                    run_results["hidden_modules"].append(modinfo)

        if flatten:
            return cls.flatten_run_modules_results(run_results)

        return run_results

    @staticmethod
    def get_modules_memory_boundaries(
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Tuple[int, int]:
        """Determine the boundaries of the module allocation area

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            A tuple containing the minimum and maximum addresses for the module allocation area.
        """
        vmlinux = context.modules[vmlinux_module_name]
        if vmlinux.has_symbol("mod_tree"):
            # Kernel >= 5.19    58d208de3e8d87dbe196caf0b57cc58c7a3836ca
            mod_tree = vmlinux.object_from_symbol("mod_tree")
            modules_addr_min = mod_tree.addr_min
            modules_addr_max = mod_tree.addr_max
        elif vmlinux.has_symbol("module_addr_min"):
            # 2.6.27 <= kernel < 5.19   3a642e99babe0617febb6f402e1e063479f489db
            modules_addr_min = vmlinux.object_from_symbol("module_addr_min")
            modules_addr_max = vmlinux.object_from_symbol("module_addr_max")

            if isinstance(modules_addr_min, objects.Void):
                raise exceptions.VolatilityException(
                    "Your ISF symbols lack type information. You may need to update the"
                    "ISF using the latest version of dwarf2json"
                )
        else:
            raise exceptions.VolatilityException(
                "Cannot find the module memory allocation area. Unsupported kernel"
            )

        return modules_addr_min, modules_addr_max

    @classmethod
    def flatten_run_modules_results(
        cls, run_results: Dict[str, List[ModuleInfo]], deduplicate: bool = True
    ) -> List[ModuleInfo]:
        """Flatten a dictionary mapping plugin names and modules list, to a single merged list.
        This is useful to get a generic lookup list of all the detected modules.

        Args:
            run_results: dictionary of plugin names mapping a list of detected modules
            deduplicate: remove duplicate modules, based on their offsets

        Returns:
            List of ModuleInfo objects
        """
        uniq_modules: List[Modules.ModuleInfo] = []

        seen_addresses: int = set()

        for modules in run_results.values():
            for module in modules:
                if deduplicate and (module.start in seen_addresses):
                    continue
                seen_addresses.add(module.start)
                uniq_modules.append(module)

        return uniq_modules

    @classmethod
    def get_hidden_modules(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        known_module_addresses: Set[int],
        modules_memory_boundaries: Tuple,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Enumerate hidden modules by taking advantage of memory address alignment patterns

        This technique is much faster and uses less memory than the traditional scan method
        in Volatility2, but it doesn't work with older kernels.

        From kernels 4.2 struct module allocation are aligned to the L1 cache line size.
        In i386/amd64/arm64 this is typically 64 bytes. However, this can be changed in
        the Linux kernel configuration via CONFIG_X86_L1_CACHE_SHIFT. The alignment can
        also be obtained from the DWARF info i.e. DW_AT_alignment<64>, but dwarf2json
        doesn't support this feature yet.
        In kernels < 4.2, alignment attributes are absent in the struct module, meaning
        alignment cannot be guaranteed. Therefore, for older kernels, it's better to use
        the traditional scan technique.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate
            known_module_addresses: Set with known module addresses
            modules_memory_boundaries: Minimum and maximum address boundaries for module allocation.
        Yields:
            module objects
        """
        vmlinux = context.modules[vmlinux_module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]

        module_addr_min, module_addr_max = modules_memory_boundaries
        module_address_alignment = cls.get_module_address_alignment(
            context, vmlinux_module_name
        )
        if not cls.validate_alignment_patterns(
            known_module_addresses, module_address_alignment
        ):
            vollog.warning(
                f"Module addresses aren't aligned to {module_address_alignment} bytes. "
                "Switching to 1 byte aligment scan method."
            )
            module_address_alignment = 1

        mkobj_offset = vmlinux.get_type("module").relative_child_offset("mkobj")
        mod_offset = vmlinux.get_type("module_kobject").relative_child_offset("mod")
        offset_to_mkobj_mod = mkobj_offset + mod_offset
        mod_member_template = vmlinux.get_type("module_kobject").child_template("mod")
        mod_size = mod_member_template.size
        mod_member_data_format = mod_member_template.data_format

        for module_addr in range(
            module_addr_min, module_addr_max, module_address_alignment
        ):
            if module_addr in known_module_addresses:
                continue

            try:
                # This is just a pre-filter. Module readability and consistency are verified in module.is_valid()
                self_referential_bytes = vmlinux_layer.read(
                    module_addr + offset_to_mkobj_mod, mod_size
                )
                self_referential = objects.convert_data_to_value(
                    self_referential_bytes, int, mod_member_data_format
                )
                if self_referential != module_addr:
                    continue
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ):
                continue

            module = vmlinux.object("module", offset=module_addr, absolute=True)
            if module and module.is_valid():
                yield module

    @classmethod
    def get_module_address_alignment(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> int:
        """Obtain the module memory address alignment.

        struct module is aligned to the L1 cache line, which is typically 64 bytes for most
        common i386/AMD64/ARM64 configurations. In some cases, it can be 128 bytes, but this
        will still work.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Returns:
            The struct module alignment
        """
        # FIXME: When dwarf2json/ISF supports type alignments. Read it directly from the type metadata
        # Additionally, while 'context' and 'vmlinux_module_name' are currently unused, they will be
        # essential for retrieving type metadata in the future.
        return 64

    @classmethod
    def list_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            vmlinux_symbols: The name of the table containing the kernel symbols

        Yields:
            The modules present in the `layer_name` layer's modules list

        This function will throw a SymbolError exception if kernel module support is not enabled.
        """
        vmlinux = context.modules[vmlinux_module_name]

        modules = vmlinux.object_from_symbol(symbol_name="modules").cast("list_head")

        table_name = vmlinux.symbol_table_name

        yield from modules.to_list(table_name + constants.BANG + "module", "list")

    @classmethod
    def get_kset_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_name: str
    ) -> Dict[str, extensions.module]:
        vmlinux = context.modules[vmlinux_name]

        try:
            module_kset = vmlinux.object_from_symbol("module_kset")
        except exceptions.SymbolError:
            module_kset = None

        if not module_kset:
            raise TypeError(
                "This plugin requires the module_kset structure. This structure is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        ret = {}

        kobj_off = vmlinux.get_type("module_kobject").relative_child_offset("kobj")

        for kobj in module_kset.list.to_list(
            vmlinux.symbol_table_name + constants.BANG + "kobject", "entry"
        ):
            mod_kobj = vmlinux.object(
                object_type="module_kobject",
                offset=kobj.vol.offset - kobj_off,
                absolute=True,
            )

            mod = mod_kobj.mod

            try:
                name = utility.pointer_to_string(kobj.name, 32)
            except exceptions.InvalidAddressException:
                continue

            if kobj.name and kobj.reference_count() > 2:
                ret[name] = mod

        return ret

    @staticmethod
    def validate_alignment_patterns(
        addresses: Iterable[int],
        address_alignment: int,
    ) -> bool:
        """Check if the memory addresses meet our alignments patterns

        Args:
            addresses: Iterable with the address values
            address_alignment: Number of bytes for alignment validation

        Returns:
            True if all the addresses meet the alignment
        """
        return all(addr % address_alignment == 0 for addr in addresses)
