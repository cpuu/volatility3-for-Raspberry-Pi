# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import dataclasses
from typing import List, Iterator, Tuple

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.constants import architectures
from volatility3.framework.objects import utility
from volatility3.framework.layers import arm
from volatility3.framework.symbols.linux import kallsyms
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


@dataclasses.dataclass
class StackEntry:
    position: int
    address: int
    value: int
    name: str = renderers.NotAvailableValue()
    type: str = renderers.NotAvailableValue()
    module: str = renderers.NotAvailableValue()


class PsCallStack(plugins.PluginInterface):
    """Enumerates the call stack of each task"""

    _required_framework_version = (2, 19, 0)

    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=[*architectures.LINUX_ARCHS, "AArch64"],
            ),
            requirements.VersionRequirement(
                name="Kallsyms", component=kallsyms.Kallsyms, version=(1, 1, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="unresolved",
                description="Include unresolved stack values",
                default=False,
                optional=True,
            ),
        ]

    @staticmethod
    def _arm64_stack_bounds(kernel, layer, task) -> Tuple[int, int]:
        """Return the saved SP and stack end using runtime or debug geometry."""
        base = layer.canonicalize(int(task.stack))
        start = layer.canonicalize(int(task.thread.cpu_context.sp))
        size = 0
        if task.has_member("stack_vm_area") and task.stack_vm_area:
            area = task.stack_vm_area
            # fork.c requires nr_pages == THREAD_SIZE / PAGE_SIZE for VMAP stacks.
            size = int(area.nr_pages) * layer.page_size
            guard = 0 if int(area.flags) & 0x40 else layer.page_size  # VM_NO_GUARD
            if (
                layer.canonicalize(int(area.addr)) != base
                or int(area.size) != size + guard
            ):
                raise exceptions.VolatilityException(
                    "Inconsistent ARM64 stack allocation"
                )
        elif kernel.has_symbol("init_stack"):
            # This array is declared as THREAD_SIZE / sizeof(unsigned long).
            # Its debug size includes architecture and KASAN configuration.
            stack_type = kernel.get_symbol("init_stack").type
            if stack_type is not None:
                size = stack_type.size
        if not size and kernel.has_type("thread_union"):
            size = kernel.get_type("thread_union").size
        if size < layer.page_size or size & (size - 1):
            raise exceptions.VolatilityException(
                "Cannot determine ARM64 thread stack size"
            )
        end = base + size
        if not base or not base <= start < end or start % 16:
            raise exceptions.VolatilityException(
                f"Invalid ARM64 saved stack pointer {start:#x}"
            )
        return start, end

    @classmethod
    def get_task_callstack(
        cls,
        context: interfaces.context.ContextInterface,
        module_name: str,
        task: interfaces.objects.ObjectInterface,
        kas: kallsyms.Kallsyms = None,
        include_unresolved=False,
    ) -> Iterator[StackEntry]:
        """Retrieves the call stack for a given task

        Args:
            context: The context used to access memory layers and symbols
            module_name: The name of the kernel module on which to operate
            task: The task object whose stack is being retrieved
            kas: Kallsyms instance for symbol resolution. If not provided or None, a new
                instance will be created each time
            include_unresolved: If True, includes stack values that could not be resolved
                to known symbols. Defaults to False.

        Yields:
            StackEntry objects
        """
        vmlinux = context.modules[module_name]
        vmlinux_layer = context.layers[vmlinux.layer_name]
        is_arm64 = isinstance(vmlinux_layer, arm.LinuxAArch64)
        # These are kernel stacks; a task's ARM64 TTBR0 maps user memory only.
        task_layer = vmlinux_layer if is_arm64 else task.get_address_space_layer()
        if not task_layer:
            return None

        if not kas:
            kas = kallsyms.Kallsyms(
                context=context,
                layer_name=vmlinux.layer_name,
                module_name=module_name,
            )

        pointer_size = vmlinux.get_type("pointer").size

        byte_order = task.files.vol.data_format.byteorder
        if is_arm64:
            try:
                rsp_start, task_top_of_stack = cls._arm64_stack_bounds(
                    vmlinux, vmlinux_layer, task
                )
            except (
                exceptions.InvalidAddressException,
                exceptions.VolatilityException,
            ) as exc:
                vollog.warning("Skipping task %d stack: %s", task.pid, exc)
                return
        else:
            thread_size_order = 2  # Safe since kernel 3.15
            # thread_size_order +=1  # If CONFIG_KASAN is enabled in kernels >= 4.0, default: DISABLED
            # thread_size_order +=1  # If CONFIG_KASAN_EXTRA is enabled in kernels >= 4.19, default: DISABLED
            thread_size = vmlinux_layer.page_size << thread_size_order
            task_base_of_stack = vmlinux_layer.canonicalize(task.stack)
            task_top_of_stack = task_base_of_stack + thread_size

            rsp_start = task.thread.sp
            if not (task_base_of_stack <= rsp_start < task_top_of_stack):
                raise exceptions.VolatilityException(
                    f"Invalid stack pointer {rsp_start:#x} for task {task.pid}"
                )

        current_sp = rsp_start
        idx = 0
        while current_sp < task_top_of_stack:
            try:
                stack_value_bytes = task_layer.read(current_sp, pointer_size)
            except exceptions.InvalidAddressException:
                break
            stack_value = int.from_bytes(stack_value_bytes, byteorder=byte_order)
            if not stack_value:
                idx += 1
                current_sp += pointer_size
                continue
            kassymbol = kas.lookup_address(stack_value)
            sp_address = current_sp & vmlinux_layer.address_mask
            stack_value &= vmlinux_layer.address_mask
            if kassymbol:
                module_name = kassymbol.module_name or renderers.NotAvailableValue()
                yield StackEntry(
                    position=idx,
                    address=sp_address,
                    value=stack_value,
                    name=kassymbol.name,
                    type=kassymbol.type,
                    module=module_name,
                )
            elif include_unresolved:
                yield StackEntry(
                    position=idx,
                    address=sp_address,
                    value=stack_value,
                )

            idx += 1
            current_sp += pointer_size

    def _generator(self):
        module_name = self.config["kernel"]
        vmlinux = self.context.modules[module_name]

        kas = kallsyms.Kallsyms(
            context=self.context,
            layer_name=vmlinux.layer_name,
            module_name=self.config["kernel"],
        )

        include_unresolved = self.config.get("unresolved", False)

        pids = self.config.get("pid", None)
        filter_func = pslist.PsList.create_pid_filter(pids)
        for task in pslist.PsList.list_tasks(
            self.context, vmlinux.name, filter_func=filter_func, include_threads=True
        ):
            task_name = utility.array_to_string(task.comm)

            for stack_entry in self.get_task_callstack(
                context=self.context,
                module_name=vmlinux.name,
                task=task,
                kas=kas,
                include_unresolved=include_unresolved,
            ):
                fields = (
                    task.pid,
                    task_name,
                    stack_entry.position,
                    format_hints.Hex(stack_entry.address),
                    format_hints.Hex(stack_entry.value),
                    stack_entry.name,
                    stack_entry.type,
                    stack_entry.module,
                )
                yield 0, fields

    def run(self):
        return renderers.TreeGrid(
            [
                ("TID", int),
                ("Comm", str),
                ("Position", int),
                ("Address", format_hints.Hex),
                ("Value", format_hints.Hex),
                ("Name", str),
                ("Type", str),
                ("Module", str),
            ],
            self._generator(),
        )
