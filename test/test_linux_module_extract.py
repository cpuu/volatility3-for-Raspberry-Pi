"""Module ELF reconstruction regressions for allocation and index handling."""

from types import SimpleNamespace as NS
from unittest.mock import patch
import struct
import pytest
from volatility3.framework.symbols.linux.utilities.modules import ModuleExtract


@pytest.mark.parametrize(
    "bits,arch,machine,size",
    [(32, "Intel32", 3, 52), (64, "Intel64", 62, 64), (64, "AArch64", 183, 64)],
)
def test_elf_machine_matches_architecture(bits, arch, machine, size):
    header = ModuleExtract._make_elf_header(bits, 128, 4, arch)
    assert len(header) == size
    assert struct.unpack_from("<H", header, 18)[0] == machine
    assert header[4] == (1 if bits == 32 else 2)


def test_aarch64_cannot_be_mislabeled_as_elf32():
    with pytest.raises(ValueError):
        ModuleExtract._make_elf_header(32, 128, 4, "AArch64")


@pytest.mark.parametrize("info", [0, 1, 2, 0x11, 0x12, 0x21, 0x22])
def test_preserves_valid_local_global_weak_and_mapping_symbol_info(info):
    sym = NS(st_info=info)
    assert ModuleExtract._get_st_info_for_sym(sym, 0x1000, ".text") == bytes([info])


@pytest.mark.parametrize(
    "name", [".plt", ".text.ftrace_trampoline", ".init.plt", ".text.hot"]
)
def test_arm64_code_sections_are_executable(name):
    assert ModuleExtract._calc_sect_flags(name) & 4


@pytest.mark.parametrize("name", [".strtab", ".symtab", ".shstrtab"])
def test_rebuilt_metadata_is_not_marked_allocated(name):
    assert ModuleExtract._calc_sect_flags(name) == 0


def test_reconstruction_excludes_freed_sections_and_remaps_symbols_to_final_order():
    reads = []
    memory = {0x1000: bytes(range(256)), 0x5000: bytes(256)}
    memory[0x5000] = memory[0x5000][:0xB0] + b"\0fn\0" + bytes(0x4C)

    def read(address, size):
        reads.append((address, size))
        for base, content in memory.items():
            if base <= address and address + size <= base + len(content):
                return content[address - base : address - base + size]
        raise AssertionError("Read crossed a gap or freed allocation")

    layer = NS(read=read, metadata={"architecture": "AArch64"})
    syms = [
        NS(st_name=0, st_value=0, st_info=0, st_shndx=0, st_other=0, st_size=0),
        NS(st_name=1, st_value=0x1004, st_info=2, st_shndx=37, st_other=0, st_size=8),
    ]

    def get_type(name):
        return NS(size={"Elf64_Sym": 24, "Elf64_Ehdr": 64, "Elf64_Shdr": 64}[name])

    kernel = NS(
        layer_name="kernel",
        symbol_table_name="symbols",
        get_type=get_type,
        object=lambda *a, **k: syms,
    )
    context = NS(modules={"kernel": kernel}, layers={"kernel": layer})
    section_specs = [
        (".data", 0x5000),
        (".init.text", 0x9000),
        (".text", 0x1000),
        (".strtab", 0x9800),
        (".symtab", 0x9600),
    ]
    sections = [
        NS(address=addr, get_name=lambda name=name: name)
        for name, addr in section_specs
    ]
    module = NS(
        mem=[
            NS(base=0x1000, size=0x100),
            NS(base=0x5000, size=0x100),
            NS(base=0, size=0),
        ],
        has_member=lambda name: name == "mem",
        section_symtab=0x5080,
        section_strtab=0x50B0,
        num_symtab=2,
        get_sections=lambda: iter(sections),
        sect_attrs=NS(nsections=5),
        vol=NS(offset=0x5000),
    )
    with patch(
        "volatility3.framework.symbols.linux.utilities.modules.symbols.symbol_table_is_64bit",
        return_value=True,
    ):
        data = ModuleExtract.extract_module(context, "kernel", module)
    offset = struct.unpack_from("<Q", data, 40)[0]
    count = struct.unpack_from("<H", data, 60)[0]
    headers = [
        struct.unpack_from("<IIQQQQIIQQ", data, offset + i * 64) for i in range(count)
    ]
    assert count == 6  # NULL, text, data, strtab, symtab, shstrtab
    text, data_section, strings, symbols = headers[1:5]
    assert (text[3], text[5]) == (0x1000, 0x100)
    assert (data_section[3], data_section[5]) == (0x5000, 0x80)
    assert symbols[6] == 3  # sh_link points to .strtab, including leading null.
    assert symbols[7] == 2  # Both retained symbols are local.
    assert data[symbols[4] : symbols[4] + 24] == bytes(24)
    sym = struct.unpack_from("<IBBHQQ", data, symbols[4] + 24)
    assert sym == (1, 2, 0, 1, 4, 8)  # Original index 37 becomes final .text index 1.
    assert data[text[4] + sym[4] : text[4] + sym[4] + sym[5]] == bytes(range(4, 12))
    assert all(address < 0x9000 for address, size in reads)
