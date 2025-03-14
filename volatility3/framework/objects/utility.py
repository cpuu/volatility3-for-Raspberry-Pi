# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Optional, Union

from volatility3.framework import interfaces, objects, constants, exceptions


def rol(value: int, count: int, max_bits: int = 64) -> int:
    """A rotate-left instruction in Python"""
    max_bits_mask = (1 << max_bits) - 1
    return (value << count % max_bits) & max_bits_mask | (
        (value & max_bits_mask) >> (max_bits - (count % max_bits))
    )


def bswap_32(value: int) -> int:
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0x00FF00FF)

    return ((value << 16) | (value >> 16)) & 0xFFFFFFFF


def bswap_64(value: int) -> int:
    low = bswap_32(value >> 32)
    high = bswap_32(value & 0xFFFFFFFF)

    return ((high << 32) | low) & 0xFFFFFFFFFFFFFFFF


def array_to_string(
    array: "objects.Array",
    count: Optional[int] = None,
    errors: str = "replace",
    block_size=32,
    encoding="utf-8",
) -> str:
    """Takes a Volatility 'Array' of characters and returns a Python string.

    Args:
        array: The Volatility `Array` object containing character elements.
        count: Optional maximum number of characters to convert. If None, the function
               processes the entire array.
        errors: Specifies error handling behavior for decoding, defaulting to "replace".
        block_size: Reading block size. Defaults to 32

    Returns:
        A decoded string representation of the character array.
    """
    # TODO: Consider checking the Array's target is a native char
    if not isinstance(array, objects.Array):
        raise TypeError("Array_to_string takes an Array of char")

    if count is None:
        count = array.vol.count

    return address_to_string(
        context=array._context,
        layer_name=array.vol.layer_name,
        address=array.vol.offset,
        count=count,
        errors=errors,
        block_size=block_size,
        encoding=encoding,
    )


def pointer_to_string(
    pointer: "objects.Pointer",
    count: int,
    errors: str = "replace",
    block_size=32,
    encoding="utf-8",
) -> str:
    """Takes a Volatility 'Pointer' to characters and returns a Python string.

    Args:
        pointer: A `Pointer` object containing character elements.
        count: Optional maximum number of characters to convert. If None, the function
               processes the entire array.
        errors: Specifies error handling behavior for decoding, defaulting to "replace".
        block_size: Reading block size. Defaults to 32

    Returns:
        A decoded string representation of the data referenced by the pointer.
    """
    if not isinstance(pointer, objects.Pointer):
        raise TypeError("pointer_to_string takes a Pointer")

    if count < 1:
        raise ValueError("pointer_to_string requires a positive count")

    return address_to_string(
        context=pointer._context,
        layer_name=pointer.vol.layer_name,
        address=pointer,
        count=count,
        errors=errors,
        block_size=block_size,
        encoding=encoding,
    )


def gather_contiguous_bytes_from_address(layer, address: int, count: int) -> bytes:
    """
    This method reconstructs a string from memory while also carefully examining each page

    It goes page-by-page reading the bytes. This is done by calculating page boundaries
    and then only reading one page at a time.

    If a page is missing, the code initially catches the exception.
    If data is non-empty (meaning at least one read succeeded), then we return what was read
    If the first page fails, then we re-raise the exception
    """

    data = b""

    left_to_read = count

    # read as many pages as possible that are contiguous
    # if the first page is missed, we re-raise the InvalidAddressException
    # if we have at least 1 page that was read succesfully,
    # then we try to construct a string from it
    while left_to_read > 0:
        # compute aligned address of current page and next the page
        aligned = address & ~0xFFF
        next_page = aligned + 0xFFF + 1

        # all fits on the current page, last read
        if address + left_to_read < next_page:
            try:
                data += layer.read(address, left_to_read)
            except exceptions.InvalidAddressException:
                # if we have data, just break the loop
                if data:
                    break
                # Raise if no data was read as this means the first page was invalid
                else:
                    raise

            left_to_read = 0

        else:
            # how many bytes are left on the current page
            len_to_read = next_page - address

            try:
                data += layer.read(address, len_to_read)
            except exceptions.InvalidAddressException:
                if data:
                    break
                # Raise if no data was read as this means the first page was invalid
                else:
                    raise

            address += len_to_read
            left_to_read -= len_to_read

    return data


def address_to_string(
    context: interfaces.context.ContextInterface,
    layer_name: str,
    address: int,
    count: int,
    errors: str = "replace",
    block_size=32,
    encoding="utf-8",
) -> str:
    """Reads a null-terminated string from a given specified memory address, processing
       it in blocks for efficiency.

    Args:
        context: The context used to retrieve memory layers and symbol tables
        layer_name: The name of the memory layer to read from
        address: The address where the string is located in memory
        count: The number of bytes to read
        errors: The error handling scheme to use for encoding errors. Defaults to "replace"
        block_size: Reading block size. Defaults to 32

    Returns:
        The decoded string extracted from memory.
    """
    if not isinstance(address, int):
        raise TypeError("Address must be a valid integer")

    if count < 1:
        raise ValueError("Count must be greater than 0")

    encodings = {
        "utf-8": 1,
        "utf8": 1,
        "utf-16": 2,
        "utf16": 2,
        "utf32": 4,
        "utf-32": 4,
    }
    if encoding not in encodings:
        raise ValueError(
            f"Encoding ({encoding} is invalid. Must be one of {[e for e in encodings]}."
        )

    layer = context.layers[layer_name]

    data = gather_contiguous_bytes_from_address(layer, address, count)

    # we need to find the ending nulls, which the amount of nulls varies based on encoding
    ending_nulls = b"\x00" * encodings[encoding]

    end_idx = data.find(ending_nulls)
    # send back the bytes even if the ending nulls aren't found (can be on the next page)
    if end_idx == -1:
        return data

    # cut at the nulls
    data = data[:end_idx]

    # For utf16 and utf32, just looking for the nulls cuts the final null from the string when its ascii characters
    # This occurs as the string 'vol.py' in utf-16 will look like this, with two ending nulls:
    # "v\x00o\x00l\x00.\x00p\x00y\x00\x00\x00"
    # By cutting at the first \x00\x00, we are taking the second byte of the character for 'y'
    # With real unicode strings this character can be non-zero
    # This check and added null, pads out the last byte(s) to the width of each character to avoid this issue
    end_size = len(ending_nulls)
    if len(data) > end_size and len(data) % end_size != 0:
        data += b"\x00" * (end_size - (len(data) % end_size))

    return data.decode(encoding=encoding, errors=errors)


def array_of_pointers(
    array: interfaces.objects.ObjectInterface,
    count: int,
    subtype: Union[str, interfaces.objects.Template],
    context: interfaces.context.ContextInterface,
) -> interfaces.objects.ObjectInterface:
    """Takes an object, and recasts it as an array of pointers to subtype."""
    symbol_table = array.vol.type_name.split(constants.BANG)[0]
    if isinstance(subtype, str) and context is not None:
        subtype = context.symbol_space.get_type(subtype)
    if not isinstance(subtype, interfaces.objects.Template) or subtype is None:
        raise TypeError(
            "Subtype must be a valid template (or string name of an object template)"
        )
    # We have to clone the pointer class, or we'll be defining the pointer subtype for all future pointers
    subtype_pointer = context.symbol_space.get_type(
        symbol_table + constants.BANG + "pointer"
    ).clone()
    subtype_pointer.update_vol(subtype=subtype)
    return array.cast("array", count=count, subtype=subtype_pointer)
