# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""Functions that read AVML files.

The user of the file doesn't have to worry about the compression,
but random access is not allowed."""

import ctypes
import logging
import struct
from typing import Tuple, List, Optional

from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.layers import segmented

vollog = logging.getLogger(__name__)

try:
    # TODO: Find library for windows if needed
    try:
        # Linux
        lib_snappy = ctypes.cdll.LoadLibrary("libsnappy.so.1")
    except OSError:
        lib_snappy = None

    try:
        if not lib_snappy:
            # macOS
            lib_snappy = ctypes.cdll.LoadLibrary("libsnappy.1.dylib")
    except OSError:
        lib_snappy = None

    try:
        if not lib_snappy:
            # Windows 64
            lib_snappy = ctypes.cdll.LoadLibrary("snappy64")
    except OSError:
        lib_snappy = None

    if not lib_snappy:
        # Windows 32
        lib_snappy = ctypes.cdll.LoadLibrary("snappy32")

    __snappy_uncompress = lib_snappy.snappy_uncompress
    __snappy_uncompressed_length = lib_snappy.snappy_uncompressed_length

    HAS_SNAPPY = True
except (AttributeError, OSError):
    HAS_SNAPPY = False


class SnappyException(exceptions.VolatilityException):
    pass


def uncompress(s):
    """Uncompress a snappy compressed string."""
    ulen = ctypes.c_size_t(0)
    cresult = __snappy_uncompressed_length(s, len(s), ctypes.byref(ulen))
    if cresult != 0:
        raise SnappyException(f"Error in snappy_uncompressed_length: {cresult}")
    ubuf = ctypes.create_string_buffer(ulen.value)
    cresult = __snappy_uncompress(s, len(s), ubuf, ctypes.byref(ulen))
    if cresult != 0:
        raise SnappyException(f"Error in snappy_uncompress: {cresult}")
    return ubuf.raw


class AVMLLayer(segmented.NonLinearlySegmentedLayer):
    """A Lime format TranslationLayer.

    Lime is generally used to store physical memory images where there
    are large holes in the physical layer
    """

    def __init__(self, *args, **kwargs):
        self._compressed = {}
        super().__init__(*args, **kwargs)

    @classmethod
    def _check_header(cls, layer: interfaces.layers.DataLayerInterface):
        header_structure = "<II"
        magic, version = struct.unpack(
            header_structure,
            layer.read(layer.minimum_address, struct.calcsize(header_structure)),
        )
        if magic not in [0x4C4D5641] or version != 2:
            raise exceptions.LayerException("File not in AVML format")
        if not HAS_SNAPPY:
            vollog.warning(
                "AVML file detected, but snappy library could not be found\n"
                "Please install the snappy from your distribution or https://google.github.io/snappy/."
            )
            raise exceptions.LayerException(
                "AVML format dependencies not satisfied (snappy)"
            )

    def _load_segments(self) -> None:
        base_layer = self.context.layers[self._base_layer]
        offset = base_layer.minimum_address
        while offset + 4 < base_layer.maximum_address:
            avml_header_structure = "<IIQQQ"
            avml_header_size = struct.calcsize(avml_header_structure)
            avml_header_data = base_layer.read(offset, avml_header_size)
            magic, version, start, end, padding = struct.unpack(
                avml_header_structure, avml_header_data
            )

            if magic not in [0x4C4D5641] or version != 2:
                raise exceptions.LayerException("File not completely in AVML format")
            if end < start:
                raise exceptions.LayerException("Invalid AVML physical range")
            stream_start = offset + avml_header_size
            segments, consumed = self._parse_snappy_frames(
                lambda pos, size: base_layer.read(stream_start + pos, size),
                base_layer.maximum_address + 1 - stream_start,
                end - start,
            )
            # Frame offsets are relative to the start of this Snappy stream.
            for thing, mapped_offset, size, mapped_size, compressed in segments:
                self._segments.append(
                    (
                        thing + start,
                        offset + mapped_offset + avml_header_size,
                        size,
                        mapped_size,
                    )
                )
                self._compressed[offset + mapped_offset + avml_header_size] = compressed

            # TODO: Check whatever the remaining 8 bytes are
            offset += avml_header_size + consumed + 8

    def _read_snappy_frames(
        self, data: bytes, expected_length: int
    ) -> Tuple[List[Tuple[int, int, int, int, bool]], int]:
        """
        Reads a framed-format snappy stream

        Args:
            data: The stream to read
            expected_length: How big the decompressed stream is expected to be (termination limit)

        Returns:
            (offset, mapped_offset, length, mapped_length, compressed) relative to the data chunk (ie, not relative to the file start)
        """
        return self._parse_snappy_frames(
            lambda pos, size: data[pos : pos + size], len(data), expected_length
        )

    def _parse_snappy_frames(self, read, available, expected_length):
        """Read bounded frames independently of their compression ratio.

        AVML uses an inclusive physical end address. Snappy framing can make
        an incompressible stream larger than the corresponding RAM range.
        """
        segments = []
        decompressed_len = 0
        offset = 0
        while decompressed_len <= expected_length:
            if offset + 4 > available:
                raise exceptions.LayerException("Truncated Snappy frame header")
            header = read(offset, 4)
            if len(header) != 4:
                raise exceptions.LayerException("Short Snappy frame header")
            frame_header = struct.unpack("<L", header)[0]
            frame_type, frame_size = frame_header & 0xFF, frame_header >> 8
            if offset + 4 + frame_size > available:
                raise exceptions.LayerException("Truncated Snappy frame payload")
            payload = read(offset + 4, frame_size)
            if len(payload) != frame_size:
                raise exceptions.LayerException("Short Snappy frame payload")
            if frame_type == 0xFF:
                if payload != b"sNaPpY":
                    raise exceptions.LayerException("Invalid Snappy stream identifier")
            elif frame_type in (0, 1):
                if frame_size < 4:
                    raise exceptions.LayerException("Missing Snappy frame CRC")
                frame_data = payload[4:]
                if frame_type == 0:
                    frame_data = uncompress(frame_data)
                if decompressed_len + len(frame_data) > expected_length + 1:
                    raise exceptions.LayerException("Snappy data exceeds AVML range")
                segments.append(
                    (
                        decompressed_len,
                        offset + 8,
                        len(frame_data),
                        frame_size - 4,
                        frame_type == 0,
                    )
                )
                decompressed_len += len(frame_data)
            elif frame_type < 0x80:
                raise exceptions.LayerException("Unskippable Snappy chunk")
            offset += 4 + frame_size
        return segments, offset

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        start_offset, _, _, _ = self._find_segment(offset)
        if self._compressed[mapped_offset]:
            decoded_data = uncompress(data)
        else:
            decoded_data = data
        decoded_data = decoded_data[offset - start_offset :]
        decoded_data = decoded_data[:output_length]
        return decoded_data


class AVMLStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            AVMLLayer._check_header(context.layers[layer_name])
        except exceptions.LayerException:
            return None
        new_name = context.layers.free_layer_name("AVMLLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )
        return AVMLLayer(context, new_name, new_name)
