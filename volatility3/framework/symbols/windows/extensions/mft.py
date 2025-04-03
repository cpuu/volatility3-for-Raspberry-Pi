# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Dict, Iterator, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, objects


class MFTEntry(objects.StructType):
    """This represents the base MFT Record"""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
        **kwargs,
    ) -> None:
        super().__init__(context, type_name, object_info, size, members)

        self._symbol_table_name = kwargs.get("symbol_table_name")
        self._attr_generator = self._attributes()
        self._attrs: List[MFTAttribute] = []

    @property
    def symbol_table_name(self) -> str:
        if self._symbol_table_name is None:
            raise ValueError(
                "MFTEntry was instantiated without an MFT symbol table name"
            )
        return self._symbol_table_name

    def get_signature(self) -> objects.String:
        signature = self.Signature.cast("string", max_length=4, encoding="latin-1")
        return signature

    def filename(self, symbol_table_name: str) -> Optional[objects.String]:
        try:
            fname_attr = next(
                attr
                for attr in self.attributes()
                if attr.Attr_Header.AttrType.lookup() == "FILE_NAME"
            )
        except StopIteration:
            return None

        fn_object = symbol_table_name + constants.BANG + "FILE_NAME_ENTRY"
        attr_data = fname_attr.Attr_Data.cast(fn_object)

        return attr_data.get_full_name()

    def attributes(self) -> Iterator["MFTAttribute"]:
        yield from self._attrs

        for attr in self._attr_generator:
            self._attrs.append(attr)
            yield attr

    def _attributes(self) -> Iterator["MFTAttribute"]:

        # We will update this on each pass in the next loop and use it as the new offset.
        attr_base_offset = self.FirstAttrOffset
        attribute_object_type_name = (
            self.symbol_table_name + constants.BANG + "ATTRIBUTE"
        )

        attr: MFTAttribute = self._context.object(
            attribute_object_type_name,
            offset=self.vol.offset + attr_base_offset,
            layer_name=self.vol.layer_name,
        )

        # There is no field that has a count of Attributes
        # Keep Attempting to read attributes until we get an invalid attr_header.AttrType
        while attr.Attr_Header.AttrType.is_valid_choice:
            yield attr

            # If there's no advancement the loop will never end, so break it now
            if attr.Attr_Header.Length == 0:
                break

            # Update the base offset to point to the next attribute
            attr_base_offset += attr.Attr_Header.Length
            # Get the next attribute
            attr: MFTAttribute = self._context.object(
                attribute_object_type_name,
                offset=self.vol.offset + attr_base_offset,
                layer_name=self.vol.layer_name,
            )


class MFTFileName(objects.StructType):
    """This represents an MFT $FILE_NAME Attribute"""

    def get_full_name(self) -> objects.String:
        output = self.Name.cast(
            "string", encoding="utf16", max_length=self.NameLength * 2, errors="replace"
        )
        return output


class MFTAttribute(objects.StructType):
    """This represents an MFT ATTRIBUTE"""

    def get_resident_filename(self) -> Optional[objects.String]:
        # 4MB chosen as cutoff instead of 4KB to allow for recovery from format /L created file systems
        # Length as 512 as its 256*2, which is the maximum size for an entire file path, so this is even generous
        if (
            self.Attr_Header.ContentOffset > 0x400000
            or self.Attr_Header.NameLength > 512
        ):
            return None

        # To get the resident name, we jump to relative name offset and read name length * 2 bytes of data
        try:
            name = self._context.object(
                self.vol.type_name.split(constants.BANG)[0] + constants.BANG + "string",
                layer_name=self.vol.layer_name,
                offset=self.vol.offset + self.Attr_Header.NameOffset,
                max_length=self.Attr_Header.NameLength * 2,
                errors="replace",
                encoding="utf16",
            )
            return name
        except exceptions.InvalidAddressException:
            return None

    def get_resident_filecontent(self) -> Optional[objects.Bytes]:
        # smear observed in mass testing of samples
        # 4MB chosen as cutoff instead of 4KB to allow for recovery from format /L created file systems
        if (
            self.Attr_Header.ContentOffset > 0x400000
            or self.Attr_Header.ContentLength > 0x400000
        ):
            return None

        # To get the resident content, we jump to relative content offset and read name length * 2 bytes of data
        try:
            bytesobj = self._context.object(
                self.vol.type_name.split(constants.BANG)[0] + constants.BANG + "bytes",
                layer_name=self.vol.layer_name,
                offset=self.vol.offset + self.Attr_Header.ContentOffset,
                native_layer_name=self.vol.native_layer_name,
                length=self.Attr_Header.ContentLength,
            )
            return bytesobj
        except exceptions.InvalidAddressException:
            return None
