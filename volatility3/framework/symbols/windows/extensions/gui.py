# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Optional, Tuple, Iterator

from volatility3.framework import exceptions, constants, interfaces
from volatility3.framework import objects
from volatility3.framework.objects import utility
from volatility3.framework.symbols.windows.extensions import pool


class tagWINDOWSTATION(objects.StructType, pool.ExecutiveObject):
    def is_valid(self) -> bool:
        sid = self.get_session_id()
        return sid is not None and 0 <= sid < 256

    def get_session_id(self) -> Optional[int]:
        try:
            return self.dwSessionId
        except exceptions.InvalidAddressException:
            return None

    def traverse(self, max_stations: int = 15):
        """
        Traverses the window stations referenced in the list of stations
        """
        seen = set()

        # include the first window station
        yield self

        while len(seen) < max_stations:
            try:
                winsta = self.rpwinstaNext.dereference()
            except exceptions.InvalidAddressException:
                break

            if winsta.vol.offset in seen:
                break

            yield winsta

            seen.add(winsta.vol.offset)

    def get_info(self, kernel_symbol_table_name) -> Optional[Tuple[str, int]]:
        try:
            name = self.get_name(kernel_symbol_table_name)
            session_id = self.get_session_id()
        except exceptions.InvalidAddressException:
            return None, None

        # attempt to avoid smear
        if session_id is not None and session_id < 256 and name and len(name) > 1:
            return name, session_id

        return None, None

    def desktops(self, symbol_table_name, max_desktops: int = 12):
        seen = set()

        while len(seen) < max_desktops:
            try:
                desktop = self.rpdeskList.dereference()
                name = desktop.get_name(symbol_table_name)
            except exceptions.InvalidAddressException:
                break

            if desktop.vol.offset in seen:
                break

            yield desktop, name

            seen.add(desktop.vol.offset)


class tagDESKTOP(objects.StructType, pool.ExecutiveObject):
    def is_valid(self) -> bool:
        """
        Enforce a valid sid + owning window station
        """
        sid = self.get_session_id()

        valid_sid = sid is not None and 0 <= sid < 256

        if valid_sid:
            return self.get_window_station() is not None

        return False

    def get_window_station(self) -> Optional["tagWINDOWSTATION"]:
        try:
            return self.rpwinstaParent.dereference()
        except exceptions.InvalidAddressException:
            return None

    def get_session_id(self) -> Optional[int]:
        winsta = self.get_window_station()
        if winsta:
            return winsta.get_session_id()

        return None

    def get_threads(
        self,
    ) -> Iterator[Tuple[interfaces.objects.ObjectInterface, str, int]]:
        """
        Returns the threads of each desktop along with owning process information
        """
        symbol_table_name = self.vol.type_name.split(constants.BANG)[0]

        for thread in self.PtiList.to_list(
            symbol_table_name + constants.BANG + "tagTHREADINFO", "PtiLink"
        ):
            try:
                process_name = utility.array_to_string(thread.ppi.Process.ImageFileName)
                process_pid = thread.ppi.Process.UniqueProcessId
            except exceptions.InvalidAddressException:
                continue

            yield thread, process_name, process_pid


class_types = {
    "tagWINDOWSTATION": tagWINDOWSTATION,
    "tagDESKTOP": tagDESKTOP,
}
