# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import warnings
from volatility3.plugins.windows.registry import lsadump

vollog = logging.getLogger(__name__)


class Lsadump(lsadump.Lsadump):
    """Dumps lsa secrets from memory (deprecated)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 1)

    def __getattr__(self, *args, **kwargs):
        warnings.warn(
            DeprecationWarning(
                "This plugin is now called windows.registry.lsadump.Lsadump"
            )
        )
        return super().__getattr__(*args, **kwargs)
