# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import warnings
from volatility3.plugins.windows.registry import hashdump

vollog = logging.getLogger(__name__)


class Hashdump(hashdump.Hashdump):
    """Dumps user hashes from memory (deprecated)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 1)

    def __getattribute__(self, *args, **kwargs):
        warnings.warn(
            FutureWarning(
                "The windows.hashdump.Hashdump plugin is deprecated and will be removed on "
                "2025-09-25. Use windows.registry.hashdump.Hashdump instead."
            )
        )
        return super().__getattribute__(*args, **kwargs)
