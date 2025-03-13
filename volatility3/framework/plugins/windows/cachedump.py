# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import warnings
from volatility3.plugins.windows.registry import cachedump

vollog = logging.getLogger(__name__)


class Cachedump(cachedump.Cachedump):
    """Dumps lsa secrets from memory (deprecated)"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 2)

    def __getattribute__(self, *args, **kwargs):
        warnings.warn(
            FutureWarning(
                "The windows.cachedump.Cachedump plugin is deprecated and will be removed on "
                "2025-09-25. Use windows.registry.cachedump.Cachedump instead."
            )
        )
        return super().__getattribute__(*args, **kwargs)
