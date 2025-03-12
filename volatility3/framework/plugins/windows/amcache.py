# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import warnings
from volatility3.plugins.windows.registry import amcache

vollog = logging.getLogger(__name__)


class Amcache(amcache.Amcache):
    """Extract information on executed applications from the AmCache (deprecated)."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    def __getattr__(self, *args, **kwargs):
        warnings.warn(
            DeprecationWarning(
                "This plugin is now called windows.registry.amcache.Amcache"
            )
        )
        return super().__getattr__(*args, **kwargs)
