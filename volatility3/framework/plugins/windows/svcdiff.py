# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.malware import svcdiff

vollog = logging.getLogger(__name__)


class SvcDiff(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=svcdiff.SvcDiff,
    removal_date="2026-06-07",
):
    """Compares services found through list walking versus scanning to find rootkits (deprecated)."""

    _required_framework_version = (2, 4, 0)

    _version = (2, 0, 0)
