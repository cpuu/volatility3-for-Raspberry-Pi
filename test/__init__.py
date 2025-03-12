from enum import Enum
from pathlib import Path

TESTS_ROOT_DIR = Path(__file__).parent
WINDOWS_TESTS_DATA_DIR = TESTS_ROOT_DIR / "plugins" / "windows" / "test_data"


class Sample:
    def __init__(self, path: str):
        self.path = path


class WindowsSamples(Enum):
    WINDOWSXP_GENERIC = Sample("./test_images/win-xp-laptop-2005-06-25.img")
    """WindowsXP sample from early Volatility training."""


class LinuxSamples(Enum):
    LINUX_GENERIC = Sample("./test_images/linux-sample-1.bin")
    """Linux Debian 3.2.0-4 sample from early Volatility training."""
