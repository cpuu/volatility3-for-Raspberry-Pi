"""Missing optional fbdev class devices must not suppress framebuffer output."""

from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest
from volatility3.framework import exceptions, renderers
from volatility3.plugins.linux.graphics import fbdev


@pytest.mark.parametrize("device_state", ["absent", "present", "unreadable"])
def test_framebuffer_output_with_optional_class_device(monkeypatch, device_state):
    info = NS(screen_base=0x1000, state=0, has_member=lambda n: n == "dev" and device_state != "absent")
    if device_state != "absent":
        info.dev = NS(kobj=NS(name=0x2000))
    # A parent device exists independently; its name must never be substituted.
    info.device = NS(kobj=NS(name=0x3000))
    frame = fbdev.Framebuffer("vc4drmfb", 2, 1, 4, 16, 4, {"R": (11, 5, 0)}, info)
    kernel = NS(has_symbol=lambda n: True, symbol_table_name="linux",
                object_from_symbol=lambda n: 1 if n == "num_registered_fb" else object())
    dump = Mock(return_value="frame.png")
    plugin = NS(config={"kernel": "kernel", "dump": True},
                context=NS(modules={"kernel": kernel}), open=object(),
                parse_fb_info=lambda obj: frame, dump_fb=dump)
    monkeypatch.setattr(fbdev, "has_pil", True)
    monkeypatch.setattr(fbdev.utility, "array_of_pointers", lambda *args: [info])
    name = Mock(return_value="fb0")
    if device_state == "unreadable":
        name.side_effect = exceptions.InvalidAddressException("kernel", 0x2000)
    monkeypatch.setattr(fbdev.utility, "pointer_to_string", name)

    rows = list(fbdev.Fbdev._generator(plugin))
    assert len(rows) == 1
    level, values = rows[0]
    assert level == 0
    assert tuple(values[2:]) == ("vc4drmfb", 4, "2x1", 16, "RUNNING", "frame.png")
    dump.assert_called_once_with(plugin.context, "kernel", plugin.open, frame, True)
    if device_state == "present":
        assert values[1] == "fb0"
    else:
        assert isinstance(values[1], renderers.NotAvailableValue)
    if device_state == "absent":
        name.assert_not_called()
    else:
        name.assert_called_once_with(0x2000, 256)
