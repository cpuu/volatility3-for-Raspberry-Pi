"""Packed framebuffer channels must map to PNG colors and respect row stride."""

from types import SimpleNamespace as NS
import pytest
from volatility3.plugins.linux.graphics.fbdev import Fbdev, Framebuffer

RGB565 = {"R": (11, 5, 0), "G": (5, 6, 0), "B": (0, 5, 0), "A": (0, 0, 0)}


def convert(raw, fields=RGB565, bpp=16, width=1, height=1, stride=None):
    stride = stride if stride is not None else width * (bpp // 8)

    def read(address, size):
        assert address == 0x1000 and size == len(raw)
        return raw

    context = NS(
        modules={"kernel": NS(layer_name="kernel")}, layers={"kernel": NS(read=read)}
    )
    fb = Framebuffer(
        "test", width, height, stride, bpp, len(raw), fields, NS(screen_base=0x1000)
    )
    return Fbdev.convert_fb_raw_buffer_to_image(context, "kernel", fb)


@pytest.mark.parametrize(
    "code,rgba",
    [
        (0, (0, 0, 0, 255)),
        (0xF800, (255, 0, 0, 255)),
        (0x07E0, (0, 255, 0, 255)),
        (0x001F, (0, 0, 255, 255)),
        (0xFFFF, (255, 255, 255, 255)),
        ((31 << 11) | (32 << 5) | 16, (255, 130, 132, 255)),
    ],
)
def test_rgb565_normalization(code, rgba):
    assert convert(code.to_bytes(2, "little")).getpixel((0, 0)) == rgba


def test_row_padding_is_not_treated_as_pixels():
    image = convert(bytes.fromhex("00f8ffff1f00ffff"), width=1, height=2, stride=4)
    assert list(image.getdata()) == [(255, 0, 0, 255), (0, 0, 255, 255)]


def test_eight_bit_rgba_is_unchanged():
    fields = {"R": (0, 8, 0), "G": (8, 8, 0), "B": (16, 8, 0), "A": (24, 8, 0)}
    assert convert(bytes([17, 128, 255, 64]), fields, 32).getpixel((0, 0)) == (
        17,
        128,
        255,
        64,
    )


def test_msb_right_reverses_before_scaling():
    fields = {**RGB565, "R": (11, 5, 1)}
    assert convert((1 << 11).to_bytes(2, "little"), fields).getpixel((0, 0)) == (
        132,
        0,
        0,
        255,
    )


def test_wider_channels_and_two_bit_alpha():
    fields = {"R": (0, 10, 0), "G": (10, 10, 0), "B": (20, 10, 0), "A": (30, 2, 0)}
    code = 1023 | (512 << 10) | (1 << 20) | (2 << 30)
    assert convert(code.to_bytes(4, "little"), fields, 32).getpixel((0, 0)) == (
        255,
        128,
        0,
        170,
    )


def test_rgb24_preserves_color_and_opaque_alpha():
    fields = {"R": (16, 8, 0), "G": (8, 8, 0), "B": (0, 8, 0), "A": (0, 0, 0)}
    assert convert(bytes([3, 2, 1]), fields, 24).getpixel((0, 0)) == (1, 2, 3, 255)
