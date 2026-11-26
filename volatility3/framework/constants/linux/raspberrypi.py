"""Device Tree compatible bindings shared by Raspberry Pi plugins."""

INTERFACE_BINDINGS = {
    "arm,pl011-axi": ("UART", "PL011 AXI UART"),
    "arm,pl011": ("UART", "PL011 UART"),
    "brcm,bcm2835-aux-uart": ("UART", "BCM2835 mini UART"),
    "brcm,bcm2711-i2c": ("I2C", "BCM2711 I2C"),
    "brcm,bcm2835-i2c": ("I2C", "BCM2835 I2C"),
    "brcm,bcm2711-hdmi-i2c": ("I2C", "BCM2711 HDMI I2C"),
    "brcm,bcm2835-spi": ("SPI", "BCM2835 SPI"),
    "brcm,bcm2835-aux-spi": ("SPI", "BCM2835 auxiliary SPI"),
    "brcm,bcm2708-usb": ("USB", "BCM2708 USB"),
    "brcm,bcm2835-usb": ("USB", "BCM2835 USB"),
    "brcm,bcm2711-xhci": ("USB", "BCM2711 xHCI"),
    "brcm,xhci-brcm-v2": ("USB", "Broadcom xHCI"),
    "generic-xhci": ("USB", "xHCI"),
}
