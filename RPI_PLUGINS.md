# Raspberry Pi Plugin Catalog

[Source](volatility3/framework/plugins/linux/rpi) · [Usage](RPI_USAGE.md)

| Plugin | Version | Purpose |
| --- | --- | --- |
| `linux.rpi.rpi.Rpi` | 0.2.0 | Full Device Tree properties, addresses, raw bytes, and EEPROM configuration recovery |
| `linux.rpi.model.Model` | 1.0.0 | Board model, revision, serial number, RAM, board manufacturer, and SoC |
| `linux.rpi.boot.Boot` | 1.0.0 | Boot medium, partition, tryboot, OS path, and requested root filesystem |
| `linux.rpi.interfaces.Interfaces` | 1.0.0 | UART, I2C, SPI, and USB configuration and parent status |
| `linux.rpi.console.Console` | 1.0.0 | Firmware stdout, controller, DT status, and requested kernel consoles |
| `linux.rpi.firmware.Firmware` | 1.0.0 | EEPROM version/timestamps, U-Boot, UEFI metadata, and warnings |
| `linux.rpi.dtchanges.DtChanges` | 1.0.0 | Node/property differences between retained FDT and live DT, with generated-name filtering |
| `linux.rpi.gpio.Gpio` | 1.0.0 | GPIO consumers, request state, cached configuration and Pi 4 header mapping |

All eight plugins are bundled with this repository and load without an external plugin path.
