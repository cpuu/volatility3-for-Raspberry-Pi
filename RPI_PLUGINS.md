# Raspberry Pi Plugin Registry

Updated: 2026-11-12 · [Source](volatility3/framework/plugins/linux/rpi) · [Usage](RPI_USAGE.md) · [Integration results](RPI_VALIDATION.md)

All seven plugins were run against eight OS/kernel dumps from the same Raspberry Pi 4 Model B Rev 1.4. Latest test suite: **78 tests passed**. This does not establish support for other boards.

| Plugin | Version | Purpose | Validation / Limitations |
|---|---|---|---|
| `linux.rpi.rpi.Rpi` | 0.2.0 | Full Device Tree properties, addresses, raw bytes, and EEPROM configuration recovery | DT recovery validated on 8/8 dumps. EEPROM configuration absent from all captures; recovery tested with synthetic LiME input. |
| `linux.rpi.model.Model` | 1.0.0 | Board model, revision, serial number, RAM, board manufacturer, and SoC | 8/8 validated. Missing Fedora revision/RAM/manufacturer reported as unavailable. |
| `linux.rpi.boot.Boot` | 1.0.0 | Boot medium, partition, tryboot, OS path, and requested root filesystem | 8/8 validated; five key fields cross-checked against retained FDT data. |
| `linux.rpi.interfaces.Interfaces` | 1.0.0 | UART, I2C, SPI, and USB configuration and parent status | 8/8 validated; 1,188 fields matched retained FDT data. |
| `linux.rpi.console.Console` | 1.0.0 | Firmware stdout, controller, DT status, and requested kernel consoles | 8/8 validated; 64 fields matched retained FDT data. |
| `linux.rpi.firmware.Firmware` | 1.0.0 | EEPROM version/timestamps, U-Boot, UEFI metadata, and warnings | 8/8 validated; 72 fields matched retained FDT data. |
| `linux.rpi.dtchanges.DtChanges` | 1.0.0 | Node/property differences between retained FDT and live DT, with generated-name filtering | 8/8 validated; no substantive differences found. Change detection and malformed input tested synthetically. |

All seven plugins are bundled with this repository and load without an external plugin path. Usage instructions, self-contained tests and the integration validation summary are included; memory dumps and full research artifacts remain in the separate research workspace.
