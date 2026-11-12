# Raspberry Pi Plugin Registry

Updated: 2026-11-12

All seven plugins were run against eight OS/kernel dumps from the same Raspberry Pi 4 Model B Rev 1.4. Latest test suite: **78 tests passed**. This does not establish support for other boards.

| Plugin | Version | Purpose | Validation / Limitations |
|---|---|---|---|
| `rpi.Rpi` | 0.2.0 | Full Device Tree properties, addresses, raw bytes, and EEPROM configuration recovery | DT recovery validated on 8/8 dumps. EEPROM configuration absent from all captures; recovery tested with synthetic LiME input. |
| `rpi.Model` | 1.0.0 | Board model, revision, serial number, RAM, board manufacturer, and SoC | 8/8 validated. Missing Fedora revision/RAM/manufacturer reported as unavailable. |
| `rpi.Boot` | 1.0.0 | Boot medium, partition, tryboot, OS path, and requested root filesystem | 8/8 validated; five key fields cross-checked against retained FDT data. |
| `rpi.Interfaces` | 1.0.0 | UART, I2C, SPI, and USB configuration and parent status | 8/8 validated; 1,188 fields matched retained FDT data. |
| `rpi.Console` | 1.0.0 | Firmware stdout, controller, DT status, and requested kernel consoles | 8/8 validated; 64 fields matched retained FDT data. |
| `rpi.Firmware` | 1.0.0 | EEPROM version/timestamps, U-Boot, UEFI metadata, and warnings | 8/8 validated; 72 fields matched retained FDT data. |
| `rpi.DtChanges` | 1.0.0 | Node/property differences between retained FDT and live DT, with generated-name filtering | 8/8 validated; no substantive differences found. Change detection and malformed input tested synthetically. |

Implementation code, detailed documentation, and validation artifacts are currently maintained in the separate research workspace; they are not yet included in this repository.
