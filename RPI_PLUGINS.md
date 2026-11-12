# Raspberry Pi Plugin Catalog

| Plugin | Version | Purpose |
| --- | --- | --- |
| [linux.rpi.rpi.Rpi](volatility3/framework/plugins/linux/rpi/rpi.py) | 0.2.0 | Full Device Tree properties, addresses, raw bytes, and EEPROM configuration recovery |
| [linux.rpi.model.Model](volatility3/framework/plugins/linux/rpi/model.py) | 1.0.0 | Board model, revision, serial number, RAM, board manufacturer, and SoC |
| [linux.rpi.boot.Boot](volatility3/framework/plugins/linux/rpi/boot.py) | 1.0.0 | Boot medium, partition, tryboot, OS path, and requested root filesystem |
| [linux.rpi.interfaces.Interfaces](volatility3/framework/plugins/linux/rpi/interfaces.py) | 1.0.0 | UART, I2C, SPI, and USB configuration and parent status |
| [linux.rpi.console.Console](volatility3/framework/plugins/linux/rpi/console.py) | 1.0.0 | Firmware stdout, controller, DT status, and requested kernel consoles |
| [linux.rpi.firmware.Firmware](volatility3/framework/plugins/linux/rpi/firmware.py) | 1.0.0 | EEPROM version/timestamps, U-Boot, UEFI metadata, and warnings |
| [linux.rpi.dtchanges.DtChanges](volatility3/framework/plugins/linux/rpi/dtchanges.py) | 1.0.0 | Node/property differences between retained FDT and live DT, with generated-name filtering |
| [linux.rpi.gpio.Gpio](volatility3/framework/plugins/linux/rpi/gpio.py) | 1.0.0 | GPIO consumers, request state, cached configuration and Pi 4 header mapping |

## Usage

All eight plugins are bundled with this repository; no extra `-p` plugin directory is required.

### Run

From a checkout of this repository:

```sh
uv sync --locked --extra full
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.model.Model
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.boot.Boot
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.interfaces.Interfaces
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.console.Console
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.firmware.Firmware
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.dtchanges.DtChanges
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.gpio.Gpio
uv run --locked --extra full python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.rpi.Rpi
```

Use Python 3.12 and replace the paths with your memory capture and **matching kernel ISF** directory. See [README](README.md) for acquisition and symbol preparation.

`linux.rpi.model.Model` is the compact starting point. `linux.rpi.rpi.Rpi` returns the full Device Tree and EEPROM configuration recovery diagnostics.

### Options

- `linux.rpi.interfaces.Interfaces --details`: full DT paths and compatible strings.
- `linux.rpi.console.Console --details`: resolved target path and firmware stdout source.
- `linux.rpi.firmware.Firmware --details`: full firmware version, UEFI table address and warning bytes.
- `linux.rpi.dtchanges.DtChanges --details`: full raw values and kernel virtual value addresses from both trees.
- `linux.rpi.dtchanges.DtChanges --include-generated`: show live-only `name` properties matching kernel synthesis. Can be combined with `--details`.
- All plugins except GPIO accept `--max-nodes`, `--max-properties` and `--max-value` traversal/read limits.
- `linux.rpi.rpi.Rpi --max-eeprom`: maximum EEPROM configuration region size. `--allow-generic` bypasses the Pi identity gate for research only.

Place global flags before the plugin name and plugin-specific options after it:

```sh
uv run --locked --extra full python vol.py -r json -s /path/to/symbols -f /path/to/memory.lime linux.rpi.firmware.Firmware --details
uv run --locked --extra full python vol.py linux.rpi.dtchanges.DtChanges -h
```

`linux.rpi.gpio.Gpio` uses separate bounds (`--max-chips`, `--max-lines`, `--max-string`) and supports `--all`, `--details`, `--chip gpiochipN`, and an explicit `--allow-generic` for non-Pi Linux simulator dumps. See [GPIO usage](RPI_GPIO.md).

### Interpretation

- These plugins recover kernel Device Tree and gpiolib data. Configuration does not prove physical attachment, electrical pin state or historical activity.
- `BoardManufacturer` means the board manufacturer encoded in its revision, not the SD-card vendor. Missing fields remain unavailable.
- Boot and console fields describe recorded settings or requests, not proof of successful device use.
- Firmware timestamps describe EEPROM build/update metadata, not the system boot time. UEFI metadata does not establish Secure Boot or firmware authenticity.
- EEPROM configuration recovery requires the relevant reserved memory to be present in the capture.
- DtChanges compares the retained `initial_boot_params` FDT with the live `of_root` tree. It requires both structures to be readable. Incomplete acquisition is not reported as “No changes.” Changes do not establish their time, actor or cause. The retained blob is not an immutable baseline, and changes shared by both trees may be invisible.
