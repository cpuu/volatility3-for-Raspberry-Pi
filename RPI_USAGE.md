# Raspberry Pi plugins

The eight plugins in [volatility3/framework/plugins/linux/rpi](volatility3/framework/plugins/linux/rpi) are bundled with this repository. No extra `-p` plugin directory or plugin download is required.

## Layout and command names

```text
volatility3/framework/plugins/linux/rpi/
├── __init__.py
├── common.py
├── rpi.py
├── model.py
├── boot.py
├── interfaces.py
├── console.py
├── gpio.py
├── firmware.py
└── dtchanges.py
```

`common.py` provides shared bounded DT traversal and interface decoding. Each analysis module defines its corresponding plugin. For example, `model.py` defines `Model`, discovered as `linux.rpi.model.Model`. These are the canonical bundled command names; the earlier standalone research commands such as `rpi.Model` are not installed as aliases.

## Run

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

Replace the paths with your capture and the symbol directory containing the **matching kernel ISF**. Use Python 3.12 and the repository's ARM64 support. Capture acquisition and symbol preparation are described in [README](README.md) and [TESTING](TESTING.md). Memory dumps are not bundled with the plugin code.

`linux.rpi.model.Model` is the compact starting point. `linux.rpi.rpi.Rpi` returns the full Device Tree and EEPROM configuration recovery diagnostics. The [catalog](RPI_PLUGINS.md) summarizes each plugin and its validation limits.

## Options

- `linux.rpi.interfaces.Interfaces --details`: full DT paths and compatible strings.
- `linux.rpi.console.Console --details`: resolved target path and firmware stdout source.
- `linux.rpi.firmware.Firmware --details`: full firmware version, UEFI table address and warning bytes.
- `linux.rpi.dtchanges.DtChanges --details`: full raw values and kernel virtual value addresses from both trees.
- `linux.rpi.dtchanges.DtChanges --include-generated`: show live-only `name` properties matching kernel synthesis. Can be combined with `--details`.
- The original seven plugins accept `--max-nodes`, `--max-properties` and `--max-value` traversal/read limits.
- `linux.rpi.rpi.Rpi --max-eeprom`: maximum EEPROM configuration region size. `--allow-generic` bypasses the Pi identity gate for research only.

Place global flags before the plugin name and plugin-specific options after it:

```sh
uv run --locked --extra full python vol.py -r json -s /path/to/symbols -f /path/to/memory.lime linux.rpi.firmware.Firmware --details
uv run --locked --extra full python vol.py linux.rpi.dtchanges.DtChanges -h
```

`linux.rpi.gpio.Gpio` uses separate bounds (`--max-chips`, `--max-lines`, `--max-string`) and supports `--all`, `--details`, `--chip gpiochipN`, and an explicit `--allow-generic` for non-Pi Linux simulator dumps. See [GPIO usage](RPI_GPIO.md).

## Interpretation

- These plugins recover kernel Device Tree data. Configuration does not prove physical attachment, electrical pin state or historical activity.
- `BoardManufacturer` means the board manufacturer encoded in its revision, not the SD-card vendor. Missing fields remain unavailable.
- Boot and console fields describe recorded settings or requests, not proof of successful device use.
- Firmware timestamps describe EEPROM build/update metadata, not the system boot time. UEFI metadata does not establish Secure Boot or firmware authenticity.
- EEPROM configuration recovery requires the relevant reserved memory to be present in the capture. None of the eight physical captures contains the configuration bytes; positive recovery is covered by a synthetic LiME test.
- DtChanges compares the retained `initial_boot_params` FDT with the live `of_root` tree. It requires both structures to be readable. Incomplete acquisition is not reported as “No changes.” Changes do not establish their time, actor or cause. The retained blob is not an immutable baseline, and changes shared by both trees may be invisible.
- All eight captures come from one Pi 4 Model B Rev 1.4. Other boards have not been physically validated. No substantive DT changes were found in these captures; positive change detection is tested synthetically.

## Tests and regression

Run the self-contained tests (no dumps required):

```sh
uv run --locked --extra full python -m unittest discover -s test/rpi -v
```

The original integration rerun exercises the first seven bundled plugins against all eight existing captures, **without `-p`**, and compares every JSON row with previously validated research output. This checks integration regressions; it is not a new independent ground-truth measurement.

The [regression script](development/rpi_regression.py) requires the original local research workspace, including `rpi-runs.json`, captures, symbols and baseline JSON files. Its manifest contains local paths; update those when relocating the data. Raw logs and actual commands are written to the chosen output directory.

```sh
uv run --locked --extra full python development/rpi_regression.py \
  --research /path/to/rpi-forensics-20261112 \
  --output /path/to/rpi-regression-results
```

On macOS, if your native dependencies require it, set `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` as in the validation environment. See [integration results](RPI_VALIDATION.md) for the recorded run and limitations.
