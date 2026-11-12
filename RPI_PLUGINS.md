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

These eight plugins were developed in this repository to recover Raspberry Pi identity, boot configuration, peripheral settings and GPIO ownership from memory captures. Start with Model for a board summary, then choose the plugin for the information you need.

## Getting started

From the repository root, prepare Python 3.12 and the optional dependencies:

```sh
uv sync --python 3.12 --extra full
```

Use a memory capture and its matching kernel ISF in `symbols/linux`; no extra `-p` plugin directory is needed. Replace `/path/to/memory.lime` in the examples with your capture. See [README](README.md#memory-acquisition) for acquisition and [ISF generation](README.md#isf-generation) for symbols.

All output examples below come from actual executions on the same Raspberry Pi 4 Model B capture running Ubuntu 24.04.5 LTS with kernel `7.0.0-1023-raspi`. Selected rows or columns are shown where the full output is long; `...` marks omitted content. Values are preserved from the command output, with spacing adjusted for readability.

### Shared options

Rpi, Model, Boot, Interfaces, Console, Firmware and DtChanges share these Device Tree traversal options:

| Option | Default | Purpose |
| --- | ---: | --- |
| `--max-nodes` | 16384 | Maximum live Device Tree nodes to visit |
| `--max-properties` | 1024 | Maximum properties to read per node |
| `--max-value` | 65536 | Maximum bytes to read per property |

GPIO has its own bounds, listed in its section. Global flags such as `-s`, `-f` and `-r json` go before the plugin name; plugin options go after it. Add `-h` after any plugin name to display its help.

## 1. Rpi — full Device Tree and EEPROM configuration

`linux.rpi.rpi.Rpi` provides the detailed view behind the focused summaries. It walks the live Device Tree and groups properties such as board identity, boot settings and peripheral configuration. Each record includes its path, decoded value, raw bytes and memory addresses, so a finding can be traced back to its source in the capture.

It also follows the Device Tree reference to the EEPROM bootloader configuration in reserved memory and extracts the configuration text when that region is present. `AddressSpace` distinguishes physical EEPROM data from kernel-virtual Device Tree data.

**Options:**

- Shared Device Tree bounds above.
- `--max-eeprom BYTES`: maximum EEPROM configuration region to read; default `65536`.
- `--allow-generic`: inspect a non-Pi Device Tree using the same property reader.

**Example — selected board and boot properties:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.rpi.Rpi

Category            Path                Property        Value                           Status  ...
...
board-identity      /                   serial-number   1000000015089641                ok      ...
...
board-identity      /                   model           Raspberry Pi 4 Model B Rev 1.4  ok      ...
...
board-identity      /system             linux,revision  0xd03114                        ok      ...
...
boot-configuration  /chosen             os_prefix       volab-7.0.0-1023-raspi/         ok      ...
...
boot-configuration  /chosen/bootloader  boot-mode       0x1: SD/eMMC                    ok      ...
...
boot-configuration  /chosen/bootloader  tryboot         1: set at boot                  ok      ...
...
boot-configuration  /chosen/bootloader  partition       1 (0x1)                         ok      ...
...
```

Here the raw revision is `0xd03114`, the boot mode decodes to SD/eMMC, and the firmware records partition 1 with tryboot set. Model and Boot turn these properties into compact summaries.

## 2. Model — board identity and revision decoding

`linux.rpi.model.Model` reports the board name, compatible model identifier, board revision, serial number and revision code in one row. It decodes the revision code into RAM capacity, board manufacturer and SoC instead of leaving those fields as a hexadecimal number.

`BoardManufacturer` identifies the Raspberry Pi board manufacturer encoded in the revision code. `Revision` is the board revision, while `RevisionCode` preserves the complete code used for decoding.

**Options:** shared Device Tree bounds; the default output already includes all identity fields.

**Example — complete result:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.model.Model

Board                   Model                  Revision  Serial            RevisionCode  RAM   BoardManufacturer  SoC      Status
Raspberry Pi 4 Model B  raspberrypi,4-model-b  1.4       1000000015089641  0x00d03114    8 GB  Sony UK            BCM2711  ok
```

This capture identifies a Raspberry Pi 4 Model B revision 1.4 with 8 GB RAM, manufactured by Sony UK, using the BCM2711 SoC.

## 3. Boot — boot source and selected OS

`linux.rpi.boot.Boot` summarizes the firmware boot medium, boot partition, tryboot flag and OS prefix, together with the `root=` value from the kernel command line. It is useful for distinguishing SD/eMMC, USB, network and other boot modes and identifying the OS path selected at boot.

`OSPrefix` is the firmware's OS directory prefix. `RootFilesystem` is the requested root device, label or identifier recorded in `root=`.

**Options:** shared Device Tree bounds; no additional output switch is needed for the summary.

**Example — complete result:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.boot.Boot

BootMedia  Partition  TryBoot  OSPrefix                 RootFilesystem  Status
SD/eMMC    1          Yes      volab-7.0.0-1023-raspi/  LABEL=writable  ok
```

The firmware selected SD/eMMC partition 1 with tryboot enabled and the `volab-7.0.0-1023-raspi/` OS prefix; the kernel requested `LABEL=writable` as its root filesystem.

## 4. Interfaces — UART, I2C, SPI and USB settings

`linux.rpi.interfaces.Interfaces` collects peripheral controllers and their Device Tree aliases into a single list. It shows the controller type, local `DTStatus`, inherited `ParentStatus` and USB mode. Comparing both status columns makes it easy to spot a locally enabled child below a disabled parent.

**Options:**

- `--details`: add the full Device Tree `Path` and `Compatible` strings.
- Shared Device Tree bounds.

**Example — selected controllers and columns from detailed output:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.interfaces.Interfaces --details

Interface  Type  Controller             DTStatus         ParentStatus            USBMode  Status  ...
i2c0       I2C   Not specified (alias)  okay (implicit)  disabled: /soc/i2c0mux  -        ok      ...
...
i2c, i2c1  I2C   BCM2711 I2C            okay             okay                    -        ok      ...
...
spi0       SPI   BCM2835 SPI            okay             okay                    -        ok      ...
...
serial0    UART  BCM2835 mini UART      okay             okay                    -        ok      ...
...
usb        USB   BCM2835 USB            okay             okay                    otg      ok      ...
```

The `i2c0` child has an implicit local status but a disabled parent mux. The I2C1, SPI0 and serial0 controllers are enabled in the tree, and the USB controller records `otg` mode. Use `--details` without excerpting the output to see each node's exact path and compatibility identifiers.

## 5. Console — firmware output and kernel consoles

`linux.rpi.console.Console` resolves the firmware's `stdout-path`, including aliases such as `serial0`, to its controller. It then places that firmware route alongside the kernel's `console=` requests, making serial settings and multiple console destinations easy to compare.

**Options:**

- `--details`: add the resolved Device Tree `Path` and the `StdoutSource` property.
- Shared Device Tree bounds.

**Example — complete detailed result:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.console.Console --details

FirmwareOutput    Controller         DTStatus  ParentStatus  KernelConsoles       Status  Path                  StdoutSource
serial0:115200n8  BCM2835 mini UART  okay      okay          ttyS0,115200 | tty1  ok      /soc/serial@7e215040  /chosen/stdout-path
```

The firmware routes output through `serial0:115200n8`, resolved to the BCM2835 mini UART. The kernel command line requests `ttyS0,115200` and `tty1`.

## 6. Firmware — EEPROM version and timestamps

`linux.rpi.firmware.Firmware` summarizes the EEPROM bootloader version and converts build/update timestamps to UTC. It also presents recorded U-Boot version information, UEFI metadata and firmware warnings in dedicated columns.

The timestamps describe the EEPROM firmware's build and update metadata. The version string can be used to correlate the capture with a particular bootloader revision.

**Options:**

- `--details`: show the full version string, UEFI system-table address and raw warning bytes.
- Shared Device Tree bounds.

**Example — selected EEPROM fields from detailed output:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.firmware.Firmware --details

BootloaderVersion                         EEPROMBuildUTC        EEPROMUpdateUTC       Status  ...
69471177ba7e4cb7597cb2496f2a0b23f19c1113  2025-05-08 15:21:35Z  2025-09-09 08:38:40Z  ok      ...
```

The capture records an EEPROM build on 2025-05-08 and an update on 2025-09-09. The full bootloader version is retained above for comparison with other captures.

## 7. DtChanges — boot-time and live Device Tree differences

`linux.rpi.dtchanges.DtChanges` compares the retained boot-time FDT (`initial_boot_params`) with the live kernel tree (`of_root`). It reports added or removed nodes and properties, changed values, and the corresponding boot/live values. Generated live-tree `name` properties are filtered by default to keep the comparison focused.

**Options:**

- `--details`: add boot/live value addresses and raw hexadecimal bytes.
- `--include-generated`: include the kernel-generated `name` properties.
- Shared Device Tree bounds.

**Example — complete default result:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.dtchanges.DtChanges

Change      Path  Property  BootValue  LiveValue  Status
No changes                                        boot=1790; live=2120; unchanged=1790; generated-name=330
```

This capture has 1,790 unchanged properties and 330 generated name properties, with no other differences reported. To inspect the generated entries as well:

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.dtchanges.DtChanges --include-generated

Change         Path      Property  BootValue  LiveValue  Status
...
GeneratedName  /         name      (absent)   hex:00     ok
...
GeneratedName  /aliases  name      (absent)   'aliases'  ok
...
GeneratedName  /chosen   name      (absent)   'chosen'   ok
...
```

The `GeneratedName` rows identify the live-tree names included by this option; `BootValue` and `LiveValue` show the two sides directly.

## 8. Gpio — line consumers and cached configuration

`linux.rpi.gpio.Gpio` reads the kernel's gpiolib devices and descriptors to recover GPIO line names, consumer labels, request state, direction and ActiveLow configuration. For a confirmed Pi 4 Model B BCM2711 controller, it also maps GPIO offsets to physical header pin numbers.

The default output focuses on requested lines and diagnostics. `--all` adds unrequested lines, and `--chip` selects one controller. Chip identifiers come from the capture; offsets are local to each controller.

| Option | Purpose |
| --- | --- |
| `--all` | Include unrequested lines |
| `--details` | Add raw flags, decoded flag names, descriptor addresses and label layout |
| `--chip gpiochipN` | Select an exact controller identifier |
| `--allow-generic` | Analyze a non-Pi Linux GPIO capture, including gpio-sim |
| `--max-chips` | Maximum devices to visit; default `64` |
| `--max-lines` | Maximum lines per device; default `4096` |
| `--max-string` | Maximum bytes per label; default `256` |

**Example — three selected lines and columns from detailed output:**

```console
$ uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.gpio.Gpio --all --details

Chip       Offset  HeaderPin  LineName          Consumer  Requested  KernelDirection  ActiveLow      Flags                          ...
gpiochip0  0       27         ID_SDA            (none)    No         Not requested    Not requested  (none)                         ...
...
gpiochip0  7       26         GPIO7             spi0 CS1  Yes        Output           Yes            requested, output, active-low  ...
...
gpiochip0  42      -          STATUS_LED_G_CLK  ACT       Yes        Output           No             requested, output              ...
...
```

GPIO7 is requested by `spi0 CS1` as an active-low output and maps to header pin 26. Offset 42 is assigned to the `ACT` consumer, while offset 0 has no active gpiolib request. `Consumer` is the kernel's label; direction and polarity describe cached kernel configuration. Free lines display `Not requested` rather than reusing a stale configuration as current state.

To focus on a controller and retain the full detailed output, use:

```sh
uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.gpio.Gpio --chip gpiochip0 --all --details
```
