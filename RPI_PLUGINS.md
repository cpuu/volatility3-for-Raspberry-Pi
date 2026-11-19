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

These eight distinct plugins add to the original 49 Linux plugins, bringing the Linux total to 57 implementations; compatibility aliases are counted separately in [TESTING.md](TESTING.md#coverage). They were developed in this repository to recover Raspberry Pi identity, boot configuration, peripheral settings and GPIO ownership from memory captures. Start with Model for a board summary, then choose the plugin for the information you need.

## Getting started

From the repository root, prepare Python 3.12 and the optional dependencies:

```sh
uv sync --python 3.12 --extra full
```

Use a memory capture and its matching kernel ISF in `symbols/linux`; no extra `-p` plugin directory is needed. See [README](README.md#memory-acquisition) for acquisition and [ISF generation](README.md#isf-generation) for symbols. Set `DUMP` to your local copy of the representative capture:

```sh
DUMP=/absolute/path/to/pi4-demo-candidate-20261119/retry/capture/memory.lime
vol() { uv run --extra full python vol.py -s symbols -f "$DUMP" "$@"; }
```

All output examples below come from actual executions on the **2026-11-19 Ubuntu 26.04.1 LTS / `7.0.0-1023-raspi` representative capture**, using analysis commit `26cee65355d4ad441603969d34428786700553db`. See [sample metadata](DUMP_SAMPLES.md#representative-gpio-and-linux-forensic-demo) for the dump checksum, Build ID and matching ISF. The [representative demo walkthrough](#representative-demo) connects the GPIO rows with general Linux artifacts. Selected rows or columns are shown where the full output is long; `...` marks omitted content. Values are preserved from the command output, with spacing adjusted for readability.

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
$ vol linux.rpi.rpi.Rpi

Category            Path                Property        Value                           Status  ...
...
board-identity      /                   serial-number   1000000015089641                ok      ...
...
board-identity      /                   model           Raspberry Pi 4 Model B Rev 1.4  ok      ...
...
board-identity      /system             linux,revision  0xd03114                        ok      ...
...
boot-configuration  /chosen             os_prefix       current/         ok      ...
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
$ vol linux.rpi.model.Model

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
$ vol linux.rpi.boot.Boot

BootMedia  Partition  TryBoot  OSPrefix  RootFilesystem  Status
SD/eMMC    1          Yes      current/  LABEL=writable  ok
```

The firmware selected SD/eMMC partition 1 with tryboot enabled and the `current/` OS prefix; the kernel requested `LABEL=writable` as its root filesystem.

## 4. Interfaces — UART, I2C, SPI and USB settings

`linux.rpi.interfaces.Interfaces` collects peripheral controllers and their Device Tree aliases into a single list. It shows the controller type, local `DTStatus`, inherited `ParentStatus` and USB mode. Comparing both status columns makes it easy to spot a locally enabled child below a disabled parent.

**Options:**

- `--details`: add the full Device Tree `Path` and `Compatible` strings.
- Shared Device Tree bounds.

**Example — selected controllers and columns from detailed output:**

```console
$ vol linux.rpi.interfaces.Interfaces --details

Interface  Type  Controller             DTStatus         ParentStatus            USBMode  Status  ...
i2c0       I2C   Not specified (alias)  okay (implicit)  disabled: /soc/i2c0mux  -        ok      ...
...
i2c, i2c1  I2C   BCM2711 I2C            okay             okay                    -        ok      ...
...
spi0       SPI   BCM2835 SPI            okay             okay                    -        ok      ...
...
serial0    UART  BCM2835 mini UART      disabled         okay                    -        ok      ...
...
usb        USB   BCM2835 USB            okay             okay                    otg      ok      ...
```

The `i2c0` child has an implicit local status but a disabled parent mux. I2C1 and SPI0 are enabled, serial0 is disabled, and the USB controller records `otg` mode. Use `--details` without excerpting the output to see each node's exact path and compatibility identifiers.

## 5. Console — firmware output and kernel consoles

`linux.rpi.console.Console` resolves the firmware's `stdout-path`, including aliases such as `serial0`, to its controller. It then places that firmware route alongside the kernel's `console=` requests, making serial settings and multiple console destinations easy to compare.

**Options:**

- `--details`: add the resolved Device Tree `Path` and the `StdoutSource` property.
- Shared Device Tree bounds.

**Example — complete detailed result:**

```console
$ vol linux.rpi.console.Console --details

FirmwareOutput    Controller         DTStatus  ParentStatus  KernelConsoles  Status                           Path                  StdoutSource
serial0:115200n8  BCM2835 mini UART  disabled  okay          tty1            stdout target unavailable in DT  /soc/serial@7e215040  /chosen/stdout-path
```

The firmware records `serial0:115200n8`, but its resolved mini UART is disabled in the Device Tree. The plugin therefore reports `stdout target unavailable in DT`; the kernel requests only `tty1`. This is a captured configuration mismatch, not a successful serial-console availability check.

## 6. Firmware — EEPROM version and timestamps

`linux.rpi.firmware.Firmware` summarizes the EEPROM bootloader version and converts build/update timestamps to UTC. It also presents recorded U-Boot version information, UEFI metadata and firmware warnings in dedicated columns.

The timestamps describe the EEPROM firmware's build and update metadata. The version string can be used to correlate the capture with a particular bootloader revision.

**Options:**

- `--details`: show the full version string, UEFI system-table address and raw warning bytes.
- Shared Device Tree bounds.

**Example — selected EEPROM fields from detailed output:**

```console
$ vol linux.rpi.firmware.Firmware --details

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
$ vol linux.rpi.dtchanges.DtChanges

Change      Path  Property  BootValue  LiveValue  Status
No changes                                        boot=1794; live=2125; unchanged=1794; generated-name=331
```

This capture has 1,794 unchanged properties and 331 generated name properties, with no other differences reported. To inspect the generated entries as well:

```console
$ vol linux.rpi.dtchanges.DtChanges --include-generated

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

**Example — the controlled gpio-sim fixture:**

```sh
vol linux.rpi.gpio.Gpio
vol linux.rpi.gpio.Gpio --all --details
```

For controller `volab-userspace-20261112` (`gpiochip2`), the default output contains **six requested lines** (0, 1, 2, 3, 5, 7); the detailed output contains **all eight lines**. Other controllers are also present in the full output. The selected controller's rows are shown below with columns omitted for readability; all eight have `Status=ok` and `ConsumerLayout=rcu-label`.

| Offset | LineName | Consumer | Requested | KernelDirection | ActiveLow | RawFlags |
|---|---|---|---|---|---|---|
| 0 | VOLAB_USER_0 | volab-user-0 | Yes | Output | Yes | 0x43 |
| 1 | VOLAB_USER_1 | volab-user-1 | Yes | Input | Yes | 0x41 |
| 2 | VOLAB_USER_2 | volab-user-2 | Yes | Input | No | 0x1 |
| 3 | VOLAB_USER_3 | volab-user-3 | Yes | Output | No | 0x3 |
| 4 | VOLAB_USER_4 | (none) | No | Not requested | Not requested | 0x2 |
| 5 | VOLAB_USER_5 | volab-user-5 | Yes | Input | No | 0x1 |
| 6 | VOLAB_USER_6 | (none) | No | Not requested | Not requested | 0x0 |
| 7 | VOLAB_USER_7 | volab-user-hog | Yes | Output | No | 0x803 |

The capture's `before.json` and `after.json` agree on the controller, line names, consumers and request states. All six requested lines also agree on direction and ActiveLow. The live API retains Output/false at unrequested offset 4 and Input/false at offset 6; the plugin deliberately reports `Not requested` for these fields instead of implying an active request. These are **gpio-sim kernel records, not physical header voltage measurements**.

To select only this controller while retaining all detailed columns:

```sh
vol linux.rpi.gpio.Gpio --chip gpiochip2 --all --details
```

Consumer labels identify kernel registrations, not an owning PID by themselves. The following controlled scenario corroborates the helper process independently.

## Representative demo

Use the `DUMP` and `vol` helper defined in [Getting started](#getting-started). Start with Model for board identity and [Gpio](#8-gpio--line-consumers-and-cached-configuration) for the eight-line comparison. The same capture then supports the process → socket → open file → recovered content walkthrough below. Offsets 4 and 6 remain unrequested; all six requested-line configurations match the capture-time reference.

### Linux processes and connections

```sh
vol linux.pslist.PsList
vol linux.pstree.PsTree
vol linux.psaux.PsAux
vol linux.sockstat.Sockstat
```

PsList, PsTree and PsAux each returned **229 processes**. The controlled process chain and command arguments matched the live reference:

```text
sudo 5867
└── python3 5905  python3 pi_demo.py capture /var/tmp/pi-demo-capture-pinned-20261119
    ├── gpio-user 5920  /var/tmp/pi4-contest-demo-pinned-20261119/gpio-user /dev/gpiochip2
    └── avml 5922       /var/tmp/pi4-contest-demo-pinned-20261119/avml acquire --source /proc/kcore /var/tmp/pi-demo-capture-pinned-20261119/memory.lime.partial
```

Sockstat matched the Python process's live PID, FD, addresses, ports and states before and after capture:

| PID | FD | Source | Destination | State |
|---|---|---|---|---|
| 5905 | 8 | 127.0.0.1:48791 | 0.0.0.0:0 | LISTEN |
| 5905 | 9 | 127.0.0.1:51386 | 127.0.0.1:48791 | ESTABLISHED |
| 5905 | 10 | 127.0.0.1:48791 | 127.0.0.1:51386 | ESTABLISHED |

As a separate ordinary Linux service example, `sshd` PID 1574 owns IPv4/IPv6 port 22 listeners at FD 3/4, shared with `systemd` PID 1 at FD 102/103. Sockstat's 2,574 rows include thread/FD duplication and are not a count of unique connections.

Live `ps` listed 233 processes; 228 PIDs were shared with the dump and every shared PPID matched. Acquisition is not atomic, so transient process differences remain. PID 1 arguments were blank and sshd arguments truncated; this demo does not claim complete recovery of every process's arguments.

### Open file and content recovery

```sh
FILE=/var/tmp/pi-demo-capture-pinned-20261119/station-status.txt
vol linux.lsof.Lsof --pid 5905
vol linux.proc.Maps --pid 5905
```

Lsof identifies the marker at **PID 5905, FD 4, device 179:2, inode 411295, size 39 bytes** (the mapping also retains a descriptor). Maps identifies the same file and inode at offset zero in VMA `0xffffa930e000–0xffffa930f000`. Recover that specific 4 KiB mapping:

```sh
mkdir -p demo-recovery
vol -o demo-recovery linux.proc.Maps --pid 5905 --address 0xffffa930e000 --dump
# Use the 39-byte size observed in Lsof, not the full page length.
head -c 39 demo-recovery/pid.5905.vma.0xffffa930e000-0xffffa930f000.dmp > demo-recovery/station-status.recovered.txt
shasum -a 256 demo-recovery/station-status.recovered.txt
```

Observed SHA-256, matching the original in both capture-time JSON records:

```text
4aecf752c1098b10e5db0a7e804867aa2ab5fd8e5ac427c761ca8da487d7b49c
```

The 4 KiB raw VMA dump is retained alongside the 39-byte derived file. This fixture holds a private file mapping with `mlock`; **successful content recovery here uses `linux.proc.Maps`**. `linux.pagecache.Files` reported `CachedPages=0`, and `linux.pagecache.InodePages --find "$FILE" --dump` did not recover content. Do not treat that command's zero exit code as a successful recovery. The cause of the unavailable page-cache content was not established.

The capture and evidence remain local; listing the checksum does not publish the memory image. The Pi was left running 1023, with its original 1017 normal-boot configuration preserved and the temporary GPIO controller cleaned up.
