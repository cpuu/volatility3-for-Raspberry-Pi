# volatility3 for Raspberry Pi

Raspberry Pi / AArch64 Linux memory analysis, maintained independently by [cpuu](https://github.com/cpuu), based on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and [Abyss-W4tcher's AArch64 implementation (#1088)](https://github.com/volatilityfoundation/volatility3/pull/1088).

My contributions in this repository include (see [contribution details](CONTRIBUTIONS.md) for inherited work and contribution scope):

- **Integration and broader plugin support:** updated the original AArch64 implementation for newer Volatility 3 code, enabled 23 Linux plugins through architecture declarations, and made plugin or shared-core fixes for 16 others; nine existing plugins needed no additional changes.
- **Bug fixes:** corrected Bash history scanning, PsScan PID limits, kernel-thread attribution, kallsyms decoding, syscall-table analysis, socket scanning and framebuffer rendering.
- **ARM64 analysis enhancements:** added ARM64 kernel-stack traversal and sparse-memory page-address handling, and improved reconstruction of resident kernel modules as analysis ELF files.
- **New Raspberry Pi-specific plugins:** developed eight plugins for board identification, boot configuration, interfaces, console settings, firmware metadata, GPIO consumer labels and cached configuration, and Device Tree analysis; see the [plugin catalog](RPI_PLUGINS.md).
- **Hardware validation:** tested 48 applicable Linux plugins on physical Raspberry Pi 4 captures across Ubuntu 24.04/26.04, Raspberry Pi OS, Kali Linux and Fedora, using capture-time references, controlled fixtures and regression runs.
- **Reproducible samples and symbols:** generated and verified matching kernel ISFs, published them as compressed `.json.xz` files, and documented acquisition steps and sample checksums.

## Basis

- Upstream `develop`: [77ff0b1932d77527f850c8ced01d85805ea7bf97](https://github.com/volatilityfoundation/volatility3/commit/77ff0b1932d77527f850c8ced01d85805ea7bf97) (2026-11-06), including development changes after the official [v2.28.2 release](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2).
- Original AArch64 implementation: [5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4](https://github.com/Abyss-W4tcher/volatility3/commit/5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4) (2024-10-20).

## Quick start

Use Python 3.12 and [uv](https://docs.astral.sh/uv/). Collect memory on the Pi and analyze it on the Mac or another host.

```sh
git clone https://github.com/cpuu/volatility3-for-Raspberry-Pi.git
cd volatility3-for-Raspberry-Pi
uv sync --python 3.12 --extra full
mkdir -p symbols/linux
# Use an included ISF, or add one matching the captured kernel build to symbols/linux.
uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.rpi.model.Model
uv run --extra full python vol.py -s symbols -f /path/to/memory.lime linux.pslist.PsList
```

## Test environment

All hardware validation reported here was completed on a Raspberry Pi 4.

[Raspberry Pi OS](TESTING.md#raspberry-pi-os) and [Kali Linux](TESTING.md#kali-linux) were also tested, but required custom kernel builds.

[Ubuntu](TESTING.md#ubuntu) and [Fedora](TESTING.md#fedora) were tested and are generally recommended because matching debug `vmlinux` files are readily available from their official packages.

Ubuntu reference environment:

| Component | Environment |
|---|---|
| Hardware | Raspberry Pi 4 Model B Rev 1.4, 8 GB RAM |
| Ubuntu 26.04.1 LTS, AArch64 | `7.0.0-1017-raspi`, `7.0.0-1023-raspi` |
| Ubuntu 24.04.5 LTS, AArch64 | `6.8.0-1068-raspi`, `6.17.0-1021-raspi`, `7.0.0-1023-raspi` |
| Memory | 4 KB pages, 48-bit virtual addresses |
| Acquisition | AVML 0.21.0, root access to `/proc/kcore` |
| Analysis / ISF generation | Apple Silicon Mac, Python 3.12.14, dwarf2json 0.9.0 |

Tested memory-image inputs include LiME and Snappy-compressed AVML acquired on a physical Raspberry Pi 4, and ELF64 acquired from a QEMU AArch64 VM. The listed kernel comparisons used LiME conversions; direct compressed-AVML reading remains limited by a framing issue.

Although the Raspberry Pi 5 became available in [October 2023](https://www.raspberrypi.com/news/raspberry-pi-5-available-now/), **skyrocketing hardware prices** have made expanding this research difficult. The prices I have encountered in South Korea are approximately KRW 300,000 (USD 225) for the 8 GB model and KRW 600,000 (USD 450) for the 16 GB model. As an independent researcher without dedicated research funding or hardware sponsorship, these costs currently exceed this project's budget; hardware donations or research support would help make this work possible. I plan to extend validation to the Raspberry Pi 5 in 2027 and, if successful, submit the findings to conferences and journals.

## Memory acquisition

Run the official [AVML 0.21.0 AArch64 binary](https://github.com/microsoft/avml/releases/tag/v0.21.0) on the Pi. Allow at least 10 GiB of free disk space for the recorded 8 GB model. The basic acquisition commands below do not create the controlled GPIO/process/file fixture used in the representative demo.

```sh
set -eu
curl -fL https://github.com/microsoft/avml/releases/download/v0.21.0/avml-aarch64 -o avml
printf '%s  %s\n' d97fd8bf043c8a14ad2bfe18ef6352ac9d3277a962f252d11fa34f4d40bacbfe avml | sha256sum -c -
chmod 700 avml
umask 077
capture_dir="$PWD/capture-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$capture_dir"
uname -a > "$capture_dir/uname.txt"
sudo ./avml acquire --source /proc/kcore "$capture_dir/memory.lime"
sudo chown "$(id -u):$(id -g)" "$capture_dir/memory.lime"
(cd "$capture_dir" && sha256sum memory.lime > memory.lime.sha256)
```

The default output is uncompressed LiME; add `--compress` for Snappy-compressed AVML. 

On macOS, compressed input also requires the native Snappy library to be discoverable (our setup used `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`).

Transfer the capture directory to the analysis host and verify its checksum:

```sh
mkdir -p samples/pi4
scp -r user@raspberry-pi:/absolute/path/to/capture-directory samples/pi4/
cd samples/pi4/capture-directory
shasum -a 256 -c memory.lime.sha256
```

Details of the representative GPIO/Linux forensic demo and eight earlier captures are available in [Memory dump samples](DUMP_SAMPLES.md).

## ISF generation

Generate an ISF from the captured kernel's matching debug `vmlinux`. The 7.0 example uses `linux-image-7.0.0-1023-raspi-dbgsym_7.0.0-1023.23_arm64.ddeb`; its GNU Build ID matched `/sys/kernel/notes` on the Pi. For Ubuntu, available Raspberry Pi kernel debug package versions can be found in the [Ubuntu debug symbol archive](https://ddebs.ubuntu.com/pool/main/l/linux-raspi/). For Fedora, matching `kernel-debuginfo` packages are available in the [Fedora Koji kernel package archive](https://kojipkgs.fedoraproject.org/packages/kernel/). With Go installed, you can run the following from the repository root. I used a Mac for this experiment; macOS is not required:

```sh
set -eu
mkdir -p symbol-input/extracted symbols/linux tools
curl -fL https://ddebs.ubuntu.com/pool/main/l/linux-raspi/linux-image-7.0.0-1023-raspi-dbgsym_7.0.0-1023.23_arm64.ddeb -o symbol-input/kernel-dbgsym.ddeb
printf '%s  %s\n' 81570d982b3223ce19420d4aa5678224016e74b32fccdad3e23a5f39262bf0a4 symbol-input/kernel-dbgsym.ddeb | shasum -a 256 -c -
ar -p symbol-input/kernel-dbgsym.ddeb data.tar.xz > symbol-input/kernel-debug-data.tar.xz
tar -xJf symbol-input/kernel-debug-data.tar.xz -C symbol-input/extracted ./usr/lib/debug/boot/vmlinux-7.0.0-1023-raspi

git clone https://github.com/volatilityfoundation/dwarf2json.git tools/dwarf2json
git -C tools/dwarf2json checkout 9f14607e0d339d463ea725fbd5c08aa7b7d40f75
(cd tools/dwarf2json && go build -o dwarf2json .)
tools/dwarf2json/dwarf2json linux --elf symbol-input/extracted/usr/lib/debug/boot/vmlinux-7.0.0-1023-raspi > symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json.partial
mv symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json.partial symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json
xz -f symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json
```

The [generated ISF](symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json.xz) passed schema 6.2.0 validation and contains 211,075 symbols and 12,826 user types. Matching ISFs for all listed kernels are included in [symbols/linux](symbols/linux) as `.json.xz` files, which Volatility reads directly. For another build, use its corresponding debug package and ISF.

## Analyzing a sample

The representative demo uses the **2026-11-19 Ubuntu 26.04.1 LTS / `7.0.0-1023-raspi` capture** in [Memory dump samples](DUMP_SAMPLES.md#representative-gpio-and-linux-forensic-demo). It is an original **uncompressed LiME** file; no AVML conversion is needed. This same dump connects GPIO configuration to process ancestry, network endpoints, an open file and recovered file content.

The capture was analyzed with commit `26cee65355d4ad441603969d34428786700553db`. Its live kernel Build ID was `e1460768fbd96b9063864daf8330650751eb2f09`, with 4,096-byte pages. Use the included `symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json.xz` (SHA-256 `07e46196ade1e3f73c5ca2c1a841db1f6f308007af02ea2314dcc6573972f708`). Existing uncommitted changes in the development checkout were excluded from this analysis.

From the repository root, set `DUMP` to your local copy and verify its checksum:

```sh
DUMP=/absolute/path/to/pi4-demo-candidate-20261119/retry/capture/memory.lime
printf '%s  %s\n' bc195a3b0232aa1020ddb396a45750cc30d5bddd249344e8d316dbc876c157d9 "$DUMP" | shasum -a 256 -c -
vol() { uv run --extra full python vol.py -s symbols -f "$DUMP" "$@"; }
vol linux.rpi.model.Model
```

Observed model output:

```text
Board                   Model                 Revision  Serial            RevisionCode  RAM   BoardManufacturer  SoC      Status
Raspberry Pi 4 Model B   raspberrypi,4-model-b  1.4       1000000015089641  0x00d03114    8 GB  Sony UK            BCM2711  ok
```

### GPIO: compare eight lines with capture-time observations

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

## Validation scope

**48 of the 49 originally evaluated Linux plugins** were validated on Raspberry Pi 4; the x86-only `Check_idt` is not applicable. The **eight newly developed [Raspberry Pi plugins](RPI_PLUGINS.md)** bring the total to **57 distinct plugins (49 + 8)**, separate from that original evaluation. The CLI lists **68 Linux command names**, including **11 compatibility aliases** for existing plugins. See [TESTING.md](TESTING.md) for test conditions, results and limitations.

On 2026-11-16, four fixes were rechecked against existing physical Pi 4 captures. Each comparison used the same dump and symbols, comparing the tested implementation with a copy in which only the relevant fix was reversed (retaining AArch64 enablement).

| Check | Without the fix | Current implementation |
| --- | --- | --- |
| Bash history | 0/6 known commands | 6/6, including PID, process name and timestamp to the second |
| PsScan | 105/144 stable reference PID/PPID pairs | 144/144, including previously missed PID 171671 |
| Sockscan | Exception on an unresolved candidate | All 10 controlled IPv4/IPv6 TCP/UDP endpoints found exactly once |
| InodePages | ARM64 page-conversion error; 0 bytes recovered | 2,135 bytes recovered, byte-for-byte and SHA256 match |

These checks validate the selected references, not every output row or all ARM64 systems. Related address-range, PID-limit, socket and page-conversion unit tests also passed: **122 tests**, Python 3.12.14 / pytest 8.4.2.

Hardware evidence comes from one physical Pi 4 across the tested distributions; Pi 5 has not been verified. EEPROM recovery and substantive Device Tree-change positive cases have synthetic coverage only. See [validation boundaries](CONTRIBUTIONS.md#boundaries) for details.

## Credits and license

Built on Volatility Foundation's framework and Abyss-W4tcher's AArch64 implementation; maintained by cpuu. Original copyright notices and the [Volatility Software License](LICENSE.txt) are retained; the source implementations are identified in [Basis](#basis). See also the [upstream README](README.upstream.md).
