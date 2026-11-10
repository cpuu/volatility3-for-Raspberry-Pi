# volatility3 for Raspberry Pi

Raspberry Pi / AArch64 Linux memory analysis, maintained independently by [cpuu](https://github.com/cpuu), based on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and [Abyss-W4tcher's AArch64 implementation (#1088)](https://github.com/volatilityfoundation/volatility3/pull/1088).

## Basis

- Upstream `develop`: [77ff0b1932d77527f850c8ced01d85805ea7bf97](https://github.com/volatilityfoundation/volatility3/commit/77ff0b1932d77527f850c8ced01d85805ea7bf97) (2026-11-06), including development changes after the official [v2.28.2 release](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2).
- Original AArch64 implementation: [5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4](https://github.com/Abyss-W4tcher/volatility3/commit/5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4) (2024-10-20).

## Quick start

Use Python 3.12 and [uv](https://docs.astral.sh/uv/). Collect memory on the Pi and analyze it on the Mac or another host.

```sh
git clone https://github.com/cpuu/volatility3-for-Raspberry-Pi.git
cd volatility3-for-Raspberry-Pi
uv sync --locked --extra full
mkdir -p symbols/linux
# Add an ISF matching the captured kernel build to symbols/linux.
uv run --locked --extra full python vol.py -s symbols -f /path/to/memory.lime linux.pslist.PsList
```

## Test environment

| Component | Environment |
|---|---|
| Hardware | Raspberry Pi 4 Model B Rev 1.4, 8 GB RAM |
| OS | Ubuntu 24.04.5 LTS, AArch64 |
| Tested kernels | `6.8.0-1068-raspi`, `6.17.0-1021-raspi`, `7.0.0-1023-raspi` |
| Memory | 4 KB pages, 48-bit virtual addresses |
| Acquisition | AVML 0.21.0, root access to `/proc/kcore` |
| Analysis / ISF generation | Apple Silicon Mac, Python 3.12.14, dwarf2json 0.9.0 |

Tested memory-image inputs include LiME and Snappy-compressed AVML acquired on a physical Raspberry Pi 4, and ELF64 acquired from a QEMU AArch64 VM. The listed kernel comparisons used LiME conversions; direct compressed-AVML reading remains limited by a framing issue.

## Memory acquisition

Run the official [AVML 0.21.0 AArch64 binary](https://github.com/microsoft/avml/releases/tag/v0.21.0) on the Pi. Allow about 8 GiB of free space for the recorded 8 GB model.

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

The recorded LiME capture (2026-10-12) was 8,443,150,080 bytes; transfer hashes matched and all three System RAM ranges were present.

## ISF generation

Generate an ISF from the captured kernel's matching debug `vmlinux`. The 6.8 example uses `linux-image-6.8.0-1068-raspi-dbgsym_6.8.0-1068.72_arm64.ddeb`; its GNU Build ID matched `/sys/kernel/notes` on the Pi. For Ubuntu, available Raspberry Pi kernel debug package versions can be found in the [Ubuntu debug symbol archive](https://ddebs.ubuntu.com/pool/main/l/linux-raspi/). Run the following from the repository root on the Mac, with Go installed:

```sh
set -eu
mkdir -p symbol-input/extracted symbols/linux tools
curl -fL https://ddebs.ubuntu.com/pool/main/l/linux-raspi/linux-image-6.8.0-1068-raspi-dbgsym_6.8.0-1068.72_arm64.ddeb -o symbol-input/kernel-dbgsym.ddeb
printf '%s  %s\n' db7a57bdc9abc1b037beea417aea73bba7008b8e7276f778134f5d9b4d6f34f3 symbol-input/kernel-dbgsym.ddeb | shasum -a 256 -c -
ar -p symbol-input/kernel-dbgsym.ddeb data.tar.xz > symbol-input/kernel-debug-data.tar.xz
tar -xJf symbol-input/kernel-debug-data.tar.xz -C symbol-input/extracted ./usr/lib/debug/boot/vmlinux-6.8.0-1068-raspi

git clone https://github.com/volatilityfoundation/dwarf2json.git tools/dwarf2json
git -C tools/dwarf2json checkout 9f14607e0d339d463ea725fbd5c08aa7b7d40f75
(cd tools/dwarf2json && go build -o dwarf2json .)
tools/dwarf2json/dwarf2json linux --elf symbol-input/extracted/usr/lib/debug/boot/vmlinux-6.8.0-1068-raspi > symbols/linux/ubuntu-6.8.0-1068-raspi-arm64.json.partial
mv symbols/linux/ubuntu-6.8.0-1068-raspi-arm64.json.partial symbols/linux/ubuntu-6.8.0-1068-raspi-arm64.json
```

The [generated ISF](symbols/linux/ubuntu-6.8.0-1068-raspi-arm64.json) passed schema 6.2.0 validation and contains 170,879 symbols and 11,184 user types. Matching ISFs for all listed kernels are included in [symbols/linux](symbols/linux). For another build, use its corresponding debug package and ISF.

## Validation scope

**48 of 49 distinct Linux plugins have been validated** using physical Raspberry Pi 4 memory captures in the environment described above. The remaining plugin, `Check_idt`, examines the x86 Interrupt Descriptor Table and is not applicable to AArch64.

Of the 48 validated plugins, 23 required only an AArch64 declaration at plugin level on the corrected core, 16 required plugin or shared-core fixes, and 9 worked with the existing implementation.

Major contributions beyond architecture declarations include:

- **Process analysis:** corrected Bash address scanning, PsScan PID limits, kernel-thread attribution and ARM64 stack traversal.
- **Symbols and tracing:** fixed kallsyms decoding (including per-entry relative offsets), syscall-table bounds, ftrace filter traversal and notifier pointer handling.
- **Memory recovery:** implemented ARM64 page-address conversion and improved resident kernel-module ELF reconstruction.
- **Sockets and devices:** corrected physical socket scanning, IPv6 peer-address selection, PTY discovery and framebuffer rendering.

Validation covers the documented fixtures and options. RecoverFs completed both tmpfs and full recovery runs, with recovery limited to cached contents. PerfEvents covers BPF-attached events, and four detectors used simulated positive controls over real Pi memory. Kmsg still has a final-message off-by-one. See [TESTING.md](TESTING.md) for results, references and remaining limitations.

## Credits and license

Built on Volatility Foundation's framework and Abyss-W4tcher's AArch64 implementation; maintained by cpuu. Original history, copyright notices and the [Volatility Software License](LICENSE.txt) are retained. See also the [upstream README](README.upstream.md).
