# volatility3 for Raspberry Pi

Experimental Raspberry Pi / AArch64 Linux memory analysis, maintained independently by [cpuu](https://github.com/cpuu). This project builds on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and [Abyss-W4tcher's AArch64 implementation (#1088)](https://github.com/volatilityfoundation/volatility3/pull/1088). It is not an official Volatility Foundation release. Original Git history, copyright notices and license are retained.

## Basis

- Upstream `develop`: `77ff0b1932d77527f850c8ced01d85805ea7bf97` (checked 2026-11-06).
- Original AArch64 implementation: `5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4`.

## Quick start

Use Python 3.12 and [uv](https://docs.astral.sh/uv/). Acquisition occurs on the Raspberry Pi; analysis can run on another machine.

```sh
git clone https://github.com/cpuu/volatility3-for-Raspberry-Pi.git
cd volatility3-for-Raspberry-Pi
uv sync --locked --extra full
uv run --locked --extra full python vol.py --help
mkdir -p symbols/linux
# Place an ISF matching the capture's exact kernel build under symbols/linux.
uv run --locked --extra full python vol.py -s symbols -f /path/to/memory.lime linux.pslist.PsList
```

The validated capture was acquired with AVML 0.21.0. Generate the ISF from the matching debug vmlinux using dwarf2json; architecture and kernel release alone do not establish a matching build. Memory captures and private symbols are not included in this repository.

## Test environment

The capture target and the analysis host were separate machines. The environment below describes the recorded experiment, rather than a minimum requirement or a claim of support for every Raspberry Pi model.

| Component | Recorded environment |
|---|---|
| Capture hardware | Raspberry Pi 4 Model B Rev 1.4, 8 GB RAM |
| Target OS | Ubuntu 24.04.5 LTS (Noble Numbat), AArch64 |
| Target kernel | `6.8.0-1064-raspi`, package version `6.8.0-1064.68` |
| Memory configuration | 4,096-byte pages; `CONFIG_ARM64_VA_BITS=48` |
| Acquisition access | Root access to `/proc/kcore`; `CONFIG_PROC_KCORE=y` |
| Kernel debug configuration | DWARF5 debug information enabled; matching debug ELF obtained separately |
| Analysis / ISF-generation host | Apple Silicon Mac (macOS ARM64) |
| Analysis runtime | Python 3.12.14, managed with uv; current project dependencies pinned in `uv.lock` |
| ISF generator | dwarf2json 0.9.0, commit `9f14607e0d339d463ea725fbd5c08aa7b7d40f75`, built with Go 1.27.1 darwin/arm64 |
| Capture / latest reanalysis | 2026-10-12 KST / 2026-11-06 KST |

The matching ISF was generated on the Mac on 2026-10-07 and reused for the October 12 capture after confirming the kernel build had not changed. The kernel was not rebuilt for this experiment, and the debug package was not installed on the Pi. Broader kernel, page-size and hardware coverage remains future work.

Both uncompressed LiME and Snappy-compressed AVML (`--compress`) captures were tested on this physical Raspberry Pi 4 using AVML 0.21.0, with the compressed AVML file analyzed directly on the Mac using the same eight plugins.

## Memory acquisition

The validation dump was collected **on the Raspberry Pi**, then transferred to a Mac for analysis. Acquisition used the official [AVML 0.21.0 AArch64 binary](https://github.com/microsoft/avml/releases/tag/v0.21.0), reading `/proc/kcore` as root and writing an **uncompressed LiME** image. No LiME kernel module was loaded for this capture.

### Recorded acquisition

| Item | Value |
|---|---|
| Target | Raspberry Pi 4, Ubuntu 24.04.5 LTS, AArch64 |
| Kernel / page size | `6.8.0-1064-raspi` / 4 KB |
| Tool | `avml 0.21.0`, official `avml-aarch64` release asset |
| AVML binary SHA-256 | `d97fd8bf043c8a14ad2bfe18ef6352ac9d3277a962f252d11fa34f4d40bacbfe` |
| Acquisition time | 2026-10-12 01:17:47–01:27:10 KST (2026-10-11 16:17:47–16:27:10 UTC) |
| Duration | 9 minutes 23 seconds |
| Image size | 8,443,150,080 bytes |
| Image SHA-256 | `bd220dba56b5fd0608c9d93896f09a786da2a5edccba88d5ed5afb3dfd666399` |

This was a live acquisition, not an atomic snapshot: processes, sockets and other structures could change during collection. The hashes above identify our recorded binary and image; a newly acquired image will have a different hash.

### Acquisition procedure on the Pi

The following uses simplified paths for reproducing the recorded procedure. `/proc/kcore` must be accessible to root on the target kernel. Before acquisition, we checked available disk space against the System RAM ranges in `/proc/iomem`, LiME header overhead, and a 512 MiB reserve. Use a destination with enough free space for your own device; the recorded image was approximately 7.86 GiB.

```sh
set -eu
curl -fL https://github.com/microsoft/avml/releases/download/v0.21.0/avml-aarch64 \
  -o avml-aarch64-v0.21.0
printf '%s  %s\n' \
  d97fd8bf043c8a14ad2bfe18ef6352ac9d3277a962f252d11fa34f4d40bacbfe \
  avml-aarch64-v0.21.0 | sha256sum -c -
chmod 700 avml-aarch64-v0.21.0
./avml-aarch64-v0.21.0 --version

umask 077
capture_dir="$PWD/capture-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$capture_dir"
df -h "$capture_dir"
uname -a > "$capture_dir/uname.txt"
cat /etc/os-release > "$capture_dir/os-release.txt"
getconf PAGE_SIZE > "$capture_dir/page-size.txt"
sudo cat /proc/iomem > "$capture_dir/iomem.txt"

date -u +%FT%TZ > "$capture_dir/capture-start.txt"
sudo ./avml-aarch64-v0.21.0 acquire \
  --source /proc/kcore \
  --max-disk-usage-percentage 97 \
  "$capture_dir/memory.lime" > "$capture_dir/avml.log" 2>&1
# Continue only if acquisition completed successfully.
sudo chown "$(id -u):$(id -g)" "$capture_dir/memory.lime"
chmod 600 "$capture_dir/memory.lime"
date -u +%FT%TZ > "$capture_dir/capture-end.txt"
(cd "$capture_dir" && sha256sum memory.lime > memory.lime.sha256)
```

The `97` disk-usage limit records the setting used in this experiment; it does not replace a free-space check. In addition to this minimal example, we saved the kernel configuration and notes, and reference process, module, mount and listening-socket lists before and after collection. A long-running test process provided `/proc/PID/maps`, command-line and mount-namespace references during acquisition. These records support the bounded comparisons described below.

### Transfer and integrity verification

Copy the capture and its checksum file over SSH to the analysis machine. For example, on macOS, replace the host and directory placeholders with your actual values:

```sh
mkdir -p samples/pi4
scp -r user@raspberry-pi:/absolute/path/to/capture-directory samples/pi4/
cd samples/pi4/capture-directory
shasum -a 256 -c memory.lime.sha256
```

For the recorded capture, SHA-256 matched on the Pi and Mac. We also parsed the LiME ranges and checked that all three System RAM ranges were covered through their final bytes, with no missing tail bytes. No dump padding was applied. Hash agreement verifies transfer integrity; it does not make a live capture atomic or prove every in-memory object is consistent.

Keep the exact kernel build information with the image and generate a matching ISF from its debug `vmlinux` before analysis. Raw memory, process reference data and private symbols are kept outside this public repository.

## ISF generation

Volatility needs an Intermediate Symbol Format (ISF) file matching the **captured kernel build**, not merely the architecture or a similar release number. We generated ours on the Mac from Ubuntu's matching debug kernel package; no separate `System.map` was supplied. dwarf2json read the DWARF types and ELF symbol table from `vmlinux`.

### Obtain the matching debug ELF

For the recorded `6.8.0-1064-raspi` kernel, the package was `linux-image-6.8.0-1064-raspi-dbgsym_6.8.0-1064.68_arm64.ddeb`. Its SHA-256 was checked against Ubuntu's [noble-updates arm64 package index](https://ddebs.ubuntu.com/dists/noble-updates/main/binary-arm64/Packages.gz) at acquisition time. Repository contents may change; use the exact package corresponding to your capture.

The commands below reproduce the recorded inputs from the repository root on macOS. They extract the debug ELF without installing the package:

```sh
set -eu
mkdir -p symbol-input/extracted symbols/linux tools
curl -fL --retry 3 \
  https://ddebs.ubuntu.com/pool/main/l/linux-raspi/linux-image-6.8.0-1064-raspi-dbgsym_6.8.0-1064.68_arm64.ddeb \
  -o symbol-input/kernel-dbgsym.ddeb
printf '%s  %s\n' \
  0e2e9c888c07fef3a9c61c014573b492fe126efd1062367f5406a2dbcf688aff \
  symbol-input/kernel-dbgsym.ddeb | shasum -a 256 -c -
ar -p symbol-input/kernel-dbgsym.ddeb data.tar.xz \
  > symbol-input/kernel-debug-data.tar.xz
tar -xJf symbol-input/kernel-debug-data.tar.xz -C symbol-input/extracted \
  ./usr/lib/debug/boot/vmlinux-6.8.0-1064-raspi
```

The extracted ELF was 64-bit little-endian AArch64 with DWARF5 information. Its GNU build ID, `6567d5728de9f4aef1f4a274d212369cfae2ff57`, matched the running Pi kernel's `/sys/kernel/notes`. A matching release string alone was not used as proof of identity.

### Build dwarf2json and generate the ISF

The recorded toolchain was Go 1.27.1 darwin/arm64. With that Go toolchain available as `go`, use a fresh `tools/dwarf2json` directory:

```sh
set -eu
git clone https://github.com/volatilityfoundation/dwarf2json.git tools/dwarf2json
git -C tools/dwarf2json checkout 9f14607e0d339d463ea725fbd5c08aa7b7d40f75
(cd tools/dwarf2json && go build -o dwarf2json .)
tools/dwarf2json/dwarf2json --version

tools/dwarf2json/dwarf2json linux \
  --elf symbol-input/extracted/usr/lib/debug/boot/vmlinux-6.8.0-1064-raspi \
  > symbols/linux/ubuntu-6.8.0-1064-raspi-arm64.json.partial
mv symbols/linux/ubuntu-6.8.0-1064-raspi-arm64.json.partial \
  symbols/linux/ubuntu-6.8.0-1064-raspi-arm64.json
shasum -a 256 symbols/linux/ubuntu-6.8.0-1064-raspi-arm64.json
```

Only rename the partial output after successful generation, as enforced by `set -e`. The Mac runs the generator; the input ELF supplies the target's ARM64 types and symbols.

### Recorded output and checks

| Artifact | Size / SHA-256 |
|---|---|
| Debug package | 1,411,802,148 bytes; `0e2e9c888c07fef3a9c61c014573b492fe126efd1062367f5406a2dbcf688aff` |
| Extracted vmlinux | 321,252,920 bytes; `8b81e112f83a80e6c4180b154c9067aa0a45b2028533904782261c51d3e21fdc` |
| Generated ISF | 40,310,603 bytes; `ee3d54aa8b55615a84560008e0ae5ffa06df0febc027378a0b4f8efd41353bbd` |

The ISF contained 170,389 symbols, 11,151 user types and 18 base types. It passed JSON parsing and ISF schema 6.2.0 validation; the original #1088 `isfinfo.IsfInfo --live --validate` check returned `Valid=True`. We checked `linux_banner`, `init_task`, `swapper_pg_dir` and the required `task_struct` fields, and subsequently confirmed the full banner in the actual dump. Ubuntu's `linux_banner` includes a packaging suffix absent from `/proc/version`, so exact equality with `/proc/version` was not required.

Use the resulting file under `symbols/linux/` with the `-s symbols` analysis commands above. Schema validity and build-ID agreement establish useful prerequisites; they do not prove every type reference or plugin result is correct. Do not reuse this ISF for a different kernel build. The debug package, ELF and generated ISF are not committed to this repository.

## Validation scope

Initial hardware evidence: Raspberry Pi 4, Ubuntu 24.04.5 LTS, kernel `6.8.0-1064-raspi`, 4 KB pages, 48-bit virtual addresses. Eight Linux plugins are enabled for AArch64; not every Linux plugin is supported.

| Plugin | Observations from the existing capture |
|---|---|
| pslist | 158 rows; all 132 PIDs stable across acquisition were present |
| lsmod | 108 module names matched |
| iomem | 61 regions matched |
| kmsg | 624 of 625 reference message texts matched |
| proc.Maps | Test process: 29 ranges and core fields matched; three path labels differed |
| psaux | Test process command line matched; another row contained a replacement character |
| mountinfo | 24 reference mounts represented; detailed option differences and one extra entry |
| sockstat | 568 rows; after the now-upstream IPv6 fix, 11/11 stable local TCP/UDP endpoint tuples matched |

These are bounded checks on one live, non-atomic capture, not a guarantee of complete forensic correctness. Real Linux Intel end-to-end discovery, other Raspberry Pi models, other kernels/page sizes and all-plugin compatibility remain unverified. Synthetic Intel tests do not replace real Linux Intel captures. See [VALIDATION.md](VALIDATION.md) for this repository's initial verification.

## Development

```sh
uv sync --locked --extra test
uv run --locked --extra test pytest test/test_linux_arm64_integration.py test/test_linux_socket_addresses.py test/test_cli.py --volatility vol.py -q
```

Use this repository's issues for reproducible problems. Include the code revision, analysis host, target kernel, page size, ISF provenance and sanitized logs. Do not post raw memory dumps containing personal data.

## Credits and license

Volatility Foundation and the original contributors provide the framework. Abyss-W4tcher provides the original AArch64 work. cpuu maintains this integration, testing and Raspberry Pi-focused distribution. See [Volatility Software License](LICENSE.txt) and [upstream README](README.upstream.md). This project does not relicense the original code. The Python package/import name remains `volatility3` for compatibility; this repository does not publish a replacement package to PyPI.
