# volatility3 for Raspberry Pi

Experimental Raspberry Pi / AArch64 Linux memory analysis, maintained independently by [cpuu](https://github.com/cpuu). This project builds on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and [Abyss-W4tcher's AArch64 implementation (#1088)](https://github.com/volatilityfoundation/volatility3/pull/1088). It is not an official Volatility Foundation release. Original Git history, copyright notices and license are retained.

## Basis

- Upstream `develop`: `77ff0b1932d77527f850c8ced01d85805ea7bf97` (checked 2026-11-06).
- Original AArch64 implementation: `5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4`.
- Previously tested integration: `c3ebd40e1863280f608d954651360bc92a763c6f`.
- Latest upstream includes the generic Linux IPv6 host-family fix (#2052); it is inherited here as an upstream change.

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
