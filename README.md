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
