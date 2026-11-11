# Linux plugin validation

Results as of 2026-11-11: **48 of 49 distinct Linux plugins verified** on Raspberry Pi 4 for the cases described here. `Check_idt` is excluded because it inspects the x86 Interrupt Descriptor Table, which has no AArch64 equivalent for this plugin to inspect.

A regression run tested 48 plugins across six environments: three Ubuntu kernels, Raspberry Pi OS, Kali Linux and Fedora. All **288 runs completed normally and matched the previous results**.

## Raspberry Pi OS

Ubuntu is recommended for normal use: matching kernel debug packages provide the DWARF-enabled `vmlinux` needed for ISF generation without rebuilding the kernel. See the [Ubuntu environment below](#ubuntu) and the [ISF generation guide](README.md#isf-generation).

Raspberry Pi OS 64-bit was also tested on 2026-11-11, using a custom-built `6.18.60-rpt-rpi-v8-volab` kernel. The official 6.18.50 and 6.18.60 debug packages we inspected contained `vmlinux`, but lacked the DWARF type information required by dwarf2json. This required the following preparation:

1. Build the official `linux` source package `1:6.18.60-1+rpt1` in a separate ARM64 Linux VM, starting from the stock `rpi-v8` configuration (4 KB pages, 39-bit virtual addresses).
2. Enable `CONFIG_DEBUG_INFO_DWARF4=y` and disable `CONFIG_DEBUG_INFO_NONE`, reduced and split debug information. Enable `CONFIG_PROC_KCORE=y` for AVML acquisition, which also selects `CONFIG_VMCORE_INFO`. Use a distinct kernel release suffix to identify the build.
3. Install that kernel and its matching modules, DTBs and overlays on the Pi, generate its initramfs on Raspberry Pi OS, and boot it while retaining the original kernel as a fallback.
4. Generate the ISF with dwarf2json from the same build's unstripped `vmlinux` and `System.map`, verify the running kernel's Build ID and banner, then acquire memory. Rebuilding the same version alone does not establish a match to the stock kernel binary.

All 48 applicable plugins completed on a verified LiME conversion of the AVML 0.21.0 capture. Independent references matched for 42 plugins; five initially empty detectors subsequently passed controlled checks (four analysis simulations and one live no-op notifier).

## Ubuntu

- Raspberry Pi 4 Model B Rev 1.4, 8 GB RAM
- Ubuntu 24.04.5 LTS, AArch64, 4 KB pages, 48-bit virtual addresses
- Tested kernels: `6.8.0-1068-raspi`, `6.17.0-1021-raspi`, `7.0.0-1023-raspi`
- AVML 0.21.0 compressed captures; matching [kernel ISFs](symbols/linux)
- Analysis on Apple Silicon macOS with Python 3.12.14 and `uv sync --locked --extra full`

The tests used several captures from the same Pi configuration, including controlled processes, sockets, tracing events and a no-op kernel notifier. The QEMU and image-format experiments are separate from this plugin validation.

## Fedora

Fedora 45 Server was tested on Raspberry Pi 4 with the official `7.2.11-300.fc45.aarch64` kernel (4 KB pages, 48-bit virtual addresses). The matching [official kernel-debuginfo package](https://kojipkgs.fedoraproject.org/packages/kernel/7.2.11/300.fc45/aarch64/) provided the DWARF-enabled `vmlinux` to generate the [matching ISF](symbols/linux/fedora-7.2.11-300.fc45-arm64.json.xz) without a custom kernel build. Testing used a verified LiME conversion of an AVML 0.21.0 compressed capture. All 48 applicable plugins were run.

## Kali Linux

Like Raspberry Pi OS, Kali Linux required a custom kernel build with DWARF debug information and `CONFIG_PROC_KCORE` enabled. Testing used Kali Linux 2026.3 on Raspberry Pi 4 with kernel `6.12.34-kali-rpi-v8` and its [matching ISF](symbols/linux/kali-6.12.34-kali-rpi-v8-arm64.json.xz).

## Coverage

`vol.py --help` lists 60 Linux entries. Eleven are compatibility aliases, leaving 49 implementations.

| Change needed | Plugins |
|---|---:|
| AArch64 declaration only at plugin level, using the corrected core | 23 |
| Plugin or shared-core implementation fixes | 16 |
| Existing implementation, no additional change | 9 |
| Not applicable: x86 `Check_idt` | 1 |

Reference checks used capture-time process listings, socket endpoints, kernel symbols and known file contents where available. A successful exit or an empty result alone was not counted as validation. The 2026-11-09 rerun of all 48 applicable plugins reproduced their earlier checked JSON results. The 236 tests in the added or modified test files also passed, along with lint and formatting checks.

## Main fixes and checks

| Area | Changes and representative results |
|---|---|
| Processes | Bash address scanning recovered all six known history entries. PsScan's corrected PID bound recovered all 144 stable reference processes. Kthreads attribution matched all 125 returned handler/module pairs. ARM64 kernel-stack traversal was added to PsCallStack. |
| Symbols and tracing | Kallsyms core/module/BPF records matched live references. Check_syscall recovered 462 native and 462 compat entries. Ftrace recovered all three configured filter entries after traversal and symbol-resolution fixes. |
| File and module recovery | ARM64 sparse-memory page conversion enabled InodePages to restore a known 2,135-byte file exactly. RecoverFs produced a tmpfs archive and completed a full run on the fresh Pi capture. ModuleExtract reconstructed two ARM64 module ELFs, with 1,884 symbol records and 582 function byte ranges checked against memory. |
| Sockets and terminals | Sockscan recovered all ten controlled IPv4/IPv6 TCP/UDP endpoints after candidate-handling and address-layer fixes. Tty_Check recovered driver devices and a Unix98 PTY pair. |
| Kernel objects | Corrected notifier pointer traversal recovered the registered callback at its known address. Sysfs module discovery returned the correct struct addresses for all 110 reference modules. |
| Memory and graphics | Malfind detected controlled executable mappings and dirty pages, with exact page extraction. Fbdev's corrected color conversion matched all 2,073,600 reference pixels. |

Declaration-only additions include LibraryList, Ptrace, PerfEvents and CheckTracepoints. LibraryList matched nine library load addresses; the tracing fixture supplied a known tracer/tracee pair, a BPF-attached perf event and registered tracepoint callbacks.

## Remaining limits

- **Kmsg:** a confirmed off-by-one can omit the final message. The fix and Intel reproduction remain pending.
- **RecoverFs:** full recovery runs complete, but only cached file contents are recoverable; unavailable pages may be skipped.
- **PerfEvents:** reports BPF-attached events only.
- **Detection controls:** Check_afinfo, Check_creds, Check_modules and Hidden_modules were checked with simulated changes during analysis, not live rootkit captures.
- **ModuleExtract:** produces analysis ELFs, not reloadable `.ko` files.
- **Coverage:** validation covers the listed Pi kernels and exercised options. Other configurations and Intel Linux remain untested.
