# Linux plugin validation

**48 of the 49 evaluated Linux plugins** were exercised on a physical Raspberry Pi 4 Model B Rev 1.4 with 8 GB RAM. The x86-specific `Check_idt` was excluded.

The eight compressed captures listed in [Memory dump samples](DUMP_SAMPLES.md#eight-additional-compressed-avml-captures) were tested with **48 plugins per sample: all 384 runs completed normally**. Validation compared JSON outputs and extracted files with saved references. The separate representative demo is documented below.

## Sample coverage

The tests use LiME conversions of the listed compressed AVML captures and matching ISFs.

| Distribution | Kernel | Normal exits |
| --- | --- | ---: |
| Ubuntu 24.04.5 LTS | `6.8.0-1064-raspi` | 48/48 |
| Ubuntu 24.04.5 LTS | `6.8.0-1068-raspi` | 48/48 |
| Ubuntu 24.04.5 LTS | `6.17.0-1021-raspi` | 48/48 |
| Ubuntu 24.04.5 LTS | `7.0.0-1023-raspi` | 48/48 |
| Ubuntu 26.04.1 LTS | `7.0.0-1017-raspi` | 48/48 |
| Raspberry Pi OS 64-bit | `6.18.60-rpt-rpi-v8-volab` | 48/48 |
| Kali Linux 2026.3 | `6.12.34-kali-rpi-v8` | 48/48 |
| Fedora 45 Server | `7.2.11-300.fc45.aarch64` | 48/48 |
| **Total** | **8 samples × 48 plugins** | **384/384** |

Input integrity was checked against recorded SHA-256 values, and the ISFs matched the archived verified symbols. Extracted files were compared by content; RecoverFs archives were also checked for metadata equality, excluding extraction-time timestamps and container encoding. Matching empty detector outputs were recorded as regression matches.

Kmsg's final-message recovery was checked against verified post-fix references. For one YARA result, the same seven PID/address/byte matches were retained while YARA-X displayed `default.r1` instead of `r1`; replay with yara-python reproduced the original JSON exactly.

## Evidence matrix

| Capability | Validation method and result |
| --- | --- |
| Bash, PsScan, cached-file recovery, Sockscan | Physical Pi captures, selected capture-time references and controlled comparisons with the relevant fix reversed; see [results](CONTRIBUTIONS.md#submission-case) |
| Existing Linux plugins | 384 runs across eight samples, with JSON and extracted-file comparisons |
| Model, Boot, Interfaces, Console, Firmware, raw DT | Physical Pi output and saved-reference replay, with source addresses and raw properties |
| GPIO | Controlled gpio-sim requests on a physical Pi, capture-time before/after comparisons and synthetic layout tests |
| DtChanges | Physical unchanged/generated-name cases; synthetic property changes, malformed inputs and incomplete reads |
| EEPROM configuration recovery | Synthetic positive tests |
| Check_afinfo, Check_creds, Check_modules, Hidden_modules | Controlled changes simulated during analysis |
| Representative sample file | 39 bytes recovered through Maps, matching an independent reference SHA-256 |
| Cross-platform shared core | Saved PsList results reproduced on x86-64 Linux and Windows captures; synthetic address-translation tests |

## Test environments

Memory was acquired with AVML 0.21.0 and analyzed with matching [kernel ISFs](symbols/linux) on Apple Silicon macOS using Python 3.12.14. Tests used 4 KB pages. Ubuntu and Fedora used 48-bit virtual addresses; the Raspberry Pi OS build used 39-bit virtual addresses.

### Ubuntu

- Ubuntu 24.04.5 LTS: `6.8.0-1064-raspi`, `6.8.0-1068-raspi`, `6.17.0-1021-raspi`, `7.0.0-1023-raspi`.
- Ubuntu 26.04.1 LTS: `7.0.0-1017-raspi`, `7.0.0-1023-raspi`.
- Controlled fixtures included processes, sockets, tracing events and a no-op kernel notifier.

Both Ubuntu 26.04 full-suite captures completed 48 plugin runs. Selected-field comparisons matched for 41 of 43 checked plugins; Kmsg was subsequently corrected as described below, and the MountInfo discrepancy is recorded under [observed behavior](#observed-behavior). Five other detectors returned empty results in these captures without positive fixtures.

Compressed AVML and converted LiME inputs for `6.8.0-1068-raspi` both returned **166 PsList rows**, matching the saved reference.

### Raspberry Pi OS

Raspberry Pi OS 64-bit used a custom `6.18.60-rpt-rpi-v8-volab` kernel built from source package `1:6.18.60-1+rpt1` and the `rpi-v8` configuration. The inspected official debug packages lacked the DWARF type information needed by dwarf2json. The test build enabled DWARF4 debug information and `CONFIG_PROC_KCORE`; its unstripped `vmlinux` and `System.map` supplied the ISF. The running kernel's Build ID and banner were checked before acquisition.

All 48 applicable plugins completed on the converted LiME capture. Independent references matched for 42 plugins; five detectors passed controlled checks comprising four analysis simulations and one live no-op notifier. Kmsg's final-message recovery was verified with the fix described below.

### Fedora

Fedora 45 Server used the official `7.2.11-300.fc45.aarch64` kernel. The matching [kernel-debuginfo package](https://kojipkgs.fedoraproject.org/packages/kernel/7.2.11/300.fc45/aarch64/) supplied DWARF-enabled `vmlinux` for ISF generation. All 48 applicable plugins were run on the converted LiME capture.

### Kali Linux

Kali Linux 2026.3 used a custom `6.12.34-kali-rpi-v8` kernel with DWARF debug information and `CONFIG_PROC_KCORE` enabled, together with its matching ISF.

Ubuntu and Fedora provide matching debug packages for ISF generation without a custom kernel build. See the [ISF generation guide](README.md#isf-generation).

## Representative sample

The [representative Ubuntu 26.04 sample](DUMP_SAMPLES.md#representative-gpio-and-linux-forensic-demo) was checked with **16 CLI commands**: GPIO default/all, Model, PsList, PsTree, PsAux, Sockstat, PID-scoped Lsof, Rpi, Boot, Interfaces, Console, Firmware, DtChanges default/include-generated, and address-scoped Maps extraction.

The recorded JSON outputs matched saved references. Independent capture-time process/parent and SSH IPv4/IPv6 listener checks passed. Maps recovered a 39-byte file matching the reference SHA-256 `4aecf752c1098b10e5db0a7e804867aa2ab5fd8e5ac427c761ca8da487d7b49c`.

DtChanges 1.0.1 was also replayed on this sample: default output (**1 row**) and `--include-generated` output (**332 rows**) matched the saved JSON after accounting for the added summary annotation. Artifact values and change classifications were unchanged.

## Coverage

| Count | Meaning |
| --- | --- |
| 49 | Original plugin implementations evaluated; 48 applicable to AArch64 |
| 8 | New [Raspberry Pi plugins](RPI_PLUGINS.md) |
| **57** | **Total implementations: 49 + 8** |
| 11 | Compatibility aliases for existing implementations |
| **68** | **Linux CLI names: 57 implementations + 11 aliases** |

For example, `linux.check_creds.Check_creds` redirects to `linux.malware.check_creds.Check_creds`.

| Change to original implementations | Plugins |
| --- | ---: |
| AArch64 declaration at plugin level, using the corrected core | 23 |
| Plugin or shared-core implementation fixes | 16 |
| Existing implementation used unchanged | 9 |
| x86-only `Check_idt` | 1 |

## Automated tests

The full unit/synthetic suite passed **515 tests**, with **24 image-dependent cases skipped** when no image arguments were supplied. A separate image-backed run passed all **8 Arrow/Parquet cases**, using Linux PsList/Lsof and Windows PsList/PID-4 Handles. The other 16 image-dependent cases are macOS-specific and were not exercised.

Test setup and command:

```sh
uv sync --locked --extra test --extra arrow
uv run --no-sync pytest test --volatility=vol.py -q -rs
```

Snappy was available for compressed-frame tests. Repository-wide Ruff lint/format checks passed for 399 Python files, and both changed DT files passed subsequent checks. Volatility's configurable-class analysis also passed. GitHub Actions checks installation, code analysis, Ruff and the unit/synthetic suite on Ubuntu and macOS.

DT tests cover added/removed/modified properties, node differences, raw addresses, missing symbols, corrupt FDT input, identical changes to both trees, runtime status changes, generated-name patterns and incomplete reads.

Shared-core regression reproduced saved PsList JSON on x86-64 Linux (`6.8.0-142-generic`, four-level paging, **117 processes**) and Windows (**38 processes**). Synthetic tests cover x86, PAE and x86-64 translation, banner-candidate validation, and recursive ISF types with 32-bit and 64-bit pointers.

## Main fixes and checks

| Area | Verified result |
| --- | --- |
| Processes | Bash recovered six known history entries. PsScan matched all 144 stable reference PID/PPID pairs. Kthreads matched 125 handler/module pairs. ARM64 kernel-stack traversal was added to PsCallStack. |
| Symbols and tracing | Kallsyms core/module/BPF records matched live references. Check_syscall recovered 462 native and 462 compat entries. Ftrace recovered three configured filters. |
| File and module recovery | InodePages restored a 2,135-byte file exactly. RecoverFs produced a tmpfs archive and completed a full Pi-capture run. ModuleExtract reconstructed two ARM64 analysis ELFs, with 1,884 symbol records and 582 function byte ranges checked against memory. |
| Sockets and terminals | Sockscan recovered ten controlled IPv4/IPv6 TCP/UDP endpoints. Tty_Check recovered driver devices and a Unix98 PTY pair. |
| Kernel objects | Notifier traversal recovered the callback at its known address. Sysfs module discovery returned correct structure addresses for 110 reference modules. |
| Memory and graphics | Malfind detected controlled executable mappings and dirty pages with exact page extraction. Fbdev matched all 2,073,600 reference pixels. |

LibraryList matched nine library load addresses. Ptrace, PerfEvents and CheckTracepoints were checked with a known tracer/tracee pair, a BPF-attached perf event and registered tracepoint callbacks.

## Kmsg validation

The fix and five unit tests from **ricardojrdez**'s [PR #2101](https://github.com/volatilityfoundation/volatility3/pull/2101) were applied with AArch64 support retained. The fix reads the newest printk descriptor and bounds traversal by the ring size.

Comparisons on eight physical Pi captures spanning kernel series 6.8, 6.12, 6.17, 6.18, 7.0 and 7.2 recovered one missing final row per capture (**6,233 → 6,241 rows**). All preceding rows remained identical. Added messages and timestamps matched capture-time `dmesg`; message text also matched direct reads of the head descriptor. All five unit tests passed.

## Observed behavior

- **MountInfo:** nsfs mounts can display `/` instead of the namespace identifier in `ROOT`; the mounts are listed.
- **PsScan:** all 144 reference PID/PPID pairs matched; 19 reference process names (`comm`) differed.
- **File recovery:** InodePages and RecoverFs recover pages present in the capture. The representative sample's file was recovered through Maps.
