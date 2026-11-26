# Contributions

This fork is maintained by [Jaeyou Park (cpuu)](https://github.com/cpuu). It builds on Volatility 3 and Abyss-W4tcher's experimental AArch64 support. The contribution is the integration, analysis fixes, Raspberry Pi artifacts and validation described below.

Setup and examples remain in [README](README.md); test conditions and known limitations remain in [TESTING](TESTING.md).

## Inherited foundations

- [Volatility 3](https://github.com/volatilityfoundation/volatility3): framework, existing Linux plugins, object and symbol APIs. The integration basis is upstream commit [`46d73b64`](https://github.com/volatilityfoundation/volatility3/commit/46d73b64286e6e828903647cc3d284e80724421a), checked on 2026-11-25.
- [Abyss-W4tcher's AArch64 implementation, PR #1088](https://github.com/volatilityfoundation/volatility3/pull/1088), based on [`5ee05ce7`](https://github.com/Abyss-W4tcher/volatility3/commit/5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4): original architecture support.
- [AVML](https://github.com/microsoft/avml) and [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) are external acquisition and symbol-generation tools, not tools authored by this project.
- Kmsg newest-record recovery and its unit tests are adopted from **ricardojrdez**'s [PR #2101](https://github.com/volatilityfoundation/volatility3/pull/2101), still unmerged when incorporated on 2026-11-16.

## Work added in this fork

| Area | Contribution |
| --- | --- |
| Integration | The AArch64 support proposed in [PR #1088](https://github.com/volatilityfoundation/volatility3/pull/1088) in 2024 had received no further commits after October 2024 as of this integration. This project adapted that work to the current Volatility 3 codebase, incorporating the latest official release, [v2.28.2](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2), and subsequent upstream development changes checked on 2026-11-25, through architecture declarations and plugin or shared-core fixes. See [coverage](TESTING.md#coverage) for the breakdown of existing implementations. |
| Analysis fixes | Address-range handling, PID bounds, kernel-thread attribution, kallsyms decoding, syscall analysis, socket candidates, sparse-memory page conversion, module reconstruction and framebuffer decoding. Changes to shared code can benefit several plugins. |
| New Raspberry Pi plugins | **Developed eight new Raspberry Pi-specific plugins in this repository:** Rpi, Model, Boot, Interfaces, Console, Firmware, DtChanges and Gpio. They recover and interpret Device Tree properties, board identity, boot configuration, peripheral and console settings, firmware metadata, retained-boot-FDT differences, and GPIO consumer/configuration state. Several share a common DT reader. See the [catalog](RPI_PLUGINS.md). |
| Validation | Acquired physical Pi 4 captures across the documented distributions, generated matching ISFs, and compared selected results with capture-time references and controlled fixtures. Existing regression runs measure consistency separately from correctness. |

Four representative fixes provide focused before/after comparison points:

| Existing capability | Change introduced here |
| --- | --- |
| Bash history recovery | Preserve full configured ARM64 user-address ranges and enable the existing Bash plugin. |
| Process scanning | Correct PID bounds and enable AArch64 scanning. |
| Socket scanning | Reject unresolved candidates and deduplicate actual socket addresses rather than a placeholder; enable AArch64. |
| Cached-file recovery | Resolve ARM64 sparse-memory `struct page` addresses, enabling existing InodePages/RecoverFs code to recover resident file contents. |

## Boundaries

Hardware evidence covers one physical Pi 4. GPIO reports consumer labels and cached request/configuration state; controlled userspace lifecycle experiments used gpio-sim on Pi and QEMU. EEPROM configuration recovery and substantive DT-change positive cases have synthetic coverage.

## Submission case

This project adapts Linux memory-forensic capabilities to the tested ARM64 captures and adds Raspberry Pi configuration analysis. Four controlled comparisons demonstrate the recovery improvements:

| Capability | Change | Result without → with the fix |
| --- | --- | --- |
| Bash history recovery | ARM64 user-address-range handling | 0/6 → 6/6 known entries, matching PID, process name and timestamps to the second |
| Process scanning | PsScan PID bounds | 105/144 → 144/144 stable reference PID/PPID pairs; PID 171671 recovered |
| Cached-file recovery | ARM64 sparse-memory page conversion | Error and 0 bytes → 2,135 bytes, exactly matching the reference file |
| Socket scanning | Candidate handling and deduplication | Exception → all ten controlled endpoints found once each |

Each comparison used the same memory dump and symbols, comparing the integrated implementation with a version in which the relevant fix was reversed while ARM64 support remained enabled.

The Raspberry Pi plugins recover and interpret Device Tree properties, compare retained boot-time FDT with the live Device Tree, and recover GPIO consumer labels and cached configuration from gpiolib descriptors. The [representative sample](DUMP_SAMPLES.md#representative-gpio-and-linux-forensic-demo) demonstrates board identification, GPIO state, processes, sockets and file artifacts, including 39 bytes recovered through Maps with a matching reference SHA-256. The [evidence matrix](TESTING.md#evidence-matrix) documents the validation method for each capability.
