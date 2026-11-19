# Contributions

This fork is maintained by [Jaeyou Park (cpuu)](https://github.com/cpuu). It builds on Volatility 3 and Abyss-W4tcher's experimental AArch64 support. The contribution is the integration, analysis fixes, Raspberry Pi artifacts and validation described below; the underlying framework and original AArch64 implementation are not new work by this project.

Setup and examples remain in [README](README.md); test conditions and known limitations remain in [TESTING](TESTING.md).

## Inherited foundations

- [Volatility 3](https://github.com/volatilityfoundation/volatility3): framework, existing Linux plugins, object and symbol APIs. The integration basis is upstream commit [`77ff0b19`](https://github.com/volatilityfoundation/volatility3/commit/77ff0b1932d77527f850c8ced01d85805ea7bf97).
- [Abyss-W4tcher's AArch64 implementation, PR #1088](https://github.com/volatilityfoundation/volatility3/pull/1088), based on [`5ee05ce7`](https://github.com/Abyss-W4tcher/volatility3/commit/5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4): original architecture support, which already included physical-device testing.
- AVML and dwarf2json are external acquisition and symbol-generation tools, not tools authored by this project.
- Kmsg newest-record recovery and its unit tests are adopted from **ricardojrdez**'s [PR #2101](https://github.com/volatilityfoundation/volatility3/pull/2101), still unmerged when incorporated on 2026-11-16. This project contributed the [Pi validation](TESTING.md#kmsg-follow-up-2026-11-16), not the original fix.

## Work added in this fork

| Area | Contribution |
| --- | --- |
| Integration | Adapted the existing AArch64 work to newer Volatility code through architecture declarations and plugin or shared-core fixes. See [coverage](TESTING.md#coverage) for the breakdown of existing implementations. |
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

Hardware evidence covers one physical Pi 4, not Pi 5 or all AArch64 configurations. GPIO reports consumer labels and cached request/configuration state, not process attribution or electrical levels; controlled userspace lifecycle experiments used gpio-sim on Pi and QEMU. EEPROM configuration recovery and substantive DT-change positive cases have synthetic coverage.
