# Contributions

This fork is maintained by [Jaeyou Park (cpuu)](https://github.com/cpuu). It builds on Volatility 3 and Abyss-W4tcher's experimental AArch64 support. The contribution is the integration, analysis fixes, Raspberry Pi artifacts and validation described below; the underlying framework and original AArch64 implementation are not new work by this project.

Scope: committed source at `1df974ca` (2026-11-16). Local, uncommitted AVML changes are outside this account. Setup and examples remain in [README](README.md); test conditions and known limitations remain in [TESTING](TESTING.md).

## Inherited foundations

- [Volatility 3](https://github.com/volatilityfoundation/volatility3): framework, existing Linux plugins, object and symbol APIs. The integration basis is upstream commit [`77ff0b19`](https://github.com/volatilityfoundation/volatility3/commit/77ff0b1932d77527f850c8ced01d85805ea7bf97).
- [Abyss-W4tcher's AArch64 implementation, PR #1088](https://github.com/volatilityfoundation/volatility3/pull/1088), based on [`5ee05ce7`](https://github.com/Abyss-W4tcher/volatility3/commit/5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4): original architecture support, which already included physical-device testing.
- AVML and dwarf2json are external acquisition and symbol-generation tools, not tools authored by this project.

## Work added in this fork

| Area | Contribution |
| --- | --- |
| Integration | Adapted the existing AArch64 work to newer Volatility code. Of the original 49 Linux plugins evaluated, 23 needed architecture declarations, 16 needed plugin or shared-core fixes, nine needed no additional changes, and the x86-only IDT plugin was inapplicable. These are coverage categories, not 48 newly written plugins. |
| Analysis fixes | Address-range handling, PID bounds, kernel-thread attribution, kallsyms decoding, syscall analysis, socket candidates, sparse-memory page conversion, module reconstruction and framebuffer decoding. Changes to shared code can benefit several plugins. |
| Pi artifacts | Added live Device Tree recovery and Pi-specific interpretation, retained-boot-FDT comparison, and GPIO descriptor analysis. Eight CLI plugins expose these capabilities; several share the same DT reader. See the [catalog](RPI_PLUGINS.md). |
| Validation | Acquired physical Pi 4 captures across the documented distributions, generated matching ISFs, and compared selected results with capture-time references and controlled fixtures. Existing regression runs measure consistency separately from correctness. |

Four representative fixes provide focused before/after comparison points:

| Existing capability | Change introduced here | Commit |
| --- | --- | --- |
| Bash history recovery | Preserve full configured ARM64 user-address ranges and enable the existing Bash plugin. | [`c1e71ae0`](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/c1e71ae03420db472039783c2cab70499055bdb8) |
| Process scanning | Correct PID bounds and enable AArch64 scanning. | [`9f6a9567`](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/9f6a95674d47017915fd160fba3d003d50ec033a) |
| Socket scanning | Reject unresolved candidates and deduplicate actual socket addresses rather than a placeholder; enable AArch64. | [`2a689f87`](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/2a689f879114e8202bd28090beadf6cc317017d4) |
| Cached-file recovery | Resolve ARM64 sparse-memory `struct page` addresses, enabling existing InodePages/RecoverFs code to recover resident file contents. | [`6890b9fd`](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/6890b9fd4e282058b7a5ce4efd66c6e9836290db) |

The Pi plugin family was introduced in [`33f58b51`](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/33f58b5185eff00ce71e3fbd4f8b8be122b993e0), followed by GPIO in [`56a01b48`](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/56a01b48020a3e4f8ea3e6af6a58c03dffa00785). Commit links identify the changes, not independent proof of their accuracy; the validation conditions are documented separately.

## Boundaries

Hardware evidence covers one physical Pi 4, not Pi 5 or all AArch64 configurations. GPIO reports consumer labels and cached request/configuration state, not process attribution or electrical levels; controlled userspace lifecycle experiments used gpio-sim on Pi and QEMU. EEPROM configuration recovery and substantive DT-change positive cases have synthetic coverage but were not demonstrated in the eight historical physical captures. A successful exit, an empty detector output or an unchanged regression result alone is not proof of forensic correctness.
