# Linux plugin validation

Results as of 2026-11-10: **48 of 49 distinct Linux plugins verified** on Raspberry Pi 4 for the cases described here. `Check_idt` is excluded because it inspects the x86 Interrupt Descriptor Table, which has no AArch64 equivalent for this plugin to inspect.

## Environment

- Raspberry Pi 4 Model B Rev 1.4, 8 GB RAM
- Ubuntu 24.04.5 LTS, AArch64, 4 KB pages, 48-bit virtual addresses
- Tested kernels: `6.8.0-1064-raspi`, `6.8.0-1068-raspi`, `6.17.0-1021-raspi`, `7.0.0-1023-raspi`
- AVML 0.21.0 compressed captures; matching [kernel ISFs](symbols/linux)
- Analysis on Apple Silicon macOS with Python 3.12.14 and `uv sync --locked --extra full`

The tests used several captures from the same Pi configuration, including controlled processes, sockets, tracing events and a no-op kernel notifier. The QEMU and image-format experiments are separate from this plugin validation.

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

## Reboot check (2026-11-10)

The Pi was rebooted into the same 1064 kernel and a fresh AVML capture was analyzed with the existing ISF. Kernel addresses and PIDs changed; all 48 applicable plugins completed. Selected reference checks matched for 41 plugins. Fbdev matched the dump's raw pixels exactly, although 16 pixels differed from live screen references, consistent with a cursor change during acquisition. Kmsg omitted the final message (see below). Five detectors had no positive fixture in this capture, so their runs establish execution only.

All 145 stable PID/parent-PID pairs, ten controlled sockets and six Bash history entries were recovered. The new test file was restored exactly by both InodePages and RecoverFs. A default full RecoverFs run completed in 95 seconds, producing a readable 123 MB gzip archive with 18,447 entries; the known 2,075-byte file matched its reference hash.

**Kthreads clarification:** PID 2 (`kthreadd`) is an expected exclusion from function enumeration: its readable `struct kthread` has a NULL `threadfn`. It is present in the task list. All 132 eligible tasks matched Kthreads output, including all 112 stable eligible tasks; counting PID 2 as a missing function was incorrect.

## Remaining limits

- **Kmsg:** a confirmed off-by-one can omit the final message. The fix and Intel reproduction remain pending.
- **RecoverFs:** full recovery runs complete, but only cached file contents are recoverable; unavailable pages may be skipped.
- **PerfEvents:** reports BPF-attached events only.
- **Detection controls:** Check_afinfo, Check_creds, Check_modules and Hidden_modules were checked with simulated changes during analysis, not live rootkit captures.
- **ModuleExtract:** produces analysis ELFs, not reloadable `.ko` files.
- **Coverage:** validation covers the listed Pi kernels and exercised options. Other configurations and Intel Linux remain untested.
