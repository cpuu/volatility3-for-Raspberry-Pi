# Linux plugin validation

## Fixed environment and completed round

Use this file as the working record; update README only after the validation results have been reviewed. **Current stage: declaration-only round completed on 2026-11-06: 100 executions, followed by reference checks and failure triage.** Historical results remain at the end.

Use one physical Pi configuration and one frozen capture for the full matrix. This is the project's existing baseline, not a claim about the most widely deployed Pi setup.

| Component | Fixed baseline |
|---|---|
| Hardware | Raspberry Pi 4 Model B Rev 1.4, 8 GB RAM |
| OS / kernel | Ubuntu 24.04.5 LTS, AArch64 / `6.8.0-1064-raspi` (`6.8.0-1064.68`) |
| Memory | 4 KB pages, 48-bit virtual addresses |
| Acquisition | AVML 0.21.0, `/proc/kcore`, **Snappy-compressed AVML** |
| Capture | Existing physical-Pi capture `pi4-compressed-001/memory.avml`, acquired 2026-11-06; reused unchanged |
| ISF | [ubuntu-6.8.0-1064-raspi-arm64.json](symbols/linux/ubuntu-6.8.0-1064-raspi-arm64.json) |
| Required kernel Build ID for this ISF | `6567d5728de9f4aef1f4a274d212369cfae2ff57` |
| Analysis host | Apple Silicon Mac, Python 3.12.14, uv, locked `full` dependencies |
| Inventory / baseline code revision | `432fd3f2a6f48684a272631f83ff2109ea804009` |

The initial plan proposed a new uncompressed capture. This round instead reuses the existing controlled **physical-Pi compressed AVML capture**, with its before/after process, mappings, socket and other references. No new acquisition was performed. QEMU and Raw experiments are not part of this matrix.

- Dump SHA-256: `9d39f26b77ca43b8866f3b3ee6af6432455f9cd18c11f75f0dc0eb66f516562e` (6,445,438,988 bytes).
- ISF SHA-256: `ee3d54aa8b55615a84560008e0ae5ffa06df0febc027378a0b4f8efd41353bbd`.
- Probe: PID `171671`, PPID `1`, name `arm64-probe`; ten controlled IPv4/IPv6 TCP/UDP socket descriptors.
- Analysis uses the locked full-dependency environment, offline mode and `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib` for Snappy.

## Inventory and counting method

Counted on 2026-11-06 using:

```sh
uv run --locked --extra full python vol.py --help
```

Count unique command names beginning with `linux.` in the plugin listing, not Python files or text occurrences. The command completed with exit code 0 and empty stderr. Architecture declarations were read from each class's `get_requirements()` including shared constants; no memory analysis was executed for this inspection.

| Measure | Count |
|---|---:|
| Linux CLI entries | **60** |
| Deprecated compatibility aliases | 11 |
| Distinct implementations | **49** |
| Canonical implementations allowing AArch64 in their kernel requirement | 8 |
| Canonical implementations declaring Intel architectures only | 40 |
| Canonical implementation without a kernel architecture requirement (`vmcoreinfo`) | 1 |

A declaration is not a runtime correctness verdict. An Intel-only requirement can reject ARM64 before the algorithm runs; this does not establish that the algorithm is inherently Intel-specific. Alias rows point to existing implementations and must not inflate functional coverage.

## PsList source comparison (2026-11-06)

This comparison separates the original ARM64 work from later upstream changes and our integration.

| Comparison | PsList change |
|---|---|
| Original branch merge base `e76d51251be922bb364f10f3fc04f7bfe06c759a` → Abyss-W4tcher `5ee05ce7b440c0d6a0d45f7f9a343b702c7b38e4` | **None**; `pslist.py` has the identical Git blob `1888bd7b834830058bd2a874953c6da8b314b257` |
| Pinned upstream `77ff0b1932d77527f850c8ced01d85805ea7bf97` → our integration | **One requirement change:** add `AArch64` to `architectures` |

```diff
- architectures=["Intel32", "Intel64"],
+ architectures=["Intel32", "Intel64", "AArch64"],
```

The requirement edit was introduced by our integration commit [d9ab4b1f](https://github.com/cpuu/volatility3-for-Raspberry-Pi/commit/d9ab4b1f00919d7e402dde83d8ed09bc2724b53b), not by the pinned original Abyss-W4tcher commit. The original branch's changes relative to its upstream merge base affect only `framework/layers/arm.py` and `framework/automagic/linux.py`.

The [original PR #1088 instructions](https://github.com/volatilityfoundation/volatility3/pull/1088) explicitly tell testers to add AArch64 to the requirements of the plugins they want to use. The author reports testing on virtual/physical Raspberry Pi, Android AVD, Pixel 6A, Jetson and NXP devices and records plugin-specific problems. Thus, absence of committed plugin edits is not evidence that the author did not test; the reported workflow used local declaration changes. These are author-reported results, distinct from our reproductions.

The current PsList task-list traversal, task validation/filtering, field extraction and output logic are unchanged from the pinned upstream. The shared Linux symbol-extension directory is also unchanged from that upstream. These algorithms work on top of the ARM64 translation/discovery layer; this finding does not mean upstream gains ARM64 support from the allowlist edit alone. Historical tests establish ordinary process enumeration, not every optional PsList path such as executable extraction.

This makes declaration-only exploration of other Linux plugins a concrete contribution candidate. The completed round below establishes bounded evidence, not all-option compatibility: validate each implementation and relevant options, and separate genuine architecture dependencies from inherited requirements or unrelated kernel-version defects.

## Validation objective

Determine how many of the 49 distinct Linux implementations actually work on AArch64, including commands whose current requirements list only Intel. **The eight currently enabled commands are the starting evidence, not the boundary of the experiment.**

Treat a missing AArch64 declaration as an untested entry gate, not an architecture incompatibility verdict. Some algorithms may already be portable, others may need ARM64-specific changes, and operations tied to x86-only structures may not apply. Use source history to distinguish inherited declarations, later upstream additions and integration changes; do not infer their provenance or the original author's intent from today's declaration alone.

## Validation protocol and follow-up plan

1. **Preflight all 49 implementations and 11 aliases.** Read help and required arguments; inspect dependency helpers, shared architecture constants, kernel structures, register names, disassembly modes and address assumptions. Plan expected artifacts. Start with generic process/tree, environment, open-file, interface and file/memory-search functionality, then feature-specific and architecture-sensitive code. A reference to an x86 register may require a port; it does not automatically make the analysis concept inapplicable.
2. **Prepare one controlled capture.** Hold a known process tree, command line, environment, open files, file/library mappings and IPv4/IPv6 TCP/UDP sockets. Add benign history/search markers and a known resident file for extraction/page-cache checks. Record optional eBPF, tracing, framebuffer and other prerequisites. Collect before/after references (`ps`, `/proc`, modules, `ip`, `ss`, mounts and kernel logs). Use this same frozen dump and ISF in both tracks below. Cases requiring another capture remain a separately identified follow-up round.
3. **Track A — unchanged baseline.** Start with the established eight, then attempt all other commands with suitable arguments. Preserve requirement rejections as baseline observations, not final unsupported verdicts. Use offline JSON output and a dedicated cache. Start sequentially with 180-second limits; document any 600-second retry for slow scans/extraction.
4. **Track B — declaration-only exploration.** For commands blocked by an Intel-only requirement, use an isolated experimental checkout/branch and add AArch64 only to the relevant allowlist. Record the exact diff and revision and rerun the same case. Do not remove symbol/version checks, falsify layer architecture metadata or change algorithm logic in this track. Trace dependent requirements; if a shared constant must be changed, enumerate every affected command. Keep Track A intact. Commands without an entry gate also receive evidence checks rather than being assumed supported. Explicit x86-only operations may be classified N/A with source evidence; all other candidates remain open for investigation.
5. **Validate output and diagnose failures.** Compare known objects and supported fields against capture-time references. For extraction compare content/hashes; for search recover known markers; for anomaly checks distinguish an expected empty baseline from positive detection. No rootkits or hooks are introduced for this baseline. Declaration-only success with matching references is evidence that the exercised path needed only the gate adjustment. Exceptions or mismatches require diagnosis: separate ARM64-specific logic, generic Linux/kernel-version issues, missing prerequisites and live-capture effects. Lack of a positive fixture remains inconclusive.
6. **Track C — implementation changes where needed.** Record the actual architecture dependency and proposed fix separately from gate changes. Any implementation patch gets a distinct before/after run on the same dump/ISF. Keep partial fixes and results separate; do not silently replace failed baseline output or label an unexplored failure unsupported.
7. **Review here before publishing the README summary.** Count 49 canonical implementations, with 11 alias consistency checks separately. Report unchanged-code results, declaration-only verified results, implementation changes, N/A, and unresolved cases independently. Record the evidence and tested options for each verified result. Keep raw memory and sensitive references outside the public repository.

### Reference checks by group

| Group | Planned evidence |
|---|---|
| Processes, credentials, arguments, environment, history | Long-lived process tree, `/proc/PID` records and benign markers |
| Mappings, ELF/libraries, open files | `/proc/PID/maps`, library paths and descriptor targets |
| Networking | Controlled IPv4/IPv6 TCP/UDP sockets plus `ip` and `ss` |
| Modules, symbols, logs, boot time | Module names, symbol addresses, kernel logs and boot-time records |
| Page cache / extraction | Known resident file, source hash and partial-recovery assessment |
| Regex / YARA | Explicit benign patterns/rules and recorded PID scope |
| eBPF, tracing, graphics, ptrace | Confirm the required feature and target objects exist before judging output |
| Malware/anomaly checks | Baseline expectations; empty output does not validate positive detection |
| Aliases | Same arguments and outcome as their canonical command; deprecation warnings recorded separately |

### Result labels

| Result | Meaning |
|---|---|
| Not run | No execution in this round yet |
| Verified | Expected artifacts and checked fields match references; specify scope |
| Output only | Non-empty output without sufficient independent correctness checks |
| Expected empty | No finding expected in the baseline; not a positive detection test |
| Unexpected empty | Known target was not returned |
| Partial / mismatch | Some expected objects or values differ |
| Architecture-gated | Track A rejected AArch64 before analysis; proceed to Track B unless intrinsically N/A |
| Prerequisite missing | Required symbol, feature, dependency or suitable target absent |
| Input / translation failure | Dump, ISF or kernel layer could not be established |
| Error | Plugin execution exception; retain traceback |
| Timeout | Budget exceeded; retain timing and partial output |
| N/A | Operation intrinsically outside this architecture/configuration; explain why |

For each run, record: track (A/B/C), command/options, dump/ISF hashes, revision and exact patch, exit code, rows, duration, logs/artifacts, checked evidence and final result. New-round statuses are not inherited from prior experiments.

### Final compatibility classification

| Classification | Evidence needed |
|---|---|
| Verified without changes | Track A output matches reference cases |
| Verified with declaration-only change | Track B matches reference cases; algorithm unchanged |
| ARM64 implementation change needed | Identify architecture-dependent logic; record Track C outcome separately |
| Architecture-specific N/A | The operation itself targets an absent architecture feature, e.g. x86 IDT |
| Environment / fixture prerequisite | Feature, symbols, or positive test target missing in this fixed environment |
| Generic issue or unresolved | Explain observed failure; do not attribute it to ARM64 without evidence |

An Intel-only allowlist is never, by itself, sufficient evidence for “ARM64 implementation change needed” or “Architecture-specific N/A.”

## Completed declaration-only experiment

An isolated source snapshot of `432fd3f2a6f48684a272631f83ff2109ea804009` adds AArch64 to **40 requirement declarations in 37 plugin files**. Shared constants, algorithms, symbol helpers and core layers were not changed. An AST comparison, excluding the architecture keyword values, confirms no other source changes. The full 40-declaration patch remains experimental. Following this round, only the six reference-checked implementations listed below were enabled in the public checkout; the other declarations and all algorithm/helper changes remain deferred.

Patch SHA-256: `27ea454ea89aa6e6582b5b132ad4967da7d96178535844aaf75ca7b2f1b650e2`.

All **40** formerly Intel-gated canonical cases failed baseline requirement validation, then reached analysis with the declaration patch. All **49** canonical implementations and **11** aliases were exercised on the same dump. The eight previously enabled plugins were rerun in the snapshot with their own source unchanged; their JSON exactly matches the earlier analysis of this same capture. This is regression evidence, not a second independent acquisition. Eleven aliases matched canonical JSON or, for tty_check, the same failure outcome. No timeout occurred. Runs used two workers and a 180-second limit per command.

### Classification totals (49 implementations)

| Classification | Count |
|---|---:|
| Regression matched | 8 |
| Declaration-only verified (bounded) | 6 |
| ARM64 implementation needed | 5 |
| Mismatch / error; diagnosis open | 7 |
| Architecture-specific N/A | 1 |
| Output only | 11 |
| Empty / insufficient fixture | 11 |

**Six additional implementations have declaration-only success within explicitly checked fields.** Eleven others produced output without enough independent evidence to call them verified. Empty results are not positive compatibility tests. Five implementations have concrete ARM64-specific implementation gaps (one identified in source but not reached by this fixture); seven have mismatches/errors requiring further diagnosis. Some failures may be generic Linux/kernel-version issues, not ARM64 defects.

### Confirmed implementation gaps and unresolved failures

| Area | Evidence and next work |
|---|---|
| Page-cache content (`InodePages`, `RecoverFs`) | Both fail in `framework/symbols/linux/extensions/__init__.py`, `page.to_paddr()`: only `intel.Intel` is accepted. Implement and validate ARM64 struct-page / PFN / vmemmap conversion in the shared helper. This is distinct from listing files, which works for the fixture. |
| Call stacks | `pscallstack.py` reads `task.thread.sp`; the ARM64 ISF lacks that member. Port stack-context access and validate unwind/stack bounds, rather than merely renaming a field. |
| Module extraction | Actual extracted ELF has `e_machine=62`. `framework/symbols/linux/utilities/modules.py` chooses x86 machine types from pointer width. Architecture-aware ELF generation is needed; changing this field alone has not been shown sufficient for a correct reconstructed module. |
| Malfind | The current empty case never reaches disassembly. Source explicitly selects `intel`/`intel64`; AArch64 disassembly support and a positive fixture are needed. This does not establish that region detection itself fails. |
| Kallsyms | `_text` reported at zero, whereas matching vmlinux places it at a high kernel virtual address. The shared decoder assumes absolute-per-CPU semantics for relative offsets. Diagnose the actual encoding; do not call this ARM64-only. Consumers' symbol annotations need rechecking afterward. |
| Syscall checks | Matching vmlinux ELF symbol size is 3,696 bytes / 8 = **462 slots**, but output ends after **400**. The native fallback size heuristic needs correction/validation. Code checks `ia32_sys_call_table`, not the present `compat_sys_call_table`; compatibility-table support is a separate architecture issue. |
| Library enumeration | Zero rows although `elfs` and captured maps confirm libraries. Shared ELF helper assumes a link-map pointer in the second PLTGOT entry. ABI/runtime handling needs investigation; root cause not yet proven. |
| Process and regex scanning | PsScan misses the controlled probe and returns only 105/144 stable PID/PPID pairs. Regex returns zero for a marker YARA finds three times. Investigate scan coverage/layer paths; neither is classified as proven ARM64-only. |
| tty_check / sockscan | Respectively invalid read at address zero and `NoneType.socket` exception. Preserve tracebacks and investigate candidate validation, live-capture consistency and shared helpers. No implementation change was made in this round. |
| check_idt | Analysis of an x86 IDT is intrinsically N/A here. Exit 0 with an ERROR and zero rows is not success. |

### Tested options and evidence limits

PID-scoped cases use `171671`: capabilities (`--pids`), elfs/envars/lsof/malfind/process_spoofing/pscallstack (`--pid`), library_list (`--pids`), and both memory searches (`--pid`). Kallsyms uses `--core`. ModuleExtract targets `tcp_diag` at `0xffffc705430910c0`. Files and InodePages target `/home/ubuntu/volatility3-arm64-lab/captures/pi4-compressed-20261106-001/scenario.py`; InodePages uses `--dump`. RecoverFs uses **`--tmpfs-only`**, not a whole-filesystem recovery. Regex uses `--pattern pi4-compressed-avml`; YARA uses `--yara-string pi4-compressed-avml`. Other cases use default options.

Process reference comparison checks the 144 PID/PPID pairs stable before/after capture. `ps` display names can differ from raw task comm (notably worker names), so general name equality is not claimed; the controlled probe's name is checked. ELF checks cover mapping start/end/path, not extracted binaries. Lsof checks controlled descriptor presence/type/owner, not every inode/time field. Files checks path/size, not recovered content. YARA checks exact marker bytes and PID, not every rule feature. No malicious hooks or hidden objects were introduced.

Local evidence is retained under `pi4-plugin-expansion/`: `results/runs.json` contains every command, options, exit code, timing and row count; per-case JSON/log files preserve output and tracebacks; `results/assessment.json` records reference comparisons; `results/elf-symbol-evidence.json` records matching debug-ELF sizes; `results/declaration-only.patch` and `scripts/` retain the patch and reproduction scripts. These local artifacts and the memory dump are not published in the repository. No Track C implementation fixes or additional captures were performed.

## Selected declaration changes adopted

On 2026-11-06, AArch64 was added to the kernel requirements of `elfs.Elfs`, `lsof.Lsof`, `pstree.PsTree`, `pidhashtable.PIDHashTable`, `pagecache.Files` and `vmayarascan.VmaYaraScan`. The shared `LINUX_ARCHS` constant and the separate `InodePages` / `RecoverFs` requirements were left unchanged. No implementation fixes were included. The matrix below retains the pre-change baseline and experiment results. All six adopted plugins were rerun from the public checkout against the same Pi dump and produced JSON identical to their validated experimental output. Changed-file Ruff lint and format checks passed. Commands and comparison results are retained locally in `pi4-plugin-expansion/results/adopted/`.

## Full CLI matrix

Rows count flattened JSON objects. A zero exit code alone is not a pass. “Regression” means the unchanged plugin was rerun within the patched snapshot. Alias outcomes do not increase the 49-implementation count.

| # | CLI command | Baseline / relationship | Declaration-only run (exit / rows) | Classification | Checked scope / observation |
|---:|---|---|---|---|---|
| 1 | `linux.bash.Bash` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No history recovered; no controlled resident bash-history fixture. |
| 2 | `linux.boottime.Boottime` | Requirement rejection (exit 1) | 0 / 1 | Output only | Boot timestamp returned; independent boot-time reference not captured. |
| 3 | `linux.capabilities.Capabilities` | Requirement rejection (exit 1) | 0 / 1 | Output only | Probe identity matches; capability bitsets lack independent capture-time reference. |
| 4 | `linux.check_afinfo.Check_afinfo` | Alias of `linux.malware.check_afinfo.Check_afinfo`; outcome matches | 0 / 0 | Empty / insufficient fixture | See canonical row; not independent coverage. |
| 5 | `linux.check_creds.Check_creds` | Alias of `linux.malware.check_creds.Check_creds`; outcome matches | 0 / 0 | Empty / insufficient fixture | See canonical row; not independent coverage. |
| 6 | `linux.check_idt.Check_idt` | Alias of `linux.malware.check_idt.Check_idt`; outcome matches | 0 / 0 | Architecture-specific N/A | See canonical row; not independent coverage. |
| 7 | `linux.check_modules.Check_modules` | Alias of `linux.malware.check_modules.Check_modules`; outcome matches | 0 / 0 | Empty / insufficient fixture | See canonical row; not independent coverage. |
| 8 | `linux.check_syscall.Check_syscall` | Alias of `linux.malware.check_syscall.Check_syscall`; outcome matches | 0 / 400 | Mismatch / error; diagnosis open | See canonical row; not independent coverage. |
| 9 | `linux.ebpf.EBPF` | Requirement rejection (exit 1) | 0 / 13 | Output only | 13 entries; no independent BPF inventory/positive fixture. |
| 10 | `linux.elfs.Elfs` | Requirement rejection (exit 1) | 0 / 10 | Declaration-only verified (bounded) | All 10 ELF mapping paths and start/end addresses match captured probe maps; executable extraction not tested. |
| 11 | `linux.envars.Envars` | Requirement rejection (exit 1) | 0 / 11 | Output only | 11 variables; no independent captured environ reference. |
| 12 | `linux.graphics.fbdev.Fbdev` | Requirement rejection (exit 1) | 0 / 1 | Output only | One framebuffer metadata row; image extraction not tested. |
| 13 | `linux.hidden_modules.Hidden_modules` | Alias of `linux.malware.hidden_modules.Hidden_modules`; outcome matches | 0 / 0 | Empty / insufficient fixture | See canonical row; not independent coverage. |
| 14 | `linux.iomem.IOMem` | Already AArch64-enabled | 0 / 61 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 15 | `linux.ip.Addr` | Requirement rejection (exit 1) | 0 / 7 | Output only | Seven addresses; no complete capture-time ip address reference. |
| 16 | `linux.ip.Link` | Requirement rejection (exit 1) | 0 / 4 | Output only | Four interfaces; no complete capture-time ip link reference. |
| 17 | `linux.kallsyms.Kallsyms` | Requirement rejection (exit 1) | 0 / 99389 | Mismatch / error; diagnosis open | 99,389 rows but _text address is 0; relative-offset decoding assumption is suspect. Not established as ARM64-only. |
| 18 | `linux.keyboard_notifiers.Keyboard_notifiers` | Alias of `linux.malware.keyboard_notifiers.Keyboard_notifiers`; outcome matches | 0 / 0 | Empty / insufficient fixture | See canonical row; not independent coverage. |
| 19 | `linux.kmsg.Kmsg` | Already AArch64-enabled | 0 / 948 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 20 | `linux.kthreads.Kthreads` | Requirement rejection (exit 1) | 0 / 127 | Output only | 127 threads; handler/symbol fields not trusted pending kallsyms investigation. |
| 21 | `linux.library_list.LibraryList` | Requirement rejection (exit 1) | 0 / 0 | Mismatch / error; diagnosis open | Zero libraries despite known mapped libraries; DT_PLTGOT/GOT link-map assumption needs investigation. |
| 22 | `linux.lsmod.Lsmod` | Already AArch64-enabled | 0 / 108 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 23 | `linux.lsof.Lsof` | Requirement rejection (exit 1) | 0 / 13 | Declaration-only verified (bounded) | All 10 controlled socket FDs match PID, process name and SOCK type; other metadata not independently verified. |
| 24 | `linux.malfind.Malfind` | Alias of `linux.malware.malfind.Malfind`; outcome matches | 0 / 0 | ARM64 implementation needed | See canonical row; not independent coverage. |
| 25 | `linux.malware.check_afinfo.Check_afinfo` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive anomaly detection not validated. |
| 26 | `linux.malware.check_creds.Check_creds` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive anomaly detection not validated. |
| 27 | `linux.malware.check_idt.Check_idt` | Requirement rejection (exit 1) | 0 / 0 | Architecture-specific N/A | x86 IDT analysis; zero rows plus ERROR about missing IDT entry structure. Not a successful ARM64 test. |
| 28 | `linux.malware.check_modules.Check_modules` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive anomaly detection not validated. |
| 29 | `linux.malware.check_syscall.Check_syscall` | Requirement rejection (exit 1) | 0 / 400 | Mismatch / error; diagnosis open | Only 400 native slots vs 462 in matching vmlinux; ARM compat table is not selected. Requires size/architecture handling investigation. |
| 30 | `linux.malware.hidden_modules.Hidden_modules` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive anomaly detection not validated. |
| 31 | `linux.malware.keyboard_notifiers.Keyboard_notifiers` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive notifier fixture absent. |
| 32 | `linux.malware.malfind.Malfind` | Requirement rejection (exit 1) | 0 / 0 | ARM64 implementation needed | Zero findings in this fixture; source selects intel/intel64 disassembly by pointer width. ARM64 rendering needs a change; positive detection remains untested. |
| 33 | `linux.malware.modxview.Modxview` | Requirement rejection (exit 1) | 0 / 108 | Output only | 108 module rows; no hidden-module positive fixture or full field verification. |
| 34 | `linux.malware.netfilter.Netfilter` | Requirement rejection (exit 1) | 0 / 30 | Output only | 30 entries; hooks and symbol attribution not independently verified. |
| 35 | `linux.malware.process_spoofing.ProcessSpoofing` | Requirement rejection (exit 1) | 0 / 1 | Output only | One probe row; no spoofing-positive fixture or complete field verification. |
| 36 | `linux.malware.tty_check.Tty_Check` | Requirement rejection (exit 1) | 1 / no complete JSON | Mismatch / error; diagnosis open | InvalidAddressException at address 0; cause not established as ARM64-specific. |
| 37 | `linux.module_extract.ModuleExtract` | Requirement rejection (exit 1) | 0 / 1 | ARM64 implementation needed | Produced 36,105-byte tcp_diag ELF with e_machine=62 (x86-64), not 183 (AArch64); successful exit is incorrect output. |
| 38 | `linux.modxview.Modxview` | Alias of `linux.malware.modxview.Modxview`; outcome matches | 0 / 108 | Output only | See canonical row; not independent coverage. |
| 39 | `linux.mountinfo.MountInfo` | Already AArch64-enabled | 0 / 368 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 40 | `linux.netfilter.Netfilter` | Alias of `linux.malware.netfilter.Netfilter`; outcome matches | 0 / 30 | Output only | See canonical row; not independent coverage. |
| 41 | `linux.pagecache.Files` | Requirement rejection (exit 1) | 0 / 1 | Declaration-only verified (bounded) | Known scenario.py path and 2,135-byte size match; content extraction is a separate, failing implementation. |
| 42 | `linux.pagecache.InodePages` | Requirement rejection (exit 1) | 1 / no complete JSON | ARM64 implementation needed | Runtime failure: shared page.to_paddr only handles Intel; LinuxAArch64 vmemmap_start calculation unsupported. |
| 43 | `linux.pagecache.RecoverFs` | Requirement rejection (exit 1) | 1 / no complete JSON | ARM64 implementation needed | Same shared page.to_paddr failure during tmpfs-only recovery; no successful filesystem recovery claimed. |
| 44 | `linux.pidhashtable.PIDHashTable` | Requirement rejection (exit 1) | 0 / 198 | Declaration-only verified (bounded) | All 144 stable PID/PPID pairs and probe identity found among 198 rows; extra thread rows not fully validated. |
| 45 | `linux.proc.Maps` | Already AArch64-enabled | 0 / 3365 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 46 | `linux.psaux.PsAux` | Already AArch64-enabled | 0 / 157 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 47 | `linux.pscallstack.PsCallStack` | Requirement rejection (exit 1) | 1 / no complete JSON | ARM64 implementation needed | Runtime AttributeError for thread_struct.sp; ARM64 stack-context handling must be implemented and validated. |
| 48 | `linux.pslist.PsList` | Already AArch64-enabled | 0 / 157 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 49 | `linux.psscan.PsScan` | Requirement rejection (exit 1) | 0 / 135 | Mismatch / error; diagnosis open | 135 rows; only 105/144 stable PID/PPID pairs and probe missing. Scan coverage issue unresolved. |
| 50 | `linux.pstree.PsTree` | Requirement rejection (exit 1) | 0 / 157 | Declaration-only verified (bounded) | All 144 stable PID/PPID pairs and probe PID/PPID/name match references; process-name presentation differences excluded from the general comparison. |
| 51 | `linux.ptrace.Ptrace` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; controlled ptrace target absent. |
| 52 | `linux.sockscan.Sockscan` | Requirement rejection (exit 1) | 1 / no complete JSON | Mismatch / error; diagnosis open | NoneType.socket exception while walking candidates; no complete socket output. Cause not established as ARM64-specific. |
| 53 | `linux.sockstat.Sockstat` | Already AArch64-enabled | 0 / 597 | Regression matched | Exact JSON match with earlier analysis of this same compressed capture; prior bounded checks retained. |
| 54 | `linux.tracing.ftrace.CheckFtrace` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive tracing fixture absent. |
| 55 | `linux.tracing.perf_events.PerfEvents` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive perf-event fixture absent. |
| 56 | `linux.tracing.tracepoints.CheckTracepoints` | Requirement rejection (exit 1) | 0 / 0 | Empty / insufficient fixture | No finding; positive tracepoint fixture absent. |
| 57 | `linux.tty_check.tty_check` | Alias of `linux.malware.tty_check.Tty_Check`; outcome matches | 1 / no complete JSON | Mismatch / error; diagnosis open | See canonical row; not independent coverage. |
| 58 | `linux.vmaregexscan.VmaRegExScan` | Requirement rejection (exit 1) | 0 / 0 | Mismatch / error; diagnosis open | Zero hits for marker recovered by YARA in the same PID/dump; scan-path discrepancy unresolved. |
| 59 | `linux.vmayarascan.VmaYaraScan` | Requirement rejection (exit 1) | 0 / 3 | Declaration-only verified (bounded) | Three exact marker hits in probe PID 171671; marker independently present in captured command line. |
| 60 | `linux.vmcoreinfo.VMCoreInfo` | No architecture gate | 0 / 0 | Empty / insufficient fixture | No record found; no guaranteed VMCOREINFO record in this live capture. No declaration change needed. |

## Historical validation

### Initial independent-project validation

Date: 2026-11-06. Base: upstream `77ff0b1932d77527f850c8ced01d85805ea7bf97` merged with ARM64 integration `c3ebd40e1863280f608d954651360bc92a763c6f` in `7ced743d`. Analysis host: macOS ARM64, Python 3.12.14, dependencies pinned in uv.lock.

The existing Raspberry Pi 4 AVML 0.21.0 capture and matching ISF were reanalyzed. Capture: Ubuntu 24.04.5 LTS / kernel6.8.0-1064-raspi / 4KB pages / VA_BITS48. Dump SHA256: `bd220dba56b5fd0608c9d93896f09a786da2a5edccba88d5ed5afb3dfd666399`. This is a new analysis of an existing capture, not a new acquisition.

| Plugin | Flattened rows | Exit code | Exact JSON match with previous validated output |
|---|---:|---:|---|
| linux.pslist.PsList | 158 | 0 | True |
| linux.lsmod.Lsmod | 108 | 0 | True |
| linux.iomem.IOMem | 61 | 0 | True |
| linux.kmsg.Kmsg | 836 | 0 | True |
| linux.proc.Maps | 3360 | 0 | True |
| linux.psaux.PsAux | 158 | 0 | True |
| linux.mountinfo.MountInfo | 368 | 0 | True |
| linux.sockstat.Sockstat | 568 | 0 | True |

For sockstat the reference is the earlier separately validated host-family fix output, now officially inherited from upstream. For all others the reference is the prior integration output. Existing limits in README still apply; matching historical output is not independent proof of all values. Raw outputs and memory dumps are not public.

48 synthetic/CLI tests passed. Whole-repository Ruff lint passed and348 Python files passed formatting. No real Intel Linux dump or broader ARM hardware/kernel matrix was tested during this initialization. GitHub Actions additionally runs the synthetic suite on Linux and macOS; those remote results are separate from these local measurements.
