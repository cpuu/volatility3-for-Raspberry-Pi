# Initial independent-project validation

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
