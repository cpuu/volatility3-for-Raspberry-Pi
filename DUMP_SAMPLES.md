# Memory dump samples

Nine captures are documented here: the current GPIO/Linux forensic demo is **uncompressed LiME**, while the eight earlier samples below are original Snappy-compressed AVML files. Sizes are rounded decimal GB (1 GB = 1,000,000,000 bytes).

## Representative GPIO and Linux forensic demo

| Field | Recorded value |
|---|---|
| Capture date | 2026-11-19 |
| Distribution | Ubuntu 26.04.1 LTS, AArch64 |
| Board | Raspberry Pi 4 Model B Rev 1.4, 8 GB |
| Kernel / page size | `7.0.0-1023-raspi` / 4,096 bytes |
| Kernel Build ID | `e1460768fbd96b9063864daf8330650751eb2f09` |
| Acquisition | AVML 0.21.0, `/proc/kcore`, uncompressed LiME |
| Filename / size | `memory.lime` / 8,443,150,080 bytes (8.44 GB) |
| SHA-256 | `bc195a3b0232aa1020ddb396a45750cc30d5bddd249344e8d316dbc876c157d9` |
| Analysis commit | `26cee65355d4ad441603969d34428786700553db` |
| ISF | [`ubuntu-7.0.0-1023-raspi-arm64.json.xz`](symbols/linux/ubuntu-7.0.0-1023-raspi-arm64.json.xz) |
| ISF SHA-256 | `07e46196ade1e3f73c5ca2c1a841db1f6f308007af02ea2314dcc6573972f708` |
| Local archive, relative to the experiment workspace | `pi4-demo-candidate-20261119/retry/capture/memory.lime` |
| Availability | Local validation candidate; not uploaded or released for download |

Pi and Mac SHA-256 values matched. The same capture's `before.json` and `after.json` are preserved with the dump. The accompanying `analysis/`, `validation.json`, `general-linux-validation.json`, `maps-recovery-validation.json`, `candidate.json` and `EVIDENCE-SHA256SUMS` record the commands and comparisons.

Verified artifacts: gpio-sim controller `volab-userspace-20261112` (six default/eight detailed rows); board model; 229 enumerated processes and the controlled `sudo 5867 → python3 5905 → gpio-user 5920 / avml 5922` chain; Python's localhost LISTEN/ESTABLISHED endpoints on ports 48791/51386; SSH listener ownership; the marker file's PID/FD/path/inode; and its 39-byte content recovered with `linux.proc.Maps`, with SHA-256 `4aecf752c1098b10e5db0a7e804867aa2ab5fd8e5ac427c761ca8da487d7b49c` matching the live reference.

This is not a successful InodePages recovery example: the marker's recorded page cache was empty. GPIO refers to simulated-controller kernel state, not measured pin voltage. Transient process sets differ during live acquisition, and some system-process argument strings are incomplete. See [the current commands and observed output](README.md#analyzing-a-sample).

## Earlier compressed AVML captures

| Distribution | Kernel | Size (GB) | SHA-256 |
|---|---|---:|---|
| Ubuntu 24.04.5 LTS | 6.8.0-1064-raspi | 6.40 | `387bad4bbdc47618ecf3ae642d4a0e1df5461ea3e8e49b0c8507a34a3d51db03` |
| Ubuntu 24.04.5 LTS | 6.8.0-1068-raspi | 6.48 | `d7f3c905115610fce465d0f92a094442fabc1259a272ef306194589fffd77b4a` |
| Ubuntu 24.04.5 LTS | 6.17.0-1021-raspi | 6.35 | `57e211ea93c2f80361ad0d0b200c8fb8366e14845afe9f4382e55bf23547810a` |
| Ubuntu 24.04.5 LTS | 7.0.0-1023-raspi | 6.42 | `c99672c9b85fbe26884080f6ad40029d1b7d628860b0b49b7624b58c3e9a95e7` |
| Ubuntu 26.04.1 LTS | 7.0.0-1017-raspi | 3.73 | `068a0116e49bfeb7dd50b7aec2041d88cc99d8ca3cab6af207df647059309442` |
| Raspberry Pi OS 64-bit (Debian 13 / Trixie) | 6.18.60-rpt-rpi-v8-volab | 2.09 | `c5daccbe3f46835f73a744fae52419373b4c9dcc900ab9bade166f844eaac22d` |
| Kali Linux 2026.3 | 6.12.34-kali-rpi-v8 | 3.20 | `2a55bb273bbd65a47dc3ce56a405d417338a89d425bde864ee15b9fb9cc29696` |
| Fedora 45 Server | 7.2.11-300.fc45.aarch64 | 1.05 | `10ce77b5acad954d65f0466aab6906913198cd5e6720831954955273365b9a49` |

The eight earlier compressed captures are not hosted directly in this repository due to their size. To request access, email [cpuu@korea.ac.kr](mailto:cpuu@korea.ac.kr), and I will arrange a way to share the requested files. After downloading, verify that each file's SHA-256 matches the value above before using it.

The README examples now use the uncompressed demo above. For an earlier compressed capture, use the matching ISF and convert to LiME with AVML 0.21.0 if needed; its PIDs, ports and GPIO rows differ from the demo.
