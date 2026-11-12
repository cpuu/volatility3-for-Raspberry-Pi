# Memory dump samples

Seven representative memory dumps from the Raspberry Pi 4 experiments are listed below. All files are original Snappy-compressed AVML captures. Sizes are rounded decimal GB (1 GB = 1,000,000,000 bytes).

| Distribution | Kernel | Size (GB) | SHA-256 |
|---|---|---:|---|
| Ubuntu 24.04.5 LTS | 6.8.0-1064-raspi | 6.40 | `387bad4bbdc47618ecf3ae642d4a0e1df5461ea3e8e49b0c8507a34a3d51db03` |
| Ubuntu 24.04.5 LTS | 6.8.0-1068-raspi | 6.48 | `d7f3c905115610fce465d0f92a094442fabc1259a272ef306194589fffd77b4a` |
| Ubuntu 24.04.5 LTS | 6.17.0-1021-raspi | 6.35 | `57e211ea93c2f80361ad0d0b200c8fb8366e14845afe9f4382e55bf23547810a` |
| Ubuntu 24.04.5 LTS | 7.0.0-1023-raspi | 6.42 | `c99672c9b85fbe26884080f6ad40029d1b7d628860b0b49b7624b58c3e9a95e7` |
| Raspberry Pi OS 64-bit (Debian 13 / Trixie) | 6.18.60-rpt-rpi-v8-volab | 2.09 | `c5daccbe3f46835f73a744fae52419373b4c9dcc900ab9bade166f844eaac22d` |
| Kali Linux 2026.3 | 6.12.34-kali-rpi-v8 | 3.20 | `2a55bb273bbd65a47dc3ce56a405d417338a89d425bde864ee15b9fb9cc29696` |
| Fedora 45 Server | 7.2.11-300.fc45.aarch64 | 1.05 | `10ce77b5acad954d65f0466aab6906913198cd5e6720831954955273365b9a49` |

Due to their size, these dumps are not hosted directly in this repository. To request access, email [cpuu@korea.ac.kr](mailto:cpuu@korea.ac.kr), and I will arrange a way to share the requested files. After downloading, verify that each file's SHA-256 matches the value above before using it.

## Analyzing a sample

The example below uses the Ubuntu `7.0.0-1023-raspi` sample. On Linux, use the [AVML 0.21.0 binary](https://github.com/microsoft/avml/releases/tag/v0.21.0) for your host architecture, saved as `./avml`. Verify the compressed original, then [convert it to LiME](https://github.com/microsoft/avml/tree/v0.21.0#to-decompress-an-avml-compressed-image):

```sh
set -eu
printf '%s  %s\n' c99672c9b85fbe26884080f6ad40029d1b7d628860b0b49b7624b58c3e9a95e7 memory.avml | sha256sum -c -
chmod +x ./avml
./avml convert memory.avml memory.lime
```

Use the converted `memory.lime` on the analysis host. From this repository's root, run:

```sh
uv sync --locked --extra full
uv run --locked --extra full python vol.py -s symbols -f /path/to/memory.lime linux.pslist.PsList
```

For this exact Ubuntu `7.0.0-1023-raspi` sample, the command above should list **167 processes** (167 data rows, excluding the header), matching the recorded PsList result.

Matching ISFs are included in [symbols/linux](symbols/linux); Volatility selects the matching kernel symbols automatically. Other samples use the same commands with their own checksum and file path.
