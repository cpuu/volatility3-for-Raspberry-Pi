# Raspberry Pi integration validation

Date: 2026-11-12. Integration base: `f3a6fd4c`. Validation runtime: Python 3.12.14, Volatility 3 Framework 2.28.3 on Apple Silicon macOS.

**56/56 executions passed**: seven bundled plugins on eight existing physical Pi captures. **78/78 unit tests passed**. CLI discovery lists all seven `linux.rpi.*` commands without an external plugin directory.

## Scope and method

The standalone implementation was split into seven plugin modules and shared helpers under `volatility3/framework/plugins/linux/rpi/`. The bundled tests import the same `volatility3.plugins.linux.rpi` namespace used by the CLI. Every dump command invokes this checkout's `vol.py`, uses the matching ISF and omits `-p`. Each nonempty JSON result is compared in full with the corresponding previously validated research output, including values, status fields and addresses. The historical Model baseline's `Manufacturer` column is normalized to `BoardManufacturer` before comparison.

This is a regression check against existing evidence, not a new independent ground-truth measurement. All captures were collected from the same Raspberry Pi 4 Model B Rev 1.4. Physical Pi 5 support has not been validated.

## Results

All cells below are **passing output row counts**, not counts of supported devices or individual assertions.

| Dump | Rpi | Model | Boot | Interfaces | Console | Firmware | DtChanges |
|---|---:|---:|---:|---:|---:|---:|---:|
| 6.8.0-1068-raspi | 2078 | 1 | 1 | 25 | 1 | 1 | 1 |
| 6.17.0-1021-raspi | 2121 | 1 | 1 | 25 | 1 | 1 | 1 |
| 7.0.0-1023-raspi | 2121 | 1 | 1 | 25 | 1 | 1 | 1 |
| raspberrypios-validation-20261111 | 2123 | 1 | 1 | 25 | 1 | 1 | 1 |
| kali-validation-20261111 | 2121 | 1 | 1 | 25 | 1 | 1 | 1 |
| fedora-validation-20261111 | 1553 | 1 | 1 | 23 | 1 | 1 | 1 |
| 6.8.0-1064-raspi | 2078 | 1 | 1 | 25 | 1 | 1 | 1 |
| 7.0.0-1017-raspi | 2126 | 1 | 1 | 25 | 1 | 1 | 1 |

- Rpi EEPROM configuration bytes remain unavailable in all eight captures; the diagnostic rows match the baseline. Positive recovery is covered by synthetic LiME input.
- DtChanges reports no substantive differences in all eight captures after generated-name filtering. Added/removed/modified properties and malformed input are covered by synthetic tests.
- All 78 tests, including existing plugin behavior and negative cases, passed against the repository copy.

## Recorded example

Ubuntu `6.8.0-1068-raspi`, bundled `linux.rpi.dtchanges.DtChanges`, no external plugin path:

```text
Volatility 3 Framework 2.28.3

Change	Path	Property	BootValue	LiveValue	Status

No changes					boot=1754; live=2077; unchanged=1754; generated-name=323
```

## Evidence and reproduction

- [Portable run summary](doc/rpi-validation-20261112/summary.json): all 56 exit codes, row counts, equality checks, durations and output SHA-256 hashes.
- [Unit-test log](doc/rpi-validation-20261112/unit-tests.txt).
- [Actual text output](doc/rpi-validation-20261112/dtchanges-example.txt).
- [Regression runner](development/rpi_regression.py) and [commands / required local data](RPI_USAGE.md#tests-and-regression).

Full output, stderr and exact per-run commands are retained in the local `rpi-repository-integration-20261112/modular-results` directory. The captures and historical baselines are not packaged in this repository; the dump regression requires that research workspace. Unit tests need no captures.

Validated source file SHA-256 hashes:

```text
{
  "volatility3/framework/plugins/linux/rpi/__init__.py": "ba61a2a1308d7f93a1c4aee954de582f70f9a36e0754747e58a04cd4b7868f1d",
  "volatility3/framework/plugins/linux/rpi/boot.py": "019fd5accaa08b9d485efdff27643c470ff7ea6142895ad2566e00e316b3d82f",
  "volatility3/framework/plugins/linux/rpi/common.py": "b58dee4655e7e4c7bb9eaedd0cbe68c0a01922fdc628277bc8a1a49d3cb713bc",
  "volatility3/framework/plugins/linux/rpi/console.py": "9478c8d1896cbe20d56c617463813525032c276b8220cff01d2c459b50339212",
  "volatility3/framework/plugins/linux/rpi/dtchanges.py": "f4bb0226215b7829ed8c4f5b13daef08d61b381f2d5b5f8b1a61047f4e005d0a",
  "volatility3/framework/plugins/linux/rpi/firmware.py": "1ddc87b40a46727530ac0ad506518340f4101c628121c165f2ca6a70adaf6089",
  "volatility3/framework/plugins/linux/rpi/interfaces.py": "7acd56a3e4427772d18d931f58fdfb1fd0a44afa3f2a044d34e9d537c41773e5",
  "volatility3/framework/plugins/linux/rpi/model.py": "0d815f95f29e54121bf158457e3ef60775c1f00ce9809c3d4ab2c9c641c448b9",
  "volatility3/framework/plugins/linux/rpi/rpi.py": "bf43cd0e4f1e4258c977e00daaac8046fc29e17f605321e7155cf5c136a78d14"
}
```
