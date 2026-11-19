# Volatility 3 Testing Framework

## Requirements

The Volatility 3 Testing Framework requires the same version of Python as Volatility 3 itself. To install the current set of dependencies that the framework requires, use a command like this:

```shell
python -m pip install -e ".[test]"
```

## Quick Start: Manual Testing

1. To test Volatility 3 on an image, first download one with a command such as:

```shell
curl -sLO "https://github.com/volatilityfoundation/volatility3-test-data/releases/download/v0.0.1/win-10_19041-2025_03.dmp.gz"
gunzip win-10_19041-2025_03.dmp.gz
```

2. In many cases, more symbols are required to be downloaded to the `./volatility3/symbols` directory. 

3. To manually run the tests, run a command, such as:

```shell
python -m pytest ./test/plugins/windows/windows.py --volatility=vol.py --image win-10_19041-2025_03.dmp -k "test_windows and not test_windows_volshell"
```

The above command selects Windows plugin tests, excluding VolShell tests. Some tests require additional samples from the test-data collection. To choose a more specific set of tests, change the phrase after `-k` in this command.

## GitHub Actions

The [image-test workflow](../.github/workflows/test.yaml) runs manually through `workflow_dispatch`. It downloads one Linux image and two Windows images, then runs the plugin and VolShell tests.

The separate [Raspberry Pi integration workflow](../.github/workflows/raspberry-pi.yml) runs synthetic tests on Ubuntu and macOS for pushes and pull requests to `main`, and can also be started manually. It does not use the physical Pi memory samples.
