# GPIO ownership and configuration

`linux.rpi.gpio.Gpio` 1.0.0 reads the live gpiolib device list and GPIO descriptors. It recovers line names, consumer labels, request state and cached kernel configuration. It does not read electrical levels or claim that a peripheral is physically connected.

## Commands

```sh
uv run --no-sync python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.gpio.Gpio
uv run --no-sync python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.gpio.Gpio --all --details
uv run --no-sync python vol.py -s /path/to/symbols -f /path/to/memory.lime linux.rpi.gpio.Gpio --all --chip gpiochip0
```

For a non-Pi Linux simulator dump, add `--allow-generic`. That bypass is explicit and each returned row notes that Pi identity was not established. Default output includes requested lines and diagnostic rows. `--all` includes unrequested lines. Chip numbers are discovered from the dump and can differ between boots; offsets are local to their controller, not global GPIO numbers.

## Output

| Field | Meaning |
|---|---|
| Chip / Controller | Kernel gpiochip id and controller label |
| Offset / LineName | Per-controller line offset and assigned name |
| HeaderPin | Physical header position only for a Pi 4 Model B and its confirmed BCM2711 DT GPIO controller; otherwise `-` |
| Consumer | Kernel-stored consumer label, not a PID or authenticated owner |
| Requested | gpiolib request flag |
| KernelDirection / ActiveLow | Descriptor configuration for requested lines; unrequested lines show `Not requested` |
| Status | Read errors, detached controllers, stale labels, unknown/conflicting flags or generic-Linux mode |
| RawFlags / Flags | `--details`: raw descriptor flags and known bit names |
| DescriptorAddress / ConsumerLayout | `--details`: kernel virtual address and detected label ABI |

The parser reads offsets and types from the matching ISF, detects `char *` versus `gpio_desc_label *`, bounds traversal/strings, checks device-list links and descriptor parent pointers, and reports incomplete reads explicitly. Unknown flag bits are preserved. It does not assume a missing request means the pin is unused: alternate functions and direct hardware access may bypass gpiolib. No PID attribution or pinmux/voltage recovery is implemented.
