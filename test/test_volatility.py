# volatility3 tests
#

#
# IMPORTS
#

import os
import subprocess
import sys
import tempfile
import contextlib
import functools
from typing import List, Tuple

#
# HELPER FUNCTIONS
#


@functools.lru_cache
def runvol(args, volatility, python):
    volpy = volatility
    python_cmd = python

    cmd = (python_cmd, volpy) + args
    print(" ".join(cmd))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    print("stdout:")
    sys.stdout.write(str(stdout))
    print("")
    print("stderr:")
    sys.stdout.write(str(stderr))
    print("")

    return p.returncode, stdout, stderr


@functools.lru_cache
def runvol_plugin(
    plugin, img, volatility, python, pluginargs: Tuple = (), globalargs: Tuple = ()
):
    args = (
        globalargs
        + (
            "--single-location",
            img,
            "-q",
            plugin,
        )
        + pluginargs
    )

    return runvol(args, volatility, python)


def runvolshell(img, volshell, python, volshellargs=None, globalargs=None):
    volshellargs = volshellargs or []
    globalargs = globalargs or []
    args = (
        globalargs
        + (
            "--single-location",
            img,
            "-q",
        )
        + volshellargs
    )

    return runvol(args, volshell, python)


def match_output_row(
    json_out: List[dict], expected_row: dict, exact_match: bool = False
):
    """Search each row of a plugin's JSON output for an expected row. Each row is a dict.

        Args:
            json_out: The plugin's output in JSON format (typically obtained through -r json and json.loads)
            expected_row: The expected row to be found in the output
            exact_match: Whether to require exactly the expected row, no more no less, or to anticipate columns' addition by checking only
    the expected row keys and values
    """

    if not exact_match:
        for row in json_out:
            if all(item in expected_row.items() for item in row.items()):
                return True
    else:
        for row in json_out:
            if expected_row == row:
                return True

    return False


#
# TESTS
#


def basic_volshell_test(image, volatility, python, globalargs):
    # Basic VolShell test to verify requirements and ensure VolShell runs without crashing

    volshell_commands = [
        "print(ps())",
        "exit()",
    ]

    # FIXME: When the minimum Python version includes 3.12, replace the following with:
    # with tempfile.NamedTemporaryFile(delete_on_close=False) as fd: ...
    fd, filename = tempfile.mkstemp(suffix=".txt")
    try:
        volshell_script = "\n".join(volshell_commands)
        with os.fdopen(fd, "w") as f:
            f.write(volshell_script)

        rc, out, _err = runvolshell(
            img=image,
            volshell=volatility,
            python=python,
            volshellargs=("--script", filename),
            globalargs=globalargs,
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.remove(filename)

    assert rc == 0
    assert out.count(b"\n") >= 4

    return out


# MAC
# TODO: Migrate and integrate in testing (once analysis is fixed ?)


def test_mac_volshell(image, volatility, python):
    basic_volshell_test(image, volatility, python, globalargs=["-m"])


def test_mac_pslist(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.pslist.PsList", image, volatility, python)
    out = out.lower()

    assert (out.find(b"kernel_task") != -1) or (out.find(b"launchd") != -1)
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_check_syscall(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_syscall.Check_syscall", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"chmod") != -1
    assert out.find(b"chown") != -1
    assert out.find(b"nosys") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_check_sysctl(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_sysctl.Check_sysctl", image, volatility, python
    )
    out = out.lower()

    assert out.find(b"__kernel__") != -1
    assert out.count(b"\n") > 250
    assert rc == 0


def test_mac_check_trap_table(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.check_trap_table.Check_trap_table", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"kern_invalid") >= 10
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_ifconfig(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.ifconfig.Ifconfig", image, volatility, python)
    out = out.lower()

    assert out.find(b"127.0.0.1") != -1
    assert out.find(b"false") != -1
    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_lsmod(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.lsmod.Lsmod", image, volatility, python)
    out = out.lower()

    assert out.find(b"com.apple") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_lsof(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.lsof.Lsof", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_malfind(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.malfind.Malfind", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 20
    assert rc == 0


def test_mac_mount(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.mount.Mount", image, volatility, python)
    out = out.lower()

    assert out.find(b"/dev") != -1
    assert out.count(b"\n") > 7
    assert rc == 0


def test_mac_netstat(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.netstat.Netstat", image, volatility, python)

    assert out.find(b"TCP") != -1
    assert out.find(b"UDP") != -1
    assert out.find(b"UNIX") != -1
    assert out.count(b"\n") > 10
    assert rc == 0


def test_mac_proc_maps(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.proc_maps.Maps", image, volatility, python)
    out = out.lower()

    assert out.find(b"[heap]") != -1
    assert out.count(b"\n") > 100
    assert rc == 0


def test_mac_psaux(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.psaux.Psaux", image, volatility, python)
    out = out.lower()

    assert out.find(b"executable_path") != -1
    assert out.count(b"\n") > 50
    assert rc == 0


def test_mac_socket_filters(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.socket_filters.Socket_filters", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 9
    assert rc == 0


def test_mac_timers(image, volatility, python):
    rc, out, _err = runvol_plugin("mac.timers.Timers", image, volatility, python)
    out = out.lower()

    assert out.count(b"\n") > 6
    assert rc == 0


def test_mac_trustedbsd(image, volatility, python):
    rc, out, _err = runvol_plugin(
        "mac.trustedbsd.Trustedbsd", image, volatility, python
    )
    out = out.lower()

    assert out.count(b"\n") > 10
    assert rc == 0
