import json
import hashlib
import shutil
import contextlib
import tempfile
import os
from test import test_volatility, WindowsSamples


class TestWindowsVolshell:
    def test_windows_volshell(self, image, volatility, python):
        out = test_volatility.basic_volshell_test(
            image, volatility, python, globalargs=("-w",)
        )
        assert out.count(b"<EPROCESS") > 40


class TestWindowsPslist:
    def test_windows_generic_pslist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pslist.PsList",
            image,
            volatility,
            python,
            # Notice that this is needed to hit lru_cache when "specific" will run
            globalargs=("-r", "json"),
        )
        assert rc == 0
        out = out.lower()
        assert out.find(b"system") != -1
        assert out.find(b"csrss.exe") != -1
        assert out.find(b"svchost.exe") != -1
        assert out.count(b"\n") > 10

    def test_windows_specific_pslist(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pslist.PsList",
            image,
            volatility,
            python,
            globalargs=("-r", "json"),
        )
        assert rc == 0
        expected_row = {
            "CreateTime": None,
            "ExitTime": None,
            "File output": "Disabled",
            "Handles": 1140,
            "ImageFileName": "System",
            "Offset(V)": 2185004992,
            "PID": 4,
            "PPID": 0,
            "SessionId": None,
            "Threads": 61,
            "Wow64": False,
            "__children": [],
        }
        assert test_volatility.match_output_row(expected_row, json.loads(out))


class TestWindowsPsscan:
    def test_windows_generic_psscan(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.psscan.PsScan", image, volatility, python
        )
        assert rc == 0
        out = out.lower()
        assert out.find(b"system") != -1
        assert out.find(b"csrss.exe") != -1
        assert out.find(b"svchost.exe") != -1
        assert out.count(b"\n") > 10


class TestWindowsDlllist:
    def test_windows_generic_dlllist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.dlllist.DllList", image, volatility, python
        )
        assert rc == 0
        out = out.lower()
        assert out.count(b"\n") > 10


class TestWindowsModules:
    def test_windows_generic_modules(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.modules.Modules", image, volatility, python
        )
        assert rc == 0
        out = out.lower()
        assert out.count(b"\n") > 10


class TestWindowsHivelist:
    def test_windows_generic_hivelist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.registry.hivelist.HiveList", image, volatility, python
        )
        assert rc == 0
        out = out.lower()

        not_xp = out.find(b"\\systemroot\\system32\\config\\software")
        if not_xp == -1:
            assert (
                out.find(
                    b"\\device\\harddiskvolume1\\windows\\system32\\config\\software"
                )
                != -1
            )
        assert out.count(b"\n") > 10


class TestWindowsDumpfiles:
    def test_windows_specific_dumpfiles(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        with open("./test/known_files.json") as json_file:
            known_files = json.load(json_file)

        failed_chksms = 0
        file_name = os.path.basename(image)

        try:
            for addr in known_files["windows_dumpfiles"][file_name]:
                path = tempfile.mkdtemp()

                rc, _out, _err = test_volatility.runvol_plugin(
                    "windows.dumpfiles.DumpFiles",
                    image,
                    volatility,
                    python,
                    globalargs=("-o", path),
                    pluginargs=("--virtaddr", addr),
                )

                for file in os.listdir(path):
                    with open(os.path.join(path, file), "rb") as fp:
                        if (
                            hashlib.md5(fp.read()).hexdigest()
                            not in known_files["windows_dumpfiles"][file_name][addr]
                        ):
                            failed_chksms += 1

                shutil.rmtree(path)
            json_file.close()

            assert failed_chksms == 0
            assert rc == 0
        except Exception as e:
            json_file.close()
            print("Key Error raised on " + str(e))
            assert False


class TestWindowsHandles:
    def test_windows_generic_handles(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.handles.Handles",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        assert out.find(b"System Pid 4") != -1
        assert (
            out.find(
                b"MACHINE\\SYSTEM\\CONTROLSET001\\CONTROL\\SESSION MANAGER\\MEMORY MANAGEMENT\\PREFETCHPARAMETERS"
            )
            != -1
        )
        assert out.find(b"MACHINE\\SYSTEM\\SETUP") != -1
        assert out.count(b"\n") > 500


class TestWindowsSvcscan:
    def test_windows_generic_svcscan(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.svcscan.SvcScan", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"Microsoft ACPI Driver") != -1
        assert out.count(b"\n") > 250


class TestWindowsThrdscan:
    def test_windows_generic_thrdscan(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.thrdscan.ThrdScan", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"\t1812\t2768\t0x7c810856") != -1
        assert out.find(b"\t840\t2964\t0x7c810856") != -1
        assert out.find(b"\t2536\t2552\t0x7c810856") != -1


class TestWindowsPrivileges:
    def test_windows_generic_privileges(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.privileges.Privs",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        assert out.find(b"SeCreateTokenPrivilege") != -1
        assert out.find(b"SeCreateGlobalPrivilege") != -1
        assert out.find(b"SeAssignPrimaryTokenPrivilege") != -1
        assert out.count(b"\n") > 20


class TestWindowsGetsids:
    def test_windows_generic_getsids(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.getsids.GetSIDs",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4"),
        )
        assert rc == 0
        assert out.find(b"Local System") != -1
        assert out.find(b"Administrators") != -1
        assert out.find(b"Everyone") != -1
        assert out.find(b"Authenticated Users") != -1


class TestWindowsEnvars:
    def test_windows_generic_envars(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.envars.Envars", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"PATH") != -1
        assert out.find(b"PROCESSOR_ARCHITECTURE") != -1
        assert out.find(b"USERNAME") != -1
        assert out.find(b"SystemRoot") != -1
        assert out.find(b"CommonProgramFiles") != -1
        assert out.count(b"\n") > 500


class TestWindowsCallbacks:
    def test_windows_generic_callbacks(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.callbacks.Callbacks", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"PspCreateProcessNotifyRoutine") != -1
        assert out.find(b"KeBugCheckCallbackListHead") != -1
        assert out.find(b"KeBugCheckReasonCallbackListHead") != -1
        assert out.count(b"KeBugCheckReasonCallbackListHead	") > 5


class TestWindowsVadwalk:
    def test_windows_generic_vadwalk(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.vadwalk.VadWalk", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"Vad") != -1
        assert out.find(b"VadS") != -1
        assert out.find(b"Vadl") != -1
        assert out.find(b"VadF") != -1
        assert out.find(b"0x0") != -1


class TestWindowsDevicetree:
    def test_windows_generic_devicetree(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.devicetree.DeviceTree", image, volatility, python
        )
        assert rc == 0
        assert out.find(b"DEV") != -1
        assert out.find(b"DRV") != -1
        assert out.find(b"ATT") != -1
        assert out.find(b"FILE_DEVICE_CONTROLLER") != -1
        assert out.find(b"FILE_DEVICE_DISK") != -1
        assert out.find(b"FILE_DEVICE_DISK_FILE_SYSTEM") != -1


class TestWindowsVadyarascan:
    def test_windows_specific_vadyarascan_yara_rule(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        yara_rule_01 = r"""
            rule fullvadyarascan
            {
                strings:
                    $s1 = "!This program cannot be run in DOS mode."
                    $s2 = "Qw))Pw"
                    $s3 = "W_wD)Pw"
                    $s4 = "1Xw+2Xw"
                    $s5 = "xd`wh``w"
                    $s6 = "0g`w0g`w8g`w8g`w@g`w@g`wHg`wHg`wPg`wPg`wXg`wXg`w`g`w`g`whg`whg`wpg`wpg`wxg`wxg`w"
                condition:
                    all of them
            }
        """
        fd, filename = tempfile.mkstemp(suffix=".yar")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(yara_rule_01)
            rc, out, _err = test_volatility.runvol_plugin(
                "windows.vadyarascan.VadYaraScan",
                image,
                volatility,
                python,
                pluginargs=("--pid", "4012", "--yara-file", filename),
            )
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.remove(filename)
        assert rc == 0
        assert out.count(b"\n") > 4

    def test_windows_specific_vadyarascan_yara_string(self, volatility, python):
        image = WindowsSamples.WINDOWSXP_GENERIC.value.path
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.vadyarascan.VadYaraScan",
            image,
            volatility,
            python,
            pluginargs=("--pid", "4012", "--yara-string", "MZ"),
        )
        assert rc == 0
        assert out.count(b"\n") > 10
