from volatility3.plugins.linux.rpi import firmware as rpi
import unittest
B='/chosen/bootloader'
def props():
 return {('/','compatible'):b'raspberrypi,4-model-b\0',(B,'version'):b'69471177ba7e4cb7597cb2496f2a0b23f19c1113\0',(B,'build-timestamp'):bytes.fromhex('681ccbff'),(B,'update-timestamp'):bytes.fromhex('68bfe790')}
class FirmwareTests(unittest.TestCase):
 def test_dates_and_missing_optional_metadata(self):
  self.assertEqual(rpi.firmware_summary(props()),('69471177ba7e...','2025-05-08 15:21:35Z','2025-09-09 08:38:40Z','Not reported','Not reported','Not reported','ok'))
 def test_full_version_in_details(self):self.assertEqual(rpi.firmware_summary(props(),details=True)[0],props()[(B,'version')][:-1].decode())
 def test_unterminated_warning_and_uefi(self):
  p=props();p[('/chosen','user-warnings')]=b'Failed cmdline\n';p[('/chosen','u-boot,version')]=b'2026.10\0';p[('/chosen','linux,uefi-system-table')]=(0x1234).to_bytes(8,'big');r=rpi.firmware_summary(p,details=True);self.assertEqual(r[3:6],('U-Boot 2026.10','Present','Failed cmdline\\n'));self.assertEqual(r[7],'0x1234');self.assertEqual(r[8],b'Failed cmdline\n'.hex())
 def test_invalid_pointer_not_secure_boot_inference(self):
  for raw in (b'\0'*8,b'\1',None):
   p=props();p[('/chosen','linux,uefi-system-table')]=raw;self.assertEqual(rpi.firmware_summary(p)[4],'Unknown')
 def test_alias_timestamp_conflict(self):
  p=props();p[(B,'build_timestamp')]=p[(B,'build-timestamp')];self.assertEqual(rpi.firmware_summary(p)[6],'ok');p[(B,'build_timestamp')]=b'\0\0\0\1';self.assertEqual(rpi.firmware_summary(p)[1],'Not available');self.assertIn('conflicting',rpi.firmware_summary(p)[6])
 def test_zero_bad_and_missing_dates(self):
  p=props();p[(B,'build-timestamp')]=b'\0'*4;p[(B,'update-timestamp')]=b'bad';self.assertEqual(rpi.firmware_summary(p)[1:3],('Unspecified (0)','Not available'));del p[(B,'build-timestamp')];self.assertIn('missing',rpi.firmware_summary(p)[6])
 def test_warnings_empty_nontext_and_controls(self):
  for raw,value in [(b'', '(empty)'),(b'\0','(empty)'),(b'\xff','Unknown (non-text)'),(b'\x1b[31m','Unknown (non-text)'),(None,'Unknown')]:
   p=props();p[('/chosen','user-warnings')]=raw;self.assertEqual(rpi.firmware_summary(p)[5],value)
 def test_nonhex_version_not_abbreviated(self):
  p=props();p[(B,'version')]=b'bootloader-release-name\0';self.assertEqual(rpi.firmware_summary(p)[0],'bootloader-release-name')
 def test_non_pi(self):
  p=props();p[('/','compatible')]=b'linux,dummy-virt\0'
  with self.assertRaises(ValueError):rpi.firmware_summary(p)
if __name__=='__main__':unittest.main()
