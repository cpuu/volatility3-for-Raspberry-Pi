from volatility3.plugins.linux.rpi import boot as rpi
import unittest
def props():
 return {('/','compatible'):b'raspberrypi,4-model-b\0brcm,bcm2711\0',('/chosen','os_prefix'):b'rollback-1017/\0',('/chosen','bootargs'):b'console=tty1 root=LABEL=writable rootwait\0',('/chosen/bootloader','boot-mode'):bytes.fromhex('00000001'),('/chosen/bootloader','partition'):bytes.fromhex('00000001'),('/chosen/bootloader','tryboot'):bytes.fromhex('00000001')}
class BootTests(unittest.TestCase):
 def test_known_boot(self):self.assertEqual(rpi.boot_summary(props()),('SD/eMMC','1','Yes','rollback-1017/','LABEL=writable','ok'))
 def test_empty_prefix_distinct_from_absent(self):
  p=props();p[('/chosen','os_prefix')]=b'\0';self.assertEqual(rpi.boot_summary(p)[3],'(none)')
  del p[('/chosen','os_prefix')];self.assertEqual(rpi.boot_summary(p)[3],'Not available');self.assertIn('missing',rpi.boot_summary(p)[-1])
 def test_unknown_and_malformed_numbers(self):
  p=props();p[('/chosen/bootloader','boot-mode')]=(55).to_bytes(4,'big');p[('/chosen/bootloader','tryboot')]=(2).to_bytes(4,'big');p[('/chosen/bootloader','partition')]=b'\1'
  row=rpi.boot_summary(p);self.assertEqual(row[:3],('Unknown (0x37)','Not available','Unknown (2)'))
 def test_quotes_duplicates_init_arguments(self):
  p=props();p[('/chosen','bootargs')]=b'root="LABEL=My Disk" root=/dev/mmcblk0p2 -- root=not-kernel\0'
  row=rpi.boot_summary(p);self.assertEqual(row[4],'LABEL=My Disk | /dev/mmcblk0p2');self.assertIn('multiple root=',row[-1])
 def test_empty_missing_and_malformed_root(self):
  for args in (b'root=\0',b'console=tty1\0',b'root="unclosed\0'):
   p=props();p[('/chosen','bootargs')]=args;self.assertNotEqual(rpi.boot_summary(p)[-1],'ok')
 def test_invalid_text_and_non_pi(self):
  p=props();p[('/chosen','os_prefix')]=b'bad\x00data\x00';self.assertEqual(rpi.boot_summary(p)[3],'Not available')
  p[('/','compatible')]=b'linux,dummy-virt\0'
  with self.assertRaises(ValueError):rpi.boot_summary(p)
 def test_all_boot_modes(self):
  for code,name in [(2,'Network'),(3,'RPIBOOT'),(4,'USB mass storage'),(5,'BCM USB mass storage'),(6,'NVMe'),(7,'HTTP')]:
   p=props();p[('/chosen/bootloader','boot-mode')]=code.to_bytes(4,'big');self.assertEqual(rpi.boot_summary(p)[0],name)
if __name__=='__main__':unittest.main()
