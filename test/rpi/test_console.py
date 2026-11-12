from volatility3.plugins.linux.rpi import console as rpi
import unittest
def tree():
 return {'/':{'compatible':b'raspberrypi,4-model-b\0'},'/soc':{},'/aliases':{'serial0':b'/soc/serial@1\0'},'/soc/serial@1':{'compatible':b'brcm,bcm2835-aux-uart\0','status':b'okay\0'},'/chosen':{'stdout-path':b'serial0:115200n8\0','bootargs':b'console=ttyS0,115200 console=tty1\0'}}
class ConsoleTests(unittest.TestCase):
 def test_alias_resolution(self):
  self.assertEqual(rpi.console_summary(tree()),('serial0:115200n8','BCM2835 mini UART','okay','okay','ttyS0,115200 | tty1','ok','/soc/serial@1','/chosen/stdout-path'))
 def test_absolute_and_legacy_stdout(self):
  t=tree();del t['/chosen']['stdout-path'];t['/chosen']['linux,stdout-path']=b'/soc/serial@1:9600n8\0';r=rpi.console_summary(t);self.assertEqual(r[6],'/soc/serial@1');self.assertEqual(r[7],'/chosen/linux,stdout-path')
 def test_primary_wins_over_legacy(self):
  t=tree();t['/chosen']['linux,stdout-path']=b'bad\0';self.assertEqual(rpi.console_summary(t)[7],'/chosen/stdout-path')
 def test_disabled_target_and_parent_reported(self):
  t=tree();t['/soc/serial@1']['status']=b'disabled\0';t['/soc']['status']=b'disabled\0';r=rpi.console_summary(t);self.assertEqual(r[2:4],('disabled','disabled: /soc'));self.assertIn('target unavailable',r[5]);self.assertIn('ancestor unavailable',r[5])
 def test_missing_is_not_disabled(self):
  t=tree();del t['/soc/serial@1']['status'];self.assertEqual(rpi.console_summary(t)[2],'okay (implicit)');t['/soc/serial@1'][None]=None;self.assertEqual(rpi.console_summary(t)[2],'Unknown')
 def test_console_order_quotes_and_init(self):
  t=tree();t['/chosen']['bootargs']=b'console="ttyS0,115200" console=tty1 console=tty1 -- console=ignore\0';self.assertEqual(rpi.console_summary(t)[4],'ttyS0,115200 | tty1 | tty1')
 def test_absent_console_vs_absent_args(self):
  t=tree();t['/chosen']['bootargs']=b'root=LABEL=writable\0';self.assertEqual(rpi.console_summary(t)[4],'(none specified)');del t['/chosen']['bootargs'];self.assertEqual(rpi.console_summary(t)[4],'Not available')
 def test_broken_alias_and_malformed_quoting(self):
  t=tree();t['/aliases']['serial0']=b'not-a-path\0';t['/chosen']['bootargs']=b'console="oops\0';r=rpi.console_summary(t);self.assertEqual(r[2],'Unknown');self.assertEqual(r[4],'Not available');self.assertIn('alias',r[5])
 def test_non_pi_rejected(self):
  t=tree();t['/']['compatible']=b'linux,dummy-virt\0'
  with self.assertRaises(ValueError):rpi.console_summary(t)
if __name__=='__main__':unittest.main()
