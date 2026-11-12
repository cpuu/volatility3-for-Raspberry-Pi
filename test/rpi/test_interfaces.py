from volatility3.plugins.linux.rpi import interfaces as rpi
import unittest
def tree():
 return {'/':{'compatible':b'raspberrypi,4-model-b\0brcm,bcm2711\0'},'/aliases':{'serial0':b'/soc/serial@1\0'},'/soc':{},'/soc/serial@1':{'compatible':b'arm,pl011\0arm,primecell\0','status':b'okay\0'}}
class InterfacesTests(unittest.TestCase):
 def test_alias_and_controller(self):
  row=list(rpi.interface_rows(tree()))[0];self.assertEqual(row[:7],('serial0','UART','PL011 UART','okay','okay','-','ok'))
 def test_disabled_parent_not_misreported_as_active(self):
  t=tree();t['/soc']['status']=b'disabled\0';row=list(rpi.interface_rows(t))[0];self.assertEqual(row[3],'okay');self.assertEqual(row[4],'disabled: /soc')
 def test_missing_status_vs_unreadable_properties(self):
  t=tree();del t['/soc/serial@1']['status'];self.assertEqual(list(rpi.interface_rows(t))[0][3],'okay (implicit)')
  t['/soc/serial@1'][None]=None;self.assertEqual(list(rpi.interface_rows(t))[0][3],'Unknown')
 def test_alias_dedup_and_aliasless_usb(self):
  t=tree();t['/aliases']['serial1']=b'/soc/serial@1\0';t['/soc/usb@2']={'compatible':b'brcm,bcm2835-usb\0','dr_mode':b'peripheral\0'}
  rows=list(rpi.interface_rows(t));self.assertEqual(len(rows),2);self.assertEqual(rows[0][0],'serial0, serial1');self.assertEqual(rows[1][5],'peripheral')
 def test_broken_alias_visible(self):
  t=tree();t['/aliases']['spi0']=b'/soc/missing\0';t['/aliases']['i2c0']=b'bad'
  rows=list(rpi.interface_rows(t));self.assertTrue(any(r[0]=='spi0' and r[3]=='Unknown' for r in rows));self.assertTrue(any(r[1]=='Diagnostic' for r in rows))
 def test_non_controller_child_excluded(self):
  t=tree();t['/soc/spi@2/device@0']={'compatible':b'spidev\0'};self.assertEqual(len(list(rpi.interface_rows(t))),1)
 def test_bad_status_and_mode_not_defaulted(self):
  t=tree();t['/soc/serial@1']['status']=b'okay';t['/soc/usb@2']={'compatible':b'generic-xhci\0','dr_mode':b''}
  rows=list(rpi.interface_rows(t));self.assertEqual(rows[0][3],'Unknown');self.assertEqual(rows[1][5],'Unknown')
 def test_fail_reserved_not_available(self):
  for value in ('fail','reserved','disabled','fail-memory'):
   t=tree();t['/soc']['status']=value.encode()+b'\0';self.assertIn(value,list(rpi.interface_rows(t))[0][4])
 def test_non_pi_rejected(self):
  t=tree();t['/']['compatible']=b'linux,dummy-virt\0'
  with self.assertRaises(ValueError):list(rpi.interface_rows(t))
if __name__=='__main__':unittest.main()
