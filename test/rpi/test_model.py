from volatility3.plugins.linux.rpi import model as rpi
import unittest
def props():
 return {('/','model'):b'Raspberry Pi 4 Model B Rev 1.4\0',('/','compatible'):b'raspberrypi,4-model-b\0brcm,bcm2711\0',('/','serial-number'):b'1000000015089641\0',('/system','linux,serial'):bytes.fromhex('1000000015089641'),('/system','linux,revision'):bytes.fromhex('00d03114')}
class ModelTests(unittest.TestCase):
 def test_pi4_identity(self):
  self.assertEqual(rpi.board_summary(props()),('Raspberry Pi 4 Model B','raspberrypi,4-model-b','1.4','1000000015089641','0x00d03114','8 GB','Sony UK','BCM2711','ok'))
 def test_fedora_missing_code_not_inferred_from_same_model(self):
  p=props();del p[('/system','linux,revision')];row=rpi.board_summary(p)
  self.assertEqual(row[2],'1.4');self.assertEqual(row[5:7],('Not available','Not available'));self.assertIn('revision code missing',row[-1])
 def test_unknown_fields_and_high_flags(self):
  self.assertEqual(rpi.decode_board_revision(0xf0d03114),rpi.decode_board_revision(0xd03114))
  d=rpi.decode_board_revision(0x00ffffff);self.assertEqual(d['ram'],'Other');self.assertIn('Unknown',d['manufacturer']);self.assertIn('Unknown',d['soc'])
 def test_old_codes(self):
  d=rpi.decode_board_revision(0x0005);self.assertEqual((d['ram'],d['manufacturer'],d['revision']),('256 MB','Qisda','2.0'))
  self.assertEqual(rpi.decode_board_revision(0x15)['ram'],'256 MB / 512 MB')
  self.assertEqual(rpi.decode_board_revision(0)['manufacturer'],'Unknown')
 def test_new_pi5_and_other_memory(self):
  self.assertEqual(rpi.decode_board_revision(0xe04171)['ram'],'16 GB')
  p=props();p[('/system','linux,revision')]=(0xf03114).to_bytes(4,'big');p[('/chosen','rpi-sdram-size-gbit')]=(192).to_bytes(4,'big')
  self.assertEqual(rpi.board_summary(p)[5],'24576 MB (firmware SDRAM property)')
 def test_serial_fallback_and_conflict(self):
  p=props();del p[('/','serial-number')];self.assertEqual(rpi.board_summary(p)[3],'1000000015089641')
  p[('/','serial-number')]=b'0000000000000001\0';self.assertIn('serial mismatch',rpi.board_summary(p)[-1])
 def test_invalid_values_not_guessed(self):
  p=props();p[('/system','linux,revision')]=b'\0';self.assertEqual(rpi.board_summary(p)[5],'Not available')
  p[('/','model')]=b'broken';self.assertEqual(rpi.board_summary(p)[0],'Not available')
  p[('/','compatible')]=b'linux,dummy-virt\0'
  with self.assertRaises(ValueError):rpi.board_summary(p)
 def test_soc_revision_conflict(self):
  p=props();p[('/system','linux,revision')]=(0xe04171).to_bytes(4,'big');self.assertIn('SoC mismatch',rpi.board_summary(p)[-1]);self.assertIn('revision mismatch',rpi.board_summary(p)[-1])
if __name__=='__main__':unittest.main()
