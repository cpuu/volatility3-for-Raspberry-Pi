from volatility3.plugins.linux.rpi import rpi as rpi
"""Synthetic positives are parser validation, not physical Pi recovery evidence."""
import unittest, struct
from copy import deepcopy
from types import SimpleNamespace
from volatility3.framework import contexts
from volatility3.framework.layers import physical, lime
TARGET='/reserved-memory/nvram@0'
CONFIG=b'[all]\nBOOT_UART=1\nBOOT_ORDER=0xf41\n# preserved\n'
def tree():
 return {'/aliases':{'blconfig':TARGET.encode()+b'\0'},'/reserved-memory':{'#address-cells':struct.pack('>I',2),'#size-cells':struct.pack('>I',1),'ranges':b''},TARGET:{'compatible':b'raspberrypi,bootloader-config\0nvmem-rmem\0','reg':struct.pack('>QI',0x1000,len(CONFIG)),'no-map':b''}}
def layer(data=CONFIG):
 c=contexts.Context();header=struct.pack('<IIQQQ',0x4c694d45,1,0x1000,0x1000+len(data)-1,0)
 c.layers.add_layer(physical.BufferDataLayer(c,'file','file',header+data))
 c.config['lime.base_layer']='file';mem=lime.LimeLayer(c,'lime','lime');c.layers.add_layer(mem)
 return mem
class EepromTests(unittest.TestCase):
 def test_actual_lime_layer_positive_and_raw_preservation(self):
  path,address,size=rpi.eeprom_region(tree());self.assertEqual(path,TARGET)
  self.assertEqual(rpi.read_eeprom(layer(),address,size),(CONFIG,CONFIG.decode(),'recovered'))
 def test_hole_is_not_padded_or_reported_empty(self):
  self.assertEqual(rpi.read_eeprom(layer(),0x3000,54),(b'','','unavailable-in-physical-layer'))
 def test_partial_range_is_not_reported_recovered(self):
  self.assertEqual(rpi.read_eeprom(layer(),0x1000,len(CONFIG)+1)[2],'unavailable-in-physical-layer')
 def test_null_and_nontext_and_short_read(self):
  for data,status in [(b'\0','empty-text'),(b'\0'*10,'non-text-region'),(b'\xff\xff','non-text-region'),(b'just printable','unrecognized-config-text')]:
   self.assertEqual(rpi.read_eeprom(SimpleNamespace(read=lambda *a,**k:data),0x1000,len(data))[2],status)
  self.assertEqual(rpi.read_eeprom(SimpleNamespace(read=lambda *a,**k:b'X'),0,4)[2],'short-read')
 def test_trailing_null_and_duplicate_keys_preserved(self):
  data=b'[all]\nX=1\nX=2\n\0';raw,text,status=rpi.read_eeprom(layer(data),0x1000,len(data))
  self.assertEqual(raw,data);self.assertEqual(text,data[:-1].decode());self.assertEqual(status,'recovered')
 def test_32bit_and_64bit_sizes(self):
  t=tree();t['/reserved-memory']['#address-cells']=struct.pack('>I',1);t['/reserved-memory']['#size-cells']=struct.pack('>I',2);t[TARGET]['reg']=struct.pack('>IQ',0x1000,54)
  self.assertEqual(rpi.eeprom_region(t),(TARGET,0x1000,54))
 def test_malformed_metadata_rejected(self):
  cases=[('/aliases','blconfig',b'bad'),('/aliases','blconfig',b'/elsewhere\0'),('/aliases','blconfig',TARGET.encode()+b'\0x\0'),('/reserved-memory','ranges',b'nonempty'),('/reserved-memory','#address-cells',b'\0'),('/reserved-memory','#size-cells',struct.pack('>I',3)),(TARGET,'compatible',b'wrong\0'),(TARGET,'reg',b'bad'),(TARGET,'reg',struct.pack('>QI',0x1000,0)),(TARGET,'reg',struct.pack('>QI',0x1000,65537)),(TARGET,'reg',struct.pack('>QI',2**64-2,4))]
  for path,key,value in cases:
   with self.subTest(path=path,key=key,value=value):
    t=tree();t[path][key]=value
    with self.assertRaises(ValueError):rpi.eeprom_region(t)
 def test_missing_metadata_not_empty_config(self):
  for path,key in [('/aliases','blconfig'),('/reserved-memory','ranges'),('/reserved-memory','#size-cells'),(TARGET,'reg')]:
   t=tree();del t[path][key]
   with self.assertRaises(ValueError):rpi.eeprom_region(t)
if __name__=='__main__':unittest.main()
