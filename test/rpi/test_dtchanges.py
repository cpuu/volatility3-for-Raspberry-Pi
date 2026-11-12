from volatility3.plugins.linux.rpi import dtchanges as rpi
import unittest
class ChangesTests(unittest.TestCase):
 def setUp(self):self.boot={('/','compatible'):(b'raspberrypi,4-model-b\0',100)};self.live=self.boot.copy()
 def compare(self,**kwargs):return rpi.dtchanges_compare(self.boot,self.live,{'/','/uart@1'},{'/','/uart@1'},**kwargs)
 def test_unchanged(self):self.assertEqual(self.compare()[0][0],'No changes')
 def test_modified_binary_and_addresses(self):
  self.boot[('/','reg')]=(b'\xff\x00',100);self.live[('/','reg')]=(b'\xff\x01',200)
  row=self.compare()[1];self.assertEqual(row[0],'Modified');self.assertEqual(row[6:],('0x64','0xc8','ff00','ff01'))
 def test_added_removed_and_empty(self):
  self.boot[('/','old')]=(b'',1);self.live[('/','new')]=(b'',2)
  rows=self.compare()[1:];self.assertEqual([r[0] for r in rows],['Added','Removed']);self.assertEqual(rows[0][3:5],('(absent)','(empty)'))
 def test_generated_exact_and_opt_in(self):
  self.live[('/uart@1','name')]=(b'uart\0',2);self.assertEqual(self.compare()[0][0],'No changes');self.assertEqual(self.compare(include_generated=True)[1][0],'GeneratedName')
 def test_custom_name_not_hidden(self):
  self.live[('/uart@1','name')]=(b'other\0',2);self.assertEqual(self.compare()[1][0],'Added')
 def test_existing_name_change_not_hidden(self):
  self.boot[('/uart@1','name')]=(b'old\0',1);self.live[('/uart@1','name')]=(b'uart\0',2);self.assertEqual(self.compare()[1][0],'Modified')
 def test_empty_nodes(self):
  rows=rpi.dtchanges_compare(self.boot,self.live,{'/','/old'},{'/','/new'});self.assertEqual([r[0] for r in rows],['Summary','NodeAdded','NodeRemoved'])
 def test_new_node_name_not_suppressed(self):
  self.live[('/new','name')]=(b'new\0',2);rows=rpi.dtchanges_compare(self.boot,self.live,{'/'},{'/','/new'});self.assertEqual([r[0] for r in rows],['Summary','NodeAdded','Added'])
 def test_incomplete_never_reports_deletion(self):
  self.live={};self.assertEqual(self.compare(diagnostics=['property-limit-reached'])[0][0],'Unavailable')
 def test_identity_both_sources(self):
  for target in (self.boot,self.live):
   before=target.copy();target[('/','compatible')]=(b'generic\0',0);self.assertEqual(self.compare()[0][0],'Unavailable');target.update(before)

class AcquisitionTests(unittest.TestCase):
 def run_plugin(self, *, missing=False, corrupt=False, diagnostic=False):
  from types import SimpleNamespace as NS
  from unittest.mock import patch
  kernel=NS(layer_name='memory',has_symbol=lambda _:not missing,object_from_symbol=lambda _:4096)
  layer=NS(read=lambda a,n,pad=False:bytes(n))
  fake=NS(context=NS(modules={'kernel':kernel},layers={'memory':layer}),config={'kernel':'kernel','max-nodes':100,'max-properties':100,'max-value':65536})
  compatible=b'raspberrypi,4-model-b\0'
  boot=[('/','compatible',10,compatible),('/','status',40,b'disabled\0')]
  live=[(1,'compatible',4106,len(compatible),compatible,'ok'),(2,'status',5000,5,b'okay\0','ok')]
  if diagnostic:live.append((0,'',0,0,b'','property-cycle'))
  with patch.object(rpi,'dtchanges_fdt_header',side_effect=ValueError('Invalid FDT magic') if corrupt else None,return_value=(100,)),patch.object(rpi,'dtchanges_parse_fdt',return_value=(boot,{'/'})),patch.object(rpi.Rpi,'walk_nodes',return_value=[(object(),'/',4096,'ok')]),patch.object(rpi.Rpi,'read_properties',return_value=live):
   return list(rpi.DtChanges._generator(fake))
 def test_positive_generator(self):
  rows=self.run_plugin();self.assertEqual(rows[1][1][:5],('Modified','/','status',"'disabled'","'okay'"))
 def test_corrupt_blob(self):self.assertEqual(self.run_plugin(corrupt=True)[0][1][0],'Unavailable')
 def test_missing_symbol(self):self.assertEqual(self.run_plugin(missing=True)[0][1][0],'Unavailable')
 def test_partial_live(self):self.assertEqual(self.run_plugin(diagnostic=True)[0][1][0],'Unavailable')
