################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

import sys
sys.path.append('..')
import unittest
import sys
sys.path.append('..')
import textwrap

from armoryengine.ArmoryUtils import *
from armoryengine.ArmoryEncryption import *
from armoryengine.WalletEntry import *
from armoryengine.ArmoryKeyPair import *
from armoryengine.ArmoryWallet import *

WALLET_VERSION_BIN = hex_to_binary('002d3101')

# This disables RSEC for all WalletEntry objects.  This causes it to stop
# checking RSEC codes on all entries, and writes all \x00 bytes when creating.
WalletEntry.DisableRSEC()


MSO_FILECODE   = 'MOCKOBJ_'
MSO_ENTRY_ID   = '\x01'+'\x33'*20
MSO_FLAGS_REG  = '\x00\x00'
MSO_FLAGS_DEL  = '\x80\x00'
MSO_PARSCRADDR = '\x05'+'\x11'*20
MSO_PAYLOAD    = '\xaf'*5

FAKE_KDF_ID  = '\x42'*8
FAKE_EKEY_ID = '\x9e'*8



################################################################################
class MockSerializableObject(WalletEntry):
   FILECODE = MSO_FILECODE

   def __init__(self, txt=None):
      super(MockSerializableObject, self).__init__()
      self.setText(txt)

   def setText(self, txt):
      self.text = '' if txt is None else txt

   def getEntryID(self):
      return MSO_ENTRY_ID

   def serialize(self):
      bp = BinaryPacker()
      bp.put(VAR_STR, self.text)
      return bp.getBinaryString()

   def unserialize(self, toUnpack):
      bu = makeBinaryUnpacker(toUnpack) 
      self.text = bu.get(VAR_STR)
      return self
      


WalletEntry.RegisterWalletStorageClass(MockSerializableObject)


################################################################################
def skipFlagExists():
   if os.path.exists('skipmosttests.flag'):
      print '*'*80
      print 'SKIPPING MOST TESTS.  REMOVE skipMostTests.flag TO REENABLE'
      print '*'*80
      return True
   else:
      return False


#############################################################################
def runSerUnserRoundTripTest(tself, obj):
   """
   Can be run with "self" as the first arg from inside a TestCase subclass
   """
   # Compare all properties for all classes, this function ignores a call 
   # properties that don't exist for the input objects
   def cmpprop(a,b,prop):
      if hasattr(a, prop) and hasattr(b, prop):
         tself.assertEqual(getattr(a, prop), getattr(b, prop))

   CLASSOBJ = obj.__class__
   ser1     = obj.serialize()  
   objNew   = CLASSOBJ().unserialize(ser1)
   ser2     = objNew.serialize()
   objNew2  = CLASSOBJ().unserialize(ser2)
   

   # Now check that all the properties are identical
   cmpprop(objNew, objNew2, 'isWatchOnly')
   cmpprop(objNew, objNew2, 'isRootRoot')
   cmpprop(objNew, objNew2, 'sbdPrivKeyData')
   cmpprop(objNew, objNew2, 'sbdPublicKey33')
   cmpprop(objNew, objNew2, 'sbdChaincode')
   cmpprop(objNew, objNew2, 'useCompressPub')
   cmpprop(objNew, objNew2, 'isUsed')
   cmpprop(objNew, objNew2, 'notForDirectUse')
   cmpprop(objNew, objNew2, 'keyBornTime')
   cmpprop(objNew, objNew2, 'keyBornBlock')
   cmpprop(objNew, objNew2, 'privKeyNextUnlock')
   cmpprop(objNew, objNew2, 'akpParScrAddr')
   cmpprop(objNew, objNew2, 'childIndex')
   cmpprop(objNew, objNew2, 'maxChildren')
   cmpprop(objNew, objNew2, 'rawScript')
   cmpprop(objNew, objNew2, 'scrAddrStr')
   cmpprop(objNew, objNew2, 'uniqueIDBin')
   cmpprop(objNew, objNew2, 'uniqueIDB58')
   cmpprop(objNew, objNew2, 'walletName')
   cmpprop(objNew, objNew2, 'sbdSeedData')
   cmpprop(objNew, objNew2, 'seedNumBytes')
   cmpprop(objNew, objNew2, 'chainIndex')
   cmpprop(objNew, objNew2, 'root135ScrAddr')
   cmpprop(objNew, objNew2, 'userRemoved')
   cmpprop(objNew, objNew2, 'rootSourceApp')
   cmpprop(objNew, objNew2, 'fakeRootID')


   # Test that the raw serializations are identical
   tself.assertEqual(ser1, ser2)



################################################################################
class ArmoryFileHeaderTests(unittest.TestCase):

   #############################################################################
   #############################################################################
   def setUp(self):
      pass

      
   #############################################################################
   def tearDown(self):
      pass
      

   #############################################################################
   def test_CreateAFH(self):
      afh = ArmoryFileHeader()
      
      afh.isTransferWallet = True
      afh.isSupplemental = False

      afh.createTime(





################################################################################
class SimpleWalletTests(unittest.TestCase):

   #############################################################################
   def setUp(self):

      

      
   #############################################################################
   def tearDown(self):
      pass
      

   #############################################################################
   def test_InitABEK(self):
      abek = ABEK_Generic()

