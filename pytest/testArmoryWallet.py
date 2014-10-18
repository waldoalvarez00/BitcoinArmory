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
   cmpprop(akpNew, akpNew2, 'isWatchOnly')
   cmpprop(akpNew, akpNew2, 'isRootRoot')
   cmpprop(akpNew, akpNew2, 'sbdPrivKeyData')
   cmpprop(akpNew, akpNew2, 'sbdPublicKey33')
   cmpprop(akpNew, akpNew2, 'sbdChaincode')
   cmpprop(akpNew, akpNew2, 'useCompressPub')
   cmpprop(akpNew, akpNew2, 'isUsed')
   cmpprop(akpNew, akpNew2, 'notForDirectUse')
   cmpprop(akpNew, akpNew2, 'keyBornTime')
   cmpprop(akpNew, akpNew2, 'keyBornBlock')
   cmpprop(akpNew, akpNew2, 'privKeyNextUnlock')
   cmpprop(akpNew, akpNew2, 'akpParScrAddr')
   cmpprop(akpNew, akpNew2, 'childIndex')
   cmpprop(akpNew, akpNew2, 'maxChildren')
   cmpprop(akpNew, akpNew2, 'rawScript')
   cmpprop(akpNew, akpNew2, 'scrAddrStr')
   cmpprop(akpNew, akpNew2, 'uniqueIDBin')
   cmpprop(akpNew, akpNew2, 'uniqueIDB58')

   tself.assertEqual( akpNew.privCryptInfo.serialize(),
                     akpNew2.privCryptInfo.serialize())

   cmpprop(akpNew, akpNew2, 'walletName')
   cmpprop(akpNew, akpNew2, 'sbdSeedData')
   cmpprop(akpNew, akpNew2, 'seedNumBytes')
   cmpprop(akpNew, akpNew2, 'chainIndex')
   cmpprop(akpNew, akpNew2, 'root135ScrAddr')
   cmpprop(akpNew, akpNew2, 'userRemoved')
   cmpprop(akpNew, akpNew2, 'rootSourceApp')
   cmpprop(akpNew, akpNew2, 'fakeRootID')

   try:
      tself.assertEqual( akpNew.seedCryptInfo.serialize(),
                        akpNew2.seedCryptInfo.serialize())
   except:
      pass

   # Test that the raw serializations are identical
   tself.assertEqual(ser1, ser2)

   # For fun, why not add these encoding tests everywhere we test ser/unser
   if akpNew.sbdPublicKey33.getSize() > 0:
      sbdPubk = akpNew2.sbdPublicKey33.copy()
      if not akpNew.useCompressPub:
         sbdPubk = CryptoECDSA().UncompressPoint(sbdPubk)
      tself.assertEqual(akpNew.getSerializedPubKey('hex'), sbdPubk.toHexStr())
      tself.assertEqual(akpNew.getSerializedPubKey('bin'), sbdPubk.toBinStr())

   if akpNew.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Available:
      lastByte = '\x01' if akpNew.useCompressPub else ''
      lastHex  =   '01' if akpNew.useCompressPub else ''
         
      sbdPriv = akpNew2.getPlainPrivKeyCopy()
      sipaPriv = PRIVKEYBYTE + sbdPriv.toBinStr() + lastByte
      sipaPriv = binary_to_base58(sipaPriv + computeChecksum(sipaPriv))
      tself.assertEqual(akpNew.getSerializedPrivKey('bin'), sbdPriv.toBinStr()+lastByte)
      tself.assertEqual(akpNew.getSerializedPrivKey('hex'), sbdPriv.toHexStr()+lastHex)
      tself.assertEqual(akpNew.getSerializedPrivKey('sipa'), sipaPriv)
      tself.assertEqual(akpNew.getSerializedPrivKey('sipa'), 
            encodePrivKeyBase58(sbdPriv.toBinStr(), isCompressed=akpNew.useCompressPub))

################################################################################
class ArmoryFileHeaderTests(unittest.TestCase):

   #############################################################################
   #############################################################################
   def setUp(self):

      

      
   #############################################################################
   def tearDown(self):
      pass
      

   #############################################################################
   def test_InitABEK(self):
      abek = ABEK_Generic()







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

