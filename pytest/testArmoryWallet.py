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
def compareWalletObjs(tself, wlt1, wlt2):
   
   def cmpLen(a,b,prop):
      if hasattr(a, prop) and hasattr(b, prop):
         tself.assertEqual(len(getattr(a, prop)), len(getattr(b, prop)))


   cmpLen(wlt1, wlt2, 'allWalletEntries')
   cmpLen(wlt1, wlt2, 'allKeyPairObjects')
   cmpLen(wlt1, wlt2, 'displayableWalletsMap')
   cmpLen(wlt1, wlt2, 'allRootRoots')
   cmpLen(wlt1, wlt2, 'lockboxMap')
   cmpLen(wlt1, wlt2, 'ekeyMap')
   cmpLen(wlt1, wlt2, 'kdfMap')
   cmpLen(wlt1, wlt2, 'masterScrAddrMap')
   cmpLen(wlt1, wlt2, 'opaqueList')
   cmpLen(wlt1, wlt2, 'unrecognizedList')
   cmpLen(wlt1, wlt2, 'unrecoverableList')
   cmpLen(wlt1, wlt2, 'wltParentMissing')
   cmpLen(wlt1, wlt2, 'disabledRootIDs')
   cmpLen(wlt1, wlt2, 'disabledList')
   tself.assertEqual(wlt1.arbitraryDataMap.countNodes(), 
                     wlt2.arbitraryDataMap.countNodes())

   def cmpMapKeys(a,b,prop):
      self.assertTrue(hasattr(a, prop) and hasattr(b, prop))
      mapA = getattr(a, prop)
      mapB = getattr(b, prop)
      if not isinstance(mapA, dict) or not isinstance(mapB, dict):
         raise KeyError('Supplied property is not a map: %s' % prop)
      for key in mapA:
         self.assertTrue(key in mapB)
      for key in mapB:
         self.assertTrue(key in mapA)

   cmpMapKeys(wlt1, wlt2, 'allKeyPairObjects')
   cmpMapKeys(wlt1, wlt2, 'displayableWalletsMap')
   cmpMapKeys(wlt1, wlt2, 'allRootRoots')
   cmpMapKeys(wlt1, wlt2, 'lockboxMap')
   cmpMapKeys(wlt1, wlt2, 'ekeyMap')
   cmpMapKeys(wlt1, wlt2, 'kdfMap')
   cmpMapKeys(wlt1, wlt2, 'masterScrAddrMap')
      
   def cmpprop(a,b,prop):
      if hasattr(a, prop) and hasattr(b, prop):
         tself.assertEqual(getattr(a, prop), getattr(b, prop))

   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'wltUserName')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'createTime')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'createBlock')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'rsecParity')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'rsecPerData')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'isDisabled')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'headerSize')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'isTransferWallet')
   cmpprop(wlt1.fileHeader, wlt2.fileHeader, 'isSupplemental')



#############################################################################
def writeReadWalletRoundTripTest(tself, wlt):
   wltDir = 'tempwallets'
   if not os.path.exists(wltDir):
      os.makedirs(wltDir)

   tstr = str(RightNow())
   fnameA = os.path.join(wltDir, 'testWltRW_%s_A.wallet' % tstr)
   fnameB = os.path.join(wltDir, 'testWltRW_%s_B.wallet' % tstr)
   fnameC = os.path.join(wltDir, 'testWltRW_%s_C.wallet' % tstr)

   for f in [fnameA, fnameB, fnameC]:
      if os.path.exists(f):
         raise FileExistsError('Temporary wallet file already exists')
      

   try:
      wlt.writeFreshWalletFile(fname)
      wlt2 = ArmoryWallet.ReadWalletFile(fname)
      compareWalletObjs(wlt, wlt2)
   finally:
      for f in [fnameA, fnameB, fnameC]:
         if os.path.exists(f):
            os.remove(f)
            
   
   



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
   def roundTripTest(self, afh):
      afhSer  = afh.serializeHeaderData()
      afh2    = ArmoryFileHeader.Unserialize(afhSer)
      afhSer2 = afh2.serializeHeaderData()
      afh3    = ArmoryFileHeader.Unserialize(afhSer2)
      self.assertEqual(afhSer, afhSer2)
      
      self.cmp2afh(afh, afh3)

   #############################################################################
   def cmp2afh(self, afh1, afh2):
      def cmp(prop):
         self.assertEqual(getattr(afh1, prop), getattr(afh2, prop))

      cmp('wltUserName')
      cmp('createTime')
      cmp('createBlock')
      cmp('rsecParity')
      cmp('rsecPerData')
      cmp('isDisabled')
      cmp('headerSize')
      cmp('isTransferWallet')
      cmp('isSupplemental')


   #############################################################################
   def test_CreateAFH(self):
      
      afh = ArmoryFileHeader()
      
      afh.isTransferWallet = True
      afh.isSupplemental = False
      afh.createTime  = long(1.4e9)
      afh.createBlock = 320000
      afh.wltUserName = u''
      afh.rsecParity  = RSEC_PARITY_BYTES
      afh.rsecPerData = RSEC_PER_DATA_BYTES
      afh.isDisabled  = False
      afh.headerSize  = ArmoryFileHeader.DEFAULTSIZE

      self.roundTripTest(afh)


      fl = BitSet(32)
      fl.setBit(0, True)
      fl.setBit(1, False)
      afh2 = ArmoryFileHeader()
      afh2.initialize(fl, u'', long(1.4e9), 320000)

      self.cmp2afh(afh, afh2)
      self.roundTripTest(afh)


      fl = BitSet(32)
      fl.setBit(0, True)
      fl.setBit(1, True)
      afh3 = ArmoryFileHeader()
      afh3.initialize(fl, u'Armory Wallet Test\u2122', 0, 0)

      fl = BitSet(32)
      fl.setBit(0, True)
      fl.setBit(1, True)
      afh4 = ArmoryFileHeader()
      afh4.initialize(fl, u'', 0, 0)

      self.assertEqual( afh3.serializeHeaderData(), 
                        afh4.serializeHeaderData(altName=u'Armory Wallet Test\u2122'))


   #############################################################################
   def test_MagicFail(self):
      fl = BitSet(32)
      fl.setBit(0, True)
      fl.setBit(1, False)
      afh = ArmoryFileHeader()
      afh.initialize(fl, u'Armory Wallet Test\u2122', long(1.4e9), 320000)

      mgcC = '\xffARMORY\xff'
      mgcW = '\xbaWALLET\x00'
      afhSer1 = afh.serializeHeaderData()
      afhSer2 = mgcW + afhSer1[8:]
      afhSer3 = '\x00'*8 + afhSer1[8:]
      self.assertRaises(FileExistsError, ArmoryFileHeader.Unserialize, afhSer2)
      self.assertRaises(FileExistsError, ArmoryFileHeader.Unserialize, afhSer3)

      MAINBYTES = '\xf9\xbe\xb4\xd9'
      TESTBYTES = '\x0b\x11\x09\x07'
      afhSer4 = afhSer1[:16] + TESTBYTES + afhSer1[20:]
      self.assertRaises(NetworkIDError, ArmoryFileHeader.Unserialize, afhSer4)

      

################################################################################
class SimpleWalletTests(unittest.TestCase):

   #############################################################################
   def setUp(self):
      pass

      

      
   #############################################################################
   def tearDown(self):
      pass
      

   #############################################################################
   def test_InitABEK(self):
      abek = ABEK_Generic()





if __name__ == "__main__":
   unittest.main()
