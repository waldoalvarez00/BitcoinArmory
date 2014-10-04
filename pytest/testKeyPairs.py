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



BIP32TestVectors = []

# 0
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")),
      'seedCC': SecureBinaryData(hex_to_binary("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")),
      'seedPubKey': SecureBinaryData(hex_to_binary("0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")),
      'seedID': SecureBinaryData(hex_to_binary("3442193e1bb70916e914552172cd4e2dbc9df811")),
      'seedFP': SecureBinaryData(hex_to_binary("3442193e")),
      'seedParFP': SecureBinaryData(hex_to_binary("00000000")),
      'nextChild': 2147483648 
   })

# 1
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")),
      'seedCC': SecureBinaryData(hex_to_binary("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")),
      'seedPubKey': SecureBinaryData(hex_to_binary("045a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc567f717885be239daadce76b568958305183ad616ff74ed4dc219a74c26d35f839")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56")),
      'seedID': SecureBinaryData(hex_to_binary("5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7")),
      'seedFP': SecureBinaryData(hex_to_binary("5c1bd648")),
      'seedParFP': SecureBinaryData(hex_to_binary("3442193e")),
      'nextChild': 1
   })

# 2
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")),
      'seedCC': SecureBinaryData(hex_to_binary("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")),
      'seedPubKey': SecureBinaryData(hex_to_binary("04501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c008794c1df8131b9ad1e1359965b3f3ee2feef0866be693729772be14be881ab")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c")),
      'seedID': SecureBinaryData(hex_to_binary("bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe")),
      'seedFP': SecureBinaryData(hex_to_binary("bef5a2f9")),
      'seedParFP': SecureBinaryData(hex_to_binary("5c1bd648")),
      'nextChild': 2147483650
   })

# 3
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")),
      'seedCC': SecureBinaryData(hex_to_binary("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f")),
      'seedPubKey': SecureBinaryData(hex_to_binary("0457bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc24310ef3676384179e713be3115e93f34ac9a3933f6367aeb3081527ea74027b7")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2")),
      'seedID': SecureBinaryData(hex_to_binary("ee7ab90cde56a8c0e2bb086ac49748b8db9dce72")),
      'seedFP': SecureBinaryData(hex_to_binary("ee7ab90c")),
      'seedParFP': SecureBinaryData(hex_to_binary("bef5a2f9")),
      'nextChild': 2
   })

# 4
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")),
      'seedCC': SecureBinaryData(hex_to_binary("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd")),
      'seedPubKey': SecureBinaryData(hex_to_binary("04e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d292728ad8d58a140050c1016e21f285636a580f4d2711b7fac3957a594ddf416a0")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29")),
      'seedID': SecureBinaryData(hex_to_binary("d880d7d893848509a62d8fb74e32148dac68412f")),
      'seedFP': SecureBinaryData(hex_to_binary("d880d7d8")),
      'seedParFP': SecureBinaryData(hex_to_binary("ee7ab90c")),
      'nextChild': 1000000000
   })

# 5
BIP32TestVectors.append( \
   {
      'seedKey': SecureBinaryData(hex_to_binary("00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")),
      'seedCC': SecureBinaryData(hex_to_binary("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e")),
      'seedPubKey': SecureBinaryData(hex_to_binary("042a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011cf31cb47de7ccf6196d3a580d055837de7aa374e28c6c8a263e7b4512ceee362")),
      'seedCompPubKey': SecureBinaryData(hex_to_binary("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011")),
      'seedExtSerPrv': SecureBinaryData(hex_to_binary("0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")),
      'seedExtSerPub': SecureBinaryData(hex_to_binary("0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011")),
      'seedID': SecureBinaryData(hex_to_binary("d69aa102255fed74378278c7812701ea641fdf32")),
      'seedFP': SecureBinaryData(hex_to_binary("d69aa102")),
      'seedParFP': SecureBinaryData(hex_to_binary("d880d7d8")),
      'nextChild': None
   })





################################################################################
class MockWalletFile(object):
   def __init__(self):
      self.ekeyMap = {}

   def doFileOperation(*args, **kwargs):
      pass

   def getName(self):
      return 'MockWalletFile'



################################################################################
def skipFlagExists():
   if os.path.exists('skipmosttests.flag'):
      print '*'*80
      print 'SKIPPING MOST TESTS.  REMOVE skipMostTests.flag TO REENABLE'
      print '*'*80
      return True
   else:
      return False


################################################################################
class UtilityFuncTests(unittest.TestCase):

   #############################################################################
   def testSplitChildIndex(self):
      self.assertRaises(ValueError, SplitChildIndex, 2**32)
      self.assertRaises(ValueError, SplitChildIndex, -1)

      TOPBIT = 0x80000000
      self.assertEqual(SplitChildIndex(0),          [0, False])
      self.assertEqual(SplitChildIndex(1),          [1, False])
      self.assertEqual(SplitChildIndex(128),        [128, False])
      self.assertEqual(SplitChildIndex(0+TOPBIT),   [0, True])
      self.assertEqual(SplitChildIndex(1+TOPBIT),   [1, True])
      self.assertEqual(SplitChildIndex(2**32-1),    [2**31-1, True])
      self.assertEqual(SplitChildIndex(0x7fffffff), [0x7fffffff, False])
      self.assertEqual(SplitChildIndex(0x80000000), [0, True])


   #############################################################################
   def testCreateChildIndex(self):
      TOPBIT = 0x80000000
      self.assertEqual(CreateChildIndex(0, False),          0)
      self.assertEqual(CreateChildIndex(1, False),          1)
      self.assertEqual(CreateChildIndex(128, False),        128)
      self.assertEqual(CreateChildIndex(0, True),           0+TOPBIT)
      self.assertEqual(CreateChildIndex(1, True),           1+TOPBIT)
      self.assertEqual(CreateChildIndex(2**31-1, True),     2**32-1)
      self.assertEqual(CreateChildIndex(0x7fffffff, False), 0x7fffffff)
      self.assertEqual(CreateChildIndex(0, True),           0x80000000)

   #############################################################################
   def testChildIdxToStr(self):
      TOPBIT = 0x80000000
      self.assertEqual(ChildIndexToStr(0), "0")
      self.assertEqual(ChildIndexToStr(1), "1")
      self.assertEqual(ChildIndexToStr(128), "128")
      self.assertEqual(ChildIndexToStr(0+TOPBIT), "0'")
      self.assertEqual(ChildIndexToStr(1+TOPBIT), "1'")
      self.assertEqual(ChildIndexToStr(2**32-1), "2147483647'")
      self.assertEqual(ChildIndexToStr(0x7fffffff), "2147483647")
      self.assertEqual(ChildIndexToStr(0x80000000), "0'")




################################################################################
class TestHDWalletLogic(unittest.TestCase):

   #############################################################################
   def testCppConvertSeed(self):
      TEST_SEED1  = SecureBinaryData(hex_to_binary("000102030405060708090a0b0c0d0e0f"));
      TEST_PRIV1  = SecureBinaryData(hex_to_binary("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"));
      TEST_PUBK1  = SecureBinaryData(hex_to_binary("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"));
      TEST_CHAIN1 = SecureBinaryData(hex_to_binary("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"));

      TEST_SEED2  = SecureBinaryData(hex_to_binary("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"));
      TEST_PRIV2  = SecureBinaryData(hex_to_binary("4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"));
      TEST_PUBK2  = SecureBinaryData(hex_to_binary("03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"));
      TEST_CHAIN2 = SecureBinaryData(hex_to_binary("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"));

      extkey = Cpp.HDWalletCrypto().ConvertSeedToMasterKey(TEST_SEED1)
      self.assertEqual(extkey.getPrivateKey().toBinStr(), TEST_PRIV1.toBinStr())
      self.assertEqual(extkey.getPublicKey().toBinStr(), TEST_PUBK1.toBinStr())
      self.assertEqual(extkey.getChaincode().toBinStr(), TEST_CHAIN1.toBinStr())
      
      extkey = Cpp.HDWalletCrypto().ConvertSeedToMasterKey(TEST_SEED2)
      self.assertEqual(extkey.getPrivateKey().toBinStr(), TEST_PRIV2.toBinStr())
      self.assertEqual(extkey.getPublicKey().toBinStr(), TEST_PUBK2.toBinStr())
      self.assertEqual(extkey.getChaincode().toBinStr(), TEST_CHAIN2.toBinStr())


   #############################################################################
   def testCppDeriveChild(self):

      for i in range(len(BIP32TestVectors)-1):
         currEKdata = BIP32TestVectors[i]
         nextEKdata = BIP32TestVectors[i+1]


         currEK = Cpp.ExtendedKey(currEKdata['seedKey'], currEKdata['seedCC'])
         compEK = Cpp.HDWalletCrypto().childKeyDeriv(currEK, currEKdata['nextChild'])
         nextPriv = SecureBinaryData(nextEKdata['seedKey'].toBinStr()[1:])
         self.assertEqual(compEK.getPrivateKey(), nextPriv)
         self.assertEqual(compEK.getPublicKey(), nextEKdata['seedCompPubKey'])
         self.assertEqual(compEK.getChaincode(), nextEKdata['seedCC'])

         if currEKdata['nextChild'] & 0x80000000 == 0:
            # Now test the same thing from the just the public key
            currEK = Cpp.ExtendedKey(currEKdata['seedCompPubKey'], currEKdata['seedCC'])
            compEK = Cpp.HDWalletCrypto().childKeyDeriv(currEK, currEKdata['nextChild'])
            #self.assertTrue(currEK.isPub())
            #self.assertEqual(compEK.getPublicKey(), nextEKdata['seedCompPubKey'])
            #self.assertEqual(compEK.getChaincode(), nextEKdata['seedCC'])
         
         


################################################################################
class AKPTests(unittest.TestCase):

   #############################################################################
   def setUp(self):
      pass
      
   #############################################################################
   def tearDown(self):
      pass
      

   #############################################################################
   def testInitABEK(self):
      #leaf = makeABEKGenericClass()
      abek = ABEK_Generic()
         
      self.assertEqual(abek.isWatchOnly, False)
      self.assertEqual(abek.sbdPrivKeyData, NULLSBD())
      self.assertEqual(abek.sbdPublicKey33, NULLSBD())
      self.assertEqual(abek.sbdChaincode, NULLSBD())
      self.assertEqual(abek.useCompressPub, True)
      self.assertEqual(abek.isUsed, False)
      self.assertEqual(abek.keyBornTime, 0)
      self.assertEqual(abek.keyBornBlock, 0)
      self.assertEqual(abek.privKeyNextUnlock, False)
      self.assertEqual(abek.akpParScrAddr, '')
      self.assertEqual(abek.akpRootScrAddr, '')
      self.assertEqual(abek.childIndex, UINT32_MAX)
      self.assertEqual(abek.childPoolSize, 5)
      self.assertEqual(abek.maxChildren, UINT32_MAX)
      self.assertEqual(abek.rawScript, None)
      self.assertEqual(abek.scrAddrStr, None)
      self.assertEqual(abek.uniqueIDBin, None)
      self.assertEqual(abek.uniqueIDB58, None)
      self.assertEqual(abek.akpChildByIndex, {})
      self.assertEqual(abek.akpChildByScrAddr, {})
      self.assertEqual(abek.lowestUnusedChild, 0)
      self.assertEqual(abek.highestCalcChild, 0)
      self.assertEqual(abek.akpParentRef, None)
      self.assertEqual(abek.masterEkeyRef, None)

      self.assertEqual(abek.isTreeLeaf(), False)
      self.assertEqual(abek.getName(), 'ABEK_Generic')
      self.assertEqual(abek.getPrivKeyAvailability(), PRIV_KEY_AVAIL.Uninit)

      # WalletEntry fields
      self.assertEqual(abek.wltFileRef, None)
      self.assertEqual(abek.wltByteLoc, None)
      self.assertEqual(abek.wltEntrySz, None)
      self.assertEqual(abek.isRequired, False)
      self.assertEqual(abek.parEntryID, None)
      self.assertEqual(abek.outerCrypt.serialize(), ArmoryCryptInfo(None).serialize())
      self.assertEqual(abek.serPayload, None)
      self.assertEqual(abek.defaultPad, 256)
      self.assertEqual(abek.wltParentRef, None)
      self.assertEqual(abek.wltChildRefs, [])
      self.assertEqual(abek.outerEkeyRef, None)
      self.assertEqual(abek.isOpaque,        False)
      self.assertEqual(abek.isUnrecognized,  False)
      self.assertEqual(abek.isUnrecoverable, False)
      self.assertEqual(abek.isDeleted,       False)
      self.assertEqual(abek.isDisabled,      False)
      self.assertEqual(abek.needFsync,       False)

   #############################################################################
   def testSpawnABEK(self):
      sbdPriv  = SecureBinaryData(BIP32TestVectors[1]['seedKey'].toBinStr()[1:])
      sbdPubk  = BIP32TestVectors[1]['seedCompPubKey']
      sbdChain = BIP32TestVectors[1]['seedCC']
      nextIdx  = BIP32TestVectors[1]['nextChild']

      parA160    = hash160(sbdPubk.toBinStr())
      parScript  = hash160_to_p2pkhash_script(parA160)
      parScrAddr = SCRADDR_P2PKH_BYTE + parA160

      nextPriv  = SecureBinaryData(BIP32TestVectors[2]['seedKey'].toBinStr()[1:])
      nextPubk  = BIP32TestVectors[2]['seedCompPubKey']
      nextChain = BIP32TestVectors[2]['seedCC']

      chA160    = hash160(nextPubk.toBinStr())
      chScript  = hash160_to_p2pkhash_script(chA160)
      chScrAddr = SCRADDR_P2PKH_BYTE + chA160

      abek = ABEK_Generic()
      abek.isWatchOnly = False
      abek.sbdPrivKeyData = sbdPriv.copy()
      abek.sbdPublicKey33 = sbdPubk.copy()
      abek.sbdChaincode   = sbdChain.copy()
      abek.useCompressPub = True
      abek.privKeyNextUnlock = False

      childAbek = abek.spawnChild(nextIdx, fsync=False)

      self.assertEqual(childAbek.sbdPrivKeyData, nextPriv)
      self.assertEqual(childAbek.sbdPublicKey33.toHexStr(), nextPubk.toHexStr())
      self.assertEqual(childAbek.sbdChaincode,   nextChain)
      self.assertEqual(childAbek.useCompressPub, True)
      self.assertEqual(childAbek.isUsed, False)
      self.assertEqual(childAbek.privKeyNextUnlock, False)
      self.assertEqual(childAbek.akpParScrAddr, None)
      self.assertEqual(childAbek.akpRootScrAddr, None)
      self.assertEqual(childAbek.childIndex, nextIdx)
      self.assertEqual(childAbek.childPoolSize, 5)
      self.assertEqual(childAbek.maxChildren, UINT32_MAX)
      self.assertEqual(childAbek.rawScript, chScript)
      self.assertEqual(childAbek.scrAddrStr, chScrAddr)
      #self.assertEqual(childAbek.uniqueIDBin, None)
      #self.assertEqual(childAbek.uniqueIDB58, None)
      #self.assertEqual(childAbek.akpChildByIndex, {})
      #self.assertEqual(childAbek.akpChildByScrAddr, {})
      self.assertEqual(childAbek.lowestUnusedChild, 0)
      self.assertEqual(childAbek.highestCalcChild, 0)
      self.assertEqual(childAbek.akpParentRef, None)
      self.assertEqual(childAbek.masterEkeyRef, None)
      
      # Test setting the child ref, which is normally done for you if fsync=True
      abek.addChildRef(childAbek)
      self.assertEqual(childAbek.akpParScrAddr, parScrAddr)



   #############################################################################
   def testInitABEK(self):
      #leaf = makeABEKGenericClass()
      abek = ABEK_Generic()

      '''
      #'seedKey': SecureBinaryData(hex_to_binary("00e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")),
      #'seedCC': SecureBinaryData(hex_to_binary("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")),
      #'seedPubKey': SecureBinaryData(hex_to_binary("0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281")),
      #'seedCompPubKey': SecureBinaryData(hex_to_binary("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2")),
      sbdPriv  = BIP32TestVectors[0]['seedKey']
      sbdPubk  = BIP32TestVectors[0]['seedCompPubKey']
      sbdChain = BIP32TestVectors[0]['seedCC']

      a160    = hash160(sbdPubk.toBinStr())
      rawScr  = hash160_to_p2pkhash_script(a160)
      scrAddr = SCRADDR_P2PKH_BYTE + a160

      #
      #childAbek  = abek.spawnChild(0x7fffffff, fsync=False)
      #child256  = hash256(childAbek.getScrAddr())
      #firstByte = binary_to_int(child256[0])
      #newFirst  = firstByte ^ binary_to_int(ADDRBYTE)
      #uidBin = int_to_binary(newFirst) + child256[1:6]
      #uidB58 = binary_to_base58(uidBin)


      # No encryption on this ABEK
      aci = ArmoryCryptInfo(None)

      parScrAddr = None

      t = long(RightNow())
      abek.initializeAKP(isWatchOnly=False,
                         privCryptInfo=aci,
                         sbdPrivKeyData=sbdPriv,
                         sbdPublicKey33=sbdPubk,
                         sbdChaincode=sbdChain,
                         privKeyNextUnlock=False,
                         akpParScrAddr=None,
                         akpRootScrAddr=None,
                         childIndex=None,
                         useCompressPub=True,
                         isUsed=True,
                         keyBornTime=t,
                         keyBornBlock=t)
                           
      self.assertEqual(abek.isWatchOnly, False)
      self.assertEqual(abek.sbdPrivKeyData, sbdPriv)
      self.assertEqual(abek.sbdPublicKey33, sbdPubk)
      self.assertEqual(abek.sbdChaincode, sbdChain)
      self.assertEqual(abek.useCompressPub, True)
      self.assertEqual(abek.isUsed, True)
      self.assertEqual(abek.keyBornTime, t)
      self.assertEqual(abek.keyBornBlock, t)
      self.assertEqual(abek.privKeyNextUnlock, False)
      self.assertEqual(abek.akpParScrAddr, None)
      self.assertEqual(abek.akpRootScrAddr, None)
      self.assertEqual(abek.childIndex, None)
      self.assertEqual(abek.childPoolSize, 5)
      self.assertEqual(abek.maxChildren, UINT32_MAX)
      self.assertEqual(abek.rawScript, rawScr)
      self.assertEqual(abek.scrAddrStr, scrAddr)
      #self.assertEqual(abek.uniqueIDBin, uidBin)
      #self.assertEqual(abek.uniqueIDB58, uidB58)
      self.assertEqual(abek.akpChildByIndex, {})
      self.assertEqual(abek.akpChildByScrAddr, {})
      self.assertEqual(abek.lowestUnusedChild, 0)
      self.assertEqual(abek.highestCalcChild, 0)
      self.assertEqual(abek.akpParentRef, None)
      self.assertEqual(abek.masterEkeyRef, None)

      self.assertEqual(abek.isTreeLeaf(), False)
      self.assertEqual(abek.getName(), 'ABEK_Generic')
      #print abek.getPrivKeyAvailability()
      #print abek.isWatchOnly
      #print pprintHex(binary_to_hex(abek.privCryptInfo.serialize()))
      #print 'use:', abek.privCryptInfo.useEncryption()
      #print 'no: ', abek.privCryptInfo.noEncryption()
      self.assertEqual(abek.getPrivKeyAvailability(), PRIV_KEY_AVAIL.Available)
      '''



if __name__ == "__main__":
   unittest.main()














