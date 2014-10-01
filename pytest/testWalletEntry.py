import sys
sys.path.append('..')
import unittest
import sys
sys.path.append('..')
import textwrap

from armoryengine.ArmoryUtils import *
from armoryengine.ArmoryEncryption import *
from armoryengine.WalletEntry import *

WALLET_VERSION_BIN = hex_to_binary('002d3101')

# This disables RSEC for all WalletEntry objects.  This causes it to stop
# checking RSEC codes on all entries, and writes all \x00 bytes when creating.
WalletEntry.DisableRSEC()


################################################################################
class MockWalletFile(object):
   def __init__(self):
      self.ekeyMap = {}

   def doFileOperation(*args, **kwargs):
      pass

   def getName(self):
      return 'MockWalletFile'


################################################################################
class MockSerializableObject(WalletEntry):
   FILECODE = "MOCKOBJ_"

   def __init__(self, txt=None):
      self.text = None
      if txt:
         self.setText(txt)

   def setText(self, txt):
      self.text = txt

   def serialize(self):
      bp = BinaryPacker()
      bp.put(VAR_STR, self.text)
      return bp.getBinaryString()

   def unserialize(self, toUnpack):
      bu = makeBinaryUnpacker(toUnpack) 
      self.text = bu.get(VAR_STR)
      

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
class WalletEntryTests(unittest.TestCase):

   #############################################################################
   def testInit(self):
      # Default constructor
      we = WalletEntry()
      self.assertEqual(we.wltFileRef, None)
      self.assertEqual(we.wltByteLoc, None)
      self.assertEqual(we.wltEntrySz, None)
      self.assertEqual(we.isRequired, False)
      self.assertEqual(we.parScrAddr, None)
      self.assertEqual(we.outerCrypt, None)
      self.assertEqual(we.serPayload, None)
      self.assertEqual(we.defaultPad, 256)

      #self.assertEqual(we.flagBitset.toBitString(), '0'*16)

      self.assertEqual(we.wltParentRef, None)
      self.assertEqual(we.wltChildRefs, [])
      self.assertEqual(we.outerEkeyRef, None)

      self.assertEqual(we.isOpaque,        False)
      self.assertEqual(we.isUnrecognized,  False)
      self.assertEqual(we.isUnrecoverable, False)
      self.assertEqual(we.isDeleted,       False)
      self.assertEqual(we.isDisabled,      False)
      self.assertEqual(we.needRewrite,     False)
      self.assertEqual(we.needsFsync,      False)


      # Init with all args supplied
      mockWlt = MockWalletFile()
      we = WalletEntry(mockWlt, 10, 10, True, '\xfa'*21, 
                       ArmoryCryptInfo(None), None, '\xaf'*5, 128)

      self.assertEqual(we.wltFileRef.getName(), 'MockWalletFile')
      self.assertEqual(we.wltByteLoc, 10)
      self.assertEqual(we.wltEntrySz, 10)
      self.assertEqual(we.isRequired, True)
      self.assertEqual(we.parScrAddr, '\xfa'*21)
      self.assertEqual(we.outerCrypt.useEncryption(), False)
      self.assertEqual(we.serPayload, '\xaf'*5)
      self.assertEqual(we.defaultPad, 128)

      #self.assertEqual(we.flagBitset.toBitString(), '0'*16)

      self.assertEqual(we.wltParentRef, None)
      self.assertEqual(we.wltChildRefs, [])
      self.assertEqual(we.outerEkeyRef, None)

      self.assertEqual(we.isOpaque,        False)
      self.assertEqual(we.isUnrecognized,  False)
      self.assertEqual(we.isUnrecoverable, False)
      self.assertEqual(we.isDeleted,       False)
      self.assertEqual(we.isDisabled,      False)
      self.assertEqual(we.needRewrite,     False)
      self.assertEqual(we.needsFsync,      False)


   #############################################################################
   def testSerializeDeleted(self):

      for testSize in [11, 53, 127, 128, 245, 246, 247, 255, 256, 257]:
         we = WalletEntry.CreateDeletedEntry(testSize)
         ser = we.serializeEntry()
         self.assertEqual(len(ser), testSize)

         expected = BinaryPacker()
         expected.put(BINARY_CHUNK, WALLET_VERSION_BIN, 4)
         expected.put(BINARY_CHUNK, '\x80\x00', 2)
         expected.put(UINT32,       testSize-10)
         expected.put(BINARY_CHUNK, '\x00'*(testSize-10))
         self.assertEqual(ser, expected.getBinaryString())


################################################################################
if __name__ == "__main__":
   unittest.main()

