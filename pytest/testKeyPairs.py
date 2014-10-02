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



if __name__ == "__main__":
   unittest.main()
