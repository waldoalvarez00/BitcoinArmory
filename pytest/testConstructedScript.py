
import sys
sys.path.append('..')
import hashlib
import locale
from random import shuffle
import time
import unittest

from CppBlockUtils import HDWalletCrypto
from armoryengine.ArmoryUtils import *
from armoryengine.BinaryPacker import *
from armoryengine.BinaryUnpacker import *
import armoryengine.ArmoryUtils
from armoryengine import ArmoryUtils
from armoryengine import ArmoryUtils
from armoryengine.ConstructedScript import *

################################################################################
################################################################################
class CSClassTests(unittest.TestCase):

   #############################################################################
   def testParseKeys(self):
      fakerootprv = SecureBinaryData('\xf1'*32)
      masterExtPrv = HDWalletCrypto().convertSeedToMasterKey(fakerootprv)
      sbdPubKey = masterExtPrv.getPublicKey()
      sbdChain  = masterExtPrv.getChaincode()

      # Get the final pub key and the multiplier proofs, then confirm that we
      # can reverse engineer the final key with the proofs and the root pub key.
      # Note that the proofs will be based on a compressed root pub key.
      finalPub, multProof = DeriveBip32PublicKeyWithProof(sbdPubKey.toBinStr(),
                                                          sbdChain.toBinStr(),
                                                          [2, 12, 37])
      final1 = ApplyProofToRootKey(sbdPubKey.toBinStr(), multProof)
      final2 = ApplyProofToRootKey(sbdPubKey.toBinStr(), multProof, finalPub)

      self.assertEqual(final1, finalPub)
      self.assertEqual(final1, final2)


if __name__ == "__main__":
   unittest.main()
