
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

############# Various constants we wish to use throughout the tests.
# Master key derived from the 2nd BIP32 test vector + child key 0.
BIP32MasterPubKey2        = hex_to_binary("04cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a77bd3305d363c26f82c1e41c667e4b3561c06c60a2104d2b548e6dd059056aa51");
BIP32MasterPubKey2Comp    = hex_to_binary("03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7");
BIP32MasterPubKey2_D1     = hex_to_binary("04fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea67a50538b6f7d8b5f7a1cc657efd267cde8cc1d8c0451d1340a0fb3642777544");
BIP32MasterPubKey2Comp_D1 = hex_to_binary("02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea");

# PKS serializations based on BIP32MasterPubKey2. Uses compressed keys.
# TODO: Confirm checksum on a known value.
PKS1ChksumPres_v0 = hex_to_binary("0000422103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a78df29190")
PKS1NoChksum_v0 = hex_to_binary("0000422103cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7")

################################################################################
class PKSClassTests(unittest.TestCase):

   #############################################################################
   def testSerialization(self):
      pks1 = PublicKeySource()
      pks1.initialize(False, True, False, False, False, False,
                      BIP32MasterPubKey2Comp, True)
      stringPKS1 = pks1.serialize()
      self.assertEqual(binary_to_hex(stringPKS1), binary_to_hex(PKS1ChksumPres_v0))


################################################################################
class DerivationTests(unittest.TestCase):

   #############################################################################
   def testBIP32Derivation(self):
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
