
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
BIP32MasterPubKey2        = hex_to_binary(
   "04cbcaa9 c98c877a 26977d00 825c956a 238e8ddd fbd322cc e4f74b0b 5bd6ace4"
   "a77bd330 5d363c26 f82c1e41 c667e4b3 561c06c6 0a2104d2 b548e6dd 059056aa 51")
BIP32MasterPubKey2Comp    = hex_to_binary(
   "03cbcaa9 c98c877a 26977d00 825c956a 238e8ddd fbd322cc e4f74b0b 5bd6ace4 a7")
BIP32MasterPubKey2_D1     = hex_to_binary(
   "04fc9e5a f0ac8d9b 3cecfe2a 888e2117 ba3d089d 8585886c 9c826b6b 22a98d12"
   "ea67a505 38b6f7d8 b5f7a1cc 657efd26 7cde8cc1 d8c0451d 1340a0fb 36427775 44")
BIP32MasterPubKey2Comp_D1 = hex_to_binary(
   "02fc9e5a f0ac8d9b 3cecfe2a 888e2117 ba3d089d 8585886c 9c826b6b 22a98d12 ea")

# PKS serializations based on BIP32MasterPubKey2. Uses compressed keys.
PKS1ChksumPres_v0 = hex_to_binary(
   "00004221 03cbcaa9 c98c877a 26977d00 825c956a 238e8ddd fbd322cc e4f74b0b"
   "5bd6ace4 a78df291 90")
PKS1NoChksum_v0 = hex_to_binary(
   "00000221 03cbcaa9 c98c877a 26977d00 825c956a 238e8ddd fbd322cc e4f74b0b"
   "5bd6ace4 a7")

# CS serializations based on BIP32MasterPubKey2. Uses compressed keys.
CS1ChksumPres_v0 = hex_to_binary(
   "00000206 76a9ff01 88ac0125 00000621 03cbcaa9 c98c877a 26977d00 825c956a"
   "238e8ddd fbd322cc e4f74b0b 5bd6ace4 a744677b 26")

CS1NoChksum_v0 = hex_to_binary(
   "00000006 76a9ff01 88ac0125 00000621 03cbcaa9 c98c877a 26977d00 825c956a"
   "238e8ddd fbd322cc e4f74b0b 5bd6ace4 a7")


################################################################################
class PKSClassTests(unittest.TestCase):

   # Use serialize/unserialize to confirm that the data struct is correctly
   # formed and can be correctly formed.
   def testSerialization(self):
      # PKS1 w/ a checksum
      pks1ChksumPres = PublicKeySource()
      pks1ChksumPres.initialize(False, True, False, False, False, False,
                                BIP32MasterPubKey2Comp, True)
      stringPKS1ChksumPres = pks1ChksumPres.serialize()
      self.assertEqual(binary_to_hex(stringPKS1ChksumPres),
                       binary_to_hex(PKS1ChksumPres_v0))

      # PKS1 w/o a checksum.
      pks1NoChksum = PublicKeySource()
      pks1NoChksum.initialize(False, True, False, False, False, False,
                              BIP32MasterPubKey2Comp, False)
      stringPKS1NoChksum = pks1NoChksum.serialize()
      self.assertEqual(binary_to_hex(stringPKS1NoChksum),
                       binary_to_hex(PKS1NoChksum_v0))

      # Unserialize and re-serialize to confirm unserialize works
      pks1ChksumPres_unser = PublicKeySource().unserialize(PKS1ChksumPres_v0)
      pks1NoChksum_unser = PublicKeySource().unserialize(PKS1NoChksum_v0)
      stringPKS1Chksum_unser = pks1ChksumPres_unser.serialize()
      stringPKS1NoChksum_unser = pks1NoChksum_unser.serialize()
      self.assertEqual(binary_to_hex(stringPKS1Chksum_unser),
                       binary_to_hex(PKS1ChksumPres_v0))
      self.assertEqual(binary_to_hex(stringPKS1NoChksum_unser),
                       binary_to_hex(PKS1NoChksum_v0))


################################################################################
class CSClassTests(unittest.TestCase):

   # Use serialize/unserialize to confirm that the data struct is correctly
   # formed and can be correctly formed.
   def testSerialization(self):
      # CS1 w/ a checksum
      cs1ChksumPres = ConstructedScript().StandardP2PKHConstructed(BIP32MasterPubKey2Comp)
      stringCS1ChksumPres = cs1ChksumPres.serialize()
      self.assertEqual(binary_to_hex(stringCS1ChksumPres),
                       binary_to_hex(CS1ChksumPres_v0))

      # CS1 w/o a checksum
      cs1NoChksum = ConstructedScript().StandardP2PKHConstructed(BIP32MasterPubKey2Comp)
      stringCS1ChksumPres = cs1ChksumPres.serialize()
      self.assertEqual(binary_to_hex(stringCS1ChksumPres),
                       binary_to_hex(CS1ChksumPres_v0))

      # Unserialize and re-serialize to confirm unserialize works
      cs1ChksumPres_unser = ConstructedScript().unserialize(CS1ChksumPres_v0)
      stringCS1Chksum_unser = cs1ChksumPres_unser.serialize()
      self.assertEqual(binary_to_hex(stringCS1Chksum_unser),
                       binary_to_hex(CS1ChksumPres_v0))


################################################################################
class DerivationTests(unittest.TestCase):

   # Confirm that BIP32 multipliers can be obtained from C++ and can be used to
   # create keys that match the keys directly derived via BIP32.
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
