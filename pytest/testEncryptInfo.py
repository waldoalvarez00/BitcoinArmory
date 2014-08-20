################################################################################
#
# Copyright (C) 2011-2014, Armory Technologies, Inc.                         
# Distributed under the GNU Affero General Public License (AGPL v3)
# See LICENSE or http://www.gnu.org/licenses/agpl.html
#
################################################################################
#
# Project:    Armory
# Author:     Andy Ofiesh
# Website:    www.bitcoinarmory.com
# Orig Date:  2 January, 2014
#
################################################################################
import sys
sys.path.append('..')
import unittest
import sys
sys.path.append('..')

from armoryengine.ArmoryEncryption import *

# NOT a real unit test. To verify this test properly
# uncomment the decorator and specify the email arguments
# The email arguments should never be pushed to the repo
# Run the test and check your email
class ArmoryCryptInfoTest(unittest.TestCase):

   def setUp(self):
      pass
      
   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail("Assert raised in assertNoRaise:" + str(e))
         

   def testStretchIV(self):
      ivShort = SecureBinaryData(hex_to_binary('00112233445566'))
      iv8     = SecureBinaryData(hex_to_binary('0011223344556677'))
      ivLong  = SecureBinaryData(hex_to_binary('001122334455667788'))

      shaIV8  = SecureBinaryData(hex_to_binary( \
         '0379fb77234a85af1a48b2011fe9e5ff6f7c6cc41b6844ddcbb7cfe877fef52c'
         '38ab0e8ed5883567027286602815441c9b47f75a73810ea529588d7890d45ad0'))

      shaIV7  = SecureBinaryData(hex_to_binary( \
         '076395aedf1aeab1e1f00866038fb00b3baea1dbade91c4ef6315bd429811f9a'
         'a6e3966682c2a90ebe11a110418680b0005439fe9f2c0220a993a14528b84c56'))

      self.assertRaises(BadInputError, stretchIV, iv8, 65)
      self.assertRaises(BadInputError, stretchIV, iv8, 0)
      self.assertRaises(TypeError, stretchIV, iv8.toBinStr(), 16)
      self.assertNoRaise(stretchIV, iv8, 1)
      self.assertNoRaise(stretchIV, iv8, 8)
      self.assertNoRaise(stretchIV, iv8, 16)

      # Identity tests
      self.assertEqual(stretchIV(iv8,     8), iv8    )
      self.assertEqual(stretchIV(ivShort, 7), ivShort)
      self.assertEqual(stretchIV(ivLong , 9), ivLong )

      # Truncation tests
      self.assertEqual(stretchIV(ivLong,  8), iv8    )
      self.assertEqual(stretchIV(ivLong,  3).toBinStr(), iv8.toBinStr()[:3])
      
      # Stretch tests
      self.assertEqual(stretchIV(iv8,      9).toBinStr(),  shaIV8.toBinStr()[:9])
      self.assertEqual(stretchIV(iv8,     16).toBinStr(),  shaIV8.toBinStr()[:16])
      self.assertEqual(stretchIV(ivShort,  8).toBinStr(),  shaIV7.toBinStr()[:8])
      self.assertEqual(stretchIV(ivShort, 16).toBinStr(),  shaIV7.toBinStr()[:16])


   def testEkeyID(self):
      keySBD = SecureBinaryData(hex_to_binary('0011223344556677'))
      keyStr =                  hex_to_binary('0011223344556677')
      hmacIV8 = hex_to_binary(\
         'bf6117ac43c76ed02ab9358e0bbbd9f560be499a471c89e799f4ff2c5e56c13f'
         '9b9561496015321b88866debedc3b10875b2537af97d1374bf0fea5b1079f1a6')

      self.assertTrue(calcEKeyID(keySBD), hmacIV8[:8])
      self.assertTrue(calcEKeyID(keyStr), hmacIV8[:8])
      
      

   def testACI_construct(self):
      aci = ArmoryCryptInfo()
      self.assertEqual(aci.kdfObjID, NULLKDF)
      self.assertEqual(aci.encryptAlgo, NULLCRYPT)
      self.assertEqual(aci.keySource, NULLSTR(8))
      self.assertEqual(aci.ivSource, NULLSTR(8))

      self.assertNoRaise(ArmoryCryptInfo, encrAlgo="AE256CFB")
      self.assertNoRaise(ArmoryCryptInfo, encrAlgo="AE256CBC")
      self.assertNoRaise(ArmoryCryptInfo, encrAlgo="IDENTITY")
      self.assertRaises(UnrecognizedCrypto, ArmoryCryptInfo, encrAlgo="UNK")

   def testACI_boolmethods(self):
      aci = ArmoryCryptInfo()
      self.assertTrue(aci.noEncryption())
      self.assertFalse(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertRaises(KeyDataError, aci.getEncryptKeySrc)

      aci = ArmoryCryptInfo(NULLKDF,'AE256CBC','fakkeyid','anything')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertTrue(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.EKEY_OBJ, 'fakkeyid'))

      aci = ArmoryCryptInfo(NULLKDF,'AE256CBC','fakkeyid','PUBKEY20')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.EKEY_OBJ, 'fakkeyid'))
      
      aci = ArmoryCryptInfo('fakkdfid','AE256CBC','PASSWORD','anything')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertTrue(aci.useKeyDerivFunc())
      self.assertTrue(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.PASSWORD, ''))

      aci = ArmoryCryptInfo('fakkdfid','AE256CBC','PARCHAIN','PUBKEY20')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertTrue(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.PARCHAIN, ''))


# Running tests with "python <module name>" will NOT work for any Armory tests
# You must run tests with "python -m unittest <module name>" or run all tests with "python -m unittest discover"
if __name__ == "__main__":
   unittest.main()
