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
import textwrap

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
         

   #############################################################################
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


   #############################################################################
   def testEkeyID(self):
      keySBD = SecureBinaryData(hex_to_binary('0011223344556677'))
      keyStr =                  hex_to_binary('0011223344556677')
      hmacIV8 = hex_to_binary(\
         'bf6117ac43c76ed02ab9358e0bbbd9f560be499a471c89e799f4ff2c5e56c13f'
         '9b9561496015321b88866debedc3b10875b2537af97d1374bf0fea5b1079f1a6')

      self.assertTrue(calcEKeyID(keySBD), hmacIV8[:8])
      self.assertTrue(calcEKeyID(keyStr), hmacIV8[:8])
      
      

   #############################################################################
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


   #############################################################################
   def testACI_boolmethods(self):
      aci = ArmoryCryptInfo()
      self.assertTrue(aci.noEncryption())
      self.assertFalse(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertRaises(KeyDataError, aci.getEncryptKeySrc)
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

      aci = ArmoryCryptInfo(NULLKDF,'AE256CBC','fakkeyid','anything')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertTrue(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.EKEY_OBJ, 'fakkeyid'))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

      aci = ArmoryCryptInfo(NULLKDF,'AE256CBC','fakkeyid','PUBKEY20')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertFalse(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.EKEY_OBJ, 'fakkeyid'))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())
      
      aci = ArmoryCryptInfo('fakkdfid','AE256CBC','PASSWORD','anything')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertTrue(aci.useKeyDerivFunc())
      self.assertTrue(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.PASSWORD, ''))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

      aci = ArmoryCryptInfo('fakkdfid','AE256CBC','PARCHAIN','PUBKEY20')
      self.assertFalse(aci.noEncryption())
      self.assertTrue(aci.useEncryption())
      self.assertTrue(aci.useKeyDerivFunc())
      self.assertFalse(aci.hasStoredIV())
      self.assertEqual(aci.getEncryptKeySrc(), (CRYPT_KEY_SRC.PARCHAIN, ''))
      ser = aci.serialize()
      self.assertEqual( aci.serialize(),  ArmoryCryptInfo.unserialize(ser).serialize())

   
   #############################################################################
   def testACI_endecrypt_rawkey(self):
      aci = ArmoryCryptInfo(NULLKDF, 'AE256CBC', 'RAWKEY32', 'randomIV')
      self.assertTrue(aci.hasStoredIV())

      rawKey32 = SecureBinaryData('\x3a'*32)
      origPlain = SecureBinaryData('test_encrypt____')  # need to encrypt len%16=0

      result = aci.encrypt(origPlain, rawKey32)
      decrypted = aci.decrypt(result, rawKey32)
      self.assertEqual(decrypted, origPlain)
      
      rawKey33_bad = SecureBinaryData('\x3a'*33)
      self.assertRaises(EncryptionError, aci.encrypt, origPlain, rawKey33_bad)
      self.assertRaises(InitVectError, aci.encrypt, origPlain, rawKey32, 
                                                ivData=SecureBinaryData('aaa'))

      plain_bad = SecureBinaryData('test_encrypt___')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, rawKey32)

      plain_bad = SecureBinaryData('test_encrypt_____')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, rawKey32)
      self.assertEqual(aci.tempKeyDecrypt.getSize(), 0)


      # Try it with something longer than one blocksize
      origPlain = SecureBinaryData('test_encrypt___test_encrypt_____test_encrypt____')  
      result = aci.encrypt(origPlain, rawKey32)
      decrypted = aci.decrypt(result, rawKey32)
      self.assertEqual(decrypted, origPlain)


   #############################################################################
   def testACI_endecrypt_password(self):
      memReqd = 4194304
      numIter = 3
      salt    = SecureBinaryData(hex_to_binary( \
                  '38c1355eb2b39330bab691b58b7ee0c0c7fbc6c706c088244d3fd3becea5e958'))
      passwd = SecureBinaryData('TestPassword')
      expectKey = SecureBinaryData(hex_to_binary( \
                  'affc2dbe749a9f5b3c01b4a88fb150fcdb7b10187555e9009265eec911108e8b'))
      kdf = KdfObject('ROMIXOV2', memReqd=memReqd, numIter=numIter, salt=salt)
      kdfID = hex_to_binary('92c130cd7399b061')

      aci = ArmoryCryptInfo(kdfID, 'AE256CBC', 'PASSWORD', 'randomIV')
      self.assertTrue(aci.hasStoredIV())

      origPlain = SecureBinaryData('test_encrypt____')  # need to encrypt len%16=0

      # This key we know should come out of the KDF for its params and pwd
      self.assertEqual(kdf.execKDF(passwd), expectKey)
      expectEncrypted = CryptoAES().EncryptCBC(origPlain, expectKey, aci.getEncryptIVSrc()[2])

      computedEncrypted = aci.encrypt(origPlain, passwd, kdfObj=kdf)
      self.assertEqual(expectEncrypted, computedEncrypted)

      decrypted = aci.decrypt(computedEncrypted, passwd, kdfObj=kdf)
      self.assertEqual(decrypted, origPlain)


      # Try it passing in a kdf map
      kdfmap = {kdf.getKdfID(): kdf}
      computedEncrypted = aci.encrypt(origPlain, passwd, kdfObj=kdfmap)
      decrypted = aci.decrypt(computedEncrypted, passwd, kdfObj=kdfmap)
      self.assertEqual(decrypted, origPlain)
      self.assertEqual(decrypted.getSize(), 16)

      # Try it with something longer than one blocksize
      origPlain = SecureBinaryData('test_encrypt___test_encrypt_____test_encrypt____')  
      result = aci.encrypt(origPlain, passwd, kdfObj=kdf)
      decrypted = aci.decrypt(result, passwd, kdfObj=kdf)
      self.assertEqual(decrypted, origPlain)
      self.assertEqual(decrypted.getSize(), 48)

      # Now some things that shoudl cause us to fail
      self.assertRaises(InitVectError, aci.encrypt, origPlain, passwd, 
                                                ivData=SecureBinaryData('aaa'))

      # Pass it a map that doesn't have the kdf in it
      self.assertRaises(KdfError, aci.encrypt, origPlain, passwd, kdfObj={})

      # Repeat the not-properly-padded tests 
      plain_bad = SecureBinaryData('test_encrypt___')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, passwd)
      plain_bad = SecureBinaryData('test_encrypt_____')  # not padded
      self.assertRaises(EncryptionError, aci.encrypt, plain_bad, passwd)
      self.assertEqual(aci.tempKeyDecrypt.getSize(), 0)


################################################################################
################################################################################
class ArmoryKDFTests(unittest.TestCase):

   def setUp(self):
      pass
      
   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail("Assert raised in assertNoRaise:" + str(e))
         

   #############################################################################
   def testConstructKDF(self):
      mem   = 64*KILOBYTE
      niter = 2
      salt  = hex_to_binary('5c'*16)

      self.assertNoRaise(KdfObject)
      self.assertNoRaise(KdfObject, 'IDENTITY')
      self.assertRaises(BadInputError, KdfObject, 'ROMIXOV2')
      self.assertNoRaise(KdfObject, 'ROMIXOV2', memReqd=mem, numIter=niter, salt=salt)


   #############################################################################
   def testKDFSerUnserRT(self):
      mem   = 64*KILOBYTE
      niter = 2
      salt  = hex_to_binary('5c'*16)
      kdf = KdfObject('ROMIXOV2', memReqd=mem, numIter=niter, salt=salt)
      expectedID = hex_to_binary('a69c7bf79583f155')

      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, 'ROMIXOV2')
      bp.put(BINARY_CHUNK, 'sha512__')
      bp.put(UINT32,       int(64*KILOBYTE))
      bp.put(UINT32,       2)
      bp.put(VAR_STR,      '\x5c'*16)
      expectedSerialize = bp.getBinaryString()
      self.assertEqual(kdf.serialize(), expectedSerialize)
      self.assertEqual(kdf.getKdfID(), expectedID)
      
      kdf = KdfObject().unserialize(expectedSerialize)
      self.assertEqual(kdf.serialize(), expectedSerialize)
      

   #############################################################################
   def testRunKDF(self):
      # These KDF params were taken directly from a testnet wallet in 0.92
      memReqd = 4194304
      numIter = 3
      salt    = SecureBinaryData(hex_to_binary( \
                  '38c1355eb2b39330bab691b58b7ee0c0c7fbc6c706c088244d3fd3becea5e958'))
      
      passwd = SecureBinaryData('TestPassword')
      expectKey = SecureBinaryData(hex_to_binary( \
                  'affc2dbe749a9f5b3c01b4a88fb150fcdb7b10187555e9009265eec911108e8b'))

      kdf = KdfObject('ROMIXOV2', memReqd=memReqd, numIter=numIter, salt=salt)
      actualOut = kdf.execKDF(passwd)
      self.assertEqual(actualOut, expectKey)


   #############################################################################
   def testCreateNewKDF(self):
      timeTgt = 0.5
      memTgt  = 64*KILOBYTE

      self.assertNoRaise(KdfObject.CreateNewKDF, 'IDENTITY')
      self.assertRaises(KeyError, KdfObject.CreateNewKDF, 'ROMIXOV2')

      newkdf = KdfObject.CreateNewKDF('ROMIXOV2', targSec=timeTgt, maxMem=memTgt)


      start = RightNow()
      newkdf.execKDF(SecureBinaryData('TestPassword'))
      timeTaken = RightNow() - start

      if not (timeTgt/3 < timeTaken < 1.5*timeTgt):
         print '%s:  KDF computational-target test failed' % self.id()
         print textwrap.dedent("""
            THIS TEST SHOUILD BE DISABLED IF THE TESTING ENV IS NOT CONSISTENT
            The computational test may execute under different loads than the final
            execution.  We expect compute time to between T/2 and T, and we explicitly 
            check for between T/3 and 1.5*T to accommodate small inconsistencies.
            This is expected to always pass, but it is feasible that conditions are
            not such that we can expect this to pass consistently.""")
         print 'Time Target: %0.2f' % timeTgt
         print 'Actual Time: %0.2f' % timeTaken
         self.fail('KDF computational-target test failed')
         

      if not (newkdf.memReqd == memTgt):
         print '%s:  KDF computational-target test failed' % self.id()
         print textwrap.dedent("""
            THIS TEST SHOULD BE DISABLED IF TESTING ENV IS EXCEPTIONALLY SLOW
            We have chosen a low max memory for the time target (%0.2f sec) so   
            that it's likely the KDF will hit that limit and be required to 
            increase numIter instead.  If this test is run on an exceptionally 
            slow machine (RPi?), this might not be the case.  In that case, 
            this test should be disabled.""" % timeTgt)
         print 'Mem Expected: %d' % int(memTgt)
         print 'Actual Mem:   %d' % int(newkdf.memReqd)
         self.assertTrue( newkdf.getMemoryReqtBytes() == memTgt)


################################################################################
################################################################################
class ArmoryEncryptKeyTests(unittest.TestCase):

   def setUp(self):
      # Use the KDF from KDF tests.  We already know its ID, pwd output, etc.
      memReqd = 4194304
      numIter = 3
      salt    = SecureBinaryData(hex_to_binary( \
                  '38c1355eb2b39330bab691b58b7ee0c0c7fbc6c706c088244d3fd3becea5e958'))
      self.passwd = SecureBinaryData('TestPassword')
      expectKey = SecureBinaryData(hex_to_binary( \
                  'affc2dbe749a9f5b3c01b4a88fb150fcdb7b10187555e9009265eec911108e8b'))
      self.kdf = KdfObject('ROMIXOV2', memReqd=memReqd, numIter=numIter, salt=salt)
      self.kdfID = hex_to_binary('92c130cd7399b061')
      
      self.rawKey32 = SecureBinaryData('\x3a'*32)


   def tearDown(self):
      pass

   def assertNoRaise(self, func, *args, **kwargs):
      try:
         func(*args, **kwargs)
      except Exception as e:
         self.fail('Assert raised in assertNoRaise: "' + str(e) + '"')


   #############################################################################
   def testEkeyConstruct_NULL(self):
      self.assertNoRaise(EncryptionKey)
         
      ekey = EncryptionKey()
      self.assertEqual(ekey.ekeyID,          NULLSBD())
      self.assertEqual(ekey.masterKeyCrypt,  NULLSBD())
      self.assertEqual(ekey.masterKeyPlain,  NULLSBD())
      self.assertEqual(ekey.testStringEncr,  NULLSBD())
      self.assertEqual(ekey.testStringPlain, NULLSBD())
      self.assertEqual(ekey.keyTripleHash,   NULLSBD())
      self.assertEqual(ekey.relockAtTime,    0)
      self.assertEqual(ekey.lockTimeout,     10)

      self.assertTrue(ekey.keyCryptInfo.noEncryption())

      self.assertRaises(EncryptionError, ekey.getEncryptionKeyID)
   

   #############################################################################
   def testEkeyCreate(self):

      ekey = EncryptionKey()
      self.assertRaises(UnrecognizedCrypto, 
                     ekey.CreateNewMasterKey, self.kdf, 'UNK', self.passwd)

      #ekey.CreateNewMasterKey(self.kdf, 'AE256CBC', self.passwd, 
                                                      #preGenKey=self.rawKey32)
      
      






# Running tests with "python <module name>" will NOT work for any Armory tests
# You must run tests with "python -m unittest <module name>" or run all tests with "python -m unittest discover"
if __name__ == "__main__":
   unittest.main()
