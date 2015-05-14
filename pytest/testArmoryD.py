'''
Created on Oct 8, 2013

@author: Andy
'''
import sys
from unittest.case import SkipTest
sys.path.append('..')
import os
import time
import json
from pytest.Tiab import TiabTest
from CppBlockUtils import SecureBinaryData, CryptoECDSA
from armoryd import Armory_Json_Rpc_Server, PrivateKeyNotFound, \
   InvalidBitcoinAddress, WalletUnlockNeeded, AmountToJSON
from armoryengine.ArmoryUtils import hex_to_binary, \
   binary_to_base58, binary_to_hex, convertKeyDataToAddress, hash160_to_addrStr,\
   hex_switchEndian, hash160, BIGENDIAN, privKey_to_base58, EncryptionError
from armoryengine.ArmoryKeyPair import CreateChildIndex
from armoryengine.ArmoryWallet import ArmoryWalletFile
from armoryengine.BDM import TheBDM, REFRESH_ACTION
from armoryengine.PyBtcWallet import PyBtcWallet
from armoryengine.Transaction import PyTx


TEST_WALLET_NAME = 'Test Wallet Name'
TEST_WALLET_DESCRIPTION = 'Test Wallet Description'
TEST_WALLET_FILE_ID = '1BsmPcJN'
TEST_WALLET_ID = '2AF4BhVoC'

TEST_ADDRESS = "mrFNfhs1qhKXGq1FZ8qNm241fQPiNWEDMw"

RAW_TX1    = '0100000001b5dbdcea08ae1ff5a547755aaab7f468a6091a573ae76c6fa5a3fcf5ec65b804010000008b4830450220081341a4e803c7c8e64c3a3fd285dca34c9f7c71c4dfc2b576d761c5783ce735022100eea66ba382d00e628d86fc5bc1928a93765e26fd8252c4d01efe22147c12b91a01410458fec9d580b0c6842cae00aecd96e89af3ff56f5be49dae425046e64057e0f499acc35ec10e1b544e0f01072296c6fa60a68ea515e59d24ff794cf8923cd30f4ffffffff0200943577000000001976a91462d978319c7d7ac6cceed722c3d08aa81b37101288acf02c41d1160000001976a91409097379782fadfbd72e5a818219cf2eb56249d288ac00000000'
TX_ID1      = 'db0ee46beff3a61f38bfc563f92c11449ed57c3d7d5cd5aafbe0114e5a9ceee4'

TX_ID1_OUTPUT0_VALUE = 20.0
TX_ID1_OUTPUT1_VALUE = 979.9999

PASSPHRASE1 = 'abcde'
PASSPHRASE2 = 'fghij'
UNLOCK_TIMEOUT = 3

# These tests could be run in or out of the TiaB
class ArmoryDTest(TiabTest):
   def removeFileList(self, fileList):
      for f in fileList:
         if os.path.exists(f):
            os.remove(f)

   def armoryDTestCallback(self, action, args):
      if action == REFRESH_ACTION:
         self.walletIsScanned = True

   def setUp(self):

      self.verifyBlockHeight()
      self.fileA    = os.path.join(self.armoryHomeDir, 'armory_wallet2.0_%s.wlt' % TEST_WALLET_FILE_ID)
      self.fileB    = os.path.join(self.armoryHomeDir, 'armory_wallet2.0_%s_backup.wlt' % TEST_WALLET_FILE_ID)
      self.fileAupd = os.path.join(self.armoryHomeDir, 'armory_wallet2.0_%s_backup_unsuccessful.wlt' % TEST_WALLET_FILE_ID)
      self.fileBupd = os.path.join(self.armoryHomeDir, 'armory_wallet2.0_%s_update_unsuccessful.wlt' % TEST_WALLET_FILE_ID)

      self.removeFileList([self.fileA, self.fileB, self.fileAupd, self.fileBupd])

      # We need a controlled test, so we script the all the normally-random stuff
      self.privKey   = SecureBinaryData('\xaa'*32)
      self.privKey2  = SecureBinaryData('\x33'*32)
      self.chainstr  = SecureBinaryData('\xee'*32)
      theIV     = SecureBinaryData(hex_to_binary('77'*16))
      self.passphrase  = SecureBinaryData(PASSPHRASE1)
      self.passphrase2 = SecureBinaryData(PASSPHRASE2)

      #register a callback
      TheBDM.registerCppNotification(self.armoryDTestCallback)

      #flag to check on wallet scan status
      self.walletIsScanned = False

      #create the wallet
      self.walletFile = ArmoryWalletFile.CreateWalletFile_SinglePwd(
         TEST_WALLET_NAME, self.passphrase, sbdPregeneratedSeed=theIV,
         createInDir=self.armoryHomeDir)
      root = self.walletFile.topLevelRoots[0]
      # go down to the ABEK_BIP44Purpose level "purpose"
      childIndex = CreateChildIndex(44, isHardened=True)
      purpose = root.getChildByIndex(childIndex)

      # go down to the ABEK_StdBip32Seed level "cointype"
      childIndex = CreateChildIndex(1, isHardened=True)
      cointype = purpose.getChildByIndex(childIndex)
      childIndex = CreateChildIndex(0, isHardened=True)
      self.wallet = cointype.getChildByIndex(childIndex)
      childIndex = CreateChildIndex(1, isHardened=True)
      cointype.unlock(self.passphrase)
      self.wallet2 = cointype.getChildByIndex(childIndex, spawnIfNeeded=True, fsync=True)

      inWltMap = {
         self.wallet.uniqueIDB58: self.wallet,
         self.wallet2.uniqueIDB58: self.wallet2,
      }

      self.jsonServer = Armory_Json_Rpc_Server(self.wallet, inWltMap=inWltMap)

      #register it
      self.wallet.registerWallet()

      #wait on scan for 2 min then raise if the scan hasn't finished yet
      i = 0
      while not self.walletIsScanned:
         time.sleep(0.5)
         i += 1
         if i >= 60*4:
            raise RuntimeError("Timeout waiting for TheBDM to register the wallet.")

   def tearDown(self):
      TheBDM.unregisterCppNotification(self.armoryDTestCallback)
      self.wallet.unregisterWallet()
      self.removeFileList([self.fileA, self.fileB, self.fileAupd, self.fileBupd])


   def testBackupWallet(self):
      backupTestPath = os.path.join(
         self.armoryHomeDir,
         'armory_wallet2.0_%s_backup.wlt.test' % TEST_WALLET_FILE_ID)
      # Remove backupTestPath in case it exists
      backupFileList = [backupTestPath, self.fileB]
      self.removeFileList(backupFileList)
      # Remove the backup test path that is to be created after tear down.
      self.addCleanup(self.removeFileList, backupFileList)
      self.jsonServer.jsonrpc_backupwallet(backupTestPath)
      self.assertTrue(os.path.exists(backupTestPath))
      self.walletFile.backupWalletFile()
      self.assertTrue(os.path.exists(self.fileB))

   def testClearAddressMetadata(self):
      metadata = {TEST_ADDRESS:{"something": "whatever"}}
      self.jsonServer.jsonrpc_setaddressmetadata(metadata)
      result = self.jsonServer.jsonrpc_getaddressmetadata()
      self.assertEqual(result[TEST_ADDRESS]["something"], "whatever")
      self.jsonServer.jsonrpc_clearaddressmetadata()
      result = self.jsonServer.jsonrpc_getaddressmetadata()
      self.assertEqual(result, {})


   def testDecodeRawTransaction(self):
      actualDD = self.jsonServer.jsonrpc_decoderawtransaction(RAW_TX1)
      # Test specific values pulled from bitcoin daemon's output for the test raw TX
      expectScriptStr = 'OP_DUP OP_HASH160 PUSHDATA(20) [62d978319c7d7ac6cceed722c3d08aa81b371012] OP_EQUALVERIFY OP_CHECKSIG'
      self.assertEqual(actualDD['locktime'], 0)
      self.assertEqual(actualDD['version'], 1)
      self.assertEqual(len(actualDD['vin']), 1)
      self.assertEqual(actualDD['vin'][0]['sequence'], 4294967295L)
      self.assertEqual(actualDD['vin'][0]['scriptSig']['hex'], '4830450220081341a4e803c7c8e64c3a3fd285dca34c9f7c71c4dfc2b576d761c5783ce735022100eea66ba382d00e628d86fc5bc1928a93765e26fd8252c4d01efe22147c12b91a01410458fec9d580b0c6842cae00aecd96e89af3ff56f5be49dae425046e64057e0f499acc35ec10e1b544e0f01072296c6fa60a68ea515e59d24ff794cf8923cd30f4')
      self.assertEqual(actualDD['vin'][0]['vout'], 1)
      self.assertEqual(actualDD['vin'][0]['txid'], '04b865ecf5fca3a56f6ce73a571a09a668f4b7aa5a7547a5f51fae08eadcdbb5')
      self.assertEqual(len(actualDD['vout']), 2)
      self.assertEqual(actualDD['vout'][0]['value'], 20.0)
      self.assertEqual(actualDD['vout'][0]['n'], 0)
      self.assertEqual(actualDD['vout'][0]['scriptPubKey']['reqSigs'], 1)
      self.assertEqual(actualDD['vout'][0]['scriptPubKey']['hex'], '76a91462d978319c7d7ac6cceed722c3d08aa81b37101288ac')
      self.assertEqual(actualDD['vout'][0]['scriptPubKey']['addresses'], ['mpXd2u8fPVYdL1Nf9bZ4EFnqhkNyghGLxL'])
      self.assertEqual(actualDD['vout'][0]['scriptPubKey']['asm'], expectScriptStr)
      self.assertEqual(actualDD['vout'][0]['scriptPubKey']['type'], 'Standard (PKH)')
      self.assertEqual(actualDD['vout'][1]['scriptPubKey']['type'], 'Standard (PKH)')

   def testDumpPrivKey(self):
      testPrivKey = self.privKey.toBinStr()
      hash160 = convertKeyDataToAddress(testPrivKey)
      addr58 = hash160_to_addrStr(hash160)

      # Verify that a locked wallet Raises WalletUnlockNeeded Exception
      self.wallet.lock()
      result = self.jsonServer.jsonrpc_dumpprivkey(addr58, 'hex')
      self.assertEqual(result['Error Type'],'WalletUnlockNeeded')

      # unlock the wallet
      result =  self.jsonServer.jsonrpc_walletpassphrase(PASSPHRASE1)

      # Verify that a bogus addrss Raises InvalidBitcoinAddress Exception
      result =  self.jsonServer.jsonrpc_dumpprivkey('bogus', 'hex')
      self.assertEqual(result['Error Type'],'InvalidBitcoinAddress')

      result =  self.jsonServer.jsonrpc_dumpprivkey(addr58, 'hex')
      self.assertEqual(result['Error Type'],'PrivateKeyNotFound')

      # verify that the first private key can be found
      firstAddr = self.wallet.getNextReceivingAddress()
      firstAddr58 = firstAddr.getAddrStr()
      actualPrivateKeyHex = self.jsonServer.jsonrpc_dumpprivkey(firstAddr58, \
                                                                'hex')
      actualPrivateKeyB58 = self.jsonServer.jsonrpc_dumpprivkey(firstAddr58, \
                                                                'base58')

      # the private key is now compressed, so we need the \x01 at the end
      self.privKey = firstAddr.getPlainPrivKeyCopy().toBinStr() + "\x01"
      expectedPrivateKeyHex = binary_to_hex(self.privKey)
      expectedPrivateKeyB58 = privKey_to_base58(self.privKey)
      self.assertEqual(actualPrivateKeyHex, expectedPrivateKeyHex)
      self.assertEqual(actualPrivateKeyB58, expectedPrivateKeyB58)


   def testEncryptWallet(self):
      # verify that the passphrase can be changed
      result = self.jsonServer.jsonrpc_encryptwallet(PASSPHRASE1, PASSPHRASE2)
      successMessage = 'Wallet %s has been encrypted.' % TEST_WALLET_ID
      self.assertEqual(result, successMessage)
      self.assertTrue(self.wallet.isLocked())

      # Verify that changing the encryption to the same passphrase raises
      # an error
      result = self.jsonServer.jsonrpc_encryptwallet(PASSPHRASE2, PASSPHRASE2)
      self.assertEqual(result.get('Error Type'), 'EncryptionError')

      # Verify that giving the wrong passphrase results in an error
      result = self.jsonServer.jsonrpc_encryptwallet(PASSPHRASE1, PASSPHRASE2)
      self.assertEqual(result, 'Wrong passphrase given')

      # change back the passphrase
      result = self.jsonServer.jsonrpc_encryptwallet(PASSPHRASE2, PASSPHRASE1)
      self.assertEqual(result, successMessage)


   def testGetActiveWallet(self):
      result = self.jsonServer.jsonrpc_getactivewallet()
      self.assertEquals(result,TEST_WALLET_ID)

   def testGetAddrBalance(self):
      for btype in ['spendable','spend', 'unconf', 'unconfirmed',
                    'ultimate','unspent', 'full']:
         result = self.jsonServer.jsonrpc_getaddrbalance(TEST_ADDRESS, btype)
         self.assertEqual(result, 20.0)

   def testGetAddressMetadata(self):
      metadata = {TEST_ADDRESS:{"something": "whatever"}}
      self.jsonServer.jsonrpc_setaddressmetadata(metadata)
      result = self.jsonServer.jsonrpc_getaddressmetadata()
      self.assertEqual(result[TEST_ADDRESS]["something"], "whatever")

   def testGetArmoryDInfo(self):
      result = self.jsonServer.jsonrpc_getarmorydinfo()
      expected = 20000000
      self.assertEqual(result.get("walletversion"), expected)

   def testGetBalance(self):
      for ballanceType in ['spendable','spend', 'unconf', \
                           'unconfirmed', 'total', 'ultimate','unspent', 'full']:
         result = self.jsonServer.jsonrpc_getbalance(ballanceType)
         expected = AmountToJSON(self.wallet.getBalance(ballanceType))
         self.assertEqual(result, expected)

   def testGetBlock(self):
      blockhash = "00000000081aea6340b72bd672e0901f5903539cf97708f8cc228019294882a8"
      result = self.jsonServer.jsonrpc_getblock(blockhash)
      expected = 1130915092
      self.assertEqual(result.get("nonce"), expected)

   def testGetNewAddress(self):
      addr = self.jsonServer.jsonrpc_getnewaddress()
      self.assertEqual(len(addr), 34)

      addr2 = self.jsonServer.jsonrpc_getnewaddress(1)
      self.assertEqual(len(addr2), 34)

      self.assertNotEqual(addr, addr2)

   def testGetRawTransaction(self):
      actualRawTx = self.jsonServer.jsonrpc_getrawtransaction(TX_ID1)
      pyTx = PyTx().unserialize(hex_to_binary(actualRawTx))
      self.assertEquals(TX_ID1, binary_to_hex(pyTx.getHash(), BIGENDIAN))

   def testGetReceivedByAddress(self):
      result = self.jsonServer.jsonrpc_getreceivedbyaddress(TEST_ADDRESS)
      self.assertEqual(result, 20.0)

   def testGetTransaction(self):
      result = self.jsonServer.jsonrpc_gettransaction(TX_ID1)
      self.assertEqual(result["inputs"][0]["address"], "mtZ2d1jFZ9YNp3Ku5Fb2u8Tfu3RgimBHAD")

   def testGetTxOut(self):
      txOut = self.jsonServer.jsonrpc_gettxout(TX_ID1, 0)
      self.assertEquals(txOut['value'],TX_ID1_OUTPUT0_VALUE)
      txOut = self.jsonServer.jsonrpc_gettxout(TX_ID1, 1)
      self.assertEquals(txOut['value'],TX_ID1_OUTPUT1_VALUE)

   def testGetWalletInfo(self):
      self.wallet.lock()
      wltInfo = self.jsonServer.jsonrpc_getwalletinfo()
      # TODO: add checks for wallet name once wallet label stuff works
#      self.assertEqual(wltInfo['name'], TEST_WALLET_NAME)
#      self.assertEqual(wltInfo['description'], TEST_WALLET_DESCRIPTION)
      self.assertEqual(wltInfo['balance'], AmountToJSON(self.wallet.getBalance('Spend')))
      e = self.wallet.external.childIndex
      i = self.wallet.internal.childIndex
      self.assertEqual(wltInfo['numaddrgen'], e+i)
      self.assertEqual(wltInfo['externaladdrgen'], e)
      self.assertEqual(wltInfo['internaladdrgen'], i)
      self.assertEqual(wltInfo['islocked'], True)

   def testHelp(self):
      result = self.jsonServer.jsonrpc_help()
      self.assertEqual(result["help"]["Description"], "Get a directionary with all functions the armoryd server can run.")

   # TODO Fix this
   def testImportPrivKey(self):
      originalLength = len(self.wallet.linearAddr160List)
      self.jsonServer.jsonrpc_importprivkey(binary_to_hex(self.privKey2.toBinStr()))
      self.assertEqual(len(self.wallet.linearAddr160List), originalLength+1)

   def testListAddresses(self):
      result = self.jsonServer.jsonrpc_listaddresses()
      self.assertEqual(result["internal"][0], TEST_ADDRESS)

   def testListLoadedWallets(self):
      result = self.jsonServer.jsonrpc_listloadedwallets()
      self.assertEqual(result["Wallet 0001"], TEST_WALLET_ID)

   def testListAddrUnspent(self):
      result = self.jsonServer.jsonrpc_listaddrunspent(TEST_ADDRESS)
      self.assertEqual(result['totalbalance'], 20.0)

   # TODO Fix this
   # Can't test with actual transactions in this environment. See ARMORY-34.
   # This wallet has no txs
   def testListUnspent(self):
       actualResult = self.jsonServer.jsonrpc_listunspent()
       self.assertEqual(actualResult, [])

   def testSetActiveWallet(self):
      result = self.jsonServer.jsonrpc_setactivewallet('nonsense')
      expected = 'Wallet nonsense does not exist.'
      self.assertEquals(result, expected)

      result = self.jsonServer.jsonrpc_setactivewallet(self.wallet2.uniqueIDB58)
      expected = 'Wallet %s is now active.' % self.wallet2.uniqueIDB58
      self.assertEquals(result, expected)

   def testSetAddressMetadata(self):
      self.jsonServer.jsonrpc_clearaddressmetadata()
      metadata = {TEST_ADDRESS:{"blah": "whatever it is"}}
      self.jsonServer.jsonrpc_setaddressmetadata(metadata)
      result = self.jsonServer.jsonrpc_getaddressmetadata()
      self.assertEqual(result[TEST_ADDRESS]["blah"], "whatever it is")


   def testWalletPassphrase(self):
      self.wallet.lock()
      self.jsonServer.jsonrpc_walletpassphrase(PASSPHRASE1, UNLOCK_TIMEOUT)
      self.assertFalse(self.wallet.isLocked())
      time.sleep(UNLOCK_TIMEOUT+2)
      self.wallet.checkLockTimeout()
      self.assertTrue(self.wallet.isLocked())

   def testWalletLock(self):
      self.jsonServer.jsonrpc_walletlock()
      self.assertTrue(self.wallet.isLocked())



# Running tests with "python <module name>" will NOT work for any Armory tests
# You must run tests with "python -m unittest <module name>" or run all tests with "python -m unittest discover"
# if __name__ == "__main__":
#    unittest.main()
