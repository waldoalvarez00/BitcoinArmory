################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
from ArmoryUtils import *
from ArmoryEncryption import *
from WalletEntry import *


HARDBIT = 0x80000000


# AKP  ~ ArmoryKeyPair
# ABEK ~ ArmoryBip32ExtendedKey
# MBEK ~ MultisigBip32ExtendedKey  # just a collection of ABEKs for multisig
# These are here b/c they might be tweaked in the future.  All other numerics
# are defined within the classes themselves
DEFAULT_CHILDPOOLSIZE = {}
DEFAULT_CHILDPOOLSIZE['ABEK_BIP44Seed']    = 0  # no keypool
DEFAULT_CHILDPOOLSIZE['ABEK_BIP44Purpose'] = 0  # no keypool
DEFAULT_CHILDPOOLSIZE['ABEK_BIP44Bitcoin'] = 2  # Look two wallets ahead

DEFAULT_CHILDPOOLSIZE['ABEK_StdBip32Seed']  = 2  # Look two wallets ahead
DEFAULT_CHILDPOOLSIZE['ABEK_SoftBip32Seed'] = 2  # Look two wallets ahead
DEFAULT_CHILDPOOLSIZE['ABEK_StdWallet']     = 2
DEFAULT_CHILDPOOLSIZE['ABEK_StdChainExt']   = 100
DEFAULT_CHILDPOOLSIZE['ABEK_StdChainInt']   = 5
DEFAULT_CHILDPOOLSIZE['ABEK_StdLeaf']       = 0  # leaf node

DEFAULT_CHILDPOOLSIZE['MBEK_StdWallet']    = 5
DEFAULT_CHILDPOOLSIZE['MBEK_StdChainExt']  = 50
DEFAULT_CHILDPOOLSIZE['MBEK_StdChainInt']  = 10
DEFAULT_CHILDPOOLSIZE['MBEK_StdLeaf']      = 0  # leaf node

DEFAULT_CHILDPOOLSIZE['Armory135Root']     = 1000  # old Armory wallets
DEFAULT_CHILDPOOLSIZE['Armory135KeyPair']  = 1     # old Armory wallets


# A key type with no constraints on child generation, mainly for testing
DEFAULT_CHILDPOOLSIZE['ABEK_Generic'] = 5

#                        0          1             2             3             4
PRIV_KEY_AVAIL = enum('Uninit', 'WatchOnly', 'Available', 'NeedDecrypt', 'NextUnlock')


#####
def SplitChildIndex(cIdx): 
   if not 0 <= cIdx < 2**32:
      raise ValueError('Child indices must be less than 2^32')
   childNum   = int(cIdx & 0x7fffffff)
   isHardened = (cIdx & HARDBIT) > 0
   return [childNum, isHardened]

#####
def CreateChildIndex(childNum, isHardened): 
   if not childNum < 1<<31:
      raise ValueError('Child number must be less than 2^31')

   topBit = HARDBIT if isHardened else 0
   return childNum | topBit   

#####
def ChildIndexToStr(cIdx):
   cnum,hard = SplitChildIndex(cIdx)
   return str(cnum) + ("'" if hard else '')


class ChildDeriveError(Exception): pass


# DECORATOR
# Use this for AEK functions that assume ekey is available and unlocked.  
# This not only checks that the key is unlocked, it sets a flag that prevents 
# another thread from locking the Ekey
def EkeyMustBeUnlocked(func):

   def wrappedFunc(*args, **kwargs):
      aekSelf = args[0]
      if aekSelf.masterEkeyRef is None:
         return func(*args, **kwargs)
         
      if aekSelf.masterEkeyRef.isLocked():
         raise WalletLockError('Ekey locked when calling %s' % func.__name__)

      try:
         aekSelf.masterEkeyRef.markKeyInUse()
         return func(*args, **kwargs)
      finally:
         aekSelf.masterEkeyRef.finishedWithKey()
         
   return wrappedFunc




################################################################################
#
# AKP ~ ArmoryKeyPair
#
################################################################################
class ArmoryKeyPair(WalletEntry):
   """
   This is essentailly a pure virtual class.  It's not intended to be used by
   itself, 
   """

   #############################################################################
   def __init__(self):
      super(ArmoryKeyPair, self).__init__()

      # Stuff mainly
      self.isWatchOnly     = False
      self.privCryptInfo   = NULLCRYPTINFO()
      self.sbdPrivKeyData  = NULLSBD()
      self.sbdPublicKey33  = NULLSBD()
      self.sbdChaincode    = NULLSBD()
      self.useCompressPub  = True
      self.isUsed          = False
      self.keyBornTime     = 0
      self.keyBornBlock    = 0
      self.privKeyNextUnlock = False
      self.akpParScrAddr   = None
      self.childIndex      = None
      self.isRootRoot      = False

      # Used for the recursive fill-keypool call
      self.childPoolSize   = DEFAULT_CHILDPOOLSIZE[self.getName()]
      self.maxChildren     = UINT32_MAX

      # Some parameters that might be slow to calc
      self.rawScript       = None
      self.scrAddrStr      = None
      self.uniqueIDBin     = None   
      self.uniqueIDB58     = None   # wallet ID used in filename

      # A bunch of references that will be set after all WalletEntries read
      self.akpChildByIndex    = {}
      self.akpChildByScrAddr  = {}
      self.lowestUnusedChild  = 0
      self.nextChildToCalc = 0   #  "P1" ~ plus 1, using top-exclude ranges
      self.akpParentRef    = None
      self.masterEkeyRef   = None



   #############################################################################
   def setChildPoolSize(self, newSize):
      self.childPoolSize = newSize



   #############################################################################
   def numKeysNeededToFillPool(self):
      # This is used to help us fill they keypool for a given node.  It respects
      # the childPoolSize member var, but never exceeds the maxChildren member
      if self.nextChildToCalc >= self.maxChildren:
         return 0
      else:
         currPoolSz = self.nextChildToCalc - self.lowestUnusedChild 
         if currPoolSz >= self.childPoolSize:
            return 0
         else:
            topChild = min(self.nextChildToCalc + self.childPoolSize, 
                                                            self.maxChildren)
            return topChild - self.nextChildToCalc



   #############################################################################
   def getNextChildToCalcIndex(self):
      topbit = HARDBIT if self.HARDCHILD else 0
      return self.nextChildToCalc | topbit


   #############################################################################
   def fillKeyPoolRecurse(self):
      if self.TREELEAF:
         return

      keysToGen = self.numKeysNeededToFillPool()
      for i in range(keysToGen):
         newAkp = self.spawnChild(self.getNextChildToCalcIndex())
         self.addChildRef(newAkp)  # this increments nextChildToCalc

      # Now recurse to each child
      for scrAddr,childAKP in self.akpChildByScrAddr.iteritems():
         childAKP.fillKeyPoolRecurse()

         
         
   #############################################################################
   def getChildByIndex(self, index, spawnIfNeeded=False, fsync=True):
      # Only gets precomputed children
      ch = self.akpChildByIndex.get(index)
      if ch is None:
         if spawnIfNeeded:
            ch = self.spawnChild(index, privSpawnReqd=False, fsync=fsync)
         else:
            raise ChildDeriveError('Child index=%s not found in %s' % \
                                    (ChildIndexToStr(index), self.getName()))

      return ch

   #############################################################################
   def getChildByScrAddr(self, scrAddr):
      # Only gets precomputed children
      ch = self.akpChildByScrAddr.get(scrAddr)
      if ch is None:
         raise ChildDeriveError('Child "%s" not found in %s' % \
                                      (binary_to_hex(scrAddr), self.getName()))
      return ch


   #############################################################################
   def getChildSpawnClass(self, index):
      # This method is used not only to get the child AKP class,
      # but to define limits on which children indices are acceptable
      raise NotImplementedError('"%s" needs to implement getChildSpawnClass()' % \
                                                                 self.getName())


   #############################################################################
   def spawnChild(self, childIndex):
      raise NotImplementedError('"%s" needs to implement spawnChild()' % \
                                                                 self.getName())

   #############################################################################
   def addChildRef(self, childAKP):
      if childAKP.childIndex is None:
         raise ValueError('Child AKP has no childIndex')
         
      self.akpChildByIndex[childAKP.childIndex] = childAKP
      self.akpChildByScrAddr[childAKP.getScrAddr()] = childAKP
      childAKP.akpParentRef  = self
      childAKP.akpParScrAddr = self.getScrAddr()

      childP1 = childAKP.childIndex + 1
      self.nextChildToCalc = max(self.nextChildToCalc, childP1)
      if childAKP.isUsed:
         self.lowestUnusedChild = max(self.lowestUnusedChild, childP1)


   #############################################################################
   def getName(self):
      return self.__class__.__name__


   #############################################################################
   def getScript(self, forceRecompute=False):
      if self.rawScript is None:
         self.recomputeScript()
      return self.rawScript

   #############################################################################
   def getScrAddr(self, forceRecompute=False):
      if self.scrAddrStr is None or forceRecompute:
         self.recomputeScrAddr()
      return self.scrAddrStr

   #############################################################################
   def getUniqueIDBin(self, forceRecompute=False):
      if self.uniqueIDBin is None or forceRecompute:
         self.recomputeUniqueIDBin()
      return self.uniqueIDBin

   #############################################################################
   def getUniqueIDB58(self, forceRecompute=False):
      if self.uniqueIDB58 is None or forceRecompute:
         self.recomputeUniqueIDB58()
      return self.uniqueIDB58

   #############################################################################
   def recomputeScript(self):
      raise NotImplementedError('"%s" needs to implement recomputeScript()' % \
                                                                 self.getName())
   def recomputeScrAddr(self):
      self.recomputeScript()
      self.scrAddrStr = script_to_scrAddr(self.rawScript)

   def recomputeUniqueIDBin(self):
      raise NotImplementedError('"%s" needs to implement recomputeUniqueIDBin()' % \
                                                                 self.getName())
   def recomputeUniqueIDB58(self):
      self.recomputeUniqueIDBin()
      if self.uniqueIDBin is None:
         self.uniqueIDB58 = None
      else:
         self.uniqueIDB58 = binary_to_base58(self.uniqueIDBin)

   #############################################################################
   def getEntryID(self):
      return self.getScrAddr()

   #############################################################################
   def copyFromAKP(self, other):
      """
      Note:  This copies just the base class AKP members.  It doesn't copy
             any members that are in the derived class, though the child class
             will be the same class as self 
      """

      self.isWatchOnly     = other.isWatchOnly

      self.privCryptInfo   = other.privCryptInfo.copy()
      self.sbdPrivKeyData  = other.sbdPrivKeyData.copy()
      self.sbdPublicKey33  = other.sbdPublicKey33.copy()
      self.sbdChaincode    = other.sbdChaincode.copy()
      self.useCompressPub  = other.useCompressPub
      self.isUsed          = other.isUsed
      self.keyBornTime     = other.keyBornTime
      self.keyBornBlock    = other.keyBornBlock
      self.privKeyNextUnlock = other.privKeyNextUnlock

      self.akpParScrAddr   = other.akpParScrAddr
      self.childIndex      = other.childIndex

      self.akpChildByIndex   = other.akpChildByIndex.copy()
      self.akpChildByScrAddr = other.akpChildByScrAddr.copy()
      self.lowestUnusedChild = other.lowestUnusedChild
      self.nextChildToCalc  = other.nextChildToCalc
      self.akpParentRef    = other.akpParentRef
      self.masterEkeyRef   = other.masterEkeyRef

      self.scrAddrStr      = other.scrAddrStr
      self.rawScript       = other.rawScript

      self.wltFileRef       = other.wltFileRef


   #############################################################################
   @EkeyMustBeUnlocked
   def resolveNextUnlockFlag(self, fsync=True):
      if not self.privKeyNextUnlock:
         return

      if self.akpParentRef is None:
         raise KeyDataError('No parent defined from which to derive this key')

      if self.childIndex is None:
         raise KeyDataError('No derivation path defined to derive this key')

      # Originally used an elegant recursive call here, but was worried 
      # about that corner case with Armory 1.35 wallets where someone has 
      # 100k addrs and will hit the recursion limit... 

      # Instead we convert the recursion to a loop of AKP references back to 
      # the first AKP whose parent.privKeyNextUnlock==False
      akpStack = [self]
      while akpStack[-1].akpParentRef.privKeyNextUnlock:
         akpStack.append(akpStack[-1].akpParentRef)
      
      # Now walk backwards, deriving every child from its parent
      self.masterEkeyRef.markKeyInUse()
      try:
         for akp in akpStack[::-1]:
            # This is technically still recursive, but we've guaranteed it will
            # only recurse one level on each call, since parent.privKeyNextUnlock
            # is false.  fsync is always False in the recursive call, applied 
            # later if needed
            newAkp = akp.akpParentRef.spawnChild(childID=self.childIndex,
                                                privSpawnReqd=True, 
                                                fsync=False)
            
               
            if akp.sbdPublicKey33.toBinStr() != newAkp.sbdPublicKey33.toBinStr():
               raise KeyDataError('Derived key supposed to match but does not')
         
            akp.sbdPrivKeyData    = newAkp.sbdPrivKeyData.copy()
            akp.privKeyNextUnlock = False
      
            if fsync:
               self.wltFileRef.addFileOperationToQueue('UpdateEntry', self)

      finally:
         self.masterEkeyRef.finishedWithKey()




   #############################################################################
   def initializeAKP(self, isWatchOnly,
                           isRootRoot,
                           privCryptInfo,
                           sbdPrivKeyData,
                           sbdPublicKey33,
                           sbdChaincode,
                           privKeyNextUnlock,
                           akpParScrAddr,
                           childIndex,
                           useCompressPub,
                           isUsed,
                           keyBornTime=UINT64_MAX,
                           keyBornBlock=UINT32_MAX):

      self.__init__()

      if isRootRoot:
         akpParScrAddr = None
         childIndex = None

      # Convert '' to None
      akpParScrAddr = akpParScrAddr if akpParScrAddr else None

      self.isWatchOnly     = isWatchOnly
      self.isRootRoot      = isRootRoot
      self.privCryptInfo   = privCryptInfo
      self.sbdPrivKeyData  = SecureBinaryData(sbdPrivKeyData)
      self.sbdPublicKey33  = SecureBinaryData(sbdPublicKey33)
      self.sbdChaincode    = SecureBinaryData(sbdChaincode)
      self.privKeyNextUnlock = privKeyNextUnlock
      self.akpParScrAddr   = akpParScrAddr
      self.childIndex      = childIndex
      self.useCompressPub  = useCompressPub
      self.isUsed          = isUsed
      self.keyBornTime     = keyBornTime
      self.keyBornBlock    = keyBornBlock

      if self.sbdPublicKey33.getSize() == 65:
         self.sbdPublicKey33 = CryptoECDSA().CompressPoint(newPub)

      if isRootRoot:
         self.akpParScrAddr = None
         self.childIndex    = None
      

      self.recomputeScript()
      self.recomputeScrAddr()
      self.recomputeUniqueIDBin()
      self.recomputeUniqueIDB58()


   
      
   #############################################################################
   def serializeAKP(self):

      pubKey = self.sbdPublicKey33.copy()
      if self.sbdPublicKey33.getSize() == 65:
         pubKey = CryptoECDSA().CompressPoint(self.sbdPublicKey33)

      flags = BitSet(16)
      flags.setBit(0, self.isWatchOnly)
      flags.setBit(1, self.isRootRoot)
      flags.setBit(2, self.useCompressPub)
      flags.setBit(3, self.privKeyNextUnlock)
      flags.setBit(4, self.isUsed)

      
      parScrAddr = self.akpParScrAddr
      childIndex = self.childIndex
      if self.isRootRoot or parScrAddr is None:
         parScrAddr = '' 
         childIndex = 0 

      # We are not committed to fixed-width wallet entries.  Might as well
      # Save space if fields are empty by using VAR_STRs
      bp = BinaryPacker()
      bp.put(UINT32,        getVersionInt(ARMORY_WALLET_VERSION))
      bp.put(BITSET,        flags,                           2)
      bp.put(BINARY_CHUNK,  self.privCryptInfo.serialize(), 32)
      bp.put(VAR_STR,       self.sbdPrivKeyData.toBinStr())
      bp.put(VAR_STR,       pubKey.toBinStr())
      bp.put(VAR_STR,       self.sbdChaincode.toBinStr())
      bp.put(UINT64,        self.keyBornTime)
      bp.put(UINT32,        self.keyBornBlock)
      bp.put(UINT32,        self.lowestUnusedChild)
      bp.put(VAR_STR,       parScrAddr)
      bp.put(UINT32,        childIndex)

      # Add Reed-Solomon error correction 
      akpData = bp.getBinaryString()
      rsecData = WalletEntry.CreateRSECCode(akpData)

      output = BinaryPacker()
      output.put(VAR_STR, akpData)
      output.put(VAR_STR, rsecData)
      return output.getBinaryString()

      
   #############################################################################
   def unserializeAKP(self, toUnpack):
      toUnpack = makeBinaryUnpacker(toUnpack)

      akpData  = toUnpack.get(VAR_STR)
      rsecData = toUnpack.get(VAR_STR)

      akpData,failFlag,modFlag = WalletEntry.CheckRSECCode(akpData, rsecData)

      if failFlag:
         LOGERROR('Unrecoverable error in wallet entry')
         self.isUnrecoverable = True 
         return self
      elif modFlag:
         LOGWARN('Error in wallet file corrected successfully')
         self.needRewrite = True 


      akpUnpack = BinaryUnpacker(akpData)

      version = akpUnpack.get(UINT32) 
      if version != getVersionInt(ARMORY_WALLET_VERSION):
         LOGWARN('AKP version in file: %s,  Armory Wallet version: %s', 
                     getVersionString(readVersionInt(version)), 
                     getVersionString(ARMORY_WALLET_VERSION))
         


      # First pass is pretty much just to get to the RSEC code, second
      # pass is over the RS-corrected data.
      flags             = akpUnpack.get(BITSET,       2)
      privCryptInfoSer  = akpUnpack.get(BINARY_CHUNK, 32)
      privk             = akpUnpack.get(VAR_STR)
      pubk              = akpUnpack.get(VAR_STR)
      chain             = akpUnpack.get(VAR_STR)
      bornTime          = akpUnpack.get(UINT64)
      bornBlk           = akpUnpack.get(UINT32)
      lowestUnused      = akpUnpack.get(UINT32)
      parScrAddr        = akpUnpack.get(VAR_STR)
      childIndex        = akpUnpack.get(UINT32)

      pcryptInfo = ArmoryCryptInfo().unserialize(privCryptInfoSer)

      #if not extKeyType==self.EXTKEYTYPE:
         #LOGERROR('Wrong EXTKEYTYPE for type being unserialized')
         #LOGERROR('Self=%s, unserialized=%s' % (self.EXTKEYTYPE, extKeyType))
         #we.isUnrecoverable = True 
         #return we
      
      isWatchOnly       = flags.getBit(0)
      isRootRoot        = flags.getBit(1)
      useCompressPub    = flags.getBit(2)
      privKeyNextUnlock = flags.getBit(3)
      isUsed            = flags.getBit(4)


      if isRootRoot:
         akpParScrAddr = None
         childIndex = None

      self.initializeAKP( isWatchOnly,
                          isRootRoot,
                          pcryptInfo, 
                          SecureBinaryData(privk),
                          SecureBinaryData(pubk),
                          SecureBinaryData(chain),
                          privKeyNextUnlock,
                          parScrAddr,
                          childIndex,
                          useCompressPub,
                          isUsed,
                          bornTime,
                          bornBlk)
                          
      return self
      

   #############################################################################
   # I originally planned to have these two methods excluded since this is an
   # abstract base class and each subclass should implement this with a direct
   # call to AKP.serializeAKP/unserializeAKP.  But it turns out that many base
   # classes don't actually require any more than ser/unserAKP combined with 
   # their unique FILECODE.  This is here so the classes can inherit it.
   def serialize(self):
      if self.sbdPublicKey33.getSize()==0:
         raise UninitializedError('Will not serialize uninitialized AKP')
      return self.serializeAKP()

   def unserialize(self, toUnpack):
      return self.unserializeAKP(toUnpack)

   #############################################################################
   def getPrivKeyAvailability(self):
      if self.isWatchOnly:
         return PRIV_KEY_AVAIL.WatchOnly
      elif self.privKeyNextUnlock:
         return PRIV_KEY_AVAIL.NextUnlock
      elif self.sbdPrivKeyData.getSize() > 0:
         if self.privCryptInfo.noEncryption():
            return PRIV_KEY_AVAIL.Available
         elif self.masterEkeyRef and not self.masterEkeyRef.isLocked():
            return PRIV_KEY_AVAIL.Available
         else:
            return PRIV_KEY_AVAIL.NeedDecrypt
      else:
         return PRIV_KEY_AVAIL.Uninit


   #############################################################################
   def useEncryption(self):
      return self.privCryptInfo.useEncryption()



   #############################################################################
   def getSerializedPubKey(self, serType='bin'):
      """
      The various public key serializations:  "bin", "hex", "xpub"
      """
      if not self.useCompressPub:
         pub = CryptoECDSA().UncompressPoint(self.sbdPublicKey33).copy()
      else:
         pub = self.sbdPublicKey33.copy()
         
      if serType.lower()=='bin':
         return pub.toBinStr()
      elif serType.lower()=='hex':
         return pub.toHexStr()
      elif serType.lower()=='xpub':
         raise NotImplementedError('Encoding not implemented yet')


   #############################################################################
   def serializeWatchOnlyData(self):
      raise NotImplementedError('Encoding not implemented yet')
      
   #############################################################################
   def unserializeWatchOnlyData(self):
      raise NotImplementedError('Encoding not implemented yet')
         
   #############################################################################
   @EkeyMustBeUnlocked
   def getSerializedPrivKey(self, serType='hex'):
      """
      The various private key serializations: "bin", hex", "sipa", "xprv", "bip38"
      """

      if self.useEncryption() and self.isLocked():
         raise WalletLockError('Cannot serialize locked priv key')

      lastByte = '\x01' if self.useCompressPub else ''
      binPriv = self.getPlainPrivKeyCopy().toBinStr() + lastByte
         
      if serType.lower()=='bin':
         return binPriv 
      if serType.lower()=='hex':
         return binary_to_hex(binPriv)
      elif serType.lower()=='sipa':
         binSipa = PRIVKEYBYTE + binPriv + computeChecksum(PRIVKEYBYTE+binPriv)
         return binary_to_hex(binSipa)
      elif serType.lower()=='xprv':
         raise NotImplementedError('xprv encoding not yet implemented')


   #############################################################################
   def getPrivCryptArgs(self, cryptInfoObj=None):
      """
      Examines self.privCryptInfo and produces as many arguments as it can
      that are needed to call self.privCryptInfo.encrypt/decrypt.   Note
      that this does not unlock the master key, or even check if it's locked.
      It simply returns a map of args that can be passed using **output to
      the cryptInfo.encrypt or decrypt functions.
      """
      if cryptInfoObj is None:
         cryptInfoObj = self.privCryptInfo

      mapOut = {}
      if cryptInfoObj.noEncryption():
         return mapOut

      if cryptInfoObj.getEncryptIVSrc()[0] == CRYPT_IV_SRC.PUBKEY20:
         mapOut['ivData'] = hash256(self.sbdPublicKey33.toBinStr())[:16]
         mapOut['ivData'] = SecureBinaryData(mapOut['ivData'])
      else:
         # If the IV is stored we don't need to pass it through, it
         # will grab it from itself in cryptInfoObj.decrypt/encrypt 
         mapOut['ivData']  = None

      mapOut['ekeyObj']  = self.masterEkeyRef
      return mapOut
      


   #############################################################################
   def setNewPlainPrivKey(self, sbdPrivData, cryptInfo, ekeyRef=None):
      """
      ekeyRef should never have to be supplied except in very strange
      enviroments -- self.masterEkeyRef should already be set, unlocked
      and correct for the new private key. 
      """
      if sbdPrivData is None or sbdPrivData.getSize()==0:
         self.sbdPrivKeyData = NULLSBD()
         self.privCryptInfo = cryptInfo.copy()
         return


      if cryptInfo.useEncryption():
         if ekeyRef is None:
            if self.masterEkeyRef is None:
               raise KeyDataError('No ekey data available for encryption')
            ekeyRef = self.masterEkeyRef
         
         if ekeyRef.isLocked():
            raise EncryptionError('Ekey needs to be unlocked to set new priv key')


         if cryptInfo.keySource == ekeyRef.ekeyID:
            # If we had no masterEkey before and it was supplied as an arg, set it
            self.masterEkeyRef = ekeyRef
         else:
            raise EncryptionError('New ACI data does not match avail EKeys')


         if cryptInfo.hasStoredIV():
            # This method copies the ACI exactly, which should (under all
            # forseeable conditions) use "PUBKEY20" as the ivSource.  This 
            # means that the IV to be used to encrypt this key will be 
            # different than other keys (good).  However, if for some reason
            # we have a storedIV, then it will be reused (bad).
            raise EncryptionError('New priv key crypto inheriting non-pubkey IV')


      self.privCryptInfo = cryptInfo.copy()
      cryptArgs = self.getPrivCryptArgs()
      self.sbdPrivKeyData = self.privCryptInfo.encrypt(sbdPrivData, **cryptArgs)



   #############################################################################
   def unlockEkey(self, passphrase, kdfObj=None):
      """
      Ekeys should always already have the kdf set already, but we can
      pass it in if this is a strange environment where it was never set

      Note:  This method works with multi-password EKeys as well.  Just pass 
             in a list of SBD passphrases (with NULLSBD() for the passphrases
             not supplied).  If KDF object refs are not already set in the 
             ekey, pass them in as a list or map as the second arg.
      """
      if self.masterEkeyRef is None:
         raise EncryptionError('No encryption key to unlock!')

      return self.masterEkeyRef.unlock(passphrase, kdfObj)
         

   
   #############################################################################
   def verifyEkeyPassphrase(self, passphrase, kdfObj=None):
      """
      Note:  This method works with multi-password EKeys as well.  Just pass 
             in a list of SBD passphrases (with NULLSBD() for the passphrases
             not supplied).  If KDF object refs are not already set in the 
             ekey, pass them in as a list or map as the second arg.
      """
      if self.masterEkeyRef is None:
         raise EncryptionError('No encryption key to unlock!')

      return self.masterEkeyRef.verifyPassphrase(passphrase, kdfObj)
                                                            

   #############################################################################
   @EkeyMustBeUnlocked
   def getPlainPrivKeyCopy(self, verifyPublic=True):
      """
      This is the only way to get the private key out of an AKP object.
      The plain key is never kept in an AKP object, which is why there's
      no lock() and unlock() methods for AKP.  Instead, we only ever lock
      and unlock the master encryption key, and should be unlocked before
      this method is called.

      NOTE:  This returns an SBD object which needs to be .destroy()ed by
             the caller when it is finished with it.
      """

      if self.isWatchOnly:
         raise KeyDataError('Cannot get priv key from watch-only wallet')

      # I dont' think this is necessary, because if privCryptInfo.noEncryption
      # is true, the decrypt() call will return the input data
      #if self.privCryptInfo.noEncryption():
         #return self.sbdPrivKeyData.copy()

      if self.privKeyNextUnlock:
         self.resolveNextUnlockFlag()

      try:
         privPlain = NULLSBD()
         aciDecryptAgs = self.getPrivCryptArgs(self.privCryptInfo)
         privPlain = self.privCryptInfo.decrypt( \
                           self.sbdPrivKeyData, **aciDecryptAgs)

         if verifyPublic:
            computedPub = CryptoECDSA().ComputePublicKey(privPlain)
            selfPub = CryptoECDSA().UncompressPoint(self.sbdPublicKey33)
            if not computedPub.toBinStr() == selfPub.toBinStr():
               raise KeyDataError('Private key does not match stored pubkey!')

         return privPlain
         
      except:
         LOGEXCEPT('Failed to decrypt private key')
         privPlain.destroy()
         return NULLSBD()

      
   #############################################################################
   @EkeyMustBeUnlocked
   def __signData(self, dataToSign, deterministicSig=False, normSig='Dontcare'):
      """
      This returns the raw data, signed using the CryptoECDSA module.  This 
      should probably not be called directly by a top-level script, but 
      instead the backbone of a bunch of standard methods for signing 
      transactions, messages, perhaps Proof-of-Reserve trees, etc.

      "normSig" is based on a proposal to only allow even s-values, or 
      odd s-values to limit transaction malleability.  We might as well
      put it here, though the default is not to mess with the outpout
      of the SignData call.
      """
      
      try:
         if deterministicSig:
            raise NotImplementedError('Cannot do deterministic signing yet')
            sig = CryptoECDSA().SignData_RFC6979(dataToSign, self.getPlainPrivKeyCopy())
         else:
            sig = CryptoECDSA().SignData(dataToSign, self.getPlainPrivKeyCopy())

         sigstr = sig.toBinStr()
         rBin = sigstr[:32 ]
         sBin = sigstr[ 32:]

         if not normSig=='Dontcare':
            # normSig will either be 'even' or 'odd'.  If the calculated
            # s-value does not match, then use -s mod N which will be correct
            raise NotImplementedError('This code is not yet tested!')
            sInt = binary_to_int(sBin, BIGENDIAN)
            if (normSig=='even' and sInt%2==1) or \
               (normSig=='odd'  and sInt%2==0):
               sInt = (-sInt) % SECP256K1_MOD
               
            sBin = int_to_binary(sInt, widthBytes=32, endOut=BIGENDIAN)

         return (rBin, sBin)

      except:
         LOGEXCEPT('Error generating signature')
      

   #############################################################################
   @EkeyMustBeUnlocked
   def signTransaction(self, serializedTx, deterministicSig=False):
      rBin,sBin = self.__signData(serializedTx, deterministicSig)
      return createSigScriptFromRS(rBin, sBin)

      
   #############################################################################
   @EkeyMustBeUnlocked
   def signMessage(self, msg, deterministicSig=False):
      """
      Returns just raw (r,s) pair instead of a sigscript because this is 
      raw message signing, not transaction signing.  We match Bitcoin-Qt
      behavior which is to prefix the message with "Bitcoin Signed Message:" 
      in order to guarantee that someone cannot be tricked into signing
      a real transaction:  instead of signing the input, MSG, it will only 
      sign hash("Bitcoin Signed Message:\n" + MSG) which cannot be a
      transaction
      """
      msgPrefix = 'Bitcoin Signed Message:\n'
      bp = BinaryPacker()
      bp.put(VAR_INT,  len(msgPrefix))
      bp.put(BINARY_CHUNK, msgPrefix)
      bp.put(VAR_INT,  len(msg))
      bp.put(BINARY_CHUNK, msg)
      msgToSign = hash256(bp.getBinaryString())
      return self.__signData(msgToSign, deterministicSig)


   #############################################################################
   def advanceLowestUnused(self, ct=1):
      topIndex = self.lowestUnusedChild + ct
      topIndex = min(topIndex, self.nextChildToCalc)
      topIndex = max(topIndex, 0)

      self.lowestUnusedChild = topIndex
      self.walletFileSafeUpdate( [[WLT_UPDATE_MODIFY, self.offsetTopUsed, \
                    int_to_binary(self.lowestUnusedChild, widthBytes=8)]])
      self.fillAddressPool()
      
   #############################################################################
   def rewindLowestUnused(self, ct=1):
      self.advanceLowestUnused(-ct)


   #############################################################################
   def peekNextUnusedChild(self):
      if self.lowestUnusedChild >= self.nextChildToCalc:
         childAddr = self.spawnChild(self.lowestUnusedChild, fsync=False)
      else:
         if not self.lowestUnusedChild in self.akpChildByIndex:
            raise ChildDeriveError('Somehow child is missing from map')
         childAddr = self.akpChildByIndex[self.lowestUnusedChild]

      return childAddr

   #############################################################################
   def getNextUnusedChild(self, currBlk=0):
      """
      Use the "currBlk" arg to set the born date for the child, since this func
      is agnostic and doesn't talk to the BDM.
      """
      if self.lowestUnusedChild >= self.nextChildToCalc:
         childAddr = self.spawnChild(self.lowestUnusedChild, fsync=True)
      else:
         childAddr = self.akpChildByIndex[self.lowestUnusedChild]

      childAddr.keyBornTime = long(RightNow())
      childAddr.keyBornBlock = currBlk
      childAddr.isUsed = True

      # This is mostly redundant, but makes sure that lowestUnused and nextCalc
      # are updated properly
      self.addChildRef(childAddr)

      self.wltFileRef.addFileOperationToQueue('UpdateEntry', self)
      self.wltFileRef.addFileOperationToQueue('UpdateEntry', childAddr)
      self.wltFileRef.fsyncUpdates()
      self.fillKeyPoolRecurse()
      
      return childAddr


   #############################################################################
   def wipePrivateData(self, fsync=False):
      self.sbdPrivKeyData.destroy() 
      self.privCryptInfo = NULLCRYPTINFO()
      self.masterEkeyRef = None
      self.isWatchOnly = True

      if fsync:
         self.fsyncUpdates()
       
      

   #############################################################################
   def getParentList(self, fromBaseScrAddr=None):
      """
      If the BIP32 tree looks like:  
         SeedRoot --> Wallet --> Chain --> Address(this)
      Then this will return:
         [[SeedRootRef, a], [WalletRef, b], [ChainRef, c]]
      Where a,b,c are the child indices
      """
      currIndex = self.childIndex
      parentAKP = self.akpParentRef
      if parentAKP is None:
         return []
         
      foundBase = False
      revParentList = []
      while parentAKP is not None:
         revParentList.append([parentAKP, currIndex])
         if parentAKP.getScrAddr() == fromBaseScrAddr:
            foundBase = True
            break
         currIndex = parentAKP.childIndex
         parentAKP = parentAKP.akpParentRef

      if fromBaseScrAddr and not foundBase:
         raise ChildDeriveError('Requested up to base par, but not found!')

      return revParentList[::-1]


   #############################################################################
   def pprintVerbose(self, indent=''):
      def returnScrAddr(obj):
         try:
            return binary_to_hex(obj.getScrAddr())
         except:
            ''
      try:
         print indent + '   RootSA  :  ', returnScrAddr(self.root135Ref)
         print indent + '   ParentSA:  ', returnScrAddr(self.akpParentRef)
         print indent + '   SelfSA:    ', returnScrAddr(self)
         print indent + '   ChildIndex:', self.childIndex
         print indent + '   ChainIdx:  ', self.chainIndex
      except:
         print indent + '   ParentSA:  ', returnScrAddr(self.akpParentRef)
         print indent + '   SelfSA:    ', returnScrAddr(self)
         print indent + '   ChildIndex:', self.childIndex

      print indent + '   MarkedUsed:', '+++' if self.isUsed else '   '
      print indent + '   LwestUnuse:', self.lowestUnusedChild
      print indent + '   NxtToCalc: ', self.nextChildToCalc
      print indent + '   AKP Children:  Num=', len(self.akpChildByIndex)
      for idx,ch in self.akpChildByIndex.iteritems():
         print indent + '      %04d    :'%idx, returnScrAddr(ch)

      print '\n'






#############################################################################
class ArmorySeededKeyPair(ArmoryKeyPair):
   """
   This is an isolated class which carries a little bit of extra metadata 
   needed turn AKP objects into ABEK_Root objects.  Any ABEK_Root class should
   be a derived class of this instead AKP
   """
      
   #############################################################################
   def __init__(self):
      # Extra data that needs to be encrypted
      super(ArmorySeededKeyPair, self).__init__()
      self.seedCryptInfo  = NULLCRYPTINFO()
      self.seedNumBytes   = 0
      self.sbdSeedData    = SecureBinaryData(0)
      self.isRootRoot     = True

      # This root has no key data.  Mainly for JBOK
      self.isFakeRoot    = False  
      self.wltLvlParent  = self


   #############################################################################
   def initializeFromSeed(self, sbdPlainSeed, fsync=True):
      raise NotImplementedError('"%s" needs to implement initializeFromSeed()' % \
                                                             self.getName())



   #############################################################################
   @EkeyMustBeUnlocked
   def getPlainSeedCopy(self):
      """
      NOTE:  This returns an SBD object which needs to be .destroy()ed by
             the caller when it is finished with it.
      """
      if self.seedNumBytes==0:
         raise KeyDataError('No seed defined for this root!')

      # I dont' think this is necessary, because if privCryptInfo.noEncryption
      # is true, the decrypt() call will return the input data
      #if self.seedCryptInfo.noEncryption():
         #return self.sbdSeedData.copy()

      try:
         aciDecryptAgs = self.getPrivCryptArgs(self.seedCryptInfo)
         paddedSeed = self.seedCryptInfo.decrypt(self.sbdSeedData, 
                                                         **aciDecryptAgs)
         return SecureBinaryData(paddedSeed.toBinStr()[:self.seedNumBytes])
      except:
         LOGEXCEPT('Failed to decrypt master seed')
         return NULLSBD()


   #############################################################################
   def wipePrivateData(self, fsync=False):
      self.sbdSeedData.destroy() 
      self.seedCryptInfo = NULLCRYPTINFO()
      super(ArmorySeededKeyPair, self).wipePrivateData(fsync)

      


   #############################################################################
   def createNewSeed(self, seedSize, extraEntropy):
      raise NotImplementedError('"%s" needs to implement createNewSeed()' % \
                                                                 self.getName())


   #############################################################################
   def serializeAKP(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, super(ArmorySeededKeyPair, self).serializeAKP())
      bp.put(UINT16,       self.seedNumBytes)
      bp.put(BINARY_CHUNK, self.seedCryptInfo.serialize(), 32)
      bp.put(VAR_STR,      self.sbdSeedData.toBinStr())
      return bp.getBinaryString()

      

   #############################################################################
   def unserializeAKP(self, toUnpack):
      bu = makeBinaryUnpacker(toUnpack)
      super(ArmorySeededKeyPair, self).unserializeAKP(bu)
      seedBytes = bu.get(UINT16)
      cryptInfo = bu.get(BINARY_CHUNK, 32)
      binSeed   = bu.get(VAR_STR)

      self.seedNumBytes  = seedBytes
      self.seedCryptInfo = ArmoryCryptInfo().unserialize(cryptInfo)
      self.sbdSeedData   = SecureBinaryData(binSeed)

      binSeed = None
      return self



################################################################################
################################################################################
#
# Classes for migrating old Armory 1.35 wallets to the wallet2.0 format
#
################################################################################
################################################################################

################################################################################
class Armory135KeyPair(ArmoryKeyPair):

   FILECODE = 'ARMRY135'

   #############################################################################
   def __init__(self, *args, **kwargs):
      """
      We treat Armory 1.35 keys like a strange BIP32 tree.  If the root is "m"
      and this key's chainIndex is 8, we treat it like:
         
         m/0/0/0/0/0/0/0/0        (8 zeros, each non-hardened derivation)

      By updating the spawnChild method in this class, all the other code that
      is otherwise written for BIP32 works as expected for Armory 1.35 AKPs
      (with a few tweaks, such as not holding the entire derive path)

      CHILD_Index is what is used by Bip32 keys, but always 0 here (as above)
      CHAIN_Index is the old Armory wlt concept, and only tracked by the root

      For Armory135KeyPair objects, we let the base class still manage the 
      children and parent references (though there will only ever be one
      child, and it has childIndex=0), and we add logic to have the root track
      all children, recursively (in the root135ChainMap & root135ScrAddrMap)

      """
      super(Armory135KeyPair, self).__init__(*args, **kwargs)

      self.useCompressPub = False
      self.chainIndex = None
      self.childIndex = 0  # always 0 for Armory 135 keys
      self.root135Ref = None
      self.root135ScrAddr = None
      self.maxChildren = 1
      self.isRootRoot  = False


   

   #############################################################################
   def getChildClass(self):
      return Armory135KeyPair
      

   #############################################################################
   def getAddrObjByPath(self, pathList, privSpawnReqd=False):
      raise NotImplementedError('This method not avail for A135 wallet chains')


   #############################################################################
   def addChildRef(self, childAKP):
      super(Armory135KeyPair, self).addChildRef(childAKP)

      # For Armory135 addrs, we also store the child in root135Ref
      rt = self.root135Ref
      rt.root135ChainMap[childAKP.chainIndex] = childAKP
      rt.root135ScrAddrMap[childAKP.getScrAddr()] = childAKP
      rt.rootNextToCalc = max(childAKP.chainIndex+1, rt.rootNextToCalc)
      if childAKP.isUsed:
         rt.rootLowestUnused = max(rt.rootLowestUnused, childAKP.chainIndex+1)

                              

   #############################################################################
   def spawnChild(self, childID=0, privSpawnReqd=False, fsync=True, forIDCompute=False):
      """
      Spawn an Armory135KeyPair from another one.
      """

      if not childID == 0:
         raise KeyDataError('Can only derive child ID=0 for 1.35 AKPs')

      if fsync and self.wltFileRef is None:
         raise IOError('Cannot fsync wallet entry without a valid file ref')

      # If the child key corresponds to a "hardened" derivation, we require
      # the priv keys to be available, or sometimes we explicitly request it
      pavail = self.getPrivKeyAvailability()
      if privSpawnReqd:
         if pavail==PRIV_KEY_AVAIL.WatchOnly:
            raise KeyDataError('Requires priv key, but this is a WO ext key')
         elif pavail==PRIV_KEY_AVAIL.NeedDecrypt:
            raise WalletLockError('Requires priv key, no way to decrypt it')
         elif pavail==PRIV_KEY_AVAIL.NextUnlock:
            self.resolveNextUnlockFlag(fsync)
         

      # If we are not watch-only but only deriving a pub key, need to set flag
      nextUnlockFlag = False
      if pavail in [PRIV_KEY_AVAIL.NeedDecrypt, PRIV_KEY_AVAIL.NextUnlock]:
         nextUnlockFlag = True


      privPlain = NULLSBD()
      pubKey65 = CryptoECDSA().UncompressPoint(self.sbdPublicKey33)
      logMult1 = NULLSBD()
      logMult2 = NULLSBD()
      sbdNewKey1 = NULLSBD()
      sbdNewKey2 = NULLSBD()
      sbdNewKey3 = NULLSBD()

      

      try:
         ecdsaObj = CryptoECDSA()
         if pavail==PRIV_KEY_AVAIL.Available:
            privPlain = self.getPlainPrivKeyCopy()
            if privPlain.getSize()==0:
               raise KeyDataError('Private key retrieval failed')
            extendFunc = ecdsaObj.ComputeChainedPrivateKey
            extendArgs = [privPlain, self.sbdChaincode, pubKey65, logMult1]
            extendType = 'Private'
         else:
            extendFunc = ecdsaObj.ComputeChainedPublicKey
            extendArgs = [pubKey65, self.sbdChaincode, logMult1]
            extendType = 'Public'
         
   
         # Do key extension twice
         sbdNewKey1 = extendFunc(*extendArgs)
         sbdNewKey2 = extendFunc(*extendArgs)

         if sbdNewKey1.toBinStr() == sbdNewKey2.toBinStr():
            sbdNewKey2.destroy()
            with open(MULT_LOG_FILE,'a') as f:
               f.write('%s chain (pkh, mult): %s,%s\n' % (extendType, 
                  pubKey65.getHash160().toHexStr(), logMult1.toHexStr()))
         else:
            LOGCRIT('Chaining failed!  Computed keys are different!')
            LOGCRIT('Recomputing chained key 3 times; bail if they do not match')
            sbdNewKey1.destroy()
            sbdNewKey2.destroy()
            logMult3 = SecureBinaryData()

            sbdNewKey1 = extendFunc(*extendArgs)
            sbdNewKey2 = extendFunc(*extendArgs)
            sbdNewKey3 = extendFunc(*extendArgs)
            LOGCRIT('   Multiplier1: ' + logMult1.toHexStr())
            LOGCRIT('   Multiplier2: ' + logMult2.toHexStr())
            LOGCRIT('   Multiplier3: ' + logMult3.toHexStr())

            if sbdNewKey1==sbdNewKey2 and sbdNewKey1==sbdNewKey3:
               with open(MULT_LOG_FILE,'a') as f:
                  f.write('Computed (pkh, mult): %s,%s\n' % (a160hex,logMult1.toHexStr()))
            else:
               raise KeyDataError('Chaining %s Key Failed!' % extendType)

         # Create a new object of the same class as this one, then copy 
         # all members and change a few
         childAddr = self.getChildClass()()
         childAddr.copyFromAKP(self)
         childAddr.isUsed = False
   
         # Assign the above calcs based on the type of calculation
         if extendType=='Private':
            privPlain = sbdNewKey1.copy()
            pubKey65  = CryptoECDSA().ComputePublicKey(privPlain)
         else:
            privPlain = NULLSBD()
            pubKey65  = sbdNewKey1.copy()


         # This sets the priv key (if non-empty)
         childAddr.sbdPublicKey33 = CryptoECDSA().CompressPoint(pubKey65)
         childAddr.sbdChaincode   = self.sbdChaincode.copy()
         # See ABEK spawnChild for comment about key setting order
         childAddr.setNewPlainPrivKey(privPlain, self.privCryptInfo)
         childAddr.masterEkeyRef = self.masterEkeyRef
         childAddr.privKeyNextUnlock = nextUnlockFlag


         if forIDCompute:
            return childAddr


         childAddr.chainIndex = self.chainIndex + 1
         childAddr.childIndex = 0
         childAddr.akpChildByIndex   = {}
         childAddr.akpChildByScrAddr = {}
         childAddr.root135Ref = self.root135Ref
         childAddr.root135ScrAddr = self.root135ScrAddr
         childAddr.wltLvlParent = self.wltLvlParent

         # These recompute calls also call recomputeScript and recomputeUniqueIDBIN
         childAddr.recomputeScrAddr()
         childAddr.recomputeUniqueIDB58()

         if fsync:
            self.addChildRef(childAddr)
            self.fsync()
            childAddr.fsync()

         return childAddr

      finally:
         privPlain.destroy()
         sbdNewKey1.destroy()
         sbdNewKey2.destroy()
         sbdNewKey3.destroy()


   #############################################################################
   def recomputeScript(self):
      pkHash160 = hash160(self.getSerializedPubKey())
      self.rawScript = hash160_to_p2pkhash_script(pkHash160)

   #############################################################################
   def recomputeUniqueIDBin(self):
      if self.sbdPublicKey33.getSize() == 0:
         self.uniqueIDBin = None
      else:
         childAKP = self.spawnChild(0, privSpawnReqd=False, fsync=False, forIDCompute=True)
         child160 = hash160(childAKP.getSerializedPubKey())
         self.uniqueIDBin = (ADDRBYTE + child160[:5])[::-1]


   #############################################################################
   def fillKeyPoolRecurse(self):
      raise KeyDataError('Cannot fill keypool from A135 key pairs')
      
   #############################################################################
   def getAddrLocatorString(self, locatorType='Plain'):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, 'A135', 4)
      bp.put(VAR_STR,      locatorType)
      bp.put(VAR_STR,      self.root135ScrAddr)
      bp.put(UINT32,       self.chainIndex)
      return bp.getBinaryString()

   #############################################################################
   def peekNextUnusedChild(self):
      raise NotImplementedError('Method not appropriate on A135 keypair objs')
   def getNextUnusedChild(self, currBlk=0):
      raise NotImplementedError('Method not appropriate on A135 keypair objs')
   def getNextChangeAddress(self, *args, **kwargs):
      raise NotImplementedError('Method not appropriate on A135 keypair objs')
   def getNextReceivingAddress(self, *args, **kwargs):
      raise NotImplementedError('Method not appropriate on A135 keypair objs')

   #############################################################################
   def serialize(self):
      if self.sbdPublicKey33.getSize()==0:
         raise UninitializedError('Will not serialize uninitialized AKP')

      rootsa = '' if self.root135ScrAddr is None else self.root135ScrAddr
      chain  = INT32_MAX if self.chainIndex is None else self.chainIndex

      bp = BinaryPacker()
      bp.put(BINARY_CHUNK,  self.serializeAKP())  # All ArmoryKeyPair stuff
      bp.put(VAR_STR,       rootsa)
      bp.put(INT32,         chain)
      return bp.getBinaryString()
      

   #############################################################################
   def unserialize(self, toUnpack):
      bu = makeBinaryUnpacker(toUnpack)
      self.unserializeAKP(bu)
      self.root135ScrAddr = bu.get(VAR_STR)
      self.chainIndex     = bu.get(INT32)

      if len(self.root135ScrAddr)==0:
         self.root135ScrAddr = None

      if self.chainIndex == INT32_MAX:
         self.chainIndex = None
      
      return self


################################################################################
class Armory135Root(Armory135KeyPair, ArmorySeededKeyPair):
   #############################################################################
   def __init__(self):
      """
      We treat Armory 1.35 keys like a strange BIP32 tree.  If the root is "m"
      and this key's chainIndex is 8, we treat it like:
         
         m/0/0/0/0/0/0/0/0        (8 zeros, each non-hardened derivation)

      By updating the spawnChild method in this class, all the other code that
      is otherwise written for BIP32 works as expected for Armory 1.35 AKPs
      (with a few tweaks, such as not holding the entire derive path)
      """
      Armory135KeyPair.__init__(self)
      ArmorySeededKeyPair.__init__(self)

      # In Armory135 wallets, we have a parallel set of maps/vars to track
      # everything at the root.  akpChildBy*, lowestUnused, nextChildToCalc
      # will all still be tracked by the root and each child, but it will
      # be pretty boring.
      self.chainIndex        = -1
      self.root135ChainMap   = {}
      self.root135ScrAddrMap = {}
      self.rootLowestUnused  = 0
      self.rootNextToCalc    = 0
      self.root135Ref        = self
      self.root135ScrAddr    = self.getScrAddr()
      self.isRootRoot        = False


   #############################################################################
   def getChildClass(self):
      return Armory135KeyPair

   #############################################################################
   def fillKeyPoolRecurse(self):
      # For 135 wallets, not actually recursive
      currPool = self.rootNextToCalc - self.rootLowestUnused
      toGen = max(0, self.childPoolSize - currPool)
      LOGINFO('Filling keypool:  topCalc=%d, lowUnuse=%d, pool=%s, toGen=%s' % \
         (self.rootNextToCalc, self.rootLowestUnused, self.childPoolSize, toGen))

      ch = self.getChildByIndex(self.rootNextToCalc-1)
      for i in range(toGen):
         ch = ch.spawnChild(0, privSpawnReqd=False, fsync=True)
       

   #############################################################################
   def getChildByIndex(self, index, spawnIfNeeded=False, fsync=True):
      if index==-1:
         return self

      ch = self.root135ChainMap.get(index)
      if ch is None:
         raise ChildDeriveError('Cannot get chain index not yet spawned')
      return ch


   #############################################################################
   def getChildByScrAddr(self, scrAddr):
      ch = self.root135ScrAddrMap.get(scrAddr)
      if ch is None:
         raise ChildDeriveError('Cannot find scrAddr in Armory135 root')
      return ch

   #############################################################################
   @EkeyMustBeUnlocked
   def getPlainSeedCopy(self):
      """
      NOTE:  This returns an SBD object which needs to be .destroy()ed by
             the caller when it is finished with it.
   
      There's no real seeds for 135 wallets, there's just a chainIndex=-1
      """
      sbdPriv = self.getPlainPrivKeyCopy()
      testChain = DeriveChaincodeFromRootKey_135(sbdPriv)
      if testChain.toBinStr() == self.sbdChaincode.toBinStr():
         return sbdPriv
      else:
         return SecureBinaryData(sbdPriv.toBinStr() + testChain.toBinStr())


   #############################################################################
   @EkeyMustBeUnlocked
   @VerifyArgTypes(sbdPlainSeed=SecureBinaryData)
   def initializeFromSeed(self, sbdPlainSeed, verifyPub=None, fillPool=True):
      """
      We must already have a master encryption key created, and a reference to
      it set in this object (so that the EkeyMustBeUnlocked decorator passes)

      For 135 "seeds", these aren't really seeds.  They are just the root 
      private/public keypair.  But we treat them as a seeds for the purposes
      of making a generic wallet interface that can produce seeds and restore
      wallets from them. 
      """
      if sbdPlainSeed.getSize() == 64:
         sbdPriv           = SecureBinaryData(sbdPlainSeed.toBinStr()[:32 ])
         self.sbdChaincode = SecureBinaryData(sbdPlainSeed.toBinStr()[ 32:])
      elif sbdPlainSeed.getSize() == 32:
         sbdPriv           = sbdPlainSeed.copy()
         self.sbdChaincode = DeriveChaincodeFromRootKey_135(sbdPriv)

      # Make sure the public key is properly set
      self.sbdPublicKey33  = CryptoECDSA().ComputePublicKey(sbdPriv)
      if self.sbdPublicKey33.getSize()==65:
         self.sbdPublicKey33 = CryptoECDSA().CompressPoint(self.sbdPublicKey33)

      # Set new priv key with encryption (must be set after pub key)
      self.setNewPlainPrivKey(sbdPriv, self.privCryptInfo)

      # Do verification of pubkey, if requested
      if verifyPub:
         if not self.sbdPublicKey33 == CryptoECDSA().CompressPoint(verifyPub):
            raise KeyDataError('Public key from seed does not match expected')

      # EDIT:  Since this is recoverable from the priv&chain fields, don't save
      """
      # Now store the seed data along with the everything else
      self.seedNumBytes = sbdPlainSeed.getSize()
      self.seedCryptInfo = self.privCryptInfo.copy()
      self.seedCryptInfo.ivSource = SecureBinaryData().GenerateRandom(8)
      self.sbdSeedData = self.seedCryptInfo.encrypt(sbdPlainSeed, 
                                                     ekeyObj=self.masterEkeyRef)
      """

      self.isWatchOnly     = False
      self.useCompressPub  = False
      self.aekParScrAddr   = None
      self.aekRootScrAddr  = None
      self.akpParentRef    = None
      self.childIndex      = None

      self.recomputeUniqueIDBin()
      self.recomputeUniqueIDB58()
      self.recomputeScript()
      self.recomputeScrAddr()

      if fillPool:
         self.fillKeyPoolRecurse()
         


   #############################################################################
   def peekNextUnusedChild(self):
      if self.rootLowestUnused == 0:
         return self.spawnChild(fsync=False)
      elif self.rootLowestUnused >= self.rootNextToCalc:
         return self.root135ChainMap[self.rootLowestUnused-1].spawnChild(fsync=False)
      else:
         return self.root135ChainMap[self.rootLowestUnused]


   #############################################################################
   def getNextUnusedChild(self, currBlk=0):

      if self.rootLowestUnused == 0:
         childAddr = self.spawnChild(fsync=True)
      elif self.rootLowestUnused >= self.rootNextToCalc:
         childAddr = self.root135ChainMap[self.rootLowestUnused-1].spawnChild(fsync=True)
      else:
         childAddr = self.root135ChainMap[self.rootLowestUnused]

      childAddr.keyBornTime = long(RightNow())
      childAddr.keyBornBlock = currBlk
      childAddr.isUsed = True
      childAddr.akpParentRef.addChildRef(childAddr)
      #self.rootLowestUnused += 1


      self.wltFileRef.addFileOperationToQueue('UpdateEntry', self)
      self.wltFileRef.addFileOperationToQueue('UpdateEntry', childAddr)
      self.wltFileRef.fsyncUpdates()
      self.fillKeyPoolRecurse()
      
      return childAddr


   #############################################################################
   # In 135 wallets, there is no difference between change and receiving.
   def getNextChangeAddress(self, *args, **kwargs):
      return getNextUnusedChild(*args, **kwargs)
   def getNextReceivingAddress(self, *args, **kwargs):
      return getNextUnusedChild(*args, **kwargs)
   
   #############################################################################
   def createNewSeed(self, seedSize, extraEntropy):
      raise NotImplementedError('Creating Armory 1.35 wallets is no more!')

      
   #############################################################################
   def serializeWatchOnlyData(self):
      raise NotImplementedError('Encoding not implemented yet')
      
   #############################################################################
   def unserializeWatchOnlyData(self):
      raise NotImplementedError('Encoding not implemented yet')
      
          
   #############################################################################
   def pprintVerbose(self, indent=''):
      def returnScrAddr(obj):
         try:
            return binary_to_hex(obj.getScrAddr())
         except:
            ''

      print indent + 'Showing info for:', returnScrAddr(self)
      print indent + '   RootScrAddr', returnScrAddr(self.root135Ref)
      print indent + '   ParentScrA:', returnScrAddr(self.akpParentRef)
      print indent + '   SelfScrAdd:', returnScrAddr(self)
      print indent + '   ChildIndex:', self.childIndex
      print indent + '   ChainIndex:', self.chainIndex
      print indent + '   LwestUnuse:', self.lowestUnusedChild
      print indent + '   NxtToCalc: ', self.nextChildToCalc
      print indent + '   RtLowest:  ', self.rootLowestUnused
      print indent + '   RtNextCa:  ', self.rootNextToCalc
      print indent + '   AKP Children:  Num=', len(self.akpChildByIndex)
      for idx,ch in self.akpChildByIndex.iteritems():
         print indent + '      %d      :'%idx, returnScrAddr(ch)

      #for sa,ch in self.akpChildByScrAddr.iteritems():
         #print indent + '      %s      :'%returnScrAddr(ch), ch.childIndex

      print indent + '   Root Children:  Num=', len(self.root135ChainMap)
      for idx,ch in self.root135ChainMap.iteritems():
         print indent + '      %d:      '%idx
         ch.pprintVerbose(indent='          ---')

      print '\n'


################################################################################
################################################################################
#
# Classes for BIP32 Extended Key objects
#
################################################################################
################################################################################

################################################################################
class ArmoryBip32ExtendedKey(ArmoryKeyPair):

   #############################################################################
   def __init__(self, *args, **kwargs):
      super(ArmoryBip32ExtendedKey, self).__init__(*args, **kwargs)



   #############################################################################
   def getCppExtendedKey(self, needPriv=False):
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Available:
         privWith00 = SecureBinaryData('\x00' + self.getPlainPrivKeyCopy().toBinStr())
         return Cpp.ExtendedKey(privWith00, self.sbdChaincode)
      else:
         if needPriv:
            raise WalletLockError('Priv EK requested, but priv not avail')
         return Cpp.ExtendedKey(self.sbdPublicKey33, self.sbdChaincode)


   #############################################################################
   def recomputeScript(self):
      pkHash160 = hash160(self.getSerializedPubKey())
      self.rawScript = hash160_to_p2pkhash_script(pkHash160)



   #############################################################################
   def recomputeUniqueIDBin(self):
      self.uniqueIDBin = None
      if self.sbdPublicKey33.getSize() == 0:
         return

      if not self.TREELEAF:
         # Compute the highest possible non-hardened child
         childAKP  = self.spawnChild(0x7fffffff, fsync=False, forIDCompute=True)
         child256  = hash256(childAKP.getScrAddr())
         firstByte = binary_to_int(child256[0])
         newFirst  = firstByte ^ binary_to_int(ADDRBYTE)
         self.uniqueIDBin = int_to_binary(newFirst) + child256[1:6]



   #############################################################################
   def spawnChild(self, childID, privSpawnReqd=False, fsync=True, forIDCompute=False):
      """
      Derive a child extended key from this one. 

      NOTE:  Var forIDCompute does two things:
                (1) Skips recursively computing the ID of the child
                (2) Allows children outside of the getChildClass() limitations
      """

      if forIDCompute:
         childAddr = ABEK_Generic()
      else:
         childAddr = self.getChildClass(childID)()

      childAddr.copyFromAKP(self)
      childAddr.isUsed = False

      # If the child key corresponds to a "hardened" derivation, we require
      # the priv keys to be available, or sometimes we explicitly request it
      pavail = self.getPrivKeyAvailability()
      privSpawnReqd = privSpawnReqd or (childID & HARDBIT > 0)
      nextUnlockFlag = False
      if privSpawnReqd:
         if pavail==PRIV_KEY_AVAIL.WatchOnly:
            raise KeyDataError('Requires priv key, but this is a WO ext key')
         elif pavail==PRIV_KEY_AVAIL.NeedDecrypt:
            raise WalletLockError('Requires priv key, no way to decrypt it')
         elif pavail==PRIV_KEY_AVAIL.NextUnlock:
            self.resolveNextUnlockFlag(fsync)


      if pavail in [PRIV_KEY_AVAIL.NeedDecrypt, PRIV_KEY_AVAIL.NextUnlock]:
         nextUnlockFlag = True


      # Call the C++ code that implements BIP32/HDW calculations
      extChild = Cpp.HDWalletCrypto().childKeyDeriv(self.getCppExtendedKey(), childID)

      childAddr.sbdPublicKey33  = extChild.getPublicKey().copy()
      childAddr.sbdChaincode = extChild.getChaincode().copy()

      if forIDCompute:
         return childAddr

      # This sets the priv key (if non-empty)
      # NOTE: this call must come after setting the public key, as it uses the 
      #       public key to compute the IV to encrypt new priv.  Because this 
      #       is fragile, we should consider making setNewPlainPrivKey() a 
      #       method that sets the pubkey and chaincode, too, to make sure this
      #       is done correctly
      childAddr.setNewPlainPrivKey(extChild.getPrivateKey(), self.privCryptInfo)
      childAddr.masterEkeyRef = self.masterEkeyRef
      childAddr.privKeyNextUnlock = nextUnlockFlag

      if not childAddr.sbdPublicKey33.getSize()==33:
         LOGERROR('Pubkey did not come out of HDW code compressed')

      childAddr.childIndex = childID
      childAddr.akpChildByIndex   = {}
      childAddr.akpChildByScrAddr = {}
      childAddr.wltLvlParent = self.wltLvlParent

      # These recompute calls also call recomputeScript and recomputeUniqueIDBIN
      childAddr.recomputeScrAddr()
      childAddr.recomputeUniqueIDB58()


      if fsync:
         self.addChildRef(childAddr)
         childAddr.fsync()
         self.fsync()

      return childAddr


   #############################################################################
   def getAddrLocatorString(self, locatorType='Plain', baseID=None):
      """
      This is a string that can be bundled with offline/multisig transactions
      to help lite devices identify that addresses/keys belong to them.  It's 
      basically just a wallet ID and path string.
   
      Can change the baseID to make the addr locator based on a different 
      root, perhaps the depth=1 node instead depth=0 

      In the future, we plan to improve privacy of these strings by encrypting
      them with data found in the watching-only wallet (i.e. using chaincodes).
      So that when someone sees M/105/8030 in one transaction and M/105/8085 in
      a separate transaction it won't be so obvious that they are part of the 
      same wallet, or owned by one person.  However, this is not a priority,
      since this kind of information leakage really only matters is very
      specific instances that are irrelevant to most users.
   
      The above paragraph refers to the fact that a multisig/lockbox transaction
      using Armory's USTX format, bundles the address locator strings into it,
      as a way for the online computers to communicate to the offline computers
      what addresses are being used.  But those strings are seen by all MS
      participants even though they are only consumed by one.
      """

      if not locatorType=='Plain':
         raise NotImplementedError('Cannot handle anything other than plain') 

      if baseID is None:
         baseID = self.root135Ref.getScrAddr()

      # Walk up the parent chain looking for the baseID, to make sure we
      # are only adding deriv-paths up to that tree node
      akp   = self
      akpID = self.getHash160()
      derivePath = []
      while not akpID==baseID:
         if akp.akpParentRef is None:
            raise WalletAddressError('Did not find specified base ID')

         derivePath.append(akp.childIndex)
         akp   = akp.akpParentRef
         akpID = akp.akpParentRef.getScrAddr()
   

      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, 'A2.0', 4)
      bp.put(VAR_STR,      locatorType)
      bp.put(BINARY_CHUNK, baseID)
      bp.put(VAR_INT, len(derivePath))
      for i in derivePath[::-1]:
         bp.put(UINT32, i)
      return bp.getBinaryString() 
      
   #############################################################################
   def getSpawnMultiplierForChild(self, childID):
      cnum,hard = SplitChildIndex(childID)
      if hard:
         raise ChildDeriveError('Cannot get multiplier for hardened children')

      sbdMult = NULLSBD()
      extPubKey = Cpp.ExtendedKey(self.sbdPublicKey33, self.sbdChaincode)
      extChild = Cpp.HDWalletCrypto().childKeyDeriv(extPubKey, childID, sbdMult)

      if sbdMult.getSize() == 0:
         raise KeyDataError('Multiplier was not set in childKeyDeriv call')

      return sbdMult.toBinStr()

      
   #############################################################################
   def getMultiplierList(self, fromBaseScrAddr=None):
      parentList = self.getParentList(fromBaseScrAddr)
      if len(parentList) == 0:
         return '',[]
      else:
         topScrAddr = parentList[0].getScrAddr()
         multList = [akp.getSpawnMultiplierForChild(i) for akp,i in parentList]
         return topScrAddr, multList



################################################################################
class ArmoryBip32Seed(ArmoryBip32ExtendedKey, ArmorySeededKeyPair):
   def __init__(self):
      ArmoryBip32ExtendedKey.__init__(self)
      ArmorySeededKeyPair.__init__(self)
      self.isRootRoot  = True


   #############################################################################
   @EkeyMustBeUnlocked
   @VerifyArgTypes(sbdPlainSeed=SecureBinaryData)
   def initializeFromSeed(self, sbdPlainSeed, verifyPub=None, fillPool=True):
      """
      We must already have a master encryption key created, and a reference to
      it set in this object (so the EkeyMustBeUnlocked decorator returns True)
      """

      cppExtKey = Cpp.HDWalletCrypto().ConvertSeedToMasterKey(sbdPlainSeed)
      self.sbdPublicKey33   = cppExtKey.getPublicKey().copy()
      self.sbdChaincode     = cppExtKey.getChaincode().copy()
      self.setNewPlainPrivKey(cppExtKey.getPrivateKey(), self.privCryptInfo)

      if verifyPub:
         if not self.sbdPublicKey33 == CryptoECDSA().CompressPoint(verifyPub):
            raise KeyDataError('Public key from seed does not match expected')
         

      self.seedNumBytes = sbdPlainSeed.getSize()
      self.seedCryptInfo = self.privCryptInfo.copy()
      # Normally PUBKEY20 is IV for priv, but need different new IV for the seed
      self.seedCryptInfo.ivSource = SecureBinaryData().GenerateRandom(8).toBinStr()
      self.seedNumBytes = sbdPlainSeed.getSize()
      paddedSize = roundUpMod(self.seedNumBytes, self.seedCryptInfo.getBlockSize())
      paddedSeed = SecureBinaryData(sbdPlainSeed.toBinStr().ljust(paddedSize, '\x00'))
      self.sbdSeedData = self.seedCryptInfo.encrypt(paddedSeed, ekeyObj=self.masterEkeyRef)


      self.isWatchOnly     = False
      self.useCompressPub  = True
      self.aekParScrAddr   = None
      self.aekRootScrAddr  = None
      self.akpParentRef    = None
      self.childIndex      = None

      self.recomputeUniqueIDBin()
      self.recomputeUniqueIDB58()
      self.recomputeScript()
      self.recomputeScrAddr()

      if fillPool:
         self.fillKeyPoolRecurse()


   #############################################################################
   @EkeyMustBeUnlocked
   def createNewSeed(self, seedSize, extraEntropy, fillPool=True):
      """
      This calls initializeFromSeed(), which requires you already set the 
      masterEkeyRef object and have it unlocked before calling this function.
      This guarantees that we know how encrypt the new seed.
      """

      if seedSize < 16 and not USE_TESTNET:
         raise KeyDataError('Seed size is not large enough to be considered secure!')

      # Uses Crypto++ PRNG -- which is suitable for cryptographic purposes.
      # 16 bytes is generally considered enough, though we add 4 extra for 
      # some margin.  We also have the option to add some extra entropy 
      # through the last command line argument.  We use this in ArmoryQt
      # and armoryd by pulling key presses and volatile system files
      if extraEntropy is None or extraEntropy.getSize()==0:
         raise KeyDataError('Must provide extra entropy for seed generation')

      newSeed = SecureBinaryData().GenerateRandom(seedSize, extraEntropy)
      self.initializeFromSeed(newSeed, fillPool=fillPool)
      newSeed.destroy()
      
      


      



################################################################################
class ArmoryImportedKeyPair(ArmoryKeyPair):

   FILECODE = 'IMPORTED'
   def __init__(self, *args, **kwargs):
      super(ArmoryImportedKeyPair, self).__init__(*args, **kwargs)

   #############################################################################
   def getAddrLocatorString(self):
      return ''

   #############################################################################
   def addChildRef(self, childAKP):
      newIdx = len(self.akpChildByIndex)
      self.akpChildByIndex[newIdx] = childAKP


################################################################################
################################################################################
class ArmoryImportedRoot(ArmorySeededKeyPair):
   def __init__(self):
      super(ArmoryImportedRoot, self).__init__()
      self.isFakeRoot = True
      self.isRootRoot = True






#############################################################################
class ABEK_BIP44Seed(ArmoryBip32Seed):
   FILECODE = 'BIP44ROT'
   TREELEAF  = False
   HARDCHILD = True

   def __init__(self):
      super(ABEK_BIP44Seed, self).__init__()

   #####
   def getChildClass(self, index):
      if index==CreateChildIndex(44, True):
         return ABEK_BIP44Bitcoin

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


   

#############################################################################
class ABEK_BIP44Purpose(ArmoryBip32ExtendedKey):
   FILECODE = 'BIP44PUR'
   TREELEAF  = False
   HARDCHILD = True

   def __init__(self):
      super(ABEK_BIP44Purpose, self).__init__()

   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      expectedIdx = 1 if USE_TESTNET else 0
      if index==expectedIdx and hard==self.HARDCHILD:
         return ABEK_BIP44Bitcoin

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


#############################################################################
class ABEK_BIP44Bitcoin(ArmoryBip32ExtendedKey):
   FILECODE = 'BIP44BTC'
   TREELEAF  = False
   HARDCHILD = True

   def __init__(self):
      super(ABEK_BIP44Bitcoin, self).__init__()
      self.maxChildren = UINT32_MAX

   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      if hard==self.HARDCHILD:
         return ABEK_StdWallet

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


#############################################################################
class ABEK_StdBip32Seed(ArmoryBip32Seed):
   FILECODE = 'BIP32ROT'
   TREELEAF  = False
   HARDCHILD = True

   def __init__(self):
      super(ABEK_StdBip32Seed, self).__init__()

   #####
   def getChildClass(self, index):
      idx,hard = SplitChildIndex(index)
      if hard==self.HARDCHILD:
         return ABEK_StdWallet

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


#############################################################################
class ABEK_SoftBip32Seed(ABEK_StdBip32Seed):
   FILECODE = 'SFT32ROT'
   TREELEAF  = False
   HARDCHILD = False


#############################################################################
class ABEK_StdWallet(ArmoryBip32ExtendedKey):
   FILECODE  = 'STD32WLT'
   TREELEAF  = False
   HARDCHILD = False
   
      
   def __init__(self):
      super(ABEK_StdWallet, self).__init__()

      self.maxChildren = 2

      self.wltName  = u''
      self.wltDescr = u''

      # If this root is intended to be used in multi-sig, it should be flagged
      # so that it won't be used as a regular wallet
      self.onlyForMultisig = False

      # This will identify what app created this root, perhaps it's imported
      # from a Trezor, or it's from another Armory instance.  This is really
      # just informational, probably not going to be used for code branching (?)
      self.rootSourceApp   = ""

      # This is a root of a single-sig phone wallet.  We have the priv keys
      # here, but we don't intend to spend it from here.  Instead of a "Send"
      # button it should have a "Help I lost my phone!" button to sweep the
      # funds.
      self.isPhoneRoot   = False  


      # Only use to gen deposit addrs, bal is meaningless.  This might be used
      # in the case that we integrate an exchange API, and we want Armory to 
      # be able to generate customer-specific deposit addresses (from floating
      # BIP32 branch).   The exchange may move the money around internally,
      # so the "balance" of this branch is meaningless, and "balance" should be
      # an API call to get your account balance.
      self.isDepositOnlyRoot = False  

      # In the event that some data type identifies this root as its parent AND
      # it identifies itself as critical AND we don't recognize it (such as if
      # you use a colored-coin variant of Armory and then later import the wlt
      # using vanilla Armory), this wallet should be identified as existent 
      # but unusable/disabled, to avoid doing something you shouldn't (like
      # paying for your pizza with 30,000 shares of your startup company)
      self.isDisabled = False

      # If the user decided to "remove" this wallet, then we simply mark it as
      # "removed" and don't display it or do anything with it.
      self.userRemoved = False



   #############################################################################
   def getChildClass(self, index):
      cnum,ishard = SplitChildIndex(index)
      if ishard==self.HARDCHILD and cnum==0:
         return ABEK_StdChainExt
      elif ishard==self.HARDCHILD and cnum==1:
         return ABEK_StdChainInt
      
      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


   #############################################################################
   def getWalletChainIndex(self, chainType="External"):
      """
      In the case of single-sig wallets, we have just two chains, EXTERNAL (0)
      and INTERNAL (1).  In the case of multi-sig, we have one pair of wallet
      chains for each signing authority.  We use the ordering of the root pub
      keys in the relationship object to determine which of the 2*N chains to
      use.  This method will be overridden by the MultisigRoot class.
      """
      return 0 if chainType.lower()=='external' else 1


   #############################################################################
   def getNextReceivingAddress(self, fsync=True):
      i = self.getWalletChainIndex('External')
      ch = self.getChildByIndex(i, spawnIfNeeded=True, fsync=True)
      return ch.getNextUnusedChild()

   #############################################################################
   def peekNextReceivingAddress(self):
      ch = self.getChildByIndex(i, spawnIfNeeded=True, fsync=False)
      return ch.peekNextUnusedChild()

   #############################################################################
   def getNextChangeAddress(self):
      i = self.getWalletChainIndex('Internal')
      ch = self.getChildByIndex(i, spawnIfNeeded=True, fsync=True)
      return ch.getNextUnusedChild()
         


   
   
#############################################################################
class ABEK_StdChainInt(ArmoryBip32ExtendedKey):
   FILECODE = 'STD32CIN'
   TREELEAF  = False
   HARDCHILD = False

   #############################################################################
   def __init__(self):
      super(ABEK_StdChainInt, self).__init__()
      self.maxChildren = UINT32_MAX

   #############################################################################
   def getChildClass(self, index):
      cnum,ishard = SplitChildIndex(index)
      if ishard==self.HARDCHILD:
         return ABEK_StdLeaf
      
      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


#############################################################################
class ABEK_StdChainExt(ArmoryBip32ExtendedKey):
   FILECODE = 'STD32CEX'
   TREELEAF  = False
   HARDCHILD = False

   #############################################################################
   def __init__(self):
      super(ABEK_StdChainExt, self).__init__()
      self.maxChildren = UINT32_MAX


   #############################################################################
   def getChildClass(self, index):
      cnum,ishard = SplitChildIndex(index)
      if ishard==self.HARDCHILD:
         return ABEK_StdLeaf
      
      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))

#############################################################################
class ABEK_StdLeaf(ArmoryBip32ExtendedKey):
   FILECODE = 'STD32LEF'
   TREELEAF  = True
   HARDCHILD = False

   #############################################################################
   def __init__(self):
      super(ABEK_StdLeaf, self).__init__()
      self.maxChildren = 0

   #############################################################################
   def getChildClass(self, index):
      raise ChildDeriveError('Cannot derive child from leaf')




################################################################################
class MultisigMetaData(WalletEntry):
   """
   For now, the only purpose of this object is to identify which sibling
   in a Multisig root object we prefer to be associated with.  This 
   needs to be separate from the Multisig root itself, since we typically
   will be transferring the MultisigRoot to other people, who will have
   a different preferredID, so storing it with the root object is counter-
   productive. 

   I expect we will find other data to store here, at some point
   """
   FILECODE = "MULTMETA"

   def __init__(self):
      super(MultisigMetaData, self).__init__()
      self.multisigRootID = None
      self.preferredSibID = None


################################################################################
class MultisigABEK(ArmoryBip32ExtendedKey):
   """
   "KeyPair" is a misnomer in this class name, but it behaves like (and derives
   from) the ArmoryKeyPair class.  It can be used almost identically to the
   other AKP objects, but instead of storing keydata, it references N different
   AKP objects to be used as part of a multisig.  

   For instance, "spawnChild" simply calls "spawnChild" of all the multisig
   "siblings", and then combines the result into an M-of-N script.
   """
   #############################################################################
   def __init__(self):
      super(MultisigABEK, self).__init__()

   #############################################################################
   def initializeMBEK(M=None, N=None, sibScrAddrList=None, lblList=None):
      self.M = M if M else 0
      self.N = N if N else 0
      self.maxChildren = 2*N
      self.sibScrAddrs = []

      # These will be set later to reference other stuff in the wallet file
      self.isComplete  = False
      self.sibLookup   = []
      self.prefSibling = None  # for determining internal/external chain pair
      self.siblingRefs = []

      if sibScrAddrList:
         if lblList is None:
            lblList = ['']*self.N

         for ssa,lbl in zip(sibScrAddrList, lblList):
            self.addSiblingID(ssa, lbl)


   #############################################################################
   def setSiblingRefs(self, abekMap, prefID=None):
      if not isComplete:
         raise WalletAddressError('Not all sibling IDs defined')

      self.prefSibling = prefID
      for s160 in self.sibScrAddrs:
         if not s160 in abekMap:
            raise WalletAddressError('Not all siblings in supplied abekMap')
         self.siblingRefs.append(abekMap[s160])
         

   #############################################################################
   def spawnChild(self, childID, privSpawnReqd=False, fsync=True, forIDCompute=False):
      if privSpawnReqd:
         raise MultisigError('Priv spawning does not make sense w/ multisig!')

      if not self.isComplete:
         raise MultisigError('Multisig ExtKey is not complete, cannot spawn')
      
      newChildList = {}
      pkList = []
      for sib in self.siblingRefs:
         ch = sib.getChildByIndex(childID, spawnIfNeeded=True, fsync=fsync)
         newChildList[ch.getScrAddr()] = ch
         pkList.append(ch.getSerializedPubKey())


      if forIDCompute():
         childMBEK = MBEK_Generic()
      else:
         childMBEK = self.getChildClass(childID)()

      childMBEK.initializeMBEK(self.M, self.N, newChildList)
      childMBEK.wltLvlParent = self.wltLvlParent

      # These recompute calls also call recomputeScript and recomputeUniqueIDBIN
      childMBEK.recomputeScrAddr()
      if not forIDCompute:
         childMBEK.recomputeUniqueIDB58()


   #############################################################################
   def recomputeScript(self):
      pklist = [akp.getSerializedPubKey() for akp in self.siblingRefs]
      rawMsScript= pubkeylist_to_multisig_script(pklist, self.M)
      self.rawScript = script_to_p2sh_script(rawMsScript)

   #############################################################################
   def recomputeScrAddr(self):
      self.recomputeScript()
      self.scrAddrStr = script_to_scrAddr(self.rawScript)


   #############################################################################
   def getEntryID(self):
      return self.getScrAddr()

      
   #############################################################################
   def getWalletChainIndex(self, chainType="External"):
      # We have two chains for each sibling.  Pick the 
      indexSelf = self.getSiblingIndex(self.multisigWhoAmI())
      return 2*indexSelf + (0 if chainType.lower()=='external' else 1)

   #############################################################################
   def multisigWhoAmI(self):
      if self.prefSibling is None:
         # Return the first non-watch-only wallet
         for i,sref in enumerate(self.siblingRefs):
            if not sref.isWatchOnly:
               return i 
      else:
         return self.getSiblingIndex(self.prefSibling)

      return 0


   #############################################################################
   def addSiblingID(self, sibRootID, label):
      if len(self.sibScrAddrs) >= self.N:
         raise BadInputError('MBEK already has %d siblings' % self.N)

      self.sibScrAddrs.append(sibRootID)
      self.sibLabels.append(label)
      self.siblingRefs.append(None)

      if len(self.sibScrAddrs) == self.N:
         self.isComplete = True
         self.sibScrAddrs.sort()
         for i,sib in enumerate(self.sibScrAddrs):
            self.sibLookup[sib] = i
          
   #############################################################################
   def setSiblingRef(self, sibRef):
      if not self.isComplete: 
         raise MultisigError('Cannot add sibling refs until all IDs are added')

      i = getSiblingIndex(sibRef.getScrAddr())
      while i>=len(self.siblingRefs):
         self.siblingRefs.append(None)

      self.siblingRefs[i] = sibRef

   #############################################################################
   def getSiblingIndex(self, sibID):
      if not self.isComplete:
         raise UninitializedError('Multisig root object not full yet')

      if not sibID in self.sibLookup:
         raise UninitializedError('Sibling not found in this root obj')
          
      return self.sibLookup[sibID]
      

      

   #############################################################################
   def serializeMultisigData(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, self.relID, widthBytes=8)
      bp.put(BINARY_CHUNK, self.randID, widthBytes=8)
      bp.put(UINT8, self.M)
      bp.put(UINT8, self.N)
      bp.put(UINT8, len(self.sibScrAddrs))
      for i in range(len(self.sibScrAddrs)):
         bp.put(VAR_STR, self.sibScrAddrs[i])
         bp.put(VAR_UNICODE, self.labels[i])

      return bp.getBinaryString()


   #############################################################################
   def unserializeMultisigData(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      relID = bu.get(BINARY_CHUNK, 8)
      rndID = bu.get(BINARY_CHUNK, 8)
      M = bu.get(UINT8)
      N = bu.get(UINT8)
      nsib = bu.get(UINT8)
      sibList = []
      lblList = []
      for i in range(nsib):
         sibList.append(bu.get(VAR_STR))
         lblList.append(bu.get(VAR_UNICODE))

      self.__init__(M, N, sibList, lblList)
      return self

   #############################################################################
   def serialize(self):
      if self.sbdPublicKey33.getSize()==0:
         raise UninitializedError('Will not serialize uninitialized AKP')

      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, super(MultisigABEK, self).serialize())
      bp.put(BINARY_CHUNK, self.serializeMultisigData())

   #############################################################################
   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)


   #############################################################################
   def serializeWatchOnlyData(self):
      raise NotImplementedError('Encoding not implemented yet')
      
   #############################################################################
   def unserializeWatchOnlyData(self):
      raise NotImplementedError('Encoding not implemented yet')



################################################################################
class MBEK_StdWallet(MultisigABEK):
   FILECODE = 'MEK32WLT'
   TREELEAF  = False
   HARDCHILD = False

   #############################################################################
   def __init__(self, M=None, N=None, siblingList=None):
      super(MBEK_StdWallet, self).__init__(M, N, siblingList)
      
    
   #############################################################################
   def getSiblingClass(self):
      return ABEK_StdWallet


   #############################################################################
   def initialize(self, M, N, siblingList):
      self.M = M
      self.N = N
      if N is not None:
         self.maxChildren = 2*N

      for sib in siblingList:
         self.addSiblingID(sib)

   #############################################################################
   def getChildClass(self, index):
      cnum,ishard = SplitChildIndex(index)
      if cnum>=self.maxChildren or not ishard==self.HARDCHILD:
         raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))

      if cnum%2==0:
         return MBEK_StdChainExt
      elif cnum%2==1:
         return MBEK_StdChainInt
      



################################################################################
class MBEK_StdChainExt(MultisigABEK):
   FILECODE = 'MEK32CEX'
   TREELEAF  = False
   HARDCHILD = False

   #############################################################################
   def __init__(self):
      super(MBEK_StdLeaf, self).__init__()
      self.maxChildren = UINT32_MAX

   #############################################################################
   def getSiblingClass(self):
      return ABEK_StdChainExt

   #############################################################################
   def getChildClass(self, index):
      cnum,ishard = SplitChildIndex(index)
      if ishard==self.HARDCHILD:
         return MBEK_StdLeaf

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))

################################################################################
class MBEK_StdChainInt(MultisigABEK):
   FILECODE = 'MEK32CIN'
   TREELEAF  = False
   HARDCHILD = False

   #############################################################################
   def __init__(self):
      super(MBEK_StdLeaf, self).__init__()
      self.maxChildren = UINT32_MAX


   #############################################################################
   def getSiblingClass(self):
      return ABEK_StdChainInt

   #############################################################################
   def getChildClass(self, index):
      cnum,ishard = SplitChildIndex(index)
      if ishard==self.HARDCHILD:
         return MBEK_StdLeaf

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


################################################################################
class MBEK_StdLeaf(MultisigABEK):
   FILECODE = 'MEK32LEF'
   TREELEAF  = True
   HARDCHILD = False

   #############################################################################
   def __init__(self):
      super(MBEK_StdLeaf, self).__init__()
      self.maxChildren = 0

   #############################################################################
   def getSiblingClass(self):
      return ABEK_StdLeaf

   #############################################################################
   def getChildClass(self, index):
      raise ChildDeriveError('Cannot derive child from leaf')



################################################################################
class MBEK_StdBip32Root(MultisigABEK):
   FILECODE = 'MULWLTMS' # MULti WaLleT MultiSig
   TREELEAF  = False
   HARDCHILD = False  # see comment below


   #############################################################################
   def __init__(self, M=None, N=None, siblingList=None, labels=None):
      """
      This class may not be common.  It is parallel to the ABEK_StdBip32Seed 
      class in that it generates any number of multisig wallets.  This is not
      derived from the *Seed class because there is no "seed" for a multi-sig
      wallet, even of this type.  You might consider the combination of the
      seeds of each of the individual ABEK seed to be cosnidered the "seed"
      for this wallet root, but combining all the seeds would completely
      defeat the purpose of multisig, and we don't expect it to happen.

      If this is used, it would essentially be to create "accounts" within
      a multi-sig wallet.  Rather, this root would be treated like the
      "wallet", and each MBEK_StdWallet object would be treated like accounts
      within it.

      NOTE: We do *not* use the hardened derivation for generating the child
      MBEKs, as that would defeat the purpose:  it'd require having the
      private keys for all sibling ABEKs in order to generate new "accounts"
      """

      super(MBEK_StdBip32Root, self).__init__(M, N, siblingList, labels)


   #############################################################################
   def getSiblingClass(self):
      return ABEK_StdBip32Seed

   #####
   def getChildClass(self, index):
      "Unlike ABEK_StdBip32Seed, we use non-hardened derivations"
      idx,hard = SplitChildIndex(index)
      if hard==self.HARDCHILD:
         return MBEK_StdWallet

      raise ChildDeriveError('Invalid child %s for %s' % \
                              (ChildIndexToStr(index), self.getName()))


#############################################################################
# ?BEK_Generic classes are for the occasional times that we just need a 
# generic BIP32 node for various calculations and don't want arbitrary
# limitations on child spawning (mostly during testing)
class ABEK_Generic(ArmoryBip32ExtendedKey):
   TREELEAF  = False
   HARDCHILD = False

   def __init__(self):
      super(ABEK_Generic, self).__init__()
      self.maxChildren = UINT32_MAX

   def getChildClass(self, index): 
      # No restrictions on spawn class (non-hardened is default, though)
      return ABEK_Generic

#############################################################################
class MBEK_Generic(MultisigABEK):
   TREELEAF  = False
   HARDCHILD = False

   def __init__(self):
      super(MBEK_Generic, self).__init__()
      self.maxChildren = UINT32_MAX

   def getChildClass(self, index): 
      return ABEK_Generic





# TODO:  Figure out how to prevent this code from getting run 4+ times without
#        this conditional
if not 'BIP44ROT' in WalletEntry.FILECODEMAP:
   WalletEntry.RegisterWalletStorageClass(ABEK_BIP44Seed)
   WalletEntry.RegisterWalletStorageClass(ABEK_BIP44Purpose)
   WalletEntry.RegisterWalletStorageClass(ABEK_BIP44Bitcoin)

   WalletEntry.RegisterWalletStorageClass(ABEK_StdBip32Seed)
   WalletEntry.RegisterWalletStorageClass(ABEK_StdWallet)
   WalletEntry.RegisterWalletStorageClass(ABEK_StdChainExt)
   WalletEntry.RegisterWalletStorageClass(ABEK_StdChainInt)
   WalletEntry.RegisterWalletStorageClass(ABEK_StdLeaf)

   WalletEntry.RegisterWalletStorageClass(MBEK_StdBip32Root)
   WalletEntry.RegisterWalletStorageClass(MBEK_StdWallet)
   WalletEntry.RegisterWalletStorageClass(MBEK_StdChainExt)
   WalletEntry.RegisterWalletStorageClass(MBEK_StdChainInt)
   WalletEntry.RegisterWalletStorageClass(MBEK_StdLeaf)

   WalletEntry.RegisterWalletStorageClass(Armory135Root)
   WalletEntry.RegisterWalletStorageClass(Armory135KeyPair)
   WalletEntry.RegisterWalletStorageClass(ArmoryImportedRoot)
   WalletEntry.RegisterWalletStorageClass(ArmoryImportedKeyPair)

