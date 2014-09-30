from ArmoryUtils import *

################################################################################
class WalletEntry(object):
   """
   The wallets will be made up of IFF/RIFF entries. 


   The REQUIRED_TYPES list is all the wallet entry codes that MUST be 
   understood by the reading application in order to move forward 
   reading and using the wallet.  If a data type is in the list, a flag
   will be set in the serialization telling the application that it 
   should throw an error if it does not recognize it.

   Example 1 -- Relationship objects:
      Wallets that are born to be part of M-of-N linked wallets are 
      never used for single-sig addresses.  If an application does
      not implement the relationship type, it should not attempt to 
      use the wallet at all, since it would skip the RLAT code and 
      create single-sig addresses.

   Example 2 -- Colored Coins (not implemented yet):
      If a given wallet handles colored coins, it could be a disaster
      if the application did not recognize that, and let you spend 
      your colored coins as if they were regular BTC.  Thefore, if you
      are going to implement colored coins, you must add that code to
      the REQUIRED_TYPES list.  Then, if vanilla Armory (without colored
      coin support) is used to read the wallet, it will not allow the 
      user to use that wallet
         
   Example 3 -- P2SH Scripts:
      This is borderline, and I may add this to the REQUIRED_TYPES list
      as I get further into implementation.  Strictly speaking, you don't
      *need* P2SH information in order to use the non-P2SH information 
      in the wallet (such as single sig addresses), but you won't 
      recognize much of the BTC that is [partially] available to that 
      wallet if you don't read P2SH scripts.
   

   The following comments are for labels & P2SH scripts:

   The goal of this object type is to allow for generic encryption to 
   be applied to wallet entries without regard for what data it is.

   Our root private key only needs to be backed up once, but all of the 
   P2SH scripts should be backed up regularly (and comment fields would be 
   nice to have backed up, too).  The problem is, you don't want to put 
   your whole wallet file into dropbox, encrypted or not.  The solution is
   to have a separate P2SH&Comments file (a wallet without any addresses)
   which can be put in Dropbox.

   The solution is to have a file that can be put in dropbox, and each
   entry is AES encrypted using the 32 bytes of the PUBLIC FINGERPRINT as
   the encryption key.   This allows you to decrypt this entry without 
   even unlocking your wallet, but it does require you to have that (WO)
   wallet in your possession.  Your wallet should NOT be backed up this
   way, thus anyone gaining access to only the P2SH&Comment file would NOT
   have the information needed to decrypt it (and by using the finger-
   print of the address, they can't simply try every public key in the 
   blockchain ... they must have access to at least the watching-only wlt).
  
   """

   #FILECODEMAP = { #'HEAD': ArmoryFileHeader,
                    #'ADDR': ArmoryAddress,
                    #'ROOT': ArmoryRoot,
                    #'LABL': AddressLabel,
                    #'COMM': TxLabel,
                    #'LBOX': MultiSigLockbox,
                    #'ZERO': ZeroData, 
                    #'RLAT': RootRelationship,
                    #'EKEY': EncryptionKey,
                    #'MKEY': MultiPwdEncryptionKey,
                    #'KDFO': KdfObject,
                    #'IDNT': IdentityPublicKey,
                    #'SIGN': WltEntrySignature }

   #REQUIRED_TYPES = ['ADDR', 'ROOT', 'RLAT']

   # See end of armoryengine/ArmoryWallet.py for the list -- this had to be
   # done dynamically because at the time this file is imported, not all the
   # classes above have been defined.
   FILECODEMAP   = {}
   REQUIRED_TYPES = []

   #############################################################################
   @staticmethod
   def addClassToMap(clsType, isReqd=False):
      weCode = clsType.FILECODE
      if weCode in WalletEntry.FILECODEMAP:
         raise ValueError('Class with code "%s" is already in map!' % weCode)

      WalletEntry.FILECODEMAP[clsType.FILECODE] = clsType
      if isReqd:
         WalletEntry.REQUIRED_TYPES.append(weCode)


   #############################################################################
   def __init__(self, wltFileRef=None, offset=-1, weSize=-1, reqdBit=False,    
              wltPar160=None, outerCrypt=None, serPayload=None, defaultPad=256):
      self.wltFileRef = wltFileRef
      self.wltByteLoc = offset
      self.wltEntrySz = weSize
      self.isRequired = reqdBit
      self.wltPar160 = wltPar160
      self.outerCrypt = outerCrypt
      self.serPayload = serPayload
      self.rsecCode   = rsecCode 
      self.flagBytes  = BitSet(8)

      self.wltParentRef = None
      self.wltChildRefs = []
      self.uniqueID20 = None

      self.isOpaque = False
      self.isUnrecognized = False
      self.isUnrecoverable = False
      self.isDeleted = False
      self.isDisabled = False
      self.needRewrite = False
      self.needsFsync = False


      self.defaultPad = defaultPad
         
   #############################################################################
   @staticmethod
   def CreateDeletedEntry(weSize):
      we = WalletEntry()
      we.isDeleted = True
      we.wltEntrySz = weSize
      return we
      
   #############################################################################
   def getEntryID(self):
      raise NotImplementedError('This must be overriden by derived class!')


   #############################################################################
   @staticmethod
   def UnserializeEntry(toUnpack, parentWlt, fOffset, **decryptKwargs):
      """
      Unserialize a WalletEntry object -- the output of this function is
      actually a class derived from WalletEntry:  it uses the 8-byte FILECODE
      [static] member to determine what class's unserialize method should be
      used on the "payload"

      The flow is a little awkward:  we make a generic WalletEntry object that 
      will be updated with generic data and some booleans, but it will only be
      used if we have to return early due to urecoverable, unrecognized or 
      undecryptable.  Otherwise, at the end we make and return a new object
      of the correct class type, and set all the members on it that were set
      on the "we" object earlier
      """
      we = WalletEntry()
      toUnpack = makeBinaryUnpacker(toUnpack)
      unpackStart  = toUnpack.getPosition()

      wltVersion   = toUnpack.get(UINT32)
      weFlags      = toUnpack.get(BITSET, 1)  # one byte

      if wltVersion != getVersionInt(ARMORY_WALLET_VERSION):
         LOGWARN('WalletEntry version: %s,  Armory Wallet version: %s', 
                     getVersionString(readVersionInt(wltVersion)), 
                     getVersionString(ARMORY_WALLET_VERSION))


      we.isDeleted = weFlags.getBit(0)
      if we.isDeleted:
         # Don't use VAR_INT/VAR_SIZE for size of zero chunk due to complixty 
         # of handling the size being at the boundary of two VAR_INT sizes
         we.wltEntrySz = toUnpack.get(UINT32) + 9
         shouldBeZeros = toUnpack.get(BINARY_CHUNK, we.wltEntrySz - 9)
         if not len(shouldBeZeros)==shouldBeZeros.count('\x00'):
            raise UnpackerError('Deleted entry is not all zero bytes')
         return we


      parent160    = toUnpack.get(BINARY_CHUNK, 20)
      serCryptInfo = toUnpack.get(BINARY_CHUNK, 32)  
      serPayload   = toUnpack.get(VAR_STR)  
      rsecCode     = toUnpack.get(VAR_STR)


      we.parent160    = parent160
      we.wltFileRef   = parentWlt
      we.wltStartByte = fOffset 
      we.wltEntrySz   = toUnpack.getPosition() - unpackStart
      we.payloadSz    = len(serPayload)

      we.isOpaque        = False
      we.isUnrecognized  = False
      we.isUnrecoverable = False

      # Detect and correct any bad bytes in the data
      we.serPayload,failFlag,modFlag = checkRSECCode(serPayload, rsecCode)
      if failFlag:
         LOGERROR('Unrecoverable error in wallet entry')
         we.isUnrecoverable = True 
         return we
      elif modFlag:
         LOGWARN('Error in wallet file corrected successfully')
         we.needRewrite = True 


      we.outerCrypt = ArmoryCryptInfo().unserialize(serCryptInfo)

      if we.outerCrypt.noEncryption():
         return we.parsePayloadReturnNewObj()
      else:
         we.isOpaque   = True
         if len(decryptKwargs)==0:
            return we
         else:
            return we.decryptPayloadReturnNewObj(**decryptKwargs)


   #############################################################################
   def parsePayloadReturnNewObj(self):

      if self.isOpaque:
         raise EncryptionError('Payload of WltEntry is encrypted.  Cannot parse')

      # The following is all the data that is inside the payload, which is
      # all hidden/opaque if it's encrypted
      buPayload = BinaryUnpacker(self.serPayload)
      plType  = buPayload.get(BINARY_CHUNK, 8)
      plFlags = buPayload.get(BITSET, 1)
      plObjID = buPayload.get(BINARY_CHUNK, 20)
      plData  = buPayload.get(VAR_STR)

      # Throw an error if padding consists of more than \x00... don't want
      # it to become a vessel for transporting/hiding data (like Windows ADS)
      nBytesLeft = buPayload.getRemainingSize()
      leftover = buPayload.getRemainingString()
      if leftover.count('\x00') < nBytesLeft:
         raise EncryptionError('Padding in wlt entry is non-zero!')


      self.uniqueID20 = plObjID

      # The first bit tells us that if we don't understand this wallet entry,
      # we shouldn't use this wallet (perhaps this wallet manages colored coins
      # and was loaded on vanilla Armory -- we dont' want to spend those 
      # coins.
      self.isRequired = plFlags.getBit(0)

      # Use the 8-byte FILECODE to determine the type of object to unserialize
      clsType = WalletEntry.FILECODEMAP.get(plType)
      if clsType is None:
         LOGWARN('Unrecognized data type in wallet')
         self.isUnrecognized = True
         return self

      # Return value is actually a subclass of WalletEntry
      weOut = WalletEntry.FILECODEMAP[plType]().unserialize(plData, self.wltFileRef)
      weOut.wltFileRef   = self.wltFileRef
      weOut.wltStartByte = self.wltStartByte
      weOut.wltEntrySz   = self.wltEntrySz
      weOut.payloadSz    = self.payloadSz
      weOut.uniqueID20   = self.uniqueID20
      weOut.needRewrite  = self.needRewrite or weOut.needRewrite
      # (subclass might've triggered rewrite flag, don't want to overwrite it)

      return weOut


   #############################################################################
   def decryptPayloadReturnNewObj(self, **outerCryptArgs):
      if not self.isOpaque:
         raise EncryptionError('Payload data is not encrypted!')

      try:
         cryptPL = SecureBinaryData(self.serPayload)
         plainPL = self.outerCrypt.decrypt(cryptPL, **outerCryptArgs)
         self.serPayload = plainPL.toBinStr()
         self.isOpaque = False
         return self.parsePayloadReturnNewObj()
      except:
         LOGEXCEPT('Decryption of WalletEntry payload failed')
      


   #############################################################################
   def serializeEntry(self, doDelete=False, **encryptKwargs):

      weFlags = BitSet(8)
      if self.isDeleted or doDelete:
         weFlags.setBit(0, True)
         nZero = self.wltEntrySz - 9  # version(4) + flags(2) + numZero(4)
         
         bp = BinaryPacker()
         bp.put(UINT32,       getVersionInt(ARMORY_WALLET_VERSION)) 
         bp.put(BITSET,       weFlags, 1)
         bp.put(UINT32,       nZero)
         bp.put(BINARY_CHUNK, '\x00'*nZero)
         return bp.getBinaryString()
         
         
      # Going to create the sub-serialized object that might be encrypted
      serObject = self.serialize()
      lenObject = len(serObject)

      plBits = BitSet(8)
      plBits.setBit(0, self.FILECODE in WalletEntry.REQUIRED_TYPES)

      payload = BinaryPacker() 
      bpPayload.put(BINARY_CHUNK, self.FILECODE, width=8) 
      bpPayload.put(BITSET,       plBits, 1)
      bpPayload.put(BINARY_CHUNK, self.uniqueID20, width=20)
      bpPayload.put(VAR_STR,      serObject)

      # Now we have the full unencrypted version of the data for the file
      serPayload = padString(bpPayload.getBinaryString(), self.defaultPad)
       
      if self.outerCryptInfo.useEncryption():
         raise NotImplementedError('Outer encryption not yet implemented!')
         if not len(serPayload) % self.outerCryptInfo.getBlockSize() == 0:
            raise EncryptionError('Improper padding on payload data for encryption')
         serPayload = self.outerCryptInfo.encrypt(serPayload, **encryptKwargs)

      # Computes 16-byte Reed-Solomon error-correction code per 1024 bytes
      rsecCode = createRSECCode(serPayload)

      # Now we have everything we need to serialize the wallet entry
      bp = BinaryPacker()
      bp.put(UINT32,       getVersionInt(ARMORY_WALLET_VERSION)) 
      bp.put(BITSET,       weFlags, 1)
      bp.put(BINARY_CHUNK, self.parent160,       width=20)
      bp.put(BINARY_CHUNK, self.outerCryptInfo,  width=32)
      bp.put(VAR_STR,      serPayload)
      bp.put(VAR_STR,      rsecCode)
      return bp.getBinaryString()
      

   #############################################################################
   def getEkeyFromWallet(self, ekeyID):
      if self.wltFileRef is None:
         raise WalletExistsError('This wallet entry has no wallet file!')

      return self.wltFileRef.ekeyMap.get(ekeyID, None)



   #############################################################################
   def fsync(self):
      if self.wltFileRef is None:
         LOGERROR('Attempted to rewrite WE object but no wlt file ref.')

      if self.wltStartByte<=0:
         self.wltFileRef.doFileOperation('AddEntry', self)
      else:
         self.wltFileRef.doFileOperation('UpdateEntry', self)

   #############################################################################
   def useOuterEncryption(self):
      return outerCryptInfo.useEncryption()

        
   #############################################################################
   def disableAllWltChildren(self):
      self.isDisabled = True
      for child in self.wltChildRefs:
         child.disableAllWltChildren()   
         



   #############################################################################
   def removeEncryption(self, oldKey, oldIV=None):
      raise NotImplementedError


   #############################################################################
   def pprintOneLine(self, nIndent=0):
      fmtField = lambda lbl,val,wid: '(%s %s)'%(lbl,str(val)[:wid].rjust(wid))
      print fmtField('', self.FILECODE, 8),
      print fmtField('in', self.self.wltFileRef.filepath.basename(), 4),

      #toPrint = [self.FILECODE, \
                 #self.wltFileRef.path.basename, \
                 #self.wltStartByte, \
                 #binary_to_hex(self.parentRoot160[:4]), \

      #self.FILECODE       = weCode

      #self.wltFileRef      = wltFileRef
      #self.wltStartByte      = wltByteLoc

      #self.wltParent160   = wltPar160
      #self.outerCryptInfo     = encr
      #self.initPayload(payload, payloadSize, encr)

      # Default to padding all data in file to modulo 16 (helps with crypto)
      #self.setPayloadPadding(16)

      #self.lockTimeout  = 9   # seconds after unlock, that key is discarded
      #self.relockAtTime = 0    # seconds after unlock, that key is discarded





