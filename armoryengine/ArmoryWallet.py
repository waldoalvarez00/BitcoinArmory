from ArmoryUtils import *
from ArmoryEncryption import *
from WalletEntry import *





################################################################################
################################################################################
class ArmoryWalletFile(object):

   def __init__(self):

      if not os.path.exists(filepath) and not createNew:
         LOGERROR('Attempted to open a wallet file that does not exist!')
         raise FileExistsError

      self.fileHeader = ArmoryFileHeader()

      # We will queue updates to the wallet file, and later apply them  
      # atomically to avoid corruption problems
      self.updateQueue   = []
      self.lastFilesize  = -1

      # WalletEntry objects may request an update, but that update is not 
      # applied right away.  This variable will be incremented on every
      # call to applyUpdates(), so WE objects know when it's done
      self.updateCount  = 0

      # We will need a bunch of different pathnames for atomic update ops
      self.walletPath        = filepath
      self.walletPathBackup  = self.getWalletPath('backup')
      self.walletPathUpdFail = self.getWalletPath('update_unsuccessful')
      self.walletPathBakFail = self.getWalletPath('backup_unsuccessful')

      # Last synchronized all chains to this block
      self.lastSyncBlockNum = 0

      # All wallet roots based on "standard" BIP 32 usage:
      #    rootMap[0] ~ Map of all zeroth-order roots, derived from seeds
      #    rootMap[1] ~ Map of all wallets for all base roots
      #    rootMap[2] ~ Map of internal/external chains of all wallets.
      # Maps are indexed by 20-byte ID (the address/hash160 they would have
      # if they were to be used to receive funds, but they are not in these
      # maps if they are ever used to receive funds -- all such addresses 
      # exist at the next level)
      self.rootMapBIP32 = [{}, {}, {}]

      # If there are other roots (such as old Armory wallets, or JBOK wlts,
      # etc) we will need to track them using other roots.  In the case of
      # old Armory wallets, the original index=-1 address will be included
      # in this map.  For importing old Bitcoin-Qt wallets, we will create 
      # a root with a random ID to hold "just a bunch of keys" (JBOK).
      self.rootMapOther = {}

      # Any lockboxes that are maintained in this wallet file
      # Indexed by p2sh-scrAddr
      self.lockboxMap = {}

      # List of all master encryption keys in this wallet (and also the 
      # data needed to understand how to decrypt them, probably by KDF)
      self.ekeyMap = {}

      # List of all KDF objects -- probably created based on testing the 
      # system speed when the wallet was created
      self.kdfMap  = {}

      # Master address list of all wallets/roots/chains that could receive BTC
      self.masterAddrMap  = {}

      # List of all encrypted wallet entries that couldn't be decrypted 
      # Perhaps later find a way decrypt and put them into the other maps
      self.opaqueList  = []

      # If != None, it means that this wallet holds only a subset of data 
      # in the parent file.  Probably just addr/tx comments and P2SH scripts
      self.masterWalletRef = None

      # Alternatively, if this is a master wallet it may have a supplemental
      # wallet for storing
      self.supplementalWltPath = None
      self.supplementalWltRef = None

      # Default encryption settings for "outer" encryption (if we want to
      # encrypt the entire WalletEntry, not just the private keys
      self.defaultOuterEncrypt = ArmoryCryptInfo(None)
      self.defaultInnerEncrypt = ArmoryCryptInfo(None)

      # This file may actually be used for a variety of wallet-related 
      # things -- such as transferring observer chains, exchanging linked-
      # wallet info, containing just comments/labels/P2SH script -- but 
      # not actually be used as a proper wallet.
      self.isTransferWallet = False
      self.isSupplemental = False


      # These flags are ONLY for unit-testing the atomic file operations
      self.interruptTest1  = False
      self.interruptTest2  = False
      self.interruptTest3  = False





   #############################################################################
   def createNewKDFObject(self, kdfAlgo, writeToFile=True, **kdfCreateArgs):
      """
      ROMixOv2 is ROMix-over-2 -- it's the ROMix algorithm as described by 
      Colin Percival, but using only 1/2 of the number of LUT ops, in order
      to bring down computation time in favor of more memory usage.

      If we had access to Scrypt, it could be an option here.  ROMix was 
      chosen due to simplicity despite its lack of flexibility
      """
      LOGINFO('Creating new %s KDF with the following parameters:' % kdfAlgo)
      for key,val in kdfCreateArgs.iteritems():
         LOGINFO('   %s: %s' % (key, str([val]))
         
      newKDF = KdfObject.createNewKDF(kdfAlgo, **kdfCreateArgs)
      self.kdfMap[newKDF.getKdfID()] = newKDF

      if writeToFile:
         self.doFileOperation('Append', newWE)


   
         
   #############################################################################
   def changePrivateKeyEncryption(self, encryptInfoObj):
      raise NotImplementedError

   #############################################################################
   def changeOuterEncryption(self, encryptInfoObj):
      raise NotImplementedError

   #############################################################################
   def findAllEntriesUsingObject(self, objID):
      """
      Use this to identify whether certain objects, such as KDF objects, are 
      no longer being used and can be removed (or for some other reason)
      """
      raise NotImplementedError

   #############################################################################
   def hasKDF(self, kdfID):
      return self.kdfMap.has_key(kdfID)

   #############################################################################
   def hasCryptoKey(self, ekeyID):
      return self.ekeyMap.has_key(ekeyID)

   #############################################################################
   def mergeWalletFile(self, wltOther, rootsToAbsorb='ALL'):
      """
      Just like in git, WltA.mergeWalletFile(WltB) means we want to pull all 
      the keys from WltB into WltA and leave WltB untouched.
      """

      if isinstance(wltOther, basestring):
         # Open wallet file
         if not os.path.exists(wltOther):
            LOGERROR('Wallet to merge does not exist: %s', filepath)
            raise WalletExistsError
         wltOther = ArmoryWalletFile.readWalletFile(filepath)


      rootRefList = []

      #
      for level in range(3):
         rootMap = wltOther.rootMap[level]
         for rootID,root in rootMap.iteritems():
            if rootsToAbsorb=='ALL' or rootID in rootsToAbsorb:
               rootRefList.append(rootID, root)



      # We need to not only copy over all addr and sub-roots, but
      # also all KDF objects and any other things in the file that ref
      # this root/addr (also any relationship objects and any roots
      # related to that, as well)
      i = 0
      procRootAlready = set([])
      while i<len(rootRefList):
         rootID,root = rootRefList[i]
         if rootID in procRootAlready:
            continue

         procRootAlready.add(rootID)

         
         addFileOperationToQueue

         if root.relationship.isMultiSig:
            # Make sure to merge the sibling wallets, too
            for sib in root.relationship.siblingList:
               if not sib.rootID in rootRefList:
                  LOGINFO('Adding sibling to root-merge list')
               rootRefList.add(sib.rootID)




   #############################################################################
   def mergeRootFromWallet(self, filepath, rootID, weTypesToMerge=['ALL']):
      # Open wallet file
      if not os.path.exists(filepath):
         LOGERROR('Wallet to merge does not exist: %s', filepath)

      with open(filepath, 'rb') as f:
         bu = BinaryUnpacker(f.read())

      while not bu.isEndOfStream():
         weObj = readWalletEntry(bu)
         if weObj.payload.root160:
            raise 'Notimplemented'   
         if weTypesToMerge[0].lower()=='all' or weObj.entryCode in weTypesToMerge:
            self.addFileOperationToQueue('Append', weObj)
      

   #############################################################################
   def loadExternalInfoWallet(self, filepath):
      """
      After this wallet is loaded, we may want to merge, in RAM only, another
      wallet file containing only P2SH scripts and comments.  The reason for
      this is that our root private key only needs to be backed up once, but 
      P2SH scripts MUST be backed up regularly (and comment fields would be 
      nice to have backed up, too).  The problem is, you don't want to put 
      your whole wallet file into dropbox, encrypted or not.  The solution is
      to have a separate P2SH&Comments file (a wallet without any addresses)
      which can be put in Dropbox.  And encrypt that file with information
      in the wathcing-only wallet -- something that you have even without 
      unlocking your wallet, but an attacker does not if they compromise your
      Dropbox account.
      """

      if not exists(filepath):
         LOGERROR('External info file does not exist!  %s' % filepath)

      self.externalInfoWallet =  PyBtcWallet().readWalletFile(filepath)


   #############################################################################
   def readWalletEntry(self, toUnpack):
      we = WalletEntry().unserialize(toUnpack)


         
        

   #############################################################################
   def doFileOperation(self, operationType, theData, loc=None):
      if not len(self.updateQueue)==0:
         LOGERROR('Wallet update queue not empty!  Applying previously')
         LOGERROR('queued operations before executing this update.')

      self.addFileOperationToQueue(operationType, theData, loc)
      self.applyUpdates()
          

   #############################################################################
   def addFileOperationToQueue(self, operationType, theData, fileLoc=None):
      """
      This will add lower-level data to the queue to be applied in a
      batch operation.  Two ways to do direct, low-level operations, 
      a shortcut method for operating with WalletEntry objects.

         (opType, theData) ~ ('Append',      'Some data to append')
         (opType, theData) ~ ('Modify',      'Overwrite beginning of file', 0)
         (opType, theData) ~ ('Modify',      'Overwrite something else', N)
         (opType, theData) ~ ('AddEntry',    WalletEntryObj)
         (opType, theData) ~ ('UpdateEntry', WalletEntryObj)
         (opType, theData) ~ ('DeleteEntry', WalletEntryObj)
         (opType, theData) ~ ('DeleteEntry', WalletEntryStartByte)

      If one of the "entry" versions is used, it will simply pull the
      necessary information out of the object and do an "Append' or "Modify'
      as necessary.
      """
         
      
      isWltEntryObj = isinstance(theData, WalletEntry)

      # The data to eventually be added to the file, or overwrite previous data
      newData = None

      # Convert the "___Entry" commands into the lower-level Append/Modify cmds
      if operationType.lower()=='addentry':
         # Add a new wallet entry to this wallet file
         if not isWltEntryObj:
            LOGERROR('Must supply WalletEntry object to use "addEntry" cmd')
            raise BadInputError
         if data already in wallet:
            skip
         newData = theData.serialize()
         operationType = 'Append'
      elif operationType.lower()=='updateentry':
         # Update an existing entry -- delete and append if size changed
         if not isWltEntryObj:
            LOGERROR('Must supply WalletEntry object to use "updateEntry" cmd')
            raise BadInputError
         newData = theData.serialize()
         oldData = self.readWalletEntry(theData.wltStartByte).serialize()
         if len(newData)==len(oldData):
            fileLoc = theData.wltStartByte
            operationType = 'Modify'
         else:
            LOGINFO('WalletEntry replace != size (%s).  ', theData.entryCode)
            LOGINFO('Delete&Append')
            self.addFileOperationToQueue('DeleteEntry', theData.wltStartByte)
            operationType = 'Append'
      elif operationType.lower()=='deleteentry':
         # Delete an entry from the wallet
         fileLoc = theData.wltStartByte if isWltEntryObj else theData
         if not isinstance(theData, (int,long)):
            LOGERROR('Delete entry only using WltEntry object or start byte')
            return

         oldData = self.readWalletEntry(fileLoc).serialize()
         totalBytes = len(oldData)
         # TODO figure out how to set up the deleted entry
         delBytes = oldData.getPayloadSize(padding=True)
         newData = ZeroData(delBytes).serialize()
         operationType = 'Modify'
            
         if isWltEntryObj:
            LOGERROR('TODO: figure out what I want to do with deleted WltEntry')
            theData.wltStartByte = -1

      else:
         if not isinstance(theData, basestring):
            LOGERROR('Can only add/update wallet data with string or unicode type!')
            return

         newData = theData[:]

      #####
      # This is where it actually gets added to the queue.
      if operationType.lower()=='append':
         if isWltEntryObj:
            theData.wltStartByte =  self.lastFilesize
         self.lastFilesize += len(newData)
         self.updateQueue.append([WLT_UPDATE_ADD, newData])
   
      elif operationType.lower()=='modify':
         if not fileLoc:
            LOGERROR('Must supply start byte of modification')
            raise BadInputError
         self.updateQueue.append([WLT_UPDATE_MODIFY, [newData, fileLoc]])

      #####
      # Tell the WalletEntry object when to expect its internal state to be 
      # consistent with the wallet file
      if isWltEntryObj:
         theData.syncWhenUpdateCount = self.updateCount + 1
         
         

   #############################################################################
   def getWalletPath(self, nameSuffix=None):
      fpath = self.walletPath

      if self.walletPath=='':
         fpath = os.path.join(ARMORY_HOME_DIR, 'armory_wallet_%s.bin' % self.uniqueIDB58)

      if nameSuffix:
         name,ext = os.path.splitext(fpath)
         joiner = '' if name.endswith('_') else '_'
         fpath = name + joiner + nameSuffix + ext
      return fpath


   #############################################################################
   def applyUpdates(self):
            
      """
      When we want to add data to the wallet file, we will do so in a completely
      recoverable way.  We define this method to make sure a backup exists when
      we start modifying the file, and keep a flag to identify when the wallet
      might be corrupt.  If we ever try to load the wallet file and see another
      file with the _update_unsuccessful suffix, we should instead just restore
      from backup.

      Similarly, we have to update the backup file after updating the main file
      so we will use a similar technique with the backup_unsuccessful suffix.
      We don't want to rely on a backup if somehow *the backup* got corrupted
      and the original file is fine.  THEREFORE -- this is implemented in such
      a way that the user should know two things:

         (1) No matter when the power goes out, we ALWAYS have a uncorrupted
             wallet file, and know which one it is.  Either the backup is safe,
             or the original is safe.  Based on the flag files, we know which
             one is guaranteed to be not corrupted.
         (2) ALWAYS DO YOUR FILE OPERATIONS BEFORE SETTING DATA IN MEMORY
             You must write it to disk FIRST using this SafeUpdate method,
             THEN give the new data to the user -- never give it to them
             until you are sure that it was written safely to disk.

      Number (2) is easy to screw up because you plan to write the file just
      AFTER the data is created and stored in local memory.  But an error
      might be thrown halfway which is handled higher up, and instead the data
      never made it to file.  Then there is a risk that the user uses their
      new address that never made it into the wallet file.
      """

      if not os.path.exists(self.walletPath):
         raise FileExistsError, 'No wallet file exists to be updated!'

      if len(updateList)==0:
         return False

      # Make sure that the primary and backup files are synced before update
      self.doWalletFileConsistencyCheck()

      # Split the queue into updates and modifications.  
      toAppend = []
      toModify = []
      for modType,rawData in updateList:
         if(modType==WLT_UPDATE_ADD):
            toAppend.append(rawData)
         elif(modType==WLT_UPDATE_MODIFY):
            toModify.append(rawData)

      # We need to safely modify both the main wallet file and backup
      # Start with main wallet
      touchFile(self.walletPathUpdFail)

      try:
         wltfile = open(self.walletPath, 'ab')
         wltfile.write(''.join(toAppend))
         wltfile.close()

         # This is for unit-testing the atomic-wallet-file-update robustness
         if self.interruptTest1: raise InterruptTestError

         wltfile = open(self.walletPath, 'r+b')
         for loc,replStr in toModify:
            wltfile.seek(loc)
            wltfile.write(replStr)
         wltfile.close()

      except IOError:
         LOGEXCEPT('Could not write data to wallet.  Permissions?')
         shutil.copy(self.walletPathBackup, self.walletPath)
         os.remove(self.walletPathUpdFail)
         return False

      # Write backup flag before removing main-update flag.  If we see
      # both flags, we know file IO was interrupted RIGHT HERE
      touchFile(self.walletPathBakFail)

      # This is for unit-testing the atomic-wallet-file-update robustness
      if self.interruptTest2: raise InterruptTestError

      os.remove(self.walletPathUpdFail)

      # Modify backup
      try:
         # This is for unit-testing the atomic-wallet-file-update robustness
         if self.interruptTest3: raise InterruptTestError

         backupfile = open(self.walletPathBackup, 'ab')
         backupfile.write(''.join(toAppend))
         backupfile.close()

         backupfile = open(self.walletPathBackup, 'r+b')
         for loc,replStr in toModify:
            backupfile.seek(loc)
            backupfile.write(replStr)
         backupfile.close()

      except IOError:
         LOGEXCEPT('Could not write backup wallet.  Permissions?')
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathUpdFail)
         return False

      os.remove(self.walletPathBakFail)
      self.updateCount += 1
      self.updateQueue = []

      return True



   #############################################################################
   def doWalletFileConsistencyCheck(self):
      """
      First we check the file-update flags (files we touched/removed during
      file modification operations), and then restore the primary wallet file
      and backup file to the exact same state -- we know that at least one of
      them is guaranteed to not be corrupt, and we know based on the flags
      which one that is -- so we execute the appropriate copy operation.

      ***NOTE:  For now, the remaining steps are untested and unused!

      After we have guaranteed that main wallet and backup wallet are the
      same, we want to do a check that the data is consistent.  We do this
      by simply reading in the key-data from the wallet, unserializing it
      and reserializing it to see if it matches -- this works due to the
      way the PyBtcAddress::unserialize() method works:  it verifies the
      checksums in the address data, and corrects errors automatically!
      And it's part of the unit-tests that serialize/unserialize round-trip
      is guaranteed to match for all address types if there's no byte errors.

      If an error is detected, we do a safe-file-modify operation to re-write
      the corrected information to the wallet file, in-place.  We DO NOT
      check comment fields, since they do not have checksums, and are not
      critical to protect against byte errors.
      """

      if not os.path.exists(self.walletPath):
         raise FileExistsError, 'No wallet file exists to be checked!'

      if not os.path.exists(self.walletPathBackup):
         # We haven't even created a backup file, yet
         LOGDEBUG('Creating backup file %s', self.walletPathBackup)
         touchFile(self.walletPathBakFail)
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathBakFail)
         return

      if os.path.exists(self.walletPathBakFail) and os.path.exists(self.walletPathUpdFail):
         # Here we actually have a good main file, but backup never succeeded
         LOGWARN('***WARNING: error in backup file... how did that happen?')
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathUpdFail)
         os.remove(self.walletPathBakFail)
      elif os.path.exists(self.walletPathUpdFail):
         LOGWARN('***WARNING: last file operation failed!  Restoring wallet from backup')
         # main wallet file might be corrupt, copy from backup
         shutil.copy(self.walletPathBackup, self.walletPath)
         os.remove(self.walletPathUpdFail)
      elif os.path.exists(self.walletPathBakFail):
         LOGWARN('***WARNING: creation of backup was interrupted -- fixing')
         shutil.copy(self.walletPath, self.walletPathBackup)
         os.remove(self.walletPathBakFail)


   #############################################################################
   def createAndAddNewMasterSeed(self, withEncryption=True, \
                                         nonDefaultEncrInfo=None):
      if withEncryption and self.isLocked():
         LOGERROR('Trying to add new encrypted root to wallet while locked')
         raise EncryptionError

      

      
   #############################################################################
   def addPregeneratedMasterSeed(self, plainSeed=None, encrSeed=None):


   #############################################################################
   def addPregeneratedMasterRoot(self, plainSeed=None, encrSeed=None):


   #############################################################################
   def createNewLinkedWallet(self, typeStr, withEncrypt,):

   #############################################################################
   def readWalletFile(self, filename):

   #############################################################################
   def writeFreshWalletFile(self, path, newName='', newDescr=''):



   #############################################################################
   # 
   def CreateNewWalletFile(self, 
                           createNewRoot=True, \
                           securePassphrase=None, \
                           kdfTargSec=DEFAULT_COMPUTE_TIME_TARGET, \
                           kdfMaxMem=DEFAULT_MAXMEM_LIMIT, \
                           defaultInnerEncrypt=None, \
                           defaultOuterEncrypt=None, \
                           doRegisterWithBDM=True, \
                           ):
                             #newWalletFilePath=None, \
                             #plainRootKey=None, \
                             ##withEncrypt=True, securePassphrase=None, \
                             #kdfTargSec=DEFAULT_COMPUTE_TIME_TARGET, \
                             #kdfMaxMem=DEFAULT_MAXMEM_LIMIT, \
                             #shortLabel='', longLabel='', isActuallyNew=True, \
                             #doRegisterWithBDM=True):
      raise NotImplementedError
      """

      We skip the atomic file operations since we don't even have
      a wallet file yet to safely update.

      DO NOT CALL THIS FROM BDM METHOD.  IT MAY DEADLOCK.
      """

      
      if self.calledFromBDM:
         LOGERROR('Called createNewWallet() from BDM method!')
         LOGERROR('Don\'t do this!')
         return None

      LOGINFO('***Creating new deterministic wallet')

      #####
      # Create a new KDF -- we need one for just about every wallet, regardless
      # of whether we are using encryption (yet).  The new KDF will be stored
      # with the wallet, and used by default whenever we want to encrypt 
      # something
      LOGDEBUG('Creating new KDF object')
      newKDF = KdfObject().createNewKDF('ROMixOv2', kdfTargSec, kdfMaxMem)
      self.kdfMap[newKDF.getKdfID()] = newKDF

      #####
      # If a secure passphrase was supplied, create a new master encryption key
      LOGDEBUG('Creating new master encryption key')
      if not securePassphrase is None:
         securePassphrase = SecureBinaryData(securePassphrase)
         newEKey = EncryptionKey().CreateNewMasterKey(newKDF, \
                                                   'AE256CFB', \
                                                   securePassphrase)
         self.ekeyMap[newEKey.getEncryptionKeyID()] = newEKey

      #####
      # If requested (usually is), create new master seed and the first wlt
      LOGDEBUG('Creating new master root seed & node')
      if createNewRoot:
         newRoot = ArmoryRoot().CreateNewMasterRoot()
      



      # Create the root address object
      rootAddr = PyBtcAddress().createFromPlainKeyData( \
                                             plainRootKey, \
                                             IV16=IV, \
                                             willBeEncr=withEncrypt, \
                                             generateIVIfNecessary=True)
      rootAddr.markAsRootAddr(chaincode)

      # This does nothing if no encryption
      rootAddr.lock(self.kdfKey)
      rootAddr.unlock(self.kdfKey)

      firstAddr = rootAddr.extendAddressChain(self.kdfKey)
      first160  = firstAddr.getAddr160()

      # Update wallet object with the new data
      self.useEncryption = withEncrypt
      self.addrMap['ROOT'] = rootAddr
      self.addrMap[firstAddr.getAddr160()] = firstAddr
      self.uniqueIDBin = (ADDRBYTE + firstAddr.getAddr160()[:5])[::-1]
      self.uniqueIDB58 = binary_to_base58(self.uniqueIDBin)
      self.labelName  = shortLabel[:32]
      self.labelDescr  = longLabel[:256]
      self.lastComputedChainAddr160 = first160
      self.lastComputedChainIndex  = firstAddr.chainIndex
      self.highestUsedChainIndex   = firstAddr.chainIndex-1
      self.wltCreateDate = long(RightNow())
      self.linearAddr160List = [first160]
      self.chainIndexMap[firstAddr.chainIndex] = first160

      # We don't have to worry about atomic file operations when
      # creating the wallet: so we just do it naively here.
      self.walletPath = newWalletFilePath
      if not newWalletFilePath:
         shortName = self.labelName .replace(' ','_')
         # This was really only needed when we were putting name in filename
         #for c in ',?;:\'"?/\\=+-|[]{}<>':
            #shortName = shortName.replace(c,'_')
         newName = 'armory_%s_.wallet' % self.uniqueIDB58
         self.walletPath = os.path.join(ARMORY_HOME_DIR, newName)

      LOGINFO('   New wallet will be written to: %s', self.walletPath)
      newfile = open(self.walletPath, 'wb')
      fileData = BinaryPacker()

      # packHeader method writes KDF params and root address
      headerBytes = self.packHeader(fileData)

      # We make sure we have byte locations of the two addresses, to start
      self.addrMap[first160].walletByteLoc = headerBytes + 21

      fileData.put(BINARY_CHUNK, '\x00' + first160 + firstAddr.serialize())


      # Store the current localtime and blocknumber.  Block number is always 
      # accurate if available, but time may not be exactly right.  Whenever 
      # basing anything on time, please assume that it is up to one day off!
      time0,blk0 = getCurrTimeAndBlock() if isActuallyNew else (0,0)

      # Don't forget to sync the C++ wallet object
      self.cppWallet = Cpp.BtcWallet()
      self.cppWallet.addAddress_5_(rootAddr.getAddr160(), time0,blk0,time0,blk0)
      self.cppWallet.addAddress_5_(first160,              time0,blk0,time0,blk0)

      # We might be holding the wallet temporarily and not ready to register it
      if doRegisterWithBDM:
         TheBDM.registerWallet(self.cppWallet, isFresh=isActuallyNew) # new wallet


      newfile.write(fileData.getBinaryString())
      newfile.close()

      walletFileBackup = self.getWalletPath('backup')
      shutil.copy(self.walletPath, walletFileBackup)

      # Lock/unlock to make sure encrypted keys are computed and written to file
      if self.useEncryption:
         self.unlock(secureKdfOutput=self.kdfKey)

      # Let's fill the address pool while we are unlocked
      # It will get a lot more expensive if we do it on the next unlock
      if doRegisterWithBDM:
         self.fillAddressPool(self.addrPoolSize, isActuallyNew=isActuallyNew)

      if self.useEncryption:
         self.lock()


      SERIALIZEEVERYTHINGINTO THE FILE
      self.writeFreshWalletFile(filepath)
      return self






#############################################################################
#############################################################################
class ZeroData(object):
   """
   Creates a chunk of zeros of size nBytes.  But to ensure it can be 
   unserialized without knowing its size, we put it's VAR_INT size 
   up front, and then write nBytes of zeros minus the VAR_INT size.
   """
   def __init__(self, nBytes=0):
      self.nBytes = nBytes


   def serialize(self):
      if self.nBytes==0:
         raise UninitializedError

      viSize = packVarInt(self.nBytes)[1]
      bp = BinaryPacker()
      bp.put(VAR_INT, self.nBytes)
      bp.put(BINARY_CHUNK, '\x00'*(self.nBytes - viSize))
      return bp.getBinaryString()

   
   def unserialize(self, zeroStr):
      bu = makeBinaryUnpacker(zeroStr)

      # We do the before/after thing in case a non-canonical VAR_INT was
      # used.  Such as using a 4-byte VAR_INT to represent what only need
      # a 2-byte VAR_INT
      beforeVI = bu.getPosition()
      nb = bu.get(VAR_INT)
      afterVI = bu.getPosition()
      viSize = afterVI - beforeVI
      zstr = bu.get(BINARY_CHUNK, nb - viSize)

      if not zstr=='\x00'*(nb-viSize):
         LOGERROR('Expected all zero bytes, but got something else')
      
      self.__init__(nb)
      return self
      


   


#############################################################################
#############################################################################
class RootRelationship(object):
   """
   A simple structure for storing the fingerprints of all the siblings of 
   multi-sig wallet.  Each wallet chain that is part of this multi-sig 
   should store a multi-sig flag and the ID of this object.    If a chain
   has RRID zero but the multi-sig flag is on, it means that it was
   generated to be part of a multi-sig but not all siblings have been 
   acquired yet.

   This object can be transferred between wallets and will be ignored if
   none of the chains in the wallet use it.  Or transferred with all the
   public chains to fully communicate a watching-only version of the 
   multi-sig.  
   """
   def __init__(self, M=None, N=None, siblingList=None, labels=None):
      self.M = M if M else 0
      self.N = N if N else 0
      self.relID     = NULLSTR(8)
      self.randID    = SecureBinaryData().GenerateRandom(8)
      self.siblings  = []
      self.sibLabels = []


      if siblingList is None:
         siblingList = []

      if labels is None:
         labels = []

      if len(siblingList) > 15:
         LOGERROR('Cannot have more than 15 wallets in multisig!')
         return

      self.siblings  = siblingList[:]
      self.sibLabels = labels[:]

      for sib in self.siblings:
         if not len(sib)==20:
            LOGERROR('All siblings must be specified by 20-byte hash160 values')
            return


   def computeRelID(self):
      self.relID = binary_to_base58(hash256(self.serialize()))[:8]
      return self.relID

      

   def addSibling(sibRootID, label):
      if len(self.siblings) >= self.N:
         raise BadInputError('RR already has %d siblings' % self.N)

      self.siblings.append(sibRootID)
      self.labels.append(label)

      if len(self.siblings) == self.N:
      self.siblings.sort()
          


   def serialize(self):
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK, self.relID, widthBytes=8)
      bp.put(BINARY_CHUNK, self.randID, widthBytes=8)
      bp.put(UINT8, self.M)
      bp.put(UINT8, self.N)
      bp.put(UINT8, len(self.siblings))
      for i in range(len(self.siblings)):
         bp.put(VAR_STR, self.siblings[i])
         bp.put(VAR_STR, self.labels[i])

      return bp.getBinaryString()


   def unserialize(self, theStr):
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
         lblList.append(bu.get(VAR_STR))

      self.__init__(M, N, sibList, lblList)
      return self


      



#############################################################################
class ArmoryAddress(WalletEntry):

   def __init__(self):
      pass


PRIV_KEY_AVAIL = enum('None', 'Plain', 'Encrypted', 'NextUnlock')
AEKTYPE = enum('Uninitialized', 'BIP32', 'ARMORY135', 'JBOK')



################################################################################
################################################################################
class ArmoryExtendedKey(WalletEntry):
   def __init__(self):
      self.isWatchOnly     = False
      self.privCryptInfo   = ArmoryCryptInfo(None)
      self.sbdPrivKeyPlain = NULLSBD()
      self.sbdPrivKeyCrypt = NULLSBD()
      self.sbdPublicKey33  = NULLSBD()
      self.sbdChaincode    = NULLSBD()
      self.aekParent       = None
      self.derivePath      = []
      self.useUncompressed = False
      self.aekType         = AEKTYPE.Uninitialized
      self.keyLifetime     = 10
      self.relockAtTime    = 0

      self.walletFileRef   = None  # ref to the ArmoryWalletFile for this key

   #############################################################################
   def createFromEncryptedKeyData(self, 
                                  privCrypt=None, sbdPub=None, sbdChain=None,    
                        privCryptInfo=None, parentID=None, parentRef=None,
                        derivePath=None, wltRef=None):
      
      privCrypt = NULLSBD()
      privPlain = NULLSBD()

      try:
         if privCryptInfo is None or privCryptInfo.noEncryption:
            plainPriv = sbdPriv.copy()
         else:
            self.
         
         if sbdPriv and not sbdPub:
            sbdPub = CryptoECDSA().ComputePublicKey(sbdPriv)
      
      
      finally:
         plainPriv.destroy()

      
      

      


   #############################################################################
   def getPrivKeyAvailability(self):
      if self.isWatchOnly:
         return PRIV_KEY_AVAIL.None
      elif self.sbdPrivKeyPlain.getSize() > 0:
         return PRIV_KEY_AVAIL.Plain
      elif self.sbdPrivKeyCrypt.getSize() > 0:
         return PRIV_KEY_AVAIL.Encrypted
      else:
         return PRIV_KEY_AVAIL.NextUnlock


   #############################################################################
   def useEncryption(self):
      return self.privCryptInfo.useEncryption()
         

   #############################################################################
   def getSerializedPubKey(self, serType='hex'):
      """
      The various public key serializations:  "hex", "xpub"
      """
      if useUncompressed:
         pub = CryptoECDSA().UncompressPoint(self.sbdPublicKey33).copy()
      else:
         pub = self.sbdPublicKey33.copy()
         
      if serType.lower()=='hex':
         return pub.toHexStr()

      elif serType.lower()=='xpub':
         raise NotImplementedError('Encoding not implemented yet')
         
   #############################################################################
   def getSerializedPrivKey(self, serType='hex'):
      """
      The various private key serializations: "hex", "sipa", "xprv"
      """

      if self.useEncryption() and self.isLocked():
         raise WalletLockError('Cannot serialize locked priv key')

      lastByte = '' if self.useUncompressed else '\x01'
      binPriv = self.sbdPrivKeyPlain.toBinStr() + lastByte
         
      if serType.lower()=='hex':
         return binary_to_hex(hexPriv)
      elif serType.lower()=='sipa':
         binSipa '\x80' + binPriv + computeChecksum('\x80' + binPriv)
         return binary_to_hex(binSipa)
      elif serType.lower()=='xprv':
         raise NotImplementedError('xprv encoding not yet implemented')


   #############################################################################
   def getPrivateKeyPlain(self, ekeyObj):
      """
      NOTE:  This returns an SBD object which needs to be .destroy()ed by
             the caller when it is finished with it.
      """
      if self.ekeyObj.isLocked():
         raise KeyDataError('Master ekey must be unlocked to fetch priv key')

      
      

   #############################################################################
   def lock(self):
      if self.sbdPrivKeyCrypt.getSize()==0:
         raise KeyDataError('No encrypted form of priv key available')

   #############################################################################
   def unlock(self, ekeyObj, keyData, justVerify=False):
      if self.sbdPrivKeyPlain.getSize() > 0:
         # Already unlocked, just extend the lifetime in RAM
         if not justVerify:
            self.relockAtTime = RightNow() + self.keyLifetime
         return


      keyType,keyID = self.privCryptInfo.getEncryptKeySrc()
      if keyType == CRYPT_KEY_SRC.EKEY_OBJ:
         if ekeyObj is None:
            raise KeyDataError('Need ekey obj to unlock, but is None')

         if not keyID == ekeyObj.getEkeyID():
            raise KeyDataError('Incorrect ekey to unlock address')
               
               
      self.sbdPrivKeyPlain = \
            self.privCryptInfo.decrypt(self.sbdPrivKeyCrypt, 
                                       keyData,
                                       self.sbdPublicKey33.getHash256()[:16], 
                                       ekeyObj)
      if justVerify:
         self.sbdPrivKeyPlain.destroy()
      else:
         self.relockAtTime = RightNow() + self.keyLifetime


   #############################################################################
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
      if self.useEncryption() and self.isLocked():
         raise WalletLockError('Cannot sign with locked priv key')
      
      try:
         self.unlock()

         if deterministicSig:
            raise NotImplementedError('Cannot do deterministic signing yet')
            sig = CryptoECDSA().SignData_RFC6979(dataToSign, self.sbdPrivKeyPlain)
         else:
            sig = CryptoECDSA().SignData(dataToSign, self.binPrivKey32_Plain)

         sigstr = sig.toBinStr()

         rBin = sigstr[:32 ]
         sBin = sigstr[ 32:]

         if not normSig=='Dontcare':
            # normSig will either be 'even' or 'odd'.  If the calculated
            # s-value does not match, then use -s mod N which will be 
            # correct
            raise NotImplementedError('This code is not yet tested!')
            sInt = binary_to_int(sBin, BIGENDIAN)
            if (normSig=='even' and sInt%2==1) or \
               (normSig=='odd'  and sInt%2==0):
               sInt = (-sInt) % SECP256K1_MOD
               
            sBin = int_to_binary(sInt, widthBytes=32, endOut=BIGENDIAN)

         return (rBin, sBin)

      except:
         LOGEXCEPT('Error generating signature')
      finally:
         self.sbdPrivKeyPlain.destroy()
      

   #############################################################################
   def signTransaction(self, serializedTx, deterministicSig=False):
      rBin,sBin = self.__signData(serializedTx, deterministicSig)
      return createSigScriptFromRS(rBin, sBin)

      
   #############################################################################
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
      raise NotImplementedError('Currently this function is not tested')
      msgPrefix = 'Bitcoin Signed Message:\n'
      bp = BinaryPacker()
      bp.put(VAR_INT,  len(msgPrefix))
      bp.put(BINARY_CHUNK, msgPrefix)
      bp.put(VAR_INT,  len(msg))
      bp.put(BINARY_CHUNK, msg)
      msgToSign = hash256(bp.getBinaryString())
      return self.__signData(msgToSign, deterministicSig)



################################################################################
class AddressLabel(WalletEntry):
  
   FILECODE = 'LABL' 

   def __init__(self, label=''):
      self.set(label)

   def set(self, lbl):
      self.label = toUnicode(lbl)

   def serialize(self):
      bp = BinaryPacker()
      bp.put(VAR_UNICODE, self.label)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      self.label = bu.get(VAR_UNICODE)
      return self.label


################################################################################
class TxComment(WalletEntry):

   FILECODE = 'COMM'

   def __init__(self, comm=''):
      self.set(comm)

   def set(self, comm):
      self.comm = toUnicode(comm)

   def serialize(self):
      bp = BinaryPacker()
      bp.put(VAR_UNICODE, self.comm)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      self.comm = bu.get(VAR_UNICODE)
      return self


################################################################################
################################################################################
class ArmoryFileHeader(WalletEntry):
  
   FILECODE = 'HEAD' 

   #############################################################################
   def __init__(self):
      # Note, we use a different fileID than wallet 1.35 so that older versions
      # of Armory don't attempt to load the 2.0 wallets
      LOGDEBUG('Creating file header')
      self.fileID        = '\xa0ARMORY\x0a'
      self.armoryVer     = getVersionInt(ARMORY_WALLET_VERSION)
      self.flags         = BitSet(64)
      self.createTime    = UINT64_MAX
      #self.wltName       = u''
      #self.wltDescr      = u''
      #self.wltID         = ''

      # Identifies whether this file is simply
      self.isTransferWallet = False
      self.isSupplemental = False

   #############################################################################
   def serialize(self):
      name  = truncUnicode(self.wltName,  32 )
      descr = truncUnicode(self.wltDescr, 256)
      
      bp = BinaryPacker()
      bp.put(BINARY_CHUNK,    self.fileID,           widthBytes=  8)
      bp.put(UINT32,          self.armoryVer)       #widthBytes=  4
      bp.put(BINARY_CHUNK,    MAGIC_BYTES,           widthBytes=  4)
      bp.put(UINT64,          self.flags.toValue()) #widthBytes=  8
      bp.put(UINT64,          self.createTime)      #widthBytes = 8
      return bp.getBinaryString()

   #############################################################################
   def unserialize(self, theStr):
      toUnpack = makeBinaryUnpacker(theStr)
      self.fileID     = bp.get(BINARY_CHUNK, 8)
      self.armoryVer  = bp.get(UINT32)
      magicbytes      = bp.get(BINARY_CHUNK, 4)
      flagsInt        = bp.get(UINT64)
      self.createTime = bp.get(UINT64)

      if not magicbytes==MAGIC_BYTES:
         LOGERROR('This wallet is for the wrong network!')
         LOGERROR('   Wallet is for:  %s ', BLOCKCHAINS[magicbytes])
         LOGERROR('   You are on:     %s ', BLOCKCHAINS[MAGIC_BYTES])
         raise NetworkIDError
      
      self.flags = BitSet().fromValue(flagsInt, 64)
      self.wltName  = toUnicode(wltNameBin.rstrip('\x00'))
      self.wltDescr = toUnicode(wltDescrBin.rstrip('\x00'))
      return self





################################################################################
################################################################################
class Armory135ExtendedKey(ArmoryExtendedKey):

   EXTKEYTYPE = 'ARMRY135'

   #############################################################################
   def __init__(self, *args, **kwargs):
      super(Armory135ExtendedKey, self).__init__(*args, **kwargs)
      self.useUncompressed = True
      self.derivePath = None
      self.chainIndex = None




   #############################################################################
   def spawnChild(self, keyData=None, kdfObjID=None, ekeyObj=None, privSpawnReqd=False):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """

      TimerStart('spawnChild_135')
      startedLocked = False

      # If the child key corresponds to a "hardened" derivation, we require
      # the priv keys to be available, or sometimes we explicitly request it
      if privSpawnReqd:
         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.None:
            raise KeyDataError('Requires priv key, but this is a WO ext key')

         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted and \
            ekeyObj is None and \
            keyData is None)
            raise KeyDataError('Requires priv key, no way to decrypt it')
         

      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.NextUnlock:
         if self.aekParent is None:
            raise KeyDataError('No parent defined from which to derive this key')

         if self.childID is None:
            raise KeyDataError('No derivation path defined to derive this key')

         # Recurse up the chain to extend from the last-fully-derived priv key
         aek = self.aekParent.spawnChild(ekeyObj, keyData, privSpawnReqd)
            
         if not aek.sbdPublicKey33.toBinStr() == self.sbdPublicKey33.toBinStr():
            raise keyData('Derived key supposed to match this one but does not')
   
         self.sbdPrivKeyPlain = aek.sbdPrivKeyPlain.copy()
         self.sbdPrivKeyCrypt = aek.sbdPrivKeyCrypt.copy()
         startedLocked = True  # if needed to derive, it was effectively locked
                              
      # If the key is currently encrypted, going to need to unlock it
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted:
         unlockSuccess = self.unlock(ekeyObj, keyData)
         if not unlockSuccess:
            raise PassphraseError('Incorrect decryption data to spawn child')
         else:
            startedLocked = True  # will re-lock at the end of this operation


      sbdPubKey65 = CryptoECDSA().UncompressPoint(self.sbdPublicKey33)
      logMult1 = NULLSBD()
      logMult2 = NULLSBD()

      CECDSA = CryptoECDSA()
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Plain:
         extendFunc = CECDSA.ComputeChainedPrivateKey
         extendArgs = [self.sbdPrivKeyPlain, self.sbdChaincode, sbdPubKey65, logMult1]
         extendType = 'Private'
      elif self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.None
         extendFunc = CECDSA.ComputeChainedPublicKey
         extendArgs = [sbdPubKey65, self.sbdChaincode, logMult1]
         extendType = 'Public'
         
   
         sbdNewKey1 = extendFunc(*extendArgs)
         sbdNewKey2 = extendFunc(*extendArgs)

         if sbdNewKey1.toBinStr() == sbdNewKey2.toBinStr():
            sbdNewKey2.destroy()
            with open(MULT_LOG_FILE,'a') as f:
               f.write('%s chain (pkh, mult): %s,%s\n' % (extendType, logMult1.toHexStr()))
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
               sbdNewKey2.destroy()
               sbdNewKey3.destroy()
               with open(MULT_LOG_FILE,'a') as f:
                  f.write('Computed chain (pkh, mult): %s,%s\n' % (a160hex,logMult1.toHexStr()))
            else:
               sbdNewKey1.destroy()
               sbdNewKey2.destroy()
               sbdNewKey3.destroy()
               # This should crash just about any process that would try to use it
               # without checking for empty private key. 
               raise KeyDataError('Chaining %s Key Failed!' % extendType)

      if extendType=='Private':
         sbdNewPriv  = sbdNewKey1.copy()
         sbdNewPub   = CryptoECDSA().ComputePublicKey(sbdNewPriv)
         sbdNewChain = self.sbdChaincode.copy()
      else:
         sbdNewPriv  = NULLSBD()
         sbdNewPub   = sbdNewKey1.copy()
         sbdNewChain = self.sbdChaincode.copy()

      childAddr = Armory135ExtendedKey(privKey=sbdNewPriv, 
                                       pubKey=sbdNewPub, 
                                       chain=sbdNewChain)
                                        
      childAddr.chainIndex = self.chainIndex + 1
      childAddr.aekParent      = self
      childAddr.aekParentID    = self.getExtKeyID()
      childAddr.privCryptInfo  = self.privCryptInfo
      childAddr.isInitialized  = True

      if startedLocked:
         childAddr.lock(ekeyObj, keyData)
         childAddr.unlock(ekeyObj, keyData)
         childAddr.lock(ekeyObj, keyData)

      return childAddr


################################################################################
################################################################################
class ArmoryBip32ExtendedKey(ArmoryExtendedKey):

   EXTKEYTYPE = 'ARMBIP32'
   def __init__(self, *args, **kwargs):
      super(ArmoryBip32ExtendedKey, self).__init__(*args, **kwargs)


   #############################################################################
   def spawnChild(self, childID, ekeyObj=None, keyData=None, privSpawnReqd=False):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """

      TimerStart('spawnChild')
      startedLocked = False

      if self.aekType==AEKTYPE.JBOK:
         # It's not that we can't do this -- just call SecureRandom(32).  
         # It's that we don't support JBOK wallets because they're terrible
         raise NotImplementedError('Cannot spawn from JBOK key.')
      
      # If the child key corresponds to a "hardened" derivation, we require
      # the priv keys to be available, or sometimes we explicitly request it
      if privSpawnReqd or (childID & 0x80000000 > 0):
         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.None:
            raise KeyDataError('Requires priv key, but this is a WO ext key')

         if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted and \
            ekeyObj is None and \
            keyData is None)
            raise KeyDataError('Requires priv key, no way to decrypt it')
         

      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.NextUnlock:
         if self.aekParent is None:
            raise KeyDataError('No parent defined from which to derive this key')

         if self.derivePath is None:
            raise KeyDataError('No derivation path defined to derive this key')

         # Recurse up the derivation path to derive the parent(s)
         if self.aekType == AEKTYPE.BIP32:
            if self.derivePath is None:
               raise KeyDataError('No derivation path defined to derive this key')
            aek = self.aekParent.spawnChild(self.derivePath[-1], ekeyObj, keyData)
         elif self.aekType == AEKTYPE.ARMORY135:
            aek = self.aekParent.spawnChild(0, ekeyObj, keyData)
            

         if not aek.sbdPublicKey33.toBinStr() == self.sbdPublicKey33.toBinStr():
            raise keyData('Derived key supposed to match this one but does not')
   
         self.sbdPrivKeyPlain = aek.sbdPrivKeyPlain.copy()
         self.sbdPrivKeyCrypt = aek.sbdPrivKeyCrypt.copy()
         startedLocked = True  # if needed to derive, it was effectively locked
                              
      # If the key is currently encrypted, going to need to unlock it
      if self.getPrivKeyAvailability()==PRIV_KEY_AVAIL.Encrypted:
         unlockSuccess = self.unlock(ekeyObj, keyData)
         if not unlockSuccess:
            raise PassphraseError('Incorrect decryption data to spawn child')
         else:
            startedLocked = True  # will re-lock at the end of this operation


         
      childAddr.childIdentifier
      extChild  = HDWalletCrypto().ChildKeyDeriv(self.getExtendedKey(), childID)

      # In all cases we compute a new public key and chaincode
      childAddr.binPubKey33  = extChild.getPub().copy()
      childAddr.binChaincode = extChild.getChain().copy()

      if privAvail==PRIV_KEY_AVAIL.Plain:
         # We are extending a chain using private key data (unencrypted)
         childAddr.binPrivKey32_Plain  = extChild.getPriv().copy()
         childAddr.needToDerivePrivKey = False
      elif privAvail==PRIV_KEY_AVAIL.NextUnlock:
         # Copy the parent's encrypted key data to child, set flag
         childAddr.binPrivKey32_Encr = self.binPrivKey32_Encr.copy()
         childAddr.binChaincode      = self.binChaincode.copy()
         childAddr.needToDerivePrivKey = True
      elif privAvail==PRIV_KEY_AVAIL.None:
         # Probably just extending a public key
         childAddr.binPrivKey32_Plain  = SecureBinaryData(0)
         childAddr.needToDerivePrivKey = False
      else:
         LOGERROR('How did we get here?  spawnchild:')
         LOGERROR('   privAvail == %s', privAvail)
         LOGERROR('   encrypt   == %s', self.useEncryption)
         LOGERROR('Bailing without spawning child')
         raise KeyDataError
   
      childAddr.parentHash160      = self.getHash160()
      childAddr.binAddr160         = self.binPubKey33or65.getHash160()
      childAddr.useEncryption      = self.useEncryption
      childAddr.isInitialized      = True
      childAddr.childIdentifier    = childID
      childAddr.hdwDepth           = self.hdwDepth+1
      childAddr.indexList          = self.indexList[:]
      childAddr.indexList.append(childID)

      if childAddr.useEncryption and not childAddr.needToDerivePrivKey:
         # We can't get here without a [valid] decryptKey 
         childAddr.lock(ekeyObj, keyData))
         if not startedLocked:
            childAddr.unlock(ekeyObj, keyData)
            self.unlock(ekeyObj, keyData)

      return ArmoryExtendedKey(
      return childAddr

   #############################################################################
   def getWalletLocator(self, encryptWithParentChain=True)
      """
      @encryptWithParentChain:

      The wallet locator information is really intended for the online
      computer to identify to an offline computer that certain public
      keys are a related to the wallet.  The problem is that the data
      passes by a lot of unrelated parties on the way and wallet locators
      with the same IDs or similar paths could leak privacy information.
      However, both online and offline computer have data that no one
      else should know: the chaincode.  So we simply put a unique 
      identifier up front, and then encrypt the thing using the chaincode
      of the parent/root as the AES256 key.  The offline computer will 
      attempt to decrypt all wallet locators strings with the chaincode,
      and if it succeeds, it will use the locator information as needed.
      If you are unrelated to the wallet, it will look like random data.

      One problem is that some devices may only have floating branches 
      of a BIP32 wallet, and wouldn't recognize the root.  In other cases
      we might have a system with thousands of wallets, and attempting 
      decryption with every chain code might be excessive.   So we 
      actually encrypt every sub-path:  i.e.

         encrypt_m_x("y/z/a") | encrypt_m_x_y("z/a") | encrrypt_m_x_y_z("a")

      The whole thing is the wallet locator, and if the wallet has no
      floating chains, it only needs to attempt decryption of the first
      16 bytes for each root (should be a small number).  

      P.S. - At the time of this writing this is a stub and I have no
             idea if this is what we want.
      """
   
      if encryptWithParentChain:
         self.



################################################################################
################################################################################
class ArmoryImportedKey(ArmoryExtendedKey):

   EXTKEYTYPE = 'IMPORTED'


# Root modes represent how we anticipate using this root.  An Armory root
# marked as BIP32_Root means it is the top of a BIP32 tree generated from a 
# seed value.  If it is marked as BIP32_Floating, it means it is a branch 
# of BIP32 tree for which we don't have the rootroot (maybe it's a piece 
# of a BIP32 tree belonging to someone else given to us to generate payment 
# addresses, or for a multisig wallet.  ARM135 is the old Armory wallet 
# algorithm that was used for the first 3 years of Armory's existence.  
# JBOK stands for "Just a bunch of keys" (like RAID-JBOD).  JBOK mode will
# most likely only be used for imported keys and old Bitcoin Core wallets.
ROOTTYPE = enum('BIP32_Root', 'BIP32_Floating', 'ARM135_Root', 'JBOK')

#############################################################################
class ArmoryRoot(ArmoryExtendedKey):
      
   FILECODE = 'ROOT'

   def __init__(self):
      super(ArmoryRoot, self).__init__()

      # General properties of this root object
      self.createDate = 0
      self.labelName   = ''
      self.labelDescr  = ''

      # Each root is a candidate for being displayed to the user, should 
      # have a Base58 ID
      self.uniqueIDBin = ''
      self.uniqueIDB58 = ''    # Base58 version of reversed-uniqueIDBin

      # If this root is intended to be used in multi-sig, it should be flagged
      # In some cases this root will be created with the intention to become
      # part of a multisig wallet.  In that case, multisig flag will be on,
      # but the relationshipID will be zeros.  Once a relationship is defined
      # and added to the wallet, this structure will be updated.
      self.isMultisig      = False
      self.relationshipID  = NULLSTR(8)

      # If this is a "normal" wallet, it is BIP32.  Other types of wallets 
      # (perhaps old Armory chains, will use different name to identify we
      # may do something different)
      self.rootType = ROOTTYPE.BIP32_Root

      # Extra data that needs to be encrypted, if 
      self.seedCryptInfo   = ArmoryCryptInfo(None)
      self.bip32seed_plain = SecureBinaryData(0)
      self.bip32seed_encr  = SecureBinaryData(0)
      self.bip32seed_size  = 0

      # This helps identify where in the BIP 32 tree this node is.
      self.rootID   = NULLSTR(8)
      self.parentID = NULLSTR(8)
      self.rootPath = []

      # FLAGS
      self.isPhoneRoot   = False # don't send from, unless emergency sweep
      self.isFakeRoot    = True  # This root has no key data.  Mainly for JBOK
      self.isSiblingRoot = False # observer root of a multi-sig wlt, don't use
      self.isDepositOnly = False # Only use to gen deposit addrs, bal is meaningless

      # In the event that some data type identifies this root as its parent AND
      # it identifies itself as critical AND we don't recognize it (such as if
      # you use a colored-coin variant of Armory and then later import the wlt
      # using vanilla Armory), this wallet should be identified as existent 
      # but unusable/disabled, to avoid doing something you shouldn't
      self.isDisabled = False

      # If the user decided to "remove" this wallet, then we simply mark it as
      # "removed" and don't display it or do anything with it.
      self.userRemoved = False

      
      # 
      self.wltFileRef = None


      """ # Old pybtcwallet stuff
      self.fileTypeStr    = '\xbaWALLET\x00'
      self.magicBytes     = MAGIC_BYTES
      self.version        = ARMORY_WALLET_VERSION  # (Major, Minor, Minor++, even-more-minor)
      self.eofByte        = 0
      self.cppWallet      = None   # Mirror of PyBtcWallet in C++ object
      self.cppInfo        = {}     # Extra info about each address to help sync
      self.watchingOnly   = False
      self.wltCreateDate  = 0

      # Three dictionaries hold all data
      self.addrMap     = {}  # maps 20-byte addresses to PyBtcAddress objects
      self.commentsMap = {}  # maps 20-byte addresses to user-created comments
      self.commentLocs = {}  # map comment keys to wallet file locations
      self.labelName   = ''
      self.labelDescr  = ''
      self.linearAddr160List = []
      self.chainIndexMap = {}
      if USE_TESTNET:
         self.addrPoolSize = 10  # this makes debugging so much easier!
      else:
         self.addrPoolSize = CLI_OPTIONS.keypool

      # For file sync features
      self.walletPath = ''
      self.doBlockchainSync = BLOCKCHAIN_READONLY
      self.lastSyncBlockNum = 0

      # Private key encryption details
      self.useEncryption  = False
      self.kdf            = None
      self.crypto         = None
      self.kdfKey         = None
      self.defaultKeyLifetime = 10    # seconds after unlock, that key is discarded
      self.lockWalletAtTime   = 0    # seconds after unlock, that key is discarded
      self.isLocked       = False
      self.testedComputeTime=None

      # Deterministic wallet, need a root key.  Though we can still import keys.
      # The unique ID contains the network byte (id[-1]) but is not intended to
      # resemble the address of the root key
      self.uniqueIDBin = ''
      self.uniqueIDB58 = ''   # Base58 version of reversed-uniqueIDBin
      self.lastComputedChainAddr160  = ''
      self.lastComputedChainIndex = 0
      self.highestUsedChainIndex  = 0 

      # All PyBtcAddress serializations are exact same size, figure it out now
      self.pybtcaddrSize = len(PyBtcAddress().serialize())


      # All BDM calls by default go on the multi-thread-queue.  But if the BDM
      # is the one calling the PyBtcWallet methods, it will deadlock if it uses
      # the queue.  Therefore, the BDM will set this flag before making any 
      # calls, which will tell PyBtcWallet to use __direct methods.
      self.calledFromBDM = False

      # Finally, a bunch of offsets that tell us where data is stored in the
      # file: this can be generated automatically on unpacking (meaning it
      # doesn't require manually updating offsets if I change the format), and
      # will save us a couple lines of code later, when we need to update things
      self.offsetWltFlags  = -1
      self.offsetLabelName = -1
      self.offsetLabelDescr  = -1
      self.offsetTopUsed   = -1
      self.offsetRootAddr  = -1
      self.offsetKdfParams = -1
      self.offsetCrypto    = -1
      """


   #############################################################################
   def CreateNewMasterRoot(self, typeStr='BIP32', cryptInfo=None, \
                                 kdfObj=None, ekeyObj=None, keyData=None, 
                                 seedBytes=20, extraEntropy=None):
      """
      The last few arguments identify how we plan to encrypt the seed and 
      master node information.  We plan to write this stuff to file right
      away, so we want to be able to encrypt it right away.  The cryptInfo
      object tells us how to encrypt it, and the ekeyObj, key and ivData
      objects are what is needed to encrypt the new seed and root immediately
      """


      if not typeStr=='BIP32':
         LOGERROR('Cannot create any roots other than BIP32 (yet)')
         raise NotImplementedError, 'Only BIP32 wallets allowed so far')

      self.walletType = typeStr
      self.wltVersion = ARMORY_WALLET_VERSION
      self.wltSource  = 'ARMORY'.ljust(12, '\x00')

      # Uses Crypto++ PRNG -- which is suitable for cryptographic purposes.
      # 16 bytes is generally considered enough, though we add 4 extra for 
      # some margin.  We also have the option to add some extra entropy 
      # through the last command line argument.  We use this in ArmoryQt
      # and armoryd by pulling key presses and volatile system files
      if extraEntropy is None:
         extraEntropy = NULLSBD() 

      self.bip32seed_plain  = SecureBinaryData().GenerateRandom(seedBytes, 
                                                                extraEntropy)

      LOGINFO('Computing extended key from seed')
      fullExtendedRoot = HDWalletCrypto().ConvertSeedToMasterKey(\
                                                   self.bip32seed_plain)
      
      self.binPrivKey32_Plain = fullExtendedRoot.getPriv()
      self.binPubKey33or65    = fullExtendedRoot.getPub()
      self.binAddr160         = fullExtendedRoot.getHash160().toBinStr()
      self.binChaincode       = fullExtendedRoot.getChain()
      

      # We have a 20-byte seed, but will need to be padded for 16-byte
      # blocksize if we ever need to encrypt it.
      self.bip32seed_size = self.bip32seed_plain.getSize()
      self.bip32seed_plain.padDataMod(cryptInfo.getBlockSize())
  

      # If no crypt info was designated, used default from this wallet file
      if cryptInfo is None:
         LOGINFO('No encryption requested, setting NULL encrypt objects')
         self.seedCryptInfo = ArmoryCryptInfo(None)
         self.bip32seed_encr = SecureBinaryData()
         self.binPrivKey32_Encr  = SecureBinaryData()
      else
         # Assume ivSource is CRYPT_IV_SRC.PUBKEY20[:16]
         self.privCryptInfo = cryptInfo.copy()
         self.seedCryptInfo = cryptInfo.copy()
         self.lock(  ekeyObj=ekeyObj, keyData=keyData)
         self.unlock(ekeyObj=ekeyObj, keyData=keyData)

            
      # FLAGS
      self.uniqueIDB58 = self.computeRootID()
      self.hdwChildID = -1
      self.hdwDepth = -1
      self.hdwIndexList = []
      self.lastComputedChainAddr160  = ''
      self.lastComputedChainIndex = 0
      self.highestUsedChainIndex  = 0 
      self.lastSyncBlockNum = 0
      self.isPhoneRoot = False  # don't send from, unless emergency sweep
      self.isSiblingRoot = False # observer root of a multi-sig wlt, don't use


   #############################################################################
   def getRootID(self, inBase58=True, nbytes=6):
      """ 
      We need some way to distinguish roots from one another, other than their
      20-byte hash.  Ideally, it will be distinct not only based on the Hash160
      value, but also based on the chaincode and chaining algorithm.  This way,
      if there are multiple variants/versions of code which are seeded with 
      the same data, but uses different algorithms, they will be distinguish-
      able.  It's also a good way to verify we are using the same algorithm as
      the code/app that originally produced this wallet.

      For this reason, if a wallet is labeled BIP32, we compute its child with
      index FFFFFFFF, take the first nbytes, and append the address byte to it
      (to identify the network, but put it in the back so that each root ID 
      has a different prefix character).
      """
      if not self.uniqueIDBin:
         endChild = self.spawnChild(0xFFFFFFFF)
         self.uniqueIDBin = endChild.getHash160()[:nbytes]+ADDRBYTE
         self.uniqueIDB58 = binary_to_base58(self.uniqueIDBin)

      return self.uniqueIDB58 if inBase58 else self.uniqueIDBin



   #############################################################################
   lkjlkfdsj
   def spawnChild(self, childID, ekeyObj=None, keyData=None):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """
      
      TimerStart('spawnChild')

      if not self.hasChaincode():
         raise KeyDataError, 'No chaincode has been defined to extend chain'

      privAvail = self.getPrivKeyAvailability()
      if privAvail==PRIV_KEY_AVAIL.NextUnlock:
         LOGERROR('Cannot allow multi-level priv key generation while locked')
         LOGERROR('i.e. If your wallet has previously computed m/x and M/x,')
         LOGERROR('but it is currently encrypted, then it can spawn m/x/y by')
         LOGERROR('storing the encrypted version of m/x and its chaincode')
         LOGERROR('and then computing it on next unlock.  But if m/x/y is ')
         LOGERROR('currently in that state, you cannot then spawn m/x/y/z ')
         LOGERROR('until you have unlocked m/x/y once.  This is what is ')
         LOGERROR('meant by "multi-level key generation while locked')
         raise KeyDataError, 'Cannot do multi-level priv key gen while locked'
                              
      wasLocked  = False
      if privAvail==PRIV_KEY_AVAIL.Encrypted:
         unlockSuccess = self.unlock(ekeyObj, keyData)
         if not unlockSuccess:
            raise PassphraseError, 'Incorrect decryption data to spawn child'
         else:
            privAvail = PRIV_KEY_AVAIL.Plain
            wasLocked = True # will re-lock at the end of this operation


      # If we have key data and it's encrypted, it's decrypted by now.
      # extchild has priv key if we have privavail == plain.  Else, we extend
      # only the public part
      if hdwDepth<3:
         childAddr = ArmoryRoot()
      else:
         childAddr = ArmoryAddress()
         
      childAddr.childIdentifier
      extChild  = HDWalletCrypto().ChildKeyDeriv(self.getExtendedKey(), childID)

      # In all cases we compute a new public key and chaincode
      childAddr.binPubKey33or65 = extChild.getPub().copy()
      childAddr.binChaincode    = extChild.getChain().copy()

      if privAvail==PRIV_KEY_AVAIL.Plain:
         # We are extending a chain using private key data (unencrypted)
         childAddr.binPrivKey32_Plain  = extChild.getPriv().copy()
         childAddr.needToDerivePrivKey = False
      elif privAvail==PRIV_KEY_AVAIL.NextUnlock:
         # Copy the parent's encrypted key data to child, set flag
         childAddr.binPrivKey32_Encr = self.binPrivKey32_Encr.copy()
         childAddr.binChaincode      = self.binChaincode.copy()
         childAddr.needToDerivePrivKey = True
      elif privAvail==PRIV_KEY_AVAIL.None:
         # Probably just extending a public key
         childAddr.binPrivKey32_Plain  = SecureBinaryData(0)
         childAddr.needToDerivePrivKey = False
      else:
         LOGERROR('How did we get here?  spawnchild:')
         LOGERROR('   privAvail == %s', privAvail)
         LOGERROR('   encrypt   == %s', self.useEncryption)
         LOGERROR('Bailing without spawning child')
         raise KeyDataError
   
      childAddr.parentHash160      = self.getHash160()
      childAddr.binAddr160         = self.binPubKey33or65.getHash160()
      childAddr.useEncryption      = self.useEncryption
      childAddr.isInitialized      = True
      childAddr.childIdentifier    = childID
      childAddr.hdwDepth           = self.hdwDepth+1
      childAddr.indexList          = self.indexList[:]
      childAddr.indexList.append(childID)

      if childAddr.useEncryption and not childAddr.needToDerivePrivKey:
         # We can't get here without a [valid] decryptKey 
         childAddr.lock(ekeyObj, keyData))
         if not wasLocked:
            childAddr.unlock(ekeyObj, keyData)
            self.unlock(ekeyObj, keyData)
      return childAddr




   #############################################################################
   def unlock(self, ekeyObj=None, encryptKey=None):
      superUnlocked = super(ArmoryRoot, self).unlock(ekeyObj, encryptKey)

      if superUnlocked and hdwDepth==0:
         # This is a master root which also has seed data
         if self.bip32seed_encr.getSize()  >  0 and \
            self.bip32seed_plain.getSize() == 0:
            self.bip32seed_plain = self.seedCryptInfo.decrypt( \
                                                   self.bip32seed_encr, \
                                                   ekeyObj=ekeyObj, \
                                                   keyData=encryptKey)
            self.bip32seed_plain.resize(self.bip32seed_size)

      return superUnlocked


   #############################################################################
   def lock(self, ekeyObj=None, encryptKey=None):
      superLocked = super(ArmoryRoot, self).lock(ekeyObj, encryptKey)
      if superLocked and hdwDepth==0:
         self.bip32seed_plain.destroy()


   #############################################################################
   def CreateNewJBOKRoot(self, typeStr='BIP32', cryptInfo=None):
      """
      JBOK is "just a bunch of keys," like the original Bitcoin-Qt client 
      (prior to version... 0.8?).   We don't actually need a deterministic 
      part in this root/chain... it's only holding a bunch of unrelated 
      """
      self.isFakeRoot = True
      self.privCryptInfo = cryptInfo.copy()


   #############################################################################
   def advanceHighestIndex(self, ct=1):
      topIndex = self.highestUsedChainIndex + ct
      topIndex = min(topIndex, self.lastComputedChainIndex)
      topIndex = max(topIndex, 0)

      self.highestUsedChainIndex = topIndex
      self.walletFileSafeUpdate( [[WLT_UPDATE_MODIFY, self.offsetTopUsed, \
                    int_to_binary(self.highestUsedChainIndex, widthBytes=8)]])
      self.fillAddressPool()
      
   #############################################################################
   def rewindHighestIndex(self, ct=1):
      self.advanceHighestIndex(-ct)


   #############################################################################
   def peekNextUnusedAddr160(self):
      return self.getAddress160ByChainIndex(self.highestUsedChainIndex+1)

   #############################################################################
   def getNextUnusedAddress(self):
      if self.lastComputedChainIndex - self.highestUsedChainIndex < \
                                              max(self.addrPoolSize-1,1):
         self.fillAddressPool(self.addrPoolSize)

      self.advanceHighestIndex(1)
      new160 = self.getAddress160ByChainIndex(self.highestUsedChainIndex)
      self.addrMap[new160].touch()
      self.walletFileSafeUpdate( [[WLT_UPDATE_MODIFY, \
                                  self.addrMap[new160].walletByteLoc, \
                                  self.addrMap[new160].serialize()]]  )

      return self.addrMap[new160]


   #############################################################################
   def changePrivateKeyEncryption(self, encryptInfoObj):
      

   #############################################################################
   def changeOuterEncryption(self, encryptInfoObj):


   #############################################################################
   def forkObserverChain(self, newWalletFile, shortLabel='', longLabel=''):



   #############################################################################
   def spawnChild(self, childID, decryptKey=None):
      """
      We require some fairly complicated logic here, due to the fact that a
      user with a full, private-key-bearing wallet, may try to generate a new
      key/address without supplying a passphrase.  If this happens, the wallet
      logic gets mucked up -- we don't want to reject the request to
      generate a new address, but we can't compute the private key until the
      next time the user unlocks their wallet.  Thus, we have to save off the
      data they will need to create the key, to be applied on next unlock.
      """

      
      TimerStart('spawnChild')

      if not self.hasChaincode():
         raise KeyDataError, 'No chaincode has been defined to extend chain'

      privAvail = self.getPrivKeyAvailability()
      if privAvail==PRIV_KEY_AVAIL.NextUnlock:
         LOGERROR('Cannot allow multi-level priv key generation while locked')
         LOGERROR('i.e. If your wallet has previously computed m/x and M/x,')
         LOGERROR('but it is currently encrypted, then it can spawn m/x/y by')
         LOGERROR('storing the encrypted version of m/x and its chaincode')
         LOGERROR('and then computing it on next unlock.  But if m/x/y is ')
         LOGERROR('currently in that state, you cannot then spawn m/x/y/z ')
         LOGERROR('until you have unlocked m/x/y once.  This is what is ')
         LOGERROR('meant by "multi-level key generation while locked')
         raise KeyDataError, 'Cannot do multi-level priv key gen while locked'
                              
      wasLocked  = False
      if privAvail==PRIV_KEY_AVAIL.Encrypted:
         if not self.verifyEncryptionKey(decryptKey):
            raise PassphraseError, 'Incorrect passphrase entered to spawn child'
         else:
            self.unlock(decryptKey)
            privAvail = PRIV_KEY_AVAIL.Plain
            wasLocked = True # will re-lock at the end of this operation


      # If we have key data and it's encrypted, it's decrypted by now.
      # extchild has priv key if we have privavail == plain.  Else, we extend
      # only the public part
      childAddr = ArmoryAddress()
      extChild  = HDWalletCrypto().ChildKeyDeriv(self.getExtendedKey(), childID)

      # In all cases we compute a new public key and chaincode
      childAddr.binPubKey33or65 = extChild.getPub().copy()
      childAddr.binChaincode    = extChild.getChain().copy()

      if privAvail==PRIV_KEY_AVAIL.Plain:
         # We are extending a chain using private key data (unencrypted)
         childAddr.binPrivKey32_Plain  = extChild.getPriv().copy()
         childAddr.needToDerivePrivKey = False
      elif privAvail==PRIV_KEY_AVAIL.NextUnlock:
         # Copy the parent's encrypted key data to child, set flag
         childAddr.binPrivKey32_Encr = self.binPrivKey32_Encr.copy()
         childAddr.binChaincode      = self.binChaincode.copy()
         childAddr.needToDerivePrivKey = True
      elif privAvail==PRIV_KEY_AVAIL.None:
         # Probably just extending a public key
         childAddr.binPrivKey32_Plain  = SecureBinaryData(0)
         childAddr.needToDerivePrivKey = False
      else:
         LOGERROR('How did we get here?  spawnchild:')
         LOGERROR('   privAvail == %s', privAvail)
         LOGERROR('   encrypt   == %s', self.useEncryption)
         LOGERROR('Bailing without spawning child')
         raise KeyDataError
   
      childAddr.parentHash160      = extChild.getParentHash160().copy()
      childAddr.binAddr160         = self.binPubKey33or65.getHash160()
      childAddr.useEncryption      = self.useEncryption
      childAddr.isInitialized      = True
      childAddr.childIdentifier    = childID
      childAddr.hdwDepth           = self.hdwDepth+1
      childAddr.indexList          = self.indexList[:]
      childAddr.indexList.append(childID)

      if childAddr.useEncryption and not childAddr.needToDerivePrivKey:
         # We can't get here without a [valid] decryptKey 
         childAddr.lock(decryptKey)
         if not wasLocked:
            childAddr.unlock(decryptKey)
            self.unlock(decryptKey)
      return childAddr



# We should have all the classes availale by now, we can add the 
# class list to the WalletEntry static members
ISREQUIRED=True
WalletEntry.addClassToMap('HEAD', ArmoryFileHeader)
WalletEntry.addClassToMap('ADDR', ArmoryAddress, ISREQUIRED)
WalletEntry.addClassToMap('ROOT', ArmoryRoot, ISREQUIRED)
WalletEntry.addClassToMap('LABL', AddressLabel)
WalletEntry.addClassToMap('COMM', TxComment)
WalletEntry.addClassToMap('LBOX', MultiSigLockbox)
WalletEntry.addClassToMap('ZERO', ZeroData,)
WalletEntry.addClassToMap('RLAT', RootRelationship, ISREQUIRED)
WalletEntry.addClassToMap('EKEY', EncryptionKey)
WalletEntry.addClassToMap('MKEY', MultiPwdEncryptionKey)
WalletEntry.addClassToMap('KDFO', KdfObject)
WalletEntry.addClassToMap('IDNT', IdentityPublicKey)
WalletEntry.addClassToMap('SIGN', WltEntrySignature)

