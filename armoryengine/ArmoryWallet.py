from ArmoryUtils import *
from ArmoryEncryption import *
from WalletEntry import *
from ArmoryKeyPair import *
from Timer import *


         


################################################################################
################################################################################
class ArmoryWalletFile(object):

   def __init__(self, filepath, createNew=False):

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
      # call to fsyncUpdates(), so WE objects know when it's done
      self.updateCount  = 0

      # Last synchronized all chains to this block
      self.lastSyncBlockNum = 0

      self.allWalletEntries = []
      self.siblingRoots = {}
      self.allRoots = {}

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

      # Maps relationship IDs to relationship objects
      self.relationshipMap  = {}

      # Master address list of all wallets/roots/chains/leaves
      self.masterScrAddrMap  = {}

      # List of all encrypted wallet entries that couldn't be decrypted 
      # Perhaps later find a way decrypt and put them into the other maps
      self.opaqueList  = []

      # List of all WalletEntry objects that had a file code we didn't 
      # recognize.  Perhaps these were created by a newer version of
      # Armory, or will be consumed by a module/plugin
      self.unrecognizedList  = []

      # List of all WalletEntry objects that had an unrecoverable error
      self.unrecoverableList  = []

      # List of all WalletEntry objects that had an unrecoverable error
      self.wltParentMissing  = []

      # We have the ability to store arbitrary data in the wallet files
      # Among other things, this gives plugins a way to read and write
      # data to wallet files, and running Armory without the plugin will
      # just shove it into this map and ignore it.
      self.arbitraryDataMap = {}

      # List of all WalletEntry object IDs disabled for various reasons
      # (usually from critical data not recognized in a child entry)
      self.disabledEntries = set()
      self.disabledList = []

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

      # Set read-only flag:  will not modify any wallet files, will not 
      # create backup, will throw error if you attempt to write anything.
      # Really, this is intended for reading and querying the wallet obj.
      # Even generating new addresses would induce file write ops.
      self.isReadOnly = False


      # Wallet operations are not threadsafe.  Detect multiple access
      self.midWriteFlag = threading.Event()


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
   def changeMasterKeyEncryptParams(self, ekeyID, oldParams, newParams):
      # We can either change encryption or kdf params of a single password,
      # or switch from single-password to multi-password or back.  To switch
      # types of password protection, we'll need to write the new entry and 
      # then delete the old one.
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
   def getKDF(self, kdfID):
      return self.kdfMap.get(kdfID, None)

   #############################################################################
   def getEkey(self, ekeyID):
      return self.ekeyMap.get(ekeyID, None)

   #############################################################################
   def mergeWalletFile(self, wltOther, rootsToAbsorb='ALL'):
      """
      Just like in git, WltA.mergeWalletFile(WltB) means we want to pull all 
      the data from WltB into WltA and leave WltB untouched.
      """

      if isinstance(wltOther, basestring):
         # Open wallet file
         if not os.path.exists(wltOther):
            raise WalletExistsError('Wallet to merge DNE: %s' % wltOther)
         wltOther = ArmoryWalletFile.readWalletFile(filepath, openReadOnly=True)


      '''
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

         if root.relationship.isForMultisig:
            # Make sure to merge the sibling wallets, too
            for sib in root.relationship.siblingList:
               if not sib.rootID in rootRefList:
                  LOGINFO('Adding sibling to root-merge list')
               rootRefList.add(sib.rootID)

      '''



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
      raise NotImplementedError

      if not exists(filepath):
         LOGERROR('External info file does not exist!  %s' % filepath)

      self.externalInfoWallet =  ArmoryWalletFile.ReadWalletFile(filepath)


   #############################################################################
   def readWalletEntry(self, toUnpack):
      we = WalletEntry().unserialize(toUnpack)


   #############################################################################
   @staticmethod
   def ReadWalletFile(wltPath, openReadOnly=False, **outerCryptArgs):
      """
      This reads an Armory wallet 2.0 wallet file, which contains a constant-
      size header, and then a collection of IFF/RIFF-like WalletEntry objects.
      
      WE DO NOT ASSUME ANY PARTICULAR ORDERING!  For instance, if a WalletEntry
      object references a KDF object that is in the same wallet file, we never
      assume that the KDF object has been read yet.  While we may enforce
      reasonable ordering when we create the wallet, there are certain wallet
      operations (like mergine wallets) which may leave them out of order.  

      For that reason, this method has two phases: 
         (1) Read and organize all the WalletEntry objects into maps/lists
         (2) Walk through all the objects and do anything that requires 
             references to other objects in the wallet file, such as setting
             child-parent references, and disabling nodes with critical
             children that are unrecognized

      In case there are outer-encrypted entries in the wallet (all info
      about the WalletEntry is encrypted except for the parent ID), then 
      we will repeat the above after decrypting the opaque objects.
      """
      if not os.path.exists(wltPath):
         raise FileExistsError('Wallet file does not exist: %s' % wltPath)


      wlt = ArmoryWalletFile()
      wlt.walletPath = wltPath
      wlt.isReadOnly = openReadOnly


      # We will need a bunch of different pathnames for atomic update ops
      self.walletPath        = self.getWalletPath('')
      self.walletPathBackup  = self.getWalletPath('backup')
      self.walletPathUpdFail = self.getWalletPath('update_unsuccessful')
      self.walletPathBakFail = self.getWalletPath('backup_unsuccessful')

   
      if openReadOnly:
         if not wlt.checkWalletIsConsistent():
            raise WalletUpdateError('Wallet to open in RO mode is inconsistent!')
      else:
         wlt.doWalletFileConsistencyCheck()

      # We assume the raw wallet fits in RAM.  This isn't a bad assumption,
      # since the wallet file is currently designed to hold all wallet entries
      # in RAM anyway.  If we want to change this, we need to switch to a 
      # database-backed wallet design.
      openfile = open(wltPath,'rb')
      rawWallet = BinaryUnpacker(openfile.read())
      openfile.close()

      
      # The header is always the first X bytes.  Check the
      wlt.fileHeader = ArmoryFileHeader.Unserialize(rawWallet)
      if wlt.fileHeader.isDisabled:
         wlt.isDisabled = True
         return wlt

      allEntries = [] 
      while rawWallet.getRemainingSize() > 0:
         currPos = rawWallet.getPosition()
         wltEntry = WalletEntry.UnserializeEntry(rawWallet, wlt, currPos)
         allEntries.append(wltEntry)
         
         
      # This will organize all the entries into their respective lists/maps,
      # set references between related objects, disable things as needed, etc
      wlt.addEntriesToWallet(allEntries)


      # If outer encryption was used on any entries, decrypt & add, if possible
      # (needed to add previous entries, because one is probably the decryption
      # key and/or KDF needed to unlock outer encryption)
      if len(wlt.opaqueList) > 0:
         if len(outerCryptArgs) == 0:
            LOGWARN('Opaque entries in wallet, no decrypt args supplied')
         else:
            newWEList = []
            for we in wlt.opaqueList:
               newWEList.append(we.decryptPayloadReturnNewObj(**outerCryptArgs))

            wlt.addEntriesToWallet(newWEList)
            wlt.opaqueList = []
         

      # The wallet is now ready for use
      return wlt



   #############################################################################
   def addEntriesToWallet(self, weList):
      """
      This operates in two steps:  
         (1) Filter the list of WalletEntry objects into the right lists/maps
         (2) Go back through everything and set references between them and 
             apply any operations that requires having all WE objects avail 
             (such as disabling parents of unrecognized-but-critical children,
             linking multi-sig roots based on relationship objects, etc)
             
      Everything that will be accessed by ID is stored in a map indexed by
      ID.  For now, we will assume that all parent references are ArmoryRootKey
      objects (or None), and everything else will know which map to look in
      (like looking in ekeyMap when looking for encryption keys).  Therefore,
      we do not store a master map of all IDs.
      """
      
      for we in weList:
         if we.isDeleted:  
            continue


         # In case the Reed-Solomon error correction actually finds an error
         if we.needRewrite and not openReadOnly:
            self.addFileOperationToQueue('UpdateEntry', we)

         # If WE is unrecognized, ignore, if also critical, disable parent
         if we.isUnrecognized:
            self.unrecognizedList.append(we)
            if we.isRequired:
               self.disabledEntries.add(we.parent160)
            continue

         if we.isUnrecoverable:
            self.unrecoverableList.append(we)
            continue
      
         if we.isOpaque:
            self.opaqueList.append(we)
            continue

         # Everything else goes in the master list of entries
         self.allWalletEntries.append(we)

         # We explicitly don't use isinstance here, because it's easy to
         # mess up derived classes, which will fall into conditional
         # branches you weren't expecting
         if we.FILECODE in WalletEntry.KEYPAIR_TYPES:
            if weID in self.masterScrAddrMap:
               LOGWARN('ScrAddr is in wallet file multiple times!')
            self.masterScrAddrMap[we.getScrAddr()] = we
            self.allRoots[weID] = we
         elif we.FILECODE=='ALBL':
            self.allLabels[we.scrAddr] = we
         elif we.FILECODE=='TLBL':
            if we.txidFull: 
               self.allLabels[we.txidFull] = we
            if we.txidMall: 
               self.allLabels[we.txidMall] = we
         elif we.FILECODE=='LOCKBOX_':
            self.lockboxMap[we.lboxID] = we
         elif we.FILECODE in ['EKEYREG_','EKEYMOFN']:
            self.ekeyMap[we.ekeyID] = we
         elif we.FILECODE=='KDFOBJCT':
            self.kdfMap[we.kdfObjID] = we
         elif we.FILECODE=='ARBDATA_':
            self.arbitraryDataMap[we.dataName] = we
         

      # Set parent-child references for wallet entries' root vars
      for i,we in enumerate(self.allWalletEntries):
         wltParent = self.allRoots.get(we.wltParentRef)
         if wltParent is None:
            self.wltParentMissing.append(we)
            del self.allWalletEntries[i]
            continue
         
         we.wltParentRef = wltParent 
         wltParent.wltChildRefs.append(we)

         # AEK objects actually have a separate DAG structure for 
         # relating keys to other keys, that is different from the
         # relationships defined at the WalletEntry level
         if isinstance(we, ArmoryKeyPair):
             
         
            
      # Set Ekey and KDF references
      for i,we in enumerate(self.allWalletEntries):
         
         if we.FILECODE == 'EKEY':
            kdfid = we.keyCryptInfo.kdfObjID
            ekeyKdf = self.kdfMap.get(kdfid)
            if ekeyKdf is None:
               LOGERROR('KDF %s for Ekey %s is not available' % \
                  binary_to_hex(kdfid), binary_to_hex(we.ekeyID))
               continue
            we.setKdfObjectRef(ekeyKdf)
         elif we.FILECODE == 'MKEY':
            # We set multiple KDFs from the wallet file for each multi-pwd key
            kdfList = []
            for einfo in we.einfos:
               kdfid = einfo.kdfObjID
               ekeyKdf = self.kdfMap.get(kdfid)
               if ekeyKdf is None:
                  LOGERROR('KDF %s for Ekey %s is not available' % \
                     binary_to_hex(kdfid), binary_to_hex(we.ekeyID))
               continue
               kdfList.append(ekeyKdf)
            we.setKdfObjectRefList(kdfList)
         elif isinstance(we, ArmoryKeyPair):
            ekid = we.privCryptInfo.keySource
            ekey = self.ekeyMap.get(ekid)
            if ekey is None:
               LOGERROR('Ekey not in wallet file: %s' % binary_to_hex(ekid))
               continue
            we.masterEkeyRef = ekey


            
      # Aggregate roots that are part of multi-sig transactions
      for root in self.allRoots:
         if not isinstance(root, MultisigRoot):
            continue

         if not root.isComplete:
            continue

         for sib160 in root.sib160s:
            sibRoot = self.allRoots.get(sib160)
            if sibRoot is None: 
               LOGWARN('Disabling multisig root b/c could not find sib root')
               self.disabledEntries.append(root.getEntryID())
               break

            root.setSiblingRef(self, sibRoot):
            sibRoot.isForMultisig = True


      # First look for all children that have been marked to be disabled
      # Mark their wltParent parents to be disabled
      for node in self.allRoots:
         if node.getEntryID() in self.disabledEntries or
            node.wltParentRef.getEntryID() in self.disabledEntries:
            node.isDisabled = True 
            self.disabledList.append(node)
            del self.allRoots[nodeID]
            
      # Then recursively disable all children of disabled roots
      for node in self.disabledList:
         node.disableAllWltChildren()
         
      # TODO: due to complexity, did not remove disabled children from
      #       their respective lists, but I believe all that matters is
      #       that the roots have been removed.  Need to test this.
               
         
      if not self.isReadOnly:
         self.fsyncUpdates()

      return wlt

      #self.rootMapBIP32 = [{}, {}, {}]
      #self.rootMapOther = {}
      #self.lockboxMap = {}
      #self.ekeyMap = {}
      #self.kdfMap  = {}
      #self.relationshipMap  = {}
      #self.masterScrAddrMap  = {}
      #self.arbitraryDataMap = {}
      #self.opaqueList  = []
      #self.unrecognizedList  = []
      #self.unrecoverableList  = []
      #self.disabledEntries = set()

      #'ROOT', ArmoryRootKey, ISREQUIRED)
      #'ALBL', AddressLabel)
      #'TLBL', TxLabel)
      #'LBOX', MultiSigLockbox)
      #'RLAT', RootRelationship, ISREQUIRED)
      #'EKEY', EncryptionKey)
      #'MKEY', MultiPwdEncryptionKey)
      #'KDF_', KdfObject)
      #'IDNT', IdentityPublicKey)
      #'SIGN', WltEntrySignature)
      #'DATA', ArbitraryDataContainer)
         
      

   #############################################################################
   def doFileOperation(self, operationType, theData, loc=None):
      """
      This is intended to be used for one-shot safe writing to file. 
      Normally, you would batch your updates using addFileOperationToQueue
      and then call fsyncUpdates() when you're done.
      """
      if not len(self.updateQueue)==0:
         LOGERROR('Wallet update queue not empty!  Adding this to the')
         LOGERROR('queue and ')

      self.addFileOperationToQueue(operationType, theData, loc)
      self.fsyncUpdates()
          

   #############################################################################
   @VerifyArgTypes(operationType=str, wltEntry=[WalletEntry, ArmoryFileHeader])
   def addFileOperationToQueue(self, operationType, wltEntry)
      """
      This will add/update/delete a wallet entry . 
      batch operation.  
      a shortcut method for operating with WalletEntry objects.

          ('RewriteHeader', ArmoryFileHeader)
          ('AddEntry',      WalletEntryObj)
          ('UpdateEntry',   WalletEntryObj)
          ('DeleteEntry',   WalletEntryObj)

      If one of the "entry" versions is used, it will simply pull the
      necessary information out of the object and do an "Append' or "Modify'
      as necessary.
      """
      if self.isReadOnly:
         raise WalletUpdateError('Cannot do file ops on ReadOnly wallet!')

      if not operationType.lower() in ['rewriteheader','addentry', 
                                       'updateentry', 'deleteentry']:
         raise BadInputError('Wallet update type invalid: %s' % operationType)
      
      self.updateQueue.append([operationType, wltEntry])
      wltEntry.needsFsync = True
         
      '''
      # The data to eventually be added to the file, or overwrite previous data
      serData = None

      # Convert the "___Entry" commands into the lower-level Append/Modify cmds
      if operationType.lower()=='addentry':
         # Add a new wallet entry to this wallet file
         if wltEntry.wltByteLoc >= 0:
            return   # Already in the wallet
         operationType = 'Append'
         serData = we.serialize()
      elif operationType.lower()=='updateentry':
         # Update an existing entry -- delete and append if size changed
         # wltEntrySz is the size of the WE when it was last read from 
         # the wallet file.  If its size has changed, its serialized size
         # will be different than that
         serData = we.serialize()
         if len(we.serializeEntry())==we.wltEntrySz:
            fileLoc = we.wltStartByte
            operationType = 'Modify'
         else:
            LOGINFO('WalletEntry replace != size (%s).  ', we.entryCode)
            LOGINFO('Delete&Append')
            self.addFileOperationToQueue('DeleteEntry', we.wltStartByte)
            operationType = 'Append'
      elif operationType.lower()=='deleteentry':
         # Delete an entry from the wallet
         fileLoc = we.wltStartByte 
         if not isinstance(we, (int,long)):
            LOGERROR('Delete entry only using WltEntry object or start byte')
            return

         delBytes = wltEntrySz
         serData = ZeroData(delBytes).serialize()
         operationType = 'Modify'

         # We already know that the entry is going away, set the start byte now
         we.wltStartByte = -1
         we.wltEntrySz = -1


      #####
      # This is where it actually gets added to the queue.
      if operationType.lower()=='append':
         if isWltEntryObj:
            we.wltStartByte =  self.lastFilesize
         self.lastFilesize += len(serData)
         self.updateQueue.append([WLT_UPDATE_ADD, serData])
      elif operationType.lower()=='modify':
         if not fileLoc:
            LOGERROR('Must supply start byte of modification')
            raise BadInputError
         self.updateQueue.append([WLT_UPDATE_MODIFY, [serData, fileLoc]])

      #####
      # Tell the WalletEntry object when to expect its internal state to be 
      # consistent with the wallet file
      if isWltEntryObj:
         we.syncWhenUpdateCount = self.updateCount + 1
      '''
         
         

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
   def fsyncUpdates(self):
            
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
      """
      if self.isReadOnly:
         raise WalletUpdateError('Wallet is opened in read-only mode!')

      if self.midWriteFlag.isSet():
         raise MultiThreadingError( \
            'Attempted to call fsync while currently fsync\'ing.  This is'
            'probably a multithreading collision.  Wallet operations are'
            'not threadsafe!')
      
      
      if len(self.updateQueue)==0:
         return False

      
      try:
         if not os.path.exists(self.walletPath):
            raise FileExistsError, 'No wallet file exists to be updated!'
   
         # Identify if the batch contains updates to the same object mult times.
         # We can safely batch updates to any mixture of objects, but not 
         # multiple changes to the same object
         fileLocToUpdate = set()
         for opType,weObj in self.updateQueue:
            if weObj.wltByteLoc in fileLocToUpdate:
               LOGERROR('Obj: %s (ID=%s, loc=%d)', weObj.FILECODE, 
                           binary_to_hex(weObj.uniqueID, weObj.wltByteLoc)
               raise WalletUpdateError('Multiple updates to same ID in batch')
            fileLocToUpdate.add(weObj.wltByteLoc)
   
         # Make sure that the primary and backup files are synced before update
         self.doWalletFileConsistencyCheck()
   
         # Make sure all entries have valid wallet file locations
         for opType,weObj in self.updateQueue:
            if opType in ['updateentry', 'deleteentry'] and weObj.wltByteLoc <= 0:
               raise WalletUpdateError('Wallet entry cannot be updated without loc')
        
         # Apply updating to both files in an identical manner
         MAIN,BACKUP = [0,1]
         for fnum in [MAIN,BACKUP]:
            # Update fail flags so that if process crashes mid-update, we know
            # upon restart where it failed and can recover appropriately
            if fnum==MAIN:
               # Modify the main wallet file, set flag to indicate we started
               wltPath = self.walletPath
               interrupt = self.interruptTest1
               touchFile(self.walletPathUpdFail)
            elif fnum==BACKUP:
               # +flag to start modifying backup file, -flag bc MAIN updating done
               wltPath = self.walletPathBackup
               interrupt = self.interruptTest3
               touchFile(self.walletPathBakFail)
               if self.interruptTest2: raise InterruptTestError 
               os.remove(self.walletPathUpdFail)
               
   
            # We will do all mid-file operations first, and queue up all 
            # append operations for the end.  Second pass will apply all the 
            # append operations and then update the weObjs with new size and 
            # loc. Append operations include both the AddEntry cmds in the 
            # queue, also UpdateEntry cmds with objects now a different size.
            appendAfterOverwriteQueue = []
   
            try:
               writefile = open(wltPath, 'r+b')
            except IOError:
               LOGEXCEPT('Failed to open %s in r+b mode. Permissions?' % wltPath)
               return False
   
            for opType,weObj in self.updateQueue:
               # At this point, self.wltEntrySz is always the size of the 
               # object currently in the file, not yet been updated if the WE 
               # is now a new size.  If we requested "UpdateEntry" but we 
               # serialize the object and it turns out to be a different size,   
               # then we delete and append, instead.
               if opType.lower()=='rewriteheader':
                  # Header is always exact same size, at beginning of file
                  wltfile.seek(0)
                  wltfile.write(weObj.serialize())
               elif opType.lower() == 'addentry':
                  # Queue up append operations until after in-place modifications
                  appendAfterOverwriteQueue.append([weObj, weObj.serializeEntry()])
               elif opType.lower() == 'deleteentry':
                  # Delete is just in-place modification, overwrite with \x00's
                  weObj.isDeleted = True
                  wltfile.seek(weObj.wltByteLoc)
                  wltfile.write(weObj.serialize())
               elif opType.lower() == 'updateentry':
                  weSer = weObj.serializeEntry()
                  if len(weSer) == weObj.wltEntrySz:
                     # Same size, overwrite in-place
                     wltfile.seek(weObj.wltByteLoc)
                     wltfile.write(weObj.serialize())
                  else:
                     # Obj changed size, delete old add new one to the queue
                     wltfile.seek(weObj.wltByteLoc)
                     wltfile.write(weObj.serializeEntry(doDelete=True))
                     appendAfterOverwriteQueue.append([weObj, weSer])
   
            # This is for unit-testing the atomic-wallet-file-update robustness
            if interrupt: raise InterruptTestError
   
            # Close file for writing, reopen it in append mode
            try:
               writefile.close()
               appendFile = open(wltPath, 'ab')
            except IOError:
               LOGEXCEPT('Failed to open %s in ab mode. Permissions?' % wltPath)
               return False
   
            for weObj,weSer in appendAfterOverwriteQueue:
               appendfile.write(weSer)
               # At end of updating backup file, can update WE objects
               if fnum==BACKUP:
                  weObj.wltEntrySz = len(weSer)
                  weObj.wltByteLoc = appendfile.tell() - weObj.wltEntrySz
         
            appendfile.close()
   
         # Finish by removing flag that indicates we were modifying backup file
         os.remove(self.walletPathBakFail)
   
         # Mark WalletEntry objects as having been updated
         for opType,weObj in self.updateQueue:
            weObj.needsFsync = False
   
         # In debug mode, verify that main and backup are identical
         if CLI_OPTIONS.doDebug:
            hashMain = sha256(open(self.walletPath,       'rb').read())
            hashBack = sha256(open(self.walletPathBackup, 'rb').read())
            if not hashMain==hashBack:
               raise WalletUpdateError('Updates of two wallet files do not match!')
   
         return True
      finally:
         self.midWriteFlag.clear()
         
   
   
   

   #############################################################################
   def doWalletFileConsistencyCheck(self, onlySyncBackup=True):
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
         raise FileExistsError('No wallet file exists to be checked!')

      walletFileBackup = self.getWalletPath('backup')
      mainUpdateFlag   = self.getWalletPath('update_unsuccessful')
      backupUpdateFlag = self.getWalletPath('backup_unsuccessful')

      if not os.path.exists(walletFileBackup):
         # We haven't even created a backup file, yet
         LOGDEBUG('Creating backup file %s', walletFileBackup)
         touchFile(backupUpdateFlag)
         shutil.copy(self.walletPath, walletFileBackup)
         os.remove(backupUpdateFlag)

      if os.path.exists(backupUpdateFlag) and os.path.exists(mainUpdateFlag):
         # Here we actually have a good main file, but backup never succeeded
         LOGERROR('***WARNING: error in backup file... how did that happen?')
         shutil.copy(self.walletPath, walletFileBackup)
         os.remove(mainUpdateFlag)
         os.remove(backupUpdateFlag)
      elif os.path.exists(mainUpdateFlag):
         LOGERROR('***WARNING: last file operation failed!  Restoring wallet from backup')
         # main wallet file might be corrupt, copy from backup
         shutil.copy(walletFileBackup, self.walletPath)
         os.remove(mainUpdateFlag)
      elif os.path.exists(backupUpdateFlag):
         LOGERROR('***WARNING: creation of backup was interrupted -- fixing')
         shutil.copy(self.walletPath, walletFileBackup)
         os.remove(backupUpdateFlag)

      if onlySyncBackup:
         return 0

   #############################################################################
   def checkWalletIsConsistent(self):
      """
      Same as doWalletFileConsistencyCheck, but does not modify anything.
      Instead, returns False if there is an inconsistency that would otherwise
      induce wallet changes by doWalletFileConsistencyCheck
      """

      if not os.path.exists(self.walletPath):
         raise FileExistsError('No wallet file exists to be checked!')

      walletFileBackup = self.getWalletPath('backup')
      mainUpdateFlag   = self.getWalletPath('update_unsuccessful')
      backupUpdateFlag = self.getWalletPath('backup_unsuccessful')

      if not os.path.exists(walletFileBackup):
         # No backup file to compare against
         return True
      elif os.path.exists(backupUpdateFlag) and os.path.exists(mainUpdateFlag):
         # Here we actually have a good main file, but backup never succeeded
         return False
      elif os.path.exists(mainUpdateFlag):
         return False
      elif os.path.exists(backupUpdateFlag):
         return False

      return True

   #############################################################################
   @VerifyArgTypes(securePwd=SecureBinaryData,
                   extraEntropy=[SecureBinaryData, None],
                   preGenSeed=[SecureBinaryData, None])
   def generateNewSinglePwdSeedEkeyKDF(self, securePwd, kdfAlgo='ROMIXOV2',
                                       kdfTargSec=0.25, kdfMaxMem=32*MEGABYTE,
                                       encrAlgo='AES256CBC', extraEntropy=None,
                                       preGenSeed=None):
      
   
      LOGINFO('Creating new single-password wallet seed')

      LOGINFO('Creating new KDF with params: time=%0.2fs, maxmem=%0.2fMB', 
                                        kdfTargSec, kdfMaxMem/float(MEGABYTE))

      newKdf = KdfObject.createNewKDF(kdfAlgo, kdfTargSec, kdfMaxMem)

      tstart = RightNow()
      newKdf.execKDF(SecureBinaryData('TestPassword'))
      tend = RightNow()

      LOGINFO('KDF ID=%s uses %0.2fMB and a test password took %0.2fs',
                     binary_to_hex(newKdf.getKdfID()), 
                     newKdf.memReqd/float(MEGABYTE), (tend-tstart))

      
      LOGINFO('Creating new master encryption key')
      newEkey = EncryptionKey().createNewMasterKey(newKdf, encrAlgo, securePwd)
      LOGINFO('New Ekey has ID=%s',  binary_to_hex(newEkey.ekeyID))

      
      # Copy all sensitive data into newSeed and destroy at the end.  If a SBD
      # object was created to be passed into pregen arg, caller can destroy it.
      if preGeneratedSeed is None:
         if extraEntropy is None:
            raise KeyDataError('Need extra entropy for secure seed creation')
         newSeed = SecureBinaryData().GenerateRandom(32, extraEntropy)
      else:
         newSeed = preGeneratedSeed.copy()


      newRoot = ArmoryRootKey().createNewRootFromSeed(seed=newSeed)
      
      
      self.addFileOperationToQueue('AddEntry', newKdf)
      self.addFileOperationToQueue('AddEntry', newEkey)
      self.addFileOperationToQueue('AddEntry', newRoot)
      self.fsyncUpdates()
      
      

   #############################################################################
   @VerifyArgTypes(extraEntropy=[SecureBinaryData, None],
                   preGeneratedSeed=[SecureBinaryData, None])
   def createAndAddNewMasterRoot(self, extraEntropy, encryptInfo, 
                                       preGeneratedSeed=None, **cryptKwArgs):
      """
      If this new master seed is being protected with encryption that isn't
      already defined in the wallet, then the new Ekey & KDF objects needs 
      to be created and added to the wallet before calling this function.  
      The **cryptKwArgs will be passed to the ACI:
         
         encryptInfo.encrypt(newSeed, **cryptKwArgs)
   
      Thus, it should contain everything that is needed to do the master 
      seed encryption.  If it's password encryption only, then it should
      include a KDF and a password.  If it's master-key encryption, should 
      include the master ekeyObj and the password(s) with which it is encrypted
      
      "extraEntropy" is a required argument here, because we should *always*
      be sending extra entropy into the secure (P)RNG for seed creation.  
      Never fully trust the operating system, and there's no way to make its 
      seed generation worse, so we will require it even if the caller decides
      to pass in all zero bytes.  ArmoryQt.getExtraEntropyForKeyGen() (as 
      of this writing) provides a 32-byte SecureBinaryData object which is 
      the hash of system files, key- and mouse-press timings, and a screenshot 
      of the user's desktop.

      Note if you pass in a pregenerated seed, you can then pass in None for 
      extraEntropy arg
      """


      # Copy all sensitive data into newSeed and destroy at the end.  If a SBD
      # object was created to be passed into pregen arg, caller can destroy it.
      if preGeneratedSeed is None:
         if extraEntropy is None:
            raise KeyDataError('Need extra entropy for secure seed creation')
         newSeed = SecureBinaryData().GenerateRandom(32, extraEntropy)
      else:
         newSeed = preGeneratedSeed.copy()


      
      try:
         cryptSeed = encryptInfo.encrypt(newSeed, **cryptKwArgs)
         self.addPregeneratedMasterSeed(newSeed, cryptSeed)

      finally:
         LOGEXCEPT('Error during seed creation and addition to wallet')
         newSeed.destroy()
      
       


      

   #############################################################################
   def unlockWalletEkey(self, ekeyID, **unlockArgs):
      ekeyObj = self.ekeyMap.get(ekeyID, None)

      if ekeyObj is None:
         raise KeyDataError("No ekey in wlt with id=%s" % binary_to_hex(ekeyID))

      ekeyObj.unlock(**unlockArgs)

   #############################################################################
   def lockWalletEkey(self, ekeyID):
      # Lock this specific ekey
      ekeyObj = self.ekeyMap.get(ekeyID, None)
      if ekeyObj is None:
         raise KeyDataError("No ekey in wlt with id=%s" % binary_to_hex(ekeyID))
      ekeyObj.lock()

   #############################################################################
   def lockwalletekeysall(self):
      for eid,ekeyObj in self.ekeyMap.iteritems():
         ekeyObj.lock()
      
      
   #############################################################################
   def checkWalletLockTimeout(self):
      currTime = RightNow()
      for eid,ekeyObj in self.ekeyMap.iteritems():
         if currTime > ekeyObj.relockAtTime:
            ekeyObj.lock()


   #############################################################################
   def createNewLinkedWallet(self, typeStr, withEncrypt,):


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
         newEKey = EncryptionKey().createNewMasterKey(newKDF, \
                                                   'AE256CFB', \
                                                   securePassphrase)
         self.ekeyMap[newEKey.getEncryptionKeyID()] = newEKey

      #####
      # If requested (usually is), create new master seed and the first wlt
      LOGDEBUG('Creating new master root seed & node')
      if createNewRoot:
         newRoot = ArmoryRootKey().CreateNewMasterRoot()
      



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








################################################################################
class AddressLabel(WalletEntry):
  
   FILECODE = 'ADDRLABL' 

   def __init__(self, scrAddrStr=None, label=None):
      self.scrAddr = scrAddrStr
      self.label   = toUnicode(lbl)

   def initialize(self, scrAddrStr=None, lbl=None):

   def serialize(self):
      if self.scrAddrStr is None:
         raise UninitializedError('AddrLabel not initialized')

      bp = BinaryPacker()
      bp.put(VAR_STR,     self.scrAddr)
      bp.put(VAR_UNICODE, self.label)
      return bp.getBinaryString()

   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      scraddr = bu.get(VAR_STR)
      lbl     = bu.get(VAR_UNICODE)
      self.__init__(scraddr, lbl)
      return self


################################################################################
class TxLabel(WalletEntry):

   FILECODE = 'TXLABEL_'

   #############################################################################
   def __init__(self, txidFull=None, txidMall=None, comment=None):
      """
      "Mall" refers to malleability-resistant.  This isn't just for 
      transactions that have been "mall"ed after broadcast, but for 
      offline and multi-sig transactions that haven't been signed yet,
      for which we don't have the full ID.  The user may set the comment
      when creating the tx, and we want Armory to later associate 
      that comment with the final transaction.  For each transaction
      in the ledger, we will look for both the "Full" and "Mall" version
      of the transaction ID (if available).  
      """
      self.setComment(txidFull, txidMall, comment)

   #############################################################################
   def setComment(self, txidFull, txidMall, comment):
      self.txidFull =   '' if txidFull is None else txidFull[:]
      self.txidMall =   '' if txidMall is None else txidMall[:]
      self.uComment  = u'' if comment  is None else toUnicode(comment)

   #############################################################################
   def serialize(self):
      if [len(self.txidFull), len(self.txidMall)] = [0,0]:
         raise UninitializedError('TxComm is not associated with any tx')

      bp = BinaryPacker()
      bp.put(VAR_STR,      self.txidFull)
      bp.put(VAR_STR,      self.txidMall)
      bp.put(VAR_UNICODE,  self.uComment)
      return bp.getBinaryString()

   #############################################################################
   def unserialize(self, theStr):
      bu = makeBinaryUnpacker(theStr)
      self.txidFull = bu.get(VAR_STR)
      self.txidMall = bu.get(VAR_STR)
      self.uComment = bu.get(VAR_UNICODE)
      return self


################################################################################
################################################################################
class ArmoryFileHeader(object):
  
   WALLETMAGIC = '\xffARMORY\xff'
   HEADERSIZE  = 200

   #############################################################################
   def __init__(self):
      # Note, we use a different fileID than wallet 1.35 so that older versions
      # of Armory don't attempt to load the 2.0 wallets
      LOGDEBUG('Creating file header')
      self.flags         = BitSet(32)
      self.createTime    = UINT64_MAX
      self.createBlock   = UINT32_MAX
      self.rsecParity    = RSEC_PARITY_BYTES
      self.rsecPerData   = RSEC_PER_DATA_BYTES
      self.isDisabled      = True


      # Identifies whether this file is intended to be used as a full wallet,
      # or perhaps holds metadata or transient data for some other operation
      self.isTransferWallet = False
      self.isSupplemental = False


   
   #############################################################################
   def initialize(self, *args):
      raise NotImplementedError

   #############################################################################
   def serializeHeaderData(self):
      """
      We leave a lot of extra space in header for future expansion, since
      header data is always up front, it's always got to be the same size.

      We hardcode RSEC sizes here, because we can't have the RSEC size vars
      protected by an RSEC code specified by that size (circular reference).
      So we use a blanket 16 bytes of parity for 1024 bytes of data.
      """
      self.flags.reset()
      self.flags.setBit(0, self.isTransferWallet)
      self.flags.setBit(1, self.isSupplemental)
      
      hdata = BinaryPacker()
      hdata.put(BINARY_CHUNK,    ArmoryFileHeader.WALLETMAGIC, width=8)
      hdata.put(UINT32,          getVersionInt(ARMORY_WALLET_VERSION))
      hdata.put(BINARY_CHUNK,    MAGIC_BYTES,           width=4)
      hdata.put(BITSET,          self.flags,            width=4)
      hdata.put(UINT64,          self.createTime)      
      hdata.put(UINT32,          self.createBlock)      
      hdata.put(UINT32,          self.rsecParity)
      hdata.put(UINT32,          self.rsecPerData)

      sizeRemaining = ArmoryFileHeader.HEADERSIZE - hdata.getSize()
      hdata.put(BINARY_CHUNK,    '\x00'*sizeRemaining)

      rsparity = createRSECCode(hdata.getBinaryString(), 16, 1024)
      hdata.put(BINARY_CHUNK, rsparity,  16)


   #############################################################################
   @staticmethod
   def Unserialize(theStr):
      """
      The header data is not so important for being stored, as much as it is
      simply reading it and checking that this is really an 2.0 wallet, for
      the correct network, of the correct version.
      """
      afh = ArmoryFileHeader()
      toUnpack = makeBinaryUnpacker(theStr)
      hdata   = toUnpack.read(ArmoryFileHeader.HEADERSIZE)
      rsecPar = toUnpack.read(16)

      hunpack = makeBinaryUnpacker(hdata)
      wltMagic   = hunpack.get(BINARY_CHUNK, 8)
      versionInt = hunpack.get(UINT32)
      netMagic   = hunpack.get(BINARY_CHUNK, 4)
      wltFlags   = hunpack.get(BITSET,       4)
      timeCreate = hunpack.get(UINT64)
      blkCreate  = hunpack.get(UINT32)
      rsecParity = hunpack.get(UINT32)
      rsecPerData= hunpack.get(UINT32)
      # These last two vars tell us what all the OTHER wallet entries will be
      # using for RS error correction.  For the header entry itself, it's
      # hardcoded to be 16 bytes per 1024.

      if not fileID==ArmoryFileHeader.WALLETMAGIC:
         if not fileID=='\xbaWALLET\x00':
            LOGERROR('The wallet file does not have the correct magic bytes')
            raise FileExistsError('This does not appear to be an Armory wallet')
         else:
            LOGERROR('You attempted to load an Armory 1.35 wallet!  Must use'
                     'Armory version 0.92 or ealier to do this, or use the '
                     'migration tool to convert it to the new format.')
            raise FileExistsError('Old Armory wallet, it must be migrated!')
         
   
      hdata,failFlag,modFlag = checkRSECCode(hdata, rsecCode)
      if failFlag:
         LOGERROR('Header data was corrupted, or not an Armory wallet')
         afh.isDisabled = True
         return afh

      if not magicbytes==MAGIC_BYTES:
         LOGERROR('This wallet is for the wrong network!')
         LOGERROR('   Wallet is for:  %s ', BLOCKCHAINS[magicbytes])
         LOGERROR('   You are on:     %s ', BLOCKCHAINS[MAGIC_BYTES])
         raise NetworkIDError('Wallet is for wrong network!')

      if not armoryVer==getVersionInt(ARMORY_WALLET_VERSION):
         LOGWARN('This wallet is for an older version of Armory!')
         LOGWARN('Wallet version: %d', armoryVer)
         LOGWARN('Armory version: %d', getVersionInt(ARMORY_WALLET_VERSION))


      if [rsecParity, rsecPerData] != [RSEC_PARITY_BYTES, RSEC_PER_DATA_BYTES]:
         # Technically, we could make all wallet code accommodate dynamic
         # RSEC parameters, but it would add some complexity for something
         # that shouldn't be necessary
         LOGERROR('This wallet uses different Reed-Solomon error correction'
                  'parameters than this version of Armory')
         afh.isDisabled = True
         return afh

      afh.initialize(flags)
      return afh
     

   #############################################################################
   @staticmethod
   def Unserialize(theStr):
      afh = ArmoryFileHeader()

      toUnpack = makeBinaryUnpacker(theStr)

      headerData    = toUnpack.get(BINARY_CHUNK, ArmoryFileHeader.HEADERSIZE)
      rsecCodeSize  = toUnpack.get(UINT32)
      rsecCode      = toUnpack.get(BINARY_CHUNK, rsecCodeSize)
      zeros         = toUnpack.get(BINARY_CHUNK, 64-rsecCodeSize)
      if not zeros.count('\x00')==len(zeros):
         raise UnpackerError('Empty space/padding as non-zero bytes')

      rsecData,failFlag,modFlag = checkRSECCode(rsecData, rsecCode)

      hunpack = BinaryUnpacker(headerData)
      fileID      = hunpack.get(BINARY_CHUNK, 8)
      armoryVer   = hunpack.get(UINT32)
      magicbytes  = hunpack.get(BINARY_CHUNK, 4)
      flagsInt    = hunpack.get(UINT32)

      
      if not fileID==ArmoryFileHeader.WALLETMAGIC:
         if not fileID=='\xbaWALLET\x00':
            LOGERROR('The wallet file does not have the correct magic bytes')
            raise FileExistsError('This does not appear to be an Armory wallet')
         else:
            LOGERROR('You attempted to load an Armory 1.35 wallet!  Must use'
                     'Armory version 0.92 or ealier to do this, or use the '
                     'migration tool to convert it to the new format.')
            raise FileExistsError('Old Armory wallet, it must be migrated!')
         

      if not magicbytes==MAGIC_BYTES:
         LOGERROR('This wallet is for the wrong network!')
         LOGERROR('   Wallet is for:  %s ', BLOCKCHAINS[magicbytes])
         LOGERROR('   You are on:     %s ', BLOCKCHAINS[MAGIC_BYTES])
         raise NetworkIDError('Wallet is for wrong network!')

      if not armoryVer==getVersionInt(ARMORY_WALLET_VERSION):
         LOGWARN('This wallet is for an older version of Armory!')
         LOGWARN('Wallet version: %d', armoryVer)
         LOGWARN('Armory version: %d', getVersionInt(ARMORY_WALLET_VERSION))


      if [rsecParity, rsecPerData] != [RSEC_PARITY_BYTES, RSEC_PER_DATA_BYTES]:
         # Technically, we could make all wallet code accommodate dynamic
         # RSEC parameters, but it would add some complexity for something
         # that shouldn't be necessary
         LOGERROR('This wallet uses different Reed-Solomon error correction'
                  'parameters than this version of Armory')
         afh.isDisabled = True
         return afh

      
      afh.initialize(flags, timeCreate, blkCreate)
      return afh






################################################################################
class ArbitraryDataContainer(WalletEntry):
   FILECODE = 'ARBDATA_'
   def __init__(self):
      pass




# We should have all the classes availale by now, we can add the 
# class list to the WalletEntry static members
ISREQUIRED=True
WalletEntry.RegisterWalletStorageClass(AddressLabel)
WalletEntry.RegisterWalletStorageClass(TxLabel)
WalletEntry.RegisterWalletStorageClass(MultiSigLockbox)
WalletEntry.RegisterWalletStorageClass(EncryptionKey)
WalletEntry.RegisterWalletStorageClass(MultiPwdEncryptionKey)
WalletEntry.RegisterWalletStorageClass(KdfObject)
WalletEntry.RegisterWalletStorageClass(IdentityPublicKey)
WalletEntry.RegisterWalletStorageClass(WltEntrySignature)
WalletEntry.RegisterWalletStorageClass(ArbitraryDataContainer)

