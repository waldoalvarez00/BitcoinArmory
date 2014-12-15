################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
from ArmoryUtils import *
from Script import *


BTCID_PAYLOAD_VERSION = (0, 1, 0, 0)
BTCID_PAYLOAD_TYPE = enum('KeySource', 'ConstructedScript')
ESCAPECHAR  = '\xff'
ESCESC      = '\x00'

BTCID_PAYLOAD_BYTE = { \
   BTCID_PAYLOAD_TYPE.KeySource:       '\x00',
   BTCID_PAYLOAD_TYPE.ConstructedScript:  '\x01' }


class VersionError(Exception): pass

try:
   # Normally the decorator simply confirms that function arguments
   # are of the expected type.  Will throw an error if not defined.
   VerifyArgTypes
except:
   # If it's not available, just make a replacement decorator that does nothing
   def VerifyArgTypes(*args, **kwargs):
      def decorator(func):
         return func
      return decorator

def makeBinaryUnpacker(inputStr):
   """
   Use this on input args so that unserialize funcs can treat the
   input as a BU object.  If it's not a BU object, convert it, and
   the consumer method will start reading from byte zero.  If it
   is BU, then forward the reference to it so that it starts unserializing
   from the current location in the BU object, leaving the position
   after the data was unserialized.
   """
   if isinstance(inputStr, BinaryUnpacker):
      # Just return the input reference
      return inputStr  
   else:
      # Initialize a new BinaryUnpacker
      return BinaryUnpacker(inputStr)



################################################################################
class PublicKeySource(object):
   """
   This defines a "source" from where we could get a public key, either to be 
   inserted directly into P2PKH, or to be used as part of a multi-sig or other
   non-standard script. 

   @isStatic:     rawSource is just a single public key
   @useCompr:     use compressed or uncompressed version of pubkey
   @useHash160:   pubKey should be hashed before being inserted into a script
   @isStealth:    rawSource is intended to be used as an sx address
   @isUserKey:    user should insert their own key in this slot
   @useExternal:  rawSource is actually a link to another pubkey source
   """

   #############################################################################
   def __init__(self):
      self.version        = BTCID_PAYLOAD_VERSION
      self.isStatic       = False
      self.useCompressed  = False
      self.useHash160     = False
      self.isStealth      = False
      self.isUserKey      = False
      self.isExternalSrc  = False
      self.rawSource      = None


   #############################################################################
   def getFingerprint(self):
      return hash256(self.rawSource)[:4]


   #############################################################################
   @VerifyArgTypes(isStatic = bool, 
                   useCompr = bool, 
                   use160   = bool,
                   isSx     = bool,
                   isUser   = bool,
                   isExt    = bool,
                   src      = [str, unicode],
                   ver      = [tuple, None])
   def initialize(self, isStatic, useCompr, use160, isSx, isUser, isExt, src, ver=None):
      """
       
      """

      # We expect regular public key sources to be binary strings, but external
      # sources may be similar to email addresses which need to be unicode
      if isExt != isinstance(src, unicode):
         raise UnicodeError('Must use str for reg srcs, unicode for external')

      self.version       = ver[:] if ver else BTCID_PAYLOAD_VERSION
      self.isStatic      = isStatic
      self.useCompressed = useCompr
      self.useHash160    = use160
      self.isStealth     = isSx
      self.isUserKey     = isUser
      self.isExternalSrc = isExt
      self.rawSource     = toBytes(src)  

         

   #############################################################################
   def isInitialized(self):
      return not (self.rawSource is None or len(self.rawSource) == 0)


   #############################################################################
   def getRawSource(self):
      """
      If this is an external source, then the rawSource might be a unicode
      string.  If it was input as unicode, it was converted into this data
      structure using toBytes(), so we'll return it using toUnicode()
      """
      if self.isExternalSrc:
         return toUnicode(self.rawSource)
      else:
         return self.rawSource


   #############################################################################
   def serialize(self):
      flags = BitSet(16)
      flags.setBit(0, self.isStatic)
      flags.setBit(1, self.useCompressed)
      flags.setBit(2, self.useHash160)
      flags.setBit(3, self.isStealth)
      flags.setBit(4, self.isUserKey)
      flags.setBit(5, self.isExternalSrc)

      inner = BinaryPacker()
      inner.put(UINT32,   getVersionInt(self.version))
      inner.put(BITSET,   flags, widthBytes=4)
      inner.put(VAR_STR,  self.rawSource)
      pkData = inner.getBinaryString()

      chksum = computeChecksum(pkData, 4)

      bp = BinaryPacker()
      bp.put(VAR_STR, pkData)
      bp.put(BINARY_CHUNK, chksum)
      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, serData):
      bu = makeBinaryUnpacker(serData)
      pkData = bu.get(VAR_STR)
      chksum = bu.get(BINARY_CHUNK, 4)

      # verify func returns the up-to-one-byte-corrected version of the input
      pkData = verifyChecksum(pkData, chksum)
      if len(pkData) == 0:
         raise UnserializeError('Error correction on key data failed')

      inner  = BinaryUnpacker(pkData)
      ver    = bu.get(UINT32)
      flags  = bu.get(BITSET, 2)
      rawSrc = bu.get(VAR_STR)

      if not readVersionInt(ver) == BTCID_PAYLOAD_VERSION:
         # In the future we will make this more of a warning, not error
         raise VersionError('BTCID version does not match the loaded version')

      self.__init__()
      self.initialize(self, flags.getBit(0),
                            flags.getBit(1), 
                            flags.getBit(2), 
                            flags.getBit(3), 
                            flags.getBit(4), 
                            flags.getBit(5), 
                            rawSrc,  
                            ver=ver)

      return self


################################################################################
class ExternalPublicKeySource(object):
   raise NotImplementedError('Have not implemented external sources yet')



################################################################################
class ConstructedScript(object):
   def __init__(self):
      self.version        = BTCID_PAYLOAD_VERSION
      self.scriptTemplate = None
      self.pubKeySrcList  = None
      self.useP2SH        = None
      self.pubKeyBundles  = []

   
   #############################################################################
   @VerifyArgTypes(scrTemp  = str, 
                   pubSrcs  = [list, tuple], 
                   useP2sh  = bool,
                   ver      = [tuple, None])
   def initialize(self, scrTemp, pubSrcs, useP2SH, ver=None):
      
      self.version        = ver[:] if ver else BTCID_PAYLOAD_VERSION
      self.useP2SH        = useP2SH
      self.pubKeyBundles  = []

      self.setTemplateAndPubKeySrcs(scrTemp, pubSrcs)

      
   
   def readTemplateAndPubKeySrcs(self, scrTemp, pubSrcs):
      """ 
      Inputs:
         scrTemp:  script template  (ff-escaped)
         pubSrcs:  flat list of PublicKeySource objects

   
      Outputs:
         Sets member vars self.scriptTemplate and self.pubKeyBundles 
         pubkeyBundles will be a list-of-lists as described below.


      Let's say we have a script template like this: this is a non-working
      2-of-3 OR 3-of-5, with the second key list sorted)

      OP_IF 
         OP_2 0xff01 0xff01 0xff01 OP_3 OP_CHECKMULTISIG 
      OP_ELSE 
         OP_3 0xff05 OP_5 OP_CHECKMULTISIG
      OP_ENDIF

      We have 4 public key bundles: first three are of size 1, the last is 5.
      In this script, the five keys in the second half of the script are sorted
      We should end up with:  
   
      Final result sould look like:

             [ [PubSrc1], [PubSrc2], [PubSrc3], [PubSrc4, PubSrc5, ...]]
                   1          2          3       <--------- 4 -------->
      """ 
      cs = ConstructedScript()

      if '\xff\xff' in scrTemp or scrTemp.endswith('\xff'):
         raise BadInputError('All 0xff sequences need to be properly escaped')

      # The first byte after each ESCAPECHAR is number of pubkeys to insert.
      # ESCAPECHAR+'\x00' is interpretted as as single
      # 0xff op code.  i.e.  0xff00 will be inserted in the final 
      # script as a single 0xff byte (which is OP_INVALIDOPCODE).   For the 
      # purposes of this function, 0xff00 is ignored.
      # 0xffff should not exist in any script template
      scriptPieces = scrTemp.split(ESCAPECHAR)

      # Example after splitting:
      # 76a9ff0188acff03ff0001 would now look like:  '76a9' '0188ac' '03', '0001']
      #                                                      ^^       ^^    ^^
      #                                                  ff-escaped chars
      # We want this to look like:                   '76a9',  '88ac',  '',   '01'
      #        with escape codes:                           01       03     ff
      #        with 2 pub key bundles                      [k0] [k1,k2,k3]
      # There will always be X script pieces and X-1 pubkey bundles

      # Get the first byte after every 0xff 
      breakoutPairs = [[pc[0],pc[1:]] for pc in scriptPieces[1:]]
      escapedBytes  = [binary_to_int(b[0]) for b in breakout if b[0]]
      scriptPieces  = [scriptPieces[0]] + [b[1] for b in bundleBytes]

      if sum(bundleSizes) != len(pubSrcs):
         raise UnserializeError('Template key count do not match pub list size')

      cs.scriptTemplate = scrTemp
      cs.pubKeySrcList  = pubSrcs[:]
      cs.pubKeyBundles  = []
      
      # Slice up the pubkey src list into the bundles
      idx = 0
      for sz in bundleSizes:
         cs.pubKeyBundles.append( cs.pubKeySrcList[idx:idx+sz] )
         idx += sz
      
      



   #############################################################################
   @staticmethod
   def StandardP2PKHConstructed(binRootPubKey):
      if not len(binRootPubKey) in [33,65]:
         raise KeyDataError('Invalid pubkey;  length=%d' % len(binRootPubKey))

      templateStr = hex_to_binary("76a9" "ff01" "88ac")
      
      pks = PublicKeySource()
      pks.initialize(isStatic=False, 
                     useCompr=(len(binRootPubKey)==33), 
                     use160=True, 
                     isSx=False, 
                     isUser=False, 
                     isExt=False, 
                     src=binRootPubKey)

      cs = ConstructedScript()
      cs.initialize(self, templateStr, [pks], False)
      return cs

   #############################################################################
   @staticmethod
   def StandardMultisigConstructed(M, binRootList):
      for pk in binRootList:
         if not len(pk) in [33,65]:
            raise KeyDataError('Invalid pubkey;  length=%d' % len(pk))

      N = len(binRootList)
      escN = int_to_binary(N)
      op_M = int_to_binary(80+M)
      op_N = int_to_binary(80+N)
      templateStr = hex_to_binary(op_M + 'ff'+escN + op_N + 'ae')
      
      
      pksList = []
      for rootPub in binRootList:
         pks = PublicKeySource()
         pks.initialize(isStatic=False, 
                        useCompr=(len(binRootPubKey)==33), 
                        use160=False, 
                        isSx=False, 
                        isUser=False, 
                        isExt=False, 
                        src=rootPub)
         pksList.append(pks)
         

      cs = ConstructedScript()
      cs.initialize(self, templateStr, pksList, True)
      return cs


################################################################################
class MultiplierList(object):
   """
   Simply a list of 32-byte multipliers and the associated hash160 we expect
   after applying them to the root pub key.
   """

   #############################################################################
   def __init__(self, isNull=None, finger4=None, multList=None):
      self.isNull           = None   # If static, stealth, etc, no mult list 
      self.srcFingerprint4  = None   # just the first 4B of hash256(rootpub)
      self.rawMultList      = []     # list of 32-byte LE multipliers

      if isNull is not None:
         self.initialize(isNull, finger4, multList)


   #############################################################################
   def initialize(self, isNull=None, finger4=None, multList=None):
      self.isNull = isNull
      if isNull:
         self.srcFingerprint4  = None
         self.rawMultList      = []
      else:
         self.srcFingerprint4  = finger4
         self.rawMultList      = multList[:]

   
   #############################################################################
   def serialize(self):
      flags = BitSet(8)
      flags.setBit(0, self.isNull)

      bp = BinaryPacker()
      bp.put(BITSET, flags, widthBytes=1)

      if not self.isNull:
         bp.put(BINARY_CHUNK, self.srcFingerprint4, widthBytes= 4)
         bp.put(VAR_INT, len(self.rawMultList))
         for mult in self.rawMultList: 
            bp.put(BINARY_CHUNK,  mult,  widthBytes=32)

      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, serData):
      bu = makeBinaryUnpacker(serData)
      flags = bu.get(BITSET, 1)

      if flags.getBit(0):
         self.initialize(True)
      else:
         finger4B = bu.get(BINARY_CHUNK, 4)
         numMult  = bu.get(UINT8)
      
         multList = [] 
         for m in numMult:
            multList.append( bu.get(BINARY_CHUNK, 32))

         self.initialize(False, finger4B, multList)

      return self
  
      

   
   

################################################################################
class SignableIDPayload(object):
   """
   This datastructure wraps up all the other classes above into a single, 
   embeddable data type.  
   """
   def __init__(self):
      self.version     = None
      self.createDate  = None
      self.expireDate  = None
      self.payloadType = None  # KeySource or ConstructedScript
      self.payload     = None


   def initialize(self, template):
      self.rawTemplate = template

   def serialize(self):

   def unserialize(self, templateStr):
      bu = makeBinaryUnpacker(templateStr)
      
      oplist = []
      for c in 
      
      

################################################################################
def computeBip32PathWithProof(binPublicKey, binChaincode, indexList):
   """
   We will actually avoid using the higher level ArmoryKeyPair (AKP) objects
   for now, as they do a ton of extra stuff we don't need for this.  We go
   a bit lower-level and talk to CppBlockUtils.HDWalletCrypto directly.

   Inputs:
      binPublicKey:  python string, 33-byte compressed public key
      binChaincode:  python string, 32-byte chaincode 
      indexList:     python list of UINT32s, anything >0x7fffffff is hardened
   
   Output: [multiplierList, finalPublicKey]

      multiplierList:   The list of 32-byte multipliers that can be applied
                        to the input binPublicKey to produce the publicExtKeyObj
                        All multipliers passed out as python strings
      finalPublicKey:   pyton string:  33-byte compressed public key

   Note that an error will be thrown if any items in the index list correspond
   to a hardened derivation.  We need this proof to be generatable strictly
   from public key material.

   """
   
   # Sanity check the inputs
   if not len(binPublicKey)==33 or not binPublicKey[0] in ['\x02','\x03']:
      raise KeyDataError('Input public key is a valid format')
      
   if not len(binChaincode)==32:
      raise KeyDataError('Chaincode must be 32 bytes')

   # Crypto-related code uses SecureBinaryData and Cpp.ExtendedKey objects
   sbdPublicKey = SecureBinaryData(binPublicKey)
   sbdChainCode = SecureBinaryData(binChaincode)
   extPubKeyObj = Cpp.ExtendedKey(sbdPublicKey, sbdChainCode)

   # Prepare the output multiplier list
   self.multList = []

   # Derive the children
   for childIndex in indexList:
      if (childIndex & 0x80000000) > 0:
         raise ChildDeriveError('Cannot generate proofs along hardened paths')
                      
      # Pass in a NULL SecureBinaryData object as a reference
      sbdMultiplier = NULLSBD()

      # Computes the child and emits the multiplier via the last arg
      extPubKeyObj = Cpp.HDWalletCrypto().childKeyDeriv(extPubKeyObj, 
                                                        childIndex, 
                                                        sbdMultiplier)

      # Append multiplier to list
      self.multiplierList.append(sbdMultiplier.toBinStr())
                      
   return self.multiplierList, extPubKeyObj.getPublicKey().toBinStr()



