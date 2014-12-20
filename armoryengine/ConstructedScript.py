################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
from ArmoryUtils import *
from BinaryPacker import *
from BinaryUnpacker import *
from Transaction import getOpCode
from ArmoryEncryption import NULLSBD
from CppBlockUtils import HDWalletCrypto


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

#############################################################################
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
   def __init__(self):
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


   #############################################################################
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
      """
      Standard Pay-to-public-key-hash script
      """

      if not len(binRootPubKey) in [33,65]:
         raise KeyDataError('Invalid pubkey;  length=%d' % len(binRootPubKey))

      templateStr  = ''
      templateStr += getOpCode('OP_DUP')
      templateStr += getOpCode('OP_HASH160')
      templateStr += '\xff\x01'
      templateStr += getOpCode('OP_EQUALVERIFY')
      templateStr += getOpCode('OP_CHECKSIG')

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
   # Check the hash160 call. There were 2 calls, one w/ Hash160 and one w/o.
   @staticmethod
   def StandardP2PKConstructed(binRootPubKey, hash160=False):
      """ This is bare pubkey, usually used with coinbases """
      if not len(binRootPubKey) in [33,65]:
         raise KeyDataError('Invalid pubkey;  length=%d' % len(binRootPubKey))

      templateStr  = ''
      templateStr += '\xff\x01'
      templateStr += getOpCode('OP_CHECKSIG')

      pks = PublicKeySource()
      pks.initialize(isStatic=False,
                     useCompr=(len(binRootPubKey)==33),
                     use160=hash160,
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
      if (not 0<M<=15) or (not 0<N<=15):
         raise BadInputError('M and N values must be less than 15')


      templateStr  = ''
      templateStr += getOpCode('OP_%d' % M)
      templateStr += '\xff' + int_to_binary(N, widthBytes=1)
      templateStr += getOpCode('OP_%d' % N)
      templateStr += getOpCode('OP_CHECKMULTISIG')

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


   #############################################################################
   @staticmethod
   def UnsortedMultisigConstructed(M, binRootList):
      """
      THIS PROBABLY WON'T BE USED -- IT IS STANDARD CONVENTION TO ALWAYS SORT!
      Consider this code to be here to illustrate using constructed scripts
      with unsorted pubkey lists.
      """
      for pk in binRootList:
         if not len(pk) in [33,65]:
            raise KeyDataError('Invalid pubkey;  length=%d' % len(pk))

      N = len(binRootList)
      if (not 0<M<=15) or (not 0<N<=15):
         raise BadInputError('M and N values must be less than 15')

      templateStr  = ''
      templateStr += getOpCode('OP_%d' % M)
      templateStr += '\xff\x01' * N
      templateStr += getOpCode('OP_%d' % N)
      templateStr += getOpCode('OP_CHECKMULTISIG')

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
class MultiplierProof(object):
   """
   Simply a list of 32-byte multipliers, and a 4-byte fingerprint of the key
   to which to apply them.  The four bytes isn't meant to be cryptographically
   strong, just to help reduce unnecessary computation.
   """

   #############################################################################
   def __init__(self, isNull=None, srcFinger4=None, dstFinger4=None,
                multList=None):
      self.isNull      = None   # If static, stealth, etc, no mult list 
      self.srcFinger4  = None   # just the first 4B of hash256(rootpub)
      self.dstFinger4  = None   # just the first 4B of hash256(rootpub)
      self.rawMultList = []     # list of 32-byte LE multipliers

      if isNull is not None:
         self.initialize(isNull, srcFinger4, dstFinger4, multList)


   #############################################################################
   def initialize(self, isNull=None, srcFinger4=None, dstFinger4=None,
                  multList=None):
      self.isNull = isNull
      if isNull:
         self.srcFinger4  = None
         self.dstFinger4  = None
         self.rawMultList = []
      else:
         self.srcFinger4  = srcFinger4
         self.dstFinger4  = dstFinger4
         self.rawMultList = multList[:]


   #############################################################################
   def serialize(self):
      flags = BitSet(8)
      flags.setBit(0, self.isNull)

      bp = BinaryPacker()
      bp.put(BITSET, flags, widthBytes=1)

      if not self.isNull:
         bp.put(BINARY_CHUNK, self.srcFinger4, widthBytes= 4)
         bp.put(BINARY_CHUNK, self.dstFinger4, widthBytes= 4)
         bp.put(VAR_INT, len(self.rawMultList))
         for mult in self.rawMultList:
            bp.put(BINARY_CHUNK,  mult,  widthBytes=32)

      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, serData):
      bu = makeBinaryUnpacker(serData)
      flags = bu.get(BITSET, 1)

      if flags.getBit(0):
         self.initialize(isNull=True)
      else:
         srcFinger4B = bu.get(BINARY_CHUNK, 4)
         dstFinger4B = bu.get(BINARY_CHUNK, 4)
         numMult  = bu.get(VAR_INT)

         multList = []
         for m in numMult:
            multList.append( bu.get(BINARY_CHUNK, 32))

         self.initialize(False, srcFinger4B, dstFinger4B, multList)

      return self


################################################################################
class SignableIDPayload(object):
   """
   This datastructure wraps up all the other classes above into a single,
   embeddable data type.
   """
   #############################################################################
   def __init__(self):
      self.version     = None
      self.createDate  = None
      self.expireDate  = None
      self.payloadType = None  # KeySource or ConstructedScript
      self.payload     = None


   #############################################################################
   def initialize(self, template):
      self.rawTemplate = template


   #############################################################################
   def serialize(self):
      pass


   #############################################################################
   def unserialize(self, templateStr):
      bu = makeBinaryUnpacker(templateStr)

      oplist = []

################################################################################
def DeriveBip32PublicKeyWithProof(startPubKey, binChaincode, indexList):
   """
   We will actually avoid using the higher level ArmoryKeyPair (AKP) objects
   for now, as they do a ton of extra stuff we don't need for this.  We go
   a bit lower-level and talk to CppBlockUtils.HDWalletCrypto directly.

   Inputs:
      startPubKey:   python string, 33-byte compressed public key
      binChaincode:  python string, 32-byte chaincode
      indexList:     python list of UINT32s, anything >0x7fffffff is hardened

   Output: [MultiplierProof, finalPubKey]

      proofObject:   MultiplierProof: list of 32-byte mults to be applied
                     to the input startPubKey to produce the finalPubKey
      finalPubKey:   pyton string:  33-byte compressed public key

   Note that an error will be thrown if any items in the index list correspond
   to a hardened derivation.  We need this proof to be generatable strictly
   from public key material.
   """

   # Sanity check the inputs
   if not len(startPubKey)==33 or not startPubKey[0] in ['\x02','\x03']:
      raise KeyDataError('Input public key is a valid format')

   if not len(binChaincode)==32:
      raise KeyDataError('Chaincode must be 32 bytes')

   # Crypto-related code uses SecureBinaryData and Cpp.ExtendedKey objects
   sbdPublicKey = SecureBinaryData(startPubKey)
   sbdChainCode = SecureBinaryData(binChaincode)
   extPubKeyObj = Cpp.ExtendedKey(sbdPublicKey, sbdChainCode)

   # Prepare the output multiplier list
   binMultList = []

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
      binMultList.append(sbdMultiplier.toBinStr())

   finalPubKey = extPubKeyObj.getPublicKey().toBinStr()
   proofObject = MultiplierProof(isNull=False,
                                srcFinger4=hash256(startPubKey)[:4],
                                dstFinger4=hash256(finalPubKey)[:4],
                                multList=binMultList)

   return finalPubKey, proofObject


################################################################################
def ApplyProofToRootKey(startPubKey, multProofObj, expectFinalPub=None):
   """
   Inputs:
      startPubKey:    python string, 33-byte compressed public key
      multProofObj:   MultiplierProof object
      expectFinalPub: Optionally provide the final pub key we expect

   Output: [MultiplierProof, finalPubKey]

      finalPubKey:    python string with resulting public key, will match
                      expectFinalPub input if supplied.

   Since we don't expect this to fail, KeyDataError raised on failure
   """
   if not hash256(startPubKey)[:4] == multProofObj.srcFinger4:
      raise KeyDataError('Source fingerprint of proof does not match root pub')

   
   finalPubKey = HDWalletCrypto().getChildKeyFromOps_SWIG(startPubKey,
                                                          multProofObj.rawMultList)


   if not hash256(finalPubKey)[:4] == multProofObj.dstFinger4:
      raise KeyDataError('Dst fingerprint of proof does not match root pub')

   if expectFinalPub and not finalPubKey==expectFinalPub:
      raise KeyDataError('Computation did not yield expected public key!')

   return finalPubKey


