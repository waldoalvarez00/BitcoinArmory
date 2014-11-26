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
      
   
   @staticmethod
   def setTemplateAndPubKeySrcs(self, scrTemp, pubSrcs):
      """ 
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

      # The first byte after each ESCAPECHAR is number of pubkeys to insert.
      # Repeated ESCAPECHAR+'\x00' bytes are interpretted as the respective 
      # (single) 0xff op code.  i.e.  0xff00 will be inserted in the final 
      # script as a single 0xff byte (which is OP_INVALIDOPCODE).   For the 
      # purposes of this function, 0xff00 is ignored.
      scriptPieces = scrTemp.split(ESCAPECHAR)
      bundleBytes  = [pc[0] for pc in scriptPieces[1:] if not pc[0]==ESCESC]
      bundleSizes  = [binary_to_int(b) for b in bundleBytes]

      if sum(bundleSizes) != len(pubSrcs):
         raise UnserializeError('Template key count do not match pub list size')

      self.scriptTemplate = scrTemp
      self.pubKeySrcList  = pubSrcs[:]
      self.pubKeyBundles  = []
      
      # Slice up the pubkey src list into the bundles
      idx = 0
      for sz in bundleSizes:
         self.pubKeyBundles.append( self.pubKeySrcList[idx:idx+sz] )
         idx += sz
      


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
      
      

   







