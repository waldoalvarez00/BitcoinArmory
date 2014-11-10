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
BTCID_PAYLOAD_TYPE = enum('PubKeySource', 'RawScript', 'ConstructedScript')
ESCAPECHAR = '\xff'

BTCID_PAYLOAD_BYTE = { \
   BTCID_PAYLOAD_TYPE.PubKeySource:       '\x00',
   BTCID_PAYLOAD_TYPE.RawScript:          '\x01',
   BTCID_PAYLOAD_TYPE.ConstructedScript:  '\x02' }


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
   @useExternal:  rawSource is actually a link to another pubkey source
   """

   #############################################################################
   def __init__(self):
      self.version        = BTCID_PAYLOAD_VERSION
      self.isStatic       = False
      self.useCompressed  = False
      self.useHash160     = False
      self.isStealth      = False
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
                   isExt    = bool,
                   src      = [str, unicode],
                   ver      = [tuple, None])
   def initialize(self, isStatic, useCompr, use160, isSx, isExt, src, ver=None):
      """
      
      """

      # We expect regular public key sources to be binary strings, but external
      # sources may be similar to email addresses which need to be unicode
      if isExt != isinstance(src, unicode):
         raise UnicodeError('Must use str for reg srcs, unicode for external')

      self.ver           = ver[:] if ver else BTCID_PAYLOAD_VERSION
      self.isStatic      = isStatic
      self.useCompressed = useCompr
      self.useHash160    = use160
      self.useStealth    = isSx
      self.isExternalSrc = isExt
      self.rawSource     = toBytes(src)  

         

   #############################################################################
   def isInitialized(self):
      return not (self.rawSource is None or len(self.rawSource) == 0)

   #############################################################################
   def getRawSource(self):
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
      flags.setBit(4, self.isExternalSrc)

      bp = BinaryPacker()
      bp.put(UINT32, getVersionInt(self.version))
      bp.put(BITSET,   flags, widthBytes=2)
      bp.put(VAR_STR,  self.rawSource)
      return bp.getBinaryString()


   #############################################################################
   def unserialize(self, serData):
      bu = BinaryUnpacker(serData)
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
                            rawSrc,  
                            ver=ver)

      return self


################################################################################
class ExternalPublicKeySource(object):
   def 


################################################################################
class MultiplierList(object):
   """
   Simply a list of 32-byte multipliers and the associated hash160 we expect
   after applying them to the root pub key.
   """

   #############################################################################
   def __init__(self):
      self.isNull           = None   # If static, stealth, etc, no mult list 
      self.srcFingerprint4  = None   # just the first 4B of hash256(rootpub)
      self.finalPubHash160  = None   # full hash160 of the expected final key
      self.rawMultList      = None   # full hash160 of the expected final key
  
      
   #############################################################################
   @VerifyArgTypes(isNull   =  bool,
                   finger4  = [str, None]
                   pub160   = [str, None]
                   multList = [list, None],
                   version  = [tuple, None])
   def initialize(self, isNull, finger4=None, pub160=None, multList=None,
                                                              version=None):

      self.version = version[:] if version else BTCID_PAYLOAD_VERSION
      if isNull:
         self.isNull = isNull
         return

      self.srcFingerprint4  = finger4
      self.finalPubHash160  = finalPub160
      self.rawMultList      = multList[:]

   
   

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
      self.payloadType = None  # PubKeySource, RawScript, or ConstructedScript
      self.payload     = None


   def initialize(self, template):
      self.rawTemplate = template

   def serialize(self):

   def unserialize(self, templateStr):
      
      toUnpack = templateStr
      oplist = []
      for c in 
      
      

################################################################################
class EmbeddedIDRecord(object):
   """
   This datastructure wraps up all the other classes above into a single, 
   embeddable data type.  Perhaps for embedding and querying via DANE.
   """
   def __init__(self):
      self.payloadMap = {}  # embed a different payloads for each versions
   







