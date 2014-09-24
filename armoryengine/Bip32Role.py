from ArmoryUtils import *
from ArmoryWallet import *

UINT32_TOPBIT = 0x80000000
UINT31_MASK   = 0x7fffffff
SplitChildIndex = lambda c: [int(c & UINT31_MASK), (c & UINT32_TOPBIT) > 0]

################################################################################
class Bip32Role(object):

   def getChildRole(self, index):
      raise NotImplementedError

   #def childIsHardened(self):
      #raise NotImplementedError

   def isLeaf(self):
      raise NotImplementedError

   def getRoleName(self):
      return self.__class__.__name__




################################################################################
class Bip44RootRole(Bip32Role):
   def getChildRole(self, index):
      idx,hard = SplitChildIndex(index)
      if index==44 and hard:
         return Bip44PurposeRole
      else:
         raise NotImplementedError("No roles other than 44' (0x2c') allowed!")

   #def childIsHardened(self):
      #return True

   def isLeaf(self):
      return False


################################################################################
class StdBip32RootRole(Bip32Role):
   def getChildRole(self, index):
      idx,hard = SplitChildIndex(index)
      if hard:
         return StdBip32WalletRole
      else:
         raise NotImplementedError("Must use hardened derivation!")


   def isLeaf(self):
      return False


################################################################################
class Bip44PurposeTreeNode(Bip32Role):
   def getChildRole(self, index):
      idx,hard = SplitChildIndex(index)
      expectedIdx = 1 if USE_TESTNET else 0
      if index==expectedIdx and hard:
         return Bip44BitcoinRole
      else:
         raise NotImplementedError("No roles other than %d' (0x%s)' allowed" % \
                                                      idx, int_to_hex(idx))

   def isLeaf(self):
      return False



################################################################################
class Bip44BitcoinTreeNode(Bip32Role):
   def getChildRole(self, index):
      idx,hard = SplitChildIndex(index)
      if hard:
         return StdBip32WalletRole
      else:
         raise NotImplementedError("Must use hardened derivation!")


   def isLeaf(self):
      return False



################################################################################
class StdBip32WalletTreeNode(Bip32Role):
   def getChildRole(self, index):
      idx,hard = SplitChildIndex(index)
      if hard:
         raise NotImplementedError("Must use non-hardened derivation!")
      elif idx%2==0:
         return StdBip32ExternalChainRole
      else:
         return StdBip32InternalChainRole
         

   def isLeaf(self):
      return False

################################################################################
class StdBip32ExternalChainRole(Bip32Role):
   def getChildRole(self, index):
      return StdBip32LeafRole
         
   def isLeaf(self):
      return False


################################################################################
class StdBip32InternalChainRole(Bip32Role):
   def getChildRole(self, index):
      return StdBip32LeafRole
         
   def isLeaf(self):
      return False


################################################################################
class StdBip32LeafRole(Bip32Role):

   def getChildRole(self, index):
      return None

   def isLeaf(self):
      return True



