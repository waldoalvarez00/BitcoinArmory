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
from ArmoryKeyPair import *
from Timer import *

################################################################################
class AddressLabel(WalletEntry):
  
   FILECODE = 'ADDRLABL' 

   def __init__(self):
      super(AddressLabel, self).__init__()
      self.scrAddr = None
      self.label   = None

   def initialize(self, scrAddrStr=None, lbl=None):
      self.scrAddr = scrAddrStr
      self.label   = toUnicode(lbl)
      

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
   def __init__(self):
      super(TxLabel, self).__init__()
      self.txidFull = ''
      self.txidMall = ''
      self.uComment = u''

   #############################################################################
   def initialize(self, txidFull, txidMall, comment):
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
      self.txidFull =   '' if txidFull is None else txidFull[:]
      self.txidMall =   '' if txidMall is None else txidMall[:]
      self.uComment  = u'' if comment  is None else toUnicode(comment)

   #############################################################################
   def serialize(self):
      if len(self.txidFull) + len(self.txidMall) == 0:
         raise UninitializedError('Tx label is not associated with any tx')

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





WalletEntry.RegisterWalletStorageClass(AddressLabel)
WalletEntry.RegisterWalletStorageClass(TxLabel)
WalletEntry.RegisterWalletStorageClass(ArbitraryDataBlob)

