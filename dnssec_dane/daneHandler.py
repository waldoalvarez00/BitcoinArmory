################################################################################
#                                                                              #
# Copyright (C) 2011-2015, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################

#from armoryengine.ArmoryUtils import UNINITIALIZED, UnitializedBlockDataError, \
#   hash256, LITTLEENDIAN, BIGENDIAN, binary_switchEndian, binary_to_hex, \
#   binaryBits_to_difficulty
#import getdns
from armoryengine.ArmoryUtils import binary_to_hex # WRONG?
from armoryengine.ConstructedScript import PublicKeySource, ConstructedScript, \
   ScriptRelationshipProof, PublicKeyRelationshipProof, BTCAID_PR_VERSION, \
   BTCAID_PAYLOAD_TYPE
from CppBlockUtils import HDWalletCrypto

PKS1NoChksum_Comp_v0 = hex_to_binary(
   "00000221 03cbcaa9 c98c877a 26977d00 825c956a 238e8ddd fbd322cc e4f74b0b"
   "5bd6ace4 a7")
CS1Chksum_Uncomp_v0 = hex_to_binary(
   "00000206 76a9ff01 88ac0145 00000441 04cbcaa9 c98c877a 26977d00 825c956a"
   "238e8ddd fbd322cc e4f74b0b 5bd6ace4 a77bd330 5d363c26 f82c1e41 c667e4b3"
   "561c06c6 0a2104d2 b548e6dd 059056aa 51142038 ce")

# Insert later.
#   finalPubKey = HDWalletCrypto().getChildKeyFromOps_SWIG(startPubKey,
#                                                          multProofObj.rawMultList)


# Function that takes a wallet ID payment request and validates it. This is the
# entry function that launches all the steps required to regenerate all the
# TxOut scripts for the requested payment.
#
# INPUT:  A PaymentRequest object received from elsewhere.
# OUTPUT: None
# RETURN: The 
def validatePaymentRequest(inPayReq):
   ctr = 0

   # Use the number of TxOut requests as our guide. The number of list entries
   # MUST match the number of TxOut requests. If they don't, something's wrong.
   # Also, while we're here, let's go ahead and check for all other fatal errors.
   if inPayReq.version != BTCAID_PR_VERSION:
      print 'Uh oh!'
   elif inPayReq.numTxOutScripts > 65535:
      print 'Uh oh!'
   elif inPayReq.reqSize > 65535:
      print 'Uh oh!'
   elif inPayReq.numTxOutScripts != len(inPayReq.unvalidatedScripts):
      print 'Uh oh!'
   elif inPayReq.numTxOutScripts != len(inPayReq.daneReqNames):
      print 'Uh oh!'
   elif inPayReq.numTxOutScripts != len(inPayReq.srpLists):
      print 'Uh oh!'
   else:
      while ctr < inPayReq.numTxOutScripts:
         # Get the DANE record.
         # HACK ALERT: This call is a hack for now. Will change very soon.
         recType, daneReq = getDANERecord(inPayReq.daneRecName[ctr],
                                          'ConstructedScript')

         # Have the record type recreate the script. If we receive a PKS, assume
         # a P2PKH record must be created. If we receive a CS, generate whatever
         # resides in the CS.
         # NOTE: The return record type can vary, all types must have the same
         # function and function prototype!
         finalKey = None
         finalScript = None
         if recType == BTCAID_PAYLOAD_TYPE.InvalidRec:
            print 'Uh oh!'
         else:
            if recType == BTCAID_PAYLOAD_TYPE.PublicKeySource:
               # Get key and then generate a P2PKH TxOut script from it.
               finalKey = daneReq.generateScript(inPayReq.srpLists[ctr])
            elif recType == BTCAID_PAYLOAD_TYPE.ConstructedScript:
               finalScript = daneReq.generateScript(inPayReq.srpLists[ctr])

         # We're done.
         ctr += 1


# Function that obtains a DANE record for a given record name.
# WARNING: For now, this is a placeholder that will return one of two pre-built
# records. Once proper DNS code has been written, actual records will be pulled
# down. The logic will be as follows:
# - Use getdns-python-bindings to get the DANE record for the given name.
# - Process the DANE header (TBD) as needed. This will include information like
#   the payment network, the wallet ID record type (PKS or CS), etc.
# - Pass back the wallet ID record type and a value indicating the record type.
#
# INPUT:  The DANE record name (string) and a byte indicating if a PKS or CS
#         record is desired (BTCA_PAYLOAD_TYPE - TEMPORARY - ONLY USED BY
#         PLACEHOLDER CODE)
# OUTPUT: None
# RETURN: An enum indicating the returned record type, and the returned record.
def getDANERecord(daneRecName, desiredRecType):
   retType = BTCAID_PAYLOAD_TYPE.InvalidRec
   retRec = None

   # THIS CODE WILL BE REPLACED WITH PROPER DNS CODE EVENTUALLY!!!
   if desiredRecType eq BTCAID_PAYLOAD_TYPE.PublicKeySource:
      retRec = PKS1NoChksum_Comp_v0
      retType = BTCAID_PAYLOAD_TYPE.PublicKeySource
   elif desiredRecType eq BTCAID_PAYLOAD_TYPE.ConstructedScript:
      retRec = CS1NoChksum_Comp_v0
      retType = BTCAID_PAYLOAD_TYPE.ConstructedScript
   else:
      print 'Wrong BTCA record type requested.'

   return retType, retRec
