from ArmoryUtils import *
from BinaryPacker import *
from BinaryUnpacker import *


# Wallets will have to be regenerated if this is changed
RSEC_PARITY_BYTES   = 16
RSEC_PER_DATA_BYTES = 1024


################################################################################
def createRSECCode(data, rsecBytes=RSEC_PARITY_BYTES, 
                         perDataBytes=RSEC_PER_DATA_BYTES):
   """
   Returns default of 16 bytes of parity per 1024 bytes of input.  
   If the input is, say 2500 bytes, then we will have 48 bytes of 
   parity, 16 for the first 1024, 16 for the next 1024, and 16 for
   the last 452.
   """
   parity = []
   nChunk = (data-1)/perDataBytes + 1
   for i in range(nChunk):
      byte0, byte1 = i*perDataBytes, (i+1)*perDataBytes
      parity.append(Cpp.GetParityBytes(data[byte0:byte1], rsecBytes))
   return ''.join(parity)


################################################################################
def checkRSECCode(data, parity):
   """
   Returns:
      data:  input after error correction
      bool:  data failed correction, invalid
      bool:  data was modified

   If parity is all zero bytes, then we ignore it and return the data as-is.
   """

   if len(parity)==parity.count('\x00'):
      # Parity is NULL, ignore it and return the input
      return data, False, False
   else:
      # Parity bytes are non-zero, check for (and correct) errors, if possible
      correctData = CheckRSErrorCorrect(data, parity)
      if len(correctData) == 0:
         return '', True, False
      elif correctData==data:
         return correctData, False, False
      else:
         return correctData, False, True
     





