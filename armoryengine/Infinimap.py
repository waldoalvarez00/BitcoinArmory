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
from WalletEntry import WalletEntry


class MaxDepthExceeded(Exception): pass

################################################################################
class InfinimapNode(WalletEntry):
   FILECODE = 'ARBDATA_'
   def __init__(self, klist=None, data=None, parent=None):
      super(InfinimapNode, self).__init__()
      self.data     = data if data else ''
      self.keyList  = klist[:] if klist else []
      self.parent   = parent
      self.children = {}


   #############################################################################
   def getSelfKey(self):
      return '' if len(self.keyList) == 0 else self.keyList[-1]

      
      
   #############################################################################
   def pprintRecurse(self, indentCt=0, indentSz=3, keyJust=16):
      prInd  = indentCt * indentSz * ' '
      prKey  = self.getSelfKey().ljust(keyJust)
      prData = str(self.data) if self.data else ''
      print prInd + prKey + ': ' + prData
      for key,child in self.children.iteritems():
         child.pprintRecurse(indentCt+1, indentSz, keyJust)


   #############################################################################
   def getPathNodeRecurse(self, keyList, doCreate=False):
      # If size is zero, we're at the requested node
      if len(keyList) == 0:
         return self

      key = toBytes(keyList[0])
      childKeyList = self.keyList[:] + [key]

      if doCreate:
         # Always creating the next child seems inefficient, but the 
         # alternative is doing two map lookups.  We will revisit this
         # if there's a reason to make this container high-performance
         nextMaybeChild = InfinimapNode(childKeyList, '', self)
         nextNode = self.children.setdefault(key, nextMaybeChild)
         return nextNode.getPathNodeRecurse(keyList[1:], doCreate)
      else:
         nextNode = self.children.get(key)
         if nextNode is None:
            return None
         else: 
            return nextNode.getPathNodeRecurse(keyList[1:], doCreate)


   #############################################################################
   def applyToAllNodesRecurse(self, funcInputNode, topFirst=True):
      if topFirst:
         funcInputNode(self)

      for key,child in self.children.iteritems():
         child.applyToAllNodesRecurse(funcInputNode, topFirst)
      
      if not topFirst:
         funcInputNode(self)


   #############################################################################
   def recurseDelete(self):
      keysToDelete = []
      for key,child in self.children.iteritems():
         child.recurseDelete()
         keysToDelete.append(key)

      for key in keysToDelete:
         del self.children[key]

   #############################################################################
   def serialize(self):
      bp = BinaryPacker()
      if self.data is None:
         raise UninitializedError

      bp = BinaryPacker()
      bp.put(VAR_INT,  len(self.keyList))
      for k in self.keyList:
         bp.put(VAR_STR,  k)
      bp.put(VAR_STR, self.data)
      return bp.getBinaryString()


   #####
   def unserialize(self, theStr):
      klist = []

      bu = makeBinaryUnpacker(theStr)
      nkeys = bu.get(VAR_INT)
      for k in nkeys:
         klist.append( bu.get(VAR_STR) )
      data = bu.get(VAR_STR)

      self.initialize(klist, data)
      return self
         

   #####
   def linkWalletEntries(self, wltFileRef):
      pass
      


      

################################################################################
class Infinimap(object):
   """
   This class is used to hold a tree of arbitrary data.  Much like BIP32 
   key trees, this is [near-]infinite-dimensional, and data can be stored
   at any node.

      self.setData(['ColorData','Red'], obj)
      self.setData(['ColorData','Red', 'Comment'], 'I like red coins')
   """

   MAX_DEPTH = 32

   #############################################################################
   def __init__(self):
      self.root = InfinimapNode()

   #############################################################################
   @staticmethod
   def checkKeyList(keyList, data=None):
      listSize = len(keyList) 
      if listSize > Infinimap.MAX_DEPTH:
         raise MaxDepthExceeded('KeyList size/depth is %d' % listSize)

      for key in keyList:
         if not isinstance(key, str):
            raise KeyError('All keys in path must be reg strings, no unicode')

      if data and not isinstance(data, str):
         raise TypeError('Data for infinimap must be reg string, no unicode')
         


   #############################################################################
   def getData(self, keyList):
      self.checkKeyList(keyList)
      node = self.root.getPathNodeRecurse(keyList)
      return None if node is None else node.data
      
   #############################################################################
   def setData(self, keyList, theData, doCreate=True, warnIfDup=False):
      # By default we create the key path
      self.checkKeyList(keyList, theData)
      node = self.root.getPathNodeRecurse(keyList, doCreate=doCreate)
      if node is None:
         raise KeyError('Key path does not exist: %s' % keyList)

      if not isinstance(theData, str):
         raise TypeError('Data for infinimap must be reg string (no unicode)')

      if warnIfDup and len(node.data)>0:
         LOGWARN('Infinimap entry already has a value: %s,%s' % \
                                                (str(keyList0), node.data))

      node.data = theData if theData is not None else ''

   #############################################################################
   def pprint(self, keyJust=8, indentCt=0, indentSz=3):
      self.root.pprintRecurse()
         
   #############################################################################
   def applyToMap(self, funcInputNode, topFirst=True, withRoot=False):
      if withRoot:
         self.root.applyToAllNodesRecurse(funcInputNode, topFirst)
      else:
         for key,child in self.root.children.iteritems():
            self.applyToBranch([key], funcInputNode, topFirst)
         
   #############################################################################
   def applyToBranch(self, keyList, funcInputNode, topFirst=True):
      self.checkKeyList(keyList)
      node = self.root.getPathNodeRecurse(keyList, doCreate=False)
      if node is None:
         raise KeyError('Key path does not exist:  %s' % str(keyList))

      node.applyToAllNodesRecurse(funcInputNode, topFirst)
         
   #############################################################################
   def clearMap(self):
      self.root.recurseDelete()
         
   #############################################################################
   def clearBranch(self, keyList, andBranchPoint=True):
      self.checkKeyList(keyList)
      node = self.root.getPathNodeRecurse(keyList, doCreate=False)
      if node is None:
         raise KeyError('Key path does not exist:  %s' % str(keyList))

      node.recurseDelete()

      if andBranchPoint:
         del node.parent.children[node.keyList[-1]]
      
      
   #############################################################################
   def countNodes(self, keyList=None):
      ct = [0]
      def ctfunc(node):
         ct[0] += 1

      if keyList is None:
         self.applyToMap(ctfunc)
      else:
         self.applyToBranch(keyList, ctfunc)

      return ct[0]  

      
   #############################################################################
   def countLeaves(self, keyList=None):
      if len(self.root.children)==0:
         return 0

      ct = [0]
      def ctfunc(node):
         ct[0] += 1 if len(node.children)==0 else 0

      if keyList is None:
         self.applyToMap(ctfunc)
      else:
         self.applyToBranch(keyList, ctfunc)

      return ct[0]
      
   #############################################################################
   def countNonEmpty(self, keyList=None):
      ct = [0]
      def ctfunc(node):
         ct[0] += 0 if len(node.data)==0 else 1

      if keyList is None:
         self.applyToMap(ctfunc)
      else:
         self.applyToBranch(keyList, ctfunc)

      return ct[0]




from WalletEntry import WalletEntry
