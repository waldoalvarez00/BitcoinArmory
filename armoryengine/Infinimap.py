################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
from ArmoryUtils import *


class MaxDepthExceeded(Exception): pass

################################################################################
class InfinimapNode(object):
   def __init__(self, key=None, parent=None):
      self.data     = ''
      self.children = {}
      self.parent   = parent
      self.selfKey  = key
      
   #############################################################################
   def pprintRecurse(self, indentCt=0, indentSz=3, keyJust=16):
      prInd  = indentCt * indentSz * ' '
      prKey  = self.selfKey[:keyJust].ljust(keyJust)
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

      if doCreate:
         # setdefault always returns the data at that key.  If the key 
         # doesn't exist yet, it adds it and sets it to the second arg.
         nextNode = self.children.setdefault(key, InfinimapNode(key, self))
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
      self.root = InfinimapNode('ROOT')

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
   def applyToMap(self, funcInputNode, topFirst=True):
      self.root.applyToAllNodesRecurse(funcInputNode, topFirst)
         
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
         del node.parent.children[node.selfKey]
      
      
   #############################################################################
   def countNodes(self, keyList=None):
      ct = [0]
      def ctfunc(node):
         ct[0] += 1

      if keyList is None:
         self.applyToMap(ctfunc)
      else:
         self.applyToBranch(keyList, ctfunc)

      return ct[0]-1  # -1 for root node which would be unexpected

      
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



