################################################################################
#                                                                              #
# Copyright (C) 2011-2014, Armory Technologies, Inc.                           #
# Distributed under the GNU Affero General Public License (AGPL v3)            #
# See LICENSE or http://www.gnu.org/licenses/agpl.html                         #
#                                                                              #
################################################################################
import sys
sys.path.append('..')
import unittest
import sys
sys.path.append('..')
import textwrap

from armoryengine.ArmoryUtils import *
from armoryengine.Infinimap import *



################################################################################
class InfinimapTests(unittest.TestCase):

   #############################################################################
   def testInfinimap(self):
      inf = Infinimap()

      inf.setData(['a','b','c'], 'Helloabc')
      inf.setData(['a','b',], 'abhi')
      inf.setData(['a','b',], 'abhi')
      inf.setData(['a','c',], 'I c u')
      inf.setData(['a','d',], 'ddddd')
      inf.setData(['a','z',], 'skipped a few')
      inf.setData(['123','456','789'], 'numbers')
      inf.setData(['123','456','abc'], 'not all numbers')
      inf.setData(['123','456','ab3'], 'hexnumbers')
      inf.setData(['123'], 'lessnumbers')

      #inf.pprint()


      self.assertEqual(inf.getData(['123']), 'lessnumbers')
      self.assertEqual(inf.getData(['123','456','ab3']), 'hexnumbers')
      self.assertEqual(inf.getData(['123','456','abr3']), None)

      self.assertEqual(inf.getData(['zzz']), None)
      inf.setData(['zzz'], 'zzz')
      self.assertEqual(inf.getData(['zzz']), 'zzz')


   #############################################################################
   def testRecurseApply(self):
      # Count all nodes that are only a single letter
      singleLetterKeys = []
      def checkNode(node):
         if len(node.selfKey)==1:
            singleLetterKeys.append(node.selfKey)

      countRef = [0]
      def anotherCheck(node):
         countRef[0] += 0 if node.data is None else len(node.data)
      
      inf = Infinimap()
      inf.setData(['a','b','c'],       'Helloabc')
      inf.setData(['a','b',],          None)
      inf.setData(['a','z',],          'skipped a few')
      inf.setData(['123','456','789'], 'numbers')
      inf.setData(['123'],             'lessnumbers')
      inf.setData(['123', '3', 'a'],   'something different')
      inf.setData(['123', '3', 'ab'],  'and simple')

      inf.applyToMap(checkNode)

      self.assertEqual(len(singleLetterKeys), 6)
      self.assertEqual(sorted(singleLetterKeys), ['3','a','a','b','c','z'])

      inf.applyToMap(anotherCheck)
      self.assertEqual(countRef[0], 68)


if __name__ == "__main__":
   unittest.main()
