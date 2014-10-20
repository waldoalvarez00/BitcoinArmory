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
      inf.setData(['a','b'], 'abhi')
      inf.setData(['a','c'], 'I c u')
      inf.setData(['a','d'], 'ddddd')
      inf.setData(['a','z'], 'skipped a few')
      inf.setData(['123','456','789'], 'numbers')
      inf.setData(['123','456','abc'], 'not all numbers')
      inf.setData(['123','456','ab3'], 'hexnumbers')
      inf.setData(['123'], 'lessnumbers')

      #inf.pprint()


      self.assertEqual(inf.getData(['123']), 'lessnumbers')
      self.assertEqual(inf.getData(['123','456','ab3']), 'hexnumbers')
      self.assertEqual(inf.getData(['123','456','abr3']), None)

      self.assertEqual(inf.countNodes(), 11)
      self.assertEqual(inf.countLeaves(), 7)
      self.assertEqual(inf.countNonEmpty(), 9)

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
      inf.setData(['a','b'],           '')
      inf.setData(['a','z'],           'skipped a few')
      inf.setData(['123','456','789'], 'numbers')
      inf.setData(['123'],             'lessnumbers')
      inf.setData(['123', '3', 'a'],   'something different')
      inf.setData(['123', '3', 'ab'],  'and simple')

      inf.applyToMap(checkNode)

      self.assertEqual(len(singleLetterKeys), 6)
      self.assertEqual(sorted(singleLetterKeys), ['3','a','a','b','c','z'])

      inf.applyToMap(anotherCheck)
      self.assertEqual(countRef[0], 68)

      
      singleLetterKeys = []
      inf.applyToBranch(['a'], checkNode)
      self.assertEqual(len(singleLetterKeys), 4)
      self.assertEqual(sorted(singleLetterKeys), ['a','b','c','z'])


   #############################################################################
   def testClearData(self):

      inf = Infinimap()
      inf.setData(['a','b','c'],       'Helloabc')
      inf.setData(['a','b'],           '')
      inf.setData(['a','z'],           'skipped a few')
      inf.setData(['123','456','789'], 'numbers')
      inf.setData(['123'],             'lessnumbers')
      inf.setData(['123', '3', 'a'],   'something different')
      inf.setData(['123', '3', 'ab'],  'and simple')

      self.assertEqual(inf.countNodes(), 10)
      self.assertEqual(inf.countLeaves(), 5)
      self.assertEqual(inf.countNonEmpty(), 6)

      inf.clearMap()
      self.assertEqual(inf.countNodes(), 0)
      self.assertEqual(inf.countLeaves(), 0)
      self.assertEqual(inf.countNonEmpty(), 0)

      inf.setData(['a','b','c'],       'Helloabc')
      inf.setData(['a','b',],          '')
      inf.setData(['a','z',],          'skipped a few')
      inf.setData(['123','456','789'], 'numbers')
      inf.setData(['123'],             'lessnumbers')
      inf.setData(['123', '3', 'a'],   'something different')
      inf.setData(['123', '3', 'ab'],  'and simple')
      
      inf.clearBranch(['123','3'])
      self.assertEqual(inf.countNodes(), 7)
      self.assertEqual(inf.countLeaves(), 3)
      self.assertEqual(inf.countNonEmpty(), 4)

      inf.clearBranch(['a'], andBranchPoint=False)
      self.assertEqual(inf.countNodes(), 4)
      self.assertEqual(inf.countLeaves(), 2)
      self.assertEqual(inf.countNonEmpty(), 2)




if __name__ == "__main__":
   unittest.main()
