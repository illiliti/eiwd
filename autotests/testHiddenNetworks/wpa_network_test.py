#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import validation
from validation import TestHiddenNetworks
from iwd import IWD

class TestWpaNetwork(unittest.TestCase):
    '''
    The bellow test cases excesise the following connection scenarios:

    Network config is
    present at start time:  Connect:  AutoConnect:  Result:
    --------------------------------------------------------------------------
    False                   True                    Connection succeeds
    True                              True          Connection succeeds
    '''

    def test_wpa(self):
        tca = TestHiddenNetworks()
        tca.validate('ssidHiddenWPA', False, None, True)
        tca.validate('ssidHiddenWPA', True, None, True)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
