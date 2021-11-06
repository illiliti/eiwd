#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import validation
from validation import TestConnectAutoConnect
from iwd import IWD

class TestOpenNetwork(unittest.TestCase):
    '''
    The bellow test cases excesise the following connection scenarios:

    Network config is
    present at start time:  Connect:  AutoConnect:  Result:
    --------------------------------------------------------------------------
    False                   True                    Connection succeeds
    True                              True          Connection succeeds
    '''
    def test_open(self):
        tca = TestConnectAutoConnect()
        tca.validate('ssidOpen', False)
        tca.validate('ssidOpen', True)

    def setUp(self):
        IWD.copy_to_storage('ssidOpen.open')

    def tearDown(self):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
