#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import validation
from validation import TestHiddenNetworks
from iwd import IWD
from hostapd import HostapdCLI

class TestWpaNetwork(unittest.TestCase):
    '''
    The bellow test cases excesise the following connection scenarios:

    Network config is
    present at start time:  Connect:  AutoConnect:  Result:
    --------------------------------------------------------------------------
    False                   True                    NotFoundEx raised
    False                   True                    ServiceSetOverlapEx raised
    False                   True                    NotHiddenEx raised
    True                    True                    AlreadyProvisionedEx raised
    '''

    def test_wpa(self):
        tca = TestHiddenNetworks()

        tca.validate('UnExistingNetwork', False, iwd.NotFoundEx)
        tca.validate('ssidOverlap', False, iwd.ServiceSetOverlapEx)
        tca.validate('ssidOpen', False, iwd.NotHiddenEx, False, True)
        tca.validate('ssidAlreadyKnown', False, iwd.AlreadyProvisionedEx)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidAlreadyKnown.open')

        cls.disabled = [HostapdCLI('ssidHiddenOpen.conf'),
                        HostapdCLI('ssidHiddenWPA.conf'),
                        HostapdCLI('ssidSomeHidden.conf')]

        for hapd in cls.disabled:
            hapd.disable()

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        for hapd in cls.disabled:
            hapd.reload()

if __name__ == '__main__':
    unittest.main(exit=True)
