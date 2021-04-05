#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
import testutil

import hostapd
from hwsim import Hwsim

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        bss_radio = hwsim.get_radio('rad0')

        self.assertIsNotNone(bss_radio)

        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidOWE')

        self.assertEqual(ordered_network.type, NetworkType.open)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio.addresses[0]
        rule0.bidirectional = True
        rule0.drop = True
        rule0.prefix = 'b0'

        # Test Authenticate (b0) and Association (00) timeouts

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

        rule0.prefix = '00'

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
