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

        bss_radio0 = hwsim.get_radio('rad0')
        bss_radio1 = hwsim.get_radio('rad1')

        self.assertIsNotNone(bss_radio0)

        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidOWE')

        self.assertEqual(ordered_network.type, NetworkType.open)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio0.addresses[0]
        rule0.bidirectional = True
        rule0.drop = True
        rule0.prefix = 'b0'

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio1.addresses[0]
        rule1.bidirectional = True
        rule1.drop = True
        rule1.prefix = 'b0'

        # Test Authenticate (b0) and Association (00) timeouts

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

        rule0.prefix = '00'
        rule1.prefix = '00'

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

    def tearDown(self):
        hwsim = Hwsim()
        for rule in list(hwsim.rules.keys()):
            del hwsim.rules[rule]

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
