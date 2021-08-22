#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import testutil

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidCCMP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        with self.assertRaises(iwd.NotSupportedEx):
            ordered_network.network_object.connect()

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
