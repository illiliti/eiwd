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
        wd = IWD(True)

        devices = wd.list_devices(1)
        device = devices[0]

        device.disconnect()
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network("ssidWPA2")
        self.assertEqual(ordered_network.type, NetworkType.psk)
        network = ordered_network.network_object

        # 0 chars
        psk_agent = PSKAgent("")
        wd.register_psk_agent(psk_agent)
        self.assertRaises(iwd.InvalidFormatEx, network.connect)
        wd.unregister_psk_agent(psk_agent)

        # 7 chars
        psk_agent = PSKAgent("a" * 7)
        wd.register_psk_agent(psk_agent)
        self.assertRaises(iwd.InvalidFormatEx, network.connect)
        wd.unregister_psk_agent(psk_agent)

        # 64 chars
        psk_agent = PSKAgent("a" * 64)
        wd.register_psk_agent(psk_agent)
        self.assertRaises(iwd.InvalidFormatEx, network.connect)
        wd.unregister_psk_agent(psk_agent)

        # 64k chars
        psk_agent = PSKAgent("a" * 65536)
        wd.register_psk_agent(psk_agent)
        self.assertRaises(iwd.InvalidFormatEx, network.connect)
        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
