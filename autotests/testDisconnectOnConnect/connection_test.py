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

        device = wd.list_devices(1)[0]

        wpa_net = device.get_ordered_network('ssidTKIP')
        self.assertEqual(wpa_net.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(wpa_net.network_object, condition)

        wpa_net.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        open_net = device.get_ordered_network('ssidOpen')
        self.assertEqual(open_net.type, NetworkType.open)

        open_net.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(open_net.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
