#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def test_incorrect_password(self):
        wd = IWD(True)

        psk_agent = PSKAgent("InvalidPassword")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidWPA2')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

        wd.unregister_psk_agent(psk_agent)

    def test_deauth_after_connection(self):
        wd = IWD(True)
        hostapd = HostapdCLI(config="ssidWPA2.conf")

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidWPA2')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect(wait=False)

        device.wait_for_event("authenticating")

        # Trigger a deauth just after authenticating
        hostapd.deauthenticate(device.address)

        device.wait_for_event("disconnected")

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
