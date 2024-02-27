#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def validate_connection(self, wd, ssid):
        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]
        device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.connected_network is not None'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network(ssid)

        self.assertTrue(ordered_network.network_object.connected)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_SAE(self):
        IWD.copy_to_storage("profiles/ssidSAE.psk.default", name="ssidSAE.psk")
        self.hostapd.wait_for_event("AP-ENABLED")

        wd = IWD(True)
        self.validate_connection(wd, "ssidSAE")

    def test_SAE_H2E(self):
        IWD.copy_to_storage("profiles/ssidSAE.psk.default", name="ssidSAE-H2E.psk")
        self.hostapd_h2e.set_value('sae_groups', '20')
        self.hostapd_h2e.reload()
        self.hostapd_h2e.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd, "ssidSAE-H2E")

    def test_SAE_H2E_password_identifier(self):
        IWD.copy_to_storage("profiles/ssidSAE.psk.identifier", name="ssidSAE-H2E.psk")
        self.hostapd_h2e.set_value('sae_groups', '20')
        self.hostapd_h2e.reload()
        self.hostapd_h2e.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd, "ssidSAE-H2E")

    def setUp(self):
        self.hostapd.default()

    def tearDown(self):
        IWD.clear_storage()

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidSAE.conf')
        cls.hostapd_h2e = HostapdCLI(config='ssidSAE-H2E.conf')

if __name__ == '__main__':
    unittest.main(exit=True)
