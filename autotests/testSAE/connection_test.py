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

    def validate_connection(self, wd, ssid, hostapd, expected_group):
        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        device.disconnect()

        network = device.get_ordered_network(ssid, full_scan=True)

        self.assertEqual(network.type, NetworkType.psk)

        network.network_object.connect(wait=False)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        wd.wait(2)

        testutil.test_iface_operstate(intf=device.name)
        testutil.test_ifaces_connected(if0=device.name, if1=hostapd.ifname)

        sta_status = hostapd.sta_status(device.address)

        self.assertEqual(int(sta_status["sae_group"]), expected_group)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_SAE(self):
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd, "ssidSAE", self.hostapd, 19)

    def test_SAE_Group20(self):
        self.hostapd.set_value('sae_groups', '20')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd, "ssidSAE", self.hostapd, 20)

    def test_SAE_H2E(self):
        self.hostapd_h2e.set_value('sae_groups', '19')
        self.hostapd_h2e.reload()
        self.hostapd_h2e.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd, "ssidSAE-H2E", self.hostapd_h2e, 19)

    def test_SAE_H2E_Group20(self):
        self.hostapd_h2e.set_value('sae_groups', '20')
        self.hostapd_h2e.reload()
        self.hostapd_h2e.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd, "ssidSAE-H2E", self.hostapd_h2e, 20)

    def setUp(self):
        self.hostapd.default()
        self.wd = IWD(True)

    def tearDown(self):
        self.wd.clear_storage()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidSAE.conf')
        cls.hostapd_h2e = HostapdCLI(config='ssidSAE-H2E.conf')

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
