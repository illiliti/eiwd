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

    def validate_connection(self, wd):
        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        device.disconnect()

        network = device.get_ordered_network('ssidSAE', full_scan=True)

        self.assertEqual(network.type, NetworkType.psk)

        network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        wd.wait(2)

        testutil.test_iface_operstate(intf=device.name)
        testutil.test_ifaces_connected(if0=device.name, if1=self.hostapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_SAE(self):
        self.hostapd.set_value('sae_pwe', '0')
        self.hostapd.set_value('sae_groups', '19')
        self.hostapd.set_value('vendor_elements', '')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd)

    def test_SAE_force_group_19(self):
        self.hostapd.set_value('sae_pwe', '0')
        self.hostapd.set_value('sae_groups', '19')
        # Vendor data from APs which require group 19 be used first
        # TODO: (for all tests) verify the expected group was used
        self.hostapd.set_value('vendor_elements', 'dd0cf4f5e8050500000000000000')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd)

    def test_SAE_Group20(self):
        self.hostapd.set_value('sae_pwe', '0')
        self.hostapd.set_value('sae_groups', '20')
        self.hostapd.set_value('vendor_elements', '')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd)

    def test_SAE_H2E(self):
        self.hostapd.set_value('sae_pwe', '1')
        self.hostapd.set_value('sae_groups', '19')
        self.hostapd.set_value('vendor_elements', '')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd)

    def test_SAE_H2E_Group20(self):
        self.hostapd.set_value('sae_pwe', '1')
        self.hostapd.set_value('sae_groups', '20')
        self.hostapd.set_value('vendor_elements', '')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection(self.wd)

    def setUp(self):
        self.wd = IWD(True)

    def tearDown(self):
        self.wd.clear_storage()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidSAE.conf')

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
