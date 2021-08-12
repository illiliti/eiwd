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

        wd.wait_for_object_condition(device, 'not obj.scanning')

        device.scan()

        wd.wait_for_object_condition(device, 'obj.scanning')
        wd.wait_for_object_condition(device, 'not obj.scanning')

        #
        # An explicit scan was done prior due to hostapd options changing.
        # Because of this scan_if_needed is set to False to avoid a redundant
        # scan
        #
        network = device.get_ordered_network('ssidSAE', scan_if_needed=False)

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
        self.hostapd.set_value('sae_pwe', '0');
        self.hostapd.set_value('sae_groups', '19');
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd)
        wd.clear_storage()

    def test_SAE_Group20(self):
        self.hostapd.set_value('sae_pwe', '0');
        self.hostapd.set_value('sae_groups', '20');
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd)
        wd.clear_storage()

    def test_SAE_H2E(self):
        self.hostapd.set_value('sae_pwe', '1');
        self.hostapd.set_value('sae_groups', '19');
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd)
        wd.clear_storage()

    def test_SAE_H2E_Group20(self):
        self.hostapd.set_value('sae_pwe', '1');
        self.hostapd.set_value('sae_groups', '20');
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd)
        wd.clear_storage()

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidSAE.conf')

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
