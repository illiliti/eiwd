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

    def validate_connection(self, wd):
        networks = []

        psk_agent = PSKAgent(["secret123"] * 4)
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(4)
        self.assertIsNotNone(devices)

        for i in range(len(devices)):
            network = devices[i].get_ordered_network('ssidSAE-Clogging', full_scan=True)
            self.assertEqual(network.type, NetworkType.psk)
            networks.append(network)

            condition = 'not obj.connected'
            wd.wait_for_object_condition(network.network_object, condition)

        for n in networks:
            n.network_object.connect(wait=False)

        for d in devices:
            condition = 'obj.state == DeviceState.connected'
            wd.wait_for_object_condition(d, condition)

        for d in devices:
            d.disconnect()

        for n in networks:
            condition = 'not obj.connected'
            wd.wait_for_object_condition(n.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_SAE_H2E_Group20(self):
        self.hostapd.set_value('sae_pwe', '1');
        self.hostapd.set_value('sae_groups', '20');
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd)
        wd.clear_storage()

    def test_SAE(self):
        self.hostapd.set_value('sae_pwe', '0');
        self.hostapd.set_value('sae_groups', '19');
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        wd = IWD(True)
        self.validate_connection(wd)
        wd.clear_storage()

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidSAE-Clogging.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
