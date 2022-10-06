#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD

class Test(unittest.TestCase):
    dict = {
        'ssid_open': False,
        'ssid_psk': False,
        'ssid_8021x': False,
        'ssid_hidden_0': False,
    }

    def set_network(self, ssid):
        if ssid not in self.dict:
            return

        if self.dict[ssid]:
            raise Exception('Duplicated list entry')

        self.dict[ssid] = True

    def validate_scan(self, wd):
        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]
        device.autoconnect = True

        # Device initiates a passive periodic scan.
        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        # Hidden networks observed in the scan results, device initialtes a
        # second active periodic scan to discover the known hidden networks.
        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()

        for network in ordered_networks:
            self.set_network(network.name)

    def test_scan(self):
        wd = IWD(True, '/tmp')

        self.validate_scan(wd)

        for ssid, seen in self.dict.items():
            self.assertEqual(seen, True)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssid_hidden_0.open')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
