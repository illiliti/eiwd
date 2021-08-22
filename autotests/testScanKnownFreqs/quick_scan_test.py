#!/usr/bin/python3

import unittest
import sys
import time

sys.path.append('../util')
import iwd
from iwd import IWD

class Test(unittest.TestCase):
    dict = {
        'ssid_open_1': False,
        'ssid_open_2': False,
        'ssid_open_3': False,
    }

    def set_network(self, ssid):
        if ssid not in self.dict:
            return

        self.dict[ssid] = True

    def validate_quick_scan(self, wd):
        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = True

        # Device initiates a passive quick scan and scans only for the known
        # frequencies (listed in .known_network.freq file).
        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()

        for network in ordered_networks:
            self.set_network(network.name)

    def test_scan(self):
        wd = IWD(True)

        self.validate_quick_scan(wd)

        # Only ssid_open_1 and ssid_open_2 should be discovered.
        self.assertEqual(self.dict['ssid_open_1'], True)
        self.assertEqual(self.dict['ssid_open_2'], True)
        self.assertEqual(self.dict['ssid_open_3'], False)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('.known_network.freq')
        IWD.copy_to_storage('ssid_open_1.open')
        IWD.copy_to_storage('ssid_open_2.open')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
