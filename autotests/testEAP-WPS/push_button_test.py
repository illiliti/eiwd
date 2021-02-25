#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import DeviceState

from hostapd import HostapdCLI
class Test(unittest.TestCase):

    def push_button_success(self, wd):
        self.hostapd.wps_push_button()

        devices = wd.list_devices(1)
        device = devices[0]

        device.wps_push_button()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertEqual(len(wd.list_known_networks()), 1)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_connection_success(self):
        wd = IWD(True)

        self.push_button_success(wd)

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidWPS.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.hostapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
