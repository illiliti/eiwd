#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import DeviceState

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def test_push_button_success(self):
        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        device.wps_push_button()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)


    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssid-wps-small-mtu.conf')

        cls.hostapd.wps_push_button()

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.hostapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
