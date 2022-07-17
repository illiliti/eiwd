#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from hostapd import HostapdCLI
from config import ctx

class Test(unittest.TestCase):

    def four_digit_pin_success(self, wd, client=False):

        devices = wd.list_devices(1)
        device = devices[0]
        pin = '1234'
        self.hostapd.wps_pin(pin)

        if not client:
            device.wps_start_pin(pin)
        else:
            ctx.start_process(['iwctl', 'wsc', device.name, 'start-user-pin', pin], check=True)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertEqual(len(wd.list_known_networks()), 1)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_connection_success(self):
        wd = IWD(True)

        self.four_digit_pin_success(wd)

    def test_client_four_digit_pin(self):
        wd = IWD(True)

        self.four_digit_pin_success(wd, client=True)

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidWPS.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.hostapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
