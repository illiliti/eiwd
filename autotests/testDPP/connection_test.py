#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from wpas import Wpas
from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def test_iwd_as_enrollee(self):
        wpas = Wpas('wpas.conf')

        wd = IWD(True)

        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = True

        uri = device.dpp_start_enrollee()

        wpas.dpp_configurator_create(uri)
        wpas.dpp_configurator_start('ssidCCMP', 'secret123')

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()
        device.dpp_stop()

        del wpas

    def test_iwd_as_configurator(self):
        IWD.copy_to_storage('ssidCCMP.psk')

        wpas = Wpas('wpas.conf')
        hapd = HostapdCLI('hostapd.conf')

        wd = IWD(True)

        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        uri = device.dpp_start_configurator()

        wpas.dpp_enrollee_start(uri)

        hapd.wait_for_event('AP-STA-CONNECTED 42:00:00:00:00:00')

        device.disconnect()
        device.dpp_stop()

        del wpas

    def tearDown(self):
        IWD.clear_storage()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
