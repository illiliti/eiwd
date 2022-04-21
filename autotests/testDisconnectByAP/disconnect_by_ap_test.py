#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import DeviceState
from iwd import NetworkType

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def test_disconnect(self):
        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        hostapd = HostapdCLI(config='ssidOpen.conf')

        ordered_network = device.get_ordered_network('ssidOpen', full_scan=True)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        hostapd.deauthenticate(device.address)

        condition = 'obj.state == DeviceState.connecting'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)


    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
