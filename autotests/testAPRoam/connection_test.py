#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def test_connection_success(self):
        bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                        HostapdCLI(config='ssid2.conf'),
                        HostapdCLI(config='ssid3.conf') ]

        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('TestAPRoam')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.connect_bssid(bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[0].wait_for_event('AP-STA-CONNECTED')

        self.assertFalse(bss_hostapd[1].list_sta())

        bss_hostapd[0].send_bss_transition(device.address,
                [(bss_hostapd[1].bssid, '8f0000005102060603000000')])

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state != DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestAPRoam.psk')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
