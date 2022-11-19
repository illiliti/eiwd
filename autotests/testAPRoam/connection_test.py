#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def validate(self, expect_roam=True):
        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('TestAPRoam')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED')

        self.assertFalse(self.bss_hostapd[1].list_sta())

        self.bss_hostapd[0].send_bss_transition(device.address,
                [(self.bss_hostapd[1].bssid, '8f0000005102060603000000')],
                disassoc_imminent=expect_roam)

        if expect_roam:
            from_condition = 'obj.state == DeviceState.roaming'
            to_condition = 'obj.state == DeviceState.connected'
            wd.wait_for_object_change(device, from_condition, to_condition)

            self.bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)
        else:
            device.wait_for_event("no-roam-candidates")

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_disassoc_imminent(self):
        self.validate(expect_roam=True)

    def test_no_candidates(self):
        self.validate(expect_roam=False)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestAPRoam.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                            HostapdCLI(config='ssid2.conf'),
                            HostapdCLI(config='ssid3.conf') ]

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
