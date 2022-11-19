#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def test_connection_success(self):
        hapd = HostapdCLI(config='ssidOWE-1.conf')

        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        device.get_ordered_network('ssidOWE')

        device.connect_bssid(hapd.bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname)

        device.disconnect()

    def test_reassociate(self):
        hapd0 = HostapdCLI(config='ssidOWE-1.conf')
        hapd1 = HostapdCLI(config='ssidOWE-2.conf')

        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        device.get_ordered_network('ssidOWE')

        device.connect_bssid(hapd0.bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd0.ifname)

        device.roam(hapd1.bssid)

        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        hapd1.wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(hapd1.ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (hapd0.ifname, device.name, True, True))

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
