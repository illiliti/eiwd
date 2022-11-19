#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
from iwd import IWD
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def test_preauth_success(self):
        bss_hostapd = [ HostapdCLI(config='eaptls-preauth-1.conf'),
                        HostapdCLI(config='eaptls-preauth-2.conf') ]

        bss0_addr = bss_hostapd[0].bssid
        bss1_addr = bss_hostapd[1].bssid

        HostapdCLI.group_neighbors(*bss_hostapd)

        wd = IWD(True)

        device = wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('TestPreauth')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        device.connect_bssid(bss0_addr)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)
        self.assertFalse(bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          bss_hostapd[1].ifname, device.name, True, True)

        device.roam(bss1_addr)

        # TODO: verify that the PMK from preauthentication was used

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (bss_hostapd[0].ifname, device.name, True, True))

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestPreauth.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
