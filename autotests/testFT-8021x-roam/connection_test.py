#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
from iwd import IWD
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def test_roam_success(self):
        wd = IWD(True)

        device = wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('TestFT')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        self.assertFalse(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)
        self.assertFalse(self.bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name, True, True))

        device.roam(self.bss_hostapd[1].bssid)

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        self.bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[0].ifname, device.name, True, True))

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestFT.8021x')

        cls.bss_hostapd = [ HostapdCLI(config='ft-eap-ccmp-1.conf'),
                            HostapdCLI(config='ft-eap-ccmp-2.conf') ]

        # Set interface addresses to those expected by hostapd config files
        os.system('ip link set dev "' + cls.bss_hostapd[0].ifname + '" down')
        os.system('ip link set dev "' + cls.bss_hostapd[0].ifname + \
                  '" address 12:00:00:00:00:01 up')
        os.system('ip link set dev "' + cls.bss_hostapd[1].ifname + '" down')
        os.system('ip link set dev "' + cls.bss_hostapd[1].ifname + \
                  '" address 12:00:00:00:00:02 up')

        cls.bss_hostapd[0].reload()
        cls.bss_hostapd[0].wait_for_event("AP-ENABLED")
        cls.bss_hostapd[1].reload()
        cls.bss_hostapd[1].wait_for_event("AP-ENABLED")

        # Fill in the neighbor AP tables in both BSSes.  By default each
        # instance knows only about current BSS, even inside one hostapd
        # process.
        # FT still works without the neighbor AP table but neighbor reports
        # have to be disabled in the .conf files
        cls.bss_hostapd[0].set_neighbor('12:00:00:00:00:02', 'TestFT',
                '1200000000028f0000005102060603000000')
        cls.bss_hostapd[1].set_neighbor('12:00:00:00:00:01', 'TestFT',
                '1200000000018f0000005101060603000000')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
