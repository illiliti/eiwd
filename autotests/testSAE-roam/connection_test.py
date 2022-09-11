#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil
from config import ctx

class Test(unittest.TestCase):
    def validate_connection(self, wd, ft=True):
        device = wd.list_devices(1)[0]

        # This won't guarantee all BSS's are found, but at least ensures that
        # at least one will be.
        device.get_ordered_network('TestFT', full_scan=True)

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

        if not ft:
                return

        device.roam(self.bss_hostapd[2].bssid)

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state != DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[2].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[2].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                            (self.bss_hostapd[1].ifname, device.name, True, True))

    def test_ft_roam_success(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-SAE SAE')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")
        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-SAE SAE')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")
        self.bss_hostapd[2].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[2].reload()
        self.bss_hostapd[2].wait_for_event("AP-ENABLED")

        self.validate_connection(wd, True)

    def test_reassociate_roam_success(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'SAE')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")
        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'SAE')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")
        self.bss_hostapd[2].set_value('wpa_key_mgmt', 'WPA-PSK')
        self.bss_hostapd[2].reload()
        self.bss_hostapd[2].wait_for_event("AP-ENABLED")

        self.validate_connection(wd, False)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[2].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[2].ifname + '" up')

    @classmethod
    def setUpClass(cls):
        cls.bss_hostapd = [ HostapdCLI(config='ft-sae-1.conf'),
                            HostapdCLI(config='ft-sae-2.conf'),
                            HostapdCLI(config='ft-psk-3.conf') ]

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')
        cls.bss_hostapd[2].set_address('12:00:00:00:00:03')

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

        IWD.copy_to_storage('TestFT.psk')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        cls.bss_hostapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
