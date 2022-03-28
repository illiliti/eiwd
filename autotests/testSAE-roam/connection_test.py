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

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

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

        ctx.start_process(['ip', 'link', 'set', 'dev', cls.bss_hostapd[0].ifname, 'down'])
        ctx.start_process(['ip', 'link', 'set', 'dev', cls.bss_hostapd[0].ifname, \
                           'addr', '12:00:00:00:00:01', 'up']).wait()
        ctx.start_process(['ip', 'link', 'set', 'dev', cls.bss_hostapd[1].ifname, 'down'])
        ctx.start_process(['ip', 'link', 'set', 'dev', cls.bss_hostapd[1].ifname, \
                           'addr', '12:00:00:00:00:02', 'up']).wait()
        ctx.start_process(['ip', 'link', 'set', 'dev', cls.bss_hostapd[2].ifname, 'down'])
        ctx.start_process(['ip', 'link', 'set', 'dev', cls.bss_hostapd[2].ifname, \
                           'addr', '12:00:00:00:00:03', 'up']).wait()

        # Set interface addresses to those expected by hostapd config files
        cls.bss_hostapd[0].reload()
        cls.bss_hostapd[0].wait_for_event("AP-ENABLED")
        cls.bss_hostapd[1].reload()
        cls.bss_hostapd[1].wait_for_event("AP-ENABLED")
        cls.bss_hostapd[2].reload()
        cls.bss_hostapd[2].wait_for_event("AP-ENABLED")

        # Fill in the neighbor AP tables in both BSSes.  By default each
        # instance knows only about current BSS, even inside one hostapd
        # process.
        # FT still works without the neighbor AP table but neighbor reports
        # have to be disabled in the .conf files
        cls.bss_hostapd[0].set_neighbor('12:00:00:00:00:02', 'TestFT',
                '1200000000028f0000005102060603000000')
        cls.bss_hostapd[0].set_neighbor('12:00:00:00:00:03', 'TestFT',
                '1200000000038f0000005102060603000000')

        cls.bss_hostapd[1].set_neighbor('12:00:00:00:00:01', 'TestFT',
                '1200000000018f0000005101060603000000')
        cls.bss_hostapd[1].set_neighbor('12:00:00:00:00:03', 'TestFT',
                '1200000000038f0000005101060603000000')

        cls.bss_hostapd[2].set_neighbor('12:00:00:00:00:01', 'TestFT',
                '1200000000018f0000005101060603000000')
        cls.bss_hostapd[2].set_neighbor('12:00:00:00:00:02', 'TestFT',
                '1200000000028f0000005101060603000000')

        IWD.copy_to_storage('TestFT.psk')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        cls.bss_hostapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
