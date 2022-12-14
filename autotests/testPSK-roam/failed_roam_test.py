#! /usr/bin/python3

import unittest
import os, sys

sys.path.append('../util')
from iwd import IWD
from iwd import NetworkType, DeviceState
from hwsim import Hwsim
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def connect(self, wd, device, hostapd):
        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.connect_bssid(hostapd.bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        hostapd.wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(hostapd.ifname, device.name)

    def verify_roam(self, wd, device, prev, new):
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        new.wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(new.ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (prev.ifname, device.name, True, True))


    # FT-over-Air failure, should stay connected
    def test_ft_over_air_failure(self):
        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[0].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[1].set_value('ft_over_ds', '0')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        wd = IWD(True)

        device = wd.list_devices(1)[0]

        self.connect(wd, device, self.bss_hostapd[0])

        self.rule0.enabled = True

        device.roam(self.bss_hostapd[1].bssid)

        # Roam should fail...
        device.wait_for_event('ft-roam-failed')
        # ... but IWD should remain connected
        self.assertTrue(device.state == DeviceState.connected)

        self.rule0.enabled = False

        # Try again once more
        device.roam(self.bss_hostapd[1].bssid)

        self.verify_roam(wd, device, self.bss_hostapd[0], self.bss_hostapd[1])

        self.bss_hostapd[1].deauthenticate(device.address)
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

        self.rule0.enabled = False
        self.rule1.enabled = False

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf') ]

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')

        # Drop Authenticate frames
        cls.rule0 = hwsim.rules.create()
        cls.rule0.bidirectional = True
        cls.rule0.prefix = 'b0'
        cls.rule0.drop = True

        # Drop Action frames
        cls.rule1 = hwsim.rules.create()
        cls.rule1.bidirectional = True
        cls.rule1.prefix = 'd0'
        cls.rule1.drop = True

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule0.remove()
        cls.rule1.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
