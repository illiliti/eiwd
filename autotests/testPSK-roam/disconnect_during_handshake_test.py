#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def validate_connection(self, wd):
        device = wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name, True, True))

        self.rule0.enabled = True

        device.roam(self.bss_hostapd[1].bssid)

        device.clear_events()
        device.wait_for_event("handshake-started")
        self.bss_hostapd[1].deauthenticate(device.address, reason=15, test=1)

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_change(device, from_condition, to_condition)

    def test_disconnect_during_handshake(self):
        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'WPA-PSK')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'WPA-PSK')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(self.wd)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

        for hapd in self.bss_hostapd:
            hapd.default()

        self.wd.stop()
        self.wd = None

    def setUp(self):
        self.wd = IWD(True)

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf') ]

        unused = HostapdCLI(config='ft-psk-ccmp-3.conf')
        unused.disable()

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')

        rad1 = hwsim.get_radio('rad1')

        cls.rule0 = hwsim.rules.create()
        cls.rule0.destination = rad1.addresses[0]
        cls.rule0.prefix = '08'
        cls.rule0.drop = True

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule0.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
