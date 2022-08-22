#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
from iwd import IWD
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def validate_connection(self, wd):
        device = wd.list_devices(1)[0]

        # Scanning is unavoidable in this case since both FILS-SHA256 and
        # FILS-SHA384 are tested. Without a new scan the cached scan results
        # would cause IWD to choose an incorrect AKM for the second test.
        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

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

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network = device.get_ordered_network('TestFT')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        # TODO: verify FILS was actually used on this second connection
        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        self.assertFalse(self.bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name, True, True))

        # Check that iwd starts transition to BSS 1 in less than 10 seconds.
        # The 10 seconds is longer than needed to scan on just two channels
        # but short enough that a full scan on the 2.4 + 5.8 bands supported
        # by mac80211_hwsim will not finish.  If this times out then, but
        # device_roam_trigger_cb has happened, it probably means that
        # Neighbor Reports are broken.
        #rule0.signal = -8000
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

        self.bss_hostapd[1].rekey(device.address)

    def test_fils_ft_roam_sha256(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-EAP FILS-SHA256 FT-FILS-SHA256')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-EAP FILS-SHA256 FT-FILS-SHA256')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(wd)

    def test_fils_ft_roam_sha384(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-EAP FILS-SHA384 FT-FILS-SHA384')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-EAP FILS-SHA384 FT-FILS-SHA384')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(wd)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

    @classmethod
    def setUpClass(cls):
        os.system('ip link set lo up')
        IWD.copy_to_storage('TestFT.8021x')

        cls.bss_hostapd = [ HostapdCLI(config='ft-eap-ccmp-1.conf'),
                            HostapdCLI(config='ft-eap-ccmp-2.conf') ]

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        #cls.bss_radio = None

if __name__ == '__main__':
    unittest.main(exit=True)
