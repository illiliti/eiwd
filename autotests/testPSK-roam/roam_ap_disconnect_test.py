#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
from iwd import IWD
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI

class Test(unittest.TestCase):
    #
    # Tests a crash reported where multiple roam scans combined with an AP
    # disconnect result in a crash getting scan results.
    #
    def validate(self):
        wd = IWD(True)
        device = wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        # Since both BSS's have low signal, the roam should fail and trigger
        # another roam scan.
        device.wait_for_event('no-roam-candidates', timeout=30)
        device.wait_for_event('roam-scan-triggered', timeout=30)

        # Hostapd sends disconnect
        self.bss_hostapd[0].disable()

        # IWD should recover, and not crash
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_ap_disconnect_no_neighbors(self):
        self.validate()

    def test_ap_disconnect_neighbors(self):
        self.bss_hostapd[0].set_neighbor('12:00:00:00:00:02', 'TestFT',
                '1200000000028f0000005102060603000000')
        self.bss_hostapd[1].set_neighbor('12:00:00:00:00:01', 'TestFT',
                '1200000000018f0000005101060603000000')

        self.validate()

    def setUp(self):
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

        self.bss_hostapd[0].remove_neighbor(self.bss_hostapd[1].bssid)
        self.bss_hostapd[1].remove_neighbor(self.bss_hostapd[0].bssid)

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf') ]
        cls.bss_hostapd[1].disable()

        cls.bss_hostapd[0].set_value('ocv', '0')
        cls.bss_hostapd[0].set_value('ieee80211w', '0')

        cls.rule0 = hwsim.rules.create()
        cls.rule0.source = 'any'
        cls.rule0.bidirectional = True
        cls.rule0.signal = -8000
        cls.rule0.enabled = True

        # Set interface addresses to those expected by hostapd config files
        os.system('ip link set dev "' + cls.bss_hostapd[0].ifname + '" down')
        os.system('ip link set dev "' + cls.bss_hostapd[0].ifname + '" addr 12:00:00:00:00:01 up')
        os.system('ip link set dev "' + cls.bss_hostapd[1].ifname + '" down')
        os.system('ip link set dev "' + cls.bss_hostapd[1].ifname + '" addr 12:00:00:00:00:02 up')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule0.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
