#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from iwd import DeviceState
from hwsim import Hwsim
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def test_roam_before_netconfig(self):
        wd = IWD(True)

        device = wd.list_devices(1)[0]
        device.get_ordered_network('TestFT', full_scan=True)
        device.connect_bssid(self.bss_hostapd[1].bssid)

        self.bss_hostapd[1].wait_for_event(f'AP-STA-CONNECTED {device.address}')
        device.wait_for_event("connecting (netconfig)")

        roam_to = 0
        roam_from = 1

        # Roam back and forth, ensuring that the state transitions between
        # roaming and connecting (netconfig).
        for _ in range(0, 5):
            self.rules[roam_to].signal = -2000
            self.rules[roam_from].signal = -8000

            # Station should internally transition to roaming, but remain in a
            # connecting state on DBus
            device.wait_for_event("ft-roaming")
            self.assertEqual(device.state, DeviceState.connecting)

            self.bss_hostapd[roam_to].wait_for_event(f'AP-STA-CONNECTED {device.address}')
            device.wait_for_event("connecting (netconfig)")

            tmp = roam_from
            roam_from = roam_to
            roam_to = tmp

        self.bss_hostapd[roam_from].deauthenticate(device.address)
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf') ]

        rule0 = hwsim.rules.create()
        rule0.source = cls.bss_hostapd[0].bssid
        rule0.signal = -6000
        rule0.enabled = True

        rule1 = hwsim.rules.create()
        rule1.source = cls.bss_hostapd[1].bssid
        rule1.signal = -2000
        rule1.enabled = True

        cls.rules = [rule0, rule1]

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rules = None

if __name__ == '__main__':
    unittest.main(exit=True)
