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
    def test_roam_success(self):
        hwsim = Hwsim()

        rule0 = hwsim.rules.create()
        rule0.source = self.bss_radio[0].addresses[0]
        rule0.bidirectional = True

        rule1 = hwsim.rules.create()
        rule1.source = self.bss_radio[1].addresses[0]
        rule1.bidirectional = True

        wd = IWD()

        psk_agent = PSKAgent('user@example.com', ('user@example.com',
                                                                  'secret123'))
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0]

        # Check that iwd selects BSS 0 first
        rule0.signal = -2000
        rule1.signal = -2500

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('TestFT')

        self.assertEqual(ordered_network.type, NetworkType.eap)
        self.assertEqual(ordered_network.signal_strength, -2000)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertTrue(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name))

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network = device.get_ordered_network('TestFT')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertTrue(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name))

        # Check that iwd starts transition to BSS 1 in less than 10 seconds.
        # The 10 seconds is longer than needed to scan on just two channels
        # but short enough that a full scan on the 2.4 + 5.8 bands supported
        # by mac80211_hwsim will not finish.  If this times out then, but
        # device_roam_trigger_cb has happened, it probably means that
        # Neighbor Reports are broken.
        rule0.signal = -8000

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        self.assertTrue(self.bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[0].ifname, device.name))

    def tearDown(self):
        os.system('ifconfig "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ifconfig "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ifconfig "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ifconfig "' + self.bss_hostapd[1].ifname + '" up')

        hwsim = Hwsim()
        wd = IWD()
        device = wd.list_devices(1)[0]
        try:
            device.disconnect()
        except:
            pass

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

        for rule in list(hwsim.rules.keys()):
            del hwsim.rules[rule]

    @classmethod
    def setUpClass(cls):
        os.system('ifconfig lo up')
        IWD.copy_to_storage('TestFT.8021x')

        hwsim = Hwsim()

        cls.bss_hostapd = [ HostapdCLI(config='ft-eap-ccmp-1.conf'),
                            HostapdCLI(config='ft-eap-ccmp-2.conf') ]
        cls.bss_radio =  [ hwsim.get_radio('rad0'),
                           hwsim.get_radio('rad1') ]

        # Set interface addresses to those expected by hostapd config files
        os.system('ifconfig "' + cls.bss_hostapd[0].ifname +
                '" down hw ether 12:00:00:00:00:01 up')
        os.system('ifconfig "' + cls.bss_hostapd[1].ifname +
                '" down hw ether 12:00:00:00:00:02 up')

        cls.bss_hostapd[0].reload()
        cls.bss_hostapd[1].reload()

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
        cls.bss_radio = None

if __name__ == '__main__':
    unittest.main(exit=True)
