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
        self.rule2.enabled = True
        self.rule3.enabled = True

        device = self.wd.list_devices(1)[0]

        self.connect(self.wd, device, self.bss_hostapd[0])

        self.rule0.enabled = True

        # IWD should connect, then attempt a roam to BSS 1, which should fail...
        device.wait_for_event('ft-roam-failed', timeout=60)
        # ... but IWD should remain connected
        self.assertTrue(device.state == DeviceState.connected)

        self.rule0.enabled = False

        # IWD should then try BSS 2, and succeed
        device.wait_for_event('ft-roaming', timeout=60)
        self.verify_roam(self.wd, device, self.bss_hostapd[0], self.bss_hostapd[2])

        self.bss_hostapd[2].deauthenticate(device.address)

    # Tests that an associate even should cause a disconnect
    def test_ft_over_air_assoc_timeout(self):
        self.rule2.enabled = True
        self.rule3.enabled = True
        self.assoc_rule.enabled = True

        device = self.wd.list_devices(1)[0]

        self.connect(self.wd, device, self.bss_hostapd[0])

        device.wait_for_event('ft-roaming', timeout=60)

        condition = 'obj.state == DeviceState.disconnected'
        self.wd.wait_for_object_condition(device, condition)

    # FT-over-Air failure with Invalid PMKID, should reassociate
    def test_ft_over_air_fallback(self):
        self.rule_bss0.signal = -8000
        self.rule_bss0.enabled = True
        self.rule_bss1.signal = -7500
        self.rule_bss1.enabled = True
        self.rule_bss2.signal = -6000
        self.rule_bss2.enabled = True

        # This will cause this BSS to reject any FT roams as its unable to
        # get keys from other APs
        self.bss_hostapd[2].set_value('ft_psk_generate_local', '0')
        self.bss_hostapd[2].reload()

        device = self.wd.list_devices(1)[0]

        self.connect(self.wd, device, self.bss_hostapd[0])

        # IWD should connect, then attempt a roam to BSS 1, which should
        # fail and cause a fallback to reassociation
        device.wait_for_event('ft-fallback-to-reassoc', timeout=60)
        device.wait_for_event('roaming', timeout=60)

        self.verify_roam(self.wd, device, self.bss_hostapd[0], self.bss_hostapd[2])

        # Trigger another roam
        self.rule_bss2.signal = -8000

        device.wait_for_event('ft-roaming', timeout=60)

        # Ensure an FT roam back to a properly configured AP works.
        self.verify_roam(self.wd, device, self.bss_hostapd[2], self.bss_hostapd[1])

        self.bss_hostapd[1].deauthenticate(device.address)
        condition = 'obj.state == DeviceState.disconnected'
        self.wd.wait_for_object_condition(device, condition)

    # FT-over-Air failure with Invalid PMKID. The ranking is such that other
    # FT candidates are available so it should FT elsewhere rather than
    # retry with reassociation
    def test_ft_over_air_fallback_retry_ft(self):
        self.rule_bss0.signal = -8000
        self.rule_bss0.enabled = True
        self.rule_bss1.signal = -7300
        self.rule_bss1.enabled = True
        self.rule_bss2.signal = -7100
        self.rule_bss2.enabled = True

        # This will cause this BSS to reject any FT roams as its unable to
        # get keys from other APs
        self.bss_hostapd[2].set_value('ft_psk_generate_local', '0')
        self.bss_hostapd[2].reload()

        device = self.wd.list_devices(1)[0]

        self.connect(self.wd, device, self.bss_hostapd[0])

        # IWD should connect, then attempt a roam to BSS 1, which should
        # fail and cause the rank to be re-computed. This should then put
        # bss 1 as the next candidate (since the FT factor is removed)
        device.wait_for_event('ft-fallback-to-reassoc', timeout=60)
        device.wait_for_event('ft-roaming', timeout=60)

        self.verify_roam(self.wd, device, self.bss_hostapd[0], self.bss_hostapd[1])

        self.bss_hostapd[1].deauthenticate(device.address)
        condition = 'obj.state == DeviceState.disconnected'
        self.wd.wait_for_object_condition(device, condition)

    def setUp(self):
        self.wd = IWD(True)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

        self.rule0.enabled = False
        self.rule1.enabled = False
        self.rule2.enabled = False
        self.rule3.enabled = False
        self.rule_bss0.enabled = False
        self.rule_bss1.enabled = False
        self.rule_bss2.enabled = False
        self.assoc_rule.enabled = False

        for hapd in self.bss_hostapd:
            hapd.default()

        self.wd.stop()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf'),
                            HostapdCLI(config='ft-psk-ccmp-3.conf') ]

        cls.bss_hostapd[0].set_address('12:00:00:00:00:01')
        cls.bss_hostapd[1].set_address('12:00:00:00:00:02')
        cls.bss_hostapd[2].set_address('12:00:00:00:00:03')

        # Drop Authenticate frames
        cls.rule0 = hwsim.rules.create()
        cls.rule0.source = hwsim.get_radio('rad1').addresses[0]
        cls.rule0.prefix = 'b0'
        cls.rule0.drop = True

        # Drop Associate frames
        cls.assoc_rule = hwsim.rules.create()
        cls.assoc_rule.prefix = '20'
        cls.assoc_rule.drop = True

        # Drop Action frames
        cls.rule1 = hwsim.rules.create()
        cls.rule1.bidirectional = True
        cls.rule1.prefix = 'd0'
        cls.rule1.drop = True

        # Causes IWD to immediately roam away from BSS 0
        cls.rule2 = hwsim.rules.create()
        cls.rule2.source = hwsim.get_radio('rad0').addresses[0]
        cls.rule2.signal = -8000

        # Causes IWD to first prefer BSS 1 to roam, then BSS 2.
        cls.rule3 = hwsim.rules.create()
        cls.rule3.source = hwsim.get_radio('rad2').addresses[0]
        cls.rule3.signal = -7000

        cls.rule_bss0 = hwsim.rules.create()
        cls.rule_bss0.source = hwsim.get_radio('rad0').addresses[0]
        cls.rule_bss1 = hwsim.rules.create()
        cls.rule_bss1.source = hwsim.get_radio('rad1').addresses[0]
        cls.rule_bss2 = hwsim.rules.create()
        cls.rule_bss2.source = hwsim.get_radio('rad2').addresses[0]

        HostapdCLI.group_neighbors(*cls.bss_hostapd)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule0.remove()
        cls.rule1.remove()
        cls.rule2.remove()
        cls.rule3.remove()
        cls.assoc_rule.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
