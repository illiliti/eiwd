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
    def test_preauth_success(self):
        hwsim = Hwsim()

        bss_hostapd = [ HostapdCLI(config='eaptls-preauth-1.conf'),
                        HostapdCLI(config='eaptls-preauth-2.conf') ]
        bss_radio =  [ hwsim.get_radio('rad0'),
                       hwsim.get_radio('rad1') ]

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio[0].addresses[0]
        rule0.bidirectional = True

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True

        # Fill in the neighbor AP tables in both BSSes.  By default each
        # instance knows only about current BSS, even inside one hostapd
        # process.
        # Roaming still works without the neighbor AP table but neighbor
        # reports have to be disabled in the .conf files
        bss0_nr = ''.join(bss_radio[0].addresses[0].split(':')) + \
                '8f0000005101060603000000'
        bss1_nr = ''.join(bss_radio[1].addresses[0].split(':')) + \
                '8f0000005102060603000000'

        bss_hostapd[0].set_neighbor(bss_radio[1].addresses[0], 'TestPreauth',
                bss1_nr)
        bss_hostapd[1].set_neighbor(bss_radio[0].addresses[0], 'TestPreauth',
                bss0_nr)

        # Check that iwd selects BSS 0 first
        rule0.signal = -2500
        rule1.signal = -3500

        wd = IWD()

        device = wd.list_devices(1)[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('TestPreauth')

        self.assertEqual(ordered_network.type, NetworkType.eap)
        self.assertEqual(ordered_network.signal_strength, -2500)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertTrue(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          bss_hostapd[1].ifname, device.name)

        # Check that iwd starts transition to BSS 1 in less than 15 seconds
        rule0.signal = -8000

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        # TODO: verify that the PMK from preauthentication was used

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        self.assertTrue(bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (bss_hostapd[0].ifname, device.name))

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestPreauth.8021x')

        os.system('ifconfig lo up')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
