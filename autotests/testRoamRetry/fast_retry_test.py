#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

import testutil

from hostapd import HostapdCLI
from hwsim import Hwsim

class Test(unittest.TestCase):
    # Normally the time between a failed roam attempt and the next roam attempt
    # is 60 seconds (default RoamRetryInterval). Test that we retry roaming
    # faster if the transision looks like this: LOW [roam] [same bss] HIGH LOW.
    def test_fast_retry(self):
        hwsim = Hwsim()

        bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                        HostapdCLI(config='ssid2.conf') ]
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

        bss_hostapd[0].set_neighbor(bss_radio[1].addresses[0], 'TestRoamRetry',
                bss1_nr)
        bss_hostapd[1].set_neighbor(bss_radio[0].addresses[0], 'TestRoamRetry',
                bss0_nr)

        # Start in the vicinity of BSS 0, check that iwd connects to BSS 0
        rule0.signal = -2000
        rule1.signal = -8500

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('TestRoamRetry')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertTrue(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        wd.wait(5)

        # Now push the signal LOW, wait for iwd to attempt a roam, fail, and
        # schedule another attempt for 60 seconds later
        rule0.signal = -8000

        wd.wait(20)

        self.assertEqual(device.state, iwd.DeviceState.connected)
        self.assertTrue(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[0].ifname, device.name)

        # Assert high signal for BSS 0 again. This clears the way for a faster
        # roam attempt on LOW again
        rule0.signal = -5000

        # Wait a little for signal recognition
        wd.wait(1)

        # Assert low signal for BSS 0, check that iwd starts transition to BSS 1
        # in less than 10 seconds. Because of the neighbor report a scan should
        # not be necessary.
        rule0.signal = -8000
        rule1.signal = -2000

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition, max_wait=10)

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        condition = 'obj.state != DeviceState.roaming'
        wd.wait_for_object_condition(device, condition, max_wait=5)

        self.assertEqual(device.state, iwd.DeviceState.connected)
        self.assertTrue(bss_hostapd[1].list_sta())

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        rule0.remove()
        rule1.remove()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
