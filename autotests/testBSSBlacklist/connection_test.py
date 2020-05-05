#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI
from hostapd import hostapd_map

from hwsim import Hwsim

import time

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                        HostapdCLI(config='ssid2.conf'),
                        HostapdCLI(config='ssid3.conf') ]
        bss_radio =  [ hwsim.get_radio('rad0'),
                       hwsim.get_radio('rad1'),
                       hwsim.get_radio('rad2') ]

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio[0].addresses[0]
        rule0.bidirectional = True
        rule0.signal = -2000

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True
        rule1.signal = -3000

        rule2 = hwsim.rules.create()
        rule2.source = bss_radio[2].addresses[0]
        rule2.bidirectional = True
        rule2.signal = -4000

        wd = IWD(True, '/tmp')

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect(wait=False)

        # Have AP1 drop all packets, should result in a connection timeout
        rule0.drop = True

        # Note the time so later we don't sleep any longer than required
        start = time.time()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        # IWD should have attempted to connect to bss_hostapd[0], since its
        # signal strength was highest. But since we dropped all packets this
        # connect should fail, and the BSS should be blacklisted. Then we
        # should automatically try the next BSS in the list, which is
        # bss_hostapd[1]
        self.assertNotIn(device.address, bss_hostapd[0].list_sta())
        self.assertIn(device.address, bss_hostapd[1].list_sta())

        rule0.drop = False

        # Next try autoconnecting to a network with a blacklisted BSS. Since an
        # explicit disconnect call would disable autoconnect we reset
        # hostapd which will disconnect IWD.
        bss_hostapd[1].reload()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Now we wait... AutoConnect should take over

        condition = 'obj.state == DeviceState.connecting'
        wd.wait_for_object_condition(device, condition, 15)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition, 15)

        # Same as before, make sure we didn't connect to the blacklisted AP.
        self.assertNotIn(device.address, bss_hostapd[0].list_sta())
        self.assertIn(device.address, bss_hostapd[1].list_sta())

        # Wait for the blacklist to expire (10 seconds)
        elapsed = time.time() - start

        if elapsed < 11:
            time.sleep(11 - elapsed)

        device.disconnect()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertIn(device.address, bss_hostapd[0].list_sta())

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('main.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
