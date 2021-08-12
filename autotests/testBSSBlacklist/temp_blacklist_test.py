#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI
from hwsim import Hwsim

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
        rule0.signal = -8000

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True
        rule1.signal = -7000

        rule2 = hwsim.rules.create()
        rule2.source = bss_radio[2].addresses[0]
        rule2.bidirectional = True
        rule2.signal = -2000

        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        dev1, dev2 = wd.list_devices(2)

        ordered_network = dev1.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev1, condition)

        self.assertIn(dev1.address, bss_hostapd[2].list_sta())

        # dev1 now connected, this should max out the first AP, causing the next
        # connection to fail to this AP.

        ordered_network = dev2.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev2, condition)

        # We should have temporarily blacklisted the first BSS, and connected
        # to this one.
        self.assertIn(dev2.address, bss_hostapd[1].list_sta())

        # Now check that the first BSS is still not blacklisted. We can
        # disconnect dev1, opening up the AP for more connections
        dev1.disconnect()
        dev2.disconnect()

        ordered_network = dev2.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev2, condition)

        self.assertIn(dev2.address, bss_hostapd[2].list_sta())

        wd.unregister_psk_agent(psk_agent)

        rule0.remove()
        rule1.remove()
        rule2.remove()

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('main.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
