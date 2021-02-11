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
        rule0.signal = -2000

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True
        rule1.signal = -8000

        rule2 = hwsim.rules.create()
        rule2.source = bss_radio[2].addresses[0]
        rule2.bidirectional = True
        rule2.signal = -9000

        wd = IWD(True)

        psk_agent = PSKAgent(["secret123", 'secret123'])
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network("TestBlacklist", scan_if_needed=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Have both APs drop all packets, both should get blacklisted
        rule0.drop = True
        rule1.drop = True
        rule2.drop = True

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

        rule0.drop = False
        rule1.drop = False
        rule2.drop = False

        # Wait for scanning (likely a quick-scan) to finish, otherwise we will
        # may not have all BSS's in the list.
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        # This connect should work
        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertIn(device.address, bss_hostapd[0].list_sta())

        wd.unregister_psk_agent(psk_agent)

        rule0.remove()
        rule1.remove()
        rule2.remove()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
