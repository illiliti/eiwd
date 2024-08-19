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
    def test_bss_unregister(self):
        device = self.wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('ssidTKIP', full_scan=True)
        network = ordered_network.network_object

        self.assertEqual(len(network.extended_service_set), 2)

        ends = [parts.split('/')[-1] for parts in network.extended_service_set]

        self.assertIn(self.bss_hostapd[0].bssid.replace(':', ''), ends)
        self.assertIn(self.bss_hostapd[1].bssid.replace(':', ''), ends)

        self.rule_bss1.enabled = True

        # Even with flushing, the kernel still seems to return the scan
        # results
        self.wd.wait(40)
        ordered_network = device.get_ordered_network('ssidTKIP', full_scan=True)
        network = ordered_network.network_object

        ends = [parts.split('/')[-1] for parts in network.extended_service_set]

        self.assertIn(self.bss_hostapd[0].bssid.replace(':', ''), ends)
        self.assertNotIn(self.bss_hostapd[1].bssid.replace(':', ''), ends)

        self.rule_bss0.enabled = True

        self.wd.wait(40)
        ordered_networks = device.get_ordered_networks('ssidTKIP', full_scan=True)
        self.assertIsNone(ordered_networks)

        self.rule_bss0.enabled = False

        ordered_networks = device.get_ordered_networks('ssidTKIP', full_scan=True)
        ends = [parts.split('/')[-1] for parts in network.extended_service_set]

        self.assertIn(self.bss_hostapd[0].bssid.replace(':', ''), ends)
        self.assertNotIn(self.bss_hostapd[1].bssid.replace(':', ''), ends)

    def tearDown(self):
        self.rule_bss0.enabled = False
        self.rule_bss1.enabled = False

        self.wd.stop()
        self.wd.wait(10)
        self.wd = None

    def setUp(self):
        self.wd = IWD(True)

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('ssidTKIP.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ssidTKIP-1.conf'),
                            HostapdCLI(config='ssidTKIP-2.conf') ]


        rad0 = hwsim.get_radio('rad0')
        rad1 = hwsim.get_radio('rad1')

        cls.rule_bss0 = hwsim.rules.create()
        cls.rule_bss0.source = rad0.addresses[0]
        cls.rule_bss0.bidirectional = True
        cls.rule_bss0.drop = True

        cls.rule_bss1 = hwsim.rules.create()
        cls.rule_bss1.source = rad1.addresses[0]
        cls.rule_bss1.bidirectional = True
        cls.rule_bss1.drop = True

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule_bss0.remove()
        cls.rule_bss1.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
