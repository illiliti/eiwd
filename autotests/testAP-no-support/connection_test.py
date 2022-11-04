#! /usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD, NetworkType, PSKAgent

class Test(unittest.TestCase):
    def test_no_ap_mode(self):
        wd = IWD(True)

        dev = wd.list_devices(1)[0]

        with self.assertRaises(iwd.NotSupportedEx):
            dev.start_ap('TestAP2', 'Password2')

    def test_only_tkip_support(self):
        wd = IWD(True)

        devices = wd.list_devices(2)

        dev_sta = devices[0]
        dev_ap = devices[1]

        dev_ap.start_ap('TestAP2', 'Password2')

        self.assertTrue(dev_ap.group_cipher == 'TKIP')
        self.assertIn('TKIP', dev_ap.pairwise_ciphers)

        ordered_network = dev_sta.get_ordered_network('TestAP2')

        if ordered_network.type != NetworkType.psk:
            raise Exception("Network type mismatch")

        psk_agent = PSKAgent('Password2')
        wd.register_psk_agent(psk_agent)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev_sta, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_no_ccmp_support(self):
        wd = IWD(True)

        dev = wd.list_devices(2)[1]

        # Should fail to start since the radio doesn't support CCMP but the
        # profile only lists CCMP as allowed.
        with self.assertRaises(iwd.NotSupportedEx):
            dev.start_ap('TestAP2')

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_ap('TestAP2.ap')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
