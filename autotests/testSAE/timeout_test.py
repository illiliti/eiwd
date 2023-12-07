#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
from config import ctx

class Test(unittest.TestCase):

    def validate_connection(self, wd):
        psk_agent = PSKAgent(["secret123", "secret123"])
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        network = device.get_ordered_network('ssidSAE')

        self.assertEqual(network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

    def test_not_acked_commit(self):
        #
        # TODO: This merely forces group 19 by acting as a 'buggy' AP. This is
        # needed because the hwsim rule only matches once and must be matched
        # on the first commit, not during group negotiation.
        #
        self.hostapd.set_value('vendor_elements', 'dd0cf4f5e8050500000000000000')
        self.hostapd.reload()

        hwsim = Hwsim()
        bss_radio = hwsim.get_radio('rad0')

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio.addresses[0]
        rule0.drop = True
        rule0.prefix = 'b0'
        rule0.match = '01 00 00 00 13 00'
        rule0.match_offset = 26
        rule0.match_times = 1
        rule0.drop_ack = True
        rule0.enabled = True

        wd = IWD(True)
        self.validate_connection(wd)

        rule0.remove()

    def test_sta_confirm_not_acked(self):
        self.hostapd.set_value('vendor_elements', 'dd0cf4f5e8050500000000000000')
        self.hostapd.reload()

        hwsim = Hwsim()
        bss_radio = hwsim.get_radio('rad0')

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio.addresses[0]
        rule0.drop = True
        rule0.prefix = 'b0'
        rule0.match = '02 00 00 00'
        rule0.match_offset = 26
        rule0.match_times = 1
        rule0.drop_ack = True
        rule0.enabled = True

        wd = IWD(True)
        self.validate_connection(wd)

        rule0.remove()

    def setUp(self):
        self.hostapd = HostapdCLI(config='ssidSAE.conf')
        self.hostapd.default()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
