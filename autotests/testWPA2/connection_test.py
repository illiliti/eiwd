#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def validate_connection_success(self, wd):
        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidWPA2')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_ccmp(self):
        self.hostapd.set_value('rsn_pairwise', 'CCMP')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection_success(self.wd)

    def test_gcmp(self):
        self.hostapd.set_value('rsn_pairwise', 'GCMP')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection_success(self.wd)

    def test_gcmp_256(self):
        self.hostapd.set_value('rsn_pairwise', 'GCMP-256')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection_success(self.wd)

    def test_ccmp_256(self):
        self.hostapd.set_value('rsn_pairwise', 'CCMP-256')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.validate_connection_success(self.wd)

    def setUp(self):
        self.wd = IWD(True)

    def tearDown(self):
        self.wd.clear_storage()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidWPA2.conf')

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
