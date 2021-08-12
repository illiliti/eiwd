#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import testutil
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def validate_connection(self, wd):
        hostapd = HostapdCLI(config='ssidEAP-TTLS-MSCHAPv2.conf')

        self.assertIsNotNone(hostapd)

        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0];

        ordered_network = device.get_ordered_network('ssidEAP-TTLS-MSCHAPv2')

        self.assertEqual(ordered_network.name, "ssidEAP-TTLS-MSCHAPv2")
        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        hostapd.eapol_reauth(device.address)

        hostapd.wait_for_event('CTRL-EVENT-EAP-STARTED')
        hostapd.wait_for_event('CTRL-EVENT-EAP-SUCCESS')

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_connection_success(self):
        wd = IWD(True)

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-TTLS-MSCHAPv2.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
