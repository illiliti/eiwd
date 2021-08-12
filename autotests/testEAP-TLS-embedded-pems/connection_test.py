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

class Test(unittest.TestCase):

    def do_test_connection_success(self, ssid, passphrase=None):
        hostapd = HostapdCLI(config=ssid + '.conf')
        wd = IWD()

        if passphrase:
            psk_agent = PSKAgent(passphrase)
            wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network(ssid)

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(hostapd.ifname, device.name)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        if passphrase:
            wd.unregister_psk_agent(psk_agent)

    def test_eap_tls(self):
        self.do_test_connection_success('ssidEAP-TLS')

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-TLS.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
