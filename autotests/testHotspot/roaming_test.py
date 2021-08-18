#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD
from iwd import IWD_CONFIG_DIR
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = self.wd

        hapd = HostapdCLI(config='ssidHotspot.conf')

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('Hotspot')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('roaming.conf')
        IWD.copy_to_storage('anqp_disabled.conf', storage_dir=IWD_CONFIG_DIR, name='main.conf')

        cls.wd = IWD(True)
        cls.psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        cls.wd.register_psk_agent(cls.psk_agent)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

        cls.wd.unregister_psk_agent(cls.psk_agent)
        cls.wd = None

if __name__ == '__main__':
    unittest.main(exit=True)
