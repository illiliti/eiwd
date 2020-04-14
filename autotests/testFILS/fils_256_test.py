#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import hostapd_map
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def test_connection_success(self):
        hapd = HostapdCLI(config='ssidFILS-256.conf')

        wd = IWD(True)

        psk_agent = PSKAgent('user@example.com', ('user@example.com',
                                                                  'secret123'))
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidFILS-256')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network = device.get_ordered_network('ssidFILS-256')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname)

        device.disconnect()

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidFILS-256.8021x')
        os.system('ifconfig lo up')
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
