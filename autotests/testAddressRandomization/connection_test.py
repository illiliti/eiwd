#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
import testutil

class Test(unittest.TestCase):
    def try_connection(self, wd):
        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidCCMP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        return device.address

    def test_connection_success(self):
        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        perm_addr = device.address

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        # 1. Test per-network deterministic MAC generation
        os.system('cat pernetwork.psk > /var/lib/iwd/ssidCCMP.psk')
        new_addr = self.try_connection(wd)
        self.assertNotEqual(perm_addr, new_addr)
        # try again to ensure the generation was deterministic
        new_addr2 = self.try_connection(wd)
        self.assertEqual(new_addr, new_addr2)

        # 2. Test FullAddressRandomization
        os.system('cat full_random.psk > /var/lib/iwd/ssidCCMP.psk')
        new_addr = self.try_connection(wd)
        self.assertNotEqual(perm_addr, new_addr)
        # try again to make sure the generation was random
        new_addr2 = self.try_connection(wd)
        self.assertNotEqual(new_addr, new_addr2)

        # 3. Test AddressOverride
        os.system('cat override.psk > /var/lib/iwd/ssidCCMP.psk')
        new_addr = self.try_connection(wd)
        self.assertEqual(new_addr, 'e6:f6:38:a9:02:02')

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
