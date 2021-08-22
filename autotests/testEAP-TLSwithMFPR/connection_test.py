#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidEAP-TLS')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-TLS.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
