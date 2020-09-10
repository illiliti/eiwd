#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class Test(unittest.TestCase):

    def validate_connection(self, wd):

        devices = wd.list_devices(4)
        self.assertIsNotNone(devices)
        device = devices[0]

        # These devices aren't used in this test, this makes logs a bit nicer
        # since these devices would presumably start autoconnecting.
        devices[1].disconnect()
        devices[2].disconnect()
        devices[3].disconnect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.connected_network is not None'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidSAE')

        self.assertTrue(ordered_network.network_object.connected)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        wd = IWD(True)

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidSAE.psk')
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
